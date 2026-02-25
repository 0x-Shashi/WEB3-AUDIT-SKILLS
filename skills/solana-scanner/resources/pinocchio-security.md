---
id: RES-SOLANA-PINOCCHIO-SECURITY
title: Pinocchio Security Patterns for Auditors
category: resource
parent: SCANNER-SOLANA
chains: [solana]
languages: [rust]
frameworks: [pinocchio, native]
last_updated: 2026-02-25
description: >-
  Use when auditing Solana programs built with Pinocchio — covers account
  validation, Token-2022 checks, safe account closing, dangerous memory
  patterns, zero-copy safety, and runtime memory constraints.
---

# Pinocchio Security Patterns for Auditors

Pinocchio provides **no automatic safety rails** — every account check, discriminator validation, and owner verification must be written by hand. Assume nothing is validated unless you see the explicit check.

## 1. Account Validation via TryFrom

Pinocchio programs separate validation from business logic using `TryFrom` implementations. This is the **primary security boundary** — if checks are missing here, the program is vulnerable.

### Complete Validation Pattern

```rust
impl<'a> TryFrom<&'a [AccountView]> for DepositAccounts<'a> {
    type Error = ProgramError;
    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [owner, vault, system_program, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
        if !vault.is_owned_by(&pinocchio_system::ID) { return Err(ProgramError::InvalidAccountOwner); }
        if system_program.address() != &pinocchio_system::ID { return Err(ProgramError::IncorrectProgramId); }
        Ok(Self { owner, vault, system_program })
    }
}
```

### Audit Checklist for TryFrom Blocks

| Check | What to look for | Vulnerability if missing |
|-------|-----------------|--------------------------|
| **Account count** | `let [a, b, ..] = accounts else { Err(...) }` | Out-of-bounds access / panic |
| **Signer** | `is_signer()` on authority accounts | Unauthorized privileged operations |
| **Owner** | `is_owned_by(&expected_program)` | Fake account injection (type cosplay) |
| **Program ID** | `address() != &known_id` on program accounts | Arbitrary CPI to malicious program |
| **PDA derivation** | `find_program_address` + key comparison | PDA spoofing |
| **Data length** | `data.len() != Expected::LEN` | Deserialization of wrong account type |
| **Discriminator** | First N bytes match expected type tag | Type confusion between account types |
| **Uniqueness** | `a.address() != b.address()` | Duplicate mutable account attacks |
| **has_one equivalent** | Manual field comparison (`vault.authority == owner.key()`) | Data mismatch / wrong authority |

### Instruction Data Validation

Pinocchio parses raw bytes — always validate length before reading:

```rust
impl<'a> TryFrom<&'a [u8]> for DepositData {
    type Error = ProgramError;
    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() != core::mem::size_of::<u64>() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let amount = u64::from_le_bytes(data.try_into().unwrap());
        if amount == 0 { return Err(ProgramError::InvalidInstructionData); }
        Ok(Self { amount })
    }
}
```

**Red flags**: No length check before `unwrap()` (panic), no semantic validation (zero amounts), `transmute` instead of `from_le_bytes` (alignment UB).

## 2. Token-2022 Discriminator-Based Validation

Token-2022 accounts have **variable sizes** due to extensions (transfer hooks, fees, metadata). You cannot validate them by length alone — you must check the **discriminator byte at offset 165**.

### SPL Token (Classic) — Length-Based

```rust
impl Mint {
    pub fn check(account: &AccountView) -> Result<(), ProgramError> {
        if !account.is_owned_by(&pinocchio_token::ID) { return Err(ProgramError::InvalidAccountOwner); }
        if account.data_len() != pinocchio_token::state::Mint::LEN { return Err(ProgramError::InvalidAccountData); }
        Ok(())
    }
}
```

### Token-2022 — Discriminator-Based

Token-2022 accounts have variable sizes due to extensions. The **discriminator byte at offset 165** distinguishes mints (`0x01`) from token accounts (`0x02`).

```rust
const DISC_OFFSET: usize = 165;
const MINT_DISC: u8 = 0x01;

impl Mint2022 {
    pub fn check(account: &AccountView) -> Result<(), ProgramError> {
        if !account.is_owned_by(&TOKEN_2022_PROGRAM_ID) { return Err(ProgramError::InvalidAccountOwner); }
        let data = account.try_borrow_data()?;
        if data.len() != pinocchio_token::state::Mint::LEN {
            if data.len() <= DISC_OFFSET { return Err(ProgramError::InvalidAccountData); }
            if data[DISC_OFFSET] != MINT_DISC { return Err(ProgramError::InvalidAccountData); }
        }
        Ok(())
    }
}
```

**Audit red flags for Token-2022:**
- Only checks `pinocchio_token::ID` owner — rejects all Token-2022 accounts
- Length-only validation on Token-2022 (fails with extensions)
- Missing discriminator check — allows mint/token-account type confusion
- No handling of transfer hooks or transfer fees (silent fund loss)
- Programs accepting both SPL Token and Token-2022 must branch on `is_owned_by` for each

## 3. Secure Account Closing (Revival Prevention)

When a Pinocchio program closes an account, it must prevent the **revival attack**: a later instruction in the same transaction reads the closed account's stale data because it remains in the runtime cache.

### Correct Closing Pattern

```rust
pub fn close(account: &AccountView, destination: &AccountView) -> ProgramResult {
    { let mut data = account.try_borrow_mut_data()?; data[0] = 0xFF; } // poison
    *destination.try_borrow_mut_lamports()? += *account.try_borrow_lamports()?;
    account.realloc(1, true)?;
    account.close()
}
```

| Step | Vulnerability if skipped |
|------|--------------------------|
| Poison discriminator (`0xFF`) | Attacker re-reads stale state in later instruction |
| Transfer all lamports | SOL locked in dead account forever |
| `realloc(1, true)` | Data remains readable in same tx |
| `account.close()` | Account persists past transaction |

**Audit checks**: Discriminator overwritten before lamport transfer. All lamports transferred. Init paths reject `0xFF`. No later instruction reads closed account. **Compare with Anchor**: `#[account(mut, close = destination)]` handles this automatically.

## 4. Dangerous Patterns to Flag

These patterns compile and may pass basic testing but introduce undefined behavior or exploitable conditions.

### 4a. `transmute` with Unaligned Data

```rust
// ❌ account data is not guaranteed to be aligned
let value: u64 = unsafe { core::mem::transmute(bytes_slice) };
// ✅ Safe: u64::from_le_bytes(bytes_slice.try_into().unwrap());
```

### 4b. Packed Struct Field References

```rust
#[repr(C, packed)]
pub struct Packed { pub a: u8, pub b: u64 }
let b_ref = &packed.b; // ← unaligned reference = instant UB
// ✅ Safe: store as [u8; 8], use from_le_bytes accessor
```

### 4c. Pointer Cast Without Alignment Proof

```rust
let config = unsafe { &*(data.as_ptr() as *const Config) };
// Only safe if ALL fields are [u8; N] (effective alignment = 1)
```

| Pattern | Risk | Safe Alternative |
|---------|------|-----------------|
| `transmute` on byte slices | Unaligned memory access (UB) | `from_le_bytes()` |
| `&packed_struct.field` | Unaligned reference (UB) | Byte array + accessor methods |
| `*(ptr as *const T)` | UB on misaligned pointers | `from_bytes()` with `[u8; N]` fields |

## 5. Zero-Copy Reading Safety

Pinocchio's performance advantage comes from zero-copy deserialization — reading account data in-place without allocating. This is safe **only** when struct layout guarantees byte-alignment.

### Safe Zero-Copy Pattern

```rust
#[repr(C)]
pub struct Config {
    pub authority: [u8; 32], // Pubkey as bytes — alignment 1
    pub mint: [u8; 32],     // Pubkey as bytes — alignment 1
    seed: [u8; 8],          // u64 stored as bytes
    fee: [u8; 2],           // u16 stored as bytes
    pub state: u8,
    pub bump: u8,
}

impl Config {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN { return Err(ProgramError::InvalidAccountData); }
        // Safe: all fields are [u8; N] → effective alignment is 1
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn seed(&self) -> u64 { u64::from_le_bytes(self.seed) }
    pub fn fee(&self) -> u16 { u16::from_le_bytes(self.fee) }
}
```

**Why this is safe**: All fields are `u8` or `[u8; N]` → alignment requirement is 1. `#[repr(C)]` guarantees deterministic layout. `from_le_bytes` handles endianness. Length check prevents buffer overread.

### Audit Checklist for Zero-Copy

- [ ] Struct uses `#[repr(C)]` (not default Rust repr)
- [ ] Multi-byte fields stored as `[u8; N]` (not `u64`, `u32` directly)
- [ ] Length validated before pointer cast
- [ ] Accessors use `from_le_bytes` (not direct field access)
- [ ] No `#[repr(C, packed)]` used with reference creation
- [ ] Discriminator bytes are allocated and checked

## 6. Memory Limits and Security Implications

Solana imposes hard runtime memory constraints. Pinocchio programs operating near these limits are vulnerable to denial-of-service or unexpected panics.

### Runtime Constraints

| Resource | Limit | Security Implication |
|----------|-------|---------------------|
| Stack per frame | **4 KB** | Deep call chains or large local arrays → stack overflow panic |
| Heap total | **32 KB** | Unbounded allocations → OOM panic → transaction fails |
| Account data | **10 MB** | Realloc without bounds checking → excessive rent drain |
| Compute units | **200K default** (1.4M max) | Unbounded loops → CU exhaustion → DoS |
| Instruction data | **1232 bytes** (MTU) | Overlong input → transaction rejected at network layer |

### Common Exhaustion Patterns

```rust
// ❌ Stack overflow: 8KB local array > 4KB limit
let buffer: [u8; 8192] = [0; 8192];
// ✅ Use zero-copy: accounts[0].try_borrow_data()?;

// ❌ Heap exhaustion: unbounded Vec from user input
let items: Vec<u64> = Vec::with_capacity(data[0] as usize); // attacker → 32KB
// ✅ Cap allocations: if count > MAX_ITEMS { return Err(...); }

// ❌ CU exhaustion: attacker-controlled loop bound
for i in 0..user_provided_count { process_item(&accounts[i])?; }
// ✅ Cap iterations: let count = core::cmp::min(user_provided_count, MAX_OPS);
```

### `no_allocator!()` Macro

If present, the program **cannot** allocate on the heap — eliminates OOM risks. If absent, audit all `Vec`, `String`, or `Box` for bounded capacity.

### Audit Checklist for Memory Safety

- [ ] No local arrays > 1KB (stay well under 4KB stack limit)
- [ ] All `Vec`/heap allocations have **bounded capacity**
- [ ] `no_allocator!()` present → verify no accidental heap usage via dependencies
- [ ] Loop bounds are **capped** and not user-controlled
- [ ] `realloc()` calls validate max size before expanding
- [ ] Account data parsing does not allocate (uses zero-copy or fixed buffers)

## Quick Reference: Pinocchio vs Anchor Safety

| Property | Anchor | Pinocchio |
|----------|--------|------------|
| Owner validation | `Account<'info, T>` | `is_owned_by()` in `TryFrom` |
| Signer | `Signer<'info>` | `is_signer()` in `TryFrom` |
| Discriminator | 8-byte auto | Manual first-N-bytes check |
| PDA | `#[account(seeds, bump)]` | `find_program_address` + key cmp |
| Account close | `#[account(close = dest)]` | Poison + transfer + realloc + close |
| CPI target | `Program<'info, T>` | `address() != &known_id` |
| Data matching | `has_one = x` | Manual field comparison |
| Overflow | Rust defaults | `checked_*` or Cargo flag |
| Duplicates | Not auto-checked | Manual `a.key() != b.key()` |

Pinocchio programs require **2-3x more audit attention** than Anchor equivalents.
