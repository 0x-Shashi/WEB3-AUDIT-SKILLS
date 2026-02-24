---
id: SOLANA-NATIVE-AUDIT
title: Native Solana Program Audit Workflow
category: solana-scanner
difficulty: advanced
triggers:
  - audit native solana program
  - solana program review
  - non-anchor solana audit
  - raw solana program
related_skills:
  - solana-scanner/workflows/anchor-audit.md
  - solana-scanner/resources/solana-patterns.md
  - solana-scanner/resources/account-validation.md
tags:
  - solana
  - native
  - workflow
  - audit
last_updated: 2026-02-24
---

# Native Solana Program Audit Workflow

> Native Solana programs (no Anchor) require manual implementation of every safety check that Anchor automates. This makes them significantly more dangerous to audit — the attack surface is larger and errors are harder to spot.

## Key Differences from Anchor Programs

| Feature | Anchor | Native | Audit Implication |
|---------|--------|--------|-------------------|
| Account validation | Automatic via `Account<'info, T>` | Manual owner/signer checks required | Every account must be manually verified |
| Discriminator | Auto-generated 8-byte SHA256 hash | None unless manually added | Type confusion risk is HIGH |
| Serialization | Borsh with derive macros | Manual pack/unpack or custom | Off-by-one, buffer overflow possible |
| Error handling | `require!()`, typed errors | Manual `ProgramResult` returns | Missing error paths = silent failures |
| PDA validation | `seeds`, `bump` constraints | Manual `find_program_address` | Seed confusion, bump misuse |
| Account closing | `#[account(close = receiver)]` | Manual lamport drain + data zero | Revival attacks if data not zeroed |
| CPI safety | Program type checking | Manual invoke/invoke_signed | No automatic target validation |

---

## Step 1: Entrypoint & Instruction Routing

### What to Review
The `process_instruction` function is the single entrypoint. All instruction routing happens manually.

```rust
// Typical pattern — review the routing logic
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = ProgramInstruction::unpack(instruction_data)?;
    match instruction {
        ProgramInstruction::Initialize { .. } => process_initialize(program_id, accounts, ..),
        ProgramInstruction::Deposit { amount } => process_deposit(program_id, accounts, amount),
        ProgramInstruction::Withdraw { amount } => process_withdraw(program_id, accounts, amount),
        // Check: Are all instruction variants handled?
        // Check: Is instruction_data parsing safe? (bounds check, valid enum)
    }
}
```

### Checklist
- [ ] All instruction variants have explicit handlers
- [ ] `instruction_data` parsing validates length before reading
- [ ] Unknown instruction variants return an error (no silent no-op)
- [ ] Instruction enum discriminant cannot be confused (e.g., single byte tag)

---

## Step 2: Account Deserialization & Validation

### What to Review
Every account must be individually validated. This is the #1 source of native Solana vulnerabilities.

```rust
pub fn process_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let user = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    // CHECK 1: Owner validation
    if vault.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    // CHECK 2: Signer validation
    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // CHECK 3: System program validation
    if *system_program.key != solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    // CHECK 4: Data type discriminator
    let data = vault.data.borrow();
    if data.len() < 8 || data[..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    // CHECK 5: Account relationships (equivalent to has_one)
    let vault_data = VaultData::unpack(&data[8..])?;
    if vault_data.owner != *user.key {
        return Err(ProgramError::InvalidAccountData);
    }
    // ...
}
```

### Checklist — EVERY Account Must Have:
- [ ] **Owner check**: `account.owner == expected_program_id`
- [ ] **Signer check**: `account.is_signer == true` for privileged accounts
- [ ] **Writable check**: `account.is_writable == true` if state is modified
- [ ] **Discriminator check**: First 8 bytes match expected type
- [ ] **Relationship check**: Cross-account references validated (e.g., vault.owner == user.key)
- [ ] **Program ID check**: Known programs (System, Token, etc.) validated by key
- [ ] **PDA derivation check**: `find_program_address` result matches passed account

---

## Step 3: PDA (Program Derived Address) Review

### What to Review
PDAs are the primary addressing mechanism. Every PDA must be verified.

```rust
// PATTERN: Creating a PDA
let (expected_pda, bump) = Pubkey::find_program_address(
    &[
        b"vault",              // Fixed prefix
        user.key.as_ref(),     // User-specific
        mint.key.as_ref(),     // Token-specific
    ],
    program_id,
);

// VERIFY: Passed account matches derived PDA
if *vault_account.key != expected_pda {
    return Err(ProgramError::InvalidSeeds);
}
```

### Common PDA Bugs
| Bug | Description | Impact |
|-----|-------------|--------|
| Missing seed component | PDA doesn't include user/mint key | All users share one account |
| Non-canonical bump | User provides bump instead of find_program_address | Multiple valid addresses |
| Seed collision | Different logical entities derive same PDA | Data corruption |
| Forgotten verification | PDA derived but never compared to passed account | Fake account accepted |

### Checklist
- [ ] All PDAs derived with `find_program_address` (canonical bump)
- [ ] Seeds include all disambiguating data (user, mint, pool, etc.)
- [ ] Derived PDA compared against passed account key
- [ ] Bump seed stored on first creation and reused
- [ ] No seed component is attacker-controlled without constraints

---

## Step 4: State Management (Serialization/Deserialization)

### What to Review
Native programs manually serialize and deserialize account data. This is error-prone.

```rust
// Typical pack/unpack pattern
impl VaultData {
    pub const LEN: usize = 32 + 32 + 8 + 1; // authority + mint + balance + bump

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let authority = Pubkey::new_from_array(data[0..32].try_into().unwrap());
        let mint = Pubkey::new_from_array(data[32..64].try_into().unwrap());
        let balance = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let bump = data[72];
        Ok(Self { authority, mint, balance, bump })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        data[0..32].copy_from_slice(&self.authority.to_bytes());
        data[32..64].copy_from_slice(&self.mint.to_bytes());
        data[64..72].copy_from_slice(&self.balance.to_le_bytes());
        data[72] = self.bump;
        Ok(())
    }
}
```

### Checklist
- [ ] `unpack` validates data length before reading
- [ ] `pack` validates data length before writing
- [ ] Field offsets are correct (manually verify byte positions)
- [ ] Borsh or manual serialization is consistent (same endianness)
- [ ] Account data space allocated matches struct LEN
- [ ] No uninitialized memory read (data.len() check before slice)
- [ ] Reallocation (if any) uses `realloc` correctly with rent check

---

## Step 5: CPI (Cross-Program Invocation) Safety

### What to Review
CPIs extend the calling program's authority to the callee. This is high-risk.

```rust
// Safe CPI: invoke SPL Token transfer with PDA signer
let transfer_ix = spl_token::instruction::transfer(
    &spl_token::id(),
    source,
    destination,
    pda_authority,
    &[],
    amount,
)?;

invoke_signed(
    &transfer_ix,
    &[source_info, destination_info, authority_info, token_program_info],
    &[&[b"authority", &[bump]]],  // PDA seeds
)?;
```

### Checklist
- [ ] CPI target program ID is validated (hardcoded or whitelisted)
- [ ] `invoke_signed` seeds match expected PDA
- [ ] Account infos passed to CPI are the correct accounts (not attacker-swapped)
- [ ] Token program ID validated: `*token_program.key == spl_token::id()`
- [ ] No user-controlled program IDs in `invoke_signed`
- [ ] Return data from CPI validated if used

---

## Step 6: Integer Arithmetic Safety

### What to Review
Rust release mode wraps on overflow. This is the default for Solana programs built with `cargo build-sbf`.

### Checklist
- [ ] All arithmetic uses `checked_add`, `checked_sub`, `checked_mul`, `checked_div`
- [ ] Division-by-zero guarded (denominator checked before division)
- [ ] Casting narrowing checked (u128 → u64 validated)
- [ ] Fee calculations: multiplication before division to minimize rounding loss
- [ ] `Cargo.toml` has `overflow-checks = true` in `[profile.release]` (recommended)
- [ ] Token amounts handle different decimal precisions (6 vs 9 vs 18)

---

## Step 7: Account Closing & Lifecycle

### What to Review
Improperly closed accounts can be reopened within the same transaction (revival attack).

```rust
// SAFE close pattern
pub fn process_close_account(accounts: &[AccountInfo]) -> ProgramResult {
    let account = next_account_info(&mut accounts.iter())?;
    let receiver = next_account_info(&mut accounts.iter())?;

    // Step 1: Transfer ALL lamports
    let lamports = account.lamports();
    **account.lamports.borrow_mut() = 0;
    **receiver.lamports.borrow_mut() += lamports;

    // Step 2: Zero ALL data (prevents revival with stale state)
    let mut data = account.data.borrow_mut();
    sol_memset(&mut data, 0, data.len());

    Ok(())
}
```

### Checklist
- [ ] All lamports transferred to receiver (balance = 0)
- [ ] All data zeroed after lamport transfer
- [ ] Discriminator zeroed (prevents type confusion after revival)
- [ ] Authority verified before allowing close
- [ ] No instructions after close that could refund lamports

---

## Step 8: Error Handling & Edge Cases

### What to Review
Missing error handling in native programs causes silent failures.

### Checklist
- [ ] Every `ProgramResult` return path is handled (no silent `Ok(())`)
- [ ] `next_account_info` failure returns meaningful error
- [ ] Deserialization failures caught (Borsh errors)
- [ ] All `if` checks have corresponding `return Err()`
- [ ] No unwrap() on production paths (use `ok_or(ProgramError::...)?`)
- [ ] Custom error codes defined for debugging ( `impl From<CustomError> for ProgramError`)

---

## Step 9: Token Operations (SPL Token / Token-2022)

### What to Review
Token operations are the most common CPI target. Verify correct handling.

### Checklist
- [ ] Token mint authority verified before minting
- [ ] Token account owner matches expected user
- [ ] Correct token program used (SPL Token vs Token-2022)
- [ ] Token-2022 transfer hooks handled (if applicable)
- [ ] Decimal precision consistent across calculations
- [ ] Associated Token Accounts (ATAs) derived correctly
- [ ] Approval amounts validated (no unlimited approvals without user consent)

---

## Step 10: Report & Documentation

### Native-Specific Report Considerations
- Flag EVERY missing validation check (these are security findings in native, but automatic in Anchor)
- Severity: Missing owner check = CRITICAL, Missing signer = CRITICAL, Missing discriminator = HIGH
- Recommend migration to Anchor for new code with extensive account validation needs
- Document the manual validation matrix:

```
| Account | Owner ✓ | Signer ✓ | Writable ✓ | PDA ✓ | Type ✓ | Relationship ✓ |
|---------|---------|----------|------------|-------|--------|-----------------|
| vault   | ✓       |          | ✓          | ✓     | ✓      | has owner       |
| user    |         | ✓        |            |       |        |                 |
| token   | Token   |          | ✓          |       | ✓      | has mint        |
| system  | System  |          |            |       |        |                 |
```

---

## Related Files

- [Anchor Audit Workflow](anchor-audit.md) — Framework-based audit (most checks are automatic)
- [Solana Patterns](../resources/solana-patterns.md) — Vulnerability pattern reference with code
- [Account Validation](../resources/account-validation.md) — Validation check details
- [Anchor Security](../resources/anchor-security.md) — Anchor-specific vulnerabilities
