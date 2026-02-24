---
id: SOLANA-PATTERNS
title: Solana Vulnerability Patterns
category: solana-scanner
difficulty: advanced
triggers:
  - solana vulnerability patterns
  - solana security issues
  - solana exploit patterns
  - PDA vulnerability
  - CPI attack
related_skills:
  - solana-scanner/resources/account-validation.md
  - solana-scanner/resources/anchor-security.md
  - solana-scanner/workflows/anchor-audit.md
  - solana-scanner/workflows/native-audit.md
tags:
  - solana
  - rust
  - anchor
  - patterns
last_updated: 2026-02-24
---

# Solana Vulnerability Patterns

> **For AI Assistants**: Use these patterns to identify vulnerabilities in Solana programs. Each pattern includes vulnerable code, secure code, and detection guidance.

---

## 1. Missing Owner Check (CRITICAL)

**Impact**: Attacker passes a fake account owned by a different program, allowing arbitrary data injection.

**Root cause**: Solana accounts can be owned by any program. Without verifying `account.owner == expected_program_id`, a malicious account with crafted data can be accepted.

### Vulnerable Code (Native)
```rust
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;

    // BUG: No owner check on vault — attacker can pass a fake account
    // owned by their own program with crafted VaultData
    let mut vault_data = VaultData::unpack(&vault.data.borrow())?;

    // Attacker controls vault_data.authority, so this check passes
    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }

    **vault.lamports.borrow_mut() -= amount;
    **authority.lamports.borrow_mut() += amount;
    Ok(())
}
```

### Secure Code
```rust
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;

    // FIX: Verify the vault account is owned by THIS program
    if vault.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut vault_data = VaultData::unpack(&vault.data.borrow())?;
    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }

    **vault.lamports.borrow_mut() -= amount;
    **authority.lamports.borrow_mut() += amount;
    Ok(())
}
```

### Anchor Equivalent
```rust
// Anchor automatically checks owner via Account<'info, T>
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, VaultData>, // owner check automatic
    pub authority: Signer<'info>,
}
```

**Real-world**: Cashio ($48M, March 2022) — missing account validation on `bank` and `collateral` accounts allowed attacker to pass fake accounts with crafted data, minting unlimited CASH tokens.

---

## 2. Missing Signer Check (CRITICAL)

**Impact**: Unauthorized users can execute privileged operations (withdrawals, admin functions).

### Vulnerable Code
```rust
pub fn process_set_admin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_admin: Pubkey,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let config = next_account_info(account_iter)?;
    let admin = next_account_info(account_iter)?;

    let mut config_data = Config::unpack(&config.data.borrow())?;
    if config_data.admin != *admin.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // BUG: Never checks admin.is_signer
    // Anyone can pass admin's pubkey without signing
    config_data.admin = new_admin;
    Config::pack(config_data, &mut config.data.borrow_mut())?;
    Ok(())
}
```

### Secure Code
```rust
pub fn process_set_admin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_admin: Pubkey,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let config = next_account_info(account_iter)?;
    let admin = next_account_info(account_iter)?;

    // FIX: Verify admin actually signed this transaction
    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut config_data = Config::unpack(&config.data.borrow())?;
    if config_data.admin != *admin.key {
        return Err(ProgramError::InvalidAccountData);
    }

    config_data.admin = new_admin;
    Config::pack(config_data, &mut config.data.borrow_mut())?;
    Ok(())
}
```

**Real-world**: Wormhole ($320M, Feb 2022) — deprecated `verify_signatures` instruction accepted a spoofed sysvar account without proper signer verification, allowing the attacker to fabricate guardian signatures and mint 120,000 wETH.

---

## 3. PDA Seed Confusion (CRITICAL)

**Impact**: Using incorrect or insufficient seeds creates PDA collisions or allows access to another user's data.

### Vulnerable Code
```rust
// BUG: PDA seeds don't include user key — all users share one vault
let (vault_pda, bump) = Pubkey::find_program_address(
    &[b"vault"],  // Missing: user.key().as_ref()
    program_id,
);

// Another BUG: Seeds lack uniqueness — attacker creates conflicting PDA
let (config_pda, _) = Pubkey::find_program_address(
    &[b"config", pool_id.to_le_bytes().as_ref()],
    program_id,
);
// If pool_id is user-controlled, attacker crafts pool_id to collide
```

### Secure Code
```rust
// FIX: Include all disambiguating data in seeds
let (vault_pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref(), mint.key().as_ref()],
    program_id,
);

// Then VERIFY the account matches
if *vault_account.key != vault_pda {
    return Err(ProgramError::InvalidSeeds);
}
```

### Anchor Equivalent
```rust
#[account(
    seeds = [b"vault", user.key().as_ref(), mint.key().as_ref()],
    bump = vault.bump,
)]
pub vault: Account<'info, VaultData>,
```

**Detection**: Check that every PDA derivation includes sufficient seeds to prevent collisions. Seeds should include the user's pubkey for user-specific data.

---

## 4. Integer Overflow in Release Mode (CRITICAL)

**Impact**: Rust release builds wrap on integer overflow (no panic). Arithmetic that overflows silently produces wrong values, enabling theft.

### Vulnerable Code
```rust
pub fn process_deposit(amount: u64, fee_bps: u64) -> ProgramResult {
    // BUG: In release mode, if amount * fee_bps > u64::MAX, this wraps
    let fee = amount * fee_bps / 10_000;
    let net_amount = amount - fee;

    // BUG: If amount < fee due to rounding, this wraps to u64::MAX
    vault_data.balance += net_amount;
    Ok(())
}
```

### Secure Code
```rust
pub fn process_deposit(amount: u64, fee_bps: u64) -> ProgramResult {
    // FIX: Use checked arithmetic for all operations
    let fee = amount
        .checked_mul(fee_bps).ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(10_000).ok_or(ProgramError::ArithmeticOverflow)?;

    let net_amount = amount
        .checked_sub(fee).ok_or(ProgramError::ArithmeticOverflow)?;

    vault_data.balance = vault_data.balance
        .checked_add(net_amount).ok_or(ProgramError::ArithmeticOverflow)?;
    Ok(())
}
```

**Note**: Anchor programs using `require!` and Rust's default behavior still wrap in release mode. Always use `checked_*` methods or enable `overflow-checks = true` in `Cargo.toml`:
```toml
[profile.release]
overflow-checks = true
```

---

## 5. Account Revival / Resurrection (CRITICAL)

**Impact**: A closed account (lamports zeroed) can be reopened within the same transaction by a subsequent instruction, bypassing closure logic.

### Vulnerable Code
```rust
pub fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = next_account_info(&mut accounts.iter())?;
    let receiver = next_account_info(&mut accounts.iter())?;

    // Transfer lamports to receiver
    **receiver.lamports.borrow_mut() += vault.lamports();
    **vault.lamports.borrow_mut() = 0;

    // BUG: Data not zeroed — account still contains valid data
    // Another instruction in the same tx can refund lamports
    // and use the account as if it were never closed
    Ok(())
}
```

### Secure Code
```rust
pub fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = next_account_info(&mut accounts.iter())?;
    let receiver = next_account_info(&mut accounts.iter())?;

    // Transfer lamports
    **receiver.lamports.borrow_mut() += vault.lamports();
    **vault.lamports.borrow_mut() = 0;

    // FIX: Zero all data to prevent deserialization if account is revived
    let mut data = vault.data.borrow_mut();
    for byte in data.iter_mut() {
        *byte = 0;
    }
    // Alternative: sol_memset(&mut data, 0, data.len());
    Ok(())
}
```

**Anchor**: Use `#[account(close = receiver)]` which automatically zeroes data and drains lamports.

---

## 6. CPI Privilege Escalation (HIGH)

**Impact**: When a program performs `invoke_signed()`, the PDA signer authority extends to the callee. If the callee is user-controlled, the attacker's program inherits signing authority.

### Vulnerable Code
```rust
pub fn process_execute(
    accounts: &[AccountInfo],
    data: Vec<u8>,
) -> ProgramResult {
    let pda_authority = next_account_info(&mut accounts.iter())?;
    let target_program = next_account_info(&mut accounts.iter())?;

    // BUG: CPI to user-provided program with PDA signer authority
    // Attacker passes their malicious program as target_program
    let ix = Instruction {
        program_id: *target_program.key,
        accounts: vec![AccountMeta::new(*pda_authority.key, true)],
        data,
    };
    invoke_signed(
        &ix,
        &[pda_authority.clone()],
        &[&[b"authority", &[bump]]],
    )?;
    Ok(())
}
```

### Secure Code
```rust
pub fn process_execute(
    accounts: &[AccountInfo],
    data: Vec<u8>,
) -> ProgramResult {
    let pda_authority = next_account_info(&mut accounts.iter())?;
    let target_program = next_account_info(&mut accounts.iter())?;

    // FIX: Whitelist allowed CPI targets
    let allowed = [spl_token::id(), system_program::id()];
    if !allowed.contains(target_program.key) {
        return Err(ProgramError::InvalidArgument);
    }

    let ix = Instruction {
        program_id: *target_program.key,
        accounts: vec![AccountMeta::new(*pda_authority.key, true)],
        data,
    };
    invoke_signed(&ix, &[pda_authority.clone()], &[&[b"authority", &[bump]]])?;
    Ok(())
}
```

---

## 7. Duplicate Account Injection (HIGH)

**Impact**: Passing the same account for two different parameters causes double-counting, double-crediting, or self-referential state corruption.

### Vulnerable Code
```rust
pub fn process_transfer(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from = next_account_info(&mut accounts.iter())?;
    let to = next_account_info(&mut accounts.iter())?;

    // BUG: If from == to, balance is unchanged but event fires
    // Or worse: in RefCell-based accounting, the second borrow_mut panics
    let mut from_data = TokenAccount::unpack(&from.data.borrow())?;
    let mut to_data = TokenAccount::unpack(&to.data.borrow())?;

    from_data.amount -= amount;
    to_data.amount += amount;

    TokenAccount::pack(from_data, &mut from.data.borrow_mut())?;
    TokenAccount::pack(to_data, &mut to.data.borrow_mut())?; // Overwrites the subtraction!
    Ok(())
}
```

### Secure Code
```rust
pub fn process_transfer(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from = next_account_info(&mut accounts.iter())?;
    let to = next_account_info(&mut accounts.iter())?;

    // FIX: Check accounts are distinct
    if from.key == to.key {
        return Err(ProgramError::InvalidArgument);
    }

    let mut from_data = TokenAccount::unpack(&from.data.borrow())?;
    let mut to_data = TokenAccount::unpack(&to.data.borrow())?;
    from_data.amount -= amount;
    to_data.amount += amount;
    TokenAccount::pack(from_data, &mut from.data.borrow_mut())?;
    TokenAccount::pack(to_data, &mut to.data.borrow_mut())?;
    Ok(())
}
```

---

## 8. Type Confusion / Missing Discriminator (HIGH)

**Impact**: Account data deserialized as the wrong type, misinterpreting fields. An attacker creates an account of type A and passes it where type B is expected.

### Vulnerable Code
```rust
// BUG: No discriminator check — any Borsh-compatible data accepted
let vault_data: VaultData = VaultData::try_from_slice(&account.data.borrow())?;
// If account actually contains UserData, fields misalign:
// VaultData.authority = UserData.amount (treated as pubkey!)
```

### Secure Code
```rust
// FIX: Check 8-byte discriminator before deserializing
let data = account.data.borrow();
if data.len() < 8 || data[..8] != VaultData::DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
let vault_data = VaultData::try_from_slice(&data[8..])?;
```

**Anchor**: Automatic — `Account<'info, VaultData>` checks the 8-byte discriminator (SHA256("account:VaultData")[..8]).

---

## 9. Rent Exemption Drain (HIGH)

**Impact**: Reducing an account's lamport balance below the rent-exempt minimum causes the runtime to delete the account at the end of the epoch, destroying its data.

### Detection
```rust
// Check: Does any instruction reduce account lamports?
// If so, verify remaining balance >= rent-exempt minimum
let rent = Rent::get()?;
let min_balance = rent.minimum_balance(account.data_len());
let remaining = account.lamports() - withdrawal_amount;
if remaining < min_balance && remaining != 0 {
    return Err(ProgramError::InsufficientFunds);
}
// Note: remaining == 0 is valid (account closure)
```

---

## 10. Clock Sysvar Manipulation (MEDIUM)

**Impact**: Using `Clock::get()?.unix_timestamp` for randomness is predictable. Validators can influence `slot` values within bounds.

### Vulnerable Code
```rust
// BUG: Deterministic "randomness" — validators can predict/influence
let clock = Clock::get()?;
let random_seed = clock.unix_timestamp as u64 ^ clock.slot;
let winner_index = random_seed % participants.len() as u64;
```

### Secure Code
```rust
// FIX: Use Switchboard VRF or similar on-chain verifiable randomness
// Or at minimum, include recent blockhash (still validator-influenceable)
let recent_slothash = get_recent_slothash()?;
// For true randomness, use Switchboard Oracle or drand integration
```

---

## 11. Remaining Accounts Injection (MEDIUM)

**Impact**: The `remaining_accounts` vector in Anchor (or extra accounts in native) is not validated, allowing injection of malicious accounts.

### Vulnerable Code
```rust
// BUG: Iterating remaining_accounts without validation
for account in ctx.remaining_accounts.iter() {
    // Assumes these are all valid token accounts
    let token_data = TokenAccount::unpack(&account.data.borrow())?;
    total += token_data.amount;
}
```

### Secure Code
```rust
// FIX: Validate every remaining account
for account in ctx.remaining_accounts.iter() {
    // Check owner is Token program
    if account.owner != &spl_token::id() {
        return Err(ErrorCode::InvalidAccount.into());
    }
    // Check mint matches expected
    let token_data = TokenAccount::unpack(&account.data.borrow())?;
    if token_data.mint != ctx.accounts.expected_mint.key() {
        return Err(ErrorCode::InvalidMint.into());
    }
    total += token_data.amount;
}
```

---

## 12. Bump Seed Canonicality (MEDIUM)

**Impact**: `find_program_address` tries bumps from 255 down to 0, returning the first valid one (canonical bump). If a program accepts any bump, two different PDAs can derive for the same seeds.

### Vulnerable Code
```rust
// BUG: Accepts user-provided bump without verifying it's canonical
let (pda, _) = Pubkey::create_program_address(
    &[b"vault", user.key().as_ref(), &[user_provided_bump]],
    program_id,
)?;
```

### Secure Code
```rust
// FIX: Always use find_program_address which returns canonical bump
let (pda, canonical_bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id,
);
// OR: Store bump on first init and reuse
// #[account(seeds = [...], bump = vault.bump)]
```

---

## 13. Instruction Introspection Bypass (MEDIUM)

**Impact**: Programs that check adjacent instructions (e.g., "a swap must follow a deposit") can be bypassed by crafting transaction ordering.

### Detection
```rust
// Look for: sysvar::instructions usage
let ixs = load_instruction_at_checked(index, &sysvar_info)?;
// Verify: Are ALL relevant instructions checked, or just one?
// Verify: Is the program_id of the adjacent instruction validated?
// Attack: Attacker can insert a no-op instruction that satisfies the check
```

---

## Real-World Exploits

| Protocol | Loss | Pattern | Year | Details |
|----------|------|---------|------|---------|
| Wormhole | $320M | Missing signer check (#2) | 2022 | Deprecated `verify_signatures` accepted spoofed sysvar; attacker minted 120K wETH |
| Cashio | $48M | Missing owner check (#1) | 2022 | Fake bank/collateral accounts; unlimited CASH minting |
| Mango Markets | $114M | Oracle manipulation | 2022 | Manipulated MNGO perp price to borrow against inflated collateral |
| Crema Finance | $8.8M | Fake tick account (#1) | 2022 | Fake Concentrated Liquidity tick account accepted without owner check |
| Slope Wallet | $4.1M | Key exposure (off-chain) | 2022 | Private keys logged to Sentry server; not a program bug |
| Solend | $1.26M | Oracle staleness | 2022 | Stale Pyth oracle price allowed undercollateralized borrows |

---

## Audit Checklist

### Critical Checks (Must Pass)
- [ ] Every account has owner validation (native) or correct `Account<>` type (Anchor)
- [ ] Every privileged account has signer check
- [ ] All PDA derivations include sufficient seeds for uniqueness
- [ ] All arithmetic uses `checked_*` methods or `overflow-checks = true`
- [ ] Closed accounts have data zeroed

### High Checks
- [ ] CPI targets are whitelisted or validated
- [ ] No duplicate accounts in instruction parameters
- [ ] Account discriminators checked (native programs)
- [ ] Rent-exempt minimum maintained after withdrawals
- [ ] Canonical bump seeds used for all PDAs

### Medium Checks
- [ ] `remaining_accounts` validated when used
- [ ] Clock sysvar not used for randomness
- [ ] Instruction introspection validates program IDs
- [ ] Token-2022 transfer hooks and extensions handled

---

## Related Files

- [Account Validation Patterns](account-validation.md) — Detailed validation check reference
- [Anchor Security Guide](anchor-security.md) — Anchor-specific vulnerability patterns
- [Anchor Audit Workflow](../workflows/anchor-audit.md) — Step-by-step Anchor audit process
- [Native Audit Workflow](../workflows/native-audit.md) — Step-by-step native Solana audit process
