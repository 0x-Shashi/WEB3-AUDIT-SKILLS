# Solana Security Guide

## Chain Overview

- **Type:** L1 (Proof of History + Proof of Stake)
- **Language:** Rust (Anchor framework) / Native
- **Account Model:** Account-based (not contract storage)
- **Finality:** ~400ms (optimistic), ~13s (confirmed)
- **Fee Token:** SOL

## Key Security Considerations

### 1. Account Model (Critical Difference from EVM!)
Solana uses an account model fundamentally different from EVM:

```
- Data lives in ACCOUNTS, not inside contracts
- Programs (smart contracts) are STATELESS
- Programs read/write to accounts passed as instruction parameters
- Accounts have owners (programs that can modify them)
- Each account has: owner, data, lamports, executable flag
```

**Audit implications:**
- All accounts used must be passed explicitly in the transaction
- Account ownership MUST be validated (anyone can pass any account)
- Account data structure MUST be validated (deserialization attacks)

### 2. Missing Account Validation (Top Vulnerability)
```rust
// [VULNERABLE] Not checking account owner
pub fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    // MISSING: Check that vault is owned by THIS program!
    // Attacker can pass their own account with fake data
    let vault_data: VaultData = VaultData::unpack(&vault.data.borrow())?;
    // ...
}

// [SAFE] With Anchor framework
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        has_one = owner,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, VaultData>,  // Anchor validates owner + type
    pub owner: Signer<'info>,
}
```

### 3. Program Derived Addresses (PDAs)
```rust
// PDAs are addresses derived from seeds + program ID
// They have no private key - only the program can sign for them

// [VULNERABLE] Not validating PDA derivation
let (expected_pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id,
);
// MUST check: vault_account.key() == expected_pda

// [VULNERABLE] Bump seed not validated
// Attacker can use different bump to derive different address
```

### 4. Cross-Program Invocation (CPI)
```rust
// Programs call other programs via CPI
// Risks:
// - Invoking wrong program (program ID not validated)
// - Privilege escalation through signed CPI
// - Reentrancy via CPI callbacks

// [VULNERABLE] Not verifying target program
invoke(
    &instruction,
    &[account1.clone(), account2.clone()],
)?;
// What if the instruction targets a malicious program?
```

### 5. Signer Validation
```rust
// [VULNERABLE] Not checking if account is a signer
pub fn process_admin_action(accounts: &[AccountInfo]) -> ProgramResult {
    let admin = &accounts[0];
    // MISSING: require!(admin.is_signer)
    // Anyone can pass the admin pubkey without signing!
}
```

### 6. Integer Overflow/Underflow
- Rust panics on overflow in debug mode
- In release mode, Rust WRAPS around (silent overflow!)
- Solana programs compile in release mode
- **Must use:** `checked_add`, `checked_sub`, `checked_mul`

### 7. Closing Accounts
```rust
// [VULNERABLE] Account not properly closed
// Attacker can "revive" a closed account by:
// 1. Account is zeroed but lamports sent somewhere
// 2. In same transaction, attacker sends lamports back
// 3. Account data is still in memory for the transaction

// [SAFE] Use Anchor's close constraint or zero out ALL data + transfer ALL lamports
```

## Solana-Specific Audit Checklist

- [ ] All accounts validated (owner, type, seeds, bump)
- [ ] PDAs derived with correct seeds and bump validated
- [ ] Signer checks on all privileged accounts
- [ ] Integer arithmetic uses checked_* methods
- [ ] CPI: target program ID validated
- [ ] Account closing: data zeroed AND lamports drained
- [ ] Duplicate accounts in instruction checked
- [ ] Type confusion: account data properly deserialized
- [ ] Rent exemption: accounts maintain minimum balance
- [ ] Clock/Slot: not used as reliable randomness source
- [ ] Reentrancy via CPI considered
- [ ] Token program: correct program ID (Token vs Token-2022)

## Common Vulnerabilities on Solana

| Vulnerability | Description | Example |
|--------------|-------------|---------|
| Missing owner check | Account ownership not validated | Wormhole ($320M) |
| PDA confusion | Wrong seeds or bump for PDA derivation | Multiple protocols |
| Missing signer check | Privileged action without signature | Cashio ($48M) |
| Integer overflow | Unchecked arithmetic in release mode | Common pattern |
| Account reuse | Closed accounts revived in same tx | Common pattern |
| CPI privilege escalation | Signed CPI grants unintended authority | Various |
