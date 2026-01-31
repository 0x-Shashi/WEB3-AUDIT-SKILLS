---
id: CHAIN-SOLANA
title: Solana Security Guide
category: chain-guides
chain: solana
difficulty: advanced
tags: [solana, account-model, pda, cpi, anchor, spl]
related_exploits: [wormhole-2022, mango-2022, cashio-2022]
last_updated: 2026-01-31
---

# Solana Security Guide

## Overview

Solana uses a fundamentally different programming model than EVM chains. Security vulnerabilities often stem from misunderstanding the account model, improper account validation, or unsafe Cross-Program Invocations (CPI).

## Key Differences from EVM

| Aspect | Ethereum | Solana |
|--------|----------|--------|
| State Storage | Contract storage | External accounts |
| Program Model | Stateful contracts | Stateless programs |
| Execution | Sequential | Parallel |
| Account Model | Implicit | Explicit accounts passed |
| Signatures | tx.origin, msg.sender | Signers passed explicitly |

## Critical Vulnerability Categories

### 1. Missing Account Validation

**The Most Common Solana Vulnerability**

Every account passed to a Solana program must be validated:
- Ownership (which program owns this account?)
- Type (is the data the expected format?)
- Authority (who can modify this account?)
- Relationships (does A correctly reference B?)

```rust
// VULNERABLE - No validation
pub fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let user_account = &accounts[0];
    let vault_account = &accounts[1];  // Could be ANY account!
    
    // Transfers without checking vault ownership
    **vault_account.lamports.borrow_mut() -= amount;
    **user_account.lamports.borrow_mut() += amount;
    
    Ok(())
}
```

```rust
// SECURE - Full validation
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64
) -> ProgramResult {
    let user_account = &accounts[0];
    let vault_account = &accounts[1];
    
    // Check 1: Vault is owned by this program
    if vault_account.owner != program_id {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // Check 2: Vault is the expected PDA
    let (expected_vault, _bump) = Pubkey::find_program_address(
        &[b"vault", user_account.key.as_ref()],
        program_id
    );
    if vault_account.key != &expected_vault {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Check 3: User is a signer
    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Now safe to transfer
    **vault_account.lamports.borrow_mut() -= amount;
    **user_account.lamports.borrow_mut() += amount;
    
    Ok(())
}
```

### 2. PDA (Program Derived Address) Vulnerabilities

PDAs are addresses derived from seeds. Common issues:

```rust
// VULNERABLE - Predictable seeds allow collision
let (pda, bump) = Pubkey::find_program_address(
    &[b"user_data"],  // Same for all users!
    program_id
);

// SECURE - Include unique identifiers
let (pda, bump) = Pubkey::find_program_address(
    &[
        b"user_data",
        user_pubkey.as_ref(),
        &[unique_nonce]
    ],
    program_id
);
```

**Bump Seed Canonicalization:**
```rust
// VULNERABLE - Accepts any bump
pub struct UserAccount {
    pub bump: u8,  // Stored bump could be non-canonical
}

// SECURE - Always use canonical bump
let (pda, canonical_bump) = Pubkey::find_program_address(seeds, program_id);
// Store and verify canonical_bump only
```

### 3. CPI (Cross-Program Invocation) Vulnerabilities

**Arbitrary CPI:**
```rust
// VULNERABLE - Attacker controls target program
pub fn forward_call(target_program: AccountInfo, data: &[u8]) -> ProgramResult {
    invoke(&Instruction {
        program_id: *target_program.key,  // Attacker controlled!
        accounts: vec![],
        data: data.to_vec(),
    }, &[])?;
    Ok(())
}
```

**CPI Privilege Escalation:**
```rust
// VULNERABLE - Passing signer privilege unsafely
invoke_signed(
    &instruction,
    &[user_account.clone()],
    &[&[b"authority", &[bump]]]  // PDA signs
)?;
// If instruction is attacker-controlled, they gain PDA authority
```

### 4. Signer Verification

```rust
// VULNERABLE - Missing signer check
pub fn admin_withdraw(admin: AccountInfo, vault: AccountInfo) -> ProgramResult {
    // No check that admin actually signed!
    transfer_tokens(&vault, &admin, vault.lamports())?;
    Ok(())
}

// SECURE
pub fn admin_withdraw(admin: AccountInfo, vault: AccountInfo) -> ProgramResult {
    // Verify signer
    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Verify admin is authorized
    if admin.key != &ADMIN_PUBKEY {
        return Err(ProgramError::InvalidAccountData);
    }
    
    transfer_tokens(&vault, &admin, vault.lamports())?;
    Ok(())
}
```

### 5. Account Reinitialization

```rust
// VULNERABLE - Can reinitialize existing account
pub fn initialize(account: AccountInfo) -> ProgramResult {
    let mut data = account.data.borrow_mut();
    let user_data = UserData::unpack(&data)?;
    
    // No check if already initialized!
    user_data.owner = new_owner;
    user_data.balance = 0;
    
    UserData::pack(user_data, &mut data)?;
    Ok(())
}

// SECURE
pub fn initialize(account: AccountInfo) -> ProgramResult {
    let mut data = account.data.borrow_mut();
    let user_data = UserData::unpack(&data)?;
    
    // Check initialization flag
    if user_data.is_initialized {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    user_data.is_initialized = true;
    user_data.owner = new_owner;
    user_data.balance = 0;
    
    UserData::pack(user_data, &mut data)?;
    Ok(())
}
```

### 6. Type Confusion

```rust
// VULNERABLE - Account type not verified
pub fn process(account: AccountInfo) -> ProgramResult {
    // Deserializing without type check
    let data: UserData = borsh::from_slice(&account.data.borrow())?;
    // Could be a completely different account type!
}

// SECURE - Include type discriminator
#[derive(BorshDeserialize, BorshSerialize)]
pub struct UserData {
    pub discriminator: [u8; 8],  // Unique identifier
    pub owner: Pubkey,
    pub balance: u64,
}

pub fn process(account: AccountInfo) -> ProgramResult {
    let data: UserData = borsh::from_slice(&account.data.borrow())?;
    
    // Verify discriminator
    if data.discriminator != USER_DATA_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
}
```

## Anchor Framework Security

Anchor provides automatic checks, but must be used correctly:

```rust
// ANCHOR SECURE PATTERN
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Ownership check: must be owned by this program
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump,
        has_one = user,  // Relationship check
    )]
    pub vault: Account<'info, Vault>,
    
    // Signer check: must have signed
    #[account(mut)]
    pub user: Signer<'info>,
    
    // Type check: must be system program
    pub system_program: Program<'info, System>,
}
```

### Anchor Pitfalls

```rust
// PITFALL 1: Using AccountInfo bypasses checks
pub remaining_accounts: &[AccountInfo<'info>],  // NOT validated!

// PITFALL 2: init without proper space
#[account(init, payer = user, space = 8)]  // Too small!

// PITFALL 3: Unchecked account with UncheckedAccount
pub dangerous: UncheckedAccount<'info>,  // No validation!
```

## SPL Token Security

```rust
// COMMON SPL TOKEN ISSUES

// 1. Missing token account ownership check
// Verify token account is owned by Token program
assert_eq!(token_account.owner, &spl_token::ID);

// 2. Missing mint verification
// Verify token account's mint matches expected
let account_data = TokenAccount::unpack(&token_account.data.borrow())?;
assert_eq!(account_data.mint, expected_mint);

// 3. Authority verification
// Verify authority can sign for this token account
assert_eq!(account_data.owner, authority.key());
assert!(authority.is_signer);
```

## Real Exploits Reference

| Exploit | Vulnerability | Loss |
|---------|---------------|------|
| [Wormhole](../exploit-forensics/wormhole-2022.md) | Signature verification bypass | $326M |
| [Cashio](../exploit-forensics/cashio-2022.md) | Missing nested account validation | $52M |
| [Mango Markets](../exploit-forensics/mango-2022.md) | Oracle manipulation | $114M |

## Audit Checklist

```
[ ] All accounts have ownership checks
[ ] All accounts have type/discriminator checks
[ ] All required signers are verified
[ ] PDAs use canonical bumps
[ ] PDAs have unique, non-guessable seeds
[ ] CPI targets are validated
[ ] CPI privileges are not escalated
[ ] Accounts cannot be reinitialized
[ ] Token accounts verified (mint, owner)
[ ] No remaining_accounts used unsafely
[ ] Anchor constraints are complete
```

## Tools

- **Soteria** - Static analyzer for Solana programs
- **Anchor test** - Built-in testing framework
- **Solana Program Library (SPL)** - Reference implementations
