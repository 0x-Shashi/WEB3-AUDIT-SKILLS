# Solana Account Validation Patterns

## Required Checks for Every Account

### 1. Owner Check
```rust
// Every account MUST be checked for correct owner
if vault_account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}

// Anchor: Automatic via Account<'info, T>
#[account(owner = program_id)]
pub vault: Account<'info, VaultData>,
```

### 2. Signer Check
```rust
// Privileged accounts must be signers
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}

// Anchor: Signer<'info>
pub authority: Signer<'info>,
```

### 3. PDA Derivation
```rust
// Validate PDA matches expected seeds
let (expected, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id,
);
if vault.key() != expected {
    return Err(ProgramError::InvalidSeeds);
}

// Anchor: seeds + bump constraint
#[account(seeds = [b"vault", user.key().as_ref()], bump)]
pub vault: Account<'info, VaultData>,
```

### 4. Account Data Type
```rust
// Verify account contains expected data type
// Check discriminator (first 8 bytes in Anchor)
let data = vault.try_borrow_data()?;
if data[..8] != VaultData::DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

### 5. has_one Relationships
```rust
// Anchor: Verify relationships between accounts
#[account(has_one = owner, has_one = mint)]
pub vault: Account<'info, VaultData>,
pub owner: Signer<'info>,
pub mint: Account<'info, Mint>,
```

## Common Bypass Attacks
| Attack | Missing Check | Impact |
|--------|--------------|--------|
| Fake account injection | Owner check | Read/write arbitrary data |
| Unauthorized action | Signer check | Steal funds |
| Wrong PDA | Seed validation | Access wrong vault |
| Type confusion | Discriminator | Misinterpret data |
