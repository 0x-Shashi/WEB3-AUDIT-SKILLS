# Anchor Security Guide

Security best practices and common pitfalls when using the Anchor framework.

---

## Anchor Security Fundamentals

### Account Type Hierarchy

```
                    AccountInfo<'info>
                          
                           (raw, no validation)
                          
    
                                             
                                             
UncheckedAccount              Account<'info, T>
(explicitly unchecked)        (validated + deserialized)
                                     
                    
                                                    
            Signer<'info>    Program<'info, T>  SystemAccount
            (is_signer)      (executable)       (system owned)
```

### Security Level by Type

| Type | Owner Check | Type Check | Signer | Use Case |
|------|-------------|------------|--------|----------|
| `AccountInfo` |  |  |  | Avoid - raw access |
| `UncheckedAccount` |  |  |  | Explicit bypass |
| `Account<T>` |  |  |  | Data accounts |
| `Signer` |  |  |  | Authority accounts |
| `Program<T>` |  |  |  | Program accounts |
| `SystemAccount` |  |  |  | SOL-only accounts |

---

## Critical Anchor Patterns

### Pattern 1: Always Use Typed Accounts

**Bad:**
```rust
#[derive(Accounts)]
pub struct Vulnerable<'info> {
    pub pool: AccountInfo<'info>,  // NO validation!
}

pub fn process(ctx: Context<Vulnerable>) -> Result<()> {
    // Attacker can pass ANY account
    let pool = Pool::try_deserialize(&mut &ctx.accounts.pool.data.borrow()[..])?;
}
```

**Good:**
```rust
#[derive(Accounts)]
pub struct Secure<'info> {
    pub pool: Account<'info, Pool>,  // Validates owner + discriminator
}

pub fn process(ctx: Context<Secure>) -> Result<()> {
    // pool is guaranteed to be owned by program and be Pool type
    let pool = &ctx.accounts.pool;
}
```

---

### Pattern 2: Use `has_one` for Relationships

**Bad:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: Signer<'info>,
    pub pool: Account<'info, Pool>,  // Not linked to authority
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // Anyone can withdraw from any pool!
    // Need to manually check: pool.authority == authority.key()
}
```

**Good:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: Signer<'info>,
    
    #[account(
        has_one = authority,  // Ensures pool.authority == authority.key()
    )]
    pub pool: Account<'info, Pool>,
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // Automatically verified!
}
```

---

### Pattern 3: Use Seeds for PDAs

**Bad:**
```rust
#[derive(Accounts)]
pub struct AccessVault<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,  // Any vault can be passed!
}
```

**Good:**
```rust
#[derive(Accounts)]
pub struct AccessVault<'info> {
    pub user: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,  // Must be user's vault
}
```

---

### Pattern 4: Store and Verify Bumps

**Bad:**
```rust
#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub amount: u64,
    // Missing bump!
}

// Later, re-deriving bump is expensive
let (pda, bump) = Pubkey::find_program_address(&[...], program_id);
```

**Good:**
```rust
#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub amount: u64,
    pub bump: u8,  // Store bump for later use
}

#[derive(Accounts)]
pub struct UseVault<'info> {
    #[account(
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,  // Use stored bump
    )]
    pub vault: Account<'info, Vault>,
}
```

---

### Pattern 5: Use `Program<T>` for CPIs

**Bad:**
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    pub token_program: AccountInfo<'info>,  // Could be any account!
}

pub fn transfer(ctx: Context<Transfer>) -> Result<()> {
    // Attacker could pass malicious program
    invoke(
        &spl_token::instruction::transfer(...),
        &[...],
    )?;
}
```

**Good:**
```rust
use anchor_spl::token::{Token, Transfer};

#[derive(Accounts)]
pub struct DoTransfer<'info> {
    pub token_program: Program<'info, Token>,  // Verified to be Token program
}

pub fn transfer(ctx: Context<DoTransfer>) -> Result<()> {
    // token_program is verified
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer { ... },
    );
    token::transfer(cpi_ctx, amount)?;
}
```

---

## Anchor Constraint Reference

### Basic Constraints

```rust
#[derive(Accounts)]
pub struct Example<'info> {
    // Mutability
    #[account(mut)]
    pub mutable_account: Account<'info, Data>,
    
    // Initialization
    #[account(
        init,
        payer = payer,
        space = 8 + Data::LEN,
    )]
    pub new_account: Account<'info, Data>,
    
    // Close account
    #[account(
        mut,
        close = receiver,
    )]
    pub account_to_close: Account<'info, Data>,
}
```

### PDA Constraints

```rust
#[derive(Accounts)]
pub struct PdaExample<'info> {
    // PDA with seeds and bump
    #[account(
        seeds = [b"vault", user.key().as_ref()],
        bump,  // Let Anchor find bump
    )]
    pub vault: Account<'info, Vault>,
    
    // PDA with stored bump
    #[account(
        seeds = [b"pool"],
        bump = pool.bump,  // Use stored bump
    )]
    pub pool: Account<'info, Pool>,
    
    // Init PDA
    #[account(
        init,
        payer = payer,
        space = 8 + Vault::LEN,
        seeds = [b"vault", user.key().as_ref()],
        bump,
    )]
    pub new_vault: Account<'info, Vault>,
}
```

### Relationship Constraints

```rust
#[derive(Accounts)]
pub struct RelationshipExample<'info> {
    // has_one: account.field == other_account.key()
    #[account(has_one = authority)]
    pub pool: Account<'info, Pool>,
    
    pub authority: Signer<'info>,
    
    // has_one with custom error
    #[account(
        has_one = owner @ ErrorCode::InvalidOwner
    )]
    pub user_data: Account<'info, UserData>,
    
    pub owner: Signer<'info>,
}
```

### Custom Constraints

```rust
#[derive(Accounts)]
pub struct CustomExample<'info> {
    // Single constraint
    #[account(
        constraint = amount > 0 @ ErrorCode::InvalidAmount
    )]
    pub data: Account<'info, Data>,
    
    // Multiple constraints
    #[account(
        constraint = pool.is_active @ ErrorCode::PoolInactive,
        constraint = pool.balance > 0 @ ErrorCode::EmptyPool,
        constraint = pool.authority == authority.key() @ ErrorCode::InvalidAuthority,
    )]
    pub pool: Account<'info, Pool>,
    
    pub authority: Signer<'info>,
}
```

### Token Constraints

```rust
use anchor_spl::token::{Token, TokenAccount, Mint};

#[derive(Accounts)]
pub struct TokenExample<'info> {
    // Token account with owner check
    #[account(
        mut,
        constraint = user_token.owner == user.key(),
        constraint = user_token.mint == mint.key(),
    )]
    pub user_token: Account<'info, TokenAccount>,
    
    // Associated token account
    #[account(
        init_if_needed,
        payer = user,
        associated_token::mint = mint,
        associated_token::authority = user,
    )]
    pub user_ata: Account<'info, TokenAccount>,
    
    pub mint: Account<'info, Mint>,
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}
```

---

## Common Anchor Vulnerabilities

### Vuln 1: Using `AccountInfo` for Data Accounts

```rust
// VULNERABLE
pub pool: AccountInfo<'info>,  // No validation

// SECURE
pub pool: Account<'info, Pool>,  // Owner + type validated
```

### Vuln 2: Missing `has_one` Constraint

```rust
// VULNERABLE
pub pool: Account<'info, Pool>,  // Pool not linked to authority
pub authority: Signer<'info>,

// SECURE
#[account(has_one = authority)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,
```

### Vuln 3: Missing Seed Validation

```rust
// VULNERABLE
#[account(mut)]
pub vault: Account<'info, Vault>,  // Any vault accepted

// SECURE
#[account(
    mut,
    seeds = [b"vault", user.key().as_ref()],
    bump = vault.bump,
)]
pub vault: Account<'info, Vault>,  // Must be user's vault
```

### Vuln 4: Using `init` Without Size

```rust
// WILL FAIL - No space specified
#[account(init, payer = user)]
pub data: Account<'info, Data>,

// CORRECT
#[account(
    init,
    payer = user,
    space = 8 + Data::LEN,  // 8 for discriminator + struct size
)]
pub data: Account<'info, Data>,
```

### Vuln 5: Mutable Without `mut`

```rust
// VULNERABLE - Write will fail silently or panic
pub pool: Account<'info, Pool>,

// CORRECT
#[account(mut)]
pub pool: Account<'info, Pool>,
```

### Vuln 6: Signer Without Verification

```rust
// VULNERABLE - Not actually required to sign
pub authority: AccountInfo<'info>,

// SECURE
pub authority: Signer<'info>,
```

---

## Account Size Calculation

```rust
#[account]
pub struct Pool {
    pub authority: Pubkey,      // 32 bytes
    pub token_mint: Pubkey,     // 32 bytes
    pub total_deposited: u64,   // 8 bytes
    pub fee_rate: u16,          // 2 bytes
    pub is_active: bool,        // 1 byte
    pub bump: u8,               // 1 byte
}

impl Pool {
    pub const LEN: usize = 32 + 32 + 8 + 2 + 1 + 1;  // 76 bytes
}

// In context:
#[account(
    init,
    payer = payer,
    space = 8 + Pool::LEN,  // 8 (discriminator) + 76 = 84 bytes
)]
pub pool: Account<'info, Pool>,
```

### Common Type Sizes

| Type | Size (bytes) |
|------|--------------|
| bool | 1 |
| u8 / i8 | 1 |
| u16 / i16 | 2 |
| u32 / i32 | 4 |
| u64 / i64 | 8 |
| u128 / i128 | 16 |
| Pubkey | 32 |
| String | 4 + len |
| Vec<T> | 4 + (len * sizeof(T)) |
| Option<T> | 1 + sizeof(T) |

---

## CPI Security in Anchor

### Secure CPI Pattern

```rust
use anchor_spl::token::{self, Token, Transfer};

pub fn secure_transfer(ctx: Context<SecureTransfer>, amount: u64) -> Result<()> {
    // Build CPI context
    let cpi_accounts = Transfer {
        from: ctx.accounts.source.to_account_info(),
        to: ctx.accounts.destination.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    // Token program is typed - verified
    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
    
    // Execute CPI
    token::transfer(cpi_ctx, amount)?;
    
    Ok(())
}

#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    pub authority: Signer<'info>,
    
    #[account(
        mut,
        constraint = source.owner == authority.key(),
    )]
    pub source: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    
    // Typed program - automatically verified
    pub token_program: Program<'info, Token>,
}
```

### CPI with PDA Signer

```rust
pub fn pda_transfer(ctx: Context<PdaTransfer>, amount: u64) -> Result<()> {
    let pool = &ctx.accounts.pool;
    
    // Seeds for signing
    let seeds = &[
        b"pool".as_ref(),
        &[pool.bump],
    ];
    let signer_seeds = &[&seeds[..]];
    
    // CPI with signer
    let cpi_accounts = Transfer {
        from: ctx.accounts.pool_token.to_account_info(),
        to: ctx.accounts.user_token.to_account_info(),
        authority: ctx.accounts.pool.to_account_info(),
    };
    
    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );
    
    token::transfer(cpi_ctx, amount)?;
    
    Ok(())
}
```

---

## Error Handling Best Practices

```rust
#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access")]
    Unauthorized,
    
    #[msg("Invalid amount: must be greater than zero")]
    InvalidAmount,
    
    #[msg("Arithmetic overflow")]
    Overflow,
    
    #[msg("Pool is not active")]
    PoolInactive,
    
    #[msg("Invalid owner for token account")]
    InvalidOwner,
    
    #[msg("Mint mismatch")]
    MintMismatch,
    
    #[msg("Duplicate accounts not allowed")]
    DuplicateAccount,
}

// Usage in constraints
#[account(
    constraint = pool.is_active @ ErrorCode::PoolInactive,
    constraint = amount > 0 @ ErrorCode::InvalidAmount,
)]
pub pool: Account<'info, Pool>,
```

---

## Security Checklist

### Per-Instruction Checklist

- [ ] All data accounts use `Account<'info, T>` not `AccountInfo`
- [ ] Authority accounts use `Signer<'info>`
- [ ] Program accounts use `Program<'info, T>`
- [ ] PDAs have `seeds` and `bump` constraints
- [ ] Related accounts use `has_one`
- [ ] Mutable accounts marked `mut`
- [ ] Token accounts validate owner and mint
- [ ] Custom constraints have error codes
- [ ] No duplicate accounts possible
- [ ] Init accounts specify correct space

