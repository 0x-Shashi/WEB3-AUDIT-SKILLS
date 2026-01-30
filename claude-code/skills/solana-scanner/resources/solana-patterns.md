# Solana Vulnerability Patterns

Comprehensive database of Solana-specific vulnerability patterns with detection strategies.

---

## Account Validation Patterns

### Pattern AV-01: Missing Owner Check (Native)

**Risk Level:** Critical

**Description:** In native Solana programs, account ownership must be explicitly verified. Without this check, an attacker can pass accounts owned by other programs with arbitrary data.

**Detection Pattern:**
```
1. Find account deserialization (unpack, try_from_slice)
2. Check if account.owner == program_id verified before
3. Flag if missing
```

**Vulnerable:**
```rust
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let data = MyData::unpack(&account.data.borrow())?;  // No owner check!
    // ... use data
}
```

**Secure:**
```rust
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    
    if account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    let data = MyData::unpack(&account.data.borrow())?;
    // ... use data
}
```

---

### Pattern AV-02: Missing Signer Check

**Risk Level:** Critical

**Description:** Instructions that require authorization must verify that the appropriate account has signed the transaction.

**Detection Pattern:**
```
1. Find authority/admin operations
2. Check if account.is_signer verified
3. Flag if missing
```

**Vulnerable:**
```rust
pub fn admin_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let admin = &accounts[0];
    let vault = &accounts[1];
    
    // Missing: if !admin.is_signer { return Err(...) }
    
    // Anyone can call this pretending to be admin
    transfer_lamports(vault, admin, vault.lamports())?;
    Ok(())
}
```

**Secure:**
```rust
pub fn admin_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let admin = &accounts[0];
    let vault = &accounts[1];
    
    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    if admin.key != &ADMIN_PUBKEY {
        return Err(ProgramError::InvalidAccountData);
    }
    
    transfer_lamports(vault, admin, vault.lamports())?;
    Ok(())
}
```

---

### Pattern AV-06: Missing Discriminator Check

**Risk Level:** Critical

**Description:** Anchor uses 8-byte discriminators to identify account types. Without proper type checking, an attacker can pass accounts of different types with crafted data.

**Detection Pattern:**
```
1. Find AccountInfo usage in Anchor
2. Check if typed Account<> or proper constraint
3. Flag if using raw AccountInfo for data accounts
```

**Vulnerable:**
```rust
#[derive(Accounts)]
pub struct Vulnerable<'info> {
    // Using AccountInfo loses type safety
    pub pool: AccountInfo<'info>,
}

pub fn process(ctx: Context<Vulnerable>) -> Result<()> {
    // Attacker can pass ANY account type here
    let pool_data = Pool::try_deserialize(&mut &ctx.accounts.pool.data.borrow()[..])?;
}
```

**Secure:**
```rust
#[derive(Accounts)]
pub struct Secure<'info> {
    // Anchor automatically checks discriminator
    pub pool: Account<'info, Pool>,
}

pub fn process(ctx: Context<Secure>) -> Result<()> {
    // pool is guaranteed to be a Pool account
    let pool_data = &ctx.accounts.pool;
}
```

---

## PDA Security Patterns

### Pattern PDA-01: Missing PDA Derivation Verification

**Risk Level:** Critical

**Description:** PDAs must be verified by re-deriving from seeds and comparing. Accepting a PDA without verification allows any account to be passed.

**Detection Pattern:**
```
1. Find accounts that should be PDAs
2. Check if find_program_address or seeds constraint used
3. Verify derived PDA compared against provided account
```

**Vulnerable:**
```rust
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // vault_pda not verified - attacker can pass any account
    let vault_pda = &ctx.accounts.vault_pda;
    
    **vault_pda.lamports.borrow_mut() -= ctx.accounts.amount;
    Ok(())
}
```

**Secure:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault_pda.bump,
    )]
    pub vault_pda: Account<'info, Vault>,
    
    pub user: Signer<'info>,
}
```

---

### Pattern PDA-04: Seed Injection

**Risk Level:** Critical

**Description:** When user-controlled data is used in PDA seeds without proper validation, attackers can derive PDAs for other users.

**Detection Pattern:**
```
1. Find PDA derivation with user input
2. Check if user input is validated/bounded
3. Flag if arbitrary data used in seeds
```

**Vulnerable:**
```rust
pub fn create_vault(
    ctx: Context<CreateVault>,
    vault_id: String,  // User-controlled!
) -> Result<()> {
    let (pda, bump) = Pubkey::find_program_address(
        &[b"vault", vault_id.as_bytes()],  // Attacker can create vault for any ID
        ctx.program_id,
    );
}
```

**Secure:**
```rust
pub fn create_vault(ctx: Context<CreateVault>) -> Result<()> {
    let (pda, bump) = Pubkey::find_program_address(
        &[b"vault", ctx.accounts.user.key().as_ref()],  // Tied to signer
        ctx.program_id,
    );
}
```

---

## CPI Security Patterns

### Pattern CPI-01: Arbitrary CPI Target

**Risk Level:** Critical

**Description:** When the program being invoked via CPI is user-controlled, attackers can invoke arbitrary programs with the privileges of your program.

**Detection Pattern:**
```
1. Find invoke/invoke_signed calls
2. Check if target program is hardcoded or from AccountInfo
3. Flag if program ID comes from user input
```

**Vulnerable:**
```rust
pub fn execute_action(ctx: Context<ExecuteAction>, data: Vec<u8>) -> Result<()> {
    // target_program is user-provided!
    invoke(
        &Instruction::new_with_bytes(
            ctx.accounts.target_program.key(),
            &data,
            vec![],
        ),
        &[],
    )?;
    Ok(())
}
```

**Secure:**
```rust
pub fn execute_action(ctx: Context<ExecuteAction>, data: Vec<u8>) -> Result<()> {
    // Only allowed program
    require_keys_eq!(
        ctx.accounts.target_program.key(),
        known_program::ID,
        ErrorCode::InvalidProgram
    );
    
    // Or use Anchor's Program type
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),  // Program<'info, Token>
        Transfer { /* ... */ },
    );
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}
```

---

### Pattern CPI-03: Signer Seed Exposure

**Risk Level:** Critical

**Description:** When passing signer seeds through CPI, ensure the invoked program cannot abuse the PDA's signing authority.

**Detection Pattern:**
```
1. Find invoke_signed calls
2. Check what operations the invoked program performs
3. Verify invoked program is trusted and expected
```

**Vulnerable:**
```rust
pub fn delegate_action(ctx: Context<DelegateAction>) -> Result<()> {
    let seeds = &[b"authority", &[ctx.accounts.authority.bump]];
    
    // Passing signer seeds to unknown program
    invoke_signed(
        &arbitrary_instruction,
        &[ctx.accounts.authority.to_account_info()],
        &[seeds],
    )?;
    Ok(())
}
```

---

## Arithmetic Patterns

### Pattern AR-01: Unchecked Arithmetic

**Risk Level:** High

**Description:** Rust's default arithmetic can panic on overflow in debug mode but wraps in release. Always use checked operations.

**Detection Pattern:**
```
1. Find arithmetic operations (+, -, *, /)
2. Check if checked_add/sub/mul/div used
3. Flag unchecked operations on user input
```

**Vulnerable:**
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // Can overflow in release mode
    ctx.accounts.pool.total_deposited += amount;
    ctx.accounts.user.balance += amount;
    Ok(())
}
```

**Secure:**
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.pool.total_deposited = ctx.accounts.pool.total_deposited
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    
    ctx.accounts.user.balance = ctx.accounts.user.balance
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    Ok(())
}
```

---

## Initialization Patterns

### Pattern INIT-01: Account Reinitialization

**Risk Level:** Critical

**Description:** Accounts that can be reinitialized allow attackers to reset state, potentially stealing funds or resetting ownership.

**Detection Pattern:**
```
1. Find initialization logic
2. Check for is_initialized flag check
3. Verify init can only happen once
```

**Vulnerable (Native):**
```rust
pub fn initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let pool = &accounts[0];
    let mut pool_data = Pool::unpack_unchecked(&pool.data.borrow())?;
    
    // Can be called repeatedly!
    pool_data.authority = *accounts[1].key;
    pool_data.total = 0;
    
    Pool::pack(pool_data, &mut pool.data.borrow_mut())?;
    Ok(())
}
```

**Secure (Native):**
```rust
pub fn initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let pool = &accounts[0];
    let mut pool_data = Pool::unpack_unchecked(&pool.data.borrow())?;
    
    if pool_data.is_initialized {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    pool_data.is_initialized = true;
    pool_data.authority = *accounts[1].key;
    pool_data.total = 0;
    
    Pool::pack(pool_data, &mut pool.data.borrow_mut())?;
    Ok(())
}
```

**Secure (Anchor):**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,  // Anchor ensures this can only be called once
        payer = authority,
        space = 8 + Pool::LEN,
    )]
    pub pool: Account<'info, Pool>,
    // ...
}
```

---

## Token Security Patterns

### Pattern TOK-01: Token Account Owner Mismatch

**Risk Level:** Critical

**Description:** Token accounts have an owner field. If not validated, users can deposit tokens from accounts they don't own.

**Detection Pattern:**
```
1. Find token transfer operations
2. Check if source token account owner matches signer
3. Flag if token account owner not validated
```

**Vulnerable:**
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub source: Account<'info, TokenAccount>,  // Not verified!
    
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}
```

**Secure:**
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
    
    #[account(
        mut,
        constraint = source.owner == user.key() @ ErrorCode::InvalidOwner,
        constraint = source.mint == destination.mint @ ErrorCode::MintMismatch,
    )]
    pub source: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}
```

---

### Pattern TOK-02: Mint Authority Confusion

**Risk Level:** Critical

**Description:** Tokens with incorrect mint authority allow unauthorized minting.

**Detection Pattern:**
```
1. Find mint operations
2. Verify mint authority is program PDA
3. Check mint authority cannot be changed to attacker
```

**Vulnerable:**
```rust
// Mint authority set to user - they can mint unlimited tokens
pub fn initialize_mint(ctx: Context<InitMint>) -> Result<()> {
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        InitializeMint {
            mint: ctx.accounts.mint.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        },
    );
    
    token::initialize_mint(
        cpi_ctx,
        9,
        ctx.accounts.user.key,  // User is mint authority!
        None,
    )?;
    Ok(())
}
```

**Secure:**
```rust
pub fn initialize_mint(ctx: Context<InitMint>) -> Result<()> {
    let (mint_authority, _) = Pubkey::find_program_address(
        &[b"mint_authority"],
        ctx.program_id,
    );
    
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        InitializeMint {
            mint: ctx.accounts.mint.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        },
    );
    
    token::initialize_mint(
        cpi_ctx,
        9,
        &mint_authority,  // Program PDA is mint authority
        None,
    )?;
    Ok(())
}
```

---

## Duplicate Account Pattern

### Pattern DV-03: Same Account Multiple Positions

**Risk Level:** Critical

**Description:** When the same account is passed in multiple positions, operations may have unexpected effects (e.g., self-transfer).

**Detection Pattern:**
```
1. Find instructions with multiple similar accounts
2. Check if accounts compared for uniqueness
3. Flag if duplicate accounts could break invariants
```

**Vulnerable:**
```rust
pub fn swap(ctx: Context<Swap>) -> Result<()> {
    // If source == destination, funds are lost
    token::transfer(
        CpiContext::new(/* ... */),
        ctx.accounts.source.amount,
    )?;
    Ok(())
}
```

**Secure:**
```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(
        mut,
        constraint = source.key() != destination.key() @ ErrorCode::DuplicateAccount
    )]
    pub source: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
}
```

---

## Quick Reference: Detection Commands

```bash
# Find owner checks (should be present)
grep -rn "\.owner ==" programs/

# Find signer checks (should be present)
grep -rn "is_signer\|Signer<'info>" programs/

# Find PDA derivations
grep -rn "find_program_address\|create_program_address" programs/

# Find CPI calls
grep -rn "invoke\|invoke_signed\|CpiContext" programs/

# Find unchecked math
grep -rn "\+\|-\|\*\|/" programs/ | grep -v checked

# Find initialization
grep -rn "init\|initialize\|is_initialized" programs/

# Find AccountInfo usage (potential type confusion)
grep -rn "AccountInfo<'info>" programs/
```

---

## Severity Quick Guide

| Pattern | Base Severity | If Exploited |
|---------|---------------|--------------|
| AV-01 (Owner check) | Critical | Account takeover |
| AV-02 (Signer check) | Critical | Unauthorized action |
| PDA-01 (PDA validation) | Critical | Wrong account access |
| CPI-01 (Arbitrary CPI) | Critical | Full program abuse |
| INIT-01 (Reinit) | Critical | State reset/theft |
| TOK-01 (Token owner) | Critical | Token theft |
| AR-01 (Overflow) | High | Economic exploit |
| DV-03 (Duplicate) | High | Logic break |

