# Account Validation Checklist

Comprehensive checklist for validating Solana accounts in both native programs and Anchor.

---

## Quick Reference Matrix

| Validation | Native Check | Anchor Constraint |
|------------|--------------|-------------------|
| Owner | `account.owner == program_id` | `Account<'info, T>` |
| Signer | `account.is_signer` | `Signer<'info>` |
| Writable | `account.is_writable` | `#[account(mut)]` |
| Key match | `account.key == &expected` | `#[account(address = ...)]` |
| PDA | `Pubkey::find_program_address` | `seeds = [...], bump` |
| Relationship | Manual field check | `has_one = field` |
| Type | Discriminator check | `Account<'info, T>` |
| Program | `account.key == &program_id` | `Program<'info, T>` |
| Rent exempt | `Rent::get()?.is_exempt()` | Automatic with `init` |

---

## Native Program Validation

### Complete Validation Template

```rust
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    
    // 1. Authority (must sign)
    let authority = next_account_info(accounts_iter)?;
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 2. Pool account (owned by program, must be writable)
    let pool_account = next_account_info(accounts_iter)?;
    if pool_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !pool_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 3. Deserialize and validate type
    let pool_data = Pool::unpack(&pool_account.data.borrow())?;
    if !pool_data.is_initialized {
        return Err(ProgramError::UninitializedAccount);
    }
    
    // 4. Validate relationships
    if pool_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 5. PDA validation (if applicable)
    let (expected_pda, bump) = Pubkey::find_program_address(
        &[b"pool", authority.key.as_ref()],
        program_id,
    );
    if pool_account.key != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // 6. Additional accounts...
    let token_program = next_account_info(accounts_iter)?;
    if token_program.key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // ... proceed with instruction logic
    Ok(())
}
```

---

## Account Type Validation Checklist

### 1. Authority/Admin Accounts

```markdown
## Authority Account Checklist

- [ ] Is signer verified
- [ ] Key matches expected authority (if hardcoded)
- [ ] Or key matches stored authority (in data account)
- [ ] If PDA authority, seeds derived and matched
```

**Native:**
```rust
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
if authority.key != &pool_data.authority {
    return Err(ProgramError::InvalidAccountData);
}
```

**Anchor:**
```rust
#[account(has_one = authority)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,
```

---

### 2. Data Accounts

```markdown
## Data Account Checklist

- [ ] Owner is this program
- [ ] Is initialized (if expected)
- [ ] Discriminator is correct (Anchor)
- [ ] Data deserializes correctly
- [ ] Relationships verified (authority, linked accounts)
- [ ] If PDA, seeds and bump verified
```

**Native:**
```rust
// Owner check
if pool_account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}

// Deserialize (includes basic validation)
let pool = Pool::unpack(&pool_account.data.borrow())?;

// Initialization check
if !pool.is_initialized {
    return Err(ProgramError::UninitializedAccount);
}
```

**Anchor:**
```rust
// All checks automatic with typed account
#[account(
    seeds = [b"pool"],
    bump = pool.bump,
)]
pub pool: Account<'info, Pool>,
```

---

### 3. Token Accounts

```markdown
## Token Account Checklist

- [ ] Owner is spl_token program
- [ ] Token account owner matches expected (user)
- [ ] Mint matches expected token mint
- [ ] Has sufficient balance (if transferring from)
- [ ] Not frozen (if checking)
```

**Native:**
```rust
// Verify is token account
if user_token.owner != &spl_token::id() {
    return Err(ProgramError::IncorrectProgramId);
}

// Deserialize
let token_account = TokenAccount::unpack(&user_token.data.borrow())?;

// Verify token account owner
if token_account.owner != *user.key {
    return Err(ProgramError::InvalidAccountData);
}

// Verify mint
if token_account.mint != expected_mint {
    return Err(ProgramError::InvalidAccountData);
}
```

**Anchor:**
```rust
#[account(
    mut,
    constraint = user_token.owner == user.key() @ ErrorCode::InvalidOwner,
    constraint = user_token.mint == pool.token_mint @ ErrorCode::MintMismatch,
)]
pub user_token: Account<'info, TokenAccount>,
```

---

### 4. Mint Accounts

```markdown
## Mint Account Checklist

- [ ] Owner is spl_token program
- [ ] Key matches expected mint
- [ ] Decimals as expected (if relevant)
- [ ] Mint authority verified (if your program controls it)
```

**Anchor:**
```rust
#[account(
    constraint = mint.key() == pool.token_mint @ ErrorCode::InvalidMint,
)]
pub mint: Account<'info, Mint>,
```

---

### 5. PDA Accounts

```markdown
## PDA Account Checklist

- [ ] Derived PDA matches provided account
- [ ] Seeds are deterministic and not user-controlled
- [ ] Bump is correct (canonical or stored)
- [ ] Owner is this program (if data PDA)
```

**Native:**
```rust
let (expected_pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key.as_ref()],
    program_id,
);

if vault_account.key != &expected_pda {
    return Err(ProgramError::InvalidSeeds);
}
```

**Anchor:**
```rust
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump,  // or bump = vault.bump
)]
pub vault: Account<'info, Vault>,
```

---

### 6. Program Accounts

```markdown
## Program Account Checklist

- [ ] Key matches expected program ID
- [ ] Is executable (if calling)
- [ ] No arbitrary program ID from user
```

**Native:**
```rust
if token_program.key != &spl_token::id() {
    return Err(ProgramError::IncorrectProgramId);
}
if !token_program.executable {
    return Err(ProgramError::InvalidAccountData);
}
```

**Anchor:**
```rust
// Automatic validation with Program type
pub token_program: Program<'info, Token>,
pub system_program: Program<'info, System>,
```

---

### 7. System Accounts (SOL only)

```markdown
## System Account Checklist

- [ ] Owner is System Program
- [ ] Has sufficient lamports (if transferring from)
- [ ] Is writable (if modifying)
- [ ] Is signer (if needed)
```

**Native:**
```rust
if user.owner != &system_program::id() && user.lamports() > 0 {
    // Non-system-owned accounts with balance
}
```

**Anchor:**
```rust
// For SOL-holding account owned by system program
pub recipient: SystemAccount<'info>,
```

---

## Cross-Cutting Concerns

### Duplicate Account Check

```markdown
- [ ] No two accounts are the same address
- [ ] Self-referential operations prevented
```

```rust
// Native
if source.key == destination.key {
    return Err(ProgramError::InvalidArgument);
}

// Anchor
#[account(
    constraint = source.key() != destination.key() @ ErrorCode::DuplicateAccount
)]
```

### Rent Exemption

```markdown
- [ ] New accounts are rent-exempt
- [ ] Account has enough lamports for rent
```

```rust
// Native
let rent = Rent::get()?;
if !rent.is_exempt(account.lamports(), account.data_len()) {
    return Err(ProgramError::AccountNotRentExempt);
}

// Anchor - automatic with init
#[account(init, payer = user, space = 8 + Data::LEN)]
pub data: Account<'info, Data>,
```

### Account Size

```markdown
- [ ] Account size matches expected data
- [ ] Buffer not too small for deserialization
- [ ] New accounts allocated correctly
```

```rust
// Native
if account.data_len() != Pool::LEN {
    return Err(ProgramError::InvalidAccountData);
}

// Anchor
#[account(init, payer = user, space = 8 + Pool::LEN)]  // 8 for discriminator
```

---

## Common Validation Failures

| Failure | Cause | Impact | Fix |
|---------|-------|--------|-----|
| Wrong owner | Foreign account passed | Data confusion | Check owner == program_id |
| Missing signer | Unsigned transaction | Auth bypass | Check is_signer |
| Wrong PDA | Attacker's PDA | Wrong state | Derive and compare |
| Type confusion | Different account type | Data misread | Check discriminator |
| Missing relationship | Unrelated accounts | Auth bypass | has_one constraint |
| Duplicate accounts | Same account twice | Logic break | Compare keys |
| Stale data | After CPI | Wrong calculations | Reload after CPI |

---

## Quick Validation Audit

For rapid validation audit, check each account:

```markdown
## Account: [name]

| Check | Present | Notes |
|-------|---------|-------|
| Owner | ✅/❌ | |
| Signer | ✅/❌/N/A | |
| Writable | ✅/❌/N/A | |
| Type/Discriminator | ✅/❌ | |
| PDA Seeds | ✅/❌/N/A | |
| Relationships | ✅/❌/N/A | |
| Duplicates | ✅/❌ | |

**Missing:** [List]
**Risk:** Critical/High/Medium/Low
```

---

## Validation By Instruction Type

### Initialize Instruction

```markdown
- [ ] Account not already initialized
- [ ] Correct space allocated
- [ ] Rent-exempt
- [ ] Authority set correctly
- [ ] PDA derived correctly (if PDA)
- [ ] Discriminator set (Anchor auto)
```

### Update Instruction

```markdown
- [ ] Account initialized
- [ ] Authority is signer
- [ ] Authority matches stored authority
- [ ] Account is writable
- [ ] New values validated
```

### Transfer/Withdraw Instruction

```markdown
- [ ] Source has sufficient balance
- [ ] Authority authorized for source
- [ ] Destination valid
- [ ] Amount validated
- [ ] No self-transfer (if problematic)
- [ ] State updated atomically
```

### Close Instruction

```markdown
- [ ] Authority is signer
- [ ] Authority matches stored authority
- [ ] Rent returned to correct recipient
- [ ] Account zeroed/marked closed
- [ ] No outstanding obligations
```

---

## Native vs Anchor Comparison

| Validation | Native Code | Anchor |
|------------|------------|--------|
| Signer | `if !acc.is_signer { err }` | `Signer<'info>` |
| Owner | `if acc.owner != pid { err }` | `Account<'info, T>` |
| Writable | `if !acc.is_writable { err }` | `#[account(mut)]` |
| PDA | `find_program_address` + compare | `seeds=[..], bump` |
| Relationship | `if acc.field != other.key { err }` | `has_one = field` |
| Type | Discriminator check | `Account<'info, T>` |
| Program | `if acc.key != &prog_id { err }` | `Program<'info, T>` |
| Constraint | Custom logic | `constraint = ...` |
| Init | Space + rent + zero-init | `init, space=...` |
| Close | Manual zero + transfer | `close = recipient` |

