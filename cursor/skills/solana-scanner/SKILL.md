---
name: solana-scanner
description: "Comprehensive Solana program vulnerability scanner for Rust and Anchor programs. Covers account validation, PDA security, CPI vulnerabilities, and Solana-specific attack vectors. Use this skill when auditing Solana programs."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Solana Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for Solana programs written in Rust (native) or Anchor framework. It includes:
- 60+ Solana-specific vulnerability patterns
- Account validation checklists
- PDA security analysis
- CPI (Cross-Program Invocation) vulnerabilities
- Anchor-specific security considerations

---

## When to Use This Skill

**Use when:**
- Auditing Solana programs (Rust or Anchor)
- Reviewing account security and validation
- Analyzing PDA derivation and verification
- Checking CPI security
- Scanning for Solana-specific attack vectors

**Trigger phrases:**
- "Audit this Solana program"
- "Check this Anchor code"
- "Review Solana security"
- "Scan for Solana vulnerabilities"

---

## When NOT to Use

Do NOT use this skill for:
- EVM chains (use solidity-scanner)
- CosmWasm (use cosmos-scanner)
- Move chains (use move-scanner)
- Generic Rust (security differs significantly)

---

## Solana Security Fundamentals

### Key Concepts

```
┌─────────────────────────────────────────────────────────┐
│                    SOLANA SECURITY MODEL                 │
├─────────────────────────────────────────────────────────┤
│ ACCOUNTS                                                 │
│ • Owned by programs (executable code)                   │
│ • Hold data and lamports                                │
│ • Must be validated on every instruction                │
├─────────────────────────────────────────────────────────┤
│ PROGRAMS                                                 │
│ • Stateless - all state in accounts                     │
│ • Can only write to accounts they own                   │
│ • Use PDAs for deterministic addresses                  │
├─────────────────────────────────────────────────────────┤
│ CROSS-PROGRAM INVOCATION (CPI)                          │
│ • Programs calling other programs                       │
│ • Privileges can be delegated                           │
│ • Critical security boundary                            │
└─────────────────────────────────────────────────────────┘
```

---

## Vulnerability Categories

### Category 1: Missing Account Validation

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AV-01 | Missing owner check | Critical | Account owner not verified |
| AV-02 | Missing signer check | Critical | Required signer not validated |
| AV-03 | Missing writable check | High | Account mutability not verified |
| AV-04 | Missing key validation | High | Expected account not verified |
| AV-05 | Missing initialization check | Critical | Account state not validated |
| AV-06 | Missing discriminator check | Critical | Anchor discriminator bypass |
| AV-07 | Type confusion | Critical | Wrong account type accepted |

#### AV-01: Missing Owner Check

**Vulnerable Code (Native):**
```rust
// VULNERABLE: No owner check
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let vault_account = &accounts[0];
    let vault_data = Vault::unpack(&vault_account.data.borrow())?;
    
    // Attacker can pass fake vault with any data
    transfer_lamports(vault_account, &accounts[1], vault_data.amount)?;
    Ok(())
}
```

**Secure Code:**
```rust
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let vault_account = &accounts[0];
    
    // CHECK: Verify owner
    if vault_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    let vault_data = Vault::unpack(&vault_account.data.borrow())?;
    transfer_lamports(vault_account, &accounts[1], vault_data.amount)?;
    Ok(())
}
```

---

### Category 2: PDA Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| PDA-01 | Missing PDA validation | Critical | PDA not verified against seeds |
| PDA-02 | Missing bump validation | High | Bump not verified |
| PDA-03 | Predictable seeds | Medium | Seeds can be brute-forced |
| PDA-04 | Seed injection | Critical | User controls PDA seeds |
| PDA-05 | Canonical bump bypass | High | Non-canonical bump used |

#### PDA-01: Missing PDA Validation

**Vulnerable Code:**
```rust
// VULNERABLE: PDA not validated
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Attacker can pass any account as vault_pda
    let vault_pda = &ctx.accounts.vault_pda;
    
    **vault_pda.lamports.borrow_mut() -= amount;
    **ctx.accounts.user.lamports.borrow_mut() += amount;
    Ok(())
}
```

**Secure Code:**
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Derive expected PDA
    let (expected_pda, _bump) = Pubkey::find_program_address(
        &[b"vault", ctx.accounts.user.key.as_ref()],
        ctx.program_id,
    );
    
    // Verify provided account matches
    require_keys_eq!(ctx.accounts.vault_pda.key(), expected_pda);
    
    **ctx.accounts.vault_pda.lamports.borrow_mut() -= amount;
    **ctx.accounts.user.lamports.borrow_mut() += amount;
    Ok(())
}
```

---

### Category 3: Arithmetic Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AR-01 | Integer overflow | High | Unchecked arithmetic |
| AR-02 | Integer underflow | High | Subtraction without check |
| AR-03 | Division by zero | High | Unchecked divisor |
| AR-04 | Precision loss | Medium | Token decimal mishandling |
| AR-05 | Casting overflow | High | Type narrowing without check |

#### AR-01: Integer Overflow

**Vulnerable Code:**
```rust
// VULNERABLE: Can overflow
pub fn add_rewards(ctx: Context<AddRewards>, amount: u64) -> Result<()> {
    ctx.accounts.pool.total_rewards += amount;  // Potential overflow
    Ok(())
}
```

**Secure Code:**
```rust
pub fn add_rewards(ctx: Context<AddRewards>, amount: u64) -> Result<()> {
    ctx.accounts.pool.total_rewards = ctx.accounts.pool.total_rewards
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    Ok(())
}
```

---

### Category 4: CPI Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| CPI-01 | Arbitrary CPI | Critical | User-controlled program ID |
| CPI-02 | Missing program check | Critical | Called program not validated |
| CPI-03 | Privilege escalation | Critical | Signer seeds exposed |
| CPI-04 | Account privilege leak | High | Writable/signer passed incorrectly |
| CPI-05 | Reentrancy via CPI | High | State corruption via callback |

#### CPI-01: Arbitrary CPI

**Vulnerable Code:**
```rust
// VULNERABLE: Arbitrary program call
pub fn execute(ctx: Context<Execute>, data: Vec<u8>) -> Result<()> {
    let cpi_program = &ctx.accounts.target_program;  // User-controlled
    
    // Attacker can call any program with our privileges
    invoke(
        &Instruction::new_with_bytes(
            *cpi_program.key,
            &data,
            vec![AccountMeta::new(*ctx.accounts.vault.key, true)],
        ),
        &[ctx.accounts.vault.clone()],
    )?;
    Ok(())
}
```

**Secure Code:**
```rust
// Only allow specific program
pub fn execute(ctx: Context<Execute>, data: Vec<u8>) -> Result<()> {
    require_keys_eq!(
        ctx.accounts.target_program.key(),
        ALLOWED_PROGRAM_ID,
        ErrorCode::InvalidProgram
    );
    
    invoke(
        &Instruction::new_with_bytes(
            ALLOWED_PROGRAM_ID,
            &data,
            vec![AccountMeta::new(*ctx.accounts.vault.key, true)],
        ),
        &[ctx.accounts.vault.clone()],
    )?;
    Ok(())
}
```

---

### Category 5: Signer Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| SIG-01 | Missing signer check | Critical | Authority not validated |
| SIG-02 | Wrong signer | Critical | Incorrect account signed |
| SIG-03 | Signer delegation | High | Signer privilege passed via CPI |
| SIG-04 | Authority confusion | High | Multiple signers, wrong one checked |

#### SIG-01: Missing Signer Check

**Vulnerable Code (Anchor):**
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    // VULNERABLE: No signer constraint
    pub authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
}
```

**Secure Code:**
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    // Signer constraint enforced
    pub authority: Signer<'info>,
    
    #[account(mut, has_one = authority)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
}
```

---

### Category 6: Data Validation

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| DV-01 | Missing length check | High | Buffer overflow |
| DV-02 | Insufficient serialization | High | Borsh deserialization abuse |
| DV-03 | Duplicate accounts | Critical | Same account passed twice |
| DV-04 | Account reuse | High | Account used for multiple purposes |
| DV-05 | Stale account data | Medium | Account not reloaded after CPI |

#### DV-03: Duplicate Accounts

**Vulnerable Code:**
```rust
// VULNERABLE: No duplicate check
pub fn swap(
    ctx: Context<Swap>,
    amount_in: u64,
) -> Result<()> {
    // Attacker passes same account for source and destination
    let source = &ctx.accounts.source;
    let destination = &ctx.accounts.destination;
    
    // Self-swap could break invariants
    **source.lamports.borrow_mut() -= amount_in;
    **destination.lamports.borrow_mut() += amount_in;
    Ok(())
}
```

**Secure Code:**
```rust
pub fn swap(
    ctx: Context<Swap>,
    amount_in: u64,
) -> Result<()> {
    // Check for duplicate accounts
    require_keys_neq!(
        ctx.accounts.source.key(),
        ctx.accounts.destination.key(),
        ErrorCode::DuplicateAccount
    );
    
    let source = &ctx.accounts.source;
    let destination = &ctx.accounts.destination;
    
    **source.lamports.borrow_mut() -= amount_in;
    **destination.lamports.borrow_mut() += amount_in;
    Ok(())
}
```

---

### Category 7: Initialization Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| INIT-01 | Reinitialization | Critical | Account can be reinitialized |
| INIT-02 | Missing init check | Critical | Uninitialized account used |
| INIT-03 | Rent exemption bypass | Medium | Account not rent-exempt |
| INIT-04 | Data size mismatch | High | Wrong allocation size |

#### INIT-01: Reinitialization

**Vulnerable Code:**
```rust
// VULNERABLE: No initialization guard
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    pool.authority = ctx.accounts.authority.key();
    pool.total_supply = 0;
    Ok(())
}
```

**Secure Code (Anchor):**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,  // Anchor's init ensures one-time initialization
        payer = authority,
        space = 8 + Pool::LEN,
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

---

### Category 8: Token Program Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| TOK-01 | Token account owner | Critical | Token account not owned by user |
| TOK-02 | Mint mismatch | High | Wrong mint for token account |
| TOK-03 | Missing close authority | Medium | Token account close issue |
| TOK-04 | Delegate abuse | High | Delegate can steal tokens |
| TOK-05 | Freeze authority | Medium | Tokens can be frozen |

#### TOK-01: Token Account Owner Check

**Vulnerable Code:**
```rust
// VULNERABLE: Token account owner not checked
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,  // Not verified to belong to user
    
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
}
```

**Secure Code:**
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
    
    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ ErrorCode::InvalidOwner
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
}
```

---

## Anchor-Specific Vulnerabilities

### Anchor Account Constraints

```rust
#[derive(Accounts)]
pub struct SecureInstruction<'info> {
    // Signer verification
    pub authority: Signer<'info>,
    
    // Account with owner verification
    #[account(
        mut,
        seeds = [b"pool", authority.key().as_ref()],
        bump = pool.bump,
        has_one = authority,  // Verifies pool.authority == authority.key()
    )]
    pub pool: Account<'info, Pool>,
    
    // Token account with constraints
    #[account(
        mut,
        constraint = user_token.owner == authority.key(),
        constraint = user_token.mint == pool.token_mint,
    )]
    pub user_token: Account<'info, TokenAccount>,
    
    // Program constraint
    pub token_program: Program<'info, Token>,
}
```

### Common Anchor Mistakes

| Mistake | Risk | Solution |
|---------|------|----------|
| Using `AccountInfo` instead of typed | Missing validation | Use `Account<'info, Type>` |
| Missing `has_one` constraint | Authority bypass | Add `has_one = authority` |
| No seed validation for PDA | PDA confusion | Use `seeds` and `bump` |
| `#[account(init)]` without space | Allocation issue | Always specify `space` |
| Missing program checks | CPI abuse | Use `Program<'info, T>` |

---

## Protocol-Specific Checklists

### Solana DEX/AMM

```markdown
## Solana DEX Checklist

### Pool Accounts
- [ ] Pool PDA derived correctly
- [ ] LP token mint authority is PDA
- [ ] Token accounts owned by pool PDA
- [ ] Correct token mints validated

### Swap Logic
- [ ] Slippage protection implemented
- [ ] Constant product maintained
- [ ] Fee calculation correct
- [ ] No precision loss in math

### Liquidity Operations
- [ ] First depositor attack prevented
- [ ] LP share calculation correct
- [ ] Withdrawal proportional
- [ ] Minimum liquidity enforced
```

### Solana Lending Protocol

```markdown
## Solana Lending Checklist

### Collateral
- [ ] Collateral account ownership verified
- [ ] Oracle price validation
- [ ] Collateral factor enforced
- [ ] Liquidation threshold correct

### Borrowing
- [ ] Borrow limit checked against collateral
- [ ] Interest rate calculation correct
- [ ] Compound interest handled
- [ ] Position health maintained

### Liquidation
- [ ] Health factor calculation correct
- [ ] Liquidation incentive reasonable
- [ ] No self-liquidation
- [ ] Proper position closure
```

### Solana NFT

```markdown
## Solana NFT Checklist

### Minting
- [ ] Mint authority validated
- [ ] Collection verified (Metaplex)
- [ ] Metadata correctly set
- [ ] Royalty enforcement

### Marketplace
- [ ] Listing authority validated
- [ ] Escrow PDA secure
- [ ] Payment split correct
- [ ] Cancellation works correctly
```

---

## Scanning Workflow

### Step 1: Setup

```bash
# Build program
anchor build
# or
cargo build-bpf

# Run tests
anchor test
# or
cargo test-bpf
```

### Step 2: Account Validation Scan

For each instruction:
```markdown
## Instruction: [name]

### Accounts
| Account | Type | Checks Present | Status |
|---------|------|----------------|--------|
| authority | Signer | Signer<'info> | ✅ |
| pool | Data | seeds, bump, has_one | ✅ |
| user_token | Token | owner, mint constraints | ✅ |

### Missing Validations
- [None or list issues]
```

### Step 3: PDA Analysis

```bash
# Find all PDA derivations
grep -rn "find_program_address\|Pubkey::create_program_address" programs/
```

For each:
- [ ] Seeds are deterministic
- [ ] Bump is validated
- [ ] PDA is verified on use

### Step 4: CPI Analysis

```bash
# Find all CPI calls
grep -rn "invoke\|invoke_signed\|CpiContext" programs/
```

For each:
- [ ] Target program verified
- [ ] Account privileges checked
- [ ] No privilege escalation

---

## Output Format

### Finding Template

```markdown
## [SOL-##] Title

**Severity:** Critical | High | Medium | Low
**Category:** [Category]
**Pattern ID:** [XX-##]

### Location
- **File:** programs/protocol/src/instructions/action.rs
- **Lines:** 45-52
- **Instruction:** process_action

### Description
[Clear explanation of the Solana-specific vulnerability]

### Vulnerable Code
```rust
// The problematic code
pub fn process_action(ctx: Context<Action>) -> Result<()> {
    // Issue here
}
```

### Attack Scenario
1. Attacker creates malicious account with crafted data
2. Attacker calls instruction with malicious account
3. Missing validation allows [exploit]

### Impact
[What an attacker could achieve]

### Recommendation
```rust
// Fixed code
#[derive(Accounts)]
pub struct Action<'info> {
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump,
        has_one = authority,
    )]
    pub pool: Account<'info, Pool>,
    // Additional constraints...
}
```
```

---

## Resources

- [Vulnerability Patterns](resources/solana-patterns.md)
- [Anchor Security Guide](resources/anchor-security.md)
- [Account Validation Checklist](resources/account-validation.md)

## Workflows

- [Native Program Audit](workflows/native-audit.md)
- [Anchor Program Audit](workflows/anchor-audit.md)
