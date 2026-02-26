---
id: SOLANA-ANCHOR-SECURITY
title: Anchor Framework Security Guide
category: solana-scanner
difficulty: intermediate
triggers:
  - anchor security
  - anchor vulnerabilities
  - anchor constraints
  - anchor audit
related_skills:
  - solana-scanner/resources/solana-patterns.md
  - solana-scanner/resources/account-validation.md
  - solana-scanner/workflows/anchor-audit.md
tags:
  - solana
  - anchor
  - framework
  - security
last_updated: 2026-02-24
---


# Anchor Framework Security Guide

> Anchor automates many Solana safety checks, but introduces its own vulnerability surface. This guide covers Anchor-specific risks beyond what the framework protects against. This expanded guide merges tenequm's claude-plugins solana-security reference for Anchor, including advanced patterns, CPI, events, error handling, and upgradability.

## What Anchor Protects Automatically

| Check | How Anchor Does It | When It Fails |
|-------|-------------------|---------------|
| Owner validation | `Account<'info, T>` checks `owner == program_id` | Using `AccountInfo` or `UncheckedAccount` bypasses this |
| Discriminator | 8-byte SHA256 hash checked on deser | Not checked on `UncheckedAccount` |
| Signer validation | `Signer<'info>` type requires signature | Only if you use the `Signer` type |
| Rent exemption | `init` ensures rent-exempt balance | Manual lamport transfers can violate |
| Account closing | `close = receiver` zeros data + drains | Only if you use the `close` constraint |

## Common Anchor Vulnerabilities

### 1. Missing Constraints
```rust
// [VULNERABLE] No constraints on account
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: Account<'info, Vault>,  // Missing: mut, has_one, seeds
    pub user: Signer<'info>,
}

// [SAFE] Full constraints
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = owner, seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}
```

### 2. Arbitrary CPI
```rust
// [VULNERABLE] CPI to user-provided program
pub fn execute(ctx: Context<Execute>, data: Vec<u8>) -> Result<()> {
    let ix = Instruction { program_id: ctx.accounts.target_program.key(), .. };
    invoke(&ix, &[ctx.accounts.signer.to_account_info()])?;
    Ok(())
}

// [SAFE] Whitelist program IDs
require!(ctx.accounts.target_program.key() == KNOWN_PROGRAM_ID, ErrorCode::InvalidProgram);
```

### 3. Init-If-Needed Risks
```rust
// CAUTION: init_if_needed can be exploited
#[account(init_if_needed, payer = user, space = 8 + Vault::LEN)]
pub vault: Account<'info, Vault>,
// Risk: Attacker can front-run initialization with their own parameters
```

### 4. Close Account Pattern
```rust
// [SAFE] Use Anchor close constraint
#[account(mut, close = receiver)]
pub account_to_close: Account<'info, Data>,
pub receiver: SystemAccount<'info>,
// Anchor zeroes data AND transfers lamports
```

### 5. Custom Discriminator Collisions (Anchor 0.31+)
```rust
// Default: sha256("account:<StructName>")[0..8]
// Custom discriminators introduce collision risk:

#[account(discriminator = 1)]
pub struct Escrow { ... }

// AUDIT RISKS:
// - [1] blocks any discriminator starting with [1, ...] (prefix collision)
// - [0] conflicts with uninitialized (zeroed) accounts
// - Discriminators MUST be unique across all accounts in the program
```

### 6. Token-2022 / InterfaceAccount Compatibility
```rust
// [VULNERABLE] Only handles SPL Token, ignores Token-2022
pub mint: Account<'info, anchor_spl::token::Mint>,

// [SAFE] Handles both SPL Token and Token-2022
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};
pub mint: InterfaceAccount<'info, Mint>,
pub token_account: InterfaceAccount<'info, TokenAccount>,
pub token_program: Interface<'info, TokenInterface>,
// AUDIT: Also check transfer hooks, transfer fees, and confidential transfers
```

### 7. LazyAccount Pitfalls (Anchor 0.31+)
```rust
// LazyAccount is heap-allocated, read-only access
pub account: LazyAccount<'info, CustomAccountType>,

// AUDIT RISKS:
// - LazyAccount is READ-ONLY — mutations are silently ignored
// - After CPI, cached values are STALE — must call unload() to refresh
// - Requires feature flag: anchor-lang = { features = ["lazy-account"] }
```

### 8. Remaining Accounts Exploitation
```rust
// [VULNERABLE] No validation on dynamic accounts
pub fn batch_operation(ctx: Context<BatchOp>) -> Result<()> {
    for account in ctx.remaining_accounts {
        // Attacker can pass any account here
        process(account)?;
    }
    Ok(())
}

// [SAFE] Validate remaining accounts
pub fn batch_operation(ctx: Context<BatchOp>) -> Result<()> {
    for account in ctx.remaining_accounts {
        require!(account.owner == &crate::ID, ErrorCode::InvalidOwner);
        require!(account.is_signer || is_known_pda(account), ErrorCode::Unauthorized);
    }
    Ok(())
}
```

### 9. Reallocation Security
```rust
// [VULNERABLE] Doesn't zero freed memory on shrink
#[account(mut, realloc = new_space, realloc::payer = payer, realloc::zero = false)]
pub account: Account<'info, CustomAccount>,
// Risk: Old data remains readable after shrink

// [SAFE] Zero old data when shrinking
#[account(mut, realloc = new_space, realloc::payer = payer, realloc::zero = true)]
pub account: Account<'info, CustomAccount>,
```

### 10. PDA-Signed CPI Security
```rust
// PDA signing requires correct bump management
let seeds = &[b"vault".as_ref(), &[ctx.bumps.vault]];
let signer = &[&seeds[..]];
let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);

// AUDIT CHECKS:
// - Bump must come from ctx.bumps (canonical), not recalculated
// - PDA seeds must match the account's derivation exactly
// - CPI target must be validated (use Program<'info, T>)
// - Never pass extra privileges to CPI callees
```

## Anchor Security Checklist
- [ ] All accounts have appropriate constraints (`mut`, `has_one`, `seeds`)
- [ ] Signer required for privileged operations
- [ ] PDA seeds include relevant data (user, mint, etc.)
- [ ] Bump stored and reused (not recalculated)
- [ ] CPI targets validated
- [ ] Account closing uses `close` constraint
- [ ] `init_if_needed` usage justified and safe
- [ ] Custom error codes for all failure paths
- [ ] No `UncheckedAccount` without manual validation comment
- [ ] `remaining_accounts` validated when accessed
- [ ] Token-2022 extensions handled (transfer hooks, transfer fees)
- [ ] `realloc` constraint checks new space is sufficient
- [ ] Events emitted for all state changes

## Anchor-Specific Constraint Reference

| Constraint | Purpose | Security Impact If Missing |
|-----------|---------|---------------------------|
| `mut` | Marks account as writable | State changes silently fail |
| `has_one = field` | Verifies account relationship | Wrong account accepted |
| `seeds = [...]` | PDA derivation | Fake PDA accepted |
| `bump` | Canonical bump | Non-canonical PDA collision |
| `close = receiver` | Safe account closing | Revival attack |
| `init` | Creates + initializes | Re-initialization attack |
| `constraint = expr` | Custom boolean check | Missing business logic validation |
| `address = PUBKEY` | Exact key match | Wrong program/account accepted |
| `owner = program` | Owner validation | Fake account injection |
| `realloc` | Resize account data | Buffer overflow / truncation |

---

## Advanced Anchor Security Patterns (2026)

### Account Constraint Security

- Use `init` for new accounts, not `init_if_needed` unless you validate existing data
- Always combine `has_one`, `seeds`, and `bump` for PDAs
- Use `constraint` for custom logic, but keep it simple (no `?` operator)
- `close` constraint must be last in the attribute list

### Secure CPI Patterns

- Use `Program<'info, T>` for program validation (not `AccountInfo`)
- Always validate CPI targets (whitelist or type-safe)
- Use `CpiContext::new_with_signer` for PDA signing
- Reload accounts after CPI if state may change
- Validate CPI return values and post-CPI state

**Example: Secure Token Transfer with CPI**
```rust
pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
    let cpi_accounts = Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
    token::transfer(cpi_ctx, amount)?;
    ctx.accounts.from.reload()?;
    Ok(())
}
```

### Event Emission and Monitoring

- Emit events for all critical state changes (deposits, withdrawals, upgrades)
- Use `emit!` for regular events, `emit_cpi!` for events visible to CPI callers
- Validate event data before emitting

**Example:**
```rust
#[event]
pub struct WithdrawalEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(ctx.accounts.vault.balance >= amount, ErrorCode::InsufficientFunds);
    ctx.accounts.vault.balance -= amount;
    emit!(WithdrawalEvent {
        user: ctx.accounts.user.key(),
        amount,
        timestamp: Clock::get()?.unix_timestamp,
    });
    Ok(())
}
```

### Error Handling Best Practices

- Define custom error codes with `#[error_code]`
- Use `require!` for all critical checks
- Always propagate errors (`?`), never silence them
- Never use `unwrap()` or `expect()` in production

**Example:**
```rust
#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFunds,
    #[msg("Unauthorized access attempt")]
    Unauthorized,
    #[msg("Invalid configuration parameters")]
    InvalidConfig,
    #[msg("Arithmetic overflow occurred")]
    Overflow,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(ctx.accounts.vault.balance >= amount, ErrorCode::InsufficientFunds);
    require!(ctx.accounts.vault.authority == ctx.accounts.user.key(), ErrorCode::Unauthorized);
    ctx.accounts.vault.balance -= amount;
    Ok(())
}
```

### Upgradability and Emergency Pause

- Use a version field in config accounts for migrations
- Implement an emergency pause flag for critical operations

**Example:**
```rust
#[account]
#[derive(InitSpace)]
pub struct ProgramConfig {
    pub version: u8,
    pub upgrade_authority: Pubkey,
    pub paused: bool,
}

pub fn migrate(ctx: Context<Migrate>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    require!(config.version < CURRENT_VERSION, ErrorCode::AlreadyMigrated);
    // ...migration logic...
    config.version = CURRENT_VERSION;
    Ok(())
}

#[derive(Accounts)]
pub struct SensitiveOperation<'info> {
    #[account(constraint = !config.paused @ ErrorCode::ProgramPaused)]
    pub config: Account<'info, ProgramConfig>,
}
```

### Token-2022 Extension Handling

- Use `InterfaceAccount` and `Interface<'info, TokenInterface>` for Token-2022 compatibility
- Always check for transfer hooks, transfer fees, and confidential transfers
- Calculate rent based on all enabled extensions

**Example:**
```rust
use anchor_spl::token_interface::{self, TokenInterface, TokenAccount};

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub to: InterfaceAccount<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}
```

---

## Modern Practices (2026)

- Use Anchor 0.32+ for latest security features
- Use `InitSpace` derive for all account space calculations
- Emit events for all critical state changes
- Write fuzz tests with Trident or similar frameworks
- Document invariants in code comments
- Follow progressive roadmap: Dev → Audit → Testnet → Audit → Mainnet

---

*Material sourced from tenequm's claude-plugins solana-security skill and adapted for the WEB3 Audit Skills project.*

---

## Related Files

- [Solana Vulnerability Patterns](solana-patterns.md) — Full pattern reference with code examples
- [Account Validation](account-validation.md) — Detailed validation check reference
- [Pinocchio Security](pinocchio-security.md) — Native-level TryFrom, Token-2022, zero-copy safety
- [Solana Testing for Auditors](solana-testing-for-auditors.md) — LiteSVM, Mollusk, PoC examples
- [Anchor Audit Workflow](../workflows/anchor-audit.md) — Step-by-step Anchor audit process
