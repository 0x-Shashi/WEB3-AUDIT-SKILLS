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

> Anchor automates many Solana safety checks, but introduces its own vulnerability surface. This guide covers Anchor-specific risks beyond what the framework protects against.

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

## Related Files

- [Solana Vulnerability Patterns](solana-patterns.md) — Full pattern reference with code examples
- [Account Validation](account-validation.md) — Detailed validation check reference
- [Pinocchio Security](pinocchio-security.md) — Native-level TryFrom, Token-2022, zero-copy safety
- [Solana Testing for Auditors](solana-testing-for-auditors.md) — LiteSVM, Mollusk, PoC examples
- [Anchor Audit Workflow](../workflows/anchor-audit.md) — Step-by-step Anchor audit process
