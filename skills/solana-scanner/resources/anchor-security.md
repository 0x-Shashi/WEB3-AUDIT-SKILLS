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
last_updated: 2026-01-31
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
- [Anchor Audit Workflow](../workflows/anchor-audit.md) — Step-by-step Anchor audit process
