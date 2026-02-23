---
id: SOLANA-ACCOUNT-VALIDATION
title: Solana Account Validation Patterns
category: solana-scanner
difficulty: intermediate
triggers:
  - solana account validation
  - owner check
  - signer check
  - PDA validation
  - account security
related_skills:
  - solana-scanner/resources/solana-patterns.md
  - solana-scanner/resources/anchor-security.md
  - solana-scanner/workflows/native-audit.md
tags:
  - solana
  - accounts
  - validation
  - security
last_updated: 2026-01-31
---

# Solana Account Validation Patterns

> Every account passed to a Solana program instruction is untrusted by default. The Solana runtime does NOT validate account ownership, type, or relationships — the program must do this manually (native) or via framework constraints (Anchor).

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
| Attack | Missing Check | Impact | Real-World Example |
|--------|--------------|--------|-------------------|
| Fake account injection | Owner check | Read/write arbitrary data | Cashio ($48M) — fake bank account |
| Unauthorized action | Signer check | Steal funds | Wormhole ($320M) — spoofed sysvar |
| Wrong PDA | Seed validation | Access wrong vault | Crema Finance ($8.8M) — fake tick |
| Type confusion | Discriminator | Misinterpret data | Common in native programs |
| Duplicate accounts | Distinctness check | Double-count balances | bZx-style self-transfer |
| Stale data | Freshness check | Use outdated state | Accounts not refreshed after CPI |

## Validation Matrix Template

Use this matrix for every instruction in a native Solana program:

```
| Account       | Owner ✓ | Signer ✓ | Writable ✓ | PDA ✓ | Type ✓ | Relationship ✓ |
|---------------|---------|----------|------------|-------|--------|----------------|
| vault         | program | -        | ✓          | ✓     | Vault  | has_one: owner |
| owner         | -       | ✓        | -          | -     | -      | -              |
| token_account | Token   | -        | ✓          | ATA   | Token  | has: mint      |
| system_prog   | Native  | -        | -          | -     | -      | hardcoded key  |
```

**Rule**: Every cell must be explicitly checked in code. An empty cell in the matrix is a potential vulnerability.

---

## Related Files

- [Solana Vulnerability Patterns](solana-patterns.md) — Full pattern reference with vulnerable + secure code
- [Anchor Security Guide](anchor-security.md) — Anchor-specific validation and vulnerabilities
- [Native Audit Workflow](../workflows/native-audit.md) — Step-by-step native program audit
