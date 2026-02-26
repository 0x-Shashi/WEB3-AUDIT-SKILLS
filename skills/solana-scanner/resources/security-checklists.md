---
id: SOLANA-SECURITY-CHECKLISTS
title: Solana Security Audit Checklists
category: solana-scanner
difficulty: intermediate
triggers:
  - solana security checklist
  - solana audit checklist
  - account validation checklist
  - CPI checklist
  - oracle checklist
  - token-2022 checklist
related_skills:
  - solana-scanner/SKILL.md
  - solana-scanner/resources/anchor-security.md
  - solana-scanner/resources/native-security.md
  - solana-scanner/resources/caveats.md
tags:
  - solana
  - checklist
  - audit
  - security
last_updated: 2026-02-26
description: >-
  Structured validation checklists for Solana program security reviews. Covers
  account validation, arithmetic safety, PDA security, CPI safety, oracle/external
  data, token programs (SPL + Token-2022), architecture, and testing.
  Material sourced from tenequm's claude-plugins solana-security skill.
---

# Solana Security Audit Checklists

> Use these checklists for every instruction in every program. An unchecked item is a potential vulnerability.

---

## 1. Account Validation Checklist

For every account in every instruction:

- [ ] **Signer validation**: Uses `Signer<'info>` or `is_signer` check when needed
- [ ] **Owner validation**: Uses `Account<'info, T>` (auto) or manual `owner == program_id` check
- [ ] **Writable checks**: Properly marked `mut` when account data will be modified
- [ ] **Account initialization**: Checks `is_initialized` before use (prevents uninitialized reads)
- [ ] **PDA validation**: Validates seeds and uses canonical bump
- [ ] **Discriminator check**: For `AccountLoader`, validates account type manually
- [ ] **Account relationships**: Uses `has_one` or manual field comparison for related accounts
- [ ] **Uniqueness**: Semantically distinct accounts compared for `key() != key()`

```rust
// Complete account validation example (Anchor)
#[derive(Accounts)]
pub struct SecureInstruction<'info> {
    #[account(
        mut,
        has_one = authority,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,

    pub authority: Signer<'info>,

    #[account(
        mut,
        constraint = token_account.owner == authority.key()
            @ ErrorCode::InvalidTokenOwner,
    )]
    pub token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}
```

---

## 2. Arithmetic Safety Checklist

For all mathematical operations:

- [ ] **Addition**: Uses `checked_add()` instead of `+`
- [ ] **Subtraction**: Uses `checked_sub()` instead of `-`
- [ ] **Multiplication**: Uses `checked_mul()` instead of `*`
- [ ] **Division**: Uses `checked_div()` instead of `/`
- [ ] **Division by zero**: Validates divisor is non-zero before dividing
- [ ] **Precision loss**: Uses `try_floor_u64()` instead of `try_round_u64()` to prevent rounding arbitrage
- [ ] **No saturating**: Does NOT use `saturating_*` methods (they hide errors silently)
- [ ] **Error propagation**: All arithmetic wrapped in `.ok_or(error)?`
- [ ] **Cargo.toml**: Check for `overflow-checks = true` in `[profile.release]`

```rust
// Secure arithmetic pattern
let total = balance
    .checked_add(amount)
    .ok_or(ErrorCode::Overflow)?;

let share = total
    .checked_div(denominator)
    .ok_or(ErrorCode::DivisionByZero)?;

// For Decimal types (token amounts)
let liquidity = Decimal::from(collateral_amount)
    .try_div(rate)?
    .try_floor_u64()?;  // Not try_round_u64()!
```

---

## 3. PDA and Account Security Checklist

- [ ] **Canonical bump**: PDAs use `bump` in seeds constraint (not hardcoded values)
- [ ] **Bump stored**: Canonical bump stored in account data at initialization
- [ ] **Unique seeds**: Seeds include unique identifier (user pubkey, mint, etc.) — no PDA sharing
- [ ] **No duplicate accounts**: Same account not passed as two different mutable parameters
- [ ] **Init vs init_if_needed**: Uses `init` with proper validation, NOT `init_if_needed` (unless justified)
- [ ] **has_one constraints**: Related accounts validated with `has_one` or manual field comparison
- [ ] **Custom constraints**: Complex validation uses `constraint` expression with `@` error codes
- [ ] **Seed collision**: Seeds designed to prevent collisions across users/contexts

```rust
// Secure PDA pattern — unique per user AND mint
#[account(
    init,
    payer = authority,
    space = 8 + UserAccount::INIT_SPACE,
    seeds = [
        b"user",
        authority.key().as_ref(),
        mint.key().as_ref(),
    ],
    bump
)]
pub user_account: Account<'info, UserAccount>,
```

---

## 4. CPI Security Checklist

For all Cross-Program Invocations:

- [ ] **Program validation**: Target is validated (`Program<'info, T>` or key comparison against constant)
- [ ] **No arbitrary CPI**: Program account is NOT user-controlled `AccountInfo`
- [ ] **Signer seeds correct**: PDA signers pass correct seeds in `invoke_signed` / `CpiContext::new_with_signer`
- [ ] **Account reloading**: Accounts reloaded (`.reload()`) after CPI that may modify them
- [ ] **Return value used**: CPI success checked — `?` propagated, not silently ignored
- [ ] **State validation**: Post-CPI state validated (not just trusting success)
- [ ] **Privilege escalation**: CPI doesn't grant unexpected signer privileges to callee
- [ ] **CPI depth**: Not exceeding 4-level CPI depth limit

```rust
// Secure CPI pattern (Anchor)
pub fn secure_transfer(ctx: Context<SecureCPI>, amount: u64) -> Result<()> {
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),  // Program<'info, Token>
            Transfer {
                from: ctx.accounts.from.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ),
        amount,
    )?;

    // Reload account after CPI
    ctx.accounts.from.reload()?;

    // Validate expected state
    require!(
        ctx.accounts.from.amount == expected_remaining,
        ErrorCode::UnexpectedBalance
    );

    Ok(())
}
```

---

## 5. Oracle and External Data Checklist

For Pyth, Switchboard, or other oracle integrations:

- [ ] **Oracle owner**: Validates oracle account owner is the correct oracle program
- [ ] **Oracle status**: Validates oracle is in valid/active state (e.g., `PriceStatus::Trading` for Pyth)
- [ ] **Price staleness**: Checks timestamp is recent enough (e.g., < 60 seconds old)
- [ ] **Confidence interval**: For Pyth, checks confidence is within acceptable range (e.g., < 1% of price)
- [ ] **Price validity**: Validates price is within reasonable bounds (not zero, not absurdly high)
- [ ] **Fallback handling**: Has strategy for oracle failure (pause, use backup, revert)

```rust
// Pyth oracle validation
pub fn validate_pyth_price(
    pyth_account: &AccountInfo,
    clock: &Clock,
) -> Result<i64> {
    // 1. Validate owner
    require_keys_eq!(
        *pyth_account.owner,
        PYTH_PROGRAM_ID,
        ErrorCode::InvalidOracle
    );

    let price_feed = load_price_feed_from_account_info(pyth_account)?;

    // 2. Check status
    require!(
        price_feed.agg.status == PriceStatus::Trading,
        ErrorCode::OracleNotTrading
    );

    // 3. Check staleness
    let max_age = 60;
    require!(
        clock.unix_timestamp - price_feed.agg.publish_time <= max_age,
        ErrorCode::StaleOraclePrice
    );

    // 4. Check confidence (max 1% of price)
    let confidence_threshold = price_feed.agg.price / 100;
    require!(
        price_feed.agg.conf <= confidence_threshold as u64,
        ErrorCode::OracleConfidenceTooLow
    );

    Ok(price_feed.agg.price)
}
```

---

## 6. Token Program Security Checklist

### SPL Token Checks

- [ ] **ATA validation**: Associated Token Accounts validated via `associated_token::mint` + `associated_token::authority`
- [ ] **Mint authority**: Proper checks on mint authority for minting operations
- [ ] **Freeze authority**: Handles frozen accounts appropriately (transfers blocked)
- [ ] **Delegate handling**: Resets delegate when authority changes
- [ ] **Close authority**: Resets close authority on owner change

### Token-2022 Specific Checks

- [ ] **Transfer hooks**: Handles transfer hook extensions correctly (may call external programs)
- [ ] **Transfer fees**: Respects transfer fee extension — actual received amount may differ
- [ ] **Extension data**: Validates all active extensions before operations
- [ ] **Confidential transfers**: Handles confidential transfer extension properly
- [ ] **Permanent delegate**: Checks for permanent delegate extension (can drain any time)
- [ ] **Additional rent**: Accounts for extension rent requirements (varies by extension)
- [ ] **Program ID branching**: If accepting both SPL Token and Token-2022, branches correctly on `owner`

```rust
// Token-2022 with extensions
use spl_token_2022::extension::{BaseStateWithExtensions, StateWithExtensions};

pub fn safe_token_2022_transfer(/* accounts */) -> Result<()> {
    let mint_data = mint.try_borrow_data()?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;

    // Check for transfer hook
    if let Ok(transfer_hook) = mint_state.get_extension::<TransferHook>() {
        // Handle transfer hook — validate program_id is trusted
    }

    // Check for transfer fee
    if let Ok(fee_config) = mint_state.get_extension::<TransferFeeConfig>() {
        // Calculate and account for fees — actual received ≠ sent amount
    }

    Ok(())
}
```

---

## 7. Architecture Review Checklist

- [ ] **PDA design**: PDAs used appropriately vs keypair accounts
- [ ] **Account space**: Space calculation uses `InitSpace` derive (Anchor 0.28+)
- [ ] **Error handling**: Custom errors with descriptive messages — no silent failures
- [ ] **Event emission**: Critical state changes emit events (deposits, withdrawals, config changes)
- [ ] **Rent exemption**: All accounts are rent-exempt (minimum balance maintained)
- [ ] **Transaction size**: Operations stay within ~1232 byte transaction limit
- [ ] **Compute budget**: Optimized to stay under compute limits (200K base, 1.4M max)
- [ ] **Upgradeability**: Upgrade authority is multisig/governance, not single EOA
- [ ] **Upgrade timelock**: If upgradeable, timelock exists for users to exit before code changes
- [ ] **Account versioning**: State struct has version field for future migrations

---

## 8. Testing Checklist

- [ ] **Unit tests**: Each instruction has unit tests for expected behavior
- [ ] **Negative tests**: Tests for expected failures (wrong signer, insufficient funds, etc.)
- [ ] **Fuzz tests**: Arithmetic and state transitions have fuzz tests (Trident framework)
- [ ] **Integration tests**: Multi-instruction scenarios with realistic account setups
- [ ] **PDA tests**: Tests for seed collision resistance
- [ ] **Edge cases**: Zero amounts, max values (`u64::MAX`), overflow boundaries
- [ ] **Duplicate accounts**: Tests passing same account for different parameters
- [ ] **Concurrency**: Tests for transaction ordering effects
- [ ] **Devnet testing**: Deployed and tested on devnet before mainnet
- [ ] **PoC for findings**: Each finding has a repeatable exploit PoC (LiteSVM / Mollusk)

```rust
// Example test structure
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_path() { /* expected behavior */ }

    #[test]
    #[should_panic(expected = "Overflow")]
    fn test_arithmetic_overflow() { /* overflow protection works */ }

    #[test]
    fn test_unauthorized_access() { /* wrong signer rejected */ }

    #[test]
    fn test_duplicate_accounts() { /* same account for from/to rejected */ }

    #[test]
    fn test_edge_case_zero_amount() { /* zero amount handled correctly */ }
}
```

---

## Related Files

- [SKILL.md](../SKILL.md) — Main scanner skill with audit procedure and vulnerability categories
- [Anchor Security](anchor-security.md) — Anchor-specific vulnerability patterns
- [Native Security](native-security.md) — Native Rust validation patterns
- [Caveats](caveats.md) — Runtime quirks, testing blind spots, common misunderstandings
- [Solana Patterns](solana-patterns.md) — Vulnerability patterns with code examples

---

*Material sourced from tenequm's claude-plugins solana-security skill and adapted for the WEB3 Audit Skills project.*
