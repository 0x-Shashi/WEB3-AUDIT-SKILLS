---
id: SOLANA-CAVEATS
title: Solana & Anchor Caveats for Auditors
category: solana-scanner
difficulty: intermediate
triggers:
  - solana caveats
  - anchor gotchas
  - solana quirks
  - solana runtime behavior
  - anchor limitations
  - token-2022 gotchas
  - testing blind spots
related_skills:
  - solana-scanner/resources/anchor-security.md
  - solana-scanner/resources/native-security.md
  - solana-scanner/resources/security-checklists.md
  - solana-scanner/resources/solana-patterns.md
tags:
  - solana
  - anchor
  - caveats
  - runtime
  - token-2022
last_updated: 2026-02-26
description: >-
  Critical limitations, quirks, and gotchas in Solana and Anchor that catch
  auditors off-guard. Covers framework limitations, runtime behavior, token
  program edge cases, testing blind spots, and common misunderstandings.
  Material sourced from tenequm's claude-plugins solana-security skill.
---

# Solana & Anchor Caveats for Auditors

> Things that compile, pass tests, and look correct — but break in production or hide exploitable conditions.

---

## 1. Anchor Framework Limitations

### 1.1 `init_if_needed` Re-initialization Risk

```rust
// Dangerous: Can bypass initialization logic
#[account(init_if_needed, payer = user, space = ...)]
pub user_account: Account<'info, UserAccount>,
```

**Issue**: If account already exists, initialization is skipped entirely. Existing malicious or inconsistent data is not validated.

**When acceptable**: Only when you explicitly validate existing accounts in instruction logic. Safe for idempotent operations or pure signing PDAs with no meaningful state.

### 1.2 `AccountLoader` Missing Discriminator Check

```rust
// Does NOT validate discriminator by default!
#[account(mut)]
pub user: AccountLoader<'info, User>,
```

**Issue**: `AccountLoader` is for zero-copy accounts and doesn't check the account discriminator automatically. Enables type cosplay attacks.

**Solution**: Use `Account<'info, T>` when possible, or add manual discriminator check.

### 1.3 `close` Constraint Ordering

```rust
// ❌ Wrong: close must be last
#[account(close = receiver, mut, has_one = authority)]

// ✅ Correct: close is last
#[account(mut, has_one = authority, close = receiver)]
```

**Issue**: Anchor processes constraints in order. If `close` isn't last, subsequent constraints may check zeroed account data.

### 1.4 Space Calculation Errors Are Permanent

```rust
// If this space is wrong, account is unusable!
#[account(init, payer = user, space = 8 + 32)]  // Too small
pub user_account: Account<'info, UserAccount>,
```

**Issue**: Once initialized, account size is fixed. Too small = deserialization fails. Too large = wasted rent.

**Solution**: Always use `InitSpace` derive macro:
```rust
#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub authority: Pubkey,
    #[max_len(100)]
    pub name: String,
}
// Use: space = 8 + UserAccount::INIT_SPACE
```

### 1.5 `constraint` Expression Limitations

```rust
// ❌ Compile error — can't use ? operator in constraint
#[account(
    constraint = some_validation(account.value)? @ ErrorCode::Invalid
)]
```

**Issue**: Constraint expressions must be simple boolean checks. Cannot use `?` operator or call fallible functions.

**Solution**: Move complex validation into the instruction body.

### 1.6 Constraint Evaluation Order

Anchor evaluates constraints in a fixed order:

1. `init` / `init_if_needed` / `mut` / `close`
2. `seeds` and `bump`
3. `has_one`
4. `constraint`
5. Account deserialization

**Implications**:
- Can't reference deserialized data in `seeds`
- `constraint` expressions CAN use deserialized data
- `close` at end ensures account data available for other checks

### 1.7 `realloc::zero = false` Leaks Data

```rust
#[account(mut, realloc = new_space, realloc::payer = payer, realloc::zero = false)]
pub data_account: Account<'info, DataAccount>,
```

**Issue**: When shrinking, `zero = false` leaves old data bytes readable. When expanding, uninitialized bytes may contain stale heap data.

**Solution**: Always use `realloc::zero = true` unless you have a specific reason not to.

---

## 2. Solana Runtime Quirks

### 2.1 Account Data Persists After Zeroing Lamports

```rust
// Within same transaction:
**account.lamports.borrow_mut() = 0;
let data = account.try_borrow_data()?;  // Still readable!
```

**Issue**: Account data remains accessible within the transaction even after lamports are zeroed. Only garbage-collected after transaction completes.

**Implication**: Always check lamports > 0 before reading account data. Poison the discriminator when closing.

### 2.2 Non-Canonical PDA Bumps

```rust
// Multiple PDAs possible with different bumps!
let (pda_canonical, _) = Pubkey::find_program_address(seeds, program_id);  // bump = 255
let pda_other = Pubkey::create_program_address(&[seeds, &[254]], program_id);  // Also valid!
```

**Issue**: Same seeds can derive multiple PDAs with different bumps, creating confusion and potential exploits.

**Solution**: Always use canonical bump. Anchor's `bump` constraint enforces this. In native Rust, always use `find_program_address` and store the returned bump.

### 2.3 Compute Budget Limits

| Network | Base CU | Maximum CU (with request) |
|---------|---------|--------------------------|
| Mainnet | 200,000 | 1,400,000 |
| Devnet | 200,000 | 1,400,000 |

**Optimization strategies**:
- Minimize CPIs (each costs ~1000 CU overhead)
- Use `AccountLoader` (zero-copy) for large accounts
- Avoid loops with variable length
- Request higher budget: `ComputeBudgetProgram::set_compute_unit_limit()`

### 2.4 Transaction Size Limit

**Hard limit**: ~1232 bytes per transaction

**Implications**:
- Limits number of accounts (~35-40 accounts typical max)
- Large instructions need Account Compression or chunking
- Can't pass large data directly in instruction data

**Solutions**: Use PDAs for large data, break into multiple txs, use Address Lookup Tables.

### 2.5 Account Snapshot Loading

```rust
let balance_before = ctx.accounts.vault.balance;
// CPI happens here — modifies vault on-chain
// balance_before is STALE — loaded before CPI
```

**Issue**: Accounts are loaded as snapshots at transaction start. Modifications during the transaction (via CPIs) don't update the loaded data.

**Solution**: Call `.reload()` after any CPI that might modify the account. In native Rust, re-deserialize from `AccountInfo`.

---

## 3. Token Program Gotchas

### 3.1 ATA Addresses Are Deterministic But Not Guaranteed to Exist

```rust
let ata = get_associated_token_address(&owner, &mint);
// ATA address is deterministic but account might not exist!
```

**Issue**: ATA address can be calculated but account may not be initialized.

**Solution**: Check account exists and is initialized before use, or use `init_if_needed` with proper validation for ATA creation.

### 3.2 Delegates Don't Automatically Reset

```rust
// After transfer of ownership:
token_account.owner = new_owner;
// BUT: delegate and delegated_amount are NOT reset!
```

**Issue**: Changing owner doesn't clear delegate or close authority. Old delegate can still spend tokens.

**Solution**: Explicitly reset authorities when changing ownership:
```rust
account.delegate = COption::None;
account.delegated_amount = 0;
if account.is_native() {
    account.close_authority = COption::None;
}
```

### 3.3 Token-2022 Extension Rent

**Issue**: Each extension adds rent cost. Account size varies by extensions enabled.

| Extension | Approximate Size |
|-----------|-----------------|
| Transfer Fee | ~83 bytes |
| Transfer Hook | ~107 bytes |
| Permanent Delegate | ~36 bytes |
| Interest Bearing | ~40 bytes |

**Solution**: Calculate rent based on ALL enabled extensions, not just base account size.

### 3.4 Token-2022 Transfer Hooks Can Be Malicious

```rust
// Transfer hook can call arbitrary program!
pub struct TransferHookAccount {
    pub program_id: Pubkey,  // Could be malicious
}
```

**Issue**: Transfer hook extensions allow calling an external program during transfers. Malicious hooks can fail transactions or drain funds.

**Solution**:
- Validate the transfer hook program if accepting specific tokens
- Consider disallowing tokens with transfer hooks in sensitive contexts
- Use `TransferChecked` instruction which respects hooks properly

---

## 4. Testing Blind Spots

### 4.1 Concurrent Transaction Ordering

**Issue**: Tests typically run transactions sequentially. In production, concurrent transactions can interleave in unexpected ways.

```
Transaction 1: Check balance = 100
Transaction 2: Withdraw 80 (balance now 20)
Transaction 1: Withdraw 80 (uses stale check, balance now -60!)
```

**Mitigation**: Use atomic operations, reload accounts before critical operations, design for idempotency.

### 4.2 Account Rent Reclaim Attacks

**Issue**: When account rent falls below minimum, the runtime can reclaim the account. Tests don't simulate this.

**Solution**: Ensure all accounts are rent-exempt (maintain minimum balance).

### 4.3 Sysvar Manipulation in Tests

```rust
// In tests, you can set arbitrary clock values
ctx.accounts.clock = Clock { unix_timestamp: attacker_value, ... };
```

**Issue**: Tests may not catch reliance on tamper-resistant sysvars. In production, always load sysvars from official sysvar accounts.

**Solution**: Use `Sysvar<'info, Clock>` (validated address), not raw `AccountInfo`.

### 4.4 Devnet vs Mainnet Differences

| Aspect | Devnet | Mainnet |
|--------|--------|---------|
| Oracle prices | Often stale/fake | Real-time |
| Program versions | May differ | Stable versions |
| Compute limits | More lenient | Strict enforcement |
| Congestion | Minimal | Can be high |
| Token availability | Test tokens (no value) | Real value |

**Issue**: Programs tested only on devnet may fail or behave differently on mainnet.

**Solution**: Test on mainnet-fork or mainnet with small amounts before full deployment. Use Surfpool for integration testing with real mainnet state.

---

## 5. Rust-Specific Gotchas

### 5.1 `unwrap()` Panics Kill Transactions

```rust
let value = some_option.unwrap();  // ❌ Panics = entire tx fails
```

**Solution**: Always use proper error handling:
```rust
let value = some_option.ok_or(ErrorCode::MissingValue)?;
```

### 5.2 Integer Division Truncation

```rust
let result = 5 / 2;  // result = 2, not 2.5!
```

**Issue**: Integer division truncates, causing precision loss in financial calculations.

**Solution**: Use `Decimal` type for precise calculations, or multiply before divide:
```rust
let result = (5u64 * PRECISION) / 2 / PRECISION;
```

### 5.3 Debug vs Release Overflow Behavior

```rust
// Debug mode: panics on overflow
// Release mode: wraps silently!
let x: u8 = 255;
let y = x + 1;  // Debug: panic, Release: y = 0
```

**Issue**: Overflow behavior differs between debug and release builds. Tests (debug mode) catch overflows that silently wrap in production (release mode).

**Solution**: Always use `checked_*` methods — they behave identically in both modes. Or set `overflow-checks = true` in `[profile.release]` in Cargo.toml.

---

## 6. CPI Gotchas

### 6.1 CPI Success Doesn't Guarantee Correct State

```rust
invoke(&transfer_instruction, &accounts)?;
// Transfer succeeded but amount might differ due to fees!
```

**Issue**: A CPI returning `Ok(())` means the callee didn't error — not that the state change matches your expectations (especially with Token-2022 transfer fees).

**Solution**: Reload and validate account state after CPI. Compare before/after balances.

### 6.2 Signer Seeds Must Be Exact

```rust
let seeds = &[b"vault", user.key().as_ref(), &[bump]];
invoke_signed(&instruction, &accounts, &[seeds])?;
```

**Issue**: Seeds for PDA signing must match the PDA derivation exactly. Wrong seeds = "signature verification failed" error. Wrong bump = different PDA entirely.

### 6.3 CPI Depth Limit

**Limit**: 4 levels of CPI depth.

```
Program A → Program B → Program C → Program D → Program E (FAILS!)
```

**Solution**: Design programs to minimize CPI depth. If you're already at depth 3, any callee that does its own CPI will fail.

---

## 7. Common Misunderstandings

| Myth | Reality |
|------|---------|
| "Anchor prevents all security issues" | Anchor prevents discriminator/owner/signer issues *if you use the right types*. Business logic, arithmetic, and authorization are still your responsibility. |
| "Devnet testing is sufficient" | Mainnet has different compute limits, real oracle data, congestion, and MEV. |
| "One audit makes code secure" | Audits find issues in a snapshot. Post-audit code changes reintroduce risk. Continuous security review is necessary. |
| "`checked_*` methods are slower" | Rust compiler optimizes these similarly to unchecked arithmetic. No meaningful performance difference. Always use checked methods. |
| "PDAs can't sign" | True for external transactions, false for CPIs. PDAs CAN sign CPIs using `invoke_signed`. |
| "`saturating_*` is safe" | It silently clips to MIN/MAX instead of erroring — this hides bugs. Use `checked_*` and propagate errors explicitly. |

---

## 8. Version-Specific Issues

### Anchor Version Compatibility

| Version | Notes |
|---------|-------|
| < 0.28 | No `InitSpace` derive — manual space calculation error-prone |
| < 0.29 | Different constraint syntax, `ctx.bumps` not available |
| 0.30+ | Breaking changes in error handling and account initialization |
| 0.31+ | Custom discriminators, LazyAccount — new attack surfaces |
| 0.32+ | Requires Rust 1.89+ |

**Audit action**: Check `Cargo.toml` for Anchor version and consult the [Anchor Changelog](https://github.com/coral-xyz/anchor/blob/master/CHANGELOG.md).

### Solana Version Differences

| Version | Change |
|---------|--------|
| Pre-1.14 | Different fee structure |
| Pre-1.16 | No Address Lookup Tables |
| Pre-1.17 | No Token-2022 |
| 2.0+ (Agave) | New validator client, potential behavior differences |

**Audit action**: Verify target Solana version matches deployment network. Check that program dependencies are compatible.

---

## Key Takeaway

Many "obvious" assumptions about blockchain behavior don't hold in Solana. Always validate against actual runtime behavior, not assumptions from other chains or from test environments.

---

## Related Files

- [Anchor Security](anchor-security.md) — Anchor-specific vulnerability patterns and constraints
- [Native Security](native-security.md) — Native Rust validation patterns and serialization security
- [Security Checklists](security-checklists.md) — Structured validation checklists for every audit
- [Solana Patterns](solana-patterns.md) — Vulnerability patterns with ❌/✅ code examples
- [Solana Testing for Auditors](solana-testing-for-auditors.md) — PoC frameworks and testing strategies

---

*Material sourced from tenequm's claude-plugins solana-security skill and adapted with YAML frontmatter for the WEB3 Audit Skills project.*
