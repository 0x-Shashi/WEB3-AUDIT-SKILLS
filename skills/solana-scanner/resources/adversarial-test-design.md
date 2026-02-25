# Adversarial Test Design for Solana Auditors

> **Purpose:** How to evaluate (and design) an attack-first test suite.
> Auditors use this to assess whether a protocol's tests actually catch exploits,
> and to identify missing attack tests during an engagement.

---

## 1. Why Attack Tests Matter for Auditors

A protocol can have 500 tests and still be vulnerable. The audit question is
not "how many tests?" but "do the tests model real adversaries?" This guide
provides a framework for evaluating test quality through an attacker's lens.

### The Auditor's Test Assessment Workflow

```
1. Catalog all tests by naming convention
2. Map tests to attack categories (Section 3)
3. Check for the master conservation invariant (Section 4)
4. Identify missing attack categories
5. Report gaps as informational findings
```

---

## 2. Test Naming Taxonomy

Well-structured test suites use naming conventions that reveal intent.
When assessing a codebase, classify every test into one of these tiers:

| Prefix | Purpose | Auditor Signal |
|--------|---------|----------------|
| `test_comprehensive_*` | Full lifecycle / happy path | Proves the protocol works for honest users |
| `test_critical_*` | Security boundary checks (auth, admin) | Proves access control is enforced |
| `test_attack_*` | Adversarial exploit attempts | Proves specific attacks are blocked |
| `test_vulnerability_*` / `test_bug*` | Regression tests for known bugs | Proves past bugs stay fixed |
| `test_honest_*` | Honest participant baselines | Proves the system is usable under normal conditions |
| `test_property_*` | Invariant / state machine fuzz | Proves global properties hold under random inputs |
| `test_extreme_*` / `test_minimum_*` | Boundary conditions | Proves edge values don't break the system |

### Attack Test Naming Convention

The best pattern is `test_attack_{action}_{condition}`:

```
test_attack_withdraw_wrong_signer          # WHO: wrong identity
test_attack_deposit_without_signer         # WHO: missing authorization
test_attack_sandwich_deposit_withdraw      # WHAT: economic extraction
test_attack_rounding_extraction_rapid      # WHAT: precision abuse
test_attack_same_slot_open_close_timing    # WHEN: timing exploit
test_attack_conservation_large_slot_jump   # INVARIANT: state corruption
test_attack_nonce_replay_same_trade        # REPLAY: duplicate execution
```

### What to Look For During Audit

**Green flags (good coverage):**
- Tests named with `attack_` prefix that model specific exploit scenarios
- Conservation invariant assertions after every state change
- Tests for both success AND failure paths (expect_err on attack)
- Regression tests linked to specific finding IDs

**Red flags (poor coverage):**
- Only happy-path tests (no `attack_` / `critical_` prefix)
- No assertions on state AFTER failed transactions
- Missing entire attack categories (see Section 3)
- No tests for admin key rotation / burned admin

---

## 3. Attack Category Checklist

Use this checklist during every audit. For each category, ask: "Does the
test suite have at least one test for this?" Missing categories are gaps.

### Category A: Authorization Bypass

Tests that verify wrong/missing signers are rejected.

| What to Test | Example Test Name | Key Assertion |
|-------------|-------------------|---------------|
| Wrong owner on user ops | `test_attack_withdraw_wrong_signer` | `assert!(result.is_err())` |
| Missing signer flag | `test_attack_deposit_without_signer` | Transaction rejected |
| Non-admin on admin ops | `test_attack_resolve_market_non_admin` | Instruction fails |
| Old admin after transfer | `test_attack_old_admin_blocked_after_transfer` | Old key rejected |
| Burned admin (zero key) | `test_attack_update_admin_to_zero_locks_out` | All admin ops fail |

**Audit check:** After every rejected auth attempt, verify state is UNCHANGED
(vault balance, positions, counters all identical to pre-attack snapshot).

### Category B: Account Substitution

Tests that verify wrong accounts (PDAs, vaults, tokens) are rejected.

| What to Test | Example Test Name |
|-------------|-------------------|
| Wrong vault PDA | `test_attack_withdraw_wrong_vault_pda` |
| Wrong token program | `test_attack_withdraw_wrong_token_program` |
| Wrong oracle account | `test_attack_deposit_wrong_oracle_account` |
| Wrong mint token account | `test_attack_deposit_wrong_mint_token_account` |
| User ATA aliased as vault | `test_attack_withdraw_alias_user_ata_is_vault` |
| Wrong slab owner | `test_attack_deposit_wrong_slab_owner` |

### Category C: Economic Extraction

Tests that verify an attacker cannot profit at others' expense.

| What to Test | Example Test Name |
|-------------|-------------------|
| Sandwich attack | `test_attack_sandwich_deposit_withdraw` |
| Rounding extraction | `test_attack_rounding_extraction_rapid_trades` |
| Fee evasion | `test_attack_trading_fee_insurance_conservation` |
| Dust accumulation theft | `test_attack_dust_sweep_to_insurance_on_crank` |
| Withdraw from others | `test_attack_withdraw_from_others_account` |
| Deposit to others (grief) | `test_attack_deposit_to_others_account` |

**Key pattern:** Economic tests should check that `attacker_balance_after <= attacker_balance_before`. The attacker should never profit.

### Category D: Conservation / Accounting Invariants

Tests that verify funds are never created or destroyed.

| What to Test | Example Test Name |
|-------------|-------------------|
| Basic conservation | `test_attack_conservation_invariant` |
| Conservation through price moves | `test_attack_conservation_through_price_movement` |
| Conservation across large time jumps | `test_attack_conservation_large_slot_jump` |
| Multi-user conservation | `test_attack_multi_user_lifecycle_conservation` |
| Full lifecycle conservation | `test_attack_full_lifecycle_conservation` |
| Deposit-withdraw cycle | `test_attack_withdraw_redeposit_cycle_conservation` |

**This is the most important category.** See Section 4 for the master
invariant pattern.

### Category E: Timing / Same-Slot Attacks

Tests that verify same-block operations don't create exploits.

| What to Test | Example Test Name |
|-------------|-------------------|
| Same-slot open+close | `test_attack_same_slot_open_close_timing` |
| Same-slot deposit+withdraw | `test_attack_deposit_withdraw_same_slot_atomicity` |
| Same-slot double crank | `test_attack_same_slot_crank_no_double_funding` |
| Deposit+trade same slot | `test_attack_trade_immediately_after_deposit_same_slot` |
| Multiple withdrawals same slot | `test_attack_multiple_withdrawals_same_slot` |

### Category F: Boundary / Extreme Values

Tests that verify edge values don't cause panics or overflows.

| What to Test | Example Test Name |
|-------------|-------------------|
| Zero amount operations | `test_attack_deposit_zero_amount_no_state_change` |
| i128::MIN / i128::MAX | `test_attack_trade_size_i128_min_boundary` |
| u64::MAX config values | `test_attack_oracle_price_cap_u64_max` |
| Size = 1 (minimum) | `test_attack_trade_size_one_conservation` |
| Size = -1 | `test_attack_trade_size_negative_one_conservation` |
| Extreme prices | `test_attack_trade_at_extreme_high_price` |

### Category G: State Machine / Lifecycle

Tests that verify operations respect state transitions.

| What to Test | Example Test Name |
|-------------|-------------------|
| Operations after resolution | `test_attack_tradecpi_after_resolution` |
| Double resolution | `test_attack_double_resolve_market` |
| Close with open position | `test_attack_close_account_with_positive_pnl` |
| GC after close (clean state) | `test_attack_slot_reuse_clean_state_after_gc` |
| Account reinit after GC | `test_attack_account_reinit_after_gc_clean_state` |
| Instruction tag out of bounds | `test_attack_instruction_tag_just_above_max` |
| Extra trailing bytes | `test_attack_instruction_data_extra_trailing_bytes` |

### Category H: Replay / Nonce

Tests that verify deduplication and ordering.

| What to Test | Example Test Name |
|-------------|-------------------|
| Nonce replay | `test_attack_nonce_replay_same_trade` |
| Double deposit accumulation | `test_attack_double_deposit_accumulation` |
| Double close | `test_attack_double_close_account_same_index` |
| Double resolve | `test_attack_double_resolve_market` |

### Category I: Oracle Manipulation

Tests that verify oracle data is validated and bounded.

| What to Test | Example Test Name |
|-------------|-------------------|
| Stale oracle timestamp | `test_attack_push_oracle_stale_timestamp` |
| Extreme oracle price | `test_attack_hyperp_push_extreme_price` |
| Zero oracle price | `test_attack_scale_price_zero_rejects_trade` |
| Wrong oracle crank | `test_attack_crank_wrong_oracle` |
| Oracle after resolution | `test_attack_push_oracle_after_resolution_rejected` |
| Circuit breaker clamping | `test_attack_circuit_breaker_clamping_second_price` |

### Category J: Cross-Account Isolation

Tests that verify one user's actions don't affect another.

| What to Test | Example Test Name |
|-------------|-------------------|
| Same owner, multiple accounts | `test_attack_same_owner_multiple_accounts_isolation` |
| Cross-market isolation | `test_attack_cross_market_isolation` |
| Multi-LP independence | `test_attack_multi_lp_independent_positions` |
| Opposing users PnL conservation | `test_attack_opposing_users_pnl_conservation` |

---

## 4. The Master Conservation Invariant

The single most important test pattern in DeFi. After EVERY state-changing
operation, assert:

```
vault_balance >= capital_total + insurance_balance
```

### The Pattern

```rust
// Before operation — snapshot state
let vault_before = env.vault_balance();

// Perform operation (deposit, trade, crank, withdraw, etc.)
env.deposit(&user, user_idx, amount);

// After operation — check conservation
let vault_after = env.vault_balance();
let engine_vault = env.read_engine_vault();
let c_tot = env.read_c_tot();
let insurance = env.read_insurance_balance();

// P1: Master conservation
assert!(vault_after as u128 >= c_tot + insurance,
    "CONSERVATION VIOLATED: vault={} c_tot={} ins={}",
    vault_after, c_tot, insurance);

// P2: Engine/SPL token sync
assert_eq!(engine_vault as u64, vault_after,
    "ENGINE/SPL DESYNC: engine={} spl={}",
    engine_vault, vault_after);
```

### What Each Invariant Catches

| Invariant | What It Catches |
|-----------|----------------|
| `vault >= c_tot + insurance` | Funds created from nothing, double-counting |
| `engine_vault == spl_vault` | Internal accounting desync from SPL token balance |
| `sum(all_capitals) == c_tot` | Aggregate drift — individual accounts don't sum to total |
| `pnl_pos_tot >= 0` | Negative PnL incorrectly marked as positive |

### When to Check

- After EVERY deposit, withdraw, trade, crank, liquidation, close
- After failed/rejected operations (state should be UNCHANGED)
- After administrative operations (config changes, admin transfers)
- After large time jumps (funding accrual, fee accumulation)
- After extreme price movements (liquidation cascade)

### Auditor's Red Flag

If the protocol has NO conservation invariant tests, this is a **high-severity
finding**. Any DeFi protocol handling user funds must prove that:
1. Funds cannot be created from nothing
2. Funds cannot disappear into the void
3. Internal accounting matches on-chain token balances

---

## 5. The Property Test Pyramid

Well-tested protocols use a layered approach:

```
        ┌──────────────────────┐
        │  Property Tests      │  ← State machine fuzzer (Section 6)
        │  (40,000 random ops) │     Finds emergent bugs from combinations
        ├──────────────────────┤
        │  Attack Tests        │  ← Targeted adversarial scenarios
        │  (~170 named tests)  │     Proves specific attack vectors fail
        ├──────────────────────┤
        │  Critical Tests      │  ← Security boundary verification
        │  (~20 auth tests)    │     Proves access control works
        ├──────────────────────┤
        │  Comprehensive Tests │  ← Full lifecycle happy path
        │  (~20 scenario tests)│     Proves the system works at all
        └──────────────────────┘
```

### Assessment Scoring

| Score | Coverage Level | What It Means |
|-------|---------------|---------------|
| **A** | All 4 layers populated, conservation invariant, property fuzzer | Production-grade |
| **B** | Attack + critical tests present, conservation invariant | Good coverage |
| **C** | Some attack tests, no conservation invariant | Significant gaps |
| **D** | Only happy-path tests | Minimal confidence |
| **F** | No tests or only unit tests on helpers | Zero exploitation evidence |

---

## 6. The "Honest Participant Baseline" Pattern

Before writing attack tests, establish that the protocol works for honest users:

```
test_honest_user_standard_market_profitable_close
test_honest_user_standard_market_losing_close
test_honest_user_standard_market_warmup_close
test_honest_user_inverted_market_close
test_honest_participants_full_lifecycle
```

Each test follows the pattern:
1. Create market, LP, user
2. User deposits, opens position, price moves, crank runs
3. User closes position, withdraws, closes account
4. Assert: user received correct amount (profit or loss)
5. Assert: conservation invariant holds

**Why it matters:** If honest-path tests fail, attack tests are meaningless.
This establishes the baseline that the protocol is internally consistent.

---

## 7. Bug Regression Test Pattern

Every finding from an audit should become a regression test:

```rust
/// Bug: CloseSlab only checks engine.vault and engine.insurance_fund.balance,
/// but not dust_base which can hold residual base tokens.
#[test]
fn test_bug3_close_slab_with_dust_should_fail() {
    // Setup: create state where dust_base > 0
    // Action: attempt CloseSlab
    // Assert: CloseSlab rejected (dust would be locked)
}

/// Bug: If fee_payment > new_account_fee, the excess is deposited to vault
/// but only new_account_fee is accounted in engine.vault/insurance.
#[test]
fn test_bug4_fee_overpayment_should_be_handled() {
    // Setup: set new_account_fee, then pay more than required
    // Assert: excess correctly handled (not lost or double-counted)
}
```

**Convention:** Link each regression test to its finding ID
(`test_bug{N}_description` or `test_vulnerability_{finding_slug}`).

---

## 8. Audit Checklist: Assessing a Test Suite

During any Solana protocol audit, run through this checklist:

```
□ Authorization bypass tests exist for EVERY privileged instruction
□ Wrong-account substitution tests exist for EVERY account parameter
□ Conservation invariant checked after EVERY state-changing operation
□ Same-slot timing tests exist for deposit, withdraw, trade, crank
□ Boundary value tests exist for 0, 1, -1, MAX, MIN values
□ Economic extraction tests (sandwich, rounding, fee evasion)
□ State machine property test with deterministic fuzzer
□ Bug regression tests linked to historical findings
□ Admin key rotation tested (old admin locked out)
□ Burned/zero admin tested (all admin ops permanently disabled)
□ Oracle staleness/extremes tested
□ Post-resolution operations rejected
```

**Reporting:** For each unchecked box, file an informational finding:
"Missing adversarial test coverage for {category}. Recommend adding
`test_attack_{specific_scenario}` to prevent future regressions."

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-02-25 | Initial creation — methodology extracted from percolator-prog test patterns |
