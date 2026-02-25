# State Machine Fuzzer Template

> **Purpose:** A reusable methodology template for building deterministic
> integration fuzzers that find emergent bugs from random operation sequences.
> Chain-agnostic — applicable to any stateful protocol.

---

## 1. What This Template Is For

Individual attack tests verify specific scenarios. But real bugs emerge from
**unexpected combinations** of valid operations. A state machine fuzzer:

1. Models the protocol as a finite state machine
2. Randomly generates sequences of valid operations
3. Checks global invariants after EVERY step
4. Uses deterministic PRNG for reproducible failures

```
Traditional tests:  "Does attack X fail?"     → Yes/No
State machine fuzz: "Do ANY 5,000 random ops break?" → Finds emergent bugs
```

### When to Recommend This in an Audit

| Situation | Recommendation |
|-----------|---------------|
| Protocol has complex state with many interacting operations | "Add state machine fuzzer" |
| Protocol handles user funds with deposits/withdrawals/trades | "Conservation invariant fuzzer recommended" |
| Protocol has admin operations that change behavior mid-lifecycle | "Include config mutations in fuzzer" |
| Protocol has no fuzz testing at all | "Consider deterministic integration fuzzer" |

---

## 2. Architecture

Every state machine fuzzer has 5 components:

```
┌──────────────────────────────────────────────┐
│  1. PRNG (deterministic, reproducible)       │
│     Seed → same sequence every time          │
├──────────────────────────────────────────────┤
│  2. Action Enum (all state-changing ops)     │
│     Deposit | Withdraw | Trade | Crank | ... │
├──────────────────────────────────────────────┤
│  3. Action Generator (weighted random)       │
│     20% deposits, 15% withdrawals, 20% trades│
├──────────────────────────────────────────────┤
│  4. Executor (applies action, catches errors)│
│     Failed ops are OK — just continue        │
├──────────────────────────────────────────────┤
│  5. Invariant Checker (runs after EVERY step)│
│     Conservation, sync, aggregate, bounds    │
└──────────────────────────────────────────────┘
```

---

## 3. Component 1: Deterministic PRNG

**Critical requirement:** The fuzzer must be 100% reproducible. Given the
same seed, it must produce the exact same operation sequence. This means:

- No `rand` crate (non-deterministic by default)
- No system clock as seed source
- No dependency on external state

### Recommended: xorshift64

A minimal PRNG that's fast, deterministic, and has good distribution:

```
function xorshift64(state):
    state ^= state << 13
    state ^= state >> 7
    state ^= state << 17
    return state

function range(state, lo, hi):
    return lo + (xorshift64(state) % (hi - lo))
```

**Why not use a standard random library?** Standard random libraries may
change their algorithm between versions, breaking reproducibility. A
hard-coded xorshift guarantees the same sequence across all environments.

---

## 4. Component 2: Action Enum

List EVERY state-changing operation the protocol supports:

```
// Fill in for your protocol:
enum FuzzAction {
    // User operations
    Deposit { user_idx, amount }
    Withdraw { user_idx, amount }
    Trade { user_idx, counterparty_idx, size }
    CloseAccount { user_idx }

    // Protocol maintenance
    Crank
    AdvanceTimeAndPrice { dt, new_price }

    // Admin operations
    TopUpInsurance { amount }
    SetFee { value }
    UpdateConfig { params }

    // User lifecycle
    InitUser
}
```

### What to Include (and Not Include)

| Include | Don't Include |
|---------|---------------|
| All user-callable instructions | Read-only queries |
| All admin-callable instructions | View functions |
| Time advancement (slot/block) | External oracle updates (model as price change) |
| Price changes (oracle simulation) | Off-chain indexer operations |
| Account creation/destruction | — |

---

## 5. Component 3: Weighted Action Generator

Not all operations are equally likely. Weight them to model realistic usage:

```
function random_action(rng, state):
    roll = rng.range(0, 100)
    switch roll:
        0..19:   Deposit (random user, random amount)       // 20%
        20..34:  Withdraw (random user, random amount)      // 15%
        35..54:  Trade (random user, random LP, random size) // 20%
        55..64:  Crank                                       // 10%
        65..79:  AdvanceTimeAndPrice (random dt, random Δ)   // 15%
        80..84:  TopUpInsurance (random amount)               //  5%
        85..89:  SetFee (random value)                        //  5%
        90..94:  InitUser                                     //  5%
        95..99:  CloseAccount (random user)                   //  5%
```

### Weight Design Principles

| Principle | Rationale |
|-----------|-----------|
| Deposits > Withdrawals | Builds state that other operations can act on |
| Trades are frequent | Most state transitions involve trades |
| Crank must run regularly | Settlement/liquidation logic needs triggering |
| Time advances are common | Funding, fees, warmup periods are time-dependent |
| Admin ops are rare | Realistic: admins don't change config every block |
| Account close is rare | Most users don't close accounts frequently |

---

## 6. Component 4: Executor

The executor applies each action and **never fails on expected errors**.
A withdrawal that fails because the user has insufficient balance is normal —
the fuzzer should continue.

```
function execute(action, env):
    switch action:
        Deposit { user_idx, amount }:
            result = env.try_deposit(users[user_idx], amount)
            // result.is_err() is fine — user might not have funds

        Withdraw { user_idx, amount }:
            result = env.try_withdraw(users[user_idx], amount)
            // result.is_err() is fine — might exceed balance

        Trade { user_idx, lp_idx, size }:
            result = env.try_trade(users[user_idx], lps[lp_idx], size)
            // result.is_err() is fine — might fail margin check

        CloseAccount { user_idx }:
            result = env.try_close(users[user_idx])
            // result.is_err() is fine — might have open position

        Crank:
            env.crank()  // should always succeed

    // AFTER EVERY ACTION: check invariants
    check_invariants(env, action)
```

**Key insight:** The fuzzer doesn't need to generate only valid operations.
Invalid operations that are correctly rejected are ALSO testing the protocol.
The invariant check after the failed operation verifies that no state was
corrupted by the rejection.

---

## 7. Component 5: Invariant Checker

The invariant checker runs after EVERY operation (including failed ones).
It should check all global properties:

### Invariant Catalog

| ID | Invariant | Formula | What Violation Means |
|----|-----------|---------|---------------------|
| P1 | Conservation | `vault >= capital_total + insurance` | Funds created from nothing |
| P2 | Engine/token sync | `internal_vault == on_chain_balance` | Accounting desync |
| P3 | Aggregate consistency | `sum(individual_capitals) == capital_total` | Lost or double-counted capital |
| P4 | PnL non-negative | `pnl_positive_total >= 0` | Invalid PnL accounting |
| P5 | Position balance | `sum(long_positions) + sum(short_positions) == 0` | Net position imbalance |
| P6 | Account count | `count(active_accounts) == used_counter` | Account tracking drift |

### Invariant Check Template

```
function check_invariants(env, context):
    vault = env.get_vault_balance()
    c_tot = env.get_total_capital()
    insurance = env.get_insurance_balance()
    engine_vault = env.get_internal_vault_tracking()

    // P1: Conservation (most critical)
    assert vault >= c_tot + insurance,
        "[seed={} step={} {}] P1 CONSERVATION: vault={} c_tot={} ins={}"

    // P2: Engine/token sync
    assert engine_vault == vault,
        "[seed={} step={} {}] P2 DESYNC: engine={} spl={}"

    // P3: Aggregate consistency
    sum_cap = 0
    for each account in env.all_accounts():
        sum_cap += account.capital
    assert sum_cap == c_tot,
        "[seed={} step={} {}] P3 AGGREGATE: sum={} c_tot={}"
```

**Include seed and step in every assertion message.** When a fuzzer fails,
you need to know exactly which seed and which step triggered the failure
to reproduce it.

---

## 8. Putting It Together: The Run Loop

```
for seed in 1..50:            // 50 different random sequences
    fuzzer = new Fuzzer(seed)
    fuzzer.setup()            // init market, create LP + 3 users
    rng = new PRNG(seed)

    for step in 0..100:       // 100 random operations per seed
        action = fuzzer.random_action(rng)
        fuzzer.execute(action)
        // invariants checked inside execute()

// Total: 50 × 100 = 5,000 random operations with invariant checks
```

### Scaling Guidelines

| Configuration | Operations | Runtime | Use Case |
|--------------|-----------|---------|----------|
| 50 seeds × 100 steps | 5,000 | ~30s | CI pipeline, every commit |
| 200 seeds × 200 steps | 40,000 | ~5min | Nightly / pre-release |
| 1000 seeds × 500 steps | 500,000 | ~1hr | Pre-audit deep fuzz |

### Extended Run (Mark as `#[ignore]` for CI)

```
// Run with: cargo test test_property_extended -- --ignored
#[ignore = "long-running exhaustive state machine (40k ops)"]
fn test_property_state_machine_extended():
    for seed in 1..200:
        fuzzer = new Fuzzer(seed)
        fuzzer.setup()
        rng = new PRNG(seed)
        for step in 0..200:
            action = fuzzer.random_action(rng)
            fuzzer.execute(action)
```

---

## 9. Companion Property Tests

Beyond the random fuzzer, write targeted property tests that subsume
large categories of individual tests:

### Authorization Exhaustive

One test that covers ALL authorization checks:

```
fn test_property_authorization_exhaustive():
    // Setup: create market, admin, attacker, LP, user
    vault_before = env.vault_balance()

    // Test EVERY owner-protected operation with wrong signer
    assert env.try_deposit(attacker, user_idx).is_err()      // A1
    assert env.try_withdraw(attacker, user_idx).is_err()     // A2
    assert env.try_close(attacker, user_idx).is_err()        // A3

    // Test EVERY admin-protected operation with non-admin
    assert env.try_set_fee(attacker, 100).is_err()           // A4
    assert env.try_set_threshold(attacker, 999).is_err()     // A5
    assert env.try_update_admin(attacker, attacker).is_err() // A6

    // Vault unchanged after all rejections
    assert vault_before == env.vault_balance()

    // Admin transfer chain: old admin locked out
    env.update_admin(admin, new_admin)
    assert env.try_set_fee(admin, 200).is_err()              // A7: old admin rejected
    assert env.try_set_fee(new_admin, 200).is_ok()           // A8: new admin works
```

This single test subsumes ~50 individual authorization tests.

### Account Lifecycle Exhaustive

One test that covers create → use → close → GC → reuse:

```
fn test_property_account_lifecycle():
    // L1: Closed accounts reject all operations
    // L2: GC'd accounts have zero state
    // L3: Account reuse after GC works correctly
    // L4: Close requires zero position and zero PnL
```

---

## 10. For Auditors: Evaluating an Existing Fuzzer

When a protocol already has a state machine fuzzer, assess it:

| Question | Good Answer | Red Flag |
|----------|-------------|----------|
| Is the PRNG deterministic? | xorshift, fixed seed | `rand::thread_rng()` |
| Are ALL instructions covered? | Every state-changing op in the enum | Missing admin ops, CPI calls |
| Are invariants checked after EVERY step? | `check_invariants()` in the execute loop | Only checked at end of sequence |
| Does it include failed operations? | `try_*` calls that may return Err | Only generates valid inputs |
| Is the seed/step in assertion messages? | `"[seed=X step=Y]"` | Generic `"invariant failed"` |
| Is the action space weighted? | Different weights per action | Uniform random (unrealistic) |
| How many operations per CI run? | 5,000+ | < 100 |
| Are admin mutations included? | Config changes mid-lifecycle | Only user operations |

### Missing Fuzzer = Finding

If the protocol has complex state but no state machine fuzzer:

> **Finding: No integration-level fuzz testing**
>
> Severity: Informational
>
> The protocol has [N] state-changing instructions interacting with shared
> state but no deterministic state machine fuzzer. Individual test cases
> cannot cover the combinatorial space of operation sequences. Recommend
> implementing a seeded integration fuzzer that generates random operation
> sequences and checks conservation and accounting invariants after each step.
> A baseline of 50 seeds × 100 steps (5,000 operations) in CI, with an
> extended 40,000-operation run pre-release, would significantly improve
> confidence in state consistency.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-02-25 | Initial creation — methodology extracted from percolator-prog integration fuzzer patterns |
