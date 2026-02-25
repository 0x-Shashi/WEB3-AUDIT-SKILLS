---
id: RES-SOLANA-FORMAL-VERIFICATION
title: Formal Verification for Solana Auditors
category: resource
parent: SCANNER-SOLANA
chains: [solana]
languages: [rust]
frameworks: [kani, cbmc]
last_updated: 2026-02-25
description: >-
  Use when auditing Solana programs that claim formal verification — covers
  Kani proof anatomy, property categories, proof classification (STRONG/WEAK/
  VACUOUS), what to look for, what to flag, and how to evaluate proof suites.
  Companion to the generic templates in skills/templates/.
---

# Formal Verification for Solana Auditors

Testing shows bugs exist. Formal verification proves they don't — within the
verified scope. This resource explains what formal verification looks like for
Solana programs, how to evaluate it, and what gaps to flag.

> **Key insight:** A protocol with 100 Kani proofs may still have critical
> unverified areas. Your job is to determine what is *actually* proven vs.
> what is *claimed* to be proven.

## When You'll Encounter This

- Protocol README says "formally verified" or "Kani-proven"
- Audit scope includes a `tests/kani.rs` file or `#[kani::proof]` attributes
- Protocol claims mathematically proven security properties
- You're reviewing a Solana program with an accompanying `audit.md`

## 1. What Kani Is

Kani is a model checker for Rust that uses CBMC (C Bounded Model Checker) as
its backend. It exhaustively explores all possible inputs to a function within
bounded domains.

| Aspect | Kani | Unit Tests | Fuzz Tests |
|--------|------|-----------|------------|
| Input space | All values (bounded) | Single concrete values | Random sample |
| Guarantee | Mathematical proof (within bounds) | One path works | No crash found yet |
| Speed | Slow (SAT solver) | Fast | Medium |
| Solana runtime | **Not modeled** | Full (via LiteSVM) | Full (via trdelnik) |
| CPI execution | **Not modeled** | Full | Full |
| Best for | Pure logic, auth checks, math | Integration, exploits | Edge cases, panics |

### What Kani CAN verify for Solana

- Pure decision functions (extracted from handlers)
- Authorization logic (owner checks, admin checks, signer validation)
- Math invariants (conservation, monotonicity, overflow safety)
- ABI/data validation (malformed return data rejected)
- State transitions (nonce advances, flag changes)
- CPI binding logic (identity matching, shape validation)

### What Kani CANNOT verify for Solana

- CPI execution (Solana's `invoke` / `invoke_signed`)
- Account deserialization (runtime handles this)
- PDA derivation (Solana's `find_program_address`)
- Token transfers (SPL Token program execution)
- Cross-program interaction effects
- Account rent and lamport accounting
- Compute unit consumption

## 2. Anatomy of a Kani Proof

### The Extract-and-Verify Pattern

Well-engineered Solana programs extract pure decision logic from instruction
handlers into a separate `verify` module, then prove properties on those
pure functions:

```
┌────────────────────────────────┐
│  processor::process_trade()    │  ← Production handler (touches accounts)
│                                │
│  1. Deserialize accounts       │  ← Runtime — NOT verified by Kani
│  2. Check signer               │
│  3. Check owner                │
│  4. Validate shape             │
│  5. Call engine                 │
│  6. CPI to matcher             │  ← Runtime — NOT verified by Kani
│  7. Validate return data       │
│  8. Update state               │
└────────────────────────────────┘
          │
          │ Extract pure logic
          ▼
┌────────────────────────────────┐
│  verify::decide_trade()        │  ← Pure function (no accounts, no I/O)
│                                │
│  Inputs: booleans/integers     │
│  Output: Accept(size,nonce)    │
│          or Reject             │
│                                │
│  Encodes steps 2-5, 7 as      │
│  pure boolean/integer logic    │
└────────────────────────────────┘
          │
          │ Kani proves properties
          ▼
┌────────────────────────────────┐
│  #[kani::proof]                │
│  fn kani_decide_trade_cpi() {  │
│    let inputs = kani::any();   │  ← Symbolic: ALL possible values
│    let result = decide_trade(  │
│      inputs                    │
│    );                          │
│    assert!(property(result));  │  ← Must hold for ALL inputs
│  }                             │
└────────────────────────────────┘
```

### The Critical Gap: Coupling

The extract-and-verify pattern has an inherent gap: the proof verifies
`verify::decide_trade()`, but production runs `processor::process_trade()`.
If these diverge, proofs verify the wrong function.

**What to look for:**
- A coupling proof showing `verify::decide == processor logic`
- Code review confirming the verify function matches the handler
- Comments documenting the check ordering

**If coupling is missing** → flag as informational: "Formal proofs verify
extracted decide function but no coupling proof binds it to the production
handler."

## 3. Proof Classification System

Not all proofs are equal. Classify each one:

### STRONG — Genuine formal guarantee

```rust
#[kani::proof]
fn kani_admin_burned_disables_ops() {
    let admin: [u8; 32] = [0; 32];          // burned
    let signer: [u8; 32] = kani::any();     // ANY signer
    assert!(!admin_ok(admin, signer));       // always rejected
}
```

Symbolic inputs, exercises key branches, non-vacuous. This actually proves
that a burned admin can never authorize operations, for ALL possible signers.

### WEAK — Bounded guarantee

```rust
#[kani::proof]
fn kani_invert_nonzero_computes_correctly() {
    let raw: u64 = kani::any();
    kani::assume(raw > 0 && raw <= 8192);   // ← SAT bound
    let result = invert(raw);
    assert_eq!(result, Some(1_000_000_000_000 / raw));
}
```

Symbolic but bounded to `[1, 8192]` for SAT tractability. The property holds
within bounds but is unverified for `raw > 8192`. The weakness is range, not
logic — important distinction.

### UNIT TEST — Concrete regression guard

```rust
#[kani::proof]
fn kani_min_abs_boundary_rejected() {
    let val = i128::MIN;                    // ← concrete, not symbolic
    assert_eq!(val.unsigned_abs(), 170141183460469231731687303715884105728);
}
```

Single concrete input. Proves exactly one case, not a general property.
Useful as regression guard for historical bugs, but not formal verification.

### CODE-EQUALS-SPEC — Tautological guard

```rust
#[kani::proof]
fn kani_accumulate_dust_saturates() {
    let a: u64 = kani::any();
    let b: u64 = kani::any();
    assert_eq!(accumulate_dust(a, b), a.saturating_add(b));
}
// But accumulate_dust IS just saturating_add!
```

The assertion restates the function body. Guards against refactoring changes
but proves no external property.

### VACUOUS — Proves nothing (red flag)

```rust
#[kani::proof]
fn kani_something() {
    let x: u64 = kani::any();
    kani::assume(x > 5);
    kani::assume(x < 3);     // ← contradicts previous assume!
    assert!(false);           // "passes" because assertion is unreachable
}
```

Contradictory assumptions make the assertion unreachable. The proof passes
vacuously. **Any vacuous proof in a suite is a finding.**

## 4. Property Categories for Solana Programs

When evaluating a proof suite, check coverage across these categories.
A mature suite should have STRONG proofs in all critical categories:

### Critical Categories (must have STRONG proofs)

| Category | What's Proven | Example Proofs |
|----------|--------------|----------------|
| **Authorization** | Owner/signer checks cannot be bypassed | `kani_owner_mismatch_rejected`, `kani_admin_burned_disables_ops` |
| **CPI Identity Binding** | CPI target must match registered program + context | `kani_matcher_identity_mismatch_rejected` |
| **Return Data Validation** | All ABI fields validated before use | `kani_matcher_rejects_wrong_*` (per-field) |
| **Nonce/Replay** | Nonce unchanged on failure, +1 on success | `kani_nonce_unchanged_on_failure`, `kani_nonce_advances_on_success` |
| **Size Constraints** | Executed size never exceeds requested size | `kani_cpi_uses_exec_size` |

### High Categories (should have proofs)

| Category | What's Proven | Example Proofs |
|----------|--------------|----------------|
| **State Transitions** | State machine follows defined lifecycle | `kani_tradenocpi_universal_characterization` |
| **Risk Gating** | Gate active iff conditions met, risk-reducing always allowed | `kani_gate_inactive_when_*`, `kani_universal_gate_risk_increase_rejects` |
| **Math Conservation** | No value loss in conversions (`units + dust == base`) | `kani_base_to_units_conservation` |
| **Vault Accounting** | `vault_after == vault_before - amount`, overflow checked | `kani_withdraw_insurance_vault_correct` |

### Medium Categories (nice to have)

| Category | What's Proven |
|----------|--------------|
| **Monotonicity** | Larger inputs → larger outputs |
| **Dust Bounds** | Remainder always < unit scale |
| **Rate Limiting** | Index movement bounded per time slot |
| **Determinism** | Same inputs → same outputs |
| **Alignment** | Misaligned amounts rejected |

## 5. How to Evaluate a Proof Suite

### Step 1: Inventory (30 min)

```
□ How many total proofs?
□ What tool? (Kani, Certora, Halmos)
□ Do all proofs pass? (if not → stop, investigate)
□ Are proofs categorized by domain?
□ Is there a verify/spec module separate from processor?
```

### Step 2: Classify (1-2 hours)

For each proof, apply the 6-point analysis:

| Point | Question |
|-------|----------|
| **1. Inputs** | Fully symbolic, bounded, or concrete? |
| **2. Branches** | Does it exercise all code paths? |
| **3. Assertion** | Strong (exact equivalence) or weak (just `is_ok()`)? |
| **4. Vacuity** | Can the assertion actually be reached? |
| **5. Collapse** | After all `assume()`, how many values remain? |
| **6. Coupling** | Does it call the real production function? |

### Step 3: Map to Claims (1 hour)

| Security Claim | Backed by STRONG Proof? | Backed by Tests? | Gap? |
|---------------|------------------------|-------------------|------|
| "Admin cannot steal funds" | | | |
| "All trades are authorized" | | | |
| "Nonces prevent replay" | | | |

### Step 4: Identify What's NOT Proven (critical)

This is often more important than what IS proven:

| Commonly Unverified | Why | Alternative Coverage |
|--------------------|-----|---------------------|
| CPI execution | Kani can't model Solana runtime | Integration tests (LiteSVM) |
| Account deserialization | Runtime handles | Framework (Anchor) |
| PDA derivation | `find_program_address` is native | Integration tests |
| Token transfers | SPL Token program | Integration tests |
| Risk engine internals | Separate crate | Unit tests + fuzzing |
| Oracle reading | Requires `AccountInfo` | Mocked integration tests |

### Step 5: Report

**Positive:**

> The proof suite contains N proofs (X% STRONG) covering authorization,
> CPI binding, nonce transitions, and math invariants. Non-vacuity
> discipline is strong with concrete witnesses for conditional proofs.

**Gaps:**

> The following security properties lack formal verification:
> - [PROPERTY]: covered only by integration tests
> - [PROPERTY]: no verification evidence found

**Findings:**

> [SEVERITY]: Security claim "[CLAIM]" in documentation is not backed by
> any formal proof. Recommend adding Kani harness or downgrading claim.

## 6. Proof Strength Tiers (Highest → Lowest)

### Tier 1: Universal Characterization

Proves `f(inputs) == expected_formula` for **ALL** input combinations.
Fully characterizes the function. Zero behavioral ambiguity.

```rust
// "decide_trade_cpi accepts iff ALL seven gates pass"
#[kani::proof]
fn kani_decide_trade_cpi_universal() {
    // 10+ symbolic inputs
    let result = decide_trade_cpi(shape, identity, pda, abi, user, lp, gate, risk, ...);
    match result {
        Accept { nonce, size } => {
            assert!(shape && identity && pda && abi && user && lp && !(gate && risk));
            assert_eq!(nonce, old_nonce.wrapping_add(1));
            assert_eq!(size, exec_size);
        }
        Reject => {
            assert!(!(shape && identity && pda && abi && user && lp && !(gate && risk)));
        }
    }
}
```

**Significance**: If a suite has Tier 1 proofs for its critical decision
functions, the authorization and state-transition logic is mathematically
characterized. This is the gold standard.

### Tier 2: Universal Gate Rejection

Proves that a single failure causes rejection regardless of ALL other inputs:

```rust
// "If shape validation fails, trade is ALWAYS rejected"
#[kani::proof]
fn kani_universal_shape_fail_rejects() {
    kani::assume(!matcher_shape_ok);     // force ONE gate open
    // all other inputs fully symbolic
    let result = decide_trade_cpi(...);
    assert!(matches!(result, Reject));    // always rejects
}
```

**Significance**: These are "kill switch" proofs — each gate independently
stops an attack. A mature suite has one per auth gate.

### Tier 3: State Transition Relations

Nonce advances by exactly 1 on success, unchanged on failure. Balance
changes by exactly the specified amount.

### Tier 4+: Input Validation, Authorization, Math

Progressively less critical but still valuable.

## 7. Red Flags in Proof Suites

| Red Flag | What It Means | Severity |
|----------|--------------|----------|
| **Any VACUOUS proof** | Dead assertion — proves nothing | High |
| **> 50% UNIT TEST** | Suite looks like tests dressed as proofs | Medium |
| **No coupling proof** | Verify module may diverge from production | Medium |
| **"Formally verified" with < 20 proofs** | Likely covers narrow slice | Medium |
| **No non-vacuity witnesses** | Conditional proofs may be vacuously true | Medium |
| **Claims exceed proof scope** | "All funds are safe" but proofs only cover auth | High |
| **Missing critical category** | No auth proofs, or no CPI proofs | High |
| **Undocumented SAT bounds** | Unclear if bounded range is sufficient | Low-Medium |

## 8. Kani-Specific Patterns for Solana

### Symbolic Account Keys

```rust
let owner: [u8; 32] = kani::any();
let signer: [u8; 32] = kani::any();
assert_eq!(owner_ok(owner, signer), owner == signer);
```

Kani explores all `2^256 × 2^256` key combinations symbolically (via SAT
encoding, not enumeration).

### Symbolic Return Data

```rust
let ret = MatcherReturn {
    abi_version: kani::any(),
    flags: kani::any(),
    exec_size: kani::any(),
    exec_price: kani::any(),
    // ... all fields symbolic
};
let valid = validate_matcher_return(ret, request);
// Assert per-field rejection causes
```

### SAT Bounds for Heavy Math

When proofs involve division chains (128-bit division, price scaling),
Kani's CBMC backend hits exponential SAT blowup. Bounded domains are normal:

```rust
let raw: u64 = kani::any();
kani::assume(raw > 0 && raw <= KANI_MAX_QUOTIENT);  // e.g., 8192
```

**This is expected**, not a weakness — if the bounded domain exercises all
code branches. Check that:
- The bound is documented in source comments
- All branches are reachable within the bound
- Production-range values are covered by integration/fuzz tests

## 9. Connecting FV to Your Audit

Formal verification complements, not replaces, the rest of the audit:

| Audit Phase | How FV Helps |
|------------|-------------|
| **Initial review** | Proof categories show what the team considers critical |
| **Attack surface mapping** | "What is NOT proven" list reveals unverified areas |
| **Finding validation** | If a property is STRONG-proven, a finding claiming violation needs extraordinary evidence |
| **Severity assessment** | Unverified properties get higher severity than verified ones |
| **Report writing** | Cite proof names when acknowledging security properties |
| **Recommendations** | "Add Kani harness for [property]" is a concrete recommendation |

### Cross-Reference with Testing Resource

| Verification Need | Tool | Resource |
|-------------------|------|----------|
| Exploit PoC for a finding | LiteSVM | [solana-testing-for-auditors.md](solana-testing-for-auditors.md) |
| CU impact analysis | Mollusk | [solana-testing-for-auditors.md](solana-testing-for-auditors.md) |
| Mainnet state replay | Surfpool | [solana-testing-for-auditors.md](solana-testing-for-auditors.md) |
| Authorization/math proof review | Kani | This document |
| Generic FV audit template | Any tool | [templates/formal-verification-audit.md](../../templates/formal-verification-audit.md) |
| Proof grading methodology | Any tool | [templates/proof-strength-assessment.md](../../templates/proof-strength-assessment.md) |

## 10. Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│  FORMAL VERIFICATION QUICK EVALUATION               │
│                                                     │
│  1. All proofs pass?          □ Yes  □ No (STOP)    │
│  2. STRONG percentage?        ___%  (target: >70%)  │
│  3. VACUOUS count?            ___   (target: 0)     │
│  4. Critical categories?                            │
│     □ Authorization                                 │
│     □ CPI binding                                   │
│     □ Return data validation                        │
│     □ Nonce/replay                                  │
│     □ Size constraints                              │
│  5. Coupling proof exists?    □ Yes  □ No           │
│  6. What is NOT proven?       ___________________   │
│  7. Claims match proofs?      □ Yes  □ Overstated   │
│                                                     │
│  CLASSIFICATION KEY:                                │
│  STRONG = symbolic + key branches + non-vacuous     │
│  WEAK   = symbolic but bounded domain               │
│  UNIT   = concrete inputs only                      │
│  SPEC   = assertion restates function body          │
│  VACUOUS = assertion unreachable (⚠️ finding)       │
└─────────────────────────────────────────────────────┘
```

## 11. The Verify Module Extract-and-Prove Pattern

The most effective pattern for making Solana programs provable is to
**extract all authorization and decision logic** into a pure `verify` module.
This technique separates WHAT the program decides from HOW it interacts with
the Solana runtime, making the decision logic independently testable and
formally provable.

### Why This Pattern Exists

Solana instruction handlers are tangled with runtime concerns:
- Deserializing account data from raw bytes
- CPI calls and return data parsing
- SPL token transfers
- Clock/rent sysvar reads

Kani cannot model the Solana runtime. But it CAN prove properties about
pure functions that take simple inputs and return decisions. The verify
module is the adapter that bridges this gap.

### The Extract-and-Prove Workflow

```
Step 1:  Identify all decision points in each instruction handler
Step 2:  Extract each decision as a pure function in `pub mod verify`
Step 3:  Define Decision enums (Accept/Reject with result data)
Step 4:  Wire instruction handlers to call verify functions
Step 5:  Write Kani proofs that exercise verify functions directly
```

### Step 1: Identify Decision Points

For each instruction, list every check that gates behavior:

```
Instruction: WithdrawCollateral
  Check 1: Account owner matches signer     → MUST match
  Check 2: Account has sufficient balance    → engine handles
  Check 3: Withdrawal aligned to unit_scale  → MUST be aligned
  Check 4: Risk gate not active (or reducing) → MUST pass

Instruction: TradeCpi
  Check 1: Matcher program is executable     → shape check
  Check 2: Matcher context owned by program  → shape check
  Check 3: LP PDA matches derivation         → PDA check
  Check 4: User owner matches signer         → auth check
  Check 5: LP owner matches signer           → auth check
  Check 6: Matcher identity matches LP reg   → identity check
  Check 7: ABI version correct               → ABI check
  Check 8: Exec size within bounds           → ABI check
  Check 9: Risk gate permits trade           → gate check
```

### Step 2: Extract as Pure Functions

Each check becomes a pure function with simple inputs:

```rust
pub mod verify {
    /// Owner authorization: stored owner must match signer.
    #[inline]
    pub fn owner_ok(stored: [u8; 32], signer: [u8; 32]) -> bool {
        stored == signer
    }

    /// Admin authorization: admin must be non-zero AND match signer.
    #[inline]
    pub fn admin_ok(admin: [u8; 32], signer: [u8; 32]) -> bool {
        admin != [0u8; 32] && admin == signer
    }

    /// Risk gate: active when threshold > 0 AND balance <= threshold.
    #[inline]
    pub fn gate_active(threshold: u128, balance: u128) -> bool {
        threshold > 0 && balance <= threshold
    }

    /// Withdrawal alignment: amount must be divisible by unit_scale.
    #[inline]
    pub fn withdraw_amount_aligned(amount: u64, scale: u32) -> bool {
        if scale == 0 { return true; }
        amount % (scale as u64) == 0
    }
}
```

**Key properties of verify functions:**
- Take primitive inputs (bool, u64, [u8; 32]) — no AccountInfo, no CPI
- Return primitive outputs (bool, enum) — no side effects
- Marked `#[inline]` — zero runtime overhead when called from handlers
- Documented with "Used by:" comments linking to instructions

### Step 3: Define Decision Enums

For complex instructions, define a decision type:

```rust
pub mod verify {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TradeCpiDecision {
        Reject,
        Accept { new_nonce: u64, chosen_size: i128 },
    }

    /// Pure decision function for TradeCpi instruction.
    pub fn decide_trade_cpi(
        old_nonce: u64,
        shape: MatcherAccountsShape,    // struct of booleans
        identity_ok: bool,
        pda_ok: bool,
        abi_ok: bool,
        user_auth_ok: bool,
        lp_auth_ok: bool,
        gate_active: bool,
        risk_increase: bool,
        exec_size: i128,
    ) -> TradeCpiDecision {
        // Check in order of actual program execution:
        if !matcher_shape_ok(shape) { return TradeCpiDecision::Reject; }
        if !pda_ok { return TradeCpiDecision::Reject; }
        if !user_auth_ok || !lp_auth_ok { return TradeCpiDecision::Reject; }
        if !identity_ok { return TradeCpiDecision::Reject; }
        if !abi_ok { return TradeCpiDecision::Reject; }
        if gate_active && risk_increase { return TradeCpiDecision::Reject; }

        TradeCpiDecision::Accept {
            new_nonce: nonce_on_success(old_nonce),
            chosen_size: cpi_trade_size(exec_size, 0),
        }
    }
}
```

**Design principle:** The decision function takes ALL pre-computed booleans
as parameters. The instruction handler computes each boolean from runtime
data, then calls the decision function. This means the decision function
contains ZERO Solana runtime dependencies.

### Step 4: Wire Into Instruction Handlers

The handler computes boolean inputs from runtime data:

```rust
// In the instruction handler (simplified):
fn process_trade_cpi(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let slab = deserialize_slab(accounts[2]);
    let user = &slab.accounts[user_idx];
    let lp = &slab.accounts[lp_idx];

    // Compute boolean inputs from runtime state
    let shape = MatcherAccountsShape {
        prog_executable: accounts[5].executable,
        ctx_executable: accounts[6].executable,
        ctx_owner_is_prog: accounts[6].owner == accounts[5].key,
        ctx_len_ok: accounts[6].data_len() >= MATCHER_CONTEXT_LEN,
    };
    let identity_ok = verify::matcher_identity_ok(
        lp.matcher_program, lp.matcher_context,
        *accounts[5].key, *accounts[6].key
    );
    let pda_ok = verify::pda_key_matches(expected_pda, *accounts[7].key);
    let user_auth_ok = verify::owner_ok(user.owner, *accounts[0].key);
    let lp_auth_ok = verify::owner_ok(lp.owner, *accounts[1].key);

    // ... CPI call, ABI validation ...
    let abi_ok = verify::abi_ok(ret, lp_account_id, oracle_price, req_size, req_id);

    // Single decision call
    match verify::decide_trade_cpi(nonce, shape, identity_ok, pda_ok,
                                    abi_ok, user_auth_ok, lp_auth_ok,
                                    gate_active, risk_increase, exec_size) {
        TradeCpiDecision::Reject => { /* error path */ }
        TradeCpiDecision::Accept { new_nonce, chosen_size } => {
            // execute trade with chosen_size, update nonce
        }
    }
}
```

### Step 5: Prove With Kani

Now Kani can prove properties about the decision function directly:

```rust
#[kani::proof]
fn kani_tradecpi_reject_nonce_unchanged() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    // ... all other params as kani::any() ...

    let decision = decide_trade_cpi(old_nonce, shape, /* ... */);

    if let TradeCpiDecision::Reject = decision {
        // Property: rejected trades NEVER change the nonce
        assert_eq!(decision_nonce(old_nonce, decision), old_nonce);
    }
}

#[kani::proof]
fn kani_tradecpi_accept_increments_nonce() {
    // ... setup with all symbolic inputs ...
    let decision = decide_trade_cpi(old_nonce, shape, /* ... */);

    if let TradeCpiDecision::Accept { new_nonce, .. } = decision {
        // Property: accepted trades increment nonce by exactly 1
        assert_eq!(new_nonce, old_nonce.wrapping_add(1));
    }
}
```

### What This Proves (and Doesn't)

| Proven by verify module | NOT proven (still needs testing) |
|------------------------|--------------------------------|
| Authorization logic is correct | Account deserialization is correct |
| Decision ordering is consistent | SPL token transfer amounts |
| Nonce updates are deterministic | CPI call is made to correct program |
| Risk gating rejects correctly | Oracle data parsing |
| ABI validation rejects malformed returns | Slab serialization/deserialization |
| Math functions don't overflow | Compute unit consumption |

**Key audit insight:** The verify module proves the POLICY is correct.
Integration tests (LiteSVM + BPF binary) prove the IMPLEMENTATION
correctly calls the policy.

### Evaluating a Verify Module During Audit

| Question | Good Answer | Red Flag |
|----------|-------------|----------|
| Does every instruction have a `decide_*` function? | Yes, complete coverage | Some instructions bypass verify |
| Do verify functions match handler check order? | Comments document order | Order differs (check may be skippable) |
| Does the handler ONLY use verify return values? | Yes, no duplicate checks | Handler has inline checks that bypass verify |
| Are all 34 proof categories in kani.rs? | Categorized A through AH | Proofs exist but don't map to verify functions |
| Does `decide_*` take computed booleans? | All runtime deps pre-computed | Verify function takes AccountInfo (not pure) |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-02-25 | Initial creation |
| 1.1 | 2025-02-25 | Added Section 11: Verify Module Extract-and-Prove Pattern |
