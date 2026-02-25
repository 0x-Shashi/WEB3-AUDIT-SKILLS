---
id: proof-strength-assessment
title: "Proof Strength Assessment Methodology"
category: templates
tier: methodology
audience: [auditors, formal-verification-engineers]
origin: methodology-extraction
version: 1.0.0
---

# Proof Strength Assessment Methodology

## Purpose

Not all formal proofs are equal. A proof suite with 100 harnesses that are
all vacuous or trivially true provides zero security guarantees. This template
gives auditors a systematic methodology for grading individual proofs and
identifying vacuity, weakness, or misclassification.

Use this when reviewing a protocol that claims formal verification, especially
when the proof suite contains many harnesses and you need a triage strategy.

---

## Step 1: Run the Suite First

Before analyzing individual proofs:

```
1. Run all proofs              → Do they pass?
2. Count total proofs          → [N]
3. Note verification tool      → [Kani / Certora / Halmos / KEVM]
4. Note any bounded parameters → [loop unwind, domain limits, etc.]
5. Note runtime per proof      → [seconds — SAT-heavy proofs take longer]
```

If any proof **fails**, stop. A failing proof is either a real bug or
a broken harness — both need investigation before proceeding.

---

## Step 2: 6-Point Analysis Per Proof

For each proof harness, evaluate these six dimensions:

### 2.1 Input Classification

| Input Type | Symbol | Verification Strength |
|-----------|--------|----------------------|
| Fully symbolic | `kani::any()` / `symbolic!()` | Full — exercises all values |
| Bounded symbolic | `assume(x < N)` | Partial — only within bounds |
| Concrete | `let x = 42;` | None — single execution path |

**Questions:**
- What symbolic inputs does this harness create?
- What `assume()` constraints narrow them?
- Are the constraints realistic (match production usage) or artificial?
- After all assumes, how large is the remaining input space?

### 2.2 Branch Coverage

**Questions:**
- Does the harness exercise all branches of the function under test?
- Are there early-return paths that bypass the core logic?
- For `if-then` proofs: is the condition satisfiable (non-vacuity)?
- Does the proof test both success and failure paths?

**Red flags:**
- `assume(condition)` followed by `assert(condition)` → tautology
- Only testing the "happy path" without forcing error cases
- Complex function with single concrete input → most branches untouched

### 2.3 Invariant Strength

The assertion should be as strong as the actual security property.

| Pattern | Strength |
|---------|----------|
| `assert!(result == expected_formula)` | Strong — exact equivalence |
| `assert!(result.is_ok())` | Weak — only checks success, not value |
| `assert!(result != 0)` | Weak — doesn't check correctness |
| `match result { A => check_a, B => check_b }` | Strong — both outcomes verified |
| `if let Ok(v) = result { assert!(v == ...) }` | Moderate — doesn't check Err case |

### 2.4 Vacuity Risk

A proof is **vacuous** if the assertion is never reached because the
assumptions are contradictory or the code path is dead.

**Detection patterns:**
- `assume(x > 5); assume(x < 3);` → contradictory → vacuous
- `assume(flag); if !flag { assert!(...) }` → dead path → vacuous
- No concrete witness proving the assertion is reachable

**Mitigation patterns (good practices):**
- Concrete witness before universal quantification
- `panic!("unexpected path")` on dead branches
- Both-outcome matching: `match result { A => ..., B => ... }`

### 2.5 Symbolic Collapse

Even with symbolic inputs, the effective domain can collapse if assumptions
restrict too aggressively.

**Formula:** Effective domain = Total symbolic range - Assumed constraints

**Example:**
```
let x: u64 = kani::any();  // 2^64 values
assume(x > 0);              // 2^64 - 1 values
assume(x < 100);            // 99 values — symbolic collapse
```

This isn't necessarily bad (some functions only need small domains to
exercise all branches), but it should be documented.

### 2.6 Coupling Completeness

The proof must test the **actual production function**, not a simplified
copy.

**Questions:**
- Does the harness call the real function from the production module?
- If a `verify`/`spec` module extracts logic: is there a coupling proof
  showing the extraction matches the production handler?
- Does the check ordering in the verify function match the production
  handler's check ordering?
- Could a refactor make the verify function diverge from production?

**Residual gap:** If the proof verifies `verify::decide(...)` but production
calls `processor::handle(...)`, and there's no coupling proof, then the
proofs verify a different function than what users interact with.

---

## Step 3: Classify Each Proof

### Classification Definitions

| Classification | Criteria | Value to Audit |
|---------------|----------|---------------|
| **STRONG** | Symbolic inputs exercise key branches. Assertion matches intended property. Non-vacuous. | High — genuine formal guarantee |
| **WEAK** | Symbolic inputs but bounded domain, or assertion weaker than property. | Medium — guarantee within bounds only |
| **UNIT TEST** | Concrete inputs or single execution path. | Low — regression guard, not verification |
| **CODE-EQUALS-SPEC** | Assertion restates the function body. | Low — guards refactors only |
| **VACUOUS** | Assertion unreachable or assumptions contradictory. | Zero — proves nothing |

### Decision Tree

```
Can the assertion be reached?
├── No → VACUOUS ⚠️
└── Yes
    ├── Are inputs symbolic?
    │   ├── No → UNIT TEST
    │   └── Yes
    │       ├── Does assertion restate the function body?
    │       │   ├── Yes → CODE-EQUALS-SPEC
    │       │   └── No
    │       │       ├── Are inputs bounded below production range?
    │       │       │   ├── Yes → WEAK
    │       │       │   │   ├── Category A: Branch gap
    │       │       │   │   ├── Category B: Weak assertion
    │       │       │   │   └── Category C: SAT-bounded
    │       │       │   └── No
    │       │       │       ├── Does it exercise key branches?
    │       │       │       │   ├── No → WEAK (Category A)
    │       │       │       │   └── Yes → STRONG ✓
```

---

## Step 4: Strength Tier Assignment

After classifying proofs as STRONG, assign tiers:

### Tier 1: Universal Characterization (highest value)

Proves `f(x) == formula` for ALL inputs. Fully characterizes the function.

**Signature pattern:**
```
let inputs = kani::any();
let result = production_function(inputs);
assert!(result == expected_formula(inputs));
// Tests BOTH outcomes for decision functions:
match result {
    Accept(v) => assert!(v == ...),
    Reject    => assert!(!should_accept(inputs)),
}
```

### Tier 2: Universal Gate Rejection (critical security)

Proves that a single failure condition causes rejection, regardless of
all other inputs being valid.

**Signature pattern:**
```
let all_inputs = kani::any();
assume(!one_specific_check);  // force ONE gate open
let result = production_function(all_inputs);
assert!(matches!(result, Reject));
```

### Tier 3: State Transition Relations (critical correctness)

Proves exact state-change rules (nonces, balances, counters).

### Tier 4: Input Validation (boundary security)

Proves malformed inputs are rejected for every field independently.

### Tier 5: Authorization (access control)

Proves unauthorized callers are rejected.

### Tier 6: Math / Conservation (arithmetic correctness)

Proves conservation laws, monotonicity, bounded dust, etc.

---

## Step 5: Generate Summary Statistics

### Required Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Total proofs | | |
| STRONG count (%) | | > 70% |
| WEAK count (%) | | < 20% |
| UNIT TEST count (%) | | < 10% |
| CODE-EQUALS-SPEC count (%) | | < 10% |
| VACUOUS count (%) | | **0%** |
| Tier 1 (Universal Characterization) | | ≥ 1 per critical function |
| Tier 2 (Gate Rejection) | | ≥ 1 per auth gate |
| Non-vacuity witnesses present | | Yes for conditional proofs |
| Coupling proofs present | | Yes if verify module exists |

### Quality Summary Template

```markdown
## Proof Suite Quality Assessment

**Suite**: [N] proofs, [TOOL], all passing.
**STRONG**: [N] ([%]) — [BRIEF DESCRIPTION OF STRONGEST PROOFS]
**WEAK**: [N] ([%]) — all [CATEGORY], bounded for [REASON]
**UNIT TEST**: [N] ([%]) — retained as [PURPOSE]
**CODE-EQUALS-SPEC**: [N] ([%]) — guards [WHAT]
**VACUOUS**: [N] ([%]) [IF > 0: ⚠️ INVESTIGATE]

**Highest-value proof**: [NAME] — [ONE LINE DESCRIPTION]
**Critical gap**: [WHAT IS NOT PROVEN]
**Overall assessment**: [MATURE / DEVELOPING / IMMATURE / THEATRICAL]
```

---

## Step 6: Common Anti-Patterns

### The Theater Suite
- 100+ proofs, but all UNIT TEST (concrete inputs)
- Looks impressive by count, provides no generalization
- **Flag**: "Formal verification suite contains [N] proofs but [%] use
  concrete inputs only, reducing to regression tests."

### The Vacuity Trap
- Proofs pass because assertions are never reached
- Common cause: contradictory `assume()` chains
- **Flag**: "Proof `[NAME]` appears vacuous — assertion at line [N] is
  unreachable under the given assumptions."

### The Weakened Spec
- Proof verifies a simpler function than production uses
- No coupling proof connecting spec to production
- **Flag**: "Proofs verify `verify::decide()` but production calls
  `processor::handle()`. No coupling proof exists."

### The Missing Column
- Only verifies "good inputs succeed" without proving "bad inputs fail"
- Authorization proofs that only test match, never mismatch
- **Flag**: "Authorization proofs only verify acceptance (match case).
  No proofs verify that mismatched callers are rejected."

### The Bounded Illusion
- `let x: u8 = kani::any()` instead of `let x: u64 = kani::any()`
- Claims "all values tested" but domain is type-bounded
- **Flag**: "Proof uses `u8` symbolic input but production type is `u64`.
  Only 256 of 2^64 values are exercised."

---

## Appendix: Verification Tool Considerations

### Kani (Rust)
- CBMC backend → integer arithmetic is bit-level SAT
- Division chains cause exponential blowup (justify SAT bounds)
- Cannot model external calls (CPI, FFI)
- `kani::any()` is fully symbolic for the given type

### Certora (Solidity/EVM)
- Prover uses SMT (Z3/Bitwuzla)
- Can model multi-contract interactions
- Loop unrolling bounds must be checked
- `require()` in rules narrows search space

### Halmos (Solidity/EVM)
- Symbolic EVM execution
- Bounded by loop unrolling and call depth
- `vm.assume()` for constraints
- Relatively new — check for known limitations

### General
- State-of-the-art tools have limitations — note them
- "Verified" means "verified under the tool's model"
- The gap between the model and production is where bugs hide
