---
id: METH-FORMAL-VERIFICATION-ASSESSMENT
title: Formal Verification Assessment
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move]
tags:
  - formal-verification
  - kani
  - certora
  - halmos
  - proof-strength
  - vacuity
  - sat-bounded
  - code-equals-spec
  - invariant
  - symbolic-execution
last_updated: 2026-02-27
description: >-
  Use when a protocol claims formal verification or when evaluating proof
  suites — covers proof classification taxonomy (STRONG, WEAK, UNIT TEST,
  CODE-EQUALS-SPEC, VACUOUS) with REAL examples from production proof
  catalogs, proof catalog assessment templates, SAT-bounded limitations,
  common vacuity traps, and quick assessment checklists. Different from
  proof-strength-evaluation.md which covers abstract methodology — this
  provides concrete classification examples and a working assessment
  framework derived from auditing 147-proof production harnesses.
---

# Formal Verification Assessment

## Overview

When a protocol says "we are formally verified," the auditor's job is NOT
to take this at face value. Formal verification is a spectrum — from
vacuous proofs that assert nothing useful to universal characterization
proofs that fully define a function's behavior. The auditor must classify
each proof and identify what is NOT covered.

**Core principle**: A proof suite is only as strong as its weakest assumption.
One vacuous proof can give false confidence in a critical property. The
auditor must find the gap between what the proofs CLAIM and what they
ACTUALLY verify.

### The Proof Strength Spectrum

```
VACUOUS → CODE-EQUALS-SPEC → UNIT TEST → WEAK → STRONG
  │              │                │          │        │
  │              │                │          │     Fully symbolic,
  │              │                │          │     all branches,
  │              │                │          │     key property
  │              │                │          │
  │              │                │       Symbolic but
  │              │                │       SAT-bounded domain
  │              │                │
  │              │             Concrete inputs,
  │              │             single execution path
  │              │
  │           Assertion restates
  │           function body
  │
  Assertion always true
  regardless of inputs
```

## Proof Classification Taxonomy

### STRONG Proofs (Target: >80% of suite)

A STRONG proof has:
1. **Symbolic inputs** — exercises all possible combinations
2. **Appropriate property** — asserts a meaningful security property
3. **Non-vacuous** — both branches of the property are reachable
4. **Adequate coverage** — key decision branches are exercised

#### Tier 1: Universal Characterization (Highest Value)

These proofs specify a function's output as EXACTLY a formula for ALL inputs.
They leave zero behavioral ambiguity.

**Real example** (from Percolator proof suite):

```
Proof: kani_tradenocpi_universal_characterization
Property: accept iff (user_auth && lp_auth && !(gate && risk))
Coverage: All 2^4 = 16 input combinations
Classification: STRONG (Tier 1)

Why it's valuable: This single proof COMPLETELY describes when a
TradeNoCpi operation succeeds. Any future code change that alters
this behavior will break the proof.
```

**More Tier 1 examples**:

| Proof | Property | Combinations |
|-------|----------|-------------|
| `matcher_shape_universal` | `ok == (prog_exec && !ctx_exec && ctx_owned && ctx_len)` | 2^4 = 16 |
| `lp_pda_shape_universal` | `ok == (system_owned && data_zero && lamports_zero)` | 2^3 = 8 |
| `decide_trade_cpi_universal` | Accept iff all 7 checks pass; on Accept: nonce+1, size=exec_size | All 10 inputs symbolic |

#### Tier 2: Universal Gate Rejection (Critical Security)

Each proof shows that a single gate failure causes rejection regardless
of ALL other inputs.

**Real example**:

```
Proof: kani_universal_shape_fail_rejects
Property: !matcher_shape_ok => Reject
Setup: Shape forced invalid, ALL other inputs fully symbolic
Classification: STRONG (Tier 2)

Why it's valuable: Proves that even if every other check passes,
a shape failure alone causes rejection. This is a "kill switch" proof.
```

| Proof Pattern | Gate | Security Property |
|--------------|------|------------------|
| `universal_shape_fail_rejects` | Matcher shape | Invalid program layout → reject |
| `universal_pda_fail_rejects` | PDA match | Wrong PDA → reject |
| `universal_user_auth_fail_rejects` | User auth | Unauthorized user → reject |
| `universal_lp_auth_fail_rejects` | LP auth | Unauthorized LP → reject |
| `universal_identity_fail_rejects` | Identity | Wrong program identity → reject |
| `universal_abi_fail_rejects` | ABI | Bad return format → reject |
| `universal_gate_risk_increase_rejects` | Anti-DoS gate | Risk increase during gate → reject |

#### Tier 3: State Transition Proofs

These verify that state transitions are correct for both success and failure:

```
Property: reject => nonce unchanged
Property: accept => nonce = old_nonce + 1
Property: accept => chosen_size = exec_size (not req_size)

Classification: STRONG because:
- Inputs are fully symbolic
- Both Accept and Reject paths are covered
- Non-vacuity is explicitly witnessed
```

### WEAK Proofs (Flag, Don't Panic)

A WEAK proof has correct structure but limited coverage due to
SAT solver tractability constraints.

**Common reason**: 128-bit division chains. The SAT solver cannot handle
`kani::any::<u128>()` values in division, so inputs are bounded.

**Real example**:

```
Proof: kani_invert_nonzero_computes_correctly
Property: floor(1e12 / raw) == function output
Input bound: raw in (0, 8192] (NOT full u64 range)
SAT reason: 128-bit division + equality check; 8192 takes ~66 seconds

Classification: WEAK (Category C: SAT-bounded)
Risk: Property holds within bounds but is UNTESTED for raw > 8192
Mitigation: Companion proofs cover overflow branches at full range
```

**How to assess WEAK proofs**:

| Question | Good Answer | Bad Answer |
|----------|------------|-----------|
| Why is it bounded? | "128-bit division chain; documented in source" | "No documentation; arbitrary bound" |
| Are bounds documented? | Source comments explain SAT limit | No explanation |
| Companion proofs exist? | Other proofs cover remaining branches | This is the only proof |
| Structural argument? | "Floor division is monotonic for all integers" | No structural reasoning |

### UNIT TEST Proofs (Regression Guards)

A UNIT TEST proof uses concrete (not symbolic) inputs. It tests a single
execution path.

**When UNIT TEST proofs are acceptable**:
- Boundary regression: `i128::MIN` handling after a historical bug
- Path-specific testing: Force-accept path via concrete pre-conditions
- Documentation: Prove a specific example works as expected

**Real example**:

```
Proof: kani_min_abs_boundary_rejected
Property: i128::MIN boundary handled correctly
Inputs: Fully concrete (i128::MIN)
Why it exists: Historical bug where .abs() panics on i128::MIN,
               but .unsigned_abs() works correctly.

Classification: UNIT TEST (intentional regression guard)
Risk: Only tests this one value, not the general case
```

### CODE-EQUALS-SPEC Proofs (Tautological)

These assert that a function returns exactly what its body computes.
They guard against refactors but prove no independent security property.

**Real examples**:

```
Proof: kani_accumulate_dust_saturates
Assertion: accumulate_dust(a, b) == a.saturating_add(b)
Function body: pub fn accumulate_dust(a, b) { a.saturating_add(b) }

Classification: CODE-EQUALS-SPEC
Value: Prevents accidental change to accumulate_dust()
Risk: Proves nothing about CORRECTNESS of using saturating_add
```

| Function | Assertion | Tautology |
|----------|-----------|-----------|
| `accumulate_dust(a,b)` | `== a.saturating_add(b)` | Function IS saturating_add |
| `base_to_units(base, 0)` | `== (base, 0)` | Function returns early for scale=0 |
| `scale_price_e6(price, 1)` | `== Some(price)` | Function returns early for scale<=1 |

### VACUOUS Proofs (Critical Audit Finding)

A VACUOUS proof is one where the assertion is ALWAYS true regardless of
inputs, or where the assume() constraints are unsatisfiable (no valid
inputs exist).

**How to detect vacuity**:

```
RED FLAGS for vacuity:
1. No conditional assertion — just `assert!(true)` or equivalent
2. Contradictory assumes — assume(x > 5) + assume(x < 3) = no valid inputs
3. Assertion restates assume — assume(x > 0); assert!(x > 0)
4. No matching on outcomes — doesn't check both Accept AND Reject paths
5. Missing non-vacuity witness — no concrete example proving both paths exist
```

**Production suite fact**: In the 110-proof Percolator suite, 0 proofs
are vacuous. This is achieved by:
- Non-vacuity witnesses (concrete examples proving both paths reachable)
- Universal quantification matching on both outcomes
- Explicit `panic!` on unexpected outcomes

## Assessment Framework

### Quick Assessment (15 minutes)

For rapid triage of a "formally verified" claim:

1. **Count proofs by category**: Run through each proof, classify as
   STRONG/WEAK/UNIT TEST/CODE-EQUALS-SPEC/VACUOUS
2. **Check STRONG percentage**: Target >80%. Below 60% = weak suite
3. **Check for VACUOUS proofs**: Any vacuous proof is a red flag
4. **Identify UNCOVERED functions**: Which functions have NO proofs?
5. **Check proof tool**: Kani, Certora, Halmos each have different strengths

### Classification Summary Template

| Classification | Count | Percentage | Assessment |
|---------------|-------|-----------|------------|
| STRONG | ? | ?% | Target: >80% |
| WEAK | ? | ?% | Acceptable: <15% with documentation |
| UNIT TEST | ? | ?% | Acceptable: <10% as regression guards |
| CODE-EQUALS-SPEC | ? | ?% | Flag: >10% suggests weak spec |
| VACUOUS | ? | ?% | Critical: ANY = audit finding |
| **Total** | **?** | **100%** | |

### 6-Point Analysis Per Proof

For each proof harness, evaluate:

1. **Input space**: Fully symbolic? Bounded? Concrete?
2. **Property asserted**: Security-relevant? Or tautological?
3. **Branch coverage**: Which function branches are exercised?
4. **Assumption strength**: Are `assume()` constraints reasonable?
5. **Non-vacuity**: Is there evidence both outcomes are reachable?
6. **Companion proofs**: Do other proofs cover what this one misses?

### Proof Coverage Gap Analysis

After classifying all proofs, identify what's NOT proven:

```
Coverage Matrix:
                    Proven              Not Proven
Authorization    [list proofs]        [list gaps]
State transitions [list proofs]       [list gaps]
Arithmetic       [list proofs]        [list gaps]
Error handling   [list proofs]        [list gaps]
Edge cases       [list proofs]        [list gaps]
```

## Tool-Specific Assessment

### Kani (Rust / Solana Programs)

**Strengths**:
- Symbolic execution via CBMC backend
- Works directly on Rust source
- Good for bit-level properties

**Limitations**:
- SAT-bounded for complex arithmetic (128-bit division)
- Cannot model Solana runtime (account loading, rent)
- Does not model CPI execution environment

**Audit assessment questions**:
- Are Kani bounds documented and justified?
- Are companion proofs covering what bounded proofs miss?
- Is the Solana runtime abstracted correctly?

### Certora (Solidity / EVM)

**Strengths**:
- CVL specification language is separate from code
- Models EVM storage layout
- Good for protocol-level invariants

**Limitations**:
- Under-specified harnesses can be vacuously true
- Loop unrolling limits affect coverage
- External call modeling may be incomplete

**Audit assessment questions**:
- Are specs separate from implementation? (stronger than CODE-EQUALS-SPEC)
- Are loop bounds explicitly justified?
- Are external calls modeled or assumed?

### Halmos (Solidity Symbolic Testing)

**Strengths**:
- Runs as Foundry tests (low adoption barrier)
- Symbolic inputs via `svm.createUint256()`
- Good for invariant testing

**Limitations**:
- Bounded by `--loop` parameter
- Path explosion with complex branching
- Not a full formal verifier (bounded model checking)

**Audit assessment questions**:
- What `--loop` bound was used? Is it sufficient?
- Are symbolic variables constrained appropriately?
- Are counterexamples investigated?

## Common Pitfalls in Proof Suites

### Pitfall 1: Testing, Not Proving

```
❌ "We ran Kani on 100 test cases" = property testing, not formal verification
✅ "Kani proves this property for ALL possible inputs" = formal verification
```

### Pitfall 2: Proving the Wrong Property

```
❌ Proof: "transfer() doesn't panic"
   (Says nothing about CORRECTNESS — it could silently do the wrong thing)

✅ Proof: "transfer() decreases sender by amount AND increases receiver by amount"
   (Proves the actual security property)
```

### Pitfall 3: Proving Implementation, Not Specification

```
❌ assert!(my_function(x) == x * 2 + 1)  // when function body IS x * 2 + 1
   → CODE-EQUALS-SPEC, proves nothing about correctness

✅ assert!(my_function(x) == reference_implementation(x))
   → Independent specification gives real assurance
```

### Pitfall 4: Unbounded Assumptions

```
❌ assume!(x < 100); prove!(property_holds(x))
   → Only proves property for x < 100, not for real-world values

Ask: What happens for x >= 100? Is it blocked at the program level?
```

## Audit Report Template

### When Protocol Claims "Formally Verified"

```markdown
## Formal Verification Assessment

**Tool**: [Kani/Certora/Halmos]
**Proof Count**: [N total]
**Classification**:
- STRONG: [N] ([%])
- WEAK: [N] ([%]) — [Category C: SAT-bounded]
- UNIT TEST: [N] ([%])
- CODE-EQUALS-SPEC: [N] ([%])
- VACUOUS: [N] ([%])

**Coverage Gaps**:
1. [Function/property not covered by any proof]
2. [Property covered only by WEAK proofs]
3. [Area where assumptions may not hold in production]

**Assessment**: [The proof suite provides {HIGH/MODERATE/LOW} assurance.
The primary gap is {description}. Recommend: {specific improvement}.]
```

## Integration with Other Skills

| Skill | Relationship |
|-------|-------------|
| [Proof Strength Evaluation](../advanced/proof-strength-evaluation.md) | Abstract methodology; this file provides concrete examples |
| [DeFi Perpetuals Audit](../patterns/defi-perpetuals-audit.md) | Percolator proofs are real-world FV in perps |
| [TDD Security Testing](methodology/tdd-security-testing.md) | Where FV ends, property-based testing begins |
| [Finding Quality Standards](methodology/finding-quality-standards.md) | FV gap = finding; classify severity appropriately |
| [Verification Discipline](methodology/verification-discipline.md) | Proofs are evidence; apply evidence-before-claims |
