---
id: formal-verification-audit
title: "Formal Verification Audit Template"
category: templates
tier: methodology
audience: [auditors, protocol-teams]
origin: methodology-extraction
version: 1.0.0
---

# Formal Verification Audit Template

## Purpose

When a protocol claims "formally verified," auditors need a structured way to
evaluate *what* is actually proven, *how strong* those proofs are, and *what
gaps remain*. This template provides that structure.

Most formal verification in DeFi covers a subset of the system. The job of an
auditor is to map the proven properties to the actual security surface and
identify uncovered areas.

---

## How to Use This Template

1. **Inventory all proofs** — list every harness/lemma/property by category.
2. **Classify each proof** — STRONG, WEAK, UNIT TEST, CODE-EQUALS-SPEC, or
   VACUOUS.
3. **Map proved properties to security claims** — does the proof actually back
   the marketing claim?
4. **Document what is NOT proven** — this is often more important than what is.
5. **Evaluate proof quality** — use Section 4 (6-point analysis).

---

## Section 1: Proof Inventory

### Protocol: `[PROTOCOL_NAME]`
### Verification Tool: `[Kani / Certora / Halmos / KEVM / other]`
### Total Proofs: `[N]`
### All Passing: `[Yes / No — if No, stop here and report]`

### Category Summary

| Category | Domain | Proof Count | Critical? |
|----------|--------|-------------|-----------|
| A | `[e.g., ABI Validation]` | | Yes / No |
| B | `[e.g., Access Control]` | | Yes / No |
| C | `[e.g., State Transitions]` | | Yes / No |
| D | `[e.g., Math/Arithmetic]` | | Yes / No |
| E | `[e.g., CPI/External Call Binding]` | | Yes / No |
| F | `[e.g., Nonce/Ordering]` | | Yes / No |
| G | `[e.g., Fund Conservation]` | | Yes / No |

### Classification Distribution

| Classification | Count | Percentage | Description |
|---------------|-------|------------|-------------|
| **STRONG** | | | Symbolic inputs, key branches exercised, non-vacuous |
| **WEAK** | | | Symbolic but bounded domain reduces coverage |
| **UNIT TEST** | | | Concrete inputs or single path — regression guard only |
| **CODE-EQUALS-SPEC** | | | Assertion restates function body; guards refactors |
| **VACUOUS** | | | Assertion never reached, or assumes contradiction |
| **Total** | | **100%** | |

> **Red flag**: If VACUOUS > 0%, investigate immediately. A vacuous proof
> proves nothing.

---

## Section 2: Proof Detail Tables

### Per-Category Proof Listing

> For each category, list every proof with its classification.

#### Category: `[CATEGORY_NAME]` (`[N]` proofs)

| # | Harness / Lemma Name | Property Proven | Classification | Notes |
|---|---------------------|----------------|----------------|-------|
| 1 | `[proof_name]` | One-line description | STRONG / WEAK / etc. | |
| 2 | `[proof_name]` | | | |
| 3 | `[proof_name]` | | | |

### Proof Tier Hierarchy

Organize STRONG proofs by verification power (highest to lowest):

**Tier 1 — Universal Characterization** (highest value)
> Proves a function's output is EXACTLY a specific formula for ALL input
> combinations. Fully characterizes the function, leaving zero behavioral
> ambiguity.

| # | Proof | Property |
|---|-------|----------|
| | | |

**Tier 2 — Universal Gate Rejection** (critical security)
> Each proves that a single failure condition causes rejection regardless
> of ALL other inputs. These are "kill switch" proofs.

| # | Proof | Gate |
|---|-------|------|
| | | |

**Tier 3 — State Transition Relations** (critical correctness)
> Proves that state changes (nonces, balances, flags) follow exact rules.

| # | Proof | Property |
|---|-------|----------|
| | | |

**Tier 4 — Input Validation** (boundary security)
> Proves that malformed/malicious inputs are rejected.

| # | Proof | Property |
|---|-------|----------|
| | | |

**Tier 5 — Authorization** (access control)
> Proves that unauthorized callers are rejected.

| # | Proof | Property |
|---|-------|----------|
| | | |

**Tier 6 — Math/Invariant** (arithmetic correctness)
> Proves conservation laws, monotonicity, boundedness.

| # | Proof | Property |
|---|-------|----------|
| | | |

---

## Section 3: WEAK Proof Analysis

### Weakness Categories

| Category | Description | Risk Level |
|----------|-------------|------------|
| **A: Branch Coverage Gaps** | Proof doesn't exercise all code paths | High |
| **B: Weak Assertions** | Assertion is weaker than the actual invariant | Medium |
| **C: SAT-Bounded Collapse** | Domain is constrained for solver tractability | Low-Medium |
| **D: Trivially True** | Assertion holds by construction, proves nothing | High |

### WEAK Proof Details

| # | Proof | Category | Bound | Why It Cannot Be Widened | Companion Proofs |
|---|-------|----------|-------|-------------------------|-----------------|
| 1 | | | | | |
| 2 | | | | | |

> **Key question for each WEAK proof**: Is the bounded domain sufficient to
> exercise all code branches? If yes, the weakness is about range, not logic.
> If no, the proof may miss real bugs.

---

## Section 4: Per-Proof Quality Analysis (6-Point)

> Apply this 6-point analysis to any proof you need to evaluate deeply.

### 1. Input Classification
- Are inputs fully symbolic, bounded symbolic, or concrete?
- What `assume()` / `require()` constraints narrow the input space?
- Do constraints match real-world usage, or are they artificial?

### 2. Branch Coverage
- Does the proof exercise all branches of the function under test?
- Are there short-circuit returns that skip the main logic?
- For conditional proofs (`if X then Y`): is the antecedent satisfiable?

### 3. Invariant Strength
- Does the assertion match the intended security property?
- Is the assertion weaker than necessary? (e.g., checking `!= 0` when
  the real invariant is `== expected_value`)
- Could the assertion pass even if the function is broken?

### 4. Vacuity Risk
- Can the proof's assumptions be simultaneously satisfied?
- Is there a concrete witness proving non-vacuity?
- Does the proof test both outcomes (accept and reject)?

### 5. Symbolic Collapse
- For bounded proofs: does the domain collapse to a small set?
- After applying all `assume()` constraints, how many distinct
  execution paths remain?
- Is the SAT bound documented and justified?

### 6. Coupling Completeness
- Does the proof call the actual production function, or a simplified
  version?
- If a `verify` / `spec` module extracts logic: is there a proof that
  the extraction matches the production code?
- Is the check ordering in the proof consistent with the production
  handler's check ordering?

### Classification Decision Tree

```
Is the proof's assertion reachable?
├── No → VACUOUS
└── Yes
    ├── Does it use symbolic inputs?
    │   ├── No → UNIT TEST
    │   └── Yes
    │       ├── Does the assertion merely restate the function body?
    │       │   ├── Yes → CODE-EQUALS-SPEC
    │       │   └── No
    │       │       ├── Are inputs bounded below production range?
    │       │       │   ├── Yes → WEAK (document which category)
    │       │       │   └── No → candidate for STRONG
    │       │       │       ├── Does it exercise key branches?
    │       │       │       │   ├── No → WEAK (Category A)
    │       │       │       │   └── Yes → STRONG
```

---

## Section 5: What is NOT Proven

> This section is often more important than proof inventory. List every
> security-relevant property that the verification does NOT cover.

### Not Covered by Formal Verification

| Area | Reason | Alternative Coverage |
|------|--------|---------------------|
| `[e.g., Risk engine internals]` | `[e.g., Lives in separate crate]` | `[e.g., Unit tests + fuzzing]` |
| `[e.g., CPI execution]` | `[e.g., Requires runtime model]` | `[e.g., Integration tests]` |
| `[e.g., Account deserialization]` | `[e.g., Runtime validation]` | `[e.g., Solana framework handles]` |
| `[e.g., Oracle reading]` | `[e.g., External dependency]` | `[e.g., Mock-based integration tests]` |
| `[e.g., Token transfers]` | `[e.g., SPL Token program]` | `[e.g., Trusted dependency]` |

### Bounded Verification Gaps

| Proof | Production Range | Verified Range | Gap |
|-------|-----------------|----------------|-----|
| `[proof_name]` | `u64::MAX` | `[0, 16384]` | Wide — but structural argument applies |
| `[proof_name]` | `u128::MAX` | `u8 range` | Covered by integration tests |

---

## Section 6: Proof-to-Claim Mapping

> Map each marketing/documentation security claim to the proofs that back it.

| # | Security Claim | Backed By Proofs? | Proof Names | Strength |
|---|---------------|-------------------|-------------|----------|
| 1 | "Admin cannot steal funds" | Yes / Partial / No | `[list]` | STRONG / WEAK |
| 2 | "All trades are authorized" | | | |
| 3 | "Nonces prevent replay" | | | |
| 4 | "Oracle manipulation is bounded" | | | |
| 5 | "Liquidations are fair" | | | |

> **Red flag**: Any claim marked "No" or backed only by WEAK/UNIT TEST proofs
> should be escalated.

---

## Section 7: Cross-Cutting Quality Signals

### Positive Signals (higher confidence)

- [ ] **Non-vacuity witnesses** — proofs include concrete examples proving
      both paths are reachable
- [ ] **Both-outcome matching** — proofs verify behavior on both accept
      AND reject paths
- [ ] **Coupling proofs** — extracted verify/spec functions are proven
      equivalent to production code
- [ ] **STRONG percentage > 70%** — majority of proofs carry real weight
- [ ] **Zero VACUOUS proofs** — no dead-code proofs
- [ ] **SAT bounds documented** — bounded proofs explain why limits exist
- [ ] **Removed proofs documented** — history of removed/consolidated proofs
      shows maturation

### Negative Signals (lower confidence)

- [ ] **High UNIT TEST percentage** — concrete-only proofs don't generalize
- [ ] **Missing coupling proofs** — verify module may diverge from production
- [ ] **Undocumented SAT bounds** — unclear if bounded range is sufficient
- [ ] **No non-vacuity witnesses** — proofs may be vacuously true
- [ ] **Proofs don't match claims** — marketing overstates verified properties
- [ ] **Verification tool limitations not disclosed** — e.g., loop unrolling
      bounds, memory model assumptions

---

## Section 8: Audit Report Language

### For findings

> **[SEVERITY]: Formal verification claim `[CLAIM]` is not backed by proofs.**
> The protocol documentation states `[QUOTE]`. However, the proof suite does
> not cover `[AREA]`. Recommend adding `[PROOF_TYPE]` proofs or downgrading
> the claim.

### For informational notes

> **[INFO]: `[N]` WEAK proofs use SAT-bounded domains.**
> Proofs `[LIST]` verify properties only within `[RANGE]` of the production
> domain. The remaining range is covered by `[ALTERNATIVE]`. This is standard
> practice for verificiation tools with SAT solvers but should be documented.

### For positive acknowledgments

> The proof suite demonstrates mature formal verification with `[N]` STRONG
> proofs (`[%]`) covering `[AREAS]`. Non-vacuity discipline is strong, with
> `[PATTERN]`. The `[TIER_1_PROOF]` is particularly valuable as it fully
> characterizes `[FUNCTION]`.
