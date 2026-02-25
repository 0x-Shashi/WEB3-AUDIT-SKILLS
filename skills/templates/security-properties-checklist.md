---
id: security-properties-checklist
title: "Security Properties Verification Checklist"
category: templates
tier: methodology
audience: [auditors, protocol-teams]
origin: methodology-extraction
version: 1.0.0
---

# Security Properties Verification Checklist

## Purpose

A protocol's security depends on a set of **properties** — invariants that
must always hold. This template provides a structured way to enumerate,
categorize, and verify those properties. It captures the methodology of
organizing security properties by domain (authorization, state transitions,
CPI, math) and mapping each property to its verification evidence.

---

## How to Use This Template

1. **Enumerate properties** by category (Section 1).
2. **For each property**, state the invariant, its criticality, and what
   happens if it's violated.
3. **Map each property to verification evidence** — test name, proof name,
   or "UNVERIFIED."
4. **Run the verification matrix** (Section 3) to identify gaps.

---

## Section 1: Security Property Categories

### Category A: Authorization Surface

> Every action must be authorized. Unauthorized access is the #1 vulnerability
> class across all chains.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| A1 | Owner enforcement | Every account operation validates `owner == signer` | Critical |
| A2 | Admin enforcement | Admin ops require `admin == signer` | Critical |
| A3 | Burned admin permanence | Burned/renounced admin disables all admin ops forever | Critical |
| A4 | Keeper authorization | Keeper actions are either permissionless or owner-gated | High |
| A5 | Trade dual-authorization | Both counterparties must sign (user AND LP) | Critical |
| A6 | Oracle authority | Only designated authority can push prices | High |
| A7 | Post-rotation lockout | Old admin/owner key is dead after rotation | Critical |

### Category B: CPI / External Call Security

> For protocols making cross-program or cross-contract calls.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| B1 | Identity binding | CPI target must match registered program | Critical |
| B2 | Context binding | CPI context must match registered context | Critical |
| B3 | Shape validation | Target is executable, context is not, owner is correct | Critical |
| B4 | Return data validation | All ABI fields validated before use | Critical |
| B5 | Size constraint | Executed size ≤ requested size | Critical |
| B6 | Sign constraint | Returned sign matches request direction | High |
| B7 | Identity trumps ABI | Identity mismatch rejects even with valid ABI data | Critical |

### Category C: State Consistency

> State transitions must follow exact rules. Incorrect transitions enable
> replay, double-spend, or state corruption.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| C1 | Nonce on failure | Any rejection leaves nonce unchanged | Critical |
| C2 | Nonce on success | Successful action advances nonce by exactly 1 | Critical |
| C3 | Nonce wrapping | Overflow wraps correctly (no revert/panic) | High |
| C4 | Balance conservation | `sum(inputs) == sum(outputs) + fees` always | Critical |
| C5 | No double execution | Same request ID cannot be processed twice | Critical |
| C6 | State machine ordering | State transitions respect defined lifecycle | High |
| C7 | Atomic transitions | Multi-step operations either fully complete or fully revert | Critical |

### Category D: Risk Gate Policy

> Protocols with risk management may gate operations under stress.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| D1 | Gate inactive at zero threshold | Zero threshold disables gating | Medium |
| D2 | Gate inactive above threshold | Sufficient balance disables gating | Medium |
| D3 | Risk-increasing rejected when active | Anti-DoS: cannot increase risk under stress | High |
| D4 | Risk-reducing allowed when active | Deleveraging always permitted | High |

### Category E: Input Validation

> All external input must be validated. Malformed input is a primary attack vector.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| E1 | ABI version enforcement | Wrong ABI version always rejected | High |
| E2 | Required flags | Missing required flags always rejected | High |
| E3 | Reserved fields | Non-zero reserved fields always rejected | Medium |
| E4 | Zero price rejection | Zero execution price always rejected | High |
| E5 | Size overflow | Executed size greater than requested always rejected | Critical |
| E6 | Sign mismatch | Opposing signs always rejected | High |
| E7 | Integer edge cases | `i128::MIN`, `u64::MAX`, `0` don't cause panic | High |

### Category F: Math / Arithmetic

> DeFi protocols depend on correct arithmetic. Rounding, overflow, and
> precision errors cause fund loss.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| F1 | Conservation | `units + dust == base` (no value loss in conversion) | Critical |
| F2 | Dust bounded | `dust < unit_scale` always | High |
| F3 | Monotonicity | Larger inputs produce larger (or equal) outputs | High |
| F4 | Roundtrip | `decode(encode(x)) >= x` (no silent loss) | Critical |
| F5 | Determinism | Same inputs always produce same outputs | Medium |
| F6 | No overflow panic | Operations saturate instead of panicking | High |
| F7 | Rate limiting | Index movement bounded by `cap * dt` per period | High |

### Category G: Fund Safety

> User and protocol funds must be protected under all conditions.

| # | Property | Invariant Statement | Criticality |
|---|----------|-------------------|-------------|
| G1 | No premature withdrawal | Cannot extract funds before obligations are cleared | Critical |
| G2 | Destination verification | Withdrawal destination matches account owner | Critical |
| G3 | Closure safety | Cannot close accounts/markets while funds remain | Critical |
| G4 | Insurance isolation | Insurance fund separate from user collateral | High |
| G5 | Alignment enforcement | Withdrawals aligned to unit scale | Medium |

---

## Section 2: Verification Evidence Matrix

> For each property, document what evidence exists.

| Property ID | Evidence Type | Evidence Name | Strength |
|-------------|--------------|---------------|----------|
| A1 | Kani proof | `kani_owner_mismatch_rejected` | STRONG |
| A1 | Integration test | `test_attack_as_wrong_owner` | Concrete |
| A2 | Kani proof | `kani_admin_mismatch_rejected` | STRONG |
| A3 | Kani proof | `kani_admin_burned_disables_ops` | STRONG |
| A3 | Integration test | `test_burned_admin_cannot_act` | Concrete |
| B1 | Kani proof | `kani_matcher_identity_mismatch_rejected` | STRONG |
| ... | | | |
| G3 | Integration test | `test_attack_close_with_remaining_funds` | Concrete |
| `[ID]` | **UNVERIFIED** | — | ⚠️ **GAP** |

### Evidence Type Hierarchy

| Type | Strength | Coverage |
|------|----------|---------|
| Formal proof (STRONG) | Highest | All inputs in domain |
| Formal proof (WEAK) | High | Bounded domain |
| Fuzz test / proptest | Medium-High | Random sample of domain |
| Integration test | Medium | Specific scenarios |
| Unit test | Low-Medium | Single execution path |
| Code review only | Low | Human analysis |
| **UNVERIFIED** | **None** | **Finding candidate** |

---

## Section 3: Gap Analysis

### Properties Without Verification Evidence

| Property ID | Description | Risk | Recommendation |
|-------------|-------------|------|----------------|
| `[ID]` | `[property statement]` | `[Critical/High/Medium]` | Add test/proof |

### Properties With Only Weak Evidence

| Property ID | Current Evidence | Gap | Recommendation |
|-------------|-----------------|-----|----------------|
| `[ID]` | Unit test only | No generalization | Add symbolic proof or fuzz |

### Uncategorized Security Claims

> List any security claims from documentation that don't map to a property above.

| Claim | Source | Mapped to Property? | Evidence? |
|-------|--------|---------------------|-----------|
| `"All trades are authorized"` | README | A5 | Yes — STRONG |
| `"Funds cannot be stolen"` | Marketing | G1, G2, G3 | Partial — G2 missing proof |
| `"[CLAIM]"` | `[SOURCE]` | `[PROPERTY_ID or UNMAPPED]` | `[STATUS]` |

---

## Section 4: Auditor Verification Procedure

### Phase 1: Property Enumeration (1-2 hours)

1. Read all documentation and extract security claims.
2. Read all instruction/function signatures to identify operations.
3. For each operation, identify what properties must hold.
4. Categorize using Sections A-G above. Add protocol-specific categories
   as needed.

### Phase 2: Evidence Mapping (2-4 hours)

1. Search test files for proof/test names related to each property.
2. Fill the verification matrix (Section 2).
3. Classify evidence strength for each property.
4. Flag any property with no evidence as **UNVERIFIED**.

### Phase 3: Gap Analysis (1-2 hours)

1. List all UNVERIFIED properties — these are finding candidates.
2. For WEAK evidence, assess if the weakness matters for the property.
3. Check for "missing column" — accept-only proofs without reject proofs.
4. Check for properties the team hasn't considered (using the categories
   in Section 1 as a checklist).

### Phase 4: Targeted Verification (remaining time)

1. Prioritize gaps by criticality.
2. For each gap, attempt to construct a concrete attack / exploit scenario.
3. If a scenario works → finding.
4. If a scenario doesn't work but no proof exists → informational note.

---

## Section 5: Property Statement Style Guide

Good property statements are:

- **Precise**: "Owner mismatch returns `Err(Unauthorized)`" not "checks owner"
- **Falsifiable**: Can be tested — if false, a concrete counterexample exists
- **Two-sided**: Both positive and negative cases stated
- **Domain-scoped**: "For all `u64` nonce values" or "For `scale in [0, 64]`"

### Examples

| Bad | Good |
|-----|------|
| "Checks admin" | "Admin ops require `admin == signer`; returns `Err(Unauthorized)` on mismatch" |
| "Handles overflow" | "`i128::MIN.unsigned_abs()` returns `2^127` without panic" |
| "Nonce works" | "Nonce is unchanged on rejection and advances by exactly 1 on success, wrapping at `u64::MAX`" |
| "Funds are safe" | "Cannot withdraw insurance while any account has open positions; returns `Err(OpenPositions)`" |
