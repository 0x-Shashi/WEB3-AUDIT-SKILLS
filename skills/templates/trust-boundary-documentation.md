---
id: trust-boundary-documentation
title: "Trust Boundary Documentation Template"
category: templates
tier: methodology
audience: [auditors, protocol-teams]
origin: methodology-extraction
version: 1.0.0
---

# Trust Boundary Documentation Template

## Purpose

Every multi-component protocol has trust boundaries — the lines where one
component assumes another behaves correctly. Auditors need to identify these
boundaries, understand what each layer trusts, and verify that trust
assumptions are enforced. This template provides the structure for that
analysis.

The methodology extracts *how* to document layered architectures where an
inner engine handles accounting, a wrapper handles validation, and external
components (matchers, oracles, keepers) are treated as adversarial.

---

## How to Use This Template

1. **Draw the layer diagram** — identify every component and its trust level.
2. **For each boundary**, document what crosses it and what validation exists.
3. **For each component**, document what it is trusted to do and what it is
   treated as adversarial for.
4. **Map verifications to boundaries** — which tests/proofs cover each
   crossing?

---

## Section 1: Architecture Layers

### Protocol: `[PROTOCOL_NAME]`

List components from most-trusted (inner) to least-trusted (outer):

| Layer | Component | Trust Level | Responsibility |
|-------|-----------|-------------|---------------|
| 0 (Core) | `[e.g., RiskEngine]` | Fully trusted | Pure accounting, state transitions |
| 1 (Wrapper) | `[e.g., Program/Contract]` | Trusted for validation | Account validation, authorization, binding |
| 2 (External) | `[e.g., Matcher/Oracle]` | **Adversarial** | LP-scoped execution, price feeds |
| 3 (User) | `[e.g., User wallet]` | **Adversarial** | Trade requests, deposits, withdrawals |

### Layer Diagram

```
┌─────────────────────────────────────────────────┐
│                                                 │
│   Layer 0: Core Engine (Fully Trusted)          │
│   ┌─────────────────────────────────────┐       │
│   │ Pure accounting logic               │       │
│   │ No I/O, no external calls           │       │
│   │ Verified by: [unit tests / proofs]  │       │
│   └─────────────────────────────────────┘       │
│                                                 │
│   Layer 1: Wrapper / Program (Validation)       │
│   ┌─────────────────────────────────────┐       │
│   │ Account validation                  │       │
│   │ Signer enforcement                  │       │
│   │ CPI binding / identity checks       │       │
│   │ Verified by: [Kani proofs / tests]  │       │
│   └─────────────────────────────────────┘       │
│                                                 │
├─────── TRUST BOUNDARY ──────────────────────────┤
│                                                 │
│   Layer 2: External Components (Adversarial)    │
│   ┌───────────┐ ┌───────────┐ ┌───────────┐    │
│   │ Matcher   │ │ Oracle    │ │ Keeper    │    │
│   │ (CPI)     │ │ (price)   │ │ (crank)   │    │
│   └───────────┘ └───────────┘ └───────────┘    │
│                                                 │
│   Layer 3: Users (Adversarial)                  │
│   ┌───────────┐ ┌───────────┐                   │
│   │ Traders   │ │ LPs       │                   │
│   └───────────┘ └───────────┘                   │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## Section 2: Trust Boundary Crossings

For each boundary crossing, document what data flows across and what
validation exists.

### Crossing: `[Component A]` → `[Component B]`

| Aspect | Detail |
|--------|--------|
| **Direction** | A calls B / B returns to A / bidirectional |
| **Data flowing** | What data crosses the boundary |
| **Trust assumption** | What A assumes about B's behavior |
| **Validation at boundary** | What checks exist before/after crossing |
| **Failure mode** | What happens if B violates the assumption |
| **Test coverage** | Named tests/proofs verifying this crossing |

### Crossing Inventory

| # | From | To | Data | Validation | Tests |
|---|------|----|------|------------|-------|
| 1 | User | Program | Instruction data | Signer check, account validation | `test_*_auth` |
| 2 | Program | Engine | Parsed instruction | Type safety (internal API) | Unit tests |
| 3 | Program | Matcher (CPI) | Trade request | Identity binding, shape validation | `kani_*_identity`, `kani_*_shape` |
| 4 | Matcher | Program (return) | Execution result | ABI validation (all fields) | `kani_matcher_rejects_*` |
| 5 | Oracle | Program | Price feed | Staleness, confidence filter | `test_oracle_*` |
| 6 | Keeper | Program | Crank instruction | Permissionless (or owner-gated) | `test_crank_*` |

---

## Section 3: Per-Component Trust Analysis

### Component: `[COMPONENT_NAME]`

#### What This Component is Trusted For

| Trust | Justification |
|-------|--------------|
| `[e.g., Correct accounting]` | `[e.g., Pure logic, no external I/O]` |
| `[e.g., Maintaining state invariants]` | `[e.g., Verified by Kani proofs]` |

#### What This Component is NOT Trusted For

| Distrust | Enforcement |
|----------|------------|
| `[e.g., Honest execution]` | `[e.g., ABI validation on return data]` |
| `[e.g., Correct pricing]` | `[e.g., Oracle staleness/confidence filters]` |

#### Attack Surface

| Vector | Description | Mitigation |
|--------|-------------|------------|
| `[e.g., Malicious return data]` | Matcher returns crafted ABI | All-field ABI validation |
| `[e.g., Identity spoofing]` | Wrong matcher program invoked | Identity binding check |
| `[e.g., Stale data]` | Oracle returns outdated price | Staleness filter |

---

## Section 4: CPI / External Call Security Model

> For protocols that make cross-program invocations (Solana CPI) or external
> calls (Solidity delegatecall, staticcall):

### Non-Negotiable Enforcements at Call Boundary

| # | Enforcement | Description | What Fails if Missing |
|---|------------|-------------|---------------------|
| 1 | **Identity binding** | Called program must match registered program | Attacker substitutes malicious program |
| 2 | **Context binding** | Context/state account must match registration | Attacker uses different state |
| 3 | **Shape validation** | Called program is executable, context is not | Type confusion attacks |
| 4 | **Owner validation** | Context account owned by expected program | Cross-program impersonation |
| 5 | **Return data validation** | All fields of return data validated | Malicious return values |
| 6 | **Size constraints** | Returned size ≤ requested size | Overflow/inflated execution |
| 7 | **Sign constraints** | Returned sign matches request direction | Long/short confusion |

### Call Flow Diagram

```
Caller Program                    External Program
─────────────────                 ─────────────────
1. Validate identity ──────┐
2. Validate shape    ──────┤
3. Validate context  ──────┤
4. Build CPI call    ──────┼──→  Execute logic
                           │     Return data  ──→  5. Validate ABI
                           │                       6. Validate sizes
                           │                       7. Validate signs
                           │                       8. Use exec_size
                           │                          (not requested)
```

---

## Section 5: Account Model Security

> For account-based chains (Solana, SUI, Aptos):

### Account Type Inventory

| Account Type | Owner | Mutability | PDA? | Seed Derivation |
|-------------|-------|------------|------|-----------------|
| `[e.g., Market Slab]` | Program | Writable | No | N/A |
| `[e.g., Vault]` | Token Program | Writable | No | N/A |
| `[e.g., Vault Authority]` | System | N/A | Yes | `["vault", slab_key]` |
| `[e.g., LP Context]` | Matcher Program | Writable | No | N/A |

### Account Validation Checklist

For each account passed to an instruction:

- [ ] **Owner check** — is the account owned by the expected program?
- [ ] **Signer check** — if the account must sign, is signer verified?
- [ ] **Writable check** — is the account marked writable when needed?
- [ ] **Size check** — is the account data large enough?
- [ ] **PDA derivation** — if PDA, are seeds validated?
- [ ] **Executable check** — for program accounts, is it executable?
- [ ] **Non-executable check** — for data accounts, is it NOT executable?
- [ ] **Initialization check** — is the account properly initialized?
- [ ] **Rent exemption** — does the account have sufficient lamports?

---

## Section 6: Risk-Reduction Gating Pattern

> Some protocols implement automatic protection mechanisms that activate
> under stress conditions.

### Gate Specification

| Parameter | Description |
|-----------|-------------|
| **Trigger condition** | `[e.g., vault balance ≤ risk threshold]` |
| **Gate behavior** | `[e.g., block risk-increasing trades]` |
| **Permitted actions** | `[e.g., risk-reducing trades, withdrawals]` |
| **Deactivation** | `[e.g., automatic when balance recovers]` |
| **Manual override** | `[e.g., admin can set threshold to 0]` |

### Gate Verification

| Property | Test/Proof |
|----------|-----------|
| Gate inactive when threshold = 0 | `[test_name]` |
| Gate inactive when balance > threshold | `[test_name]` |
| Risk-increasing rejected when gate active | `[test_name]` |
| Risk-reducing allowed when gate active | `[test_name]` |

---

## Section 7: Audit Application

### For Auditors Reviewing a Protocol's Trust Model

1. **Draw the layer diagram** — identify all components and their trust
   levels. If the team hasn't documented this, they may not have thought
   it through.

2. **List every boundary crossing** — what data flows between components?
   Each crossing is a potential attack surface.

3. **For each crossing, ask**:
   - What validation exists at this boundary?
   - What happens if the validation is missing or bypassable?
   - Is there a test/proof covering this validation?

4. **Check for "trust confusion"**:
   - Is a component trusted for more than it should be?
   - Is an adversarial component's output used without validation?
   - Is internal data exposed at a boundary without sanitization?

5. **Verify CPI/external call security** (if applicable):
   - Identity binding: cannot call wrong program
   - Shape validation: cannot pass wrong account types
   - Return validation: cannot accept malformed return data
   - Size constraints: returned sizes bounded by request

6. **Check account model** (for account-based chains):
   - Every account validated for owner, signer, size, PDA
   - No "owned by anyone" accounts used for sensitive operations

### Common Trust Model Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| Missing identity binding | Critical | CPI target not validated against registration |
| No return data validation | Critical | External call return used without ABI checks |
| Incomplete account validation | High | Missing owner/signer/size checks |
| Trust confusion | High | Adversarial component output used as trusted |
| Missing PDA verification | High | Derived address not validated against expected seeds |
| No staleness check on oracle | Medium | Price data may be arbitrarily old |
| Undocumented trust assumptions | Medium | Team cannot articulate trust boundaries |
