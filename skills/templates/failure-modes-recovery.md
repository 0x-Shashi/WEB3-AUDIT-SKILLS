---
id: failure-modes-recovery
title: "Failure Modes & Recovery Documentation Template"
category: templates
tier: methodology
audience: [auditors, protocol-teams, operators]
origin: methodology-extraction
version: 1.0.0
---

# Failure Modes & Recovery Documentation Template

## Purpose

Every protocol has failure modes. The difference between a well-engineered
protocol and a disaster waiting to happen is whether those failure modes are
**documented**, **categorized as recoverable vs. permanent**, and have
**concrete recovery procedures**.

This template captures the methodology of systematically documenting:
- What can fail and why
- Whether it's a safety rejection (expected) or a real problem
- How to recover (or why recovery is intentionally impossible)
- What operators should monitor

---

## How to Use This Template

1. **Enumerate failure modes** by category (Section 1).
2. **Classify each** as safety rejection vs. actual failure vs. permanent state.
3. **Document recovery procedure** for each recoverable failure.
4. **Build the monitoring checklist** (Section 4).
5. **Test recovery paths** — undocumented recovery that hasn't been tested
   is not recovery.

---

## Section 1: Failure Mode Categories

### Category A: Safety Rejections (Expected — Not Bugs)

> These are rejections enforced by the protocol's security model. They are
> correct behavior, not errors. Operators should understand them but not
> panic.

| # | Rejection | Cause | Expected Behavior | User Impact |
|---|-----------|-------|-------------------|-------------|
| A1 | Identity mismatch | Wrong program/contract called via CPI | Transaction rejected | Trade fails, retry with correct target |
| A2 | Shape validation failure | Malformed account structure | Transaction rejected | Should not occur with correct SDK |
| A3 | PDA mismatch | Wrong derived address provided | Transaction rejected | SDK bug or attack attempt |
| A4 | ABI validation failure | Malformed external return data | Transaction rejected | External integration error |
| A5 | Risk gate active | Protocol under stress, risk-increase blocked | Trade rejected | Wait for conditions to improve |
| A6 | Auth failure | Wrong signer | Transaction rejected | Wallet misconfiguration |
| A7 | `[Add protocol-specific]` | | | |

**Key principle**: Safety rejections should be **hard** — no fallback logic
that weakens the check. If the rejection is bypassed, it's a finding.

### Category B: Oracle Failures

> Oracle failures are recoverable but can cause temporary protocol lockup.

| # | Failure | Cause | Detection | Recovery |
|---|---------|-------|-----------|----------|
| B1 | Stale price | Oracle not updated within max staleness window | `age > max_staleness` | Wait for oracle update |
| B2 | Wide confidence | Price confidence interval too wide | `conf > max_conf_ratio * price` | Wait for market to stabilize |
| B3 | Oracle down | Feed completely unavailable | No price data | Switch oracle source (if supported) |
| B4 | Manipulated price | Flash loan / sandwich attack on oracle | Unusual price deviation | TWAP / median oracle (if supported) |

### Category C: Keeper / Crank Failures

> Keeper failures cause delayed state updates but usually don't cause
> fund loss.

| # | Failure | Cause | Detection | Recovery |
|---|---------|-------|-----------|----------|
| C1 | Keeper offline | Infrastructure failure | Stale funding rates | Restart keeper service |
| C2 | Keeper bottleneck | Too many accounts to process | Partial crank completion | Scale keeper infrastructure |
| C3 | Transaction failures | Network congestion | Failed keeper txns | Retry with higher priority fee |

### Category D: State-Related Failures

> These affect the protocol's ability to process certain operations.

| # | Failure | Cause | Detection | Recovery |
|---|---------|-------|-----------|----------|
| D1 | Market resolved | Admin resolution | State flag | By design — permanent |
| D2 | Admin burned | Admin set to zero address | Admin == zero | By design — permanent, irreversible |
| D3 | Insufficient insurance | Insurance fund depleted | Balance check | `TopUpInsurance` |
| D4 | Account limit reached | Max accounts per market | Account count | Deploy new market |

### Category E: Infrastructure Failures

| # | Failure | Cause | Detection | Recovery |
|---|---------|-------|-----------|----------|
| E1 | RPC unavailable | Network issues | Connection errors | Switch RPC provider |
| E2 | Program upgrade needed | Bug discovered | Off-chain detection | Deploy upgrade (if authority exists) |
| E3 | Chain congestion | Network overload | Transaction timeouts | Wait or increase priority |
| E4 | Account rent | Insufficient lamports | Rent check | Top up account |

---

## Section 2: Recoverability Classification

For each failure mode, classify:

| Classification | Definition | Action |
|---------------|------------|--------|
| **Safety Rejection** | Correct behavior — the protocol is protecting itself | None needed (expected) |
| **Transient** | Will resolve on its own (oracle updates, keeper restarts) | Wait |
| **Recoverable (operator)** | Requires operator action to resolve | Follow recovery procedure |
| **Recoverable (governance)** | Requires admin/governance action | Initiate governance process |
| **Permanent (by design)** | Irreversible state change, intentional | Document and accept |
| **Permanent (bug)** | Irreversible state corruption, unintentional | **Finding — Critical** |

### Failure Recoverability Matrix

| Failure ID | Classification | Recovery Procedure | Time to Recovery |
|------------|---------------|-------------------|-----------------|
| A1-A6 | Safety Rejection | N/A | Immediate (retry correctly) |
| B1 | Transient | Wait for oracle update | Seconds to minutes |
| B2 | Transient | Wait for market stability | Minutes to hours |
| C1 | Recoverable (operator) | Restart keeper | Minutes |
| D1 | Permanent (by design) | N/A | N/A |
| D2 | Permanent (by design) | N/A — "by design impossible" | N/A |
| `[ID]` | | | |

---

## Section 3: Recovery Procedures

> For each recoverable failure, provide a concrete procedure.

### Recovery: `[FAILURE_NAME]`

**Trigger**: `[What condition indicates this failure is occurring]`

**Diagnosis**:
```
1. Check [WHAT]
2. Verify [CONDITION]
3. Confirm [ROOT_CAUSE]
```

**Recovery Steps**:
```
1. [SPECIFIC_ACTION]
2. [SPECIFIC_ACTION]
3. [VERIFY_RESOLUTION]
```

**Verification**: `[How to confirm recovery is complete]`

**Escalation**: `[What to do if recovery fails]`

---

## Section 4: Operational Monitoring Checklist

> What should operators continuously monitor?

### Real-Time Alerts (require immediate attention)

- [ ] **Admin key rotation** — alert on any change
- [ ] **Large parameter changes** — fee, margin, threshold modifications
- [ ] **Oracle staleness** — price age exceeding threshold
- [ ] **Insurance fund level** — dropping below safe threshold
- [ ] **Emergency actions** — market resolution, panic crank, force-close
- [ ] **Unusual fund movements** — large withdrawals, unexpected transfers

### Periodic Checks (hourly / daily)

- [ ] **Keeper health** — crank transactions succeeding
- [ ] **Funding rate convergence** — rates moving toward fair value
- [ ] **Account utilization** — approaching capacity limits
- [ ] **Oracle confidence** — price feeds within acceptable bounds
- [ ] **Program upgrade authority** — unchanged (or intentionally changed)
- [ ] **Vault balance reconciliation** — actual balance matches accounting

### Post-Incident Review

After any failure event, document:

| Field | Description |
|-------|-------------|
| **Timestamp** | When the failure was detected |
| **Failure ID** | Which failure mode from the inventory |
| **Duration** | How long before recovery |
| **Impact** | Users affected, funds at risk, operations blocked |
| **Root cause** | What actually went wrong |
| **Recovery actions** | What was done to resolve |
| **Prevention** | What changes prevent recurrence |

---

## Section 5: Permanent State Transitions

> Special attention needed for one-way state changes that cannot be undone.

### Permanent Transition Inventory

| Transition | Trigger | Who Can Trigger | Reversible? | Impact |
|-----------|---------|----------------|-------------|--------|
| Admin burned | `UpdateAdmin(zero_address)` | Current admin | **No — by design** | All admin ops permanently disabled |
| Market resolved | `ResolveMarket` | Admin | **No** | Trading halted, wind-down begins |
| Market closed | `CloseMarket` | Admin (after empty) | **No** | Market permanently decommissioned |
| `[ADD_OTHERS]` | | | | |

### For Each Permanent Transition, Verify:

- [ ] **Intentionality** — is this transition deliberate, not accidental?
- [ ] **Prerequisite enforcement** — are all prerequisites checked before allowing?
- [ ] **User notification** — are users warned before/during the transition?
- [ ] **Fund safety** — are all user funds accessible before/during/after?
- [ ] **Test coverage** — is there a test proving prerequisites are enforced?
- [ ] **No bypass** — is there no way to trigger the transition without
      meeting prerequisites?

---

## Section 6: Feature Flag Dangers

> Compile-time or runtime flags that change security behavior.

| Flag | Effect When Enabled | Production Safe? | Test Coverage |
|------|-------------------|-----------------|---------------|
| `[flag_name]` | Skips safety check X | **NO — do not deploy** | `test_..._with_flag` |
| `[flag_name]` | Enables debug logging | Yes (no security impact) | N/A |
| `[flag_name]` | Reduces CU but weakens check | **Conditional** — assess risk | `test_..._unsafe_path` |

> **Rule**: Any flag that weakens a security check must be documented with
> "DO NOT ENABLE IN PRODUCTION" in code comments, README, and this document.

---

## Section 7: Auditor Application

### For Auditors Reviewing Failure Handling

1. **Find all error paths** — search for `Err`, `revert`, `require`, `assert`,
   `Error(`, `panic!` in the codebase.
2. **Classify each error** — is it a safety rejection (correct) or an
   unexpected failure (potential issue)?
3. **Check for swallowed errors** — are any error paths caught and ignored?
4. **Check for missing errors** — are there code paths that should fail
   but don't?
5. **Verify permanent transitions** — for each one-way state change:
   - Are prerequisites enforced?
   - Is there a test proving prerequisites work?
   - Can the transition be triggered accidentally?
6. **Verify recovery paths** — for each recoverable failure:
   - Does the documented recovery actually work?
   - Is there a test simulating failure + recovery?
7. **Check feature flags** — search for `#[cfg(feature`, `#[cfg(not(`,
   `if DEBUG`, conditional compilation that affects security checks.

### Common Failure-Mode Findings

| Finding | Severity | Pattern |
|---------|----------|---------|
| Permanent transition without prerequisites | Critical | `ResolveMarket` callable without checking for open positions |
| Missing error on invalid state | High | Operation succeeds when it should fail |
| Swallowed error in CPI return | Critical | External call error caught and treated as success |
| No monitoring for critical events | Medium | Admin rotation emits no event/log |
| Feature flag weakens production security | Critical | Debug flag left enabled in deployment |
| Recovery procedure untested | Medium | Documentation says "restart keeper" but no test simulates it |
| Permanent burn without confirmation | High | Single-step burn with no two-phase or timelock |
