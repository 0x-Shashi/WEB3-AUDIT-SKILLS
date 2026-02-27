---
id: METH-AUDIT-PLAN-EXECUTION
title: Structured Audit Plan Execution
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - audit-planning
  - task-granularity
  - batch-execution
  - review-checkpoints
  - coverage-tracking
  - audit-workflow
last_updated: 2026-02-27
description: >-
  Use when executing a multi-contract audit — breaks scope into bite-sized
  tasks with verification checkpoints between batches. Different from
  audit-session-management (which covers session files and state tracking)
  — this focuses on the EXECUTION plan: task decomposition, ordering,
  batch size, and checkpoint verification.
---

# Structured Audit Plan Execution

## Overview

Large audits fail when the plan is "read everything, find everything."
Structured execution decomposes the audit into small, verifiable tasks
with defined completion criteria. Each task has one objective, takes
bounded time, and produces a checkable output.

**Core principle**: If a task takes more than 30 minutes without a
concrete finding or "confirmed safe" conclusion, the task is too large.
Split it.

### Execution Model

```
SCOPE DECOMPOSITION
    │
    ├── Phase 1: Architecture Review (1-2 hours)
    │   └── Produce: Threat model, attack surface map
    │
    ├── Phase 2: Per-Contract Deep Dive (bulk of audit)
    │   ├── Batch A: [Contract-1, Contract-2] + checkpoint
    │   ├── Batch B: [Contract-3, Contract-4] + checkpoint
    │   └── Batch C: [Contract-5, Contract-6] + checkpoint
    │
    ├── Phase 3: Cross-Contract Analysis (1-2 hours)
    │   └── Produce: Integration findings, attack chains
    │
    └── Phase 4: Report & Verification (1-2 hours)
        └── Produce: Final report with verified findings
```

## Task Decomposition Rules

### Rule 1: One Function, One Task

Do NOT create tasks like "audit Vault.sol". Instead:

```yaml
# BAD — too broad
- task: "Review Vault.sol"
  estimate: "4 hours"

# GOOD — granular, checkable
- task: "Vault.deposit(): access control + input validation"
  estimate: "15 min"
  output: "finding or SAFE with reasoning"

- task: "Vault.withdraw(): reentrancy + balance accounting"
  estimate: "20 min"
  output: "finding or SAFE with reasoning"

- task: "Vault.liquidate(): oracle dependency + incentive alignment"
  estimate: "25 min"
  output: "finding or SAFE with reasoning"
```

### Rule 2: Maximum 2 Concerns Per Task

Each task checks at most 2 security properties:

| Task | Concern 1 | Concern 2 |
|------|-----------|-----------|
| `deposit()` | Access control | Input validation |
| `withdraw()` | Reentrancy | Balance accounting |
| `liquidate()` | Oracle trust | Incentive alignment |
| `setFee()` | Authorization | Range validation |

Why 2? Human attention for code review degrades after checking
more than 2 properties simultaneously. Agents show the same pattern.

### Rule 3: Every Task Has a Completion Output

A task is not "done" until it produces one of:

```
FINDING:  {severity} — {title} — {location} — {1-line description}
SAFE:     {function} — checked {property1}, {property2} — no issues
UNCLEAR:  {function} — {what's unclear} — needs {more context/second opinion}
```

Never close a task with "looked at it, seems fine." Justify WHY it's safe.

### Rule 4: Time-Box Then Escalate

| Time Spent | Action |
|-----------|--------|
| 0-15 min | Normal analysis |
| 15-30 min | Should have a conclusion soon |
| 30-45 min | Split the task — it's too complex |
| 45+ min | STOP — escalate to architecture review |

If a single function takes >30 minutes, it's an indicator of:
- Missing context (need to read dependencies first)
- Complex state interactions (need state machine mapping)
- Architectural issue (finding is bigger than one function)

## Phase 1: Architecture Review

Before touching individual functions, map the system:

### Task List Template

```yaml
architecture_review:
  - task: "Map contract inheritance hierarchy"
    output: "Inheritance diagram"
    time: "15 min"
  
  - task: "Identify all external entry points"
    output: "List of external/public functions with callers"
    time: "20 min"
  
  - task: "Map token flows (deposit → internal → withdraw)"
    output: "Token flow diagram"
    time: "20 min"
  
  - task: "Identify trust boundaries (admin, user, external)"
    output: "Trust boundary map"
    time: "15 min"
  
  - task: "List all external dependencies (oracles, other protocols)"
    output: "Dependency list with trust assumptions"
    time: "10 min"
  
  - task: "Review deployment/upgrade mechanism"
    output: "Upgrade risk assessment"
    time: "15 min"
```

**Architecture checkpoint**:
- All entry points mapped?
- Trust boundaries identified?
- Token flow understood?
- If NO to any → don't proceed to Phase 2

## Phase 2: Per-Contract Deep Dive

### Batch Construction

Group contracts by coupling — tightly coupled contracts go in the same
batch so cross-contract flows are analyzed together:

```yaml
batch_A:
  contracts: ["Vault.sol", "VaultStorage.sol"]
  reason: "Vault + its storage are tightly coupled"
  tasks:
    - "Vault.deposit(): access + validation"
    - "Vault.withdraw(): reentrancy + accounting"
    - "Vault.liquidate(): oracle + incentives"
    - "VaultStorage: slot collision + visibility"
  checkpoint: "All Vault entry points reviewed"

batch_B:
  contracts: ["Oracle.sol", "PriceAggregator.sol"]
  reason: "Oracle system is self-contained"
  tasks:
    - "Oracle.getPrice(): freshness + manipulation"
    - "Oracle.updatePrice(): access + validation"
    - "PriceAggregator: aggregation logic + edge cases"
  checkpoint: "Oracle trust model verified"

batch_C:
  contracts: ["Governor.sol", "Timelock.sol"]
  reason: "Governance + execution are coupled"
  tasks:
    - "Governor.propose(): threshold + validation"
    - "Governor.vote(): weight + timing"
    - "Governor.execute(): timelock interaction"
    - "Timelock.execute(): delay enforcement + admin"
  checkpoint: "Governance lifecycle verified"
```

### Batch Checkpoint Template

After completing each batch, verify before moving to the next:

```yaml
checkpoint_batch_A:
  questions:
    - "All external functions reviewed?"           # YES/NO
    - "All findings have evidence?"                # YES/NO  
    - "Coverage gaps identified?"                  # List or NONE
    - "Cross-contract findings noted for Phase 3?" # List or NONE
    - "Any UNCLEAR items to revisit?"              # List or NONE
  
  gate: "All YES + gaps addressed → proceed to Batch B"
```

## Phase 3: Cross-Contract Analysis

After all individual contracts reviewed, check cross-cutting concerns:

```yaml
cross_contract_tasks:
  - task: "Trace complete deposit→withdraw lifecycle"
    check: "No fund loss at any state transition"
    time: "30 min"
  
  - task: "Trace oracle price → liquidation decision path"
    check: "No manipulation window between price read and action"
    time: "20 min"
  
  - task: "Check governance proposal → execution path"
    check: "No bypass of timelock delay"
    time: "20 min"
  
  - task: "Verify upgrade path doesn't break storage layout"
    check: "Storage slots preserved across upgrade"
    time: "20 min"
  
  - task: "Check reentrancy across contract boundaries"
    check: "No cross-contract reentrancy via callbacks"
    time: "20 min"
```

## Phase 4: Report and Verification

### Finding Verification Checklist

Before including a finding in the report:

```yaml
for_each_finding:
  - "Root cause identified and specific?"          # Not "bad coding"
  - "Impact quantified or bounded?"                # "$X at risk" or "N users affected"
  - "Exploit path has concrete steps?"             # Not theoretical
  - "PoC written (for Critical/High)?"             # test_VULN_ test exists
  - "Fix recommendation is actionable?"            # Not "add validation"
  - "Fix doesn't introduce new issues?"            # Verified via green test
  - "Severity justified with evidence?"            # See verification-discipline.md
```

## Execution Tracking

### Progress Matrix

Track coverage with a function-level matrix:

```
╔═══════════════╦═══════╦════════╦═══════╦══════════╗
║ Function      ║ Access║ Math   ║ State ║ External ║
╠═══════════════╬═══════╬════════╬═══════╬══════════╣
║ deposit()     ║  ✅   ║  ✅   ║  ✅  ║   ✅    ║
║ withdraw()    ║  ✅   ║  ✅   ║  🔍  ║   ✅    ║
║ liquidate()   ║  ✅   ║  ⚠️   ║  ✅  ║   ✅    ║
║ setFee()      ║  🔍   ║  ✅   ║  —   ║   —     ║
║ upgrade()     ║  ✅   ║  —    ║  ✅  ║   —     ║
╚═══════════════╩═══════╩════════╩═══════╩══════════╝

Legend: ✅ Reviewed (safe) | ⚠️ Finding | 🔍 In Progress | — N/A
```

### Velocity Metrics

Track execution speed to predict completion:

```yaml
velocity:
  tasks_per_hour: 4-6   # Target: 10-15 min per task
  findings_per_100_loc: 1-3  # Typical for mature code
  batch_checkpoint_time: 15 min  # Should be quick
  
  warning_signs:
    - "Velocity < 2 tasks/hour → tasks too complex, split"
    - "0 findings after 500 LOC → verify audit depth"
    - "Checkpoint takes >30 min → too many unclear items"
```

## Priority Ordering

Not all tasks are equal. Order by risk:

```yaml
priority_tiers:
  P0_first:
    - "Functions handling ETH/token transfers"
    - "Functions with external calls"
    - "Admin/upgrade functions"
    - "Functions using oracle data"
  
  P1_second:
    - "State-changing functions"
    - "Functions with complex math"
    - "Functions with access control"
  
  P2_third:
    - "View/pure functions"
    - "Internal helper functions"
    - "Event emission"
  
  P3_if_time:
    - "Test coverage review"
    - "Gas optimization patterns"
    - "Code quality / best practices"
```

## Common Rationalizations

| Excuse | Reality |
|--------|---------|
| "I'll plan as I go" | You'll miss functions and waste time |
| "No need for checkpoints" | You'll lose track of coverage |
| "Tasks are too granular" | Granular tasks catch more bugs |
| "I know this pattern, I can skip" | Familiarity breeds oversight |
| "I'll write findings at the end" | You'll forget details. Document immediately. |
| "One quick pass is enough" | Phase 3 catches what Phase 2 misses |

## Anti-Patterns

| Anti-Pattern | Why It Fails |
|-------------|-------------|
| Audit entire contract as one task | Attention degrades, coverage gaps |
| Skip architecture review | Missing context causes false positives |
| No checkpoint between batches | Errors compound silently |
| Phase 3 skipped (no cross-contract) | Misses integration vulnerabilities |
| Tasks without completion criteria | "Done" has no meaning |
| All tasks same priority | Critical paths audited last |

## Cross-References

- [audit-session-management.md](audit-session-management.md) — Session state (not execution plan)
- [parallel-audit-agents.md](parallel-audit-agents.md) — Multi-agent dispatch strategy
- [verification-discipline.md](verification-discipline.md) — Evidence requirements
- [systematic-root-cause.md](systematic-root-cause.md) — Root cause analysis
- [tdd-security-testing.md](tdd-security-testing.md) — Test-driven PoC cycle

## Sources

- Superpowers: writing-plans + executing-plans skills (adapted for security audit)
- OpenZeppelin: Structured audit methodology
- Consensys Diligence: Audit workflow documentation
