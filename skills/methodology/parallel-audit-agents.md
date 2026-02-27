---
id: METH-PARALLEL-AUDIT-AGENTS
title: Parallel Audit Agent Dispatch
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - multi-agent
  - parallel-execution
  - audit-workflow
  - scope-splitting
  - agent-dispatch
  - finding-integration
  - coverage-optimization
last_updated: 2026-02-27
description: >-
  Use when auditing large codebases (>2000 LOC) or complex multi-module
  protocols — dispatches focused sub-agents for different security domains
  (access control, math, oracle, governance) in parallel, then integrates
  findings. Different from ai-assisted-auditing (which covers prompt
  engineering) — this focuses on DISPATCH strategy, scope partitioning,
  and finding deduplication across agents.
---

# Parallel Audit Agent Dispatch

## Overview

A single-pass audit of a large protocol hits diminishing returns — attention
degrades after ~800 lines of sequential analysis. Parallel agent dispatch
splits the audit scope by security domain and contract, runs focused agents
on each partition, then merges and deduplicates findings.

**Core principle**: Each agent gets ONE focused domain. Broad agents find
less than narrow agents run in parallel.

### Dispatch Model

```
AUDIT SCOPE
    │
    ├── Agent-1: Access Control Domain
    │   └── Focus: onlyOwner, roles, permissions, proxy admin
    │
    ├── Agent-2: Math / Precision Domain
    │   └── Focus: rounding, overflow, share calculation, fees
    │
    ├── Agent-3: External Integration Domain
    │   └── Focus: oracle calls, cross-contract, flash loans
    │
    ├── Agent-4: State Machine Domain
    │   └── Focus: lifecycle, ordering, reentrancy, timing
    │
    └── Agent-5: Economic / Game Theory Domain
        └── Focus: incentives, MEV, frontrunning, sandwich
            │
            ▼
    INTEGRATION: Merge → Deduplicate → Cross-reference → Rank
```

## When to Use

**Always use for**:
- Protocols with >5 contracts
- Codebases >2000 lines of logic
- Multi-module systems (lending + swapping, staking + governance)
- Time-constrained audits needing parallel throughput

**Do NOT use for**:
- Single-contract audits (<500 LOC)
- Simple token contracts
- Already-audited codebases (differential review is better)

## Domain Definitions

### Domain 1: Access Control

**Focus**: Who can call what, under what conditions.

```
SCOPE:
- All external/public functions
- Role-based access (onlyOwner, hasRole, modifiers)
- Proxy admin vs implementation admin confusion
- Initializer protection (initializer, reinitializer)
- Timelock bypasses
- Multi-sig threshold manipulation

PROMPT TEMPLATE:
"Analyze ONLY access control in [contracts]. For each external function,
verify: (1) who can call it, (2) what authorization is required,
(3) whether that authorization can be bypassed. Ignore math, oracles,
and economic logic. Report ONLY access control findings."
```

### Domain 2: Math and Precision

**Focus**: Numerical correctness, rounding, overflow.

```
SCOPE:
- Division before multiplication
- Rounding direction (favor protocol vs user)
- Share/token calculation precision loss
- Fee calculation correctness
- Decimal handling across tokens (6 vs 8 vs 18)
- Unchecked blocks
- Type casting truncation (uint256 → uint128)

PROMPT TEMPLATE:
"Analyze ONLY mathematical operations in [contracts]. For each
calculation, verify: (1) rounding direction, (2) precision loss
potential, (3) overflow/underflow possibility, (4) decimal handling.
Ignore access control and state transitions. Report ONLY math findings."
```

### Domain 3: External Integration

**Focus**: Oracle dependencies, cross-contract calls, composability.

```
SCOPE:
- Oracle price freshness (stale price)
- Oracle manipulation (spot price vs TWAP)
- Flash loan attack surfaces
- Return value handling (silent failures)
- Callback reentrancy from external calls
- Token hooks (ERC-777 receive, ERC-1155 batch)
- Approval race conditions

PROMPT TEMPLATE:
"Analyze ONLY external interactions in [contracts]. For each external
call, verify: (1) return value checked, (2) reentrancy protection,
(3) manipulation resistance, (4) failure handling. Ignore internal
math and access control. Report ONLY integration findings."
```

### Domain 4: State Machine and Ordering

**Focus**: State transitions, lifecycle correctness, timing.

```
SCOPE:
- State transition completeness (all edges defined)
- Reentrancy in state transitions
- Block.timestamp manipulation windows
- Transaction ordering dependencies (frontrunning)
- Initialization race conditions
- Pause/unpause edge cases
- Cross-function state interference

PROMPT TEMPLATE:
"Analyze ONLY state transitions in [contracts]. Map every state change
and verify: (1) all transitions are valid, (2) no states are unreachable,
(3) ordering dependencies are enforced, (4) concurrent access is safe.
Ignore math precision and external oracles. Report ONLY state findings."
```

### Domain 5: Economic and Game Theory

**Focus**: Incentive alignment, MEV, value extraction.

```
SCOPE:
- MEV extraction opportunities
- Sandwich attack surfaces
- Liquidation incentive alignment
- Fee extraction / rent-seeking
- Governance manipulation (vote buying, flash governance)
- Protocol-draining economic attacks
- Interest rate manipulation
- Collateral ratio gaming

PROMPT TEMPLATE:
"Analyze ONLY economic incentives in [contracts]. For each economic
mechanism, verify: (1) participants can't extract unfair value,
(2) MEV is minimized or returned, (3) incentives align under adversarial
conditions, (4) no griefing vectors. Ignore code-level bugs and focus
on economic design. Report ONLY economic findings."
```

## Dispatch Strategy

### Step 1: Scope Partitioning

Partition by contract AND domain:

```
Given: Vault.sol, Oracle.sol, Governor.sol, Token.sol

Agent dispatches:
┌──────────────┬─────────┬────────┬──────────┬────────┐
│              │ Vault   │ Oracle │ Governor │ Token  │
├──────────────┼─────────┼────────┼──────────┼────────┤
│ Access Ctrl  │ Agent-1 │ Agent-1│ Agent-1  │ Agent-1│
│ Math         │ Agent-2 │ Agent-2│ —        │ Agent-2│
│ External     │ Agent-3 │ —      │ Agent-3  │ —      │
│ State        │ Agent-4 │ —      │ Agent-4  │ —      │
│ Economic     │ Agent-5 │ Agent-5│ Agent-5  │ —      │
└──────────────┴─────────┴────────┴──────────┴────────┘
```

### Step 2: Context Injection

Each agent receives:
1. **Target contracts** — The specific files to analyze
2. **Domain focus** — Single domain from above
3. **Dependency context** — Interfaces and types from related contracts
4. **Known patterns** — Common vulnerability patterns for this domain

**Critical rule**: Include dependency interfaces but instruct agents to
report findings ONLY for target contracts, not dependencies.

```
CONTEXT PACKAGE for Agent-2 (Math):
├── Target: Vault.sol (full source)
├── Interfaces: IOracle.sol, IERC20.sol
├── Types: DataTypes.sol (structs only)
├── Known patterns: rounding-direction.md, precision-loss.md
└── Instruction: "Report findings ONLY in Vault.sol math"
```

### Step 3: Parallel Execution

Launch all agents simultaneously. Each runs independently with its
focused scope:

```
TIME ──────────────────────────────────────────►
Agent-1 ████████████████░░░░░░░░  (Access Control done)
Agent-2 ████████████████████░░░░  (Math done)
Agent-3 ██████████████████████░░  (External done)
Agent-4 ████████████████░░░░░░░░  (State done)
Agent-5 ████████████████████████  (Economic done)
         │                      │
         └── All parallel ──────┘
```

### Step 4: Finding Integration

Merge all agent outputs using structured integration:

```yaml
integration_process:
  1_collect:
    - Gather all findings from all agents
    - Normalize to common format (ID, title, severity, location, description)
  
  2_deduplicate:
    - Group findings by affected function/line
    - Merge findings pointing to same root cause
    - Keep the most detailed version
  
  3_cross_reference:
    - Check if Agent-1 finding + Agent-3 finding combine to worse impact
    - Example: Missing access control (Agent-1) + external call (Agent-3) 
      = unauthorized fund drain (combined Critical)
  
  4_rank:
    - Re-rank all findings with combined context
    - Escalate findings that agents individually rated Medium
      but combined impact is Critical
  
  5_gap_check:
    - Identify uncovered areas (functions no agent examined)
    - Dispatch targeted follow-up agents for gaps
```

## Cross-Agent Finding Escalation

Single-domain agents may underrate findings that span multiple domains.
Integration must catch these:

| Agent-1 Finding | Agent-2 Finding | Combined Impact |
|-----------------|-----------------|-----------------|
| Missing role check on `setFee()` | Fee calculation has 100x multiplier | Unauthorized user sets fee to drain protocol |
| Proxy admin can upgrade | Initializer not protected | Admin upgrades to steal all funds |
| Anyone can call `liquidate()` | Price oracle uses spot price | Flash loan + liquidation for immediate profit |
| Governor quorum is 1% | No vote-lock period | Flash governance attack drains treasury |

**Escalation rule**: When findings from different agents touch the same
contract state, check if they combine to form a higher-severity attack chain.

## Agent Output Format

Each agent must return findings in this structure:

```yaml
agent_id: "access-control-agent"
scope: ["Vault.sol", "Governor.sol"]
domain: "access_control"
findings:
  - id: "AC-001"
    title: "Missing onlyOwner on setFee()"
    severity: "Medium"
    location: "Vault.sol:L142"
    root_cause: "No access modifier on state-changing function"
    impact: "Any user can modify protocol fees"
    exploit_path: |
      1. Attacker calls setFee(MAX_FEE)
      2. All subsequent operations pay inflated fee
      3. If attacker is fee recipient, profits directly
    recommendation: "Add onlyOwner modifier to setFee()"
    confidence: 0.95
    cross_domain_links: ["math-agent may find fee calculation issues"]
coverage:
  functions_analyzed: 24
  functions_with_findings: 3
  functions_clear: 21
```

## Conflict Resolution

When agents disagree about the same code:

| Conflict Type | Resolution |
|---------------|------------|
| Different severity for same finding | Take the HIGHER severity, verify |
| One agent says safe, another says vulnerable | Re-analyze with both contexts |
| Overlapping findings with different root causes | Report as separate findings |
| Agent says "out of scope" for cross-domain issue | Route to correct domain agent |

## Anti-Patterns

| Anti-Pattern | Why It Fails |
|-------------|-------------|
| One agent does everything | Attention degrades after ~800 LOC |
| Agents share findings during execution | Creates bias, not independent |
| No integration step | Misses cross-domain escalations |
| No gap analysis | Some functions are never examined |
| Domain boundaries are fuzzy | Agents duplicate work or skip areas |
| Agent runs without dependency context | Can't trace cross-contract flows |
| Copy-paste same prompt for all agents | Domain focus is the whole point |

## Scaling Guide

| Protocol Size | Contracts | Recommended Agents |
|---------------|-----------|-------------------|
| Small | 1-3 | 2-3 (merge domains) |
| Medium | 4-10 | 5 (standard domains) |
| Large | 11-25 | 5-8 (add chain-specific) |
| Massive | 25+ | 8-12 (split by module + domain) |

For chain-specific additions:
- **Solana**: Add "PDA/CPI Security Agent" (account validation, CPI privilege)
- **Move**: Add "Resource Safety Agent" (ownership, borrow, acquires)
- **CosmWasm**: Add "Message Routing Agent" (Execute, Query, Migrate)

## Cross-References

- [ai-assisted-auditing.md](ai-assisted-auditing.md) — Prompt engineering (not dispatch)
- [verification-discipline.md](verification-discipline.md) — Evidence requirements per agent
- [systematic-root-cause.md](systematic-root-cause.md) — Root cause methodology
- [audit-plan-execution.md](audit-plan-execution.md) — Execution workflow for plans
- [audit-session-management.md](audit-session-management.md) — Session tracking

## Sources

- Superpowers: dispatching-parallel-agents skill (adapted for security audit)
- Trail of Bits: Multi-reviewer audit methodology
- OpenAI: Agent orchestration patterns for specialized tasks
