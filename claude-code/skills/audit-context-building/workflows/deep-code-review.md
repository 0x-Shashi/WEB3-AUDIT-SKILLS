# Deep Code Review Workflow

A systematic workflow for performing ultra-granular code review with full context building.

---

## Overview

This workflow guides you through a complete deep code review, building comprehensive context before identifying issues. It emphasizes understanding over speed.

**Duration:** 2-4 hours for small codebase, 1-2 days for large protocol
**Output:** Complete function analyses with invariants, assumptions, and risk assessments

---

## Phase 1: Initial Reconnaissance (30-60 minutes)

### Step 1.1: Scope Definition

```markdown
## Review Scope

**Codebase:** [Protocol Name]
**Files in Scope:** [List or pattern]
**Lines of Code:** [Approximate count]
**Review Type:** [ ] New Audit [ ] Update Review [ ] Specific Feature

**Out of Scope:**
- [Libraries/dependencies]
- [Test files]
- [Specific contracts if any]
```

### Step 1.2: Structural Mapping

Map the codebase structure:

```markdown
## Structural Map

### Contracts
| Contract | LOC | Purpose | Dependencies |
|----------|-----|---------|--------------|
| Main.sol | 500 | Core logic | Lib.sol, Token.sol |
| Token.sol | 200 | Token implementation | OpenZeppelin |

### Inheritance Graph
```
Main
├── Ownable
├── ReentrancyGuard
└── PausableUpgradeable
```

### External Dependencies
- OpenZeppelin v4.9.0
- Chainlink Oracles
- Uniswap V3 Core
```

### Step 1.3: Actor Identification

```markdown
## Actors & Trust Levels

| Actor | Trust Level | Capabilities | Entry Points |
|-------|-------------|--------------|--------------|
| Owner | High | Pause, upgrade, configure | admin functions |
| User | None | Deposit, withdraw, trade | public functions |
| Keeper | Medium | Execute automation | keeper functions |
| Oracle | Medium | Provide price data | callback functions |
```

### Step 1.4: Entry Point Enumeration

List all public/external functions:

```markdown
## Entry Points

### User-Facing
| Function | Contract | Access | Critical |
|----------|----------|--------|----------|
| deposit() | Vault.sol | public | ✅ |
| withdraw() | Vault.sol | public | ✅ |

### Admin-Facing
| Function | Contract | Access | Critical |
|----------|----------|--------|----------|
| setFee() | Vault.sol | onlyOwner | ⚠️ |
| pause() | Vault.sol | onlyOwner | ⚠️ |

### Callback/Internal
| Function | Contract | Access | Critical |
|----------|----------|--------|----------|
| _callback() | Vault.sol | internal | ✅ |
```

---

## Phase 2: Prioritized Analysis (Core Work)

### Step 2.1: Priority Ordering

Order functions by risk/importance:

1. **Critical Path Functions** (handle value, access control)
2. **External Integration Points** (oracles, other protocols)
3. **State Modification Functions** (non-view, non-pure)
4. **View/Pure Functions** (helpers, getters)

### Step 2.2: Function-by-Function Analysis

For each function in priority order:

```markdown
## Function Analysis: [functionName]

[Use the full output template from resources/output-template.md]

### Completion Check
- [ ] Purpose documented (2-3 sentences)
- [ ] All inputs with assumptions (5+)
- [ ] All outputs and effects
- [ ] Block-by-block analysis complete
- [ ] Invariants identified (3+)
- [ ] Risks analyzed
- [ ] Cross-references documented
- [ ] First Principles / 5 Whys / 5 Hows applied
```

### Step 2.3: Cross-Function Synthesis

After analyzing related functions:

```markdown
## Cross-Function Analysis: [Module Name]

### Shared State
| State Variable | Read By | Written By | Invariant |
|----------------|---------|------------|-----------|
| balances | withdraw, getBalance | deposit, withdraw | sum = totalSupply |

### Interaction Patterns
1. deposit() → _updateRewards() → balances
2. withdraw() → _updateRewards() → _transfer()

### Module Invariants
1. [Invariant spanning multiple functions]
2. [Another cross-function invariant]

### Dependency Graph
```
deposit() ──► _updateRewards() ──► _calculateReward()
    │                                    │
    ▼                                    ▼
balances                            rewardRate
```
```

---

## Phase 3: Integration Analysis (1-2 hours)

### Step 3.1: External Call Review

For each external integration:

```markdown
## External Integration: [Target Protocol/Contract]

### Call Sites
| Our Function | Target Function | Purpose |
|--------------|-----------------|---------|
| swap() | UniswapRouter.exactInput() | Execute swap |
| getPrice() | Chainlink.latestRoundData() | Get price |

### Trust Analysis
**Target Trust Level:** [Trusted/Semi-trusted/Untrusted]

**Assumptions About Target:**
1. [Returns valid data]
2. [Won't be malicious]
3. [Available and responsive]

### Failure Modes
| Failure | Likelihood | Impact | Our Handling |
|---------|------------|--------|--------------|
| Reverts | Medium | Medium | Caught, tx fails |
| Returns stale | Low | High | No validation! ⚠️ |
| Returns wrong | Very Low | Critical | No validation! ⚠️ |

### Recommendations
- [ ] Add staleness check for oracle
- [ ] Add sanity bounds for prices
```

### Step 3.2: Value Flow Analysis

```markdown
## Value Flow Map

### Token Flows
```
User ──[tokenA]──► deposit() ──[tokenA]──► Contract
                                              │
                                              ▼
Contract ──[tokenB]──► withdraw() ──[tokenB]──► User
```

### ETH Flows
```
User ──[ETH]──► payable receive() ──[ETH]──► Stored
                                               │
                                               ▼
Stored ──[ETH]──► claimRewards() ──[ETH]──► User
```

### Value Entry Points
1. deposit() - tokens in
2. receive() - ETH in

### Value Exit Points
1. withdraw() - tokens out
2. claimRewards() - ETH out

### Value Locked
- Token balances
- Reward pool
```

### Step 3.3: Access Control Review

```markdown
## Access Control Analysis

### Role Hierarchy
```
DEFAULT_ADMIN_ROLE
    │
    ├── OPERATOR_ROLE
    │       └── Can: harvest, compound
    │
    └── PAUSER_ROLE
            └── Can: pause, unpause
```

### Function Access Matrix
| Function | Public | Owner | Operator | Pauser |
|----------|--------|-------|----------|--------|
| deposit | ✅ | ✅ | ✅ | ✅ |
| pause | ❌ | ✅ | ❌ | ✅ |
| harvest | ❌ | ✅ | ✅ | ❌ |

### Access Control Gaps
- ⚠️ [Missing modifier on function X]
- ⚠️ [Role can be self-assigned]
```

---

## Phase 4: Synthesis & Documentation (30-60 minutes)

### Step 4.1: Global Invariant Summary

```markdown
## Global Invariants

### Economic Invariants
1. Total deposits == sum of all user balances
2. Rewards distributed <= rewards earned
3. No negative balances possible

### Security Invariants
1. Only owner can modify parameters
2. Paused state blocks all user operations
3. Reentrancy protected on all external calls

### Protocol Invariants
1. Interest rate bounded by [min, max]
2. Collateral ratio >= minimum at all times
3. Liquidation only when health < threshold
```

### Step 4.2: Risk Summary

```markdown
## Risk Summary

### Critical Risks
| Risk | Location | Status | Action Needed |
|------|----------|--------|---------------|
| Reentrancy | swap() L45 | ❌ | Add guard |
| Oracle manipulation | getPrice() | ⚠️ | Add TWAP |

### High Risks
[Same format]

### Medium Risks
[Same format]

### Low Risks
[Same format]
```

### Step 4.3: Open Questions

```markdown
## Open Questions for Protocol Team

### Clarifications Needed
1. What is the expected behavior when X happens?
2. Is Y intentional or a bug?

### Design Decisions to Validate
1. Why was Z implemented this way instead of W?
2. What are the trust assumptions about Oracle?

### Potential Issues to Discuss
1. Observed pattern X - is this intended?
2. Edge case Y - has this been considered?
```

---

## Phase 5: Completion Checklist

```markdown
## Review Completion Checklist

### Coverage
- [ ] All public/external functions analyzed
- [ ] All state variables documented
- [ ] All external calls reviewed
- [ ] All modifiers understood
- [ ] Constructor/initializer analyzed

### Depth
- [ ] Block-by-block analysis for critical functions
- [ ] Invariants identified (3+ per function, 5+ global)
- [ ] Assumptions documented (5+ per function)
- [ ] Cross-references complete

### Quality
- [ ] All line numbers cited
- [ ] No vague statements
- [ ] Uncertainties marked
- [ ] First Principles/5 Whys/5 Hows applied

### Integration
- [ ] External calls fully analyzed
- [ ] Value flows mapped
- [ ] Access control verified
- [ ] Trust boundaries defined

### Output
- [ ] Risk summary complete
- [ ] Open questions documented
- [ ] Ready for vulnerability hunting phase
```

---

## Transition to Vulnerability Hunting

After completing this workflow:

1. **Context is built** - You understand the system deeply
2. **Invariants are known** - You know what should never break
3. **Risks are identified** - You know where to focus
4. **Assumptions are documented** - You can challenge them

Now you can:
- Use **cyfrin-findings** to research similar vulnerabilities
- Use **solidity-scanner** to scan for pattern-based issues
- Apply **variant-analysis** to find similar bugs
- Write up findings using **audit-report-writer**

