# Pre-Audit Context Workflow

Build comprehensive context BEFORE the audit begins to maximize efficiency and coverage.

---

## Purpose

This workflow is designed for the **preparation phase** before a formal security audit. It ensures you have deep familiarity with the codebase before the time-boxed audit period begins.

**When to Use:**
- 2-3 days before audit start
- When receiving new codebase for review
- Before competitive audit submission deadlines

**Outcome:** Complete mental model of the system, ready for vulnerability hunting

---

## Day -3: Documentation Deep Dive

### Step 1: Gather All Documentation

Collect and read:
- [ ] README files
- [ ] Technical documentation
- [ ] Whitepaper (if applicable)
- [ ] Architecture diagrams
- [ ] Previous audit reports
- [ ] Known issues list
- [ ] Test documentation

### Step 2: Extract Key Information

```markdown
## Documentation Summary

### Protocol Overview
**Type:** [DEX/Lending/NFT/Bridge/etc.]
**Purpose:** [1-2 sentence description]
**Key Innovation:** [What makes this different]

### Token Economics
- Native token: [name, purpose]
- Fee structure: [how fees work]
- Reward mechanism: [if applicable]

### User Journeys
1. **Deposit Flow:** [step by step]
2. **Withdrawal Flow:** [step by step]
3. **Other Key Flows:** [step by step]

### Documented Invariants
From docs/specs:
1. [Invariant from documentation]
2. [Another invariant]

### Documented Risks
From docs/previous audits:
1. [Known risk or limitation]
2. [Another known issue]
```

### Step 3: Create Question List

```markdown
## Questions from Documentation

### Unclear Points
1. [Something not well explained]
2. [Ambiguous statement]

### Missing Information
1. [What should be documented but isn't]
2. [Gap in documentation]

### Inconsistencies
1. [Docs say X but code might say Y]
2. [Conflicting statements]
```

---

## Day -2: Codebase Overview

### Step 4: Structural Analysis

```markdown
## Codebase Structure

### Contract Inventory
| Contract | LOC | Inheritance | Purpose |
|----------|-----|-------------|---------|
| Vault.sol | 450 | Ownable, ReentrancyGuard | Main vault |
| Strategy.sol | 300 | IStrategy | Yield strategy |

### Dependency Map
```
Vault.sol
├── imports Strategy.sol
├── imports Token.sol
└── imports Oracle.sol
    └── imports Chainlink
```

### External Dependencies
| Dependency | Version | Risk Level |
|------------|---------|------------|
| OpenZeppelin | 4.9.0 | Low |
| Chainlink | v0.8 | Medium |
| UniswapV3 | Core | Medium |

### Upgrade Pattern
- [ ] Immutable contracts
- [ ] Proxy pattern (which type?)
- [ ] Diamond pattern
- [ ] Beacon proxy
```

### Step 5: Entry Point Mapping

Map all ways users/contracts can interact:

```markdown
## Entry Points

### Direct User Calls
| Function | Risk Level | Value Handling |
|----------|------------|----------------|
| deposit() | Critical | Receives tokens |
| withdraw() | Critical | Sends tokens |
| claim() | High | Sends rewards |

### Callback Entry Points
| Function | Caller | Trigger |
|----------|--------|---------|
| onFlashLoan() | Pool | Flash loan |
| uniswapV3Callback() | Router | Swap |

### Admin Entry Points
| Function | Role Required | Impact |
|----------|--------------|--------|
| setFee() | Owner | Economic |
| pause() | Pauser | Operations |
| upgrade() | Admin | Full control |

### Automated/Keeper Entry Points
| Function | Expected Caller | Purpose |
|----------|-----------------|---------|
| harvest() | Keeper bot | Collect yields |
| rebalance() | Keeper bot | Optimize |
```

### Step 6: State Variable Inventory

```markdown
## State Variables

### Value-Holding Variables
| Variable | Type | Who Modifies | Invariants |
|----------|------|--------------|------------|
| balances | mapping | deposit, withdraw | sum = totalDeposits |
| totalSupply | uint256 | mint, burn | matches token supply |

### Configuration Variables
| Variable | Type | Default | Bounds | Who Sets |
|----------|------|---------|--------|----------|
| feeRate | uint256 | 30 | 0-1000 | Owner |
| minDeposit | uint256 | 1e18 | >0 | Owner |

### Access Control Variables
| Variable | Type | Purpose |
|----------|------|---------|
| owner | address | Admin functions |
| paused | bool | Emergency stop |
```

---

## Day -1: Deep Function Analysis

### Step 7: Critical Path Analysis

Identify and analyze the most critical functions:

```markdown
## Critical Functions (Top 5)

### 1. deposit(uint256 amount)
[Full analysis using output-template.md]

### 2. withdraw(uint256 amount)
[Full analysis using output-template.md]

### 3. [Next most critical]
[Full analysis]

### 4. [Next most critical]
[Full analysis]

### 5. [Next most critical]
[Full analysis]
```

### Step 8: External Integration Analysis

```markdown
## External Integrations

### Integration 1: [Protocol Name]
**Type:** Oracle / DEX / Lending / Bridge
**Trust Level:** High / Medium / Low

**Our Calls to Them:**
| Our Function | Their Function | Purpose |
|--------------|----------------|---------|
| getPrice() | latestRoundData() | Get price |

**Their Callbacks to Us:**
| Their Trigger | Our Handler | Purpose |
|---------------|-------------|---------|
| Flash loan | onFlashLoan() | Receive funds |

**Assumptions:**
1. [They return valid data]
2. [They are not malicious]
3. [Specific assumption]

**Risks:**
1. [What could go wrong]
2. [Another risk]

### Integration 2: [Protocol Name]
[Same format]
```

### Step 9: Invariant Compilation

```markdown
## Compiled Invariants

### Protocol-Level Invariants
From documentation and code:
1. **I1:** Total deposited == sum of user balances
2. **I2:** No user can withdraw more than deposited
3. **I3:** Fees never exceed X%

### Contract-Level Invariants
Per contract:
**Vault.sol:**
1. totalAssets >= totalLiabilities
2. [Another invariant]

**Strategy.sol:**
1. Invested funds traceable
2. [Another invariant]

### Function-Level Invariants
From function analysis:
1. deposit(): balance[user] increases by amount
2. withdraw(): balance[user] decreases by amount

### Invariant Verification Plan
| Invariant | Verification Method | Status |
|-----------|---------------------|--------|
| I1 | Check deposit/withdraw | ⏳ |
| I2 | Review withdraw logic | ⏳ |
```

---

## Day 0: Audit Readiness

### Step 10: Final Preparation

```markdown
## Audit Readiness Checklist

### Knowledge Check
- [ ] Can explain protocol in 2 sentences
- [ ] Know all entry points
- [ ] Know all value flows
- [ ] Know all external integrations
- [ ] Know documented invariants

### Materials Ready
- [ ] Documentation summary complete
- [ ] Contract inventory complete
- [ ] Entry point map complete
- [ ] Critical function analyses complete
- [ ] External integration analyses complete
- [ ] Invariant list compiled
- [ ] Question list prepared

### Focus Areas Identified
Based on context building:
1. **High Priority:** [Area with most risk]
2. **Medium Priority:** [Another area]
3. **Low Priority:** [Less critical area]

### Known Patterns to Check
From previous audits / cyfrin-findings:
1. [Pattern relevant to this protocol type]
2. [Another relevant pattern]
3. [Another relevant pattern]
```

### Step 11: Create Attack Surface Map

```markdown
## Attack Surface Map

### Value Entry/Exit Points
```
User ──[tokens]──► deposit() ──► balances storage
                                      │
User ◄──[tokens]── withdraw() ◄───────┘
```

### Trust Boundaries
```
┌─────────────────────────────────────┐
│ TRUSTED (Owner/Admin)              │
│   setFee(), pause(), upgrade()     │
├─────────────────────────────────────┤
│ SEMI-TRUSTED (Keepers/Oracles)     │
│   harvest(), priceCallback()       │
├─────────────────────────────────────┤
│ UNTRUSTED (Users/External)         │
│   deposit(), withdraw(), claim()   │
└─────────────────────────────────────┘
```

### High-Risk Intersections
Where untrusted input meets critical operations:
1. User input → value transfer
2. Oracle data → calculation
3. Callback → state change
```

---

## Transition to Active Audit

With pre-audit context complete:

### You Now Have:
✅ Complete protocol understanding  
✅ All entry points mapped  
✅ External integrations analyzed  
✅ Invariants identified  
✅ Attack surface mapped  
✅ Focus areas prioritized  

### Ready For:
- Systematic vulnerability hunting
- Pattern-based scanning
- Edge case exploration
- Exploit development
- Finding documentation

### Recommended Next Skills:
1. **cyfrin-findings** - Research similar protocol vulnerabilities
2. **solidity-scanner** - Scan for known patterns
3. **variant-analysis** - Find similar issues in related code
4. **audit-report-writer** - Document findings professionally
