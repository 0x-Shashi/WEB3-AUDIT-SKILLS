---
id: CYFRIN-WF-CODE-REVIEW
title: Code Review Enhancement Workflow
parent: cyfrin-findings
type: workflow
last_updated: 2025-01-31
---

# Code Review Enhancement Workflow

Use the Solodit findings database **during active code review** to validate suspicions, identify missed patterns, and enrich findings with historical context. This is a real-time companion workflow — query as you review.

---

## When to Use

- During line-by-line code review when you encounter a suspicious pattern
- When you find a vulnerability and want to assess its commonality and impact
- When you need to confirm whether a code pattern is actually vulnerable
- When writing findings and want to reference similar historical issues

---

## Workflow Steps

### Step 1: Identify Suspicious Patterns During Review

While reviewing code, flag patterns that match known vulnerability indicators:

| Code Pattern Observed | Likely Vulnerability | Query Category |
|----------------------|---------------------|----------------|
| `latestRoundData()` without timestamp check | Stale oracle price | `oracle-manipulation` |
| External `.call{value:}` before state update | Reentrancy | `reentrancy` |
| `totalSupply == 0` in share calculation | First depositor attack | `rounding` or search `first depositor` |
| `onERC721Received` callback in mint flow | ERC721 callback reentrancy | `reentrancy` |
| Missing `msg.sender` check on sensitive function | Access control | `access-control` |
| Division before multiplication (`a / b * c`) | Precision loss | `precision` |
| `block.timestamp` used for randomness | Predictable randomness | `randomness` |
| `tx.origin` for authentication | Phishing attack vector | `access-control` |
| Unbounded loop over dynamic array | DoS via gas exhaustion | `dos` |
| Token transfer without balance check | Insufficient balance handling | `token-integration` |

### Step 2: Query Solodit for Matching Findings

For each suspicious pattern, query the database to find historical instances:

```bash
# Example: Found a latestRoundData() call without freshness check
GET /findings?q=latestRoundData+stale+price&severity=high&per_page=20

# Example: Found an external call before state update
GET /findings?category=reentrancy&q=external+call+state+update&per_page=20

# Example: Found division before multiplication
GET /findings?q=division+before+multiplication+precision&per_page=20
```

### Step 3: Compare Historical Findings to Current Code

For each matching finding returned, compare:

| Comparison Point | Current Code | Historical Finding |
|-----------------|-------------|-------------------|
| **Vulnerable function** | What function contains the pattern? | What function was vulnerable? |
| **State affected** | What state variables are at risk? | What state was corrupted? |
| **External call target** | Who is called? (user, oracle, token) | Who was called in the exploit? |
| **Preconditions** | What must be true for exploit? | What preconditions existed? |
| **Mitigation present?** | Does current code have a fix? | What fix was recommended? |

**Decision Matrix:**

```
IF historical finding matches current code pattern
  AND current code has NO mitigation
  AND preconditions are achievable
  → REPORT as finding (severity from historical data)

IF historical finding matches current code pattern  
  AND current code HAS partial mitigation
  → VERIFY mitigation is complete and correct

IF historical finding does NOT match current context
  → False alarm — move on
```

### Step 4: Assess Severity Using Historical Data

When you confirm a vulnerability, use historical data to calibrate severity:

```bash
# How many times has this exact vulnerability type been found?
GET /findings?category=reentrancy&per_page=1
# → Check pagination.total for count (e.g., 59 reentrancy findings)

# What's the typical severity for this category?
GET /findings?category=reentrancy&severity=critical&per_page=1
GET /findings?category=reentrancy&severity=high&per_page=1
GET /findings?category=reentrancy&severity=medium&per_page=1
# → Compare counts to determine typical severity distribution
```

**Severity Calibration Table (from historical data):**

| Category | Typical Severity | Fund Loss Potential |
|----------|-----------------|---------------------|
| Reentrancy | HIGH (66% of findings) | Direct fund theft |
| Oracle manipulation | HIGH-CRITICAL | Incorrect liquidations, bad debt |
| Access control | CRITICAL (when admin bypass) | Protocol takeover |
| Precision/rounding | MEDIUM (70%) | Gradual value leakage |
| Flash loan | HIGH-CRITICAL | Single-transaction drain |
| DoS | MEDIUM (80%) | Service disruption, no fund loss |
| Logic error | Varies widely | Depends on affected function |

### Step 5: Enrich Finding with Historical Context

When writing up a confirmed finding, reference historical instances:

```markdown
### [H-01] Missing Oracle Freshness Check in getPrice()

**Severity**: HIGH

**Location**: `src/PriceOracle.sol:L42`

**Description**: The `getPrice()` function calls Chainlink's `latestRoundData()` 
but does not validate the `updatedAt` timestamp. If the Chainlink feed becomes 
stale (e.g., during network congestion or oracle downtime), the protocol will 
use an outdated price for all operations including liquidations and borrowing.

**Impact**: Using stale prices can result in:
- Under-collateralized loans not being liquidated
- Over-collateralized positions being incorrectly liquidated  
- Arbitrage opportunities between stale and true market prices

**Historical Precedent**: This vulnerability has been identified in 145+ audit 
findings across lending and DEX protocols in the Solodit database. It is 
consistently rated HIGH severity. Notable instances:
- Aave V2 audit by Trail of Bits — identical missing freshness check
- Compound fork audit on Code4rena — led to $2M potential loss
- Multiple Sherlock contests — one of the most frequently reported issues

**Recommendation**: 
```solidity
(, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
require(price > 0, "Invalid price");
```
```

### Step 6: Validate Mitigations

For each finding, check whether the recommended fix from historical findings matches best practices:

```bash
# Get findings that include fix recommendations for this category
GET /findings?category=oracle-manipulation&q=recommendation+freshness&per_page=10
```

Extract recommendation patterns:

| Mitigation | Historical Success Rate | Notes |
|------------|------------------------|-------|
| CEI pattern for reentrancy | Very high | Standard, well-understood |
| ReentrancyGuard modifier | Very high | OpenZeppelin battle-tested |
| Oracle freshness check | Very high | Simple timestamp comparison |
| Slippage parameter (minAmountOut) | High | User-controlled, flexible |
| Access control (Ownable/AccessControl) | High | Use OpenZeppelin standard |
| Rounding up in favor of protocol | High | Standard accounting practice |

---

## Real-Time Query Cheat Sheet

Quick reference for common review-time queries:

```bash
# "Is this reentrancy actually exploitable?"
?category=reentrancy&q=[specific pattern]&severity=high

# "How dangerous is this oracle implementation?"
?q=chainlink+latestRoundData&severity=critical,high

# "Have first-depositor attacks actually been exploited?"
?q=first+depositor+inflation+vault&severity=high

# "Is this access control issue really critical?"
?category=access-control&q=[function name or pattern]

# "How common is this ERC20 integration issue?"
?q=fee+on+transfer+token&severity=medium,high

# "What's the impact of this rounding error?"
?category=precision&q=rounding+direction&severity=medium
```

---

## Integration with Other Skills

| Skill | Integration Point |
|-------|-------------------|
| `patterns/` | Deep-dive into the specific vulnerability pattern files for detailed examples |
| `anti-patterns/` | Check if the code matches known anti-pattern signatures |
| `checklists/` | Verify you haven't missed checklist items related to the finding |
| `scoring/` | Use historical severity distribution to calibrate your risk score |
| `fix-patterns/` | Reference validated fix patterns when writing recommendations |
