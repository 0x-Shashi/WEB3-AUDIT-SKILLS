# Code Review Enhancement Workflow

Combine Solodit findings with manual code review for comprehensive security analysis.

---

## Purpose

Use this workflow when:
- Reviewing a pull request with security implications
- Auditing code during development
- Self-reviewing before committing
- Pair programming on sensitive features

**Time Required:** 15-30 minutes per significant feature

---

## Step 1: Identify Security-Relevant Patterns

Scan the code for patterns that commonly lead to vulnerabilities:

| Pattern | Security Concern | Priority |
|---------|-----------------|----------|
| External calls | Reentrancy, DoS | HIGH |
| Token transfers | Malicious tokens, fees | HIGH |
| Price/oracle usage | Manipulation | HIGH |
| Access modifiers | Authorization bypass | HIGH |
| State after call | CEI violation | HIGH |
| Loops with external input | DoS, gas limit | MEDIUM |
| Arithmetic operations | Overflow (unchecked) | MEDIUM |
| Timestamp usage | Manipulation | MEDIUM |
| Block data | Miner manipulation | LOW |

---

## Step 2: Query by Pattern

For each pattern identified, query Solodit:

### External Calls Present

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "external call callback reentrancy",
      "tags": ["reentrancy"],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Token Transfers Present

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "token transfer ERC20 fee rebase",
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Oracle/Price Usage

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "oracle price stale manipulation",
      "tags": ["oracle", "price-manipulation"],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

---

## Step 3: Map Findings to Code

For each finding retrieved:

1. **Read the vulnerability description**
2. **Identify the code pattern that causes it**
3. **Search for that pattern in your code**
4. **Verify if vulnerable or mitigated**

### Example Mapping

**Finding:** "Missing slippage check allows sandwich attack"

**Code Pattern:**
```solidity
// VULNERABLE
swap(amountIn, 0, path, to);  // minAmountOut = 0

// SAFE
swap(amountIn, minAmountOut, path, to);  // User-specified minimum
```

**In Your Code:**
- Search for: `swap(`, `exchange(`, `trade(`
- Check: Is minAmountOut provided and validated?
- Result: [VULNERABLE/SAFE]

---

## Step 4: Function-Level Analysis

For each function with security patterns:

```markdown
## Function: withdraw(uint256 amount)

### Patterns Detected
- [x] External call (transfer)
- [x] State change after call (CEI concern)
- [ ] Oracle usage
- [ ] Access control

### Relevant Findings
1. "Reentrancy via withdraw callback" - [CHECKED]
2. "Missing amount validation" - [NEEDS REVIEW]

### Analysis
- CEI Pattern: [FOLLOWED/VIOLATED]
- Reentrancy Guard: [PRESENT/MISSING]
- Input Validation: [PRESENT/MISSING]

### Verdict: [SAFE/NEEDS FIX]
```

---

## Step 5: Cross-Function Analysis

Check for vulnerabilities that span multiple functions:

### State Consistency

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "state inconsistent race condition",
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Access Control Bypass

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "access control bypass privilege escalation",
      "tags": ["access-control"],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

---

## Step 6: Edge Case Verification

Query for edge case vulnerabilities:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "keywords": "zero amount first deposit empty array",
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Common Edge Cases

| Edge Case | Query Keywords |
|-----------|---------------|
| Zero amount | `"zero amount validation"` |
| First depositor | `"first deposit attack donation"` |
| Empty array | `"empty array revert"` |
| Max uint256 | `"max uint overflow"` |
| Same sender/receiver | `"self transfer"` |

---

## Step 7: Document Findings

For each concern discovered:

```markdown
## [SEVERITY] Finding Title

**Location:** `contracts/Vault.sol:145-160`

**Pattern:** [Pattern name from Solodit]

**Description:**
[What the vulnerability is]

**Evidence from Solodit:**
- Finding ID: [ID]
- Similar Issue: [Title from similar finding]

**Affected Code:**
```solidity
// The vulnerable code snippet
```

**Recommendation:**
[How to fix based on Solodit recommendations]

**References:**
- [Solodit finding URL]
```

---

## Step 8: Create Review Summary

```markdown
# Code Review Summary

## Files Reviewed
- contracts/Vault.sol
- contracts/Oracle.sol

## Patterns Analyzed
| Pattern | Occurrences | Issues Found |
|---------|-------------|--------------|
| External calls | 5 | 1 |
| Token transfers | 3 | 0 |
| Oracle usage | 2 | 1 |
| Access control | 8 | 0 |

## Findings Summary
| Severity | Count |
|----------|-------|
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 3 |

## Top Issues
1. [HIGH] Reentrancy in withdraw function
2. [MEDIUM] Stale oracle price not checked
3. [MEDIUM] Missing slippage protection

## Recommendations
1. Add ReentrancyGuard to withdraw
2. Check oracle timestamp freshness
3. Implement minAmountOut parameter

## Verification Checklist
- [ ] Fixes applied
- [ ] Tests added
- [ ] Re-review completed
```

---

## Quick Reference

### Pattern → Query Mapping

| If You See | Query This |
|------------|-----------|
| `.call{value:` | reentrancy, callback |
| `transfer(` | ERC20, fee-on-transfer |
| `getPrice(` | oracle, manipulation |
| `onlyOwner` | access control, bypass |
| `block.timestamp` | timestamp manipulation |
| `for (uint i` | dos, gas limit, loop |
| `assembly {` | low-level, memory |
| `delegatecall` | proxy, storage collision |
| `abi.encode` | signature, collision |

### Severity Guidelines

| Severity | Criteria |
|----------|----------|
| HIGH | Direct fund loss, protocol takeover |
| MEDIUM | Conditional loss, DoS, limited impact |
| LOW | Minor issues, best practices |
| INFO | Suggestions, optimizations |
