# Finding Templates

Standardized templates for documenting security findings across different categories.

---

## Critical Finding Template

```markdown
## [C-XX] [Descriptive Title]

### Severity
**Critical** 🔴

### Location
- **File:** `path/to/Contract.sol`
- **Lines:** XXX-YYY
- **Function:** `functionName()`

### Description
[Clear explanation of the vulnerability in 2-3 sentences]

### Root Cause
[Technical explanation of why this vulnerability exists]

### Vulnerable Code
```solidity
// Include the exact vulnerable code
function vulnerable() external {
    // Highlight the problematic line(s)
}
```

### Attack Scenario
1. Attacker deploys malicious contract
2. Attacker calls function X with parameter Y
3. Due to [vulnerability], Z happens
4. Attacker drains funds/gains control/etc.

### Impact
- **Funds at Risk:** [Amount or percentage]
- **Affected Users:** [All users / specific subset]
- **Attack Complexity:** [Low/Medium/High]
- **Attack Cost:** [Minimal/Moderate/Significant]

### Proof of Concept
```solidity
// test/PoC.t.sol
contract CriticalPoCTest is Test {
    function testExploit() public {
        // Setup
        
        // Attack
        
        // Verify exploit succeeded
        assertEq(attacker.balance, stolenAmount);
    }
}
```

### Recommendation
```solidity
// Fixed version
function secure() external {
    // Implement the fix
}
```

[Explain why this fix addresses the root cause]

### References
- [Link to similar vulnerability]
- [Relevant documentation or standard]

### Status
**[Open/Fixed/Acknowledged/Won't Fix]**

### Team Response
> [Quote from team's response if available]

### Fix Verification
[If fixed, confirm the fix is correct and complete]
Verified in commit: `abc1234`
```

---

## High Finding Template

```markdown
## [H-XX] [Descriptive Title]

### Severity
**High** 🟠

### Location
- **File:** `path/to/Contract.sol`
- **Lines:** XXX-YYY

### Description
[Clear explanation of the vulnerability]

### Vulnerable Code
```solidity
function problematic() external {
    // Vulnerable code
}
```

### Impact
[Explain the potential damage]

### Recommendation
```solidity
function fixed() external {
    // Fixed code
}
```

### Status
**[Status]**
```

---

## Medium Finding Template

```markdown
## [M-XX] [Descriptive Title]

### Severity
**Medium** 🟡

### Location
`path/to/Contract.sol#LXXX`

### Description
[Explanation of the issue and conditions required]

### Impact
[What happens under those conditions]

### Recommendation
[How to address the issue]

### Status
**[Status]**
```

---

## Low Finding Template

```markdown
## [L-XX] [Descriptive Title]

### Severity
**Low** 🟢

### Location
`path/to/Contract.sol#LXXX`

### Description
[Brief explanation]

### Recommendation
[Simple fix or best practice to follow]

### Status
**[Status]**
```

---

## Informational Template

```markdown
## [I-XX] [Descriptive Title]

### Type
**Informational** ℹ️

### Location
`path/to/Contract.sol#LXXX`

### Description
[Observation or suggestion]

### Suggestion
[Improvement recommendation]
```

---

## Gas Optimization Template

```markdown
## [G-XX] [Optimization Title]

### Location
`path/to/Contract.sol#LXXX`

### Description
[What can be optimized]

### Current Implementation
```solidity
// Current code
```

### Optimized Version
```solidity
// Optimized code
```

### Gas Savings
| Operation | Before | After | Savings |
|-----------|--------|-------|---------|
| Deploy | X gas | Y gas | Z gas |
| Function Call | X gas | Y gas | Z gas |
```

---

## Category-Specific Templates

### Access Control Finding

```markdown
## [X-XX] Missing Access Control on [Function]

### Severity
**[Severity]**

### Location
`path/to/Contract.sol#LXXX`

### Description
The `[function]` function lacks proper access control, allowing [unauthorized party] 
to [perform action] when only [authorized party] should be able to.

### Current Implementation
```solidity
function adminFunction() external {  // No access control!
    // Sensitive operation
}
```

### Impact
- [Unauthorized party] can [action]
- [Consequence 1]
- [Consequence 2]

### Recommendation
```solidity
function adminFunction() external onlyOwner {
    // Sensitive operation
}
```

### Status
**[Status]**
```

### Reentrancy Finding

```markdown
## [X-XX] Reentrancy in [Function]

### Severity
**[Severity]**

### Location
`path/to/Contract.sol#LXXX`

### Description
The `[function]` function performs an external call before updating state, 
enabling reentrancy attacks.

### Vulnerable Pattern
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // External call
    balances[msg.sender] -= amount;  // State update after
}
```

### Attack Flow
1. Attacker calls withdraw(X)
2. Contract sends X ETH to attacker
3. Attacker's receive() calls withdraw(X) again
4. Contract sends X ETH again (balance not yet updated)
5. Repeat until contract is drained

### Recommendation
```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State update first
    (bool success,) = msg.sender.call{value: amount}("");  // External call last
    require(success);
}
```

### Status
**[Status]**
```

### Oracle Manipulation Finding

```markdown
## [X-XX] Oracle/Price Manipulation in [Function]

### Severity
**[Severity]**

### Location
`path/to/Contract.sol#LXXX`

### Description
The `[function]` uses spot price from [source] which can be manipulated 
via [flash loan/large trade/etc.].

### Vulnerable Pattern
```solidity
function getPrice() external view returns (uint256) {
    // Spot price - manipulatable!
    return pool.getReserve0() * 1e18 / pool.getReserve1();
}
```

### Attack Scenario
1. Attacker takes flash loan of X tokens
2. Attacker swaps to manipulate pool price
3. Attacker calls vulnerable function (gets favorable rate)
4. Attacker swaps back and repays flash loan
5. Attacker profits [amount]

### Recommendation
- Use TWAP (Time-Weighted Average Price)
- Use decentralized oracle (Chainlink)
- Add manipulation-resistant checks

```solidity
function getPrice() external view returns (uint256) {
    (uint256 price, uint256 updatedAt) = oracle.getLatestPrice();
    require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");
    return price;
}
```

### Status
**[Status]**
```

### Input Validation Finding

```markdown
## [X-XX] Missing Input Validation in [Function]

### Severity
**[Severity]**

### Location
`path/to/Contract.sol#LXXX`

### Description
The `[function]` does not validate [parameter], allowing [invalid value] 
to cause [issue].

### Missing Validation
```solidity
function setFee(uint256 newFee) external onlyOwner {
    // No validation - fee could be set to 100%!
    fee = newFee;
}
```

### Impact
[What happens with invalid input]

### Recommendation
```solidity
function setFee(uint256 newFee) external onlyOwner {
    require(newFee <= MAX_FEE, "Fee too high");
    require(newFee >= MIN_FEE, "Fee too low");
    fee = newFee;
}
```

### Status
**[Status]**
```

---

## Batch Findings Format

For multiple similar issues:

```markdown
## [L-XX] Multiple Instances of [Issue Type]

### Severity
**Low**

### Description
[Description of the common issue]

### Instances

1. `src/Contract1.sol#L100` - [specific context]
2. `src/Contract1.sol#L200` - [specific context]
3. `src/Contract2.sol#L50` - [specific context]
4. `src/Contract3.sol#L75` - [specific context]

### Recommendation
[Common fix for all instances]

### Status
**[Status]**
```

---

## Status Definitions

```markdown
| Status | Definition |
|--------|------------|
| Open | Finding not yet addressed |
| Fixed | Finding resolved, fix verified |
| Acknowledged | Team aware, accepted risk |
| Won't Fix | Team decided not to address |
| Disputed | Team disagrees with finding |
| Partially Fixed | Some instances addressed |
```
