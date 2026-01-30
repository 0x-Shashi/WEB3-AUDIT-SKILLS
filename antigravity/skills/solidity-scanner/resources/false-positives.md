# False Positive Guide

How to distinguish real vulnerabilities from false positives in Solidity security analysis.

---

## Overview

Not every pattern match is a vulnerability. This guide helps you:
1. Understand common false positive scenarios
2. Apply context to pattern matches
3. Document rationale for dismissals

---

## Reentrancy False Positives

### FP-RE-01: Reentrancy Guard Present

**Pattern Match:** External call before state update
**Why It's Not Vulnerable:** Function has `nonReentrant` modifier

```solidity
function withdraw(uint256 amount) external nonReentrant {
    (bool success, ) = msg.sender.call{value: amount}("");  // External call
    require(success);
    balances[msg.sender] -= amount;  // State after call - SAFE with modifier
}
```

**Verification Steps:**
1. Confirm `nonReentrant` is from trusted library (OpenZeppelin)
2. Check it's applied correctly (not just declared)
3. Verify no other functions share state without protection

---

### FP-RE-02: No State to Corrupt

**Pattern Match:** External call in function
**Why It's Not Vulnerable:** No meaningful state changes possible

```solidity
function claim() external {
    uint256 amount = pendingRewards[msg.sender];
    pendingRewards[msg.sender] = 0;  // State BEFORE call
    
    (bool success, ) = msg.sender.call{value: amount}("");  // External call
    require(success);
    
    emit Claimed(msg.sender, amount);  // Only event after
}
```

**Verification Steps:**
1. All state changes happen before external call
2. Only events/logs after the call
3. No cross-function state dependencies

---

### FP-RE-03: Trusted Target

**Pattern Match:** External call to address
**Why It's Not Vulnerable:** Target is trusted and immutable

```solidity
WETH public immutable weth;  // Trusted, immutable

function wrapETH() external payable {
    weth.deposit{value: msg.value}();  // Call to trusted WETH
    weth.transfer(msg.sender, msg.value);
}
```

**Verification Steps:**
1. Target address is immutable (set in constructor)
2. Target is well-known, audited contract (WETH, major DEX)
3. No admin can change the target

---

## Access Control False Positives

### FP-AC-01: Intentionally Public

**Pattern Match:** State-changing function without access control
**Why It's Not Vulnerable:** Designed to be publicly callable

```solidity
// Lending protocol - anyone can liquidate
function liquidate(address user) external {
    require(getHealthFactor(user) < 1e18, "Not liquidatable");
    // ... liquidation logic
}
```

**Verification Steps:**
1. Function is documented as public
2. Has proper validation/checks
3. Matches protocol specification

---

### FP-AC-02: View/Pure Functions

**Pattern Match:** Function without access modifier
**Why It's Not Vulnerable:** View/pure functions don't modify state

```solidity
function getBalance(address user) external view returns (uint256) {
    return balances[user];  // Read-only, no protection needed
}
```

**Verification Steps:**
1. Function is `view` or `pure`
2. Doesn't call state-changing functions
3. Return value exposure is acceptable

---

### FP-AC-03: Internal/Private Functions

**Pattern Match:** Function modifies state without check
**Why It's Not Vulnerable:** Internal function, access controlled at caller

```solidity
function _transfer(address from, address to, uint256 amount) internal {
    // No access check here - that's the caller's job
    balances[from] -= amount;
    balances[to] += amount;
}

function transfer(address to, uint256 amount) external {
    // Access implicitly controlled - msg.sender can only transfer own tokens
    _transfer(msg.sender, to, amount);
}
```

**Verification Steps:**
1. All callers properly check access
2. No way to call internal function with arbitrary parameters
3. Function is truly internal/private

---

## Arithmetic False Positives

### FP-AR-01: Solidity 0.8+ Built-in Checks

**Pattern Match:** Arithmetic operation without SafeMath
**Why It's Not Vulnerable:** Solidity 0.8+ has built-in overflow checks

```solidity
pragma solidity ^0.8.0;

function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // Safe in 0.8+, reverts on overflow
}
```

**Verification Steps:**
1. Pragma is `^0.8.0` or higher
2. Operation is not in `unchecked` block
3. No inline assembly bypassing checks

---

### FP-AR-02: Intentional Unchecked

**Pattern Match:** Unchecked arithmetic
**Why It's Not Vulnerable:** Bounds proven by prior checks

```solidity
function decrement(uint256 value) public pure returns (uint256) {
    require(value > 0, "Cannot decrement zero");
    
    unchecked {
        return value - 1;  // Safe - we checked value > 0
    }
}
```

**Verification Steps:**
1. Prior check guarantees safety
2. Gas optimization is the reason
3. Logic is obviously correct

---

### FP-AR-03: Acceptable Precision Loss

**Pattern Match:** Integer division with precision loss
**Why It's Not Vulnerable:** Loss is within acceptable bounds

```solidity
function calculateFee(uint256 amount) public pure returns (uint256) {
    // 0.3% fee - precision loss < 1 wei per 100 wei input
    return amount * 3 / 1000;
}
```

**Verification Steps:**
1. Precision loss is documented/expected
2. Loss is economically insignificant
3. No cumulative precision attack possible

---

## Oracle False Positives

### FP-OR-01: TWAP Oracle

**Pattern Match:** Reading price from AMM
**Why It's Not Vulnerable:** Uses TWAP, not spot price

```solidity
function getPrice() public view returns (uint256) {
    // Uses 30-minute TWAP, not spot price
    return oracle.consult(token, 1e18, 30 minutes);
}
```

**Verification Steps:**
1. Verify TWAP implementation is correct
2. TWAP period is long enough (10+ minutes)
3. Implementation matches Uniswap V3 or known pattern

---

### FP-OR-02: Not Price-Sensitive

**Pattern Match:** External data source used
**Why It's Not Vulnerable:** Data is not used for value calculations

```solidity
function getLastUpdateTime() external view returns (uint256) {
    (, , , uint256 updatedAt, ) = priceFeed.latestRoundData();
    return updatedAt;  // Just for display, not for calculations
}
```

**Verification Steps:**
1. Data is for informational purposes only
2. No value calculations depend on this
3. Manipulation has no economic impact

---

## Token False Positives

### FP-TK-01: Known Token Whitelist

**Pattern Match:** No fee-on-transfer handling
**Why It's Not Vulnerable:** Only whitelisted tokens allowed

```solidity
mapping(address => bool) public allowedTokens;

function deposit(address token, uint256 amount) external {
    require(allowedTokens[token], "Token not allowed");
    // Known tokens verified to not have transfer fees
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;
}
```

**Verification Steps:**
1. Token whitelist is controlled
2. Each whitelisted token verified as standard ERC20
3. No way to add arbitrary tokens

---

### FP-TK-02: Balance Difference Pattern

**Pattern Match:** Token transfer without fee handling
**Why It's Not Vulnerable:** Uses balance difference pattern

```solidity
function deposit(address token, uint256 amount) external {
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;
    
    // Uses actual received amount, handles fee-on-transfer
    balances[msg.sender] += received;
}
```

**Verification Steps:**
1. Balance measured before and after
2. Actual difference used in accounting
3. No assumptions about amount received

---

## DoS False Positives

### FP-DOS-01: Bounded Loop

**Pattern Match:** Loop over array
**Why It's Not Vulnerable:** Array size is bounded

```solidity
address[10] public admins;  // Fixed size array

function payAdmins() external {
    for (uint i = 0; i < 10; i++) {
        // Fixed 10 iterations - bounded gas cost
        if (admins[i] != address(0)) {
            payable(admins[i]).transfer(1 ether);
        }
    }
}
```

**Verification Steps:**
1. Loop bound is constant or capped
2. Maximum iterations won't exceed gas limit
3. No way to increase array size

---

### FP-DOS-02: Admin-Only Function

**Pattern Match:** Potentially expensive operation
**Why It's Not Vulnerable:** Only admin can trigger

```solidity
function clearAllPending() external onlyOwner {
    // Expensive but only owner can call
    // Owner won't DoS themselves
    delete pendingTransactions;
}
```

**Verification Steps:**
1. Function is admin-only
2. Admin has no incentive to DoS
3. Operation is not user-triggered

---

## Documentation Template

When dismissing a finding as false positive:

```markdown
## Dismissed: [Pattern ID] in [Location]

**Pattern:** [What was flagged]
**Dismissal Category:** FP-XX-##

**Why Not Vulnerable:**
[Clear explanation]

**Verification:**
1. [Check performed]
2. [Another check]
3. [Conclusion]

**Residual Risk:** None | Low
```

---

## Best Practices

### Always Verify
- Don't assume false positive without checking
- Context matters - same pattern can be vuln or FP
- Check all related code, not just flagged line

### Document Everything
- Every dismissal needs rationale
- Future auditors will review your work
- "Looks fine" is not a valid dismissal

### When in Doubt
- Assume it's vulnerable
- Ask for clarification
- Report as informational if unsure

### Red Flags That Override FP
- Dismissal logic relies on external behavior
- "The frontend prevents this" (it doesn't)
- Complex reasoning needed to prove safety

