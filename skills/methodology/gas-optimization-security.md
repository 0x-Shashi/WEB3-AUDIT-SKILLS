---
id: METHOD-GAS-SECURITY
title: Gas Optimization Security Patterns
category: methodology
difficulty: advanced
triggers: [gas optimization vulnerability, unchecked block bug, assembly security, storage packing risk, optimization exploit]
related_skills: [methodology/secure-pattern-reference.md, patterns/reentrancy-patterns.md, checklists/comprehensive-checklist.md]
tags: [gas, optimization, unchecked, assembly, storage-packing]
last_updated: 2026-01-31
---

# Gas Optimization Security Patterns

## Overview

Gas optimizations are necessary for cost-effective contracts, but aggressive optimizations frequently introduce security vulnerabilities. This guide covers dangerous optimization patterns and safe alternatives.

---

## 1. Dangerous Optimization Patterns

### 1.1 Unchecked Blocks Gone Wrong

```solidity
// DANGEROUS: Unchecked used too broadly
function transfer(address to, uint256 amount) external {
    unchecked {
        // Intended optimization for balance subtraction
        balances[msg.sender] -= amount;  // Can underflow!
        balances[to] += amount;          // Can overflow!
    }
}

// SAFE: Unchecked only where mathematically guaranteed
function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // Safe: checked that balance >= amount above
    unchecked {
        balances[msg.sender] -= amount;
    }
    
    // NOT safe in unchecked - could overflow
    balances[to] += amount;
}

// SAFEST: Explicit about what's unchecked
function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // Only the subtraction is safe to uncheck
    uint256 newSenderBalance;
    unchecked {
        newSenderBalance = balances[msg.sender] - amount;
    }
    balances[msg.sender] = newSenderBalance;
    balances[to] += amount;  // Keep checked
}
```

### 1.2 Loop Optimizations Creating DoS

```solidity
// DANGEROUS: Cached length with push in loop
function processAndAdd(uint256[] calldata newItems) external {
    uint256 len = items.length;  // Cached!
    
    for (uint256 i = 0; i < len;) {
        process(items[i]);
        
        if (shouldAdd(items[i])) {
            items.push(newItems[i]);  // Length changed but cache stale!
        }
        
        unchecked { ++i; }
    }
    // BUG: New items never processed
}

// DANGEROUS: Unbounded loop for gas savings
function processAllPending() external {
    // "Optimized" by processing all at once
    for (uint256 i = 0; i < pendingUsers.length;) {
        processUser(pendingUsers[i]);
        unchecked { ++i; }
    }
    // DoS: If pendingUsers grows too large, function becomes uncallable
}

// SAFE: Bounded with pagination
function processAllPending(uint256 startIndex, uint256 batchSize) external {
    uint256 endIndex = startIndex + batchSize;
    if (endIndex > pendingUsers.length) {
        endIndex = pendingUsers.length;
    }
    
    for (uint256 i = startIndex; i < endIndex;) {
        processUser(pendingUsers[i]);
        unchecked { ++i; }
    }
}
```

### 1.3 Storage Packing Vulnerabilities

```solidity
// DANGEROUS: Packed storage with unsafe casting
struct UserData {
    uint128 balance;      // Slot 0, bytes 0-15
    uint64 lastUpdate;    // Slot 0, bytes 16-23
    uint64 rewardDebt;    // Slot 0, bytes 24-31
}

function deposit(uint256 amount) external {
    // amount is uint256 but balance is uint128
    userData[msg.sender].balance += uint128(amount);  // TRUNCATION!
}

// SAFE: Explicit overflow check
function deposit(uint256 amount) external {
    require(amount <= type(uint128).max, "Amount too large");
    require(
        userData[msg.sender].balance + uint128(amount) >= userData[msg.sender].balance,
        "Balance overflow"
    );
    userData[msg.sender].balance += uint128(amount);
}
```

### 1.4 Assembly Optimizations

```solidity
// DANGEROUS: Assembly without proper checks
function unsafeTransfer(address token, address to, uint256 amount) internal {
    assembly {
        // Gas optimized but no return value check!
        let ptr := mload(0x40)
        mstore(ptr, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
        mstore(add(ptr, 4), to)
        mstore(add(ptr, 36), amount)
        
        let success := call(gas(), token, 0, ptr, 68, 0, 0)
        // Missing: if iszero(success) { revert }
        // Missing: Return value check for non-reverting tokens
    }
}

// SAFE: Assembly with full validation
function safeTransfer(address token, address to, uint256 amount) internal {
    assembly {
        let ptr := mload(0x40)
        mstore(ptr, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
        mstore(add(ptr, 4), to)
        mstore(add(ptr, 36), amount)
        
        let success := call(gas(), token, 0, ptr, 68, ptr, 32)
        
        // Check call success
        if iszero(success) {
            revert(0, 0)
        }
        
        // Check return value (handle tokens that don't return)
        let returnSize := returndatasize()
        if returnSize {
            if iszero(mload(ptr)) {
                revert(0, 0)
            }
        }
    }
}
```

---

## 2. Common Gas-Security Tradeoffs

### 2.1 Reentrancy Guards vs Gas

```solidity
// "Optimized": No reentrancy guard (saves ~2400 gas)
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // VULNERABLE
}

// SECURE: With reentrancy guard
function withdraw(uint256 amount) external nonReentrant {  // +2400 gas
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}

// OPTIMAL: CEI pattern (secure + efficient)
function withdraw(uint256 amount) external {  // No extra SSTORE
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State change first
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

### 2.2 Validation Skipping

```solidity
// DANGEROUS: Skipping validation for gas
function bulkTransfer(
    address[] calldata recipients,
    uint256[] calldata amounts
) external {
    // "Optimization": Assume arrays same length
    for (uint256 i = 0; i < recipients.length;) {
        _transfer(recipients[i], amounts[i]);
        unchecked { ++i; }
    }
    // BUG: If amounts.length < recipients.length, reads garbage
}

// SAFE: Always validate
function bulkTransfer(
    address[] calldata recipients,
    uint256[] calldata amounts
) external {
    require(recipients.length == amounts.length, "Length mismatch");
    
    for (uint256 i = 0; i < recipients.length;) {
        _transfer(recipients[i], amounts[i]);
        unchecked { ++i; }
    }
}
```

### 2.3 SSTORE Optimization Pitfalls

```solidity
// DANGEROUS: Caching storage for gas, missing update
function complexOperation() external {
    uint256 cachedBalance = balances[msg.sender];  // SLOAD once
    
    // Multiple operations using cache
    require(cachedBalance >= fee1);
    cachedBalance -= fee1;
    
    if (condition) {
        require(cachedBalance >= fee2);
        cachedBalance -= fee2;
    }
    
    // Forgot to write back!
    // balances[msg.sender] = cachedBalance;  // MISSING!
}

// DANGEROUS: Write-back in wrong scope
function complexOperation() external {
    uint256 cachedBalance = balances[msg.sender];
    
    if (condition) {
        cachedBalance -= fee;
        balances[msg.sender] = cachedBalance;  // Only written in branch!
    }
    // If !condition, balance not updated despite other operations
}
```

---

## 3. Optimization-Induced Attack Vectors

### 3.1 Flash Loan via "Optimized" Balance Check

```solidity
// VULNERABLE: Using balance instead of accounting
contract OptimizedPool {
    function availableLiquidity(address token) public view returns (uint256) {
        // "Optimization": No separate accounting variable
        return IERC20(token).balanceOf(address(this));
    }
    
    function borrow(address token, uint256 amount) external {
        require(amount <= availableLiquidity(token));
        // Vulnerable to flash loan manipulation
    }
}

// SECURE: Explicit accounting
contract SecurePool {
    mapping(address => uint256) public totalDeposited;
    
    function availableLiquidity(address token) public view returns (uint256) {
        return totalDeposited[token] - totalBorrowed[token];
    }
}
```

### 3.2 Price Manipulation via "Efficient" Oracle

```solidity
// VULNERABLE: Spot price for gas efficiency
function getPrice() public view returns (uint256) {
    // "Optimized": Direct calculation, no TWAP storage
    return reserve0 * 1e18 / reserve1;  // Manipulable!
}

// SECURE: TWAP with storage cost
function getPrice() public view returns (uint256) {
    return twapOracle.consult(token, TWAP_PERIOD);  // More gas, much safer
}
```

### 3.3 Signature Replay via "Optimized" Nonce

```solidity
// VULNERABLE: Bitmap nonce for gas
contract OptimizedPermit {
    mapping(address => uint256) public nonceBitmap;
    
    function permit(
        address owner,
        uint256 nonceIndex,  // User chooses nonce!
        // ...
    ) external {
        uint256 wordIndex = nonceIndex / 256;
        uint256 bitIndex = nonceIndex % 256;
        
        // Check and set bit
        require(nonceBitmap[owner] & (1 << bitIndex) == 0, "Used");
        nonceBitmap[owner] |= (1 << bitIndex);
    }
    // ISSUE: User can choose different nonceIndex, reuse sig concept
}

// SECURE: Sequential nonce
contract SecurePermit {
    mapping(address => uint256) public nonces;
    
    function permit(address owner, /* ... */) external {
        uint256 currentNonce = nonces[owner]++;  // Sequential, no choice
    }
}
```

---

## 4. Safe Optimization Patterns

### 4.1 Safe Unchecked Usage

```solidity
// PATTERN: Only uncheck provably safe operations
function safeIncrement(uint256 i) internal pure returns (uint256) {
    unchecked {
        return i + 1;  // Safe if used in bounded loop
    }
}

// PATTERN: Uncheck after validation
function divide(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0, "Division by zero");
    unchecked {
        return a / b;  // Safe: b != 0 verified
    }
}

// PATTERN: Uncheck subtraction after comparison
function subtract(uint256 a, uint256 b) internal pure returns (uint256) {
    require(a >= b, "Underflow");
    unchecked {
        return a - b;  // Safe: a >= b verified
    }
}
```

### 4.2 Safe Storage Packing

```solidity
// PATTERN: Use library for safe packed operations
library SafePacking {
    function toUint128Safe(uint256 value) internal pure returns (uint128) {
        require(value <= type(uint128).max, "Overflow uint128");
        return uint128(value);
    }
    
    function toUint64Safe(uint256 value) internal pure returns (uint64) {
        require(value <= type(uint64).max, "Overflow uint64");
        return uint64(value);
    }
}

struct PackedData {
    uint128 balance;
    uint64 timestamp;
    uint64 extra;
}

function updateBalance(uint256 newBalance) external {
    data.balance = SafePacking.toUint128Safe(newBalance);
}
```

### 4.3 Safe Loop Patterns

```solidity
// PATTERN: Bounded loops with clear limits
uint256 public constant MAX_BATCH_SIZE = 100;

function processBatch(uint256[] calldata items) external {
    require(items.length <= MAX_BATCH_SIZE, "Batch too large");
    
    uint256 len = items.length;
    for (uint256 i = 0; i < len;) {
        _process(items[i]);
        unchecked { ++i; }
    }
}

// PATTERN: Pull over push for unbounded operations
function claimRewards() external {
    uint256 rewards = pendingRewards[msg.sender];
    pendingRewards[msg.sender] = 0;
    
    // User pulls their own rewards, no loop needed
    _transfer(msg.sender, rewards);
}
```

---

## 5. Optimization Audit Checklist

### 5.1 Unchecked Block Review

```markdown
□ Every unchecked block has documented safety proof
□ No user input directly in unchecked arithmetic
□ Overflow/underflow impossible given constraints
□ Loop counters bounded before unchecked increment
□ Subtraction has prior >= check
□ Division has prior != 0 check
```

### 5.2 Storage Optimization Review

```markdown
□ All downcasts have overflow checks
□ Packed structs don't truncate on assignment
□ Cached storage values written back on all paths
□ No TOCTOU between cache read and write
□ Mapping keys don't collide after optimization
```

### 5.3 Loop Optimization Review

```markdown
□ All loops have explicit bounds
□ Cached length not invalidated by loop body
□ No unbounded external calls in loops
□ State properly updated if loop exits early
□ Gas limit cannot cause partial execution issues
```

### 5.4 Assembly Review

```markdown
□ All external calls check return value
□ Memory pointers don't overlap incorrectly
□ No assumptions about memory layout
□ Return data properly validated
□ Reverts have meaningful error data
```

---

## 6. Gas vs Security Decision Matrix

| Optimization | Gas Saved | Security Risk | Recommendation |
|-------------|-----------|---------------|----------------|
| Unchecked loop counter | ~50/iter | Low |  Safe if bounded |
| Unchecked all math | ~50/op | **Critical** |  Never |
| Skip array length check | ~100 | High |  Never |
| Pack structs | ~2100/slot | Medium |  With safe casts |
| Remove reentrancy guard | ~2400 | **Critical** |  CEI pattern instead |
| Use assembly for transfers | ~200 | High |  Use audited library |
| Cache storage in memory | ~100/read | Medium |  With careful writeback |
| Skip zero-address checks | ~100 | Medium |  Keep checks |
| Bitmap vs sequential nonce | ~2000 | High |  Sequential safer |

---

## 7. Real-World Optimization Exploits

### 7.1 Opyn Protocol — Skipped Zero-Value Check ($371K, Aug 2020)

**What happened**: The `exercise()` function for ETH put options didn't validate that the exercise amount was greater than zero. Calling `exercise(0)` allowed the attacker to trigger the exercise logic, receive the underlying collateral, without providing any payment tokens.

**The "optimization"**: Omitting zero-value validation saves ~200 gas per call. This is a common pattern where developers skip `require(amount > 0)` assuming callers always pass meaningful values.

```solidity
// VULNERABLE: Missing zero-value check
function exercise(uint256 oTokensToExercise) external {
    // No require(oTokensToExercise > 0) — saves ~200 gas
    uint256 collateralToPay = oTokensToExercise * strikePrice / 1e18;
    // When oTokensToExercise = 0, collateralToPay = 0
    // But the function still transfers underlying to caller
    underlying.transfer(msg.sender, exerciseAmount);
}

// FIXED: Always validate inputs regardless of gas cost
function exercise(uint256 oTokensToExercise) external {
    require(oTokensToExercise > 0, "Cannot exercise zero");
    uint256 collateralToPay = oTokensToExercise * strikePrice / 1e18;
    require(collateralToPay > 0, "Payment too small");
    underlying.transfer(msg.sender, exerciseAmount);
}
```

**Lesson**: Input validation is not optional. The 200 gas saved is meaningless compared to a $371K exploit. Every public/external function should validate all inputs.

---

### 7.2 Harvest Finance — Spot Price Instead of TWAP ($34M, Oct 2020)

**What happened**: Harvest's vaults calculated deposit share value using the current balance ratio of Curve pools rather than a TWAP oracle. The attacker flash-loaned $50M USDC/USDT, manipulated the Curve pool ratio, deposited into Harvest at an inflated rate, restored the pool, and withdrew at the true rate — extracting $34M profit across 7 repeated transactions in a single block.

**The "optimization"**: Reading spot balances costs ~2,600 gas (a single `SLOAD`). A Uniswap V2 TWAP costs ~10,000+ gas (two storage reads + math). A Chainlink oracle call costs ~7,000+ gas. The protocol chose the cheapest option.

```solidity
// VULNERABLE: Spot price from pool balances (cheapest, ~2,600 gas)
function getSharePrice() public view returns (uint256) {
    uint256 poolBalance = curvePool.balances(0); // Current balance
    return (totalAssets() * 1e18) / totalShares;
    // totalAssets reads pool balance directly — manipulable via flash loan
}

// FIXED: Use manipulation-resistant oracle (costs more gas, prevents exploit)
function getSharePrice() public view returns (uint256) {
    uint256 twapPrice = uniswapOracle.consult(token, 1e18); // 30-min TWAP
    // Or: uint256 chainlinkPrice = priceFeed.latestRoundData();
    // TWAP cannot be manipulated within a single transaction
    return (totalAssets(twapPrice) * 1e18) / totalShares;
}
```

**Lesson**: Price data is the most security-critical input in DeFi. Never use spot prices to save gas — the cost difference between a TWAP (~10K gas) and a spot read (~2.6K gas) is 7,400 gas ≈ $0.15 at typical gas prices. The $34M loss makes this the most expensive gas optimization in DeFi history.

---

### 7.3 bZx iToken Duplication — Storage Cache Writeback Bug ($8M, Sep 2020)

**What happened**: The bZx iToken `transferFrom()` function cached the sender's and recipient's balances in memory to avoid redundant `SLOAD`s. However, when sender == recipient (self-transfer), only one cached variable was written back to storage, effectively doubling the balance.

**The "optimization"**: Caching storage variables in memory saves ~2,100 gas per avoided `SLOAD`/`SSTORE` pair. The developer cached both balances before updating, but didn't handle the edge case where both variables alias the same storage slot.

```solidity
// VULNERABLE: Storage cache doesn't handle self-transfer
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fromBalance = balances[from]; // Cache (SLOAD)
    uint256 toBalance = balances[to];     // Cache (SLOAD)

    fromBalance -= amount;
    toBalance += amount;

    balances[from] = fromBalance; // Write back (SSTORE)
    balances[to] = toBalance;     // When from == to, overwrites the subtraction!
    // Result: balance doubled instead of unchanged
}

// FIXED: Handle self-transfer explicitly
function _transfer(address from, address to, uint256 amount) internal {
    if (from == to) return; // Self-transfer is a no-op
    balances[from] -= amount;
    balances[to] += amount;
}
```

**Lesson**: Storage caching optimizations must account for aliasing. Whenever two cached storage variables could refer to the same slot, the edge case MUST be handled. The 4,200 gas saved (~$0.08) is irrelevant against unlimited token minting.

---

### 7.4 Level Finance — Unchecked Block in Reward Calculation ($1.1M, May 2023)

**What happened**: Level Finance used Solidity 0.8's `unchecked` blocks in their referral reward calculation to save gas. An integer overflow in the unchecked multiplication allowed an attacker to claim massively inflated rewards — draining 214,000 LVL tokens ($1.1M) from the referral controller.

**The "optimization"**: Wrapping arithmetic in `unchecked {}` saves ~120 gas per operation by skipping overflow/underflow checks. This is safe only when mathematical proofs guarantee the values cannot overflow.

```solidity
// VULNERABLE: unchecked without mathematical proof of bounds
function claimReward(uint256 epoch) external {
    unchecked {
        uint256 reward = userPoints[msg.sender] * rewardPerPoint[epoch];
        // If userPoints * rewardPerPoint > type(uint256).max → wraps silently
        // Attacker manipulates points to cause overflow → huge reward
        token.transfer(msg.sender, reward);
    }
}

// FIXED: Only use unchecked where overflow is mathematically impossible
function claimReward(uint256 epoch) external {
    uint256 reward = userPoints[msg.sender] * rewardPerPoint[epoch];
    // Solidity 0.8 automatically reverts on overflow
    require(reward <= maxRewardPerUser, "Reward exceeds cap");
    token.transfer(msg.sender, reward);
}
```

**Lesson**: Every `unchecked` block needs a documented mathematical proof that overflow cannot occur. The proof should consider adversarial inputs, not just expected values. If the proof requires more than two sentences, don't use `unchecked`.

---

### 7.5 Common Anti-Patterns Summary

| Anti-Pattern | Gas Saved | Typical Loss | Ratio |
|---|---|---|---|
| Skip zero-value checks | ~200 gas | $371K (Opyn) | 1 : 1.85 billion |
| Spot price instead of TWAP | ~7,400 gas | $34M (Harvest) | 1 : 4.6 billion |
| Unsafe storage caching | ~4,200 gas | $8M+ (bZx) | 1 : 1.9 billion |
| Unbounded `unchecked` blocks | ~120 gas | $1.1M (Level) | 1 : 9.2 billion |

Every entry in this table demonstrates the same truth: **no gas optimization justifies a security compromise**.

---

## Summary

| Principle | Implementation |
|-----------|----------------|
| **Prove Safety** | Every unchecked needs mathematical proof |
| **Validate Inputs** | Never skip validation for gas |
| **Bound Operations** | All loops must have explicit limits |
| **Safe Casts** | Always check before downcasting |
| **Test Edges** | Fuzz with max values specifically |

**Golden Rule**: The cheapest vulnerability is infinitely more expensive than any gas optimization. When in doubt, pay the gas.
