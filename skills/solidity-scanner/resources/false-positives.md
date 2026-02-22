# Common False Positives in Solidity Audits

## Reentrancy False Positives

### 1. Reentrancy on Non-State-Changing Calls
```solidity
// FALSE POSITIVE: Read-only call, no state change after
uint256 balance = IERC20(token).balanceOf(address(this));
// No vulnerable state update follows
```

### 2. Trusted External Calls
```solidity
// FALSE POSITIVE: Calling known, audited protocol (e.g., WETH)
IWETH(WETH).deposit{value: msg.value}();
// WETH deposit is safe, no callback
```

### 3. ReentrancyGuard Already Present
```solidity
// FALSE POSITIVE: Function has nonReentrant modifier
function withdraw() external nonReentrant { ... }
```

## Access Control False Positives

### 1. Admin Actions That Are Accepted Risk
```solidity
// Often flagged as "centralization risk" but is intended design
function pause() external onlyOwner { _pause(); }
// This IS the intended behavior for emergency stops
```

### 2. Constructor-Only Setup
```solidity
// FALSE POSITIVE: Set once in constructor, never changeable
constructor(address _oracle) {
    oracle = _oracle; // Immutable after deployment
}
```

## Integer Math False Positives

### 1. Intentional Unchecked for Gas Optimization
```solidity
// FALSE POSITIVE: Loop counter can't overflow
unchecked { ++i; } // In a bounded for loop
```

### 2. Safe Casting from Bounded Values
```solidity
// FALSE POSITIVE: Value known to be small
uint8 decimals = uint8(IERC20(token).decimals()); // Always 0-255
```

## How to Handle
1. Document each false positive with reasoning
2. Distinguish "accepted risk" from "not a bug"
3. If in doubt, report as informational
4. Don't skip flagged items - verify each one manually
