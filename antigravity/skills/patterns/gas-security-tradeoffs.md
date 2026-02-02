# Gas-to-Security Tradeoff Matrix

## Overview

Gas optimizations are critical for DeFi protocols, but many introduce subtle security vulnerabilities. This guide maps common gas optimizations to their security implications.

> **Rule of Thumb:** Premature optimization is the root of all evil (and many exploits).

---

## 1. Complete Tradeoff Matrix

### 1.1 Arithmetic Optimizations

| Gas Optimization | Security Risk | Severity | When Safe | When Dangerous |
|-----------------|---------------|----------|-----------|----------------|
| `unchecked { }` math | Integer overflow/underflow | [C] Critical | Provably bounded values, loop counters | User input, token amounts, prices |
| Bit shifting instead of multiply/divide | Precision loss | [M] Medium | Power of 2 operations | Non-power-of-2 divisors |
| `>> 1` instead of `/ 2` | Off-by-one for odd numbers | [L] Low | Even numbers only | Odd number division |
| Pre-increment `++i` vs `i++` | None | [OK] Safe | Always | Never |
| `!= 0` vs `> 0` for uints | None | [OK] Safe | Always | Never |

```solidity
// [DANGEROUS]: Unchecked user input
function deposit(uint256 amount) external {
    unchecked {
        balances[msg.sender] += amount;  // Can overflow!
    }
}

// [SAFE]: Unchecked loop counter
for (uint256 i = 0; i < length;) {
    // ... loop body
    unchecked { ++i; }  // i is bounded by length
}

// [SAFE]: Unchecked subtraction after check
require(balances[msg.sender] >= amount);
unchecked {
    balances[msg.sender] -= amount;  // Can't underflow
}
```

---

### 1.2 Storage Optimizations

| Gas Optimization | Security Risk | Severity | When Safe | When Dangerous |
|-----------------|---------------|----------|-----------|----------------|
| Variable packing | Dirty upper bits | [M] Medium | Same-size types | Mixed sizes, inline assembly |
| Transient storage (`TSTORE`) | Cross-call state leakage | [C] Critical | Single transaction | Delegatecall, reentrancy |
| Skip zero-initialization | Non-zero defaults | [L] Low | Value types | Reference types, mappings |
| Immutable variables | None | [OK] Safe | Constants | Never |
| Short strings (<32 bytes) | None if no assembly | [OK] Safe | Standard access | Assembly string ops |

```solidity
// [DANGEROUS]: Variable packing with inline assembly
struct Packed {
    uint128 a;
    uint128 b;
}

function exploit(Packed storage p) external {
    assembly {
        // If upper bits dirty, this reads garbage
        let value := sload(p.slot)
    }
}

// [DANGEROUS]: Transient storage with reentrancy
function swap() external {
    assembly {
        tstore(0, caller())  // Set in transient storage
    }
    
    // External call - attacker reenters
    token.transfer(msg.sender, amount);
    
    assembly {
        let cached := tload(0)  // May not be original caller!
    }
}
```

---

### 1.3 Call Optimizations

| Gas Optimization | Security Risk | Severity | When Safe | When Dangerous |
|-----------------|---------------|----------|-----------|----------------|
| `call` over `transfer` | Reentrancy | [C] Critical | With reentrancy guard | No guard, CEI broken |
| Skip return value check | Silent failure | [C] Critical | Never safe | Always |
| Assembly `call` | All of the above + more | [C] Critical | Expert-reviewed code | General use |
| `staticcall` for views | None | [OK] Safe | Read-only operations | Never |
| Batched calls | First-failure DoS | [M] Medium | Try/catch each | Linear batch |

```solidity
// [DANGEROUS]: No return check
token.transfer(to, amount);  // Returns false on failure, doesn't revert

// [SAFE]: With SafeERC20
SafeERC20.safeTransfer(token, to, amount);

// [DANGEROUS]: Assembly call without full checks
assembly {
    let success := call(gas(), target, value, 0, 0, 0, 0)
    // Missing: returndatasize check, error bubbling
}

// [SAFE]: Assembly call with proper checks
assembly {
    let success := call(gas(), target, value, add(data, 0x20), mload(data), 0, 0)
    if iszero(success) {
        let size := returndatasize()
        returndatacopy(0, 0, size)
        revert(0, size)
    }
}
```

---

### 1.4 Validation Optimizations

| Gas Optimization | Security Risk | Severity | When Safe | When Dangerous |
|-----------------|---------------|----------|-----------|----------------|
| Skip zero-address check | Token burn, locked funds | [M] Medium | Token minting | Transfer recipients |
| Skip zero-amount check | Division by zero, DoS | [M] Medium | Validated upstream | Raw user input |
| Combine require statements | Unclear revert reason | [L] Low | Internal functions | User-facing functions |
| Custom errors over strings | None | [OK] Safe | Always | Never |
| Skip array length check | Out-of-bounds access | [C] Critical | Validated upstream | Raw user arrays |

```solidity
// [DANGEROUS]: Skipped zero check
function setPrice(uint256 newPrice) external {
    price = newPrice;  // Can set to 0
}

function calculateShares(uint256 amount) view returns (uint256) {
    return amount * 1e18 / price;  // Division by zero!
}

// [SAFE]: Zero validated upstream
function setPrice(uint256 newPrice) external {
    require(newPrice > 0, "Zero price");
    price = newPrice;
}

// Or in calculateShares if price could legitimately be 0:
function calculateShares(uint256 amount) view returns (uint256) {
    if (price == 0) return 0;  // Graceful handling
    return amount * 1e18 / price;
}
```

---

### 1.5 Loop Optimizations

| Gas Optimization | Security Risk | Severity | When Safe | When Dangerous |
|-----------------|---------------|----------|-----------|----------------|
| Unbounded loops | DoS via gas exhaustion | [C] Critical | Never | Always |
| Cache array length | None | [OK] Safe | Always | Never |
| Process in batches | Incomplete processing | [M] Medium | With continuation | One-shot operations |
| `pop()` instead of `delete` | Order dependency bugs | [M] Medium | Order doesn't matter | Ordered data |

```solidity
// [DANGEROUS]: Unbounded loop
function distributeRewards(address[] calldata users) external {
    for (uint256 i = 0; i < users.length; i++) {
        // Attacker adds 10000 users → out of gas
        _sendReward(users[i]);
    }
}

// [SAFE]: Bounded with pagination
uint256 public constant MAX_BATCH = 100;

function distributeRewards(
    address[] calldata users,
    uint256 startIndex
) external returns (uint256 nextIndex) {
    uint256 end = min(startIndex + MAX_BATCH, users.length);
    
    for (uint256 i = startIndex; i < end;) {
        _sendReward(users[i]);
        unchecked { ++i; }
    }
    
    return end < users.length ? end : 0;
}
```

---

### 1.6 Encoding Optimizations

| Gas Optimization | Security Risk | Severity | When Safe | When Dangerous |
|-----------------|---------------|----------|-----------|----------------|
| `abi.encodePacked` | Hash collision | [C] Critical | Fixed-size types only | Dynamic types |
| Skip ABI encoding | Malformed calldata | [C] Critical | Never | Always |
| Tight packing for hashing | Collision with similar data | [M] Medium | Unique structure | User-controlled strings |

```solidity
// [DANGEROUS]: Hash collision possible
function verify(string memory a, string memory b) pure returns (bytes32) {
    // "ab" + "c" == "a" + "bc" → same hash!
    return keccak256(abi.encodePacked(a, b));
}

// [SAFE]: With separator or abi.encode
function verify(string memory a, string memory b) pure returns (bytes32) {
    return keccak256(abi.encode(a, b));  // Includes length prefixes
}
```

---

## 2. Quick Reference Card

### [C] Never Skip These Checks (Security > Gas)

```solidity
// Always check these:
require(success, "Call failed");              // External call return
require(amount > 0, "Zero amount");           // Division denominators
require(to != address(0), "Zero address");    // Transfer recipients
require(i < array.length, "Out of bounds");   // Array access
require(deadline >= block.timestamp, "Expired"); // Time-sensitive ops
```

### [M] Context-Dependent Optimizations

```solidity
// Safe with guards:
unchecked { ++i; }                // In bounded loops
call{value: amount}("");          // With reentrancy guard

// Safe with upstream validation:
unchecked { a - b; }              // After require(a >= b)
x / y;                            // After require(y > 0)
```

### [OK] Always Safe Optimizations

```solidity
++i;                              // Pre-increment
!= 0                              // Zero comparison
immutable                         // Constant values
constant                          // Compile-time constants
custom errors                     // Error() over require("")
```

---

## 3. Gas Savings vs Risk Assessment

| Optimization | Gas Saved | Risk Level | Recommendation |
|-------------|-----------|------------|----------------|
| Custom errors | ~50-200 | None | [OK] Always use |
| Immutable vars | ~2100 per read | None | [OK] Always use |
| Unchecked counters | ~40-80 per op | Low | [OK] Use in loops |
| Skip zero-checks | ~100-200 | Medium-High | [!] Only with upstream validation |
| Assembly calls | ~200-500 | Very High | [X] Avoid unless expert |
| abi.encodePacked | ~100-300 | High | [!] Fixed types only |

---

## 4. Audit Checklist for Gas Optimizations

When reviewing gas-optimized code:

- [ ] All `unchecked` blocks have documented invariants
- [ ] No unchecked blocks with user-controlled values
- [ ] All external call return values checked
- [ ] No `abi.encodePacked` with dynamic types for hashing
- [ ] Loops have explicit bounds
- [ ] Zero-checks present before division
- [ ] Transfer recipients validated
- [ ] Assembly code thoroughly reviewed

---

## Related

- [Solidity Anti-Patterns](patterns/solidity-antipatterns.md)
- [Arithmetic Attack Tree](attack-trees/arithmetic-attack-tree.md)
- [Fix Verification Patterns](fix-patterns/INDEX.md)
