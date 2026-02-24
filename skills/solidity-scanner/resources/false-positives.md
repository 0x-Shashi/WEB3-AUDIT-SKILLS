---
id: solidity-false-positives
title: Common False Positives in Solidity Audits
category: resource
parent_skill: solidity-scanner/SKILL.md
description: >
  Catalog of patterns that appear vulnerable but are actually safe,
  with detailed reasoning for each. Use this to avoid wasting time
  on non-issues and to defend dismissals in audit reports.
tags:
  - solidity
  - false-positives
  - audit
  - verification
last_updated: 2026-02-24
---

# Common False Positives in Solidity Audits

## Why This Matters

False positives waste auditor time and erode credibility. Understanding why a pattern is safe is just as important as knowing when it's dangerous. For each pattern below, the **reasoning** explains exactly why it's not exploitable.

---

## Reentrancy False Positives

### 1. Read-Only External Call (No State Change After)

```solidity
// FALSE POSITIVE: balanceOf is a view function, no callback
uint256 balance = IERC20(token).balanceOf(address(this));
shares = balance * totalShares / totalDeposited;
```

**Why safe**: `balanceOf()` is a `view` function that does not execute arbitrary code. It cannot trigger a callback to re-enter the contract. The external call is read-only.

**Exception**: If the token is a non-standard ERC20 with a malicious `balanceOf`, this could be dangerous. Only a false positive when the token is known/whitelisted.

### 2. Trusted Protocol Calls

```solidity
// FALSE POSITIVE: WETH.deposit() is a well-audited protocol with no callback
IWETH(WETH).deposit{value: msg.value}();
userBalance += msg.value;
```

**Why safe**: WETH's `deposit()` is a simple function that does not trigger callbacks. Calling audited, widely-used protocol functions like WETH or DAI Savings Rate is generally safe against reentrancy.

**Exception**: If the protocol was forked and modified, it may have different behavior. Verify it's the canonical deployment.

### 3. nonReentrant Modifier Already Present

```solidity
// FALSE POSITIVE: ReentrancyGuard prevents re-entry
function withdraw(uint256 amount) external nonReentrant {
    token.safeTransfer(msg.sender, amount);
    balances[msg.sender] -= amount;
}
```

**Why safe**: The `nonReentrant` modifier from OpenZeppelin sets a lock before execution and checks it on entry. Even though CEI is violated, the reentrancy guard prevents re-entry.

**Exception**: Cross-contract reentrancy — if the attacker re-enters a *different* contract that reads stale state from this one, `nonReentrant` on this contract doesn't help.

### 4. Transfer to msg.sender Without Callback Opportunity

```solidity
// FALSE POSITIVE: Standard ERC20 transfer has no callback to msg.sender
IERC20(USDC).safeTransfer(msg.sender, amount);
balances[msg.sender] -= amount;
```

**Why safe**: Standard ERC20 `transfer` does not call any hooks on the recipient. Unlike ERC777 (which has `tokensReceived`) or ERC721 (`onERC721Received`), ERC20 transfers are non-callback.

**Exception**: ERC777 tokens masquerading as ERC20 (e.g., some wrapped tokens). Verify the token contract does not implement ERC777.

### 5. ETH Transfer via transfer() or send()

```solidity
// PARTIAL FALSE POSITIVE: 2300 gas stipend limits what callback can do
payable(msg.sender).transfer(amount);
balances[msg.sender] -= amount;
```

**Why mostly safe**: `transfer()` forwards only 2300 gas, insufficient for most reentrancy attacks (can't write to storage). However, this is NOT future-proof — EIP-1884 changed gas costs, and future EIPs could make 2300 gas sufficient for an attack.

**Recommendation**: Still flag as informational. Prefer CEI pattern regardless.

---

## Access Control False Positives

### 6. Admin Functions That Are Intended Design

```solidity
// FALSE POSITIVE (usually): Emergency pause is desired functionality
function pause() external onlyOwner {
    _pause();
}
```

**Why safe**: Emergency pause capability is a standard security feature, not a vulnerability. The owner *should* be able to pause in emergencies.

**When it IS a finding**: If the owner is an EOA (not multisig), or if `pause()` can lock user funds indefinitely with no escape hatch, report as centralization risk (Medium).

### 7. Constructor-Initialized Immutables

```solidity
// FALSE POSITIVE: Set once, never changeable
constructor(address _oracle) {
    oracle = _oracle; // Immutable after deployment
}
```

**Why safe**: Constructor-set values cannot be changed after deployment. No need for ongoing access control checks. If the variable is `immutable`, it's stored in bytecode, not storage.

### 8. Internal/Private Functions Without Access Control

```solidity
// FALSE POSITIVE: Internal function can't be called externally
function _updatePrice(uint256 newPrice) internal {
    price = newPrice;
}
```

**Why safe**: `internal` and `private` functions cannot be called by external accounts. They can only be reached through public/external entry points, which should have their own access control.

**Exception**: If the function is called via `delegatecall` from a proxy, the access control context changes.

### 9. Functions That Only Read State

```solidity
// FALSE POSITIVE: View function can't modify state
function getBalance(address user) external view returns (uint256) {
    return balances[user]; // No access control needed for reading
}
```

**Why safe**: `view` functions cannot modify state. Even if an attacker calls them, no harm can result. Access control on view functions is only needed for privacy (which Solidity doesn't provide on-chain anyway).

---

## Integer Math False Positives

### 10. Intentional Unchecked for Gas Optimization

```solidity
// FALSE POSITIVE: Loop counter cannot overflow
for (uint256 i = 0; i < length; i++) {
    unchecked { ++i; } // Counter bounded by length, can't overflow uint256
}

// FALSE POSITIVE: Subtraction guaranteed safe by prior check
unchecked {
    balance = balance - amount; // Safe: require(balance >= amount) above
}
```

**Why safe**: When a prior `require` statement guarantees no underflow/overflow, using `unchecked` is a valid gas optimization. The Solidity compiler adds overflow checks that cost gas — removing them when mathematically unnecessary is a best practice.

**When it IS a finding**: If the prior check is missing or insufficient, or if the relationship between the check and the `unchecked` block is non-obvious.

### 11. Safe Casting from Known-Bounded Values

```solidity
// FALSE POSITIVE: decimals() returns uint8 (0–255), fits in uint8
uint8 decimals = uint8(IERC20(token).decimals());

// FALSE POSITIVE: Percentage always 0–100
uint8 utilization = uint8(totalBorrowed * 100 / totalSupply);
```

**Why safe**: When the input value is mathematically guaranteed to fit in the target type, the cast is safe. `decimals()` returns `uint8` by standard, so casting to `uint8` is identity.

**When it IS a finding**: If the return type could be larger than expected (non-standard token returning uint256 from `decimals()`).

### 12. Rounding in Protocol's Favor

```solidity
// FALSE POSITIVE: Rounding down on deposit = protocol keeps the dust
shares = assets * totalSupply / totalAssets; // Rounds down

// FALSE POSITIVE: Rounding down on withdrawal = protocol keeps the dust  
assets = shares * totalAssets / totalSupply; // Rounds down
```

**Why safe**: When both deposit and withdrawal round down (floor), the protocol retains dust. This is the conservative approach — the protocol never overpays. 

**When it IS a finding**: If deposit rounds UP (user gets more shares than they should) or withdrawal rounds UP (user gets more assets than they should).

---

## Token Integration False Positives

### 13. Fee-on-Transfer with Known Token

```solidity
// FALSE POSITIVE: USDC/DAI/WETH do not have transfer fees
function deposit(uint256 amount) external {
    IERC20(USDC).safeTransferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount; // Safe because USDC has no fee
}
```

**Why safe**: If the protocol only supports specific, known tokens (USDC, DAI, WETH), and those tokens do not have transfer fees, the standard pattern is safe.

**When it IS a finding**: If the protocol accepts arbitrary/user-supplied tokens, or if the token list can be extended by governance without fee-on-transfer checks.

### 14. Approve Race Condition on Non-USDT Tokens

```solidity
// FALSE POSITIVE for most tokens: approve race only affects USDT
IERC20(DAI).approve(spender, amount);
```

**Why safe**: The approve race condition (requiring `approve(0)` before `approve(newAmount)`) only exists in USDT. Standard ERC20 tokens like DAI, USDC, WETH allow direct approve changes.

**When it IS a finding**: If the protocol handles USDT or unknown tokens. Use `forceApprove()` (OZ 5.x) or `safeApprove(0)` then `safeApprove(amount)`.

---

## Oracle False Positives

### 15. Chainlink Price with Adequate Staleness Check

```solidity
// FALSE POSITIVE: All staleness checks present
(uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) 
    = priceFeed.latestRoundData();
require(answer > 0, "Invalid price");
require(updatedAt >= block.timestamp - HEARTBEAT, "Stale");
require(answeredInRound >= roundId, "Stale round");
```

**Why safe**: All three staleness checks are present — `answer > 0`, `updatedAt` freshness, and round completeness. This is the correct usage pattern.

### 16. Protocol-Controlled Oracle

```solidity
// PARTIAL FALSE POSITIVE: Admin-set price can't be flash-loan manipulated
function setPrice(uint256 _price) external onlyOracle {
    price = _price;
}
```

**Why safe from flash loans**: A protocol-controlled oracle cannot be manipulated within a single transaction via flash loans. The price is set by a trusted off-chain process.

**Why it may still be a finding**: Centralization risk — the oracle operator can set arbitrary prices. Report as centralization concern (Medium), not oracle manipulation (High).

---

## Proxy / Upgrade False Positives

### 17. Storage Gap Present

```solidity
// FALSE POSITIVE: Gap slots reserved for future expansion
contract BaseContract {
    uint256 public value;
    uint256[49] private __gap; // 49 slots reserved
}
```

**Why safe**: The `__gap` pattern reserves storage slots for future upgrades, preventing collision when new variables are added.

### 18. disableInitializers in Constructor

```solidity
// FALSE POSITIVE: Implementation cannot be initialized
constructor() {
    _disableInitializers();
}
```

**Why safe**: `_disableInitializers()` in the constructor sets the initialized flag to `type(uint64).max` on the implementation contract, preventing anyone from calling `initialize()` directly on the implementation.

---

## How to Handle False Positives

### In Your Audit Report

```markdown
## False Positive Documentation

### FP-01: Reentrancy in withdraw() — Dismissed
**Reason**: nonReentrant modifier present on line 45
**Verification**: Confirmed ReentrancyGuard imported from OZ 4.9.3
**Risk**: Cross-contract reentrancy checked — not applicable (no callback tokens)

### FP-02: Unchecked return in transfer() — Dismissed
**Reason**: Using SafeERC20.safeTransfer on line 89
**Verification**: Confirmed import and `using SafeERC20 for IERC20` declaration
```

### Decision Framework

```
Pattern flagged by tool →
  Is the pattern actually present? (check code, not just grep match)
    NO → False positive (code mismatch)
    YES → Is it reachable by untrusted caller?
      NO → False positive (unreachable)
      YES → Is there existing mitigation?
        YES → False positive (mitigated) — but document the mitigation
        NO → TRUE POSITIVE — report as finding
```

### Golden Rule

**Never dismiss without documenting the reason.** Even if you're confident it's a false positive, write down *why*. Future reviewers (including yourself) will need this context.
