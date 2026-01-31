---
id: CHECKLIST-DEX-AMM
title: DEX/AMM Protocol Audit Checklist
category: checklists
difficulty: intermediate
tags: [dex, amm, swap, liquidity, mev, slippage]
last_updated: 2026-01-31
---

# DEX/AMM Protocol Audit Checklist

Quick-reference checklist for auditing decentralized exchanges and automated market makers.

---

## 🔴 Critical Checks

### Price Manipulation
```
[ ] Can reserves be manipulated within one transaction?
[ ] Flash loan + swap attack possible?
[ ] Is TWAP used for external price queries?
[ ] Can single large trade manipulate price significantly?
[ ] Are oracle reads from this DEX protected?
```

### Swap Execution
```
[ ] Slippage protection enforced (minAmountOut)?
[ ] Deadline parameter checked?
[ ] Correct token amounts transferred in/out?
[ ] K (constant product) maintained after swap?
[ ] Are fees correctly deducted?
```

### Liquidity Provision
```
[ ] First LP attack possible (share inflation)?
[ ] Minimum liquidity locked (like Uni's MINIMUM_LIQUIDITY)?
[ ] Can LP tokens be minted for free?
[ ] Are reserves updated correctly?
[ ] Correct LP token amount calculation?
```

---

## 🟠 High Priority Checks

### MEV Protection
```
[ ] Sandwich attack possible?
[ ] Front-running profitable for attackers?
[ ] Is there commit-reveal for large trades?
[ ] Private mempool option available?
[ ] Does protocol have MEV protection integration?
```

### Reentrancy
```
[ ] CEI pattern followed in swaps?
[ ] Reentrancy guards on all entry points?
[ ] ERC-777/ERC-721/ERC-1155 callback attacks?
[ ] Read-only reentrancy on price functions?
[ ] Cross-function reentrancy between swap/add/remove?
```

### Fee Handling
```
[ ] Fees correctly calculated?
[ ] Fee-on-transfer tokens handled?
[ ] Protocol fees vs LP fees separated?
[ ] Can fees be set to 100%?
[ ] Fee accumulation overflow possible?
```

---

## 🟡 Medium Priority Checks

### Pool Creation
```
[ ] Anyone can create pools?
[ ] Duplicate pools prevented?
[ ] Malicious token pairs filtered?
[ ] Initial price manipulation on creation?
[ ] Pool initialization front-running?
```

### Token Compatibility
```
[ ] Rebasing tokens handled?
[ ] Fee-on-transfer tokens?
[ ] Tokens with 0 decimals?
[ ] Tokens with >18 decimals?
[ ] Tokens with multiple addresses (proxies)?
[ ] Pausable tokens?
[ ] Blocklist tokens (USDC, USDT)?
```

### Concentrated Liquidity (Uni V3 Style)
```
[ ] Tick math correct?
[ ] Position boundaries validated?
[ ] Liquidity correctly tracked per tick?
[ ] Out-of-range positions handled?
[ ] Tick crossing logic correct?
```

---

## 🟢 Standard Checks

### Math & Precision
```
[ ] Correct multiplication before division?
[ ] Sqrt calculation safe?
[ ] Overflow in reserve calculations?
[ ] Precision loss in fee calculations?
[ ] Minimum output amounts reasonable?
```

### Access Control
```
[ ] Who can pause swaps?
[ ] Who can update fees?
[ ] Who can add/remove tokens?
[ ] Factory owner privileges?
[ ] Pool upgrade mechanisms?
```

### Flash Functionality
```
[ ] Flash loan fee enforced?
[ ] Flash loan repayment verified?
[ ] Flash swap callback validated?
[ ] Reentrancy during flash operations?
```

---

## Common Vulnerability Patterns

### 1. Sandwich Attack
```solidity
// Attack flow in same block:
// 1. Attacker buys (price goes up)
// 2. Victim buys at higher price
// 3. Attacker sells (profits from victim)

// PROTECTION: Tight slippage
function swap(uint amountIn, uint minAmountOut) {
    require(amountOut >= minAmountOut, "Slippage");
}
```

### 2. Price Oracle Manipulation
```solidity
// VULNERABLE: Spot price
function getPrice() external view returns (uint256) {
    return reserve1 / reserve0; // Can be manipulated
}

// SECURE: TWAP
function getPrice() external view returns (uint256) {
    return oracle.consult(token, 30 minutes);
}
```

### 3. First LP Attack
```solidity
// VULNERABLE: No minimum liquidity
function mint() external {
    liquidity = sqrt(amount0 * amount1);
    _mint(to, liquidity);
}

// SECURE: Lock minimum liquidity
function mint() external {
    liquidity = sqrt(amount0 * amount1);
    if (totalSupply == 0) {
        _mint(address(0), MINIMUM_LIQUIDITY); // Lock forever
        liquidity -= MINIMUM_LIQUIDITY;
    }
    _mint(to, liquidity);
}
```

### 4. Reentrancy via Token Callbacks
```solidity
// VULNERABLE: Update after transfer
function swap(uint amountOut) external {
    token.transfer(to, amountOut); // ERC-777 callback!
    reserve -= amountOut; // Too late
}

// SECURE: CEI pattern
function swap(uint amountOut) external nonReentrant {
    reserve -= amountOut;
    token.transfer(to, amountOut);
}
```

---

## AMM Type-Specific Checks

### Constant Product (x * y = k)
```
[ ] K value increases only from fees?
[ ] Swap maintains K invariant?
[ ] Arbitrage possible to restore K?
```

### Stable Swap (Curve Style)
```
[ ] Amplification factor bounded?
[ ] A parameter change timing safe?
[ ] Imbalanced pool handling?
[ ] Virtual price manipulation?
```

### Concentrated Liquidity
```
[ ] Position NFT ownership correct?
[ ] Fee collection per position?
[ ] Tick bitmap updates correct?
[ ] Global vs position-specific state?
```

### Weighted Pools (Balancer Style)
```
[ ] Weight sum = 100%?
[ ] Weight changes gradual?
[ ] Invariant calculation correct?
```

---

## Integration Patterns

### Router Checks
```
[ ] Path validation correct?
[ ] Multi-hop slippage accumulated correctly?
[ ] Native token (ETH) wrapping/unwrapping?
[ ] Deadline passed to all swaps?
[ ] Leftover tokens returned to user?
```

### Permit Integration
```
[ ] Permit2 vs legacy permit?
[ ] Signature replay prevention?
[ ] Deadline in permit checked?
[ ] Allowance correctly set?
```

---

## Quick Reference Formulas

```
Constant Product AMM:
x * y = k (invariant)
amountOut = (amountIn * reserveOut) / (reserveIn + amountIn)
price = reserveY / reserveX

With 0.3% fee:
amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)

Price Impact = (newPrice - oldPrice) / oldPrice * 100%

LP Tokens:
shares = min(amount0 * totalSupply / reserve0, amount1 * totalSupply / reserve1)
```

---

## Red Flags 🚩

- [ ] No slippage protection parameter
- [ ] No deadline parameter
- [ ] Spot price used as oracle
- [ ] No minimum liquidity on first mint
- [ ] Fee-on-transfer tokens ignored
- [ ] Single-token deposit without safeguards
- [ ] No reentrancy protection
- [ ] Price can move >10% in one tx
- [ ] No MEV protection discussion in docs
