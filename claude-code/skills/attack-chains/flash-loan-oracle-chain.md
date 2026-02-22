# Attack Chain: Flash Loan + Oracle Manipulation

## Overview

Attacker uses a flash loan to temporarily distort an on-chain price oracle, then exploits a protocol that reads the manipulated price, all within a single transaction.

**Complexity:** Medium
**Typical Severity:** CRITICAL
**Protocols At Risk:** Lending protocols, DEXs, Vaults, Yield aggregators

---

## Attack Steps

```
FLASH LOAN → DISTORT PRICE → EXPLOIT PROTOCOL → REPAY LOAN → PROFIT
```

### Step 1: Flash Loan Acquisition
```
Borrow large amount of TokenA from flash loan provider
- Aave, dYdX, Uniswap V3, Balancer
- No collateral needed, repay in same tx
```

**What to check:**
- [ ] Does protocol interact with tokens available via flash loans?
- [ ] Is flash loan amount sufficient to move the oracle?

### Step 2: Oracle Distortion
```
Use borrowed tokens to manipulate price:
- Swap large amount on AMM → moves spot price
- Deposit/withdraw from pool → changes reserves
- Manipulate TWAP if window is short
```

**What to check:**
- [ ] Does protocol use spot price from AMM reserves?
- [ ] Is TWAP window < 30 minutes?
- [ ] Does protocol use single oracle source?
- [ ] Can oracle be manipulated with available liquidity?

### Step 3: Exploit the Protocol
```
With price distorted, interact with target protocol:
- Borrow against inflated collateral
- Liquidate positions using deflated prices
- Mint tokens at wrong exchange rate
- Withdraw more than deposited value
```

**What to check:**
- [ ] Does protocol read price during user interaction?
- [ ] Is price used for minting/burning/borrowing/liquidating?
- [ ] Are there any price deviation checks?
- [ ] Is there a delay between price read and action?

### Step 4: Repay and Extract
```
- Reverse the price manipulation (swap back)
- Repay flash loan + fee
- Keep difference as profit
```

---

## Code Signals

### Signal: Spot Price Usage
```solidity
// [VULNERABLE] Using AMM reserves directly
function getPrice() public view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    return r1 * 1e18 / r0;  // Manipulable via flash loan
}
```

### Signal: Missing Oracle Validation
```solidity
// [VULNERABLE] No sanity check on price
function borrow(uint256 amount) external {
    uint256 collateralValue = getPrice() * collateral[msg.sender] / 1e18;
    require(collateralValue >= amount * LTV / 100);
    // Price could be inflated by flash loan
}
```

### Signal: Short TWAP Window
```solidity
// [VULNERABLE] 10-minute TWAP is too short
uint32 constant TWAP_PERIOD = 600;  // 10 minutes
```

---

## Real-World Examples

| Protocol | Loss | Oracle Manipulated | Year |
|----------|------|-------------------|------|
| Cream Finance | $130M | Spot price via flash loan | 2021 |
| Harvest Finance | $34M | Curve pool manipulation | 2020 |
| Mango Markets | $114M | Perp oracle manipulation | 2022 |
| Value DeFi | $6M | Curve pool spot price | 2020 |

---

## Detection Checklist

- [ ] Protocol uses on-chain price oracle (AMM-based)
- [ ] No multi-source oracle aggregation
- [ ] No price deviation bounds checking
- [ ] Flash loan tokens available for manipulation
- [ ] TWAP window is short (< 30 min)
- [ ] Large swap can meaningfully move price
- [ ] Protocol performs actions at oracle price in same tx
- [ ] No time delay between price read and action

---

## Mitigations

| Mitigation | Effectiveness |
|-----------|---------------|
| Use Chainlink/off-chain oracles | HIGH |
| Multi-source oracle aggregation | HIGH |
| TWAP with 30+ min window | MEDIUM |
| Price deviation circuit breakers | MEDIUM |
| Flash loan guards (check balance changes) | MEDIUM |
| Time delay on price-sensitive operations | LOW-MEDIUM |

---

## Related Patterns

- [Oracle Manipulation Patterns](../patterns/oracle-patterns.md)
- [Flash Loan Patterns](../patterns/flash-loan-patterns.md)
- [Chainlink Patterns](../patterns/chainlink-patterns.md)
- [Stale Price Patterns](../patterns/stale-price-patterns.md)
