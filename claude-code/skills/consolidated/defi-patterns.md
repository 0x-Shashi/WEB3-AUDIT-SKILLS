# Consolidated: DeFi Patterns

## Overview

DeFi protocols share common vulnerability patterns across lending, DEXs, yield aggregators, and derivatives. This consolidates the most critical DeFi-specific patterns.

---

## Price Manipulation Patterns

### 1. Oracle Manipulation
```solidity
// [VULNERABLE] Using spot price from DEX
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // Flash loan manipulable!
}

// [SAFE] Chainlink oracle with staleness check
function getPrice() public view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    require(block.timestamp - updatedAt < HEARTBEAT, "Stale price");
    return uint256(price);
}
```

### 2. TWAP Manipulation
```solidity
// TWAP is safer but not immune:
// - Low liquidity pools: cheaper to manipulate
// - Short TWAP window: easier to skew
// - Multi-block MEV: sustained price influence

// Minimum recommended: 30-minute TWAP with liquidity threshold check
```

### 3. Donation Attack (Vault Inflation)
```solidity
// [VULNERABLE] Share price inflated by direct token transfer
function sharePrice() public view returns (uint256) {
    return totalAssets() / totalSupply; // totalAssets includes donated tokens!
}

// Attack flow:
// 1. Deposit 1 wei, get 1 share
// 2. Donate 1000 tokens directly to vault
// 3. Share price = 1001 tokens per share
// 4. Next depositor with < 1001 tokens gets 0 shares (rounding)
// 5. Attacker redeems 1 share for 1001 + victim's tokens

// [SAFE] Minimum initial deposit OR virtual shares
constructor() {
    _mint(address(0), 1000); // Dead shares prevent manipulation
}
```

---

## Lending Patterns

### 4. Liquidation Manipulation
```solidity
// Attack: Flash loan to trigger unfair liquidation
// 1. Flash loan large amount
// 2. Dump collateral token on DEX (crash price)
// 3. Liquidate target position at depressed price
// 4. Buy back collateral cheaply
// 5. Repay flash loan

// Mitigation: Use manipulation-resistant oracle (Chainlink, not DEX)
```

### 5. Interest Rate Manipulation
```solidity
// Attack: Manipulate utilization to spike borrow rate
// 1. Borrow large amount (increase utilization)
// 2. Interest rate jumps above kink
// 3. Other borrowers forced to pay high rates
// 4. Potential liquidation cascade

// [VULNERABLE] No utilization smoothing
function getBorrowRate(uint256 utilization) public view returns (uint256) {
    if (utilization > kink) {
        return baseRate + kink * multiplier + (utilization - kink) * jumpMultiplier;
        // Rate can spike dramatically
    }
}
```

### 6. Bad Debt Socialization
```solidity
// When liquidation doesn't cover debt:
// - Remaining debt = bad debt
// - Who absorbs it? LPs? Insurance fund? Protocol?
// - If socialized to LPs: bank run incentive

// [CHECK] Protocol has:
// - [ ] Bad debt handling mechanism
// - [ ] Insurance fund or reserve
// - [ ] Liquidation incentives sufficient for all collateral types
// - [ ] Dust position handling (too small to profitably liquidate)
```

---

## DEX/AMM Patterns

### 7. Sandwich Attack
```
Front-run → Victim Swap → Back-run
Profit = price impact from victim's swap

// Defense: User-controlled slippage + deadline
router.swapExactTokensForTokens(
    amountIn,
    amountOutMin,   // User sets this OFF-CHAIN
    path,
    recipient,
    deadline         // Prevents stale tx execution
);
```

### 8. Just-In-Time (JIT) Liquidity
```
1. Detect large swap in mempool
2. Add concentrated liquidity at exact price range
3. Large swap executes through your liquidity (earn fees)
4. Remove liquidity immediately after

// Impact: LPs earn less, MEV searcher captures fees
// Defense: Minimum liquidity provision period (if implemented)
```

### 9. Constant Product Invariant
```solidity
// x * y = k (must hold before and after swap)

// [CHECK] After every swap:
// newReserve0 * newReserve1 >= oldReserve0 * oldReserve1
// (Inequality because fees increase k)

// Common bug: fee calculation breaks invariant
// Common bug: rounding direction favors user over protocol
```

---

## Yield and Staking Patterns

### 10. Reward Manipulation
```solidity
// [VULNERABLE] Flash stake to claim rewards
function claim() external {
    uint256 reward = stakedBalance[msg.sender] * rewardRate;
    // Attacker: flash loan -> stake -> claim -> unstake -> repay
}

// [SAFE] Time-weighted rewards
function claim() external {
    uint256 reward = stakedBalance[msg.sender] * rewardRate * (block.timestamp - lastClaimTime[msg.sender]);
}
```

### 11. First Depositor Attack
```solidity
// Attack on vault/staking tokens:
// 1. Deposit 1 wei (get 1 share)
// 2. Transfer large amount directly (inflate share price)
// 3. Next depositor's amount rounds down to 0 shares
// 4. Withdraw all (including victim's deposit)

// Mitigations:
// - Virtual shares (dead shares minted to address(0))
// - Minimum first deposit
// - Share calculation: assets * totalSupply / totalAssets (with +1 offset)
```

### 12. Composability Risk
```solidity
// Risk: Protocol A's token used in Protocol B
// If Protocol A has a bug, Protocol B is also affected

// Example: Rebasing token as collateral
// - Token rebases up: collateral value increases but protocol doesn't know
// - Token rebases down: position underwater but appears fine

// [CHECK] Protocol handles:
// - [ ] Rebasing tokens
// - [ ] Fee-on-transfer tokens
// - [ ] Pausable tokens
// - [ ] Upgradeable tokens
// - [ ] Tokens with hooks (ERC-777)
```

---

## Real-World DeFi Exploits

| Protocol | Loss | Pattern | Year |
|----------|------|---------|------|
| Euler Finance | $197M | Donation + liquidation | 2023 |
| Mango Markets | $114M | Oracle manipulation | 2022 |
| Cream Finance | $130M | Flash loan + oracle | 2021 |
| Harvest Finance | $34M | Price manipulation (USDC/USDT) | 2020 |
| bZx | $8M | Flash loan + oracle | 2020 |
| Compound | $80M | Oracle precision error | 2022 |

---

## Related Files
- [DeFi Lending Checklist](../checklists/defi-lending-checklist.md)
- [DEX/AMM Checklist](../checklists/dex-amm-checklist.md)
- [Oracle Patterns](../patterns/oracle-patterns.md)
- [Flash Loan Chain](../attack-chains/flash-loan-oracle-chain.md)
- [Sandwich MEV Chain](../attack-chains/sandwich-mev-chain.md)
