---
id: PROTOCOL-GMX
title: GMX Security Playbook
category: protocol-playbook
protocol: gmx
difficulty: advanced
tags: [perpetuals, leverage, oracle, trading, arbitrum]
last_updated: 2026-01-31
---

# GMX Security Playbook

> **Attack Surface:** See [attack-trees/perpetuals-attack-tree.md](../attack-trees/perpetuals-attack-tree.md)

## Protocol Overview

GMX is a decentralized perpetual exchange offering up to 50x leverage. It uses a unique model with a multi-asset liquidity pool (GLP) and oracle-based pricing.

## Architecture

| Component | Description | Key Risks |
|-----------|-------------|-----------|
| Vault | Holds all assets | Oracle manipulation |
| Router | User entry point | Access control |
| PositionRouter | Async position management | Keeper MEV |
| OrderBook | Limit orders | Execution timing |
| GLP | Liquidity token | Depeg, utilization |
| Keepers | Execute orders | Front-running |

## Critical Security Areas

### 1. Oracle Manipulation

GMX uses a combination of Chainlink and custom pricing.

```solidity
// GMX price feed system:
// - Primary: Chainlink
// - Secondary: Custom fast price feed
// - Spread: Protects against manipulation

// VULNERABLE - Assuming price feed is always accurate
contract GMXIntegration {
    function getPositionValue() external view returns (uint256) {
        // getMaxPrice/getMinPrice should be used appropriately
        uint256 price = vault.getMaxPrice(token);  // Wrong for shorts!
        return positionSize * price;
    }
}

// SECURE - Use appropriate price based on position
contract SafeGMXIntegration {
    function getPositionValue(bool isLong) external view returns (uint256) {
        // Longs use min price (conservative for user)
        // Shorts use max price (conservative for user)
        uint256 price = isLong 
            ? vault.getMinPrice(token) 
            : vault.getMaxPrice(token);
        return positionSize * price;
    }
}
```

### 2. Position Keeper Front-Running

Positions are executed by keepers, creating MEV opportunities.

```solidity
// Position execution flow:
// 1. User calls createIncreasePosition
// 2. Request stored in PositionRouter
// 3. Keeper calls executeIncreasePosition
// 4. Position opened at execution price

// VULNERABLE - No slippage protection
contract TradeBot {
    function openLong(uint256 size) external {
        // Attacker sees this in mempool
        // Attacker front-runs with large position
        // Price moves against user
        positionRouter.createIncreasePosition{value: executionFee}(
            path,
            indexToken,
            size,
            0,  // minOut = 0 is DANGEROUS
            size * leverage,
            true,  // isLong
            0,     // acceptablePrice = 0 is DANGEROUS
            executionFee,
            referralCode,
            callbackTarget
        );
    }
}

// SECURE - Strict slippage protection
contract SafeTradeBot {
    function openLong(
        uint256 size,
        uint256 acceptablePrice,
        uint256 minOut
    ) external {
        // Get current price
        uint256 currentPrice = vault.getMaxPrice(indexToken);
        
        // Set acceptable price with slippage (0.3% example)
        if (acceptablePrice == 0) {
            acceptablePrice = currentPrice * 1003 / 1000;
        }
        
        positionRouter.createIncreasePosition{value: executionFee}(
            path,
            indexToken,
            size,
            minOut,  // Protect against swap slippage
            size * leverage,
            true,
            acceptablePrice,  // Position won't open above this
            executionFee,
            referralCode,
            callbackTarget
        );
    }
}
```

### 3. GLP Manipulation

GLP holders are counterparty to all trades.

```solidity
// GLP value depends on:
// - Underlying asset prices
// - Trader PnL
// - Utilization

// ATTACK: Manipulate GLP price by moving markets

// VULNERABLE - Calculating GLP value naively
contract GLPLender {
    function getGLPValue(uint256 glpAmount) external view returns (uint256) {
        // AUM can be manipulated by large trades
        uint256 aum = glpManager.getAum(true);  // Maximize
        uint256 glpSupply = glp.totalSupply();
        
        return glpAmount * aum / glpSupply;
    }
}

// SECURE - Use time-weighted or bounded values
contract SafeGLPLender {
    uint256 public lastAum;
    uint256 public lastUpdate;
    
    function getGLPValue(uint256 glpAmount) external view returns (uint256) {
        uint256 currentAum = glpManager.getAum(true);
        
        // Bound AUM change (max 5% per hour)
        uint256 timeDelta = block.timestamp - lastUpdate;
        uint256 maxChange = lastAum * 5 * timeDelta / (100 * 1 hours);
        
        uint256 boundedAum;
        if (currentAum > lastAum + maxChange) {
            boundedAum = lastAum + maxChange;
        } else if (currentAum < lastAum - maxChange) {
            boundedAum = lastAum - maxChange;
        } else {
            boundedAum = currentAum;
        }
        
        uint256 glpSupply = glp.totalSupply();
        return glpAmount * boundedAum / glpSupply;
    }
}
```

### 4. Liquidation Risks

```solidity
// GMX liquidation occurs when:
// losses + fees > collateral * (100% - marginFeeBps - liquidationFeeUsd)

// VULNERABLE - Not tracking liquidation risk
contract LeverageBot {
    function isPositionSafe(address account) external view returns (bool) {
        // Doesn't account for fees!
        (uint256 size, uint256 collateral,,,,,,) = vault.getPosition(
            account, collateralToken, indexToken, isLong
        );
        
        return collateral > size / maxLeverage;  // Wrong calculation
    }
}

// SECURE - Full liquidation check
contract SafeLeverageBot {
    function getPositionHealth(
        address account,
        address collateralToken,
        address indexToken,
        bool isLong
    ) external view returns (uint256 healthFactor) {
        (
            uint256 size,
            uint256 collateral,
            uint256 averagePrice,
            uint256 entryFundingRate,
            ,
            ,
            ,
            uint256 lastIncreasedTime
        ) = vault.getPosition(account, collateralToken, indexToken, isLong);
        
        if (size == 0) return type(uint256).max;
        
        // Calculate current PnL
        uint256 price = isLong 
            ? vault.getMinPrice(indexToken) 
            : vault.getMaxPrice(indexToken);
        
        bool hasProfit;
        uint256 delta;
        
        if (isLong) {
            hasProfit = price > averagePrice;
            delta = hasProfit 
                ? size * (price - averagePrice) / averagePrice
                : size * (averagePrice - price) / averagePrice;
        } else {
            hasProfit = averagePrice > price;
            delta = hasProfit
                ? size * (averagePrice - price) / averagePrice
                : size * (price - averagePrice) / averagePrice;
        }
        
        // Calculate fees
        uint256 fundingFee = vault.getFundingFee(
            account, collateralToken, indexToken, isLong, size, entryFundingRate
        );
        uint256 positionFee = vault.getPositionFee(size);
        
        // Calculate remaining collateral
        int256 remainingCollateral = int256(collateral);
        if (hasProfit) {
            remainingCollateral += int256(delta);
        } else {
            remainingCollateral -= int256(delta);
        }
        remainingCollateral -= int256(fundingFee + positionFee);
        
        if (remainingCollateral <= 0) return 0;
        
        // Health factor: remainingCollateral / liquidationThreshold
        uint256 liquidationThreshold = size * vault.liquidationFeeBps() / 10000 
            + vault.liquidationFeeUsd();
        
        return uint256(remainingCollateral) * 10000 / liquidationThreshold;
    }
}
```

### 5. Funding Rate Exploitation

```solidity
// Funding rates balance long/short exposure
// Can be exploited for profit

// ATTACK: 
// 1. Check funding rate direction
// 2. Open position in favorable direction
// 3. Collect funding payments
// 4. Close when rates change

// Monitor funding rates:
function getFundingInfo(address token) external view returns (
    uint256 fundingRateFactor,
    uint256 cumulativeFundingRate
) {
    fundingRateFactor = vault.fundingRateFactor();
    cumulativeFundingRate = vault.cumulativeFundingRates(token);
}
```

### 6. Order Book Manipulation

```solidity
// Limit orders can be front-run or manipulated

// VULNERABLE - Obvious order placement
contract OrderBot {
    function placeLimitOrder(
        uint256 triggerPrice,
        uint256 size
    ) external {
        // Attackers can see order and manipulate price to trigger
        orderBook.createIncreaseOrder{value: executionFee}(
            path,
            amountIn,
            indexToken,
            minOut,
            size,
            collateralToken,
            isLong,
            triggerPrice,
            triggerAboveThreshold,
            executionFee,
            false
        );
    }
}

// MITIGATION: Use private transactions or split orders
```

## Audit Checklist

```
[ ] Price feed usage (min vs max) appropriate for position type
[ ] Slippage protection on all position operations
[ ] Acceptable price set appropriately
[ ] Funding rate costs calculated
[ ] Liquidation threshold correctly computed
[ ] GLP AUM manipulation considered
[ ] Keeper execution timing risks assessed
[ ] Order visibility and front-running considered
[ ] Fee calculations complete
[ ] Leverage limits enforced
```

## Integration Patterns

### Safe Position Opening
```solidity
function safeOpenPosition(
    address[] memory path,
    address indexToken,
    uint256 amountIn,
    uint256 sizeDelta,
    bool isLong,
    uint256 maxSlippageBps
) external {
    // Calculate acceptable price
    uint256 currentPrice = isLong 
        ? vault.getMaxPrice(indexToken) 
        : vault.getMinPrice(indexToken);
    
    uint256 acceptablePrice = isLong
        ? currentPrice * (10000 + maxSlippageBps) / 10000
        : currentPrice * (10000 - maxSlippageBps) / 10000;
    
    // Calculate minimum output from swap
    uint256 minOut = amountIn * (10000 - maxSlippageBps) / 10000;
    
    positionRouter.createIncreasePosition{value: executionFee}(
        path,
        indexToken,
        amountIn,
        minOut,
        sizeDelta,
        isLong,
        acceptablePrice,
        executionFee,
        bytes32(0),
        address(0)
    );
}
```

### Safe Position Closing
```solidity
function safeClosePosition(
    address[] memory path,
    address indexToken,
    uint256 collateralDelta,
    uint256 sizeDelta,
    bool isLong,
    uint256 maxSlippageBps
) external {
    uint256 currentPrice = isLong 
        ? vault.getMinPrice(indexToken) 
        : vault.getMaxPrice(indexToken);
    
    uint256 acceptablePrice = isLong
        ? currentPrice * (10000 - maxSlippageBps) / 10000
        : currentPrice * (10000 + maxSlippageBps) / 10000;
    
    positionRouter.createDecreasePosition{value: executionFee}(
        path,
        indexToken,
        collateralDelta,
        sizeDelta,
        isLong,
        msg.sender,
        acceptablePrice,
        0,  // minOut (for closing, usually 0)
        executionFee,
        false,
        address(0)
    );
}
```

## Key Addresses (Arbitrum)

```solidity
// GMX V1 Arbitrum
address constant VAULT = 0x489ee077994B6658eAfA855C308275EAd8097C4A;
address constant ROUTER = 0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064;
address constant POSITION_ROUTER = 0xb87a436B93fFE9D75c5cFA7bAcFff96430b09868;
address constant ORDER_BOOK = 0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB;
address constant GLP = 0x4277f8F2c384827B5273592FF7CeBd9f2C1ac258;
address constant GLP_MANAGER = 0x321F653eED006AD1C29D174e17d96351BDe22649;
```
