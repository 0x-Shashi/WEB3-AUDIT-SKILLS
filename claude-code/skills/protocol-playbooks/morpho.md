---
id: PROTOCOL-MORPHO
title: Morpho Protocol Security Playbook
category: protocol-playbook
protocol: morpho
difficulty: advanced
tags: [lending, p2p, optimization, aave, compound, meta-protocol]
last_updated: 2026-01-31
---

# Morpho Protocol Security Playbook

> **Attack Surface:** See [attack-trees/lending-attack-tree.md](../attack-trees/lending-attack-tree.md)

## Protocol Overview

Morpho is a lending optimizer that sits on top of Aave and Compound, offering improved rates through peer-to-peer matching. Morpho Blue is their newer isolated markets protocol.

## Architecture

| Component | Description | Key Risks |
|-----------|-------------|-----------|
| Morpho-Aave | Optimizer on Aave V2/V3 | Compound risk |
| Morpho-Compound | Optimizer on Compound V2 | Compound risk |
| Morpho Blue | Standalone isolated markets | Oracle, liquidation |
| P2P Matching | Direct lender-borrower | Matching failure |

## Critical Security Areas

### 1. P2P Matching Vulnerabilities

```solidity
// Morpho matches lenders with borrowers directly for better rates
// Unmatched funds go to underlying pool (Aave/Compound)

// ATTACK: Matching manipulation
// Attacker could try to:
// 1. Game matching priority
// 2. Cause unmatch/rematch for profit
// 3. Sandwich P2P rate changes

// Key parameters:
// - p2pSupplyIndex: Index for P2P supply rate
// - p2pBorrowIndex: Index for P2P borrow rate
// - Delta: Funds in pool vs P2P

// VULNERABLE - Assuming all funds are P2P matched
contract WrongRateCalculator {
    function getExpectedRate(address market) external view returns (uint256) {
        // WRONG: Not all funds are P2P matched
        return morpho.p2pSupplyRate(market);
    }
}

// SECURE - Account for matching
contract CorrectRateCalculator {
    function getExpectedRate(
        address market,
        uint256 amount
    ) external view returns (uint256) {
        // Get current deltas
        (uint256 p2pSupply, uint256 poolSupply, , ) = morpho.market(market);
        
        // Calculate blend of P2P and pool rates
        uint256 p2pRate = morpho.p2pSupplyRate(market);
        uint256 poolRate = morpho.poolSupplyRate(market);
        
        uint256 totalSupply = p2pSupply + poolSupply;
        if (totalSupply == 0) return poolRate;
        
        // Weighted average
        return (p2pRate * p2pSupply + poolRate * poolSupply) / totalSupply;
    }
}
```

### 2. Morpho Blue Oracle Risks

Morpho Blue uses configurable oracles per market.

```solidity
// Morpho Blue market structure
struct MarketParams {
    address loanToken;
    address collateralToken;
    address oracle;         // Configurable oracle!
    address irm;           // Interest rate model
    uint256 lltv;          // Liquidation LTV
}

// CRITICAL: Oracle is market-specific, could be malicious

// VULNERABLE - Trusting any Morpho Blue market
contract TrustingIntegration {
    function getCollateralValue(
        MarketParams memory params,
        address user
    ) external view returns (uint256) {
        uint256 collateral = morpho.collateral(params.id(), user);
        // Oracle could be malicious!
        uint256 price = IOracle(params.oracle).price();
        return collateral * price;
    }
}

// SECURE - Validate oracle
contract SecureIntegration {
    mapping(address => bool) public trustedOracles;
    
    function getCollateralValue(
        MarketParams memory params,
        address user
    ) external view returns (uint256) {
        // Verify oracle is trusted
        require(trustedOracles[params.oracle], "Untrusted oracle");
        
        uint256 collateral = morpho.collateral(params.id(), user);
        uint256 price = IOracle(params.oracle).price();
        
        // Additional price validation
        require(price > 0 && price < MAX_REASONABLE_PRICE, "Invalid price");
        
        return collateral * price;
    }
}
```

### 3. Isolated Market Risks (Morpho Blue)

Each market is isolated - bad debt stays contained.

```solidity
// Morpho Blue market isolation:
// - Each market has its own risk parameters
// - Bad debt in one market doesn't affect others
// - BUT: Same collateral in multiple markets = correlated risk

// AUDIT CONSIDERATION: Cross-market collateral correlation
// If WETH is collateral in markets A, B, C:
// WETH price crash affects all three simultaneously

// Market creation is PERMISSIONLESS
// Anyone can create a market with any parameters

// VULNERABLE - Using any Morpho Blue market
contract AnyMarketUser {
    function deposit(Id marketId, uint256 amount) external {
        // Could be a malicious market!
        morpho.supply(marketId, amount, 0, msg.sender, "");
    }
}

// SECURE - Whitelist validated markets
contract SafeMarketUser {
    mapping(Id => bool) public validatedMarkets;
    
    function deposit(Id marketId, uint256 amount) external {
        require(validatedMarkets[marketId], "Market not validated");
        
        // Verify market parameters haven't changed (immutable in Blue)
        MarketParams memory params = morpho.idToMarketParams(marketId);
        require(trustedOracles[params.oracle], "Bad oracle");
        require(params.lltv <= MAX_LLTV, "LTV too high");
        
        morpho.supply(marketId, amount, 0, msg.sender, "");
    }
}
```

### 4. Liquidation Mechanics

```solidity
// Morpho Blue liquidation:
// - Seized = min(maxLiquidatable, repaidShares * collateralPrice / LLTV)
// - Incentive: liquidator gets collateral at discount

// VULNERABLE - Not accounting for liquidation incentive
contract BadLiquidator {
    function isLiquidationProfitable(
        Id marketId,
        address borrower
    ) external view returns (bool) {
        // Doesn't account for gas or incentive calculation
        return morpho.isHealthy(marketId, borrower);
    }
}

// SECURE - Full profitability calculation
contract SmartLiquidator {
    function calculateLiquidationProfit(
        Id marketId,
        address borrower,
        uint256 repayShares
    ) external view returns (int256) {
        MarketParams memory params = morpho.idToMarketParams(marketId);
        
        // Get current positions
        uint256 collateral = morpho.collateral(marketId, borrower);
        uint256 borrowShares = morpho.borrowShares(marketId, borrower);
        
        // Get price
        uint256 price = IOracle(params.oracle).price();
        
        // Calculate seized collateral
        uint256 repayAmount = morpho.convertToAmount(marketId, repayShares);
        uint256 seizedValue = repayAmount * ORACLE_PRICE_SCALE / price;
        
        // Apply liquidation incentive (typically 1.15x)
        uint256 incentiveFactor = 1.15e18;
        uint256 seized = seizedValue * incentiveFactor / 1e18;
        
        // Profit = seized collateral value - repay amount - gas
        uint256 estimatedGas = 500000 * tx.gasprice;
        
        return int256(seized * price / ORACLE_PRICE_SCALE) 
            - int256(repayAmount) 
            - int256(estimatedGas);
    }
}
```

### 5. Interest Rate Model Risks

```solidity
// Morpho Blue uses configurable IRMs
// IRM could be manipulated or malicious

// VULNERABLE - Trusting any IRM
contract TrustingBorrower {
    function borrow(Id marketId, uint256 amount) external {
        // IRM could return extreme rates!
        morpho.borrow(marketId, amount, 0, msg.sender, msg.sender);
    }
}

// SECURE - Validate IRM and check rate
contract SafeBorrower {
    mapping(address => bool) public trustedIRMs;
    uint256 public constant MAX_BORROW_RATE = 0.5e18;  // 50% APR max
    
    function borrow(Id marketId, uint256 amount) external {
        MarketParams memory params = morpho.idToMarketParams(marketId);
        
        // Verify IRM is trusted
        require(trustedIRMs[params.irm], "Untrusted IRM");
        
        // Check current rate
        uint256 rate = IIRM(params.irm).borrowRate(params, morpho.market(marketId));
        require(rate <= MAX_BORROW_RATE, "Rate too high");
        
        morpho.borrow(marketId, amount, 0, msg.sender, msg.sender);
    }
}
```

### 6. Supply/Borrow Share Accounting

```solidity
// Morpho Blue uses shares for accounting (like ERC4626)

// CRITICAL: First depositor inflation attack possible

// VULNERABLE - First deposit without protection
contract VulnerableVault {
    function deposit(Id marketId, uint256 assets) external {
        // First depositor can manipulate share ratio
        morpho.supply(marketId, assets, 0, address(this), "");
    }
}

// SECURE - Enforce minimum or use shares parameter
contract SecureVault {
    uint256 constant MINIMUM_SHARES = 1000;
    
    function deposit(Id marketId, uint256 assets) external {
        (, uint256 totalSupplyShares, , ) = morpho.market(marketId);
        
        if (totalSupplyShares == 0) {
            // First depositor - ensure minimum shares
            // Or use shares parameter to specify expected shares
            morpho.supply(marketId, assets, MINIMUM_SHARES, address(this), "");
        } else {
            // Calculate expected shares
            uint256 expectedShares = morpho.convertToShares(marketId, assets);
            uint256 minShares = expectedShares * 99 / 100;  // 1% slippage
            
            morpho.supply(marketId, 0, minShares, address(this), "");
        }
    }
}
```

### 7. Authorization System

```solidity
// Morpho Blue uses setAuthorization for delegation

// VULNERABLE - Over-authorization
contract UnsafeManager {
    function setup() external {
        // Authorizing for ALL markets!
        morpho.setAuthorization(manager, true);
    }
}

// SECURE - Market-specific authorization via callbacks
contract SafeManager {
    // Use callbacks for granular control
    function onMorphoSupply(
        uint256 assets,
        bytes calldata data
    ) external returns (bytes4) {
        // Validate the operation
        require(allowedMarkets[currentMarket], "Not allowed");
        return this.onMorphoSupply.selector;
    }
}
```

## Audit Checklist

```
[ ] P2P matching rates correctly blended
[ ] Oracle validation for each market
[ ] Market parameters validated (LLTV, IRM)
[ ] Liquidation incentive calculations correct
[ ] Share accounting for inflation attacks
[ ] IRM rate bounds checked
[ ] Authorization scope minimized
[ ] Cross-market correlation considered
[ ] Bad debt isolation understood
[ ] Market immutability verified
```

## Integration Patterns

### Safe Morpho Blue Supply
```solidity
function safeSupply(
    Id marketId,
    uint256 assets,
    uint256 minShares
) external returns (uint256 shares) {
    // Validate market
    require(validatedMarkets[marketId], "Invalid market");
    
    // Get token
    MarketParams memory params = morpho.idToMarketParams(marketId);
    IERC20(params.loanToken).approve(address(morpho), assets);
    
    // Supply with share protection
    (uint256 suppliedAssets, shares) = morpho.supply(
        marketId,
        assets,
        minShares,
        msg.sender,
        ""
    );
    
    require(shares >= minShares, "Slippage");
    return shares;
}
```

## Key Addresses

```solidity
// Morpho Blue (Ethereum)
address constant MORPHO_BLUE = 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;

// Morpho Aave V3 Optimizer (Ethereum)
address constant MORPHO_AAVE_V3 = 0x33333aea097c193e66081E930c33020272b33333;

// Morpho Compound V2 Optimizer (Ethereum)
address constant MORPHO_COMPOUND = 0x8888882f8f843896699869179fB6E4f7e3B58888;
```
