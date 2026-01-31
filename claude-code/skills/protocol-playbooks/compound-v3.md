---
id: PROTOCOL-COMPOUND-V3
title: Compound V3 (Comet) Security Playbook
category: protocol-playbook
protocol: compound-v3
difficulty: advanced
tags: [lending, borrowing, comet, single-asset, collateral]
last_updated: 2026-01-31
---

# Compound V3 (Comet) Security Playbook

## Protocol Overview

Compound V3 (Comet) is a complete redesign focusing on a single borrowable asset per market (e.g., USDC) with multiple collateral assets. This simplifies risk management but introduces new considerations.

## Architecture Differences from V2

| Aspect | Compound V2 | Compound V3 |
|--------|-------------|-------------|
| Borrowed Assets | Multiple | Single per market |
| Collateral | Same as borrowed | Separate, non-borrowable |
| Interest Model | Per-asset | Single asset |
| Liquidation | Seize collateral | Absorb position |
| Token Standard | cTokens | No LP token |

## Critical Security Areas

### 1. Collateral Factor Exploitation

```solidity
// V3 has different collateral handling
// Each collateral has: liquidateCollateralFactor, borrowCollateralFactor

// VULNERABLE - Not distinguishing between factors
contract BadIntegration {
    function getMaxBorrow(address account) external view returns (uint256) {
        // Wrong: using liquidation factor for borrow
        // This would overestimate borrow capacity
    }
}

// SECURE - Use correct factors
contract SafeIntegration {
    IComet public comet;
    
    function getMaxBorrow(address account) external view returns (uint256) {
        // Get all collateral
        uint256 totalCollateralValue = 0;
        
        uint8 numAssets = comet.numAssets();
        for (uint8 i = 0; i < numAssets; i++) {
            AssetInfo memory info = comet.getAssetInfo(i);
            uint256 balance = comet.collateralBalanceOf(account, info.asset);
            
            if (balance > 0) {
                uint256 price = comet.getPrice(info.priceFeed);
                // Use borrowCollateralFactor, not liquidateCollateralFactor
                uint256 value = balance * price * info.borrowCollateralFactor 
                    / info.scale / 1e18;
                totalCollateralValue += value;
            }
        }
        
        // Subtract existing borrow
        uint256 borrowed = comet.borrowBalanceOf(account);
        
        if (totalCollateralValue > borrowed) {
            return totalCollateralValue - borrowed;
        }
        return 0;
    }
}
```

### 2. Absorb Mechanism (Liquidation)

V3 uses "absorb" instead of traditional liquidation.

```solidity
// Absorb transfers underwater position to protocol reserves
// Liquidator doesn't seize collateral directly

// VULNERABLE - Assuming V2 liquidation mechanics
contract WrongLiquidator {
    function liquidate(address account) external {
        // This is V2 style - won't work in V3
        // cToken.liquidateBorrow(borrower, amount, collateral);
    }
}

// SECURE - Use absorb correctly
contract V3Liquidator {
    IComet public comet;
    
    function liquidate(address[] calldata accounts) external {
        // Check if accounts are liquidatable
        for (uint i = 0; i < accounts.length; i++) {
            require(comet.isLiquidatable(accounts[i]), "Not liquidatable");
        }
        
        // Absorb all accounts
        comet.absorb(msg.sender, accounts);
        
        // Now buy collateral from reserves
        // This is how liquidators profit
    }
    
    function buyCollateral(
        address asset,
        uint256 minAmount,
        uint256 baseAmount,
        address recipient
    ) external {
        // After absorb, buy collateral at discount
        comet.buyCollateral(asset, minAmount, baseAmount, recipient);
    }
}
```

### 3. Interest Accrual

```solidity
// V3 interest works differently:
// - Supply: earns interest on base asset only
// - Borrow: pays interest
// - Collateral: does NOT earn interest

// VULNERABLE - Assuming collateral earns interest
contract WrongYieldCalculator {
    function expectedYield(address account) external view returns (uint256) {
        // WRONG: Collateral doesn't earn yield in V3
        uint256 collateralBalance = comet.collateralBalanceOf(account, WETH);
        return collateralBalance * WETH_APY / 1e18;  // Always 0!
    }
}

// SECURE - Only base asset earns
contract CorrectYieldCalculator {
    function expectedYield(address account) external view returns (uint256) {
        // Only supply of base asset earns interest
        int256 principal = comet.balanceOf(account);  // Can be negative (borrow)
        
        if (principal > 0) {
            // Supplying - earns supply rate
            uint256 supplyRate = comet.getSupplyRate(comet.getUtilization());
            return uint256(principal) * supplyRate / 1e18;
        } else {
            // Borrowing - pays borrow rate
            uint256 borrowRate = comet.getBorrowRate(comet.getUtilization());
            return uint256(-principal) * borrowRate / 1e18;  // Cost, not yield
        }
    }
}
```

### 4. Allow/Allowance System

V3 uses an operator system for delegation.

```solidity
// V3 uses allow() for operator permissions

// VULNERABLE - Not checking allowances
contract UnsafeManager {
    function supplyOnBehalf(address user, uint256 amount) external {
        // What if this contract isn't allowed?
        comet.supplyFrom(user, address(this), baseToken, amount);  // Reverts!
    }
}

// SECURE - Verify permissions
contract SafeManager {
    IComet public comet;
    
    function supplyOnBehalf(address user, uint256 amount) external {
        // Check if we're allowed to act on behalf of user
        require(comet.hasPermission(user, address(this)), "Not allowed");
        
        comet.supplyFrom(user, address(this), baseToken, amount);
    }
    
    function requestPermission(address user) external {
        // User must call allow() on Comet
        // This contract cannot grant itself permission
    }
}

// Permission pattern in V3:
// User calls: comet.allow(manager, true)
// Then manager can: comet.supplyFrom(user, ...)
```

### 5. Price Feed Reliability

```solidity
// V3 uses Chainlink price feeds with additional safety

// Get asset info including price feed
function checkPriceFeed(uint8 assetIndex) external view returns (
    address priceFeed,
    uint64 scale,
    uint64 borrowCollateralFactor,
    uint64 liquidateCollateralFactor,
    uint64 liquidationFactor,
    uint128 supplyCap
) {
    AssetInfo memory info = comet.getAssetInfo(assetIndex);
    return (
        info.priceFeed,
        info.scale,
        info.borrowCollateralFactor,
        info.liquidateCollateralFactor,
        info.liquidationFactor,
        info.supplyCap
    );
}

// VULNERABLE - Using external price without validation
contract UnsafePriceUser {
    function getValue() external view returns (uint256) {
        uint256 price = comet.getPrice(priceFeed);
        // Price could be stale or extreme
        return balance * price;
    }
}

// SECURE - Validate price bounds
contract SafePriceUser {
    uint256 public lastKnownPrice;
    uint256 public constant MAX_PRICE_DEVIATION = 10;  // 10%
    
    function getValue() external view returns (uint256) {
        uint256 price = comet.getPrice(priceFeed);
        
        // Validate price isn't extreme
        if (lastKnownPrice > 0) {
            uint256 deviation = price > lastKnownPrice 
                ? (price - lastKnownPrice) * 100 / lastKnownPrice
                : (lastKnownPrice - price) * 100 / lastKnownPrice;
            
            require(deviation <= MAX_PRICE_DEVIATION, "Price deviation too high");
        }
        
        return balance * price / 1e8;  // Chainlink uses 8 decimals
    }
}
```

### 6. Supply Cap Enforcement

```solidity
// V3 has supply caps per collateral asset

// VULNERABLE - Not checking supply caps
contract CapIgnorer {
    function deposit(address asset, uint256 amount) external {
        // May revert if cap exceeded
        IERC20(asset).approve(address(comet), amount);
        comet.supply(asset, amount);
    }
}

// SECURE - Check caps before deposit
contract CapAwareDepositor {
    function deposit(address asset, uint256 amount) external {
        // Find asset info
        uint8 numAssets = comet.numAssets();
        for (uint8 i = 0; i < numAssets; i++) {
            AssetInfo memory info = comet.getAssetInfo(i);
            if (info.asset == asset) {
                // Check remaining capacity
                uint256 totalSupply = comet.totalsCollateral(asset).totalSupplyAsset;
                uint256 remaining = info.supplyCap > totalSupply 
                    ? info.supplyCap - totalSupply 
                    : 0;
                
                require(amount <= remaining, "Exceeds supply cap");
                break;
            }
        }
        
        IERC20(asset).approve(address(comet), amount);
        comet.supply(asset, amount);
    }
}
```

### 7. Base Token vs Collateral

```solidity
// Critical distinction in V3:
// - Base token (e.g., USDC): borrowed/supplied, earns/pays interest
// - Collateral (e.g., WETH, WBTC): only deposited, no interest

// Operations:
// supply(asset, amount)     - Add base or collateral
// withdraw(asset, amount)   - Remove base or collateral
// supplyTo/withdrawTo       - For other accounts
// supplyFrom/withdrawFrom   - From other accounts (needs permission)

// For base token:
function supplyBase(uint256 amount) external {
    comet.supply(baseToken, amount);  // Adds to base balance, earns interest
}

// For collateral:
function supplyCollateral(address asset, uint256 amount) external {
    comet.supply(asset, amount);  // Adds to collateral, NO interest
}

// Balances are tracked differently:
function getBalances(address account) external view returns (
    int256 baseBalance,        // Can be negative (borrow)
    uint256 wethCollateral,
    uint256 wbtcCollateral
) {
    baseBalance = comet.balanceOf(account);  // Signed!
    wethCollateral = comet.collateralBalanceOf(account, WETH);
    wbtcCollateral = comet.collateralBalanceOf(account, WBTC);
}
```

## Audit Checklist

```
[ ] Correct factor usage (borrow vs liquidate)
[ ] Absorb mechanism understood (not V2 liquidation)
[ ] Interest only on base asset (not collateral)
[ ] Allow/permission system correctly used
[ ] Supply caps checked before deposits
[ ] Price feed validation
[ ] Base vs collateral distinction clear
[ ] Negative balance handling (borrows)
[ ] Accrual timing understood
[ ] Utilization rate impact on rates
```

## Integration Patterns

### Safe Supply/Borrow
```solidity
contract SafeCompoundV3 {
    IComet public comet;
    IERC20 public baseToken;
    
    function safeSupply(uint256 amount) external {
        // Check allowance
        if (baseToken.allowance(address(this), address(comet)) < amount) {
            baseToken.approve(address(comet), type(uint256).max);
        }
        
        comet.supply(address(baseToken), amount);
    }
    
    function safeBorrow(uint256 amount) external {
        // Check borrow capacity
        require(amount <= getMaxBorrow(msg.sender), "Exceeds capacity");
        
        comet.withdraw(address(baseToken), amount);
    }
    
    function getMaxBorrow(address account) public view returns (uint256) {
        // Implementation from earlier
    }
}
```

## Key Addresses (Ethereum Mainnet)

```solidity
// Compound V3 USDC Market (Ethereum)
address constant COMET_USDC = 0xc3d688B66703497DAA19211EEdff47f25384cdc3;
address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

// Supported Collateral (USDC market)
// - WETH, WBTC, COMP, UNI, LINK
```
