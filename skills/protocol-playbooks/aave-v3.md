---
id: PLAY-AAVE-V3
title: Aave V3 Secure Integration Guide
protocol: aave
version: v3
category: lending
chains: [ethereum, arbitrum, optimism, polygon]
integration_type: [deposit, borrow, repay, liquidation, flash-loan]
common_mistakes: [oracle-misuse, wrong-decimals, missing-e-mode-checks, interest-rate-assumptions, health-factor-ignore]
secure_patterns: [oracle-validation, health-factor-checks, e-mode-guardrails, flash-loan-fee-accounting]
difficulty: advanced
prerequisites: [lending-basics, oracle-patterns, flash-loan-patterns]
audit_checklist_items: 12
last_updated: 2026-01-31
---

# Aave V3 Secure Integration Guide

> **Attack Surface:** See [attack-trees/lending-attack-tree.md](../attack-trees/lending-attack-tree.md)

## Overview

Aave V3 is the most widely-used lending protocol in DeFi, with unique features like Efficiency Mode (E-Mode), Isolation Mode, Portal (cross-chain), and flash loans. Integrating with Aave V3 exposes protocols to oracle manipulation, liquidation MEV, flash loan attacks, and accounting errors. This guide covers every integration surface with vulnerable and secure code examples.

---

## 1. Oracle Integration Security

### 1.1 How Aave V3 Prices Assets

Aave uses Chainlink price feeds via its `AaveOracle` contract. Every financial decision (borrow limits, liquidations, health factors) depends on these prices.

```
Aave V3 Oracle Architecture:
=============================

[Chainlink Feed]     [Chainlink Feed]     [Chainlink Feed]
  ETH/USD              BTC/USD              USDC/USD
     |                    |                     |
     v                    v                     v
+----------------------------------------------------+
|              AaveOracle Contract                    |
|  getAssetPrice(asset) -> price in BASE_CURRENCY    |
|  BASE_CURRENCY = USD (8 decimals)                  |
+----------------------------------------------------+
     |                    |                     |
     v                    v                     v
+----------------------------------------------------+
|              Pool Contract                          |
|  Uses prices for:                                  |
|  - Borrow limit calculation                        |
|  - Health factor computation                       |
|  - Liquidation threshold checking                  |
|  - Interest rate updates                           |
+----------------------------------------------------+
```

### 1.2 Common Oracle Mistakes

```solidity
// BAD: Reading price without staleness check
function getCollateralValue(address asset, uint amount) public view returns (uint) {
    uint price = aaveOracle.getAssetPrice(asset);
    // [VULNERABLE] No check if price feed is stale
    // [VULNERABLE] No check if price is zero
    // [VULNERABLE] No decimal normalization
    return price * amount;
}

// GOOD: Safe price reading
function getCollateralValue(address asset, uint amount) public view returns (uint) {
    uint price = aaveOracle.getAssetPrice(asset);
    
    // Verify price is valid
    require(price > 0, "Invalid oracle price");
    
    // Get asset decimals for normalization
    uint assetDecimals = IERC20Metadata(asset).decimals();
    uint priceDecimals = 8; // Aave oracle uses 8 decimals (USD base)
    
    // Normalize: (amount * price) / 10^(assetDecimals + priceDecimals - targetDecimals)
    uint value = (amount * price) / (10 ** assetDecimals);
    
    return value;
}
```

### 1.3 Decimal Mismatch Vulnerability

```
Asset Decimal Reference:
========================

Asset    | Token Decimals | Oracle Decimals | Pitfall
---------|---------------|-----------------|--------
USDC     | 6             | 8               | 6 != 18, must normalize
WBTC     | 8             | 8               | Direct math works BUT verify
WETH     | 18            | 8               | Common assumption: both 18
DAI      | 18            | 8               | Standard case
USDT     | 6             | 8               | Same as USDC, easy to miss

CRITICAL: Never assume all tokens have 18 decimals.
CRITICAL: Oracle price is ALWAYS 8 decimals in Aave V3.
```

---

## 2. Flash Loan Integration

### 2.1 Flash Loan Patterns

```solidity
// BAD: Flash loan receiver without proper validation
contract UnsafeFlashLoan is IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint amount,
        uint premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // [VULNERABLE] No check that caller is the Aave pool
        // [VULNERABLE] No check that initiator is authorized
        
        // Do something with borrowed funds...
        _doArbitrage(asset, amount);
        
        // Approve repayment
        IERC20(asset).approve(msg.sender, amount + premium);
        return true;
    }
}

// GOOD: Secured flash loan receiver
contract SafeFlashLoan is IFlashLoanSimpleReceiver {
    IPool public immutable POOL;
    address public immutable OWNER;
    
    constructor(address pool, address owner) {
        POOL = IPool(pool);
        OWNER = owner;
    }
    
    function executeOperation(
        address asset,
        uint amount,
        uint premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        // [CRITICAL] Verify caller is the Aave pool
        require(msg.sender == address(POOL), "Caller is not the Pool");
        
        // [CRITICAL] Verify initiator is authorized
        require(initiator == OWNER, "Initiator not authorized");
        
        // Execute strategy
        _executeStrategy(asset, amount, params);
        
        // Ensure we have enough to repay
        uint totalDebt = amount + premium;
        uint balance = IERC20(asset).balanceOf(address(this));
        require(balance >= totalDebt, "Insufficient balance for repayment");
        
        // Approve repayment
        IERC20(asset).approve(address(POOL), totalDebt);
        
        return true;
    }
    
    // Only owner can initiate flash loans
    function requestFlashLoan(address asset, uint amount, bytes calldata params) external {
        require(msg.sender == OWNER, "Not authorized");
        POOL.flashLoanSimple(address(this), asset, amount, params, 0);
    }
}
```

### 2.2 Flash Loan Fee Accounting

```solidity
// Flash loan premium in Aave V3
// Default: 0.05% (5 bps) for regular flash loans
// Default: 0% for flash loans within the same block (flashLoanSimple)

// IMPORTANT: Account for fees in profitability calculations
function calculateFlashLoanProfit(
    uint borrowAmount,
    uint expectedRevenue
) public view returns (int profit) {
    uint premium = POOL.FLASHLOAN_PREMIUM_TOTAL(); // In bps (e.g., 5 = 0.05%)
    uint fee = (borrowAmount * premium) / 10000;
    uint gasCost = estimateGasCost();
    
    profit = int(expectedRevenue) - int(fee) - int(gasCost);
    // Only execute if profit > 0
}
```

---

## 3. Liquidation MEV Security

### 3.1 How Liquidations Work in Aave V3

```
Liquidation Flow:
=================

1. Borrower's health factor drops below 1.0
   HF = (totalCollateral * liquidationThreshold) / totalDebt

2. Liquidator calls liquidationCall():
   - Repays up to 50% of borrower's debt (close factor)
   - Receives collateral + liquidation bonus (5-15%)
   
3. MEV Risk:
   - Bots monitor pending transactions for price updates
   - When a Chainlink update would make positions liquidatable,
     bots front-run with liquidation transactions
   - This is profitable but creates adversarial conditions
```

### 3.2 Liquidation Integration Security

```solidity
// BAD: Liquidation bot without profit validation
function liquidate(
    address collateral,
    address debt,
    address user, 
    uint debtToCover
) external {
    // [VULNERABLE] No profitability check
    // [VULNERABLE] No slippage protection on collateral received
    IERC20(debt).approve(address(pool), debtToCover);
    pool.liquidationCall(collateral, debt, user, debtToCover, false);
}

// GOOD: Profitable and safe liquidation
function safeLiquidate(
    address collateral,
    address debt,
    address user,
    uint debtToCover,
    uint minCollateralReceived
) external onlyOwner {
    // Check position is actually liquidatable
    (,,,,, uint healthFactor) = pool.getUserAccountData(user);
    require(healthFactor < 1e18, "Position not liquidatable");
    
    // Calculate expected collateral
    uint expectedCollateral = _calculateExpectedCollateral(
        collateral, debt, debtToCover
    );
    require(expectedCollateral >= minCollateralReceived, "Slippage too high");
    
    // Execute liquidation
    uint balanceBefore = IERC20(collateral).balanceOf(address(this));
    
    IERC20(debt).approve(address(pool), debtToCover);
    pool.liquidationCall(collateral, debt, user, debtToCover, false);
    
    uint collateralReceived = IERC20(collateral).balanceOf(address(this)) - balanceBefore;
    require(collateralReceived >= minCollateralReceived, "Insufficient collateral received");
    
    emit LiquidationExecuted(user, debt, debtToCover, collateral, collateralReceived);
}
```

---

## 4. E-Mode (Efficiency Mode) Security

### 4.1 E-Mode Overview

E-Mode allows higher LTV and liquidation thresholds for correlated assets (e.g., stablecoins, ETH/stETH).

```
E-Mode Categories:
===================

Category | Assets          | LTV  | Liq Threshold | Liq Bonus
---------|-----------------|------|---------------|----------
1        | Stablecoins     | 97%  | 97.5%         | 2%
2        | ETH correlated  | 93%  | 95%           | 1%
0        | Default         | Varies| Varies        | Varies

Security Risks:
- Higher LTV = less margin for error = faster liquidation
- Assumes correlation persists (what if stablecoin depegs?)
- Markets with high E-Mode LTV are more susceptible to
  oracle manipulation since less price movement triggers liquidation
```

### 4.2 E-Mode Integration Checks

```solidity
// When integrating with E-Mode positions:

// CHECK 1: Verify E-Mode category is appropriate
function validateEMode(address user) public view {
    uint eMode = pool.getUserEMode(user);
    
    if (eMode != 0) {
        // User is in E-Mode - verify their collateral matches
        DataTypes.EModeCategory memory category = pool.getEModeCategoryData(eMode);
        
        // All collateral must be in the same E-Mode category
        // If user adds non-correlated collateral, they lose E-Mode benefits
        // This can cause unexpected liquidations
    }
}

// CHECK 2: Account for depeg risk in E-Mode
// E-Mode assumes assets are correlated
// If USDC depegs (like March 2023), E-Mode positions become dangerous
// Always have contingency logic for correlation breakdown
```

---

## 5. Isolation Mode Security

```solidity
// Isolation Mode restricts new assets to prevent systemic risk
// Isolated assets can only borrow specific stablecoins up to a debt ceiling

// Security considerations:
// 1. Debt ceiling can be reached, preventing new borrows
// 2. Isolated positions cannot use other assets as collateral
// 3. Liquidation thresholds may differ in isolation mode

// CHECK: Is the asset isolated?
function checkIsolation(address asset) public view {
    DataTypes.ReserveConfiguration memory config = pool.getConfiguration(asset);
    uint debtCeiling = config.getDebtCeiling();
    
    if (debtCeiling > 0) {
        // Asset is in isolation mode
        // Can only borrow assets flagged as borrowableInIsolation
        // Total debt limited to debtCeiling
    }
}
```

---

## 6. Interest Rate Security

```solidity
// Aave V3 uses variable and stable interest rates
// Stable rates can be rebalanced if conditions change

// RISK: Assuming stable rate means fixed rate
// Stable rates CAN be rebalanced by anyone when:
// 1. The current stable rate is below the optimal stable rate
// 2. The user's health factor would still be > 1 after rebalancing

// BAD: Assuming stable rate never changes
function calculateFutureDebt(uint principal, uint stableRate, uint time) pure returns (uint) {
    // [VULNERABLE] Assuming stableRate is constant
    return principal * (1 + stableRate * time / 365 days);
}

// GOOD: Account for rate rebalancing
function monitorStableRate(address user, address asset) external {
    uint currentRate = pool.getUserStableRate(user, asset);
    uint optimalRate = getOptimalStableRate(asset);
    
    if (currentRate < optimalRate * 95 / 100) {
        // Rate rebalancing is possible
        // Position economics may change
        emit StableRateRebalanceRisk(user, asset, currentRate, optimalRate);
    }
}
```

---

## 7. Integration Security Checklist

### Oracle Security
- [ ] Price feeds validated for staleness
- [ ] Zero price check implemented
- [ ] Decimal normalization correct for all assets (6, 8, 18 decimals)
- [ ] Fallback oracle mechanism exists

### Flash Loan Security
- [ ] `executeOperation` verifies `msg.sender == pool`
- [ ] `executeOperation` verifies `initiator` is authorized
- [ ] Fee accounting includes flash loan premium
- [ ] Sufficient balance for repayment verified before approval

### Position Management
- [ ] Health factor checked before and after operations
- [ ] E-Mode category validated for collateral compatibility
- [ ] Isolation mode constraints respected
- [ ] Debt ceiling checked for isolated assets

### Liquidation Security
- [ ] Profitability calculated including gas costs
- [ ] Minimum collateral received enforced (slippage protection)
- [ ] Health factor verified before liquidation attempt
- [ ] Close factor limits respected (max 50% of debt)

### Interest Rate Security
- [ ] Stable rate rebalancing accounted for
- [ ] Variable rate volatility considered in position sizing
- [ ] Interest accrual timing understood (per-second, not per-block)

### General Security
- [ ] Reentrancy guards on all external integrations
- [ ] Approval amounts minimized (no unlimited approvals to unknown contracts)
- [ ] Token compatibility verified (rebasing, fee-on-transfer, etc.)
- [ ] Emergency pause mechanism exists

---

## 8. Known Exploit Patterns Against Aave Integrators

| Exploit | Protocol | Loss | Root Cause |
|---------|----------|------|------------|
| Euler Finance (2023) | Euler | $197M | Flash loan donation attack |
| Cream Finance (2021) | Cream | $130M | Oracle manipulation via flash loan |
| Radiant Capital (2022) | Radiant | $4.5M | Flash loan + price manipulation |
| Mango Markets (2022) | Mango | $114M | Oracle manipulation of thin market |

## Cross-References

- Pattern: [flash-loan-attack-patterns.md](../patterns/flash-loan-attack-patterns.md)
- Pattern: [oracle-manipulation-patterns.md](../patterns/oracle-manipulation-patterns.md)
- Pattern: [liquidation-patterns.md](../patterns/liquidation-mev-patterns.md)
- Attack Tree: [lending-attack-tree.md](../attack-trees/lending-attack-tree.md)
- Anti-Pattern: [oracle-anti-patterns.md](../anti-patterns/oracle-anti-patterns.md)
- Forensics: [euler-2023.md](../exploit-forensics/euler-2023.md)
