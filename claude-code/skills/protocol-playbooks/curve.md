---
id: PROTOCOL-CURVE
title: Curve Finance Security Playbook
category: protocol-playbook
protocol: curve
difficulty: advanced
tags: [dex, stableswap, amm, stablecoins, liquidity]
last_updated: 2026-01-31
---

# Curve Finance Security Playbook

> **Attack Surface:** See [attack-trees/dex-attack-tree.md](../attack-trees/dex-attack-tree.md) | [attack-trees/stablecoin-attack-tree.md](../attack-trees/stablecoin-attack-tree.md)

## Protocol Overview

Curve Finance specializes in stablecoin and pegged asset swaps using the StableSwap invariant. It's critical infrastructure for DeFi with complex math and multiple pool types.

## Pool Types

| Pool Type | Use Case | Key Risks |
|-----------|----------|-----------|
| StableSwap | Pegged assets (USDC/USDT) | Depeg handling |
| CryptoSwap | Volatile pairs | Oracle manipulation |
| Metapools | LP token + base pool | Composability risks |
| Tricrypto | BTC/ETH/USDT | Complex math |

## Critical Security Areas

### 1. StableSwap Math Vulnerabilities

```python
# Curve's StableSwap invariant
# D is the invariant, x[i] are balances
# A * sum(x) * n^n + D = A * D * n^n + D^(n+1) / (n^n * prod(x))

# The amplification coefficient A determines how "stable" the curve is
# High A = more like constant sum (stable)
# Low A = more like constant product (volatile)
```

```solidity
// VULNERABLE - Not accounting for amplification changes
contract CurveIntegration {
    function getExpectedOutput(uint256 dx) external view returns (uint256) {
        // A can change over time via ramp
        // This calculation may be stale
        return pool.get_dy(0, 1, dx);
    }
}

// SECURE - Check A ramp status
contract SafeCurveIntegration {
    function getExpectedOutput(uint256 dx) external view returns (uint256) {
        // Check if A is ramping
        uint256 futureA = pool.future_A();
        uint256 currentA = pool.A();
        uint256 futureATime = pool.future_A_time();
        
        if (futureA != currentA && block.timestamp < futureATime) {
            // A is actively ramping - use caution
            // Consider waiting or adjusting slippage
        }
        
        return pool.get_dy(0, 1, dx);
    }
}
```

### 2. Virtual Price Manipulation

```solidity
// virtual_price represents the value of LP tokens
// It should only go up (with fees) but can be manipulated

// VULNERABLE - Using virtual_price directly
contract LendingProtocol {
    function getCollateralValue(uint256 lpTokens) external view returns (uint256) {
        // virtual_price can be manipulated via flash loans
        return lpTokens * curvePool.get_virtual_price() / 1e18;
    }
}

// SECURE - Use read-only reentrancy protection
contract SafeLendingProtocol {
    function getCollateralValue(uint256 lpTokens) external view returns (uint256) {
        // Call a view function that would fail if in callback
        // Curve pools have reentrancy guards
        
        // For ETH pools, use oracle or delayed price
        uint256 price = virtualPriceOracle.getPrice();
        
        // Bound the price to prevent manipulation
        uint256 minPrice = lastKnownPrice * 99 / 100;  // Max 1% drop
        uint256 maxPrice = lastKnownPrice * 101 / 100;  // Max 1% rise
        
        if (price < minPrice) price = minPrice;
        if (price > maxPrice) price = maxPrice;
        
        return lpTokens * price / 1e18;
    }
}
```

### 3. Read-Only Reentrancy (The Curve Attack)

This was the vulnerability exploited in the July 2023 Curve hack.

```solidity
// Curve ETH pools use raw calls for ETH transfers
// This allows reentrancy during withdraw

// ATTACK FLOW:
// 1. Attacker adds liquidity
// 2. Attacker calls remove_liquidity
// 3. During ETH transfer, attacker's receive() is called
// 4. Attacker calls external protocol that reads virtual_price
// 5. virtual_price is stale (LP burned but ETH not yet sent)
// 6. External protocol gives inflated value

// VULNERABLE EXTERNAL PROTOCOL
contract VulnerableProtocol {
    function getPositionValue(address user) external view returns (uint256) {
        uint256 lpBalance = curveLP.balanceOf(user);
        // This is called while Curve is mid-withdrawal!
        uint256 virtualPrice = curvePool.get_virtual_price();
        return lpBalance * virtualPrice / 1e18;
    }
}

// SECURE - Use reentrancy guard or oracle
contract SecureProtocol {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private status;
    
    // Option 1: Non-view function with reentrancy guard
    function getPositionValue(address user) external returns (uint256) {
        require(status != ENTERED, "Reentrant call");
        status = ENTERED;
        
        uint256 lpBalance = curveLP.balanceOf(user);
        uint256 virtualPrice = curvePool.get_virtual_price();
        
        status = NOT_ENTERED;
        return lpBalance * virtualPrice / 1e18;
    }
    
    // Option 2: Use Chainlink or other oracle
    function getPositionValueSafe(address user) external view returns (uint256) {
        uint256 lpBalance = curveLP.balanceOf(user);
        uint256 virtualPrice = curveLPOracle.latestAnswer();
        return lpBalance * virtualPrice / 1e18;
    }
}
```

### 4. Metapool Composability Risks

```solidity
// Metapools: [newToken, basePoolLP]
// basePoolLP represents multiple underlying tokens

// VULNERABLE - Not accounting for base pool
contract MetapoolIntegration {
    function deposit(uint256 amount) external {
        // Depositing into metapool
        // But what if base pool is imbalanced?
        metapool.add_liquidity([amount, 0], 0);
    }
}

// SECURE - Check base pool health
contract SafeMetapoolIntegration {
    function deposit(uint256 amount) external {
        // Check base pool balance
        uint256[] memory baseBalances = basePool.get_balances();
        
        // Verify reasonable balance ratios
        uint256 ratio = baseBalances[0] * 1e18 / baseBalances[1];
        require(ratio > 0.95e18 && ratio < 1.05e18, "Base pool imbalanced");
        
        // Check metapool balance
        uint256[] memory metaBalances = metapool.get_balances();
        
        // Now safe to deposit
        metapool.add_liquidity([amount, 0], minLPExpected);
    }
}
```

### 5. Gauge and Reward Manipulation

```solidity
// CRV rewards can be manipulated via vote buying or gauge gaming

// VULNERABLE - Assuming stable rewards
contract RewardCalculator {
    function expectedRewards(uint256 lpAmount) external view returns (uint256) {
        // Gauge weights can change dramatically
        uint256 gaugeWeight = gaugeController.gauge_relative_weight(gauge);
        return calculateRewards(lpAmount, gaugeWeight);
    }
}

// SECURE - Account for weight changes
contract SafeRewardCalculator {
    function expectedRewards(uint256 lpAmount) external view returns (uint256) {
        // Get current and future weights
        uint256 currentWeight = gaugeController.gauge_relative_weight(gauge);
        uint256 futureWeight = gaugeController.gauge_relative_weight(gauge, block.timestamp + 1 weeks);
        
        // Use minimum for conservative estimate
        uint256 weight = currentWeight < futureWeight ? currentWeight : futureWeight;
        
        return calculateRewards(lpAmount, weight);
    }
}
```

### 6. Admin Key Risks

```solidity
// Curve pools have admin functions that can:
// - Ramp A parameter
// - Set fees
// - Kill pools (in emergency)

// AUDIT CHECKLIST for admin functions:
// [ ] Who controls admin keys?
// [ ] Is there a timelock?
// [ ] Can admin drain funds?
// [ ] Can admin manipulate prices?
// [ ] Emergency kill switch scope

// Check admin on a pool:
address admin = curvePool.admin();
address feeReceiver = curvePool.fee_receiver();
```

### 7. Fee Handling

```solidity
// Curve fees are split between LPs and admin

// VULNERABLE - Not accounting for fees
contract Arbitrageur {
    function calculateProfit(uint256 amount) external view returns (int256) {
        uint256 fee = curvePool.fee();  // Usually 4bp = 0.04%
        uint256 adminFee = curvePool.admin_fee();  // % of fee to admin
        
        // Effective fee to LPs
        uint256 lpFee = fee * (1e10 - adminFee) / 1e10;
        
        // Must account for this in profit calculation
    }
}
```

## Integration Patterns

### Safe Curve Swap
```solidity
function safeCurveSwap(
    address pool,
    int128 i,
    int128 j,
    uint256 dx,
    uint256 minDy
) external returns (uint256) {
    // Get quote first
    uint256 expectedDy = ICurve(pool).get_dy(i, j, dx);
    
    // Verify slippage protection
    require(expectedDy >= minDy, "Slippage");
    
    // Approve and swap
    IERC20(coins[uint128(i)]).approve(pool, dx);
    
    uint256 dy = ICurve(pool).exchange(i, j, dx, minDy);
    
    return dy;
}
```

### Safe LP Operations
```solidity
function safeAddLiquidity(
    address pool,
    uint256[] calldata amounts,
    uint256 minMintAmount
) external returns (uint256) {
    // Calculate expected LP
    uint256 expectedLP = ICurve(pool).calc_token_amount(amounts, true);
    
    // Apply slippage (account for fees)
    require(expectedLP >= minMintAmount, "Slippage");
    
    // Approve all tokens
    for (uint i = 0; i < amounts.length; i++) {
        if (amounts[i] > 0) {
            IERC20(coins[i]).approve(pool, amounts[i]);
        }
    }
    
    // Add liquidity
    return ICurve(pool).add_liquidity(amounts, minMintAmount);
}
```

## Audit Checklist

```
[ ] Virtual price not used in view functions called by external protocols
[ ] Reentrancy guards in place for ETH pool interactions
[ ] A parameter ramp timing checked
[ ] Slippage protection on all swaps and LP operations
[ ] Base pool health verified for metapools
[ ] Fee calculations correct
[ ] Admin function scope understood
[ ] Gauge weight assumptions documented
[ ] Token decimals handled correctly (Curve uses raw amounts)
[ ] Pool imbalance checked before large operations
```

## Known Exploits

| Date | Vulnerability | Loss |
|------|---------------|------|
| Jul 2023 | Read-only reentrancy | $70M+ |
| Aug 2022 | Various pool drains | ~$13M |

## Pool Interface Reference

```solidity
interface ICurve {
    // Views
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
    function get_virtual_price() external view returns (uint256);
    function A() external view returns (uint256);
    function fee() external view returns (uint256);
    function balances(uint256 i) external view returns (uint256);
    
    // State-changing
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
    function add_liquidity(uint256[] calldata amounts, uint256 min_mint_amount) external returns (uint256);
    function remove_liquidity(uint256 amount, uint256[] calldata min_amounts) external returns (uint256[] memory);
    function remove_liquidity_one_coin(uint256 amount, int128 i, uint256 min_amount) external returns (uint256);
}
```
