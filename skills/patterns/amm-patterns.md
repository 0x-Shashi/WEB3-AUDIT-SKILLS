---
id: PAT-AMM
title: AMM Security Patterns
category: defi
severity: high
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - amm
  - liquidity-pool
  - constant-product
  - lp-tokens
  - swaps
related_patterns:
  - swap-patterns
  - uniswap-patterns
  - slippage-patterns
  - sandwich-attack-patterns
  - flash-loan-patterns
finding_count: 38
last_updated: 2026-02-24
---
# AMM Security Patterns

## Overview

**Frequency**: 38 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 4 | 16 | 14 | 4 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check that price calculations use TWAP or reliable oracle, never `slot0` / spot price
- [ ] Verify LP share minting handles the first-depositor edge case correctly
- [ ] Review slippage and deadline parameters on all swap and liquidity operations
- [ ] Analyze K-value invariant maintenance across all state-changing functions
- [ ] Test for pool draining via price manipulation, flash loans, or donation attacks

---

## Key Vulnerability Classes

### 1. Spot Price Manipulation (slot0 Usage)

Using Uniswap V3 `slot0()` for pricing is the single most common AMM vulnerability. `slot0` reflects the current tick/price which can be manipulated within a single transaction via flash loans.

```solidity
// VULNERABLE: Using slot0 for pricing
(uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
uint256 price = (uint256(sqrtPriceX96) ** 2) / (2 ** 192);
// ⚠ Attacker can manipulate this with a flash loan swap

// SECURE: Use TWAP
(int24 arithmeticMeanTick, ) = OracleLibrary.consult(pool, twapInterval);
uint256 price = OracleLibrary.getQuoteAtTick(arithmeticMeanTick, amount, token0, token1);
```

**Real-World**: RealWagmi — used `slot0` to determine LP position value during leverage liquidation, allowing flash-loan price manipulation to extract funds.

### 2. K-Value Invariant Violation

The constant product formula `x * y = k` must hold across all operations. Violations allow pool draining.

```solidity
// VULNERABLE: K not validated after operation
function swap(uint256 amountIn, address tokenIn) external {
    uint256 amountOut = calculateOutput(amountIn, tokenIn);
    _transfer(tokenOut, msg.sender, amountOut);
    _transferFrom(tokenIn, msg.sender, amountIn);
    // ⚠ Missing: require(newK >= oldK, "K decreased");
}
```

Attack vectors:
- Fee calculation errors that leak value
- Rounding errors accumulated across many swaps
- Donation attacks that manipulate reserves without updating K

### 3. LP Token Share Inflation

When adding liquidity, LP shares must be calculated proportionally. The first LP can set an arbitrary ratio.

```solidity
// VULNERABLE: No minimum liquidity lock
function addLiquidity(uint256 amount0, uint256 amount1) external {
    if (totalSupply == 0) {
        shares = sqrt(amount0 * amount1);
        // ⚠ No MINIMUM_LIQUIDITY burned — first depositor attack possible
    } else {
        shares = min(
            (amount0 * totalSupply) / reserve0,
            (amount1 * totalSupply) / reserve1
        );
        // ⚠ Attacker can donate to one reserve to make ratio extreme
    }
}
```

**Fix**: Burn `MINIMUM_LIQUIDITY` to dead address on first deposit (Uniswap V2 pattern).

### 4. Missing Deadline / Stale Transactions

Swap transactions without deadlines can be held by miners/validators and executed later at unfavorable prices.

```solidity
// VULNERABLE: No deadline parameter
function swap(uint256 amountIn, uint256 minOut) external {
    // ⚠ Transaction can be held in mempool indefinitely
}

// SECURE: Enforce deadline
function swap(uint256 amountIn, uint256 minOut, uint256 deadline) external {
    require(block.timestamp <= deadline, "EXPIRED");
}
```

**Real-World**: Blueberry/CurveSpell — set `deadline = type(uint256).max`, making the deadline check meaningless for all transactions.

### 5. Cross-Token Swap Loss

In multi-hop swaps, intermediate token handling can lead to fund loss if tokens get stuck in intermediate contracts.

```solidity
// VULNERABLE: Multi-hop with intermediate remainder
function multiSwap(SwapData[] calldata swaps) external {
    for (uint i = 0; i < swaps.length; i++) {
        _executeSwap(swaps[i]);
        // ⚠ If intermediate swap outputs more than next swap needs,
        //    remainder stays in router contract
    }
}
```

**Real-World**: LI.FI — cross-chain swap token loss where intermediate tokens were not properly forwarded.

---

## Real-World Examples

### Example 1: [H-01] slot0 price manipulation in RealWagmi leveraged positions

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: HIGH

**Details**:

The protocol used Uniswap V3 `slot0()` to determine the value of LP positions during leverage operations. An attacker could:
1. Flash loan a large amount of one token
2. Execute a massive swap to move `slot0` price
3. Interact with the protocol at the manipulated price
4. Reverse the swap and repay the flash loan

This allowed extraction of funds from leveraged positions by making them appear under-collateralized at the manipulated price.

---

### Example 2: [H-03] Pool draining via oracle manipulation in WOOFi

**Source**: Immunefi
**Protocol**: WOOFi
**Impact**: CRITICAL

**Details**:

WOOFi's custom AMM used an internal oracle for pricing. The oracle could be manipulated through a sequence of swaps, allowing the attacker to drain pool reserves. The attack exploited the price update mechanism that was too responsive to individual trades, creating a feedback loop.

**Loss**: $8.75M drained across multiple chains.

---

### Example 3: [M-02] LP providers lose funds due to proportional mismatch

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

When adding liquidity, if token amounts were provided in different proportions, the smaller proportion determined LP tokens minted. The excess of the proportionally larger token was effectively donated to existing LPs, causing loss to the depositor.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| Flash loans | Spot price manipulation for all slot0-dependent operations |
| Sandwich attacks | MEV extraction via front/back-running swaps |
| Oracles | Protocols using AMM price as oracle inherit manipulation risk |
| Reentrancy | Callback-based token standards can re-enter during swaps |
| Fee-on-transfer | Actual amounts received differ from input amounts |

---

## Recommended Secure Patterns

1. **TWAP pricing**: Use time-weighted average price, never spot/slot0
2. **Minimum liquidity**: Burn `MINIMUM_LIQUIDITY` on first deposit
3. **Deadline enforcement**: Require `block.timestamp <= deadline` on all user operations
4. **Slippage protection**: Always enforce `minAmountOut` on swaps, `minLiquidity` on LP
5. **K-value validation**: Assert `newK >= oldK` after every state change
6. **Reentrancy guards**: Protect all swap and liquidity functions with nonReentrant
