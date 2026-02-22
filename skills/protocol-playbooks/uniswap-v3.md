---
id: PLAY-UNISWAP-V3
title: Uniswap V3 Secure Integration Guide
protocol: uniswap
version: v3
category: dex
chains: [ethereum, arbitrum, optimism, polygon, base]
integration_type: [swap, liquidity, oracle]
common_mistakes: [slippage-not-set, deadline-not-enforced, price-manipulation, callback-reentrancy]
secure_patterns: [exact-input-single, twap-oracle, deadline-validation]
difficulty: advanced
prerequisites: [defi-basics, amm-mechanics, oracle-patterns]
audit_checklist_items: 12
last_updated: 2026-01-31
---

# Uniswap V3 Secure Integration Guide

> **Attack Surface:** See [attack-trees/dex-attack-tree.md](../attack-trees/dex-attack-tree.md)

## Overview

Uniswap V3 introduces concentrated liquidity, allowing LPs to allocate capital within custom price ranges. This dramatically increases capital efficiency but also introduces new attack surfaces: tick manipulation, concentrated liquidity sniping, just-in-time (JIT) liquidity, and TWAP oracle manipulation. This guide covers secure integration patterns for swaps, liquidity provision, and oracle usage.

---

## 1. Swap Integration Security

### 1.1 Slippage Protection

Every swap MUST have slippage protection. Without it, MEV bots will sandwich your transaction.

```solidity
// BAD: No slippage protection
function unsafeSwap(address tokenIn, address tokenOut, uint amountIn) external {
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: tokenIn,
        tokenOut: tokenOut,
        fee: 3000,
        recipient: msg.sender,
        deadline: block.timestamp,           // [VULNERABLE] No real deadline
        amountIn: amountIn,
        amountOutMinimum: 0,                 // [VULNERABLE] Accepts ANY output
        sqrtPriceLimitX96: 0                 // [VULNERABLE] No price limit
    });
    router.exactInputSingle(params);
}

// GOOD: Full slippage protection
function safeSwap(
    address tokenIn,
    address tokenOut,
    uint amountIn,
    uint amountOutMin,    // User-specified minimum
    uint deadline         // User-specified deadline
) external {
    require(block.timestamp <= deadline, "Transaction expired");
    
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: tokenIn,
        tokenOut: tokenOut,
        fee: 3000,
        recipient: msg.sender,
        deadline: deadline,
        amountIn: amountIn,
        amountOutMinimum: amountOutMin,      // [SAFE] Minimum output enforced
        sqrtPriceLimitX96: 0                 // Optional additional protection
    });
    
    uint amountOut = router.exactInputSingle(params);
    require(amountOut >= amountOutMin, "Insufficient output");
}
```

### 1.2 Deadline Attacks

Setting `deadline: block.timestamp` provides ZERO protection. Validators can hold the transaction and execute it at any future time when the price is unfavorable.

```solidity
// BAD: Deadline set to block.timestamp
deadline: block.timestamp  // Miner can include this in any future block

// BAD: Deadline too far in the future
deadline: block.timestamp + 365 days  // Year-long window for MEV

// GOOD: Reasonable deadline from user
deadline: userDeadline  // User sets based on their tolerance (e.g., 5-30 minutes)

// GOOD: Protocol-enforced maximum
require(deadline <= block.timestamp + MAX_DEADLINE, "Deadline too far");
require(deadline >= block.timestamp, "Deadline already passed");
```

### 1.3 Multi-Hop Swap Risks

```solidity
// BAD: Multi-hop without intermediate checks
function unsafeMultiHop(bytes memory path, uint amountIn) external {
    ISwapRouter.ExactInputParams memory params = ISwapRouter.ExactInputParams({
        path: path,                    // [VULNERABLE] Path not validated
        recipient: msg.sender,
        deadline: block.timestamp,
        amountIn: amountIn,
        amountOutMinimum: 0            // [VULNERABLE] No minimum
    });
    router.exactInput(params);
}

// GOOD: Validated multi-hop
function safeMultiHop(
    bytes memory path,
    uint amountIn,
    uint amountOutMin,
    uint deadline
) external {
    // Validate path
    require(path.length >= 43, "Invalid path");  // minimum: token(20) + fee(3) + token(20)
    
    // Validate path contains only whitelisted tokens and fee tiers
    _validatePath(path);
    
    ISwapRouter.ExactInputParams memory params = ISwapRouter.ExactInputParams({
        path: path,
        recipient: msg.sender,
        deadline: deadline,
        amountIn: amountIn,
        amountOutMinimum: amountOutMin
    });
    
    uint amountOut = router.exactInput(params);
    emit SwapExecuted(msg.sender, amountIn, amountOut);
}
```

---

## 2. TWAP Oracle Security

### 2.1 Why Spot Price is Dangerous

```solidity
// BAD: Using spot price for any financial decision
function getSpotPrice(address pool) public view returns (uint price) {
    (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(pool).slot0();
    // [VULNERABLE] slot0 price can be manipulated in a single transaction
    // via flash loans or large swaps
    price = uint(sqrtPriceX96) * uint(sqrtPriceX96) / (2**192);
}

// GOOD: Using TWAP with sufficient observation window
function getTWAPPrice(
    address pool,
    uint32 twapInterval
) public view returns (uint price) {
    require(twapInterval >= 1800, "TWAP window too short"); // Minimum 30 minutes
    
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;
    secondsAgos[1] = 0;
    
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    
    int56 tickCumulativeDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativeDelta / int56(int32(twapInterval)));
    
    // Handle rounding for negative ticks
    if (tickCumulativeDelta < 0 && (tickCumulativeDelta % int56(int32(twapInterval)) != 0)) {
        arithmeticMeanTick--;
    }
    
    price = OracleLibrary.getQuoteAtTick(
        arithmeticMeanTick,
        1e18,            // baseAmount
        baseToken,
        quoteToken
    );
}
```

### 2.2 TWAP Manipulation Risks

Even TWAP can be manipulated with sufficient capital and time:

```
TWAP Manipulation Cost Analysis:
================================

Window | Capital Needed  | Feasibility
-------|----------------|------------
1 min  | ~$1-5M         | Easy for sophisticated attackers
5 min  | ~$5-25M        | Feasible for well-funded attackers
30 min | ~$50-500M      | Very expensive, usually impractical
1 hour | ~$1B+          | Practically impossible for most pools

Recommendations:
- Minimum 30-minute TWAP for price-sensitive operations
- Use multiple oracle sources (Chainlink + TWAP)
- Add deviation checks between oracle sources
- Monitor for sustained price movements
```

### 2.3 Oracle Observation Cardinality

```solidity
// IMPORTANT: Pool must have enough observations for your TWAP window
function ensureOracleReady(address pool, uint16 minCardinality) external {
    (,,,,uint16 observationCardinality,,) = IUniswapV3Pool(pool).slot0();
    
    if (observationCardinality < minCardinality) {
        // Increase observation slots (one-time cost, paid in gas)
        IUniswapV3Pool(pool).increaseObservationCardinalityNext(minCardinality);
    }
}

// If cardinality is too low, observe() will revert
// Always check before relying on TWAP
```

---

## 3. Liquidity Position Security

### 3.1 Concentrated Liquidity Risks

```
Risks unique to Uniswap V3 concentrated liquidity:

1. IMPERMANENT LOSS AMPLIFICATION
   - V3 positions in narrow ranges suffer higher IL than V2
   - A 10% price move can cause 50%+ IL in tight ranges
   
2. JUST-IN-TIME (JIT) LIQUIDITY
   - MEV bots add massive liquidity right before a swap,
     earn fees, then remove immediately after
   - Legitimate LPs earn less fees as a result
   
3. TICK SNIPING
   - Attackers manipulate price to specific ticks
     to trigger position activation/deactivation
   - Can be used to grief LPs or trigger stop-loss-like behavior
   
4. POSITION NFT THEFT
   - LP positions are ERC721 NFTs
   - If transferred to a malicious contract, position can be drained
```

### 3.2 Safe Liquidity Management

```solidity
// BAD: Minting LP position without checks
function unsafeMint(
    address token0,
    address token1,
    int24 tickLower,
    int24 tickUpper,
    uint amount0,
    uint amount1
) external {
    // [VULNERABLE] No validation of tick spacing, amounts, or ownership
    nonfungiblePositionManager.mint(INonfungiblePositionManager.MintParams({
        token0: token0,
        token1: token1,
        fee: 3000,
        tickLower: tickLower,
        tickUpper: tickUpper,
        amount0Desired: amount0,
        amount1Desired: amount1,
        amount0Min: 0,              // [VULNERABLE] No minimum
        amount1Min: 0,              // [VULNERABLE] No minimum
        recipient: msg.sender,
        deadline: block.timestamp   // [VULNERABLE] No real deadline
    }));
}

// GOOD: Safe LP position creation
function safeMint(
    address token0,
    address token1,
    int24 tickLower,
    int24 tickUpper,
    uint amount0Desired,
    uint amount1Desired,
    uint amount0Min,
    uint amount1Min,
    uint deadline
) external returns (uint tokenId) {
    // Validate tick alignment
    int24 tickSpacing = IUniswapV3Factory(factory).feeAmountTickSpacing(3000);
    require(tickLower % tickSpacing == 0, "tickLower not aligned");
    require(tickUpper % tickSpacing == 0, "tickUpper not aligned");
    require(tickLower < tickUpper, "Invalid tick range");
    
    // Validate amounts
    require(amount0Desired > 0 || amount1Desired > 0, "No liquidity");
    
    (tokenId,,,) = nonfungiblePositionManager.mint(
        INonfungiblePositionManager.MintParams({
            token0: token0,
            token1: token1,
            fee: 3000,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: amount0Desired,
            amount1Desired: amount1Desired,
            amount0Min: amount0Min,
            amount1Min: amount1Min,
            recipient: msg.sender,
            deadline: deadline
        })
    );
    
    emit PositionCreated(msg.sender, tokenId, tickLower, tickUpper);
}
```

---

## 4. Callback Security

### 4.1 Swap Callback Reentrancy

```solidity
// BAD: Callback without validation
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // [VULNERABLE] No verification that caller is the pool
    // [VULNERABLE] No reentrancy protection
    if (amount0Delta > 0) {
        IERC20(token0).transfer(msg.sender, uint(amount0Delta));
    }
    if (amount1Delta > 0) {
        IERC20(token1).transfer(msg.sender, uint(amount1Delta));
    }
}

// GOOD: Secured callback
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external override {
    // [CRITICAL] Verify caller is a legitimate Uniswap V3 pool
    CallbackData memory decoded = abi.decode(data, (CallbackData));
    address pool = PoolAddress.computeAddress(
        factory,
        PoolAddress.PoolKey({
            token0: decoded.token0,
            token1: decoded.token1,
            fee: decoded.fee
        })
    );
    require(msg.sender == pool, "Not authorized pool");
    
    // Pay the pool
    if (amount0Delta > 0) {
        IERC20(decoded.token0).safeTransfer(msg.sender, uint(amount0Delta));
    }
    if (amount1Delta > 0) {
        IERC20(decoded.token1).safeTransfer(msg.sender, uint(amount1Delta));
    }
}
```

### 4.2 Flash Loan Callback

```solidity
// Uniswap V3 flash loans via the pool's flash() function
function uniswapV3FlashCallback(
    uint fee0,
    uint fee1,
    bytes calldata data
) external override {
    // MUST verify caller is the pool
    require(msg.sender == address(pool), "Not authorized");
    
    // Execute flash loan logic
    FlashData memory decoded = abi.decode(data, (FlashData));
    
    // Repay principal + fee
    if (fee0 > 0) {
        IERC20(token0).safeTransfer(msg.sender, decoded.amount0 + fee0);
    }
    if (fee1 > 0) {
        IERC20(token1).safeTransfer(msg.sender, decoded.amount1 + fee1);
    }
}
```

---

## 5. Fee Tier Selection Security

```
Fee Tier Analysis:
==================

Tier    | Use Case                      | Manipulation Risk
--------|-------------------------------|------------------
0.01%   | Stablecoin pairs (USDC/USDT)  | Low (deep liquidity)
0.05%   | Correlated pairs (ETH/stETH)  | Low-Medium
0.30%   | Standard pairs (ETH/USDC)     | Medium
1.00%   | Exotic pairs (low liquidity)  | HIGH (thin liquidity)

Security Implications:
- Low-fee pools have deeper liquidity, harder to manipulate
- 1% fee pools often have thin liquidity, easier to move price
- TWAP from 1% pools is less reliable than from 0.3% pools
- Always verify the pool has sufficient liquidity before relying on it
```

---

## 6. Integration Security Checklist

### Pre-Integration

- [ ] Identify which fee tier pool to use (prefer deepest liquidity)
- [ ] Verify pool exists and has sufficient TVL
- [ ] Check observation cardinality for TWAP needs
- [ ] Audit all callback functions for reentrancy
- [ ] Verify token ordering (token0 < token1 by address)

### Swap Security

- [ ] `amountOutMinimum` is calculated off-chain and passed by user
- [ ] `deadline` is set to a reasonable future time (not `block.timestamp`)
- [ ] `sqrtPriceLimitX96` is set for single-pool swaps when appropriate
- [ ] Multi-hop paths are validated (whitelisted tokens, valid fee tiers)
- [ ] Swap callbacks verify caller is legitimate pool

### Oracle Security

- [ ] Using TWAP, not spot price (slot0)
- [ ] TWAP window is at least 30 minutes for price-sensitive operations
- [ ] Observation cardinality is sufficient for TWAP window
- [ ] Deviation check between TWAP and external oracle (e.g., Chainlink)
- [ ] Fallback oracle exists if TWAP observation fails

### Liquidity Security

- [ ] `amount0Min` and `amount1Min` are set to prevent sandwich attacks
- [ ] Tick ranges are properly aligned to tick spacing
- [ ] Position NFT ownership is properly tracked
- [ ] Fee collection is protected from front-running
- [ ] Decrease/increase liquidity has proper access controls

### MEV Protection

- [ ] Private mempool or Flashbots Protect for sensitive transactions
- [ ] Slippage parameters are tight enough to limit sandwich profit
- [ ] Large swaps are split across multiple transactions/blocks
- [ ] Time-weighted approach for large position changes

---

## 7. Known Exploit Patterns Against Uniswap V3 Integrators

| Exploit | Protocol | Loss | Root Cause |
|---------|----------|------|------------|
| Harvest Finance (2020) | Harvest | $24M | Used spot price, not TWAP |
| Warp Finance (2020) | Warp | $7.7M | LP token price manipulation |
| Visor Finance (2021) | Visor | $8.2M | Callback reentrancy |
| Various MEV | Multiple | $100M+ | Missing slippage/deadline protection |

## Cross-References

- Pattern: [oracle-manipulation-patterns.md](../patterns/oracle-manipulation-patterns.md)
- Pattern: [flash-loan-patterns.md](../patterns/flash-loan-attack-patterns.md)
- Pattern: [mev-sandwich-patterns.md](../patterns/mev-sandwich-patterns.md)
- Attack Tree: [dex-attack-tree.md](../attack-trees/dex-attack-tree.md)
- Anti-Pattern: [oracle-anti-patterns.md](../anti-patterns/oracle-anti-patterns.md)
- Checklist: [protocol-integration.md](../checklists/roles/protocol-integration.md)
