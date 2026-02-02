---
id: PLAYBOOK-BALANCER
title: Balancer Integration Playbook
category: protocol-playbooks
protocol: balancer
version: v2
difficulty: advanced
tags: [balancer, amm, weighted-pool, composable-stable, flash-loans]
last_updated: 2026-01-31
---

# Balancer Integration Playbook

> **Attack Surface:** See [attack-trees/dex-attack-tree.md](../attack-trees/dex-attack-tree.md)

Comprehensive guide for integrating with and auditing Balancer V2 - the flexible multi-token AMM.

---

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Balancer V2                              │
├─────────────────────┬───────────────────────────────────────────┤
│       Vault         │              Pool Types                   │
│  (Single Contract)  │                                           │
├─────────────────────┼───────────────┬───────────────┬───────────┤
│ • All tokens stored │ Weighted Pool │ Stable Pool   │ Boosted   │
│ • Flash loans       │ (like Uni)    │ (like Curve)  │ (Nested)  │
│ • Internal balances │ 2-8 tokens    │ 2-5 tokens    │ Linear +  │
│ • Batch swaps       │ Custom weights│ Similar prices│ Composable│
└─────────────────────┴───────────────┴───────────────┴───────────┘
```

## Key Contracts

| Contract | Address (Mainnet) | Purpose |
|----------|-------------------|---------|
| Vault | `0xBA12222222228d8Ba445958a75a0704d566BF2C8` | Core vault (holds all tokens) |
| WeightedPoolFactory | `0x897888115Ada5773E02aA29F775430BFB5F34c51` | Creates weighted pools |
| ComposableStablePoolFactory | `0xfADa0f4547AB2de89D1304A668C39B3E09Aa7c76` | Creates stable pools |
| BalancerQueries | `0xE39B5e3B6D74016b2F6A9673D7d7493B6DF549d5` | Query helper |
| BAL | `0xba100000625a3754423978a60c9317c58a424e3D` | Governance token |

---

## Core Concepts

### 1. The Vault Architecture

```solidity
// Unlike Uniswap, ALL tokens for ALL pools are in ONE Vault
// Pools are "logic only" - they calculate swaps but don't hold tokens

interface IVault {
    // Swaps
    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external returns (uint256);
    
    function batchSwap(
        SwapKind kind,
        BatchSwapStep[] memory swaps,
        IAsset[] memory assets,
        FundManagement memory funds,
        int256[] memory limits,
        uint256 deadline
    ) external returns (int256[] memory);
    
    // Liquidity
    function joinPool(bytes32 poolId, address sender, address recipient, JoinPoolRequest memory request) external;
    function exitPool(bytes32 poolId, address sender, address recipient, ExitPoolRequest memory request) external;
    
    // Flash Loans (no fee!)
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}
```

### 2. Pool Types

```solidity
// Weighted Pool: Generalized constant product
// Product of (balance ^ weight) is constant
// Σ weights = 1 (100%)

// Example: 80/20 BAL/WETH pool
// (balBAL ^ 0.8) * (balWETH ^ 0.2) = k

// Stable Pool: Curve-style for pegged assets
// Uses StableMath amplification factor
// Good for: stETH/WETH, USDC/USDT/DAI

// Composable Stable Pool: Can be nested
// Contains BPT (pool token) in its own pool
// Enables boosted pools and nesting
```

### 3. Pool IDs and Specialization

```solidity
// Pool ID = pool address + pool specialization + nonce
bytes32 poolId = bytes32(bytes20(poolAddress)) | bytes32(specialization << 160);

// Specializations:
// 0 = General (most pools)
// 1 = Minimal Swap Info (gas optimization)
// 2 = Two Token (most gas efficient)
```

---

## Integration Patterns

### Simple Swap

```solidity
function swapExactIn(
    bytes32 poolId,
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut
) external returns (uint256 amountOut) {
    IVault.SingleSwap memory swap = IVault.SingleSwap({
        poolId: poolId,
        kind: IVault.SwapKind.GIVEN_IN,
        assetIn: IAsset(tokenIn),
        assetOut: IAsset(tokenOut),
        amount: amountIn,
        userData: ""
    });
    
    IVault.FundManagement memory funds = IVault.FundManagement({
        sender: address(this),
        fromInternalBalance: false,
        recipient: payable(address(this)),
        toInternalBalance: false
    });
    
    IERC20(tokenIn).approve(address(vault), amountIn);
    
    return vault.swap(swap, funds, minAmountOut, block.timestamp);
}
```

### Multi-Hop Batch Swap

```solidity
function batchSwap(
    address tokenIn,
    address tokenIntermediate,
    address tokenOut,
    bytes32 poolId1,
    bytes32 poolId2,
    uint256 amountIn
) external returns (int256[] memory deltas) {
    IAsset[] memory assets = new IAsset[](3);
    assets[0] = IAsset(tokenIn);
    assets[1] = IAsset(tokenIntermediate);
    assets[2] = IAsset(tokenOut);
    
    IVault.BatchSwapStep[] memory swaps = new IVault.BatchSwapStep[](2);
    
    // First swap: tokenIn → tokenIntermediate
    swaps[0] = IVault.BatchSwapStep({
        poolId: poolId1,
        assetInIndex: 0,
        assetOutIndex: 1,
        amount: amountIn,
        userData: ""
    });
    
    // Second swap: tokenIntermediate → tokenOut
    swaps[1] = IVault.BatchSwapStep({
        poolId: poolId2,
        assetInIndex: 1,
        assetOutIndex: 2,
        amount: 0,  // 0 means use output from previous swap
        userData: ""
    });
    
    int256[] memory limits = new int256[](3);
    limits[0] = int256(amountIn);
    limits[1] = 0;  // Intermediate: no limit
    limits[2] = -int256(minAmountOut);  // Negative = receiving
    
    return vault.batchSwap(
        IVault.SwapKind.GIVEN_IN,
        swaps,
        assets,
        funds,
        limits,
        block.timestamp
    );
}
```

### Adding Liquidity

```solidity
function joinPool(
    bytes32 poolId,
    address[] memory tokens,
    uint256[] memory maxAmountsIn
) external {
    IVault.JoinPoolRequest memory request = IVault.JoinPoolRequest({
        assets: _toAssets(tokens),
        maxAmountsIn: maxAmountsIn,
        userData: abi.encode(
            WeightedPoolUserData.JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT,
            maxAmountsIn,
            0  // minimumBPT
        ),
        fromInternalBalance: false
    });
    
    for (uint i = 0; i < tokens.length; i++) {
        IERC20(tokens[i]).approve(address(vault), maxAmountsIn[i]);
    }
    
    vault.joinPool(poolId, address(this), address(this), request);
}
```

### Free Flash Loans

```solidity
// Balancer flash loans have NO FEE (unlike Aave's 0.09%)
contract BalancerFlashLoan is IFlashLoanRecipient {
    IVault constant vault = IVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    
    function executeFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts
    ) external {
        vault.flashLoan(this, tokens, amounts, "");
    }
    
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,  // All zeros!
        bytes memory userData
    ) external override {
        require(msg.sender == address(vault), "Not vault");
        
        // Use the flash loaned funds
        // feeAmounts[i] = 0 for all tokens
        
        // Repay exact amount borrowed
        for (uint i = 0; i < tokens.length; i++) {
            tokens[i].transfer(address(vault), amounts[i]);
        }
    }
}
```

---

## Security Considerations

###  Critical Checks

```
[ ] Slippage protection on all swaps (limit parameter)?
[ ] Deadline parameter used and checked?
[ ] Pool ID validated (correct pool)?
[ ] Internal balance usage intentional?
[ ] Flash loan callback secured (msg.sender == vault)?
```

### Price Calculation

```solidity
// VULNERABLE: Using spot price from getPoolTokens
function getPrice(bytes32 poolId) external view returns (uint256) {
    (, uint256[] memory balances, ) = vault.getPoolTokens(poolId);
    return balances[0] * 1e18 / balances[1];  // Manipulable!
}

// SECURE: Use oracle or TWAP
// Balancer provides built-in oracle for some pools
interface IWeightedPool {
    function getLatest(Variable variable) external view returns (uint256);
    
    enum Variable { PAIR_PRICE, BPT_PRICE, INVARIANT }
}
```

### Reentrancy via Callbacks

```solidity
// Pools can have callbacks (hooks) during joins/exits
// Some pools use external protocols (Boosted Pools)

// RISK: Composable pools can call external contracts
// During join/exit, nested pools are interacted with

// MITIGATION:
// - Use reentrancy guards
// - Be cautious with composable/boosted pools
// - Verify pool implementation
```

---

## Common Vulnerabilities

### 1. Missing Slippage Protection

```solidity
// VULNERABLE: No minimum output
function unsafeSwap(bytes32 poolId, uint256 amountIn) external {
    vault.swap(swap, funds, 0, deadline);  // limit = 0!
}

// SECURE: Proper slippage
function safeSwap(bytes32 poolId, uint256 amountIn, uint256 minOut) external {
    vault.swap(swap, funds, minOut, deadline);
}
```

### 2. Flash Loan Attacks on BPT Price

```solidity
// BPT (Balancer Pool Token) price can be manipulated

// VULNERABLE: Using BPT price as oracle
uint256 bptPrice = pool.getRate();  // Can be manipulated

// SECURE: Use time-weighted values
uint256 bptPrice = pool.getLatest(Variable.BPT_PRICE);
```

### 3. Composable Pool Read-Only Reentrancy

```solidity
// Similar to Curve: virtual price can be manipulated during join/exit

// VULNERABLE: Reading rate during external call
function getCollateralValue(address bpt, uint256 amount) external view {
    uint256 rate = IComposableStablePool(bpt).getRate();
    return amount * rate / 1e18;  // Rate might be stale during reentrancy
}

// SECURE: Check reentrancy status
modifier noReentrantPool(address pool) {
    IVault vault = IComposableStablePool(pool).getVault();
    vault.manageUserBalance(new IVault.UserBalanceOp[](0));  // Will revert if reentering
    _;
}
```

### 4. Internal Balance Confusion

```solidity
// Balancer supports internal balances (tokens stay in Vault)
// Cheaper for multiple operations but can cause confusion

// RISK: Forgetting tokens in internal balance
FundManagement memory funds = FundManagement({
    sender: address(this),
    fromInternalBalance: false,
    recipient: payable(address(this)),
    toInternalBalance: true  // Tokens stay in Vault!
});

// Need to withdraw later:
vault.manageUserBalance(ops);  // WITHDRAW_INTERNAL
```

---

## Pool-Specific Considerations

### Weighted Pools
```
[ ] Weight sum = 1e18 (100%)?
[ ] Swap fee within bounds (0.0001% - 10%)?
[ ] Weight changes gradual (if applicable)?
```

### Stable Pools
```
[ ] Amplification factor appropriate?
[ ] A parameter changes are gradual?
[ ] Tokens are actually stable relative to each other?
```

### Composable Stable Pools
```
[ ] BPT is included in pool tokens?
[ ] Nested pool interactions safe?
[ ] Rate providers trusted?
```

### Boosted Pools
```
[ ] Linear pools properly configured?
[ ] Yield-bearing tokens (aTokens, etc.) handled?
[ ] Rate provider oracle secure?
```

---

## Quick Reference

### Weighted Pool Math
```
spotPrice = (balanceIn / weightIn) / (balanceOut / weightOut)

amountOut = balanceOut * (1 - (balanceIn / (balanceIn + amountIn)) ^ (weightIn / weightOut))

// With swap fee:
amountOut = amountOut * (1 - swapFee)
```

### Join/Exit Types (Weighted Pool)
```solidity
enum JoinKind {
    INIT,                         // First join
    EXACT_TOKENS_IN_FOR_BPT_OUT,  // Specify tokens, get BPT
    TOKEN_IN_FOR_EXACT_BPT_OUT,   // Specify BPT, pay one token
    ALL_TOKENS_IN_FOR_EXACT_BPT_OUT  // Specify BPT, pay proportional
}

enum ExitKind {
    EXACT_BPT_IN_FOR_ONE_TOKEN_OUT,  // Burn BPT, get one token
    EXACT_BPT_IN_FOR_TOKENS_OUT,     // Burn BPT, get proportional
    BPT_IN_FOR_EXACT_TOKENS_OUT      // Specify tokens, burn BPT
}
```

### Useful Queries
```solidity
// Get pool tokens and balances
(tokens, balances, lastChangeBlock) = vault.getPoolTokens(poolId);

// Query without executing (for quotes)
amountOut = balancerQueries.querySwap(swap, funds);
(bptOut, amountsIn) = balancerQueries.queryJoin(poolId, sender, recipient, request);
```

---

## Red Flags 

- [ ] No slippage protection (limit = 0)
- [ ] Using spot price as oracle
- [ ] Ignoring internal balance state
- [ ] Not validating pool ID
- [ ] Composable pool reentrancy exposure
- [ ] Missing flash loan callback validation
- [ ] Weight manipulation in custom pools
- [ ] Rate provider trust assumptions
