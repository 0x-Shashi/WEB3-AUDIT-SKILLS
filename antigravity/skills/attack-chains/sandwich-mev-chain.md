---
id: ATTACK-CHAIN-SANDWICH
title: Sandwich MEV Attack Chain
category: attack-chains
difficulty: intermediate
tags: [mev, sandwich, frontrun, backrun, amm]
typical_loss: $1K-1M per transaction
last_updated: 2026-01-31
---

# Sandwich MEV Attack Chain

## Overview

A sandwich attack places two transactions around a victim's trade to extract value. The attacker front-runs to move the price, the victim trades at a worse price, then the attacker back-runs to profit.

## Attack Flow Diagram

```
Block N:
┌─────────────────┐
│ 1. Attacker Buy │ ─── Price moves UP
├─────────────────┤
│ 2. Victim Buy   │ ─── Victim pays more (slippage)
├─────────────────┤
│ 3. Attacker Sell│ ─── Attacker profits
└─────────────────┘
```

## Prerequisites

- **Visible pending transaction** (public mempool)
- **DEX trade with slippage tolerance**
- **Sufficient capital to move price**
- **Gas price manipulation ability**

## Attack Steps

### Step 1: Monitor Mempool

```javascript
// MEV bot monitoring mempool
const pendingFilter = ethers.provider.on("pending", async (txHash) => {
    const tx = await ethers.provider.getTransaction(txHash);
    
    // Check if it's a DEX swap
    if (isTargetRouter(tx.to) && isSwapFunction(tx.data)) {
        const decoded = decodeSwap(tx.data);
        
        // Calculate profitability
        const profit = calculateSandwichProfit(decoded);
        
        if (profit > minProfitThreshold) {
            await executeSandwich(tx, decoded);
        }
    }
});
```

**State Change**: Victim transaction identified

### Step 2: Calculate Optimal Sandwich

```solidity
// Calculate how much to front-run with
function calculateOptimalFrontrun(
    uint256 victimAmountIn,
    uint256 reserveIn,
    uint256 reserveOut,
    uint256 victimSlippage
) public pure returns (uint256 frontrunAmount) {
    // Find amount that maximizes:
    // profit = backrun_output - frontrun_input - gas
    
    // Subject to:
    // victim still gets >= minAmountOut (slippage tolerance)
    
    // Complex math involving:
    // - AMM constant product formula
    // - Victim's slippage tolerance
    // - Gas costs
    
    return optimizedAmount;
}
```

### Step 3: Execute Front-Run Transaction

```solidity
// Attacker's front-run transaction
function frontrun(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) external {
    // Higher gas price than victim
    // Miners/validators include this BEFORE victim
    
    IERC20(tokenIn).approve(router, amountIn);
    
    IRouter(router).swapExactTokensForTokens(
        amountIn,
        0,  // Accept any output (we control the price)
        [tokenIn, tokenOut],
        address(this),
        block.timestamp
    );
    
    // Price of tokenOut is now HIGHER
}
```

**State Change**: Pool price moved against victim

### Step 4: Victim Transaction Executes

```solidity
// Victim's transaction (submitted by victim, but controlled timing by attacker)
function victimSwap() external {
    // Victim set slippage, e.g., 1%
    uint256 minAmountOut = expectedOutput * 99 / 100;
    
    IRouter(router).swapExactTokensForTokens(
        victimAmountIn,
        minAmountOut,  // Gets just above this
        [tokenIn, tokenOut],
        msg.sender,
        deadline
    );
    
    // Victim receives LESS tokenOut than expected
    // (But still above their minAmountOut slippage)
}
```

**State Change**: Victim traded at worse price

### Step 5: Execute Back-Run Transaction

```solidity
// Attacker's back-run transaction
function backrun(
    address tokenIn,  // Same as victim's tokenOut
    address tokenOut, // Same as victim's tokenIn
    uint256 amountIn  // Tokens from frontrun
) external {
    // Included AFTER victim in same block
    
    IERC20(tokenIn).approve(router, amountIn);
    
    IRouter(router).swapExactTokensForTokens(
        amountIn,
        0,
        [tokenIn, tokenOut],
        address(this),
        block.timestamp
    );
    
    // Price moved back, attacker has MORE tokenOut than started with
    // Profit = backrun_output - frontrun_input
}
```

**Final State**: Attacker profits, victim received minimum

## Full Attack Implementation

```solidity
contract SandwichBot {
    IRouter public router;
    
    function sandwich(
        address tokenA,
        address tokenB,
        uint256 frontrunAmount,
        uint256 victimExpectedOutput
    ) external {
        // This entire function executes atomically
        // In reality, front/back-run are separate txs
        
        // Front-run: Buy tokenB, raising its price
        uint256 tokenBReceived = _swap(tokenA, tokenB, frontrunAmount);
        
        // Victim tx happens here (different tx, same block)
        
        // Back-run: Sell tokenB, profit from victim's impact
        uint256 tokenAReturned = _swap(tokenB, tokenA, tokenBReceived);
        
        require(tokenAReturned > frontrunAmount, "Not profitable");
    }
    
    // Flashbots bundle for atomic execution
    function bundledSandwich(
        bytes calldata frontrunData,
        bytes calldata backrunData
    ) external {
        // Submit as bundle to Flashbots/MEV Boost
        // Guarantees ordering: frontrun -> victim -> backrun
    }
}
```

## Real-World Economics

### Typical Sandwich Metrics

| Metric | Value |
|--------|-------|
| Victim trade size | $10K - $1M |
| Attacker capital | $100K - $10M |
| Profit per sandwich | $100 - $50K |
| Success rate | 60-90% |
| Gas cost | $20 - $200 |

### Profitability Formula

```
Profit = (BackrunOutput - FrontrunInput) - GasCosts - BribeToBuilder

Where:
- BackrunOutput depends on: victim trade size, slippage, pool depth
- FrontrunInput: capital required to move price
- GasCosts: 21,000 * 2 * gasPrice + swap gas
- BribeToBuilder: payment to block builder for inclusion
```

## Detection Points

| Step | Detection Signal | Monitoring |
|------|-----------------|------------|
| 1 | Pending tx monitoring | Private mempool |
| 2-3 | Same-block tx pattern | Block analysis |
| 4 | Worse execution than expected | Compare to fair price |
| 5 | Profit extraction | Track bot addresses |

```solidity
// Detection: Check for sandwich pattern
function detectSandwich(
    address[] memory blockTxs,
    uint256 targetIndex
) public view returns (bool) {
    // Look for pattern: BUY -> TARGET -> SELL by same address
    if (targetIndex < 1 || targetIndex >= blockTxs.length - 1) {
        return false;
    }
    
    address before = getTxSender(blockTxs[targetIndex - 1]);
    address after = getTxSender(blockTxs[targetIndex + 1]);
    
    // Same sender before and after victim
    if (before == after) {
        // Check if it's opposite direction trades
        bool beforeIsBuy = isSwapBuy(blockTxs[targetIndex - 1]);
        bool afterIsSell = isSwapSell(blockTxs[targetIndex + 1]);
        
        return beforeIsBuy && afterIsSell;
    }
    
    return false;
}
```

## Prevention Measures

### For Users

| Protection | How |
|------------|-----|
| Private mempool | Use Flashbots Protect, MEV Blocker |
| Tight slippage | Minimize slippage tolerance |
| Split trades | Break large trades into smaller ones |
| Off-peak trading | Avoid high-activity periods |

### For Protocols

```solidity
// Protection 1: Commit-reveal for large trades
contract CommitRevealSwap {
    mapping(bytes32 => uint256) public commits;
    uint256 public constant REVEAL_DELAY = 1;  // 1 block
    
    function commit(bytes32 hash) external {
        commits[hash] = block.number;
    }
    
    function reveal(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minOut,
        bytes32 secret
    ) external {
        bytes32 hash = keccak256(abi.encode(
            msg.sender, tokenIn, tokenOut, amountIn, minOut, secret
        ));
        
        require(commits[hash] != 0, "Not committed");
        require(block.number >= commits[hash] + REVEAL_DELAY, "Too early");
        
        delete commits[hash];
        _executeSwap(tokenIn, tokenOut, amountIn, minOut);
    }
}

// Protection 2: TWAP execution
contract TWAPSwap {
    function twapSwap(
        address tokenIn,
        address tokenOut,
        uint256 totalAmount,
        uint256 chunks,
        uint256 chunkInterval
    ) external {
        uint256 chunkSize = totalAmount / chunks;
        
        for (uint i = 0; i < chunks; i++) {
            _scheduleSwap(
                tokenIn,
                tokenOut,
                chunkSize,
                block.timestamp + (i * chunkInterval)
            );
        }
    }
}

// Protection 3: Private order flow (CoW Protocol style)
contract BatchAuction {
    // Collect orders, execute at uniform clearing price
    // No frontrunning possible within batch
}
```

### Using Flashbots Protect

```javascript
// Send transaction through Flashbots Protect
const flashbotsProvider = await FlashbotsBundleProvider.create(
    provider,
    wallet,
    FLASHBOTS_ENDPOINT
);

// Transaction goes to private mempool
// Not visible to sandwich bots
const signedTx = await wallet.signTransaction(tx);
const result = await flashbotsProvider.sendPrivateTransaction({
    transaction: {
        chainId: 1,
        signedTransaction: signedTx
    }
});
```

## Audit Checklist

```
[ ] Does protocol have swap functionality?
[ ] Can users set slippage?
[ ] Are transactions in public mempool?
[ ] Is there batch auction / private orderflow?
[ ] Are TWAP or commit-reveal patterns available?
[ ] What's the typical trade size?
[ ] Pool depth vs expected trade size?
```
