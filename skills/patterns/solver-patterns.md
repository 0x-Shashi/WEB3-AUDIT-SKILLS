---
id: PAT-SOLVER
title: Solver Security Patterns
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
  - solver
  - intent
  - order-flow
  - batch-auction
  - mev
related_patterns:
  - intent-based-attacks
  - signature-malleability-patterns
  - sandwich-attack-patterns
  - front-running-patterns
finding_count: 15
last_updated: 2026-02-24
---
# Solver Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 2 | 6 | 5 | 2 | 0 |

**Common Sources**: Sherlock, Code4rena, Immunefi, Spearbit

---

## Detection Checklist

- [ ] Verify solver bonding/slashing mechanism prevents malicious or lazy solvers
- [ ] Check that user intents enforce minimum output and expiry to prevent stale execution
- [ ] Review batch settlement for ordering manipulation (solver can reorder within batch)
- [ ] Analyze solver competition mechanism — can one solver grief others or monopolize flow?
- [ ] Test solver signature validation, intent cancellation, and partial fill edge cases

---

## Key Vulnerability Classes

### 1. Solver Collusion / Preferential Execution

In solver networks, multiple solvers compete to fill user intents. Collusion occurs when solvers coordinate to provide worse execution than competitive markets would produce.

```solidity
// Intent-based swap architecture:
// 1. User signs: "I want to swap 1 ETH for at least 2000 USDC"
// 2. Solvers compete to fill this intent
// 3. Honest competition: user gets 2050 USDC (best available price)
// 4. Collusion: all solvers agree to fill at exactly 2000 USDC
//    → User gets minimum, solvers extract the surplus

// Detection: Compare solver execution prices to DEX quotes at same block
// If solvers consistently fill at minOutput, collusion is likely
```

**Mitigation**: Surplus sharing (CoW Protocol), on-chain price benchmarks, solver reputation scores.

### 2. Intent Front-Running

Solvers see user intents before execution. A malicious solver can:
- Execute trades ahead of the user's intent to move price
- Fill the intent at the now-worse price
- Profit from the price difference

```solidity
// Attack flow:
// 1. User broadcasts intent: swap 100 ETH → USDC, minOut = 200,000
// 2. Solver sees intent, current market price = 2100 USDC/ETH
// 3. Solver buys ETH on DEX, pushing price up
// 4. Solver fills intent at 200,000 USDC (the minimum)
// 5. Solver sells ETH at higher price, pocketing difference

// Even worse: solver submits user's intent to batch with their own front-run tx
```

### 3. Batch Ordering Manipulation

When solvers execute batches of intents, the order within the batch matters. A solver can order transactions to extract MEV.

```solidity
// Batch contains:
// Intent A: Swap 100 ETH → USDC
// Intent B: Swap 50 ETH → USDC  
// Intent C: Swap 200 USDC → ETH (opposite direction)
//
// Honest ordering: A, C, B → C provides liquidity, prices stay balanced
// Malicious ordering: A, B, C → A and B push price, C fills at worse rate
// Solver captures price impact difference

// SECURE: Uniform clearing price
// All swaps in same pair execute at same price within a batch
function settleBatch(Order[] calldata orders) external {
    uint256 clearingPrice = calculateUniformPrice(orders);
    for (uint i = 0; i < orders.length; i++) {
        execute(orders[i], clearingPrice); // Same price for all
    }
}
```

### 4. Solver Bond / Slashing Failures

Solvers must be bonded (post collateral) to prevent misbehavior. Common failures:

```solidity
// VULNERABLE: Bond insufficient relative to extracted value
uint256 constant SOLVER_BOND = 1 ether; // Bond: 1 ETH
// ⚠ If solver can extract 10 ETH from malicious execution,
//    losing bond is profitable

// VULNERABLE: Slashing conditions too narrow
function slashSolver(address solver, bytes calldata proof) external {
    require(block.timestamp <= fillTimestamp + SLASH_WINDOW, "Too late");
    // ⚠ If SLASH_WINDOW is too short, off-chain evidence can't be gathered in time
    
    require(verifyMisbehavior(proof), "Invalid proof");
    // ⚠ What constitutes "misbehavior"? If only non-fill is slashable,
    //    bad-price fills go unpunished
}
```

### 5. Intent Replay and Cancellation

Signed intents can be replayed if they don't include proper nonces, deadlines, or chain IDs.

```solidity
// VULNERABLE: Intent without expiry
struct Intent {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    bytes signature;
    // ⚠ No deadline — can be filled days later at stale price
    // ⚠ No nonce — same intent can be filled multiple times
    // ⚠ No chainId — can be replayed on other chains
}

// SECURE: Full intent specification
struct Intent {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    uint256 deadline;
    uint256 nonce;
    uint256 chainId;
    address solver; // Optional: restrict which solver can fill
    bytes signature;
}
```

### 6. Partial Fill Exploitation

When intents allow partial fills, solvers can exploit rounding or fill only the profitable portion.

```solidity
// User intent: "Sell 100 ETH for at least 2000 USDC/ETH"
// Solver partial fills:
//   Fill 1: 0.001 ETH at 2000 USDC/ETH (minimum price)
//   Fill 2: 0.001 ETH at 2000 USDC/ETH
//   ... repeated until intent expires
// ⚠ User gets minimum price on all fills while market is at 2100

// FIX: Minimum fill size, or all-or-nothing option
require(fillAmount >= intent.amountIn * MIN_FILL_PCT / 10000, "Fill too small");
```

---

## Real-World Examples

### Example 1: [H-01] Solver extracts surplus via intent ordering in CoW Protocol fork

**Source**: Sherlock
**Protocol**: CoW-style Batch Auction
**Impact**: HIGH

**Details**:

The solver had freedom to order transactions within a batch. By placing their own sandwich trades around user intents, the solver extracted the price improvement that should have gone to users. The surplus sharing mechanism only validated total batch output, not per-intent fairness, allowing the solver to redistribute surplus from users to themselves.

---

### Example 2: [H-02] Intent replay across chains in cross-chain solver network

**Source**: Immunefi
**Protocol**: Cross-chain Intent Protocol
**Impact**: CRITICAL

**Details**:

User intents were signed over (tokenIn, tokenOut, amountIn, minAmountOut) without chain ID. A user's intent on Ethereum could be replayed on Arbitrum where token prices differed. The solver could fill the intent on the chain with worst pricing for the user, even after the user thought the intent was filled on the original chain.

---

### Example 3: [M-01] Minimum fill size allows dust fills to grief users

**Source**: Code4rena
**Protocol**: Intent-based DEX
**Impact**: MEDIUM

**Details**:

Without a minimum fill size, a malicious actor could repeatedly fill intents with dust amounts (1 wei), each time claiming the minimum execution reward. This effectively griefed users by:
- Consuming gas for each dust fill notification
- Preventing legitimate solvers from filling (nonce already used)
- Draining protocol incentive pools via reward per fill

---

## Protocol-Specific Considerations

| Protocol | Model | Key Risk |
|----------|-------|----------|
| **CoW Protocol** | Batch auction, surplus to user | Solver batch ordering, surplus miscalculation |
| **UniswapX** | Dutch auction decay | Decay parameter manipulation, exclusive filler window |
| **1inch Fusion** | Resolver network | Resolver collusion, stale auction prices |
| **Across** | Optimistic relay | Relay front-running, proof manipulation |

---

## Recommended Secure Patterns

1. **Surplus sharing**: User receives price improvement above minimum, not just minimum
2. **Uniform clearing price**: All same-pair intents in a batch fill at one price
3. **Time-bound intents**: Mandatory deadline + nonce + chainId in signed intent
4. **Solver bonds proportional to flow**: Bond size scales with executed volume
5. **Minimum fill size**: Prevent dust fill griefing with per-fill minimums
6. **On-chain price benchmark**: Compare solver execution to TWAP as fairness check
7. **Intent cancellation**: Users can on-chain cancel intents before fill via nonce invalidation
