# Attack Chain: Sandwich + MEV

## Overview

Attacker front-runs and back-runs a victim's transaction on a DEX, profiting from the price impact caused by the victim's swap. Can be combined with other MEV strategies for amplified extraction.

**Complexity:** Low-Medium
**Typical Severity:** HIGH
**Protocols At Risk:** DEXs, AMMs, Any protocol with price-sensitive on-chain transactions

---

## Attack Steps

```
DETECT VICTIM TX → FRONT-RUN (BUY) → VICTIM TX EXECUTES → BACK-RUN (SELL) → PROFIT
```

### Step 1: Detect Victim Transaction
```
Monitor mempool for:
- Large swaps on DEXs
- Swaps with high slippage tolerance
- Liquidity additions/removals
- Any tx that will move price
```

**What to check (as auditor):**
- [ ] Does protocol submit swaps with user-controlled slippage?
- [ ] Is slippage tolerance hardcoded or user-set?
- [ ] Are swaps routed through public mempool?
- [ ] Is there a deadline on swaps?

### Step 2: Front-Run (Buy Before Victim)
```
- Submit same-direction swap BEFORE victim
- Use higher gas price to get priority
- Buy the token victim wants to buy
- This increases the price for victim
```

### Step 3: Victim Transaction Executes
```
- Victim buys at higher price (worse rate)
- Price increases further
- Victim's slippage tolerance absorbs the loss
```

### Step 4: Back-Run (Sell After Victim)
```
- Sell tokens acquired in front-run
- Price is now higher due to victim's purchase
- Profit = sell price - buy price - gas costs
```

---

## Code Signals

### Hardcoded Zero Slippage
```solidity
// [VULNERABLE] No slippage protection at all
function swap(uint256 amountIn) external {
    router.swapExactTokensForTokens(
        amountIn,
        0,  // amountOutMin = 0, accepts ANY price
        path,
        msg.sender,
        block.timestamp
    );
}
```

### Missing Deadline
```solidity
// [VULNERABLE] No deadline - tx can be held and executed later
function swap(uint256 amountIn, uint256 minOut) external {
    router.swapExactTokensForTokens(
        amountIn,
        minOut,
        path,
        msg.sender,
        type(uint256).max  // No deadline!
    );
}
```

### Protocol Swaps Without User Slippage Control
```solidity
// [VULNERABLE] Protocol hardcodes slippage, user can't control
function harvestAndSwap() external {
    uint256 rewards = _claimRewards();
    uint256 minOut = rewards * 95 / 100;  // 5% hardcoded slippage
    router.swapExactTokensForTokens(
        rewards, minOut, path, address(this), block.timestamp
    );
}
```

### On-Chain Slippage Calculation
```solidity
// [VULNERABLE] Calculating minOut on-chain from oracle = sandwichable
function swap(uint256 amountIn) external {
    uint256 price = oracle.getPrice();
    uint256 minOut = amountIn * price * 99 / 100 / 1e18;
    // Oracle can be manipulated in same block!
    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);
}
```

---

## Extended MEV Combinations

### Sandwich + Liquidation MEV
```
1. Front-run a large swap that will move price
2. Price movement triggers liquidations
3. Back-run: liquidate the now-undercollateralized positions
4. Also sell the front-run tokens
```

### Sandwich + JIT Liquidity
```
1. Detect large swap
2. Add concentrated liquidity just before
3. Victim swaps through your liquidity (you earn fees)
4. Remove liquidity right after
```

### Time-Bandit Attack
```
1. If block reward + MEV > parent block reward
2. Re-mine parent block with different tx ordering
3. Extract MEV from reordered transactions
```

---

## Detection Checklist

For protocols performing swaps:
- [ ] User can specify their own slippage tolerance
- [ ] Slippage is NOT hardcoded in contract
- [ ] Swap deadline is set (not type(uint256).max)
- [ ] MinOut calculated off-chain (not on-chain from oracle)
- [ ] Private transaction submission option documented
- [ ] Batch/auction mechanism for large swaps
- [ ] No zero-slippage swap calls (amountOutMin = 0)
- [ ] Protocol-level swaps (harvests, rebalances) have MEV protection

For DEX/AMM protocols:
- [ ] TWAP oracle resistant to single-block manipulation
- [ ] Price impact limits per transaction
- [ ] Concentrated liquidity positions checked for JIT
- [ ] Multi-block price consideration

---

## Mitigations

| Mitigation | Effectiveness | For |
|-----------|---------------|-----|
| User-controlled slippage | HIGH | Protocol swaps |
| Off-chain minOut calculation | HIGH | Protocol swaps |
| Flashbots/private mempool | HIGH | User txs |
| Batch auctions (CoWSwap) | HIGH | DEX design |
| Commit-reveal schemes | MEDIUM | DEX design |
| Deadline parameter | MEDIUM | All swaps |
| Price impact limits | MEDIUM | AMM design |
| TWAP (30min+) oracle | MEDIUM | Oracle-dependent |

---

## Related Patterns

- [Front-Running Patterns](../patterns/front-running-patterns.md)
- [Slippage Patterns](../patterns/slippage-patterns.md)
- [Oracle Patterns](../patterns/oracle-patterns.md)
