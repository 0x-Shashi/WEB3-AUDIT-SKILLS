# DEX / AMM SECURITY CONTEXT
> Ultra-compressed audit context. ~200 lines = 80% coverage.

## SLIPPAGE & MEV CRITICAL
1. No slippage param: `swap(amount)` without minOut → 100% sandwich | require minAmountOut
2. Hardcoded slippage: `minOut = expected * 99 / 100` → MEV in volatile markets | user-defined slippage
3. Deadline missing: swap executes hours later at bad price | require deadline param
4. Deadline too long: `deadline = block.timestamp + 1 year` → useless | recommend < 20 minutes
5. Private mempool bypass: Flashbots doesn't protect against validator MEV | accept residual risk

## PRICE CALCULATION
1. Spot price: `reserve0 / reserve1` → flash loan manipulation | use TWAP for external reads
2. K invariant violation: `newK < oldK` after swap → protocol drained | assert k >= k_prev
3. Fee not applied: swap without fee → arbitrageurs drain via k violation | always deduct fee
4. Rounding direction: round against user (favor protocol) | `amountOut = amountIn * reserveOut / (reserveIn + amountIn)`
5. Precision loss: division before multiplication | always `(a * b) / c` not `(a / c) * b`

## LIQUIDITY PROVIDER RISKS
1. First LP attack: similar to first depositor | virtual liquidity or min first LP
2. Imbalanced add: add liquidity at wrong ratio → immediate arb loss | match pool ratio
3. Remove liquidity reentrancy: callback during burn → manipulate reserves | nonReentrant
4. LP token inflation: mint LP without adding liquidity → dilute existing LPs | strict accounting

## CONSTANT PRODUCT (x*y=k)
```solidity
// Swap calculation
amountOut = (amountIn * fee * reserveOut) / (reserveIn * 10000 + amountIn * fee);
// fee = 9970 for 0.3% fee (10000 - 30)

// CHECKS:
// - amountIn > 0
// - reserveIn, reserveOut > 0
// - amountOut <= reserveOut (can't drain entire reserve)
// - new_k >= old_k
```

## CONCENTRATED LIQUIDITY (V3-style)
1. Tick math: overflow in `getSqrtRatioAtTick` → wrong prices | check tick bounds
2. Position boundaries: liquidity at wrong ticks → not earning fees | verify tick spacing
3. Fee growth: `feeGrowthInside` underflow → negative fees | use unchecked with care
4. Flash accounting: borrow in callback → must repay with fee | strict repayment check

## FLASH LOAN / FLASH SWAP
1. Callback validation: anyone can call callback directly → drain funds | verify msg.sender == pool
2. Fee collection: flash loan without fee → infinite leverage for free | enforce minimum fee
3. Reentrancy in callback: attacker reenters during flash → double spend | lock during flash
4. K check after flash: `require(k_after >= k_before)` | must verify invariant

## ORACLE MANIPULATION VIA AMM
1. Single-block: manipulate → read price → restore → profit | use TWAP
2. Multi-block: manipulate over N blocks → TWAP moves → profit | longer TWAP window
3. Low liquidity: small trade moves price significantly → cheap manipulation | liquidity requirements

## ROUTER VULNERABILITIES
1. Token approval to router: router can pull unlimited tokens | use permit or exact approval
2. Wrong path: router swaps A→B→C but B is malicious token → steal funds | validate path
3. Multi-hop slippage: slippage only on final output → sandwich in middle | per-hop limits
4. Leftover funds: ETH/token dust left in router → anyone can claim | sweep in same tx

## FEE-ON-TRANSFER TOKENS
1. Assume amount received = amount sent → accounting error | measure actual balance change
2. Pattern:
```solidity
uint256 before = token.balanceOf(address(this));
token.transferFrom(sender, address(this), amount);
uint256 received = token.balanceOf(address(this)) - before;
// Use 'received' not 'amount'
```

## REBASING TOKEN ISSUES
1. Balance changes between operations → wrong LP share calculations
2. Negative rebase → LP balance decreases, can't withdraw full
3. Fix: use wrapped non-rebasing version (wstETH not stETH)

## PERMIT / GASLESS APPROVAL
1. Replay: same signature works multiple times → drain allowance | include nonce
2. Cross-chain replay: signature from chain A works on chain B | include chainId
3. Deadline: expired permit still works → stale signatures | check deadline strictly
4. Signature malleability: s can be high or low → replay | require low s

## POOL CREATION / INITIALIZATION
1. First swap before init: pool uninitialized but swappable → wrong price | check initialized
2. Price manipulation at init: set initial price to manipulate first swap | use oracle reference
3. Pool cloning: deterministic addresses → front-run pool creation | accept or use CREATE2 salt

## CRITICAL CODE PATTERNS

### Bad Swap (No Slippage)
```solidity
// ❌ VULNERABLE
function swap(uint256 amountIn) external {
    uint256 amountOut = getAmountOut(amountIn);
    token1.transfer(msg.sender, amountOut);
}

// ✅ SAFE
function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
    require(block.timestamp <= deadline, "Expired");
    uint256 amountOut = getAmountOut(amountIn);
    require(amountOut >= minAmountOut, "Slippage");
    token1.transfer(msg.sender, amountOut);
}
```

### Bad K Invariant Check
```solidity
// ❌ VULNERABLE - K can decrease
uint256 balance0After = token0.balanceOf(address(this));
uint256 balance1After = token1.balanceOf(address(this));
// No k check!

// ✅ SAFE
require(balance0After * balance1After >= reserve0 * reserve1, "K");
```

### Bad Flash Loan Callback
```solidity
// ❌ VULNERABLE - Anyone can call
function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Attacker calls directly with fake data
}

// ✅ SAFE
function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    require(msg.sender == address(pair), "Invalid caller");
    require(sender == address(this), "Invalid sender");
}
```

## CHECKLIST (Quick Scan)
- [ ] Slippage: minAmountOut parameter, user-controlled
- [ ] Deadline: reasonable limit, checked on-chain
- [ ] K invariant: verified after every swap
- [ ] Flash loans: callback validation, fee collection
- [ ] Router: path validation, leftover handling
- [ ] Fee-on-transfer: measure actual received amount
- [ ] Rebasing: use wrapped versions
- [ ] Permit: nonce, chainId, deadline, malleability
- [ ] Oracle reads: use TWAP not spot price

## COMMON FINDINGS BY SEVERITY
**Critical**: Missing slippage, flash loan callback bypass, K violation
**High**: Oracle manipulation, router path injection, reentrancy
**Medium**: Fee-on-transfer accounting, permit replay, deadline issues
**Low**: Dust accumulation, rounding in user favor, gas optimization
