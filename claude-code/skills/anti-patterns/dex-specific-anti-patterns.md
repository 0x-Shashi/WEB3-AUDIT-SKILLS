---
id: DEX-SPECIFIC-ANTI-PATTERNS
title: DEX-Specific Anti-Patterns
category: anti-pattern
protocol: dex
triggers:
  - dex vulnerability patterns
  - amm security issues
  - swap exploit patterns
  - liquidity pool attacks
  - mev vulnerabilities
related_skills:
  - attack-trees/dex-attack-tree.md
  - patterns/amm-patterns.md
  - patterns/mev-patterns.md
  - patterns/slippage-patterns.md
---

# DEX-Specific Anti-Patterns

Comprehensive catalog of vulnerability patterns specific to decentralized exchanges and automated market makers.

---

## Overview

DEX vulnerabilities are unique due to their:
- Constant product/sum invariants
- Permissionless liquidity provision
- MEV exposure
- Price oracle usage
- Complex fee mechanics

---

## Anti-Pattern Categories

| Category | Count | Severity Range |
|----------|-------|----------------|
| [AMM Core](#amm-core-anti-patterns) | 8 | Critical-High |
| [Slippage & Price Impact](#slippage-anti-patterns) | 7 | Critical-Medium |
| [MEV & Front-Running](#mev-anti-patterns) | 8 | Critical-High |
| [Liquidity Provider](#lp-anti-patterns) | 7 | Critical-Medium |
| [Fee Mechanics](#fee-anti-patterns) | 6 | High-Medium |
| [Oracle & Pricing](#oracle-anti-patterns) | 6 | Critical-High |
| [Router & Aggregator](#router-anti-patterns) | 5 | Critical-High |

---

## AMM Core Anti-Patterns

### DEX-AP-01: Incorrect Invariant Calculation

**Description:** AMM invariant (k = x * y for constant product) calculated incorrectly, allowing extraction of value.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Integer overflow/underflow in invariant
function swap(uint256 amountIn, bool zeroForOne) external {
    uint256 reserveIn = zeroForOne ? reserve0 : reserve1;
    uint256 reserveOut = zeroForOne ? reserve1 : reserve0;
    
    // VULNERABLE: No overflow check, precision loss
    uint256 amountOut = (amountIn * reserveOut) / (reserveIn + amountIn);
    
    // VULNERABLE: Invariant not verified after swap
    _updateReserves();
}
```

**Secure Pattern:**
```solidity
function swap(uint256 amountIn, bool zeroForOne) external {
    uint256 reserveIn = zeroForOne ? reserve0 : reserve1;
    uint256 reserveOut = zeroForOne ? reserve1 : reserve0;
    
    // Calculate with fee
    uint256 amountInWithFee = amountIn * 997;
    uint256 numerator = amountInWithFee * reserveOut;
    uint256 denominator = (reserveIn * 1000) + amountInWithFee;
    uint256 amountOut = numerator / denominator;
    
    // Update reserves
    uint256 newReserveIn = reserveIn + amountIn;
    uint256 newReserveOut = reserveOut - amountOut;
    
    // SECURE: Verify invariant maintained (k only increases with fees)
    require(
        uint256(newReserveIn) * uint256(newReserveOut) >= 
        uint256(reserveIn) * uint256(reserveOut),
        "K decreased"
    );
    
    _updateReserves(newReserveIn, newReserveOut, zeroForOne);
}
```

**Real-World Instances:**
- Uranium Finance: $57M (invariant calculation error)
- Belt Finance: $6.2M (incorrect curve math)

---

### DEX-AP-02: Reentrancy in Swap

**Description:** Swap function vulnerable to reentrancy, allowing manipulation of reserves during callback.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: State updated after external call
function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
    require(amount0Out > 0 || amount1Out > 0, "Invalid output");
    
    (uint112 _reserve0, uint112 _reserve1,) = getReserves();
    require(amount0Out < _reserve0 && amount1Out < _reserve1, "Insufficient liquidity");
    
    // VULNERABLE: External call before state update
    if (amount0Out > 0) _safeTransfer(token0, to, amount0Out);
    if (amount1Out > 0) _safeTransfer(token1, to, amount1Out);
    
    if (data.length > 0) ICallee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
    
    // State update after external calls
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    
    // Update reserves (vulnerable to manipulation)
    _update(balance0, balance1, _reserve0, _reserve1);
}
```

**Secure Pattern:**
```solidity
function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external nonReentrant {
    require(amount0Out > 0 || amount1Out > 0, "Invalid output");
    
    (uint112 _reserve0, uint112 _reserve1,) = getReserves();
    require(amount0Out < _reserve0 && amount1Out < _reserve1, "Insufficient liquidity");
    
    // SECURE: Lock acquired before any state changes
    uint256 balance0Before = IERC20(token0).balanceOf(address(this));
    uint256 balance1Before = IERC20(token1).balanceOf(address(this));
    
    if (amount0Out > 0) _safeTransfer(token0, to, amount0Out);
    if (amount1Out > 0) _safeTransfer(token1, to, amount1Out);
    
    if (data.length > 0) ICallee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
    
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    
    // SECURE: Verify amounts received
    uint256 amount0In = balance0 > balance0Before - amount0Out ? balance0 - (balance0Before - amount0Out) : 0;
    uint256 amount1In = balance1 > balance1Before - amount1Out ? balance1 - (balance1Before - amount1Out) : 0;
    require(amount0In > 0 || amount1In > 0, "Insufficient input");
    
    // SECURE: K check with proper accounting
    require(balance0 * balance1 >= uint256(_reserve0) * uint256(_reserve1), "K");
    
    _update(balance0, balance1, _reserve0, _reserve1);
}
```

**Real-World Instances:**
- Curve Finance (Read-only): Multiple DeFi protocols affected
- Various UniV2 forks with callback vulnerabilities

---

### DEX-AP-03: Flash Loan Pool Manipulation

**Description:** AMM pool state can be manipulated within a flash loan to extract value.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Price derived from current reserves
function getPrice(address token) external view returns (uint256) {
    if (token == token0) {
        return (reserve1 * 1e18) / reserve0;  // VULNERABLE: Manipulatable
    } else {
        return (reserve0 * 1e18) / reserve1;
    }
}

// Another protocol using this price
function liquidate(address user) external {
    uint256 price = dex.getPrice(collateralToken);
    uint256 collateralValue = userCollateral[user] * price / 1e18;
    
    require(collateralValue < userDebt[user], "Not liquidatable");
    // Execute liquidation...
}
```

**Secure Pattern:**
```solidity
// SECURE: TWAP oracle
function getPrice(address token) external view returns (uint256) {
    // Use time-weighted average price
    (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp) = 
        UniswapV2OracleLibrary.currentCumulativePrices(address(pair));
    
    uint32 timeElapsed = blockTimestamp - blockTimestampLast;
    require(timeElapsed >= MINIMUM_PERIOD, "Period too short");
    
    // Calculate TWAP
    uint256 price0Average = (price0Cumulative - price0CumulativeLast) / timeElapsed;
    return price0Average;
}

// With manipulation resistance
function liquidate(address user) external {
    uint256 spotPrice = dex.getSpotPrice(collateralToken);
    uint256 twapPrice = dex.getTwapPrice(collateralToken, 30 minutes);
    
    // SECURE: Require price consistency
    require(
        spotPrice * 100 / twapPrice > 95 && spotPrice * 100 / twapPrice < 105,
        "Price deviation too high"
    );
    
    // Use the more conservative price
    uint256 price = spotPrice < twapPrice ? spotPrice : twapPrice;
    // Continue with liquidation...
}
```

**Real-World Instances:**
- Harvest Finance: $34M (flash loan + pool manipulation)
- Warp Finance: $7.7M (LP token price manipulation)

---

### DEX-AP-04: Incorrect Reserve Update

**Description:** Reserves not updated atomically or correctly after operations.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Reserves updated from balances without accounting for fees
function _update() internal {
    reserve0 = uint112(IERC20(token0).balanceOf(address(this)));
    reserve1 = uint112(IERC20(token1).balanceOf(address(this)));
    // VULNERABLE: Donation attack possible
    // Anyone can send tokens to inflate reserves
}
```

**Secure Pattern:**
```solidity
// SECURE: Track expected balances separately
function _update(
    uint256 balance0, 
    uint256 balance1, 
    uint112 _reserve0, 
    uint112 _reserve1
) internal {
    require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, "Overflow");
    
    // SECURE: Update with provided values, not raw balances
    reserve0 = uint112(balance0);
    reserve1 = uint112(balance1);
    
    // Update price accumulators for TWAP
    uint32 blockTimestamp = uint32(block.timestamp % 2**32);
    uint32 timeElapsed = blockTimestamp - blockTimestampLast;
    
    if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
        price0CumulativeLast += uint256(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
        price1CumulativeLast += uint256(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
    }
    
    blockTimestampLast = blockTimestamp;
    emit Sync(reserve0, reserve1);
}

// SECURE: Skim function to handle donations
function skim(address to) external nonReentrant {
    address _token0 = token0;
    address _token1 = token1;
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
}
```

---

### DEX-AP-05: Unbalanced Pool Initialization

**Description:** Pool can be initialized with extreme ratios, creating arbitrage opportunities.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No validation on initial liquidity ratio
function initialize(uint256 amount0, uint256 amount1) external {
    require(totalSupply == 0, "Already initialized");
    
    IERC20(token0).transferFrom(msg.sender, address(this), amount0);
    IERC20(token1).transferFrom(msg.sender, address(this), amount1);
    
    // VULNERABLE: Any ratio accepted
    uint256 liquidity = Math.sqrt(amount0 * amount1);
    _mint(msg.sender, liquidity);
}
```

**Secure Pattern:**
```solidity
function initialize(uint256 amount0, uint256 amount1) external {
    require(totalSupply == 0, "Already initialized");
    
    // SECURE: Validate against external oracle
    uint256 expectedRatio = priceOracle.getPrice(token0, token1);
    uint256 actualRatio = (amount1 * 1e18) / amount0;
    
    require(
        actualRatio > expectedRatio * 95 / 100 &&
        actualRatio < expectedRatio * 105 / 100,
        "Ratio too far from market"
    );
    
    // SECURE: Minimum liquidity burned
    IERC20(token0).transferFrom(msg.sender, address(this), amount0);
    IERC20(token1).transferFrom(msg.sender, address(this), amount1);
    
    uint256 liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
    _mint(address(0), MINIMUM_LIQUIDITY);  // Burn minimum liquidity
    _mint(msg.sender, liquidity);
}
```

---

### DEX-AP-06: Concentrated Liquidity Range Exploit

**Description:** Concentrated liquidity positions (Uniswap V3 style) with exploitable tick boundaries.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No validation on tick range
function mint(int24 tickLower, int24 tickUpper, uint128 amount) external {
    require(tickLower < tickUpper, "Invalid range");
    
    // VULNERABLE: Extremely narrow ranges can be exploited
    // VULNERABLE: Tick at exact current price can cause issues
    
    (uint256 amount0, uint256 amount1) = _calculateAmounts(tickLower, tickUpper, amount);
    // ...
}
```

**Secure Pattern:**
```solidity
function mint(int24 tickLower, int24 tickUpper, uint128 amount) external {
    require(tickLower < tickUpper, "Invalid range");
    require(tickLower >= TickMath.MIN_TICK, "tickLower too low");
    require(tickUpper <= TickMath.MAX_TICK, "tickUpper too high");
    
    // SECURE: Enforce minimum range width
    require(tickUpper - tickLower >= MIN_TICK_RANGE, "Range too narrow");
    
    // SECURE: Ticks must be on valid spacing
    require(tickLower % tickSpacing == 0, "tickLower not on spacing");
    require(tickUpper % tickSpacing == 0, "tickUpper not on spacing");
    
    (uint256 amount0, uint256 amount1) = _calculateAmounts(tickLower, tickUpper, amount);
    // ...
}
```

---

### DEX-AP-07: Virtual Reserve Manipulation

**Description:** Virtual AMMs or synthetic pools with manipulatable virtual reserves.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Virtual reserves can be gamed
function setVirtualReserves(uint256 _virtualReserve0, uint256 _virtualReserve1) external onlyOwner {
    virtualReserve0 = _virtualReserve0;
    virtualReserve1 = _virtualReserve1;
    // VULNERABLE: No validation, instant update
}

function getAmountOut(uint256 amountIn) external view returns (uint256) {
    // Uses virtual reserves for calculation
    uint256 k = virtualReserve0 * virtualReserve1;
    return virtualReserve1 - (k / (virtualReserve0 + amountIn));
}
```

**Secure Pattern:**
```solidity
// SECURE: Gradual virtual reserve adjustment
function adjustVirtualReserves(uint256 _virtualReserve0, uint256 _virtualReserve1) external onlyOwner {
    require(
        _virtualReserve0 <= virtualReserve0 * 110 / 100 &&
        _virtualReserve0 >= virtualReserve0 * 90 / 100,
        "Adjustment too large"
    );
    
    // SECURE: Time-delayed update
    pendingVirtualReserve0 = _virtualReserve0;
    pendingVirtualReserve1 = _virtualReserve1;
    virtualReserveUpdateTime = block.timestamp + TIMELOCK_DELAY;
}

function applyVirtualReserves() external {
    require(block.timestamp >= virtualReserveUpdateTime, "Too early");
    virtualReserve0 = pendingVirtualReserve0;
    virtualReserve1 = pendingVirtualReserve1;
}
```

---

### DEX-AP-08: Multi-Hop Routing Exploit

**Description:** Multi-hop swaps through multiple pools with exploitable intermediate states.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No slippage check on intermediate hops
function swapMultiHop(
    address[] calldata path,
    uint256 amountIn,
    uint256 minAmountOut
) external returns (uint256) {
    uint256 currentAmount = amountIn;
    
    for (uint256 i = 0; i < path.length - 1; i++) {
        // VULNERABLE: Each hop uses current pool price
        // Attacker can manipulate intermediate pools
        currentAmount = _swap(path[i], path[i+1], currentAmount);
    }
    
    require(currentAmount >= minAmountOut, "Slippage");
    return currentAmount;
}
```

**Secure Pattern:**
```solidity
function swapMultiHop(
    address[] calldata path,
    uint256 amountIn,
    uint256 minAmountOut,
    uint256[] calldata minIntermediateAmounts  // SECURE: Per-hop minimums
) external returns (uint256) {
    require(path.length - 1 == minIntermediateAmounts.length, "Invalid params");
    
    uint256 currentAmount = amountIn;
    
    for (uint256 i = 0; i < path.length - 1; i++) {
        currentAmount = _swap(path[i], path[i+1], currentAmount);
        // SECURE: Check each intermediate amount
        require(currentAmount >= minIntermediateAmounts[i], "Intermediate slippage");
    }
    
    require(currentAmount >= minAmountOut, "Final slippage");
    return currentAmount;
}
```

---

## Slippage Anti-Patterns

### DEX-AP-09: No Slippage Protection

**Description:** Swap functions without minimum output amount or deadline.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No minimum output
function swap(address tokenIn, uint256 amountIn) external returns (uint256) {
    uint256 amountOut = getAmountOut(amountIn);
    // VULNERABLE: User gets whatever the current price gives
    _doSwap(tokenIn, amountIn, amountOut);
    return amountOut;
}
```

**Secure Pattern:**
```solidity
function swap(
    address tokenIn, 
    uint256 amountIn,
    uint256 minAmountOut,  // SECURE: Slippage protection
    uint256 deadline       // SECURE: Time protection
) external returns (uint256) {
    require(block.timestamp <= deadline, "Expired");
    
    uint256 amountOut = getAmountOut(amountIn);
    require(amountOut >= minAmountOut, "Slippage too high");
    
    _doSwap(tokenIn, amountIn, amountOut);
    return amountOut;
}
```

---

### DEX-AP-10: Zero Slippage Tolerance

**Description:** Setting minAmountOut to 0 or extremely low values.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Frontend or contract uses 0 slippage
router.swapExactTokensForTokens(
    amountIn,
    0,  // VULNERABLE: minAmountOut = 0
    path,
    to,
    deadline
);
```

**Secure Pattern:**
```solidity
// SECURE: Calculate appropriate slippage
uint256 expectedOut = getExpectedOutput(amountIn, path);
uint256 minAmountOut = expectedOut * (100 - SLIPPAGE_BPS) / 100;

require(minAmountOut > 0, "Min amount cannot be 0");

router.swapExactTokensForTokens(
    amountIn,
    minAmountOut,
    path,
    to,
    deadline
);
```

---

### DEX-AP-11: Stale Deadline

**Description:** Transaction deadline set too far in the future or not enforced.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Deadline far in future
router.swapExactTokensForTokens(
    amountIn,
    minAmountOut,
    path,
    to,
    block.timestamp + 365 days  // VULNERABLE: Can be executed much later
);
```

**Secure Pattern:**
```solidity
// SECURE: Short deadline
uint256 deadline = block.timestamp + 15 minutes;

router.swapExactTokensForTokens(
    amountIn,
    minAmountOut,
    path,
    to,
    deadline
);
```

---

### DEX-AP-12: Price Impact Not Checked

**Description:** Large swaps without checking total price impact.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No price impact check
function swapLarge(uint256 amountIn) external {
    // Swaps regardless of how much it moves the price
    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);
}
```

**Secure Pattern:**
```solidity
function swapLarge(uint256 amountIn, uint256 maxPriceImpact) external {
    // Get price before
    uint256 priceBefore = getPrice();
    
    // Calculate expected output at current price
    uint256 expectedOut = amountIn * priceBefore / 1e18;
    uint256 minAmountOut = expectedOut * (10000 - maxPriceImpact) / 10000;
    
    uint256 actualOut = router.swapExactTokensForTokens(
        amountIn, 
        minAmountOut, 
        path, 
        address(this), 
        deadline
    );
    
    // SECURE: Verify actual price impact
    uint256 actualPriceImpact = (expectedOut - actualOut) * 10000 / expectedOut;
    require(actualPriceImpact <= maxPriceImpact, "Price impact too high");
}
```

---

### DEX-AP-13: Slippage on Wrong Value

**Description:** Slippage protection applied to wrong metric (e.g., shares instead of value).

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Slippage on shares, not value
function removeLiquidity(uint256 lpTokens, uint256 minShares) external {
    // minShares doesn't protect against share value manipulation
    uint256 shares = _calculateShares(lpTokens);
    require(shares >= minShares, "Slippage");
    // Attacker can manipulate underlying value while maintaining share count
}
```

**Secure Pattern:**
```solidity
function removeLiquidity(
    uint256 lpTokens, 
    uint256 minAmount0,  // SECURE: Min for each token
    uint256 minAmount1
) external {
    (uint256 amount0, uint256 amount1) = _calculateWithdrawal(lpTokens);
    
    require(amount0 >= minAmount0, "Slippage token0");
    require(amount1 >= minAmount1, "Slippage token1");
    
    _burnAndTransfer(lpTokens, amount0, amount1);
}
```

---

### DEX-AP-14: Partial Fill Without Protection

**Description:** Orders that can be partially filled without user consent.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Partial fills allowed without protection
function fillOrder(Order memory order, uint256 fillAmount) external {
    require(fillAmount <= order.amount, "Exceeds order");
    // VULNERABLE: User might not want partial fills
    _executeFill(order, fillAmount);
}
```

**Secure Pattern:**
```solidity
struct Order {
    uint256 amount;
    uint256 minFillAmount;  // SECURE: Minimum fill or reject
    bool allowPartialFill;  // SECURE: Explicit opt-in
}

function fillOrder(Order memory order, uint256 fillAmount) external {
    require(fillAmount <= order.amount, "Exceeds order");
    
    if (!order.allowPartialFill) {
        require(fillAmount == order.amount, "Partial fill not allowed");
    } else {
        require(fillAmount >= order.minFillAmount, "Fill too small");
    }
    
    _executeFill(order, fillAmount);
}
```

---

### DEX-AP-15: Slippage Bypass via Callback

**Description:** Callbacks allowing slippage protection to be circumvented.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Callback can manipulate state before slippage check
function swapWithCallback(uint256 amountIn, uint256 minOut, bytes calldata data) external {
    uint256 amountOut = _calculateOut(amountIn);
    
    // Callback before slippage check
    ICallback(msg.sender).swapCallback(amountIn, amountOut, data);
    
    // VULNERABLE: State could be changed in callback
    require(amountOut >= minOut, "Slippage");
}
```

**Secure Pattern:**
```solidity
function swapWithCallback(uint256 amountIn, uint256 minOut, bytes calldata data) external nonReentrant {
    uint256 amountOut = _calculateOut(amountIn);
    
    // SECURE: Slippage check before callback
    require(amountOut >= minOut, "Slippage");
    
    // SECURE: Record state before callback
    uint256 balanceBefore = token.balanceOf(address(this));
    
    ICallback(msg.sender).swapCallback(amountIn, amountOut, data);
    
    // SECURE: Verify state unchanged by callback
    require(token.balanceOf(address(this)) >= balanceBefore + amountIn, "Insufficient input");
}
```

---

## MEV Anti-Patterns

### DEX-AP-16: Unprotected Swap Transaction

**Description:** Swap transactions visible in mempool, enabling front-running.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Standard swap visible to MEV bots
function swap(uint256 amountIn, uint256 minOut) external {
    // This transaction is in mempool
    // MEV bots can front-run with same trade
    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);
}
```

**Secure Pattern:**
```solidity
// SECURE: Use private mempool or commit-reveal
function commitSwap(bytes32 commitment) external {
    require(commitments[msg.sender] == bytes32(0), "Pending commitment");
    commitments[msg.sender] = commitment;
    commitTimes[msg.sender] = block.timestamp;
}

function executeSwap(
    uint256 amountIn, 
    uint256 minOut, 
    bytes32 salt
) external {
    bytes32 commitment = keccak256(abi.encode(amountIn, minOut, salt));
    require(commitments[msg.sender] == commitment, "Invalid commitment");
    require(block.timestamp >= commitTimes[msg.sender] + COMMIT_DELAY, "Too early");
    require(block.timestamp <= commitTimes[msg.sender] + COMMIT_EXPIRY, "Expired");
    
    delete commitments[msg.sender];
    
    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);
}
```

---

### DEX-AP-17: Sandwich Attack Vulnerability

**Description:** Transactions can be sandwiched between attacker's buy and sell.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Large swap with low slippage tolerance
function executeLargeSwap() external {
    // Visible in mempool, sandwich-able
    router.swapExactTokensForTokens(
        1000000e18,  // Large amount
        950000e18,   // 5% slippage - attacker profit margin
        path,
        msg.sender,
        deadline
    );
}
```

**Secure Pattern:**
```solidity
// SECURE: Use Flashbots/MEV protection + tight slippage
function executeLargeSwap(uint256 amountIn, uint256 minOut) external {
    // Tighter slippage (0.5%)
    uint256 expectedOut = getQuote(amountIn);
    require(minOut >= expectedOut * 995 / 1000, "Slippage too loose");
    
    // Use MEV-protected RPC or private transaction
    // This should be sent via Flashbots Protect or similar
    router.swapExactTokensForTokens(
        amountIn,
        minOut,
        path,
        msg.sender,
        block.timestamp + 2 minutes  // Short deadline
    );
}
```

---

### DEX-AP-18: JIT Liquidity Attack

**Description:** Just-in-time liquidity added to capture fees, then removed.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Instant LP add/remove allowed
function addLiquidity(uint256 amount0, uint256 amount1) external {
    // No time lock
    _mint(msg.sender, _calculateLP(amount0, amount1));
}

function removeLiquidity(uint256 lpAmount) external {
    // VULNERABLE: Can remove immediately after adding
    _burn(msg.sender, lpAmount);
    _transferTokens(msg.sender);
}
```

**Secure Pattern:**
```solidity
mapping(address => uint256) public lpLockTime;

function addLiquidity(uint256 amount0, uint256 amount1) external {
    uint256 lpAmount = _calculateLP(amount0, amount1);
    _mint(msg.sender, lpAmount);
    
    // SECURE: Set lock time
    lpLockTime[msg.sender] = block.timestamp + MIN_LP_LOCK;
}

function removeLiquidity(uint256 lpAmount) external {
    // SECURE: Enforce minimum holding period
    require(block.timestamp >= lpLockTime[msg.sender], "LP locked");
    
    _burn(msg.sender, lpAmount);
    _transferTokens(msg.sender);
}
```

---

### DEX-AP-19: Oracle Update Front-Running

**Description:** Price oracle updates can be front-run to profit from stale prices.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Oracle update visible, swap uses old price until updated
function updatePrice() external {
    // This can be front-run
    price = getExternalPrice();
    lastUpdateTime = block.timestamp;
}

function swap(uint256 amountIn) external returns (uint256) {
    // Uses potentially stale price
    return amountIn * price / 1e18;
}
```

**Secure Pattern:**
```solidity
// SECURE: Use Chainlink with heartbeat checks
function swap(uint256 amountIn) external returns (uint256) {
    (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    
    // SECURE: Check freshness
    require(updatedAt >= block.timestamp - MAX_ORACLE_DELAY, "Stale price");
    require(answer > 0, "Invalid price");
    require(answeredInRound >= roundId, "Stale round");
    
    return amountIn * uint256(answer) / 1e18;
}
```

---

### DEX-AP-20: Backrunning Vulnerability

**Description:** Large trades create backrunning opportunity for arbitrageurs.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Large trade creates arbitrage opportunity
function executeTrade(uint256 largeAmount) external {
    // This moves the price significantly
    router.swap(largeAmount, 0, path);
    // After this, price is imbalanced
    // Arbitrageurs backrun to profit from rebalancing
}
```

**Secure Pattern:**
```solidity
// SECURE: Split large trades, use TWAP
function executeLargeTrade(
    uint256 totalAmount, 
    uint256 chunks,
    uint256 delay
) external {
    uint256 chunkSize = totalAmount / chunks;
    
    for (uint256 i = 0; i < chunks; i++) {
        // Queue chunks with delays
        pendingSwaps.push(PendingSwap({
            amount: chunkSize,
            executeAfter: block.timestamp + (delay * i),
            executed: false
        }));
    }
}

function executeChunk(uint256 index) external {
    PendingSwap storage ps = pendingSwaps[index];
    require(block.timestamp >= ps.executeAfter, "Too early");
    require(!ps.executed, "Already executed");
    
    ps.executed = true;
    router.swap(ps.amount, calculateMinOut(ps.amount), path);
}
```

---

### DEX-AP-21: Block Stuffing for Price Manipulation

**Description:** Attacker fills blocks to delay transactions and manipulate timing.

**Severity:** High

**Mitigation:**
```solidity
// SECURE: Use block number ranges instead of exact blocks
function executeTimeSensitiveSwap(
    uint256 amountIn,
    uint256 minOut,
    uint256 minBlock,
    uint256 maxBlock
) external {
    require(block.number >= minBlock, "Too early");
    require(block.number <= maxBlock, "Too late");
    
    // Use multiple block confirmations for price
    uint256 price = getAveragePrice(minBlock, block.number);
    // ...
}
```

---

### DEX-AP-22: Long-Tail Asset MEV

**Description:** Low-liquidity tokens especially vulnerable to MEV due to high price impact.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Same slippage for all tokens
function swap(address token, uint256 amountIn) external {
    uint256 minOut = amountIn * 95 / 100;  // 5% for all tokens
    router.swap(token, amountIn, minOut);
}
```

**Secure Pattern:**
```solidity
// SECURE: Dynamic slippage based on liquidity
function swap(address token, uint256 amountIn) external {
    uint256 liquidity = getPoolLiquidity(token);
    
    // Higher slippage protection for low liquidity
    uint256 slippageBps;
    if (liquidity < 100000e18) {
        slippageBps = 1000;  // 10% for very low liquidity
    } else if (liquidity < 1000000e18) {
        slippageBps = 500;   // 5% for low liquidity
    } else {
        slippageBps = 50;    // 0.5% for high liquidity
    }
    
    uint256 expectedOut = getQuote(token, amountIn);
    uint256 minOut = expectedOut * (10000 - slippageBps) / 10000;
    
    router.swap(token, amountIn, minOut);
}
```

---

### DEX-AP-23: Mempool Sniping

**Description:** Monitoring mempool to snipe new token listings or liquidity additions.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Visible liquidity addition
function addInitialLiquidity(address token, uint256 amount) external {
    // This is visible in mempool
    // Snipers can front-run to buy before liquidity is added
    router.addLiquidity(token, WETH, amount, ethAmount, 0, 0, msg.sender, deadline);
}
```

**Secure Pattern:**
```solidity
// SECURE: Private launch with anti-snipe
function addInitialLiquidity(
    address token, 
    uint256 amount,
    uint256 maxBuyPerBlock  // SECURE: Limit buys per block
) external onlyOwner {
    // Use private mempool (Flashbots)
    // Deploy with anti-snipe parameters
    
    IAntiSnipeToken(token).setMaxBuyPerBlock(maxBuyPerBlock);
    IAntiSnipeToken(token).setLaunchBlock(block.number);
    
    router.addLiquidity(token, WETH, amount, ethAmount, 0, 0, msg.sender, deadline);
    
    // Enable trading after N blocks
    IAntiSnipeToken(token).enableTrading();
}
```

---

## LP Anti-Patterns

### DEX-AP-24: LP Share Inflation Attack

**Description:** First depositor or subsequent depositors can manipulate LP share value.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No minimum liquidity
function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
    if (totalSupply == 0) {
        liquidity = Math.sqrt(amount0 * amount1);
    } else {
        liquidity = Math.min(
            amount0 * totalSupply / reserve0,
            amount1 * totalSupply / reserve1
        );
    }
    _mint(msg.sender, liquidity);
}
```

**Secure Pattern:**
```solidity
uint256 public constant MINIMUM_LIQUIDITY = 1000;

function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
    if (totalSupply == 0) {
        liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
        // SECURE: Burn minimum liquidity to prevent inflation
        _mint(address(0xdead), MINIMUM_LIQUIDITY);
    } else {
        liquidity = Math.min(
            amount0 * totalSupply / reserve0,
            amount1 * totalSupply / reserve1
        );
    }
    
    require(liquidity > 0, "Insufficient liquidity minted");
    _mint(msg.sender, liquidity);
}
```

**Real-World Instances:**
- Multiple Uniswap V2 fork exploits
- Balancer pool initialization attacks

---

### DEX-AP-25: Impermanent Loss Amplification

**Description:** Protocol mechanics that amplify impermanent loss beyond normal AMM behavior.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Asymmetric fees amplify IL
function collectFees() external {
    // Only token0 fees collected
    uint256 fees0 = accumulatedFees0;
    accumulatedFees0 = 0;
    
    // VULNERABLE: LPs bear IL on token1 without compensation
    _transfer(token0, feeCollector, fees0);
}
```

**Secure Pattern:**
```solidity
function collectFees() external {
    // SECURE: Proportional fee collection
    uint256 fees0 = accumulatedFees0;
    uint256 fees1 = accumulatedFees1;
    
    // Distribute to LPs proportionally
    uint256 lpFees0 = fees0 * LP_FEE_SHARE / 100;
    uint256 lpFees1 = fees1 * LP_FEE_SHARE / 100;
    
    // Add back to reserves (benefits LPs)
    reserve0 += lpFees0;
    reserve1 += lpFees1;
    
    // Protocol takes remainder
    _transfer(token0, feeCollector, fees0 - lpFees0);
    _transfer(token1, feeCollector, fees1 - lpFees1);
}
```

---

### DEX-AP-26: LP Token as Collateral Exploit

**Description:** Using LP tokens as collateral without accounting for manipulation risk.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: LP token price from spot reserves
function getLPTokenPrice() external view returns (uint256) {
    uint256 reserve0Value = reserve0 * getPrice(token0);
    uint256 reserve1Value = reserve1 * getPrice(token1);
    return (reserve0Value + reserve1Value) / totalSupply;
    // VULNERABLE: Can be manipulated with flash loan
}
```

**Secure Pattern:**
```solidity
// SECURE: Fair LP token pricing (Alpha Homora method)
function getFairLPTokenPrice() external view returns (uint256) {
    uint256 sqrtK = Math.sqrt(uint256(reserve0) * uint256(reserve1));
    uint256 px0 = getTwapPrice(token0);  // TWAP, not spot
    uint256 px1 = getTwapPrice(token1);
    
    // Fair price = 2 * sqrt(k * px0 * px1) / totalSupply
    uint256 fairPrice = 2 * Math.sqrt(sqrtK * Math.sqrt(px0 * px1)) * 1e18 / totalSupply;
    
    return fairPrice;
}
```

---

### DEX-AP-27: Rug Pull via LP Removal

**Description:** Large LP holder can remove liquidity suddenly, crashing price.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No limits on LP removal
function removeLiquidity(uint256 lpAmount) external {
    require(balanceOf[msg.sender] >= lpAmount, "Insufficient LP");
    
    uint256 amount0 = lpAmount * reserve0 / totalSupply;
    uint256 amount1 = lpAmount * reserve1 / totalSupply;
    
    _burn(msg.sender, lpAmount);
    _transfer(token0, msg.sender, amount0);
    _transfer(token1, msg.sender, amount1);
}
```

**Secure Pattern:**
```solidity
// SECURE: Gradual withdrawal limits
uint256 public constant MAX_DAILY_WITHDRAWAL_PERCENT = 10;
mapping(address => uint256) public dailyWithdrawn;
mapping(address => uint256) public lastWithdrawalDay;

function removeLiquidity(uint256 lpAmount) external {
    uint256 today = block.timestamp / 1 days;
    
    if (lastWithdrawalDay[msg.sender] < today) {
        dailyWithdrawn[msg.sender] = 0;
        lastWithdrawalDay[msg.sender] = today;
    }
    
    uint256 maxWithdrawal = balanceOf[msg.sender] * MAX_DAILY_WITHDRAWAL_PERCENT / 100;
    require(dailyWithdrawn[msg.sender] + lpAmount <= maxWithdrawal, "Daily limit exceeded");
    
    dailyWithdrawn[msg.sender] += lpAmount;
    
    // Proceed with withdrawal...
}
```

---

### DEX-AP-28: Single-Sided Liquidity Exploit

**Description:** Single-sided deposits without proper imbalance fees.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No imbalance fee
function addSingleSided(address token, uint256 amount) external {
    // Just swap half and add
    uint256 halfAmount = amount / 2;
    uint256 swappedAmount = _swap(token, otherToken, halfAmount);
    
    // VULNERABLE: No fee for imbalancing the pool
    _addLiquidity(halfAmount, swappedAmount);
}
```

**Secure Pattern:**
```solidity
function addSingleSided(address token, uint256 amount) external {
    uint256 currentRatio = reserve0 * 1e18 / reserve1;
    
    // Calculate optimal split
    (uint256 amount0, uint256 amount1) = _calculateOptimalSplit(token, amount);
    
    // Swap portion
    uint256 swapAmount = token == token0 ? amount - amount0 : amount - amount1;
    uint256 swappedAmount = _swap(token, _otherToken(token), swapAmount);
    
    // SECURE: Charge imbalance fee
    uint256 newRatio = (reserve0 + amount0) * 1e18 / (reserve1 + swappedAmount);
    uint256 ratioDiff = newRatio > currentRatio ? 
        newRatio - currentRatio : currentRatio - newRatio;
    
    uint256 imbalanceFee = ratioDiff * IMBALANCE_FEE_BPS / 1e18;
    uint256 feeAmount = amount * imbalanceFee / 10000;
    
    _addLiquidity(amount0 - feeAmount, swappedAmount);
}
```

---

### DEX-AP-29: LP Migration Attack

**Description:** Migrating LP to new contract without proper validation.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Migration to arbitrary address
function migrate(address newPool) external onlyOwner {
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    
    // VULNERABLE: No validation of newPool
    IERC20(token0).transfer(newPool, balance0);
    IERC20(token1).transfer(newPool, balance1);
}
```

**Secure Pattern:**
```solidity
address public pendingMigration;
uint256 public migrationTimestamp;

function proposeMigration(address newPool) external onlyOwner {
    require(newPool != address(0), "Invalid address");
    require(IPool(newPool).token0() == token0, "Token mismatch");
    require(IPool(newPool).token1() == token1, "Token mismatch");
    
    pendingMigration = newPool;
    migrationTimestamp = block.timestamp + MIGRATION_DELAY;
    
    emit MigrationProposed(newPool, migrationTimestamp);
}

function executeMigration() external onlyOwner {
    require(pendingMigration != address(0), "No migration proposed");
    require(block.timestamp >= migrationTimestamp, "Too early");
    
    // Users have had time to exit
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    
    IERC20(token0).transfer(pendingMigration, balance0);
    IERC20(token1).transfer(pendingMigration, balance1);
    
    emit MigrationExecuted(pendingMigration);
}
```

---

### DEX-AP-30: Fee-on-Transfer LP Issues

**Description:** LP tokens with transfer fees causing accounting errors.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Doesn't account for LP token fees
function stakeLp(uint256 amount) external {
    lpToken.transferFrom(msg.sender, address(this), amount);
    // VULNERABLE: If LP has fee, received less than amount
    stakedBalance[msg.sender] += amount;
}
```

**Secure Pattern:**
```solidity
function stakeLp(uint256 amount) external {
    uint256 balanceBefore = lpToken.balanceOf(address(this));
    lpToken.transferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = lpToken.balanceOf(address(this));
    
    // SECURE: Use actual received amount
    uint256 received = balanceAfter - balanceBefore;
    stakedBalance[msg.sender] += received;
}
```

---

## Fee Anti-Patterns

### DEX-AP-31: Fee Bypass via Direct Transfer

**Description:** Fees can be avoided by directly transferring tokens.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Swap function charges fee, but direct transfers don't
function swap(uint256 amountIn, bool zeroForOne) external {
    uint256 fee = amountIn * FEE_BPS / 10000;
    uint256 amountInAfterFee = amountIn - fee;
    // ...
}

// VULNERABLE: Direct transfer updates reserves without fee
function sync() external {
    reserve0 = IERC20(token0).balanceOf(address(this));
    reserve1 = IERC20(token1).balanceOf(address(this));
}
```

**Secure Pattern:**
```solidity
function sync() external {
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    
    // SECURE: Treat excess as donation (or route to fee collector)
    if (balance0 > reserve0) {
        uint256 excess = balance0 - reserve0;
        IERC20(token0).transfer(feeCollector, excess);
        balance0 = reserve0;
    }
    if (balance1 > reserve1) {
        uint256 excess = balance1 - reserve1;
        IERC20(token1).transfer(feeCollector, excess);
        balance1 = reserve1;
    }
    
    _update(balance0, balance1);
}
```

---

### DEX-AP-32: Dynamic Fee Manipulation

**Description:** Dynamic fees can be manipulated to pay less.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Fee based on current volatility
function getFee() public view returns (uint256) {
    uint256 volatility = calculateVolatility();
    if (volatility > HIGH_VOL_THRESHOLD) {
        return HIGH_FEE;
    }
    return LOW_FEE;  // VULNERABLE: Can be manipulated to stay low
}
```

**Secure Pattern:**
```solidity
function getFee() public view returns (uint256) {
    // SECURE: Use time-weighted volatility
    uint256 volatility = twapVolatility.getAverage(VOLATILITY_WINDOW);
    
    // SECURE: Minimum fee always applies
    uint256 baseFee = MIN_FEE;
    uint256 volatilityFee = volatility * VOLATILITY_FEE_MULTIPLIER / 1e18;
    
    return baseFee + volatilityFee;
}
```

---

### DEX-AP-33: Protocol Fee Extraction

**Description:** Protocol fees accumulated but extractable by attackers.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Anyone can call, fees sent to msg.sender
function collectProtocolFees() external {
    uint256 fees = accumulatedFees;
    accumulatedFees = 0;
    IERC20(token).transfer(msg.sender, fees);
}
```

**Secure Pattern:**
```solidity
function collectProtocolFees() external {
    require(msg.sender == feeCollector, "Not authorized");
    
    uint256 fees = accumulatedFees;
    accumulatedFees = 0;
    IERC20(token).transfer(feeCollector, fees);
    
    emit FeesCollected(fees);
}
```

---

### DEX-AP-34: Fee Rounding Exploitation

**Description:** Fee calculations with rounding errors can be exploited.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Rounding down can result in 0 fee
function calculateFee(uint256 amount) internal pure returns (uint256) {
    return amount * FEE_BPS / 10000;  // If amount < 10000/FEE_BPS, fee = 0
}
```

**Secure Pattern:**
```solidity
function calculateFee(uint256 amount) internal pure returns (uint256) {
    // SECURE: Round up, minimum fee
    uint256 fee = (amount * FEE_BPS + 9999) / 10000;
    return fee > MIN_FEE ? fee : MIN_FEE;
}
```

---

### DEX-AP-35: Referral Fee Gaming

**Description:** Referral fees can be gamed by self-referral.

**Severity:** Low

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Self-referral possible
function swapWithReferral(uint256 amountIn, address referrer) external {
    uint256 fee = amountIn * FEE_BPS / 10000;
    uint256 referralBonus = fee * REFERRAL_BPS / 10000;
    
    // VULNERABLE: User can be their own referrer
    IERC20(token).transfer(referrer, referralBonus);
}
```

**Secure Pattern:**
```solidity
function swapWithReferral(uint256 amountIn, address referrer) external {
    require(referrer != msg.sender, "Self-referral not allowed");
    require(referrer != address(0), "Invalid referrer");
    require(isApprovedReferrer[referrer], "Referrer not approved");
    
    uint256 fee = amountIn * FEE_BPS / 10000;
    uint256 referralBonus = fee * REFERRAL_BPS / 10000;
    
    pendingReferralRewards[referrer] += referralBonus;
    // Referrer claims later with time delay
}
```

---

### DEX-AP-36: Flash Swap Fee Avoidance

**Description:** Flash swaps allowing fee avoidance through atomic arbitrage.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Flash swap doesn't charge fee if repaid with same token
function flashSwap(uint256 amount, bytes calldata data) external {
    IERC20(token).transfer(msg.sender, amount);
    
    IFlashSwapCallback(msg.sender).flashSwapCallback(amount, data);
    
    // VULNERABLE: Only checks repayment, not fee
    require(IERC20(token).balanceOf(address(this)) >= reserveBefore, "Not repaid");
}
```

**Secure Pattern:**
```solidity
function flashSwap(uint256 amount, bytes calldata data) external {
    uint256 fee = amount * FLASH_FEE_BPS / 10000;
    uint256 repayAmount = amount + fee;
    
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(msg.sender, amount);
    
    IFlashSwapCallback(msg.sender).flashSwapCallback(amount, fee, data);
    
    // SECURE: Require principal + fee
    require(
        IERC20(token).balanceOf(address(this)) >= balanceBefore + fee,
        "Insufficient repayment"
    );
}
```

---

## Oracle Anti-Patterns

### DEX-AP-37: Spot Price as Oracle

**Description:** Using current AMM spot price as a price oracle.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Spot price is manipulatable
function getPrice() external view returns (uint256) {
    return reserve1 * 1e18 / reserve0;
}
```

**Secure Pattern:**
```solidity
// SECURE: TWAP oracle
function getPrice(uint32 secondsAgo) external view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = secondsAgo;
    secondsAgos[1] = 0;
    
    (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
    
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(secondsAgo)));
    
    return TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
}
```

**Real-World Instances:**
- Dozens of lending protocols exploited using spot price oracles

---

### DEX-AP-38: TWAP Window Too Short

**Description:** TWAP calculated over too short a period, still manipulatable.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: 1 block TWAP
function getTwap() external view returns (uint256) {
    return getAveragePrice(1);  // VULNERABLE: Can be manipulated in 1 block
}
```

**Secure Pattern:**
```solidity
// SECURE: Longer TWAP window
uint256 public constant MIN_TWAP_PERIOD = 30 minutes;

function getTwap(uint256 period) external view returns (uint256) {
    require(period >= MIN_TWAP_PERIOD, "TWAP period too short");
    return getAveragePrice(period);
}
```

---

### DEX-AP-39: Missing Oracle Freshness Check

**Description:** Using oracle price without checking if it's stale.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No staleness check
function getOraclePrice() external view returns (uint256) {
    (, int256 price,,,) = priceFeed.latestRoundData();
    return uint256(price);
}
```

**Secure Pattern:**
```solidity
uint256 public constant MAX_ORACLE_DELAY = 1 hours;

function getOraclePrice() external view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    
    // SECURE: Multiple checks
    require(price > 0, "Invalid price");
    require(updatedAt > 0, "Round not complete");
    require(block.timestamp - updatedAt <= MAX_ORACLE_DELAY, "Stale price");
    require(answeredInRound >= roundId, "Stale round");
    
    return uint256(price);
}
```

---

### DEX-AP-40: Single Oracle Dependency

**Description:** Relying on a single oracle source without fallback.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single oracle, no fallback
function getPrice(address token) external view returns (uint256) {
    return chainlinkOracle.getPrice(token);
}
```

**Secure Pattern:**
```solidity
// SECURE: Multi-oracle with fallback
function getPrice(address token) external view returns (uint256) {
    // Try primary oracle
    try chainlinkOracle.getPrice(token) returns (uint256 price) {
        if (isPriceValid(price)) {
            return price;
        }
    } catch {}
    
    // Try secondary oracle
    try uniswapTwap.getPrice(token) returns (uint256 price) {
        if (isPriceValid(price)) {
            return price;
        }
    } catch {}
    
    // Fallback to stored price with safety bounds
    uint256 lastPrice = lastValidPrice[token];
    require(block.timestamp - lastPriceTime[token] < FALLBACK_MAX_AGE, "No valid price");
    
    return lastPrice;
}
```

---

### DEX-AP-41: Cross-DEX Price Inconsistency

**Description:** Using prices from multiple DEXes without consistency checks.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Use any available price
function getPrice() external view returns (uint256) {
    if (uniswapPrice > 0) return uniswapPrice;
    if (sushiswapPrice > 0) return sushiswapPrice;
    return curvePrice;
}
```

**Secure Pattern:**
```solidity
// SECURE: Require price consistency
function getPrice() external view returns (uint256) {
    uint256 uniPrice = uniswapOracle.getPrice();
    uint256 sushiPrice = sushiswapOracle.getPrice();
    
    // SECURE: Check deviation
    uint256 deviation = uniPrice > sushiPrice ? 
        (uniPrice - sushiPrice) * 10000 / uniPrice :
        (sushiPrice - uniPrice) * 10000 / sushiPrice;
    
    require(deviation <= MAX_PRICE_DEVIATION, "Price deviation too high");
    
    // Return average
    return (uniPrice + sushiPrice) / 2;
}
```

---

### DEX-AP-42: LP Token Oracle Manipulation

**Description:** LP token prices calculated incorrectly, enabling manipulation.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: LP price from spot reserves
function getLPTokenPrice(address lpToken) external view returns (uint256) {
    IUniswapV2Pair pair = IUniswapV2Pair(lpToken);
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    
    uint256 totalValue = reserve0 * getPrice(token0) + reserve1 * getPrice(token1);
    return totalValue / pair.totalSupply();
    // VULNERABLE: Reserves can be manipulated
}
```

**Secure Pattern:**
```solidity
// SECURE: Fair LP token pricing (manipulation resistant)
function getLPTokenPrice(address lpToken) external view returns (uint256) {
    IUniswapV2Pair pair = IUniswapV2Pair(lpToken);
    
    address token0 = pair.token0();
    address token1 = pair.token1();
    uint256 totalSupply = pair.totalSupply();
    
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    
    // Get fair prices from TWAP
    uint256 price0 = getTwapPrice(token0);
    uint256 price1 = getTwapPrice(token1);
    
    // Fair LP price formula (Alpha Homora)
    uint256 sqrtK = Math.sqrt(uint256(reserve0) * uint256(reserve1));
    uint256 sqrtP = Math.sqrt(price0 * price1);
    
    return 2 * sqrtK * sqrtP / totalSupply;
}
```

---

## Router Anti-Patterns

### DEX-AP-43: Router Authorization Bypass

**Description:** Router permissions can be bypassed to execute unauthorized swaps.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No validation of caller
function swap(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    address recipient
) external {
    // Anyone can call, uses pool's tokens
    _executeSwap(tokenIn, tokenOut, amountIn, recipient);
}
```

**Secure Pattern:**
```solidity
function swap(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    address recipient
) external {
    // SECURE: Pull tokens from caller
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    
    // SECURE: Validate recipient
    require(recipient != address(0), "Invalid recipient");
    require(recipient != address(this), "Cannot swap to router");
    
    _executeSwap(tokenIn, tokenOut, amountIn, recipient);
}
```

---

### DEX-AP-44: Permit Replay Attack

**Description:** Permit signatures can be replayed across chains or contexts.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No chain ID in permit
function swapWithPermit(
    uint256 amountIn,
    uint8 v, bytes32 r, bytes32 s
) external {
    token.permit(msg.sender, address(this), amountIn, deadline, v, r, s);
    // VULNERABLE: Same signature works on other chains
}
```

**Secure Pattern:**
```solidity
// Token implements EIP-2612 properly with DOMAIN_SEPARATOR including chainId
// Router verifies chain
function swapWithPermit(
    uint256 amountIn,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    require(block.chainid == EXPECTED_CHAIN_ID, "Wrong chain");
    
    // EIP-2612 permit includes chainId in domain separator
    token.permit(msg.sender, address(this), amountIn, deadline, v, r, s);
    
    _executeSwap(amountIn);
}
```

---

### DEX-AP-45: Multi-Call Reentrancy

**Description:** Batched calls via multicall enabling reentrancy.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Multicall without reentrancy protection
function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
        (bool success, bytes memory result) = address(this).delegatecall(data[i]);
        require(success, "Call failed");
        results[i] = result;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Reentrancy guard on multicall
function multicall(bytes[] calldata data) external nonReentrant returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
        (bool success, bytes memory result) = address(this).delegatecall(data[i]);
        require(success, "Call failed");
        results[i] = result;
    }
}

// SECURE: Alternative - per-function locks
modifier lockFunction(bytes4 selector) {
    require(!functionLocked[selector], "Function locked");
    functionLocked[selector] = true;
    _;
    functionLocked[selector] = false;
}
```

---

### DEX-AP-46: Aggregator Source Manipulation

**Description:** DEX aggregators using manipulatable price sources for routing.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Uses spot price for routing decision
function findBestRoute(address tokenIn, address tokenOut, uint256 amountIn) 
    external view returns (address[] memory route) 
{
    uint256 bestOutput = 0;
    
    for (uint256 i = 0; i < dexes.length; i++) {
        // VULNERABLE: Spot price can be manipulated
        uint256 output = IDex(dexes[i]).getAmountOut(tokenIn, tokenOut, amountIn);
        if (output > bestOutput) {
            bestOutput = output;
            route = getRoute(dexes[i]);
        }
    }
}
```

**Secure Pattern:**
```solidity
function findBestRoute(address tokenIn, address tokenOut, uint256 amountIn) 
    external view returns (address[] memory route) 
{
    uint256 bestOutput = 0;
    
    for (uint256 i = 0; i < dexes.length; i++) {
        // SECURE: Consider liquidity depth
        uint256 liquidity = IDex(dexes[i]).getLiquidity(tokenIn, tokenOut);
        if (liquidity < MIN_LIQUIDITY_THRESHOLD) continue;
        
        // SECURE: Check price impact
        uint256 output = IDex(dexes[i]).getAmountOut(tokenIn, tokenOut, amountIn);
        uint256 priceImpact = (amountIn * 1e18 / output) - getOraclePrice(tokenIn, tokenOut);
        
        if (priceImpact > MAX_PRICE_IMPACT) continue;
        
        if (output > bestOutput) {
            bestOutput = output;
            route = getRoute(dexes[i]);
        }
    }
}
```

---

### DEX-AP-47: Leftover Token Theft

**Description:** Tokens left in router contract can be stolen.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Leftover tokens accessible
function swap(address tokenIn, uint256 amountIn) external {
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    
    // If swap partially fails, tokens left in router
    _executeSwap(tokenIn, amountIn);
    
    // No cleanup of leftover tokens
}

// VULNERABLE: Anyone can sweep
function rescueTokens(address token) external {
    uint256 balance = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(msg.sender, balance);
}
```

**Secure Pattern:**
```solidity
function swap(address tokenIn, uint256 amountIn) external {
    uint256 balanceBefore = IERC20(tokenIn).balanceOf(address(this));
    
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    
    _executeSwap(tokenIn, amountIn);
    
    // SECURE: Return any leftovers to caller
    uint256 leftover = IERC20(tokenIn).balanceOf(address(this)) - balanceBefore;
    if (leftover > 0) {
        IERC20(tokenIn).transfer(msg.sender, leftover);
    }
}

// SECURE: Only admin can rescue, with timelock
function rescueTokens(address token, address to) external onlyOwner {
    require(block.timestamp >= rescueUnlockTime[token], "Locked");
    uint256 balance = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(to, balance);
}
```

---

## Quick Reference Table

| ID | Name | Severity | Category |
|----|------|----------|----------|
| DEX-AP-01 | Incorrect Invariant | Critical | AMM Core |
| DEX-AP-02 | Swap Reentrancy | Critical | AMM Core |
| DEX-AP-03 | Flash Loan Manipulation | Critical | AMM Core |
| DEX-AP-04 | Reserve Update Error | High | AMM Core |
| DEX-AP-05 | Unbalanced Init | High | AMM Core |
| DEX-AP-06 | Concentrated Liquidity | High | AMM Core |
| DEX-AP-07 | Virtual Reserve | Critical | AMM Core |
| DEX-AP-08 | Multi-Hop Exploit | High | AMM Core |
| DEX-AP-09 | No Slippage Protection | Critical | Slippage |
| DEX-AP-10 | Zero Slippage | High | Slippage |
| DEX-AP-11 | Stale Deadline | Medium | Slippage |
| DEX-AP-12 | No Price Impact Check | High | Slippage |
| DEX-AP-13 | Wrong Slippage Target | High | Slippage |
| DEX-AP-14 | Partial Fill | Medium | Slippage |
| DEX-AP-15 | Callback Slippage Bypass | High | Slippage |
| DEX-AP-16 | Unprotected Swap | Critical | MEV |
| DEX-AP-17 | Sandwich Vulnerability | Critical | MEV |
| DEX-AP-18 | JIT Liquidity | High | MEV |
| DEX-AP-19 | Oracle Front-Running | Critical | MEV |
| DEX-AP-20 | Backrunning | Medium | MEV |
| DEX-AP-21 | Block Stuffing | High | MEV |
| DEX-AP-22 | Long-Tail MEV | High | MEV |
| DEX-AP-23 | Mempool Sniping | High | MEV |
| DEX-AP-24 | LP Share Inflation | Critical | LP |
| DEX-AP-25 | IL Amplification | Medium | LP |
| DEX-AP-26 | LP Collateral Exploit | Critical | LP |
| DEX-AP-27 | Rug Pull | High | LP |
| DEX-AP-28 | Single-Sided Exploit | High | LP |
| DEX-AP-29 | LP Migration Attack | Critical | LP |
| DEX-AP-30 | Fee-on-Transfer LP | High | LP |
| DEX-AP-31 | Fee Bypass | High | Fee |
| DEX-AP-32 | Dynamic Fee Manipulation | Medium | Fee |
| DEX-AP-33 | Protocol Fee Theft | High | Fee |
| DEX-AP-34 | Fee Rounding | Medium | Fee |
| DEX-AP-35 | Referral Gaming | Low | Fee |
| DEX-AP-36 | Flash Fee Avoidance | Medium | Fee |
| DEX-AP-37 | Spot Price Oracle | Critical | Oracle |
| DEX-AP-38 | Short TWAP | High | Oracle |
| DEX-AP-39 | Stale Oracle | High | Oracle |
| DEX-AP-40 | Single Oracle | High | Oracle |
| DEX-AP-41 | Cross-DEX Inconsistency | Medium | Oracle |
| DEX-AP-42 | LP Oracle Manipulation | Critical | Oracle |
| DEX-AP-43 | Router Auth Bypass | Critical | Router |
| DEX-AP-44 | Permit Replay | High | Router |
| DEX-AP-45 | Multicall Reentrancy | High | Router |
| DEX-AP-46 | Aggregator Manipulation | High | Router |
| DEX-AP-47 | Leftover Token Theft | Medium | Router |

---

## See Also

- **Attack Tree:** [dex-attack-tree.md](../attack-trees/dex-attack-tree.md)
- **AMM Patterns:** [amm-patterns.md](../patterns/amm-patterns.md)
- **MEV Patterns:** [mev-patterns.md](../patterns/mev-patterns.md)
- **Related:** [oracle-anti-patterns.md](./oracle-anti-patterns.md)

---

**Last Updated:** 2025
**Version:** 1.0
