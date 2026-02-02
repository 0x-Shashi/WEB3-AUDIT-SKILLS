---
id: PLAYBOOK-PENDLE
title: Pendle Integration Playbook
category: protocol-playbooks
protocol: pendle
version: v2
difficulty: advanced
tags: [pendle, yield, pt, yt, tokenization, amm]
last_updated: 2026-01-31
---

# Pendle Integration Playbook

> **Attack Surface:** See [attack-trees/vault-attack-tree.md](../attack-trees/vault-attack-tree.md) | [attack-trees/dex-attack-tree.md](../attack-trees/dex-attack-tree.md)

Comprehensive guide for integrating with Pendle V2 - the yield tokenization and trading protocol.

---

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Pendle V2                                │
├───────────────────────┬─────────────────────────────────────────┤
│   Yield Tokenization  │              Pendle AMM                 │
├───────────────────────┼─────────────────────────────────────────┤
│                       │                                          │
│   SY (Standardized    │    Special AMM for PT trading           │
│       Yield Token)    │    - Time-decay pricing                  │
│         ↓             │    - Concentrated liquidity              │
│   ┌─────┴─────┐       │    - Single-sided LP possible            │
│   │           │       │                                          │
│   PT          YT      │    PT/SY pools                           │
│ (Principal) (Yield)   │                                          │
│                       │                                          │
└───────────────────────┴─────────────────────────────────────────┘

PT + YT = SY (always, until maturity)
```

## Key Concepts

### 1. Token Types

```solidity
// SY (Standardized Yield) - Wrapper for yield-bearing tokens
// Example: SY-stETH wraps stETH
interface ISY {
    function deposit(
        address receiver,
        address tokenIn,
        uint256 amountTokenIn,
        uint256 minSharesOut
    ) external returns (uint256 sharesOut);
    
    function redeem(
        address receiver,
        uint256 amountSharesToRedeem,
        address tokenOut,
        uint256 minTokenOut,
        bool burnFromInternalBalance
    ) external returns (uint256 amountTokenOut);
    
    function exchangeRate() external view returns (uint256);
}

// PT (Principal Token) - Represents principal, redeemable 1:1 at maturity
// YT (Yield Token) - Represents yield stream until maturity
// PT + YT = SY (can be combined/split)
```

### 2. Maturity Mechanics

```solidity
// Before maturity:
// - PT trades at discount (implied yield)
// - YT captures streaming yield
// - PT + YT can be minted from SY or redeemed to SY

// At/After maturity:
// - PT redeemable 1:1 for underlying
// - YT stops accruing, has residual value
// - Market stops trading
```

## Key Contracts

| Contract | Purpose |
|----------|---------|
| PendleRouter | Main entry point for swaps |
| PendleMarket | AMM pool for PT/SY trading |
| SY (various) | Standardized yield wrappers |
| PT (various) | Principal tokens |
| YT (various) | Yield tokens |
| vePENDLE | Vote-escrowed PENDLE |

---

## Integration Patterns

### Minting PT and YT

```solidity
interface IPendleRouter {
    function mintSyFromToken(
        address receiver,
        address SY,
        uint256 minSyOut,
        TokenInput calldata input
    ) external payable returns (uint256 netSyOut);
    
    function mintPyFromSy(
        address receiver,
        address YT,
        uint256 netSyIn,
        uint256 minPyOut
    ) external returns (uint256 netPyOut);
}

// Full flow: Token → SY → PT + YT
function mintPTandYT(
    address sy,
    address yt,
    address tokenIn,
    uint256 amountIn
) external {
    // 1. Deposit token to get SY
    TokenInput memory input = TokenInput({
        tokenIn: tokenIn,
        netTokenIn: amountIn,
        tokenMintSy: tokenIn,
        pendleSwap: address(0),
        swapData: SwapData({...})
    });
    
    uint256 syAmount = router.mintSyFromToken(
        address(this),
        sy,
        0,  // minSyOut
        input
    );
    
    // 2. Split SY into PT + YT
    // Returns equal amounts of PT and YT
    uint256 pyAmount = router.mintPyFromSy(
        msg.sender,
        yt,
        syAmount,
        0  // minPyOut
    );
}
```

### Swapping for PT (Fixed Yield)

```solidity
// Buy PT at discount = lock in fixed yield
function swapForPT(
    address market,
    uint256 exactSyIn,
    uint256 minPtOut
) external returns (uint256 netPtOut) {
    ApproxParams memory approx = ApproxParams({
        guessMin: 0,
        guessMax: type(uint256).max,
        guessOffchain: 0,
        maxIteration: 256,
        eps: 1e14
    });
    
    (netPtOut,) = router.swapExactSyForPt(
        msg.sender,
        market,
        exactSyIn,
        minPtOut,
        approx
    );
}
```

### Redeeming at Maturity

```solidity
// After maturity, PT can be redeemed 1:1
function redeemPT(
    address yt,
    uint256 ptAmount,
    address tokenOut
) external returns (uint256 amountOut) {
    // PT → SY
    uint256 syAmount = router.redeemPyToSy(
        address(this),
        yt,
        ptAmount,
        0  // minSyOut
    );
    
    // SY → underlying token
    TokenOutput memory output = TokenOutput({
        tokenOut: tokenOut,
        minTokenOut: 0,
        tokenRedeemSy: tokenOut,
        pendleSwap: address(0),
        swapData: SwapData({...})
    });
    
    amountOut = router.redeemSyToToken(
        msg.sender,
        ISY(sy).yieldToken(),
        syAmount,
        output
    );
}
```

---

## Pendle AMM Mechanics

### Implied Rate and Pricing

```solidity
// The Pendle AMM uses a custom curve for PT/SY
// Price depends on:
// 1. Time to maturity (approaches 1:1 as maturity nears)
// 2. Implied yield rate
// 3. Market liquidity

interface IPendleMarket {
    function readState(address router) external view returns (MarketState memory);
    
    // Get exchange rate considering time to maturity
    function getExchangeRate() external view returns (int256);
    
    // Implied Annual Percentage Yield
    function getImpliedRate() external view returns (int256);
}

struct MarketState {
    int256 totalPt;
    int256 totalSy;
    int256 totalLp;
    address treasury;
    int256 scalarRoot;
    uint256 expiry;
    uint256 lnFeeRateRoot;
    uint256 reserveFeePercent;
    uint256 lastLnImpliedRate;
}
```

### Adding Liquidity

```solidity
// LP can provide single-sided or dual-sided
function addLiquidityDualSyAndPt(
    address market,
    uint256 syDesired,
    uint256 ptDesired,
    uint256 minLpOut
) external returns (uint256 lpOut) {
    (lpOut,,) = router.addLiquidityDualSyAndPt(
        msg.sender,
        market,
        syDesired,
        ptDesired,
        minLpOut
    );
}

// Single-sided: PT only
function addLiquiditySinglePt(
    address market,
    uint256 ptIn,
    uint256 minLpOut
) external returns (uint256 lpOut) {
    ApproxParams memory approx = ApproxParams({...});
    
    (lpOut,) = router.addLiquiditySinglePt(
        msg.sender,
        market,
        ptIn,
        minLpOut,
        approx
    );
}
```

---

## Security Considerations

###  Critical Checks

```
[ ] Is market expired? (different logic post-maturity)
[ ] Slippage protection on all swaps?
[ ] ApproxParams configured correctly?
[ ] Understanding PT vs YT value at current time?
[ ] Exchange rate calculation correct?
```

### Time-Dependent Risks

```solidity
// PT price approaches 1:1 with SY as maturity nears
// YT value decreases as yield accrual period shortens

// RISK: Buying YT close to maturity
// YT has very little time to accrue yield
// May pay more than total yield received

function checkYTValue(address yt) external view {
    uint256 expiry = IYT(yt).expiry();
    uint256 timeRemaining = expiry - block.timestamp;
    
    // Warning if less than 7 days to maturity
    if (timeRemaining < 7 days) {
        // YT has limited remaining value
        // Be cautious with pricing
    }
}
```

### Exchange Rate Manipulation

```solidity
// SY exchange rate is critical for pricing
// If SY's underlying is manipulable, PT/YT pricing can be attacked

// VULNERABLE: Using spot price for SY
uint256 exchangeRate = sy.exchangeRate();  // Could be manipulated

// SECURE: Use oracle or TWAP where available
// Pendle markets have built-in rate anchoring
```

---

## Common Vulnerabilities

### 1. Expired Market Operations

```solidity
// VULNERABLE: Not checking expiry
function swapPT(address market, uint256 amount) external {
    router.swapExactSyForPt(...);  // Reverts if expired!
}

// SECURE: Check expiry first
function swapPT(address market, uint256 amount) external {
    MarketState memory state = IPendleMarket(market).readState(address(router));
    require(block.timestamp < state.expiry, "Market expired");
    router.swapExactSyForPt(...);
}
```

### 2. Approximation Parameters

```solidity
// Pendle uses iterative approximation for some calculations
// Wrong params can cause failures or suboptimal execution

// VULNERABLE: Too few iterations
ApproxParams memory badParams = ApproxParams({
    guessMin: 0,
    guessMax: type(uint256).max,
    guessOffchain: 0,
    maxIteration: 3,  // Too few!
    eps: 1e14
});

// SECURE: Sufficient iterations
ApproxParams memory goodParams = ApproxParams({
    guessMin: 0,
    guessMax: type(uint256).max,
    guessOffchain: expectedAmount,  // Help convergence
    maxIteration: 256,
    eps: 1e14  // 0.01% precision
});
```

### 3. PT/YT Accounting Errors

```solidity
// PT + YT = SY (always before maturity)
// This invariant must be maintained

// VULNERABLE: Treating PT and YT independently
function deposit(uint256 ptAmount, uint256 ytAmount) external {
    // What if ptAmount != ytAmount? They should be paired
}

// SECURE: Handle PT/YT as pairs
function deposit(uint256 pyAmount) external {
    // pyAmount of both PT and YT
    pt.transferFrom(msg.sender, address(this), pyAmount);
    yt.transferFrom(msg.sender, address(this), pyAmount);
}
```

### 4. Yield Distribution Timing

```solidity
// YT accrues yield over time
// Must claim before certain operations

// VULNERABLE: Not claiming before transfer
function transferYT(address to, uint256 amount) external {
    yt.transfer(to, amount);  // Yield goes to wrong recipient!
}

// SECURE: Claim first
function transferYT(address to, uint256 amount) external {
    yt.redeemDueInterestAndRewards(msg.sender);
    yt.transfer(to, amount);
}
```

---

## Integration Checklist

### Pre-Integration
```
[ ] Understand PT/YT mechanics for the specific SY
[ ] Know the maturity date and implications
[ ] Understand the underlying yield source (stETH, GLP, etc.)
[ ] Check liquidity in Pendle markets
```

### Implementation
```
[ ] Handle both pre and post-maturity cases
[ ] Use proper slippage protection
[ ] Configure ApproxParams correctly
[ ] Claim YT rewards before transfers
[ ] Account for SY exchange rate changes
```

### Risk Assessment
```
[ ] Underlying yield source risk (smart contract, depeg)
[ ] Liquidity risk in Pendle markets
[ ] Time decay risk for YT
[ ] Exchange rate oracle risk
```

---

## Quick Reference

### Key Formulas

```
PT + YT = SY (before maturity)

PT Price = SY Price / (1 + impliedRate)^timeToMaturity

YT Value = SY Value - PT Value
         = Expected yield until maturity

Implied APY = (SY/PT - 1) / timeToMaturity * 365 days
```

### Common Markets (Ethereum)

| Underlying | SY | Typical Maturity |
|------------|-----|------------------|
| stETH | SY-stETH | Quarterly |
| GLP | SY-GLP | Monthly |
| sDAI | SY-sDAI | Quarterly |
| rETH | SY-rETH | Quarterly |

### vePENDLE Benefits

```
- Boosted LP rewards
- Voting for pool incentives
- Share of protocol revenue
- Governance participation
```

---

## Red Flags 

- [ ] Operating on expired markets without handling
- [ ] Not accounting for time decay in YT valuation
- [ ] Missing slippage protection on swaps
- [ ] Not claiming YT rewards before transfers
- [ ] Insufficient ApproxParams iterations
- [ ] Assuming PT price without time consideration
- [ ] Not validating SY exchange rate source
- [ ] Mixing PT/YT amounts incorrectly
