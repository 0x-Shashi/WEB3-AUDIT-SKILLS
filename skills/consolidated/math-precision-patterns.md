---
id: PAT-MATH-PRECISION
title: Math Precision Security Patterns
category: validation
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - pre-condition
  - balance
  - check
finding_count_source: 14
finding_count_note: "Count reflects precision-loss tag only (14). Related tags: rounding (32), wrong-math (107), decimals (45), overflow-underflow (43). See STATISTICS.md."
last_updated: 2026-02-24
---
# Math & Precision Security Patterns (Consolidated)

> **Precision errors silently drain funds. Rounding in the wrong direction = attacker profit.**

---

## Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Division Before Multiply | Precision lost in intermediate calculation | High |
| Wrong Rounding Direction | Rounding favors attacker over protocol | High |
| Decimal Mismatch | Different token decimals not normalized | High |
| Unchecked Overflow | Arithmetic overflow in unchecked blocks | High |
| Truncation | Casting to smaller type loses data | Medium |
| 1/64 Gas Rule | Only 63/64 gas forwarded to subcalls | Medium |

---

## Detection Strategy

### Division Before Multiplication
```solidity
// WRONG: Precision loss
uint result = (a / b) * c;  // If a=5, b=3, c=6: (5/3)*6 = 1*6 = 6

// CORRECT: Multiply first
uint result = (a * c) / b;  // If a=5, b=3, c=6: (5*6)/3 = 30/3 = 10
```

### Rounding Direction
```solidity
// Protocol should NEVER round in attacker's favor
// Deposits: Round DOWN (user gets fewer shares)
// Withdrawals: Round DOWN (user gets fewer assets)
// Fees: Round UP (protocol gets more)

// Use OpenZeppelin's Math.mulDiv with rounding
import "@openzeppelin/contracts/utils/math/Math.sol";
shares = Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Down);
```

### Decimal Normalization
```solidity
// WRONG: Assuming same decimals
uint value = amountA * priceA / amountB;  // Fails if decimals differ

// CORRECT: Normalize decimals
uint8 decimalsA = tokenA.decimals();
uint8 decimalsB = tokenB.decimals();
uint normalizedA = amountA * 10**(18 - decimalsA);
```

### Audit Checklist
- [ ] All divisions happen AFTER multiplications
- [ ] Rounding direction checked for every calculation
- [ ] Token decimals normalized before comparison
- [ ] No unchecked blocks with user input
- [ ] Type casting checked for truncation
- [ ] Large numbers checked for overflow potential

---

## Included Pattern Files

- precision-loss-patterns.md, rounding-patterns.md, time-rounding-patterns.md
- overflow-underflow-patterns.md, truncation-patterns.md, type-casting-patterns.md
- decimals-patterns.md, wrong-math-patterns.md, 1-64-rule-patterns.md

---

## Full Pattern Details

---
## precision-loss-patterns.md
# Precision Loss Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 7 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Immunefi, Cyfrin

---

## Detection Checklist

- [ ] Check for precision loss vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Precision loss in the invariant function can lead to loss of funds

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: HIGH

**Details**:

[src/core/Pair.sol#L56](https://github.com/code-423n4/2023-01-numoen/blob/2ad9a73d793ea23a25a381faadc86ae0c8cb5913/src/core/Pair.sol#L56)<br>

An attacker can steal the funds without affecting the invariant.

### Proof of Concept

We can say the function `Pair.invariant()` is the heart of the protocol.<br>
All the malicious trades should be prevented by this function.

```solidity
Pair.sol
52:   /// @inheritdoc IPair
53:   function invariant(uint256 amount0, uint256 amount1, uint256 liquidity) public view override returns (bool) {
54:     if (liquidity == 0) return (amount0 == 0 && amount1 == 0);
55:
56:     uint256 scale0 = FullMath.mulDiv(amount0, 1e18, liquidity) * token0Scale;//@audit-info precison loss
57:     uint256 scale1 = FullMath.mulDiv(amount1, 1e18, liquidity) * token1Scale;//@audit-info precison loss
58:
59:     if (scale1 > 2 * upperBound) revert InvariantError();
60:
61:     uint256 a = scale0 * 1e18;
62:     uint256 b = scale1 * upperBound;
63:     uint256 c = (scale1 * scale1) / 4;
64:     uint256 d = upperBound * upperBound;
65:
66:     return a + b >= c + d;
67:   }

```

The problem is there is a precision loss in the L56 and L57.<br>
The precision loss can result in the wrong invariant check result.<br>
Let's say the `token0` has 6 decimals and liquidity has more than 24 decimals.<br>
Then the first `FullMath.mulDiv` will cause significant rounding before it's converted to D18.<br>
To clarify the difference I wrote a custom function `invariant()` to see 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 2: `TokenSaleProposal::buy` implicitly assumes that buy token has 18 decimals resulting in a potential total loss scenario for Dao Pool

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** `TokenSaleProposalBuy::buy` is called by users looking to buy the DAO token using a pre-approved token. The exchange rate for this sale is pre-assigned for the specific tier. This function internally calls `TokenSaleProposalBuy::_purchaseWithCommission` to transfer funds from the buyer to the gov pool. Part of the transferred funds are used to pay the DexeDAO commission and balance funds are transferred to the `GovPool` address. To do this, `TokenSaleProposalBuy::_sendFunds` is called.

```solidity
    function _sendFunds(address token, address to, uint256 amount) internal {
        if (token == ETHEREUM_ADDRESS) {
            (bool success, ) = to.call{value: amount}("");
            require(success, "TSP: failed to transfer ether");
        } else {
  >>          IERC20(token).safeTransferFrom(msg.sender, to, amount.from18(token.decimals())); //@audit -> amount is assumed to be 18 decimals
        }
    }
```

Note that this function assumes that the `amount` of ERC20 token is always 18 decimals. The `DecimalsConverter::from18` function converts from a base decimal (18) to token decimals. Note that the amount is directly passed by the buyer and there is no prior normalisation done to ensure the token decimals are converted to 18 decimals before the `_sendFunds` is called.


**Impact:** It is easy to see that for tokens with smaller decimals, eg. USDC with 6 decimals, will cause a total loss to the DAO. In such cases amount is presumed to be 18 decimals & on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 3: [H-06] `EUSD.mint` function wrong assumption of cases when calculated sharesAmount = 0

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/token/EUSD.sol#L299-#L306> <br><https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/token/EUSD.sol#L414-#L418>

### Impact

*   `Mint` function might calculate the `sharesAmount` incorrectly.
*   User can profit by manipulating the protocol to enjoy 1-1 share-eUSD ratio even when share prices is super high.

### Proof of Concept

Currently, the function `EUSD.mint` calls function `EUSD.getSharesByMintedEUSD` to calculate the shares corresponding to the input eUSD amount:

```solidity
function mint(address _recipient, uint256 _mintAmount) external onlyMintVault MintPaused returns (uint256 newTotalShares) {
        require(_recipient != address(0), "MINT_TO_THE_ZERO_ADDRESS");

        uint256 sharesAmount = getSharesByMintedEUSD(_mintAmount);
        if (sharesAmount == 0) {
            //EUSD totalSupply is 0: assume that shares correspond to EUSD 1-to-1
            sharesAmount = _mintAmount;
        }
        ...
}
function getSharesByMintedEUSD(uint256 _EUSDAmount) public view returns (uint256) {
        uint256 totalMintedEUSD = _totalSupply;
        if (totalMintedEUSD == 0) {
            return 0;
        } else {
            return _EUSDAmount.mul(_totalShares).div(totalMintedEUSD);
        }
}
```

As you can see in the comment after `sharesAmount` is checked, `//EUSD totalSupply is 0: assume that shares correspond to EUSD 1-to-1`. The code assumes that if `shar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 4: [H-02] Division Before Multiplication Can Lead To Zero Rounding Of Return Amount

**Source**: Code4rena
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

_Submitted by kirk-baird, also found by csanuragjain, datapunk, and ladboy233_

There is a division before multiplication bug that exists in [`lend()`](https://github.com/code-423n4/2022-06-illuminate/blob/92cbb0724e594ce025d6b6ed050d3548a38c264b/lender/Lender.sol#L280) for the Swivel case.

If `order.premium` is less than `order.principal` then `returned` will round to zero due to the integer rounding.

When this occurs the user's funds are essentially lost. That is because they transfer in the underlying tokens but the amount sent to `yield(u, y, returned, address(this))` will be zero.

### Proof of Concept

```solidity
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256[] calldata a,
        address y,
        Swivel.Order[] calldata o,
        Swivel.Components[] calldata s
    ) public unpaused(p) returns (uint256) {

        // lent represents the number of underlying tokens lent
        uint256 lent;
        // returned represents the number of underlying tokens to lend to yield
        uint256 returned;

        {
            uint256 totalFee;
            // iterate through each order a calculate the total lent and returned
            for (uint256 i = 0; i < o.length; ) {
                Swivel.Order memory order = o[i];
                // Require the Swivel order provided matches the underlying and maturity market provided
                if (order.underlying != u) {
                    revert NotEqual('underlying');
           

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-illuminate)

---

### Example 5: [M-06] Division before multiplication incurs unnecessary precision loss

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: MEDIUM

**Details**:

[src/core/Pair.sol#L56](https://github.com/code-423n4/2023-01-numoen/blob/2ad9a73d793ea23a25a381faadc86ae0c8cb5913/src/core/Pair.sol#L56)<br>
[src/core/Pair.sol#L57](https://github.com/code-423n4/2023-01-numoen/blob/2ad9a73d793ea23a25a381faadc86ae0c8cb5913/src/core/Pair.sol#L57)<br>
[core/Lendgine.sol#L252](https://github.com/code-423n4/2023-01-numoen/blob/2ad9a73d793ea23a25a381faadc86ae0c8cb5913/src/core/Lendgine.sol#L252)

### Proof of Concept

In the current codebase, FullMath.mulDiv is used, the function takes three parameters.

Basically `FullMath.mulDIv(a, b, c)` means `a * b / c`.

Then there are some operations which incur unnecessary precision loss because of division before multiplcation.

When accruing interest, the code below:

```solidity
  /// @notice Helper function for accruing lendgine interest
  function _accrueInterest() private {
    if (totalSupply == 0 || totalLiquidityBorrowed == 0) {
      lastUpdate = block.timestamp;
      return;
    }

    uint256 timeElapsed = block.timestamp - lastUpdate;
    if (timeElapsed == 0) return;

    uint256 _totalLiquidityBorrowed = totalLiquidityBorrowed; // SLOAD
    uint256 totalLiquiditySupplied = totalLiquidity + _totalLiquidityBorrowed; // SLOAD

    uint256 borrowRate = getBorrowRate(_totalLiquidityBorrowed, totalLiquiditySupplied);

    uint256 dilutionLPRequested = (FullMath.mulDiv(borrowRate, _totalLiquidityBorrowed, 1e18) * timeElapsed) / 365 days;
    uint256 dilutionLP = dilutionLPRequested > _totalLiquidi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 6: Initial SwapManager cumulative prices values are wrong

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Medium Risk Severity Report

## Context
- **File:** SwapManagerUniV2.sol
- **Lines:** 65-66

## Description
The initial cumulative price values are integer divisions of unscaled reserves and not UQ112x112 fixed-point values.

```solidity
(reserve0, reserve1, blockTimestampLast) = pair.getReserves();
price0CumulativeLast = reserve1 / reserve0;
price1CumulativeLast = reserve0 / reserve1;
```

One of these values will (almost) always be zero due to integer division. Then, when the difference is taken to the real `currentCumulativePrices` in `update`, the TWAP will be a large, wrong value. The slippage checks will not work correctly.

## Recommendation
Consider using the same code as the UniswapV2 example oracle.

## Morpho
Fixed in PR #550.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 7: Loss of precision while calculating claimable flux and Point

**Source**: Immunefi
**Protocol**: Alchemix
**Impact**: HIGH

**Details**:

Report type: Smart Contract


Target: https://github.com/alchemix-finance/alchemix-v2-dao/blob/main/src/FluxToken.sol

Impacts:
- Contract fails to deliver promised returns, but doesn't lose value

## Description
## Bug Description

https://github.com/alchemix-finance/alchemix-v2-dao/blob/f1007439ad3a32e412468c4c42f62f676822dc1f/src/VotingEscrow.sol#L38
```solidity
/// @notice Multiplier for the slope of the decay
uint256 public constant MULTIPLIER = 2;
```

https://github.com/alchemix-finance/alchemix-v2-dao/blob/f1007439ad3a32e412468c4c42f62f676822dc1f/src/VotingEscrow.sol#L44
```solidity
int256 internal constant iMULTIPLIER = 2;
```

https://github.com/alchemix-finance/alchemix-v2-dao/blob/f1007439ad3a32e412468c4c42f62f676822dc1f/src/VotingEscrow.sol#L1157-L1160
```solidity
function _calculatePoint(LockedBalance memory _locked, uint256 _time) internal pure returns (Point memory point) {
    if (_locked.end > _time && _locked.amount > 0) {
        point.slope = _locked.maxLockEnabled ? int256(0) : (int256(_locked.amount) * iMULTIPLIER) / iMAXTIME;
        point.bias = _locked.maxLockEnabled
            ? ((int256(_locked.amount) * iMULTIPLIER) / iMAXTIME) * (int256(_locked.end - _time))
            : (point.slope * (int256(_locked.end - _time)));
    }
}
```

As we can see, `iMULTIPLIER` and `MULTIPLIER` is set to 2, which is not sufficient to preserve the  precision. 

`point.slope`  and `point.bias` are calculated as follow:
```
point.slope = _locked.maxLockEnabled ? int2

*[Content truncated...]*

---

### Example 8: [H-09] UniswapV3 tokens of certain pairs will be wrongly valued, leading to liquidations

**Source**: Code4rena
**Protocol**: ParaSpace
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-paraspace/blob/c6820a279c64a299a783955749fdc977de8f0449/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L245>

UniswapV3OracleWrapper is responsible for price feed of UniswapV3 NFT tokens. Its getTokenPrice() is used by the health check calculation in GenericLogic.

getTokenPrice gets price from the oracle and then uses it to calculate value of its liquidity.

    function getTokenPrice(uint256 tokenId) public view returns (uint256) {
        UinswapV3PositionData memory positionData = getOnchainPositionData(
            tokenId
        );
        PairOracleData memory oracleData = _getOracleData(positionData);
        (uint256 liquidityAmount0, uint256 liquidityAmount1) = LiquidityAmounts
            .getAmountsForLiquidity(
                oracleData.sqrtPriceX96,
                TickMath.getSqrtRatioAtTick(positionData.tickLower),
                TickMath.getSqrtRatioAtTick(positionData.tickUpper),
                positionData.liquidity
            );
        (
            uint256 feeAmount0,
            uint256 feeAmount1
        ) = getLpFeeAmountFromPositionData(positionData);
        return
            (((liquidityAmount0 + feeAmount0) * oracleData.token0Price) /
                10**oracleData.token0Decimal) +
            (((liquidityAmount1 + feeAmount1) * oracleData.token1Price) /
                10**oracleData.token1Decimal);
    }

In `_getOracleData`,  sqrtPriceX96 of the holding is calculated, using square root of t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-paraspace)

---

### Example 9: [H-11] Users can lose fractions to precision loss during migraction if _newFractionSupply is set very low

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by 0x52, also found by 0x29A, hansfriese, and MEP_

Precision loss causing loss of user value and potentially cause complete loss to vault.

### Proof of Concept

<https://github.com/code-423n4/2022-07-fractional/blob/8f2697ae727c60c93ea47276f8fa128369abfe51/src/modules/Migration.sol#L471-L472>

If the supply of the fraction is set to say 10 then any user that uses `migrateFractions` with less than 10% of the contributions will receive no shares at all due to precision loss. Under certain conditions it may even cause complete loss of access to the vault. In this same example, if less than 5 fractions can be redeemed (i.e. not enough people have more than 10% to overcome the precision loss) then the vault would never be able to be bought out and the vault would forever be frozen.

### Recommended Mitigation Steps

When calling propose require that `\_newFractionSupply` is greater than some value (i.e. 1E18).

**[stevennevins (Fractional) confirmed](https://github.com/code-423n4/2022-07-fractional-findings/issues/137)** 

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-07-fractional-findings/issues/137#issuecomment-1208614341):**
 > Rounding can lead to loss of assets. Agree with severity.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 10: M-1: Unnecessary precision loss in `_recipientBalance()`

**Source**: Sherlock
**Protocol**: NounsDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-nounsdao-judging/issues/70 

## Found by 
WATCHPUG

## Summary

Using `ratePerSecond()` to calculate the `_recipientBalance()` incurs an unnecessary precision loss.

## Vulnerability Detail

The current formula in `_recipientBalance()` to calculate the vested amount (`balance`) incurs an unnecessary precision loss, as it includes div before mul:

```solidity
balance = elapsedTime_ * (RATE_DECIMALS_MULTIPLIER * tokenAmount_ / duration) / RATE_DECIMALS_MULTIPLIER
```

This can be avoided and the improved formula can also save some gas.

## Impact

Precision loss in `_recipientBalance()`.

## Code Snippet

https://github.com/sherlock-audit/2022-11-nounsdao/blob/main/src/Stream.sol#L341-L344

## Tool used

Manual Review

## Recommendation

Consdier changing to:

```solidity
balance = elapsedTime_ * tokenAmount_ / duration
```

## Discussion

**eladmallel**

Fix PR: https://github.com/nounsDAO/streamer/pull/7

---

### Example 11: M-7: Calculating new rewards is susceptible to precision loss due to division before multiplication

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/121 

## Found by 
berndartmueller

## Summary

Rewards may be lost (0) due to division before multiplication precision issues.

## Vulnerability Detail

The `RewardsManager._calculateNewRewards` function calculates the new rewards for a staker by first dividing `interestEarned_` by `totalInterestEarnedInPeriod` and then multiplying by `totalBurnedInPeriod`. If `interestEarned_` is small enough and `totalInterestEarnedInPeriod` is large enough, the division may result in a value of 0, resulting in the staker receiving 0 rewards.

## Impact

Stakers may not receive rewards due to precision loss.

## Code Snippet

[contracts/src/RewardsManager.sol#L426-L428](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/RewardsManager.sol#L426-L428)

```solidity
408: function _calculateNewRewards(
409:     address ajnaPool_,
410:     uint256 interestEarned_,
411:     uint256 nextEpoch_,
412:     uint256 epoch_,
413:     uint256 rewardsClaimedInEpoch_
414: ) internal view returns (uint256 newRewards_) {
415:     (
416:         ,
417:         // total interest accumulated by the pool over the claim period
418:         uint256 totalBurnedInPeriod,
419:         // total tokens burned over the claim period
420:         uint256 totalInterestEarnedInPeriod
421:     ) = _getPoolAccumulators(ajnaPool_, nextEpoch_, epoch_);
422:
423:     // calculate rewards earned
424:     newRewards_ = Maths.wmul(
425:       

*[Content truncated...]*

---

### Example 12: [M-01] secRewardsPerShare Insufficient precision

**Source**: Code4rena
**Protocol**: Canto
**Impact**: MEDIUM

**Details**:

> We also introduced the field secRewardDebt. The idea of this field is to enable any lending platforms that are integrated with Neofinance Coordinator to send their own rewards based on this value (or rather the difference of this value since the last time secondary rewards were sent) and their own emission schedule for the tokens.

The current calculation formula for `secRewardsPerShare` is as follows:

```solidity
market.secRewardsPerShare += uint128((blockDelta * 1e18) / marketSupply);
```

`marketSupply` is `cNOTE`, with a precision of `1e18`
So as long as the supply is greater than `1` cNote, `secRewardsPerShare` is easily `rounded down` to `0`
Example:
marketSupply = 10e18
blockDelta = 1
secRewardsPerShare=1 &ast;  1e18 / 10e18 = 0

### Impact

Due to insufficient precision, `secRewardsPerShare` will basically be 0.

### Recommended Mitigation

It is recommended to use 1e27 for `secRewardsPerShare`:

```solidity
    market.secRewardsPerShare += uint128((blockDelta * 1e27) / marketSupply);
```
**[Alex the Entreprenerd (Judge) commented](https://github.com/code-423n4/2024-01-canto-findings/issues/12#issuecomment-1920977276):**
 > The Warden has shown how, due to incorrect precision, it is possible to create a loss due to rounding down.
> 
> Because the loss is limited to yield, Medium Severity seems most appropriate.

**[OpenCoreCH (sponsor) confirmed](https://github.com/code-423n4/2024-01-canto-findings/issues/12#issuecomment-1923534235)**

***

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-canto)

---

### Example 13: [M-25] Moving average precision is lost

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by hyh, also found by CertoraInc, d3e4, and rbserver_

Now the precision is lost in moving average calculations as the difference is calculated separately and added each time, while it typically can be small enough to lose precision in the division involved.

For example, `10000` moves of `990` size, `numObservations = 1000`. This will yield `0` on each update, while must yield `9900` increase in the moving average.

### Proof of Concept

Moving average is calculated with the addition of the difference:

<https://github.com/code-423n4/2022-08-olympus/blob/2a0b515012b4a40076f6eac487f7816aafb8724a/src/modules/PRICE.sol#L134-L139>

```solidity
        // Calculate new moving average
        if (currentPrice > earliestPrice) {
            _movingAverage += (currentPrice - earliestPrice) / numObs;
        } else {
            _movingAverage -= (earliestPrice - currentPrice) / numObs;
        }
```

`/ numObs` can lose precision as `currentPrice - earliestPrice` is usually small.

It is returned on request as is:

<https://github.com/code-423n4/2022-08-olympus/blob/2a0b515012b4a40076f6eac487f7816aafb8724a/src/modules/PRICE.sol#L189-L193>

```solidity
    /// @notice Get the moving average of OHM in the Reserve asset over the defined window (see movingAverageDuration and observationFrequency).
    function getMovingAverage() external view returns (uint256) {
        if (!initialized) revert Price_NotInitialized();
        return _movingAverage;
    }
```

### Recommended 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 14: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

**Source**: Pashov Audit Group
**Protocol**: RWf(x)_2025-08-20
**Impact**: MEDIUM

**Details**:

_Resolved_

## Severity

**Impact:** Medium  

**Likelihood:** Medium  

## Description

The `Market.mint()` function mints both fToken and xToken [based on the current collateral ratio](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/blob/main/contracts/f(x)/math/FxLowVolatilityMath.sol#L293-L307).  
In the original Aladdin implementation, this function could be called only once. However, RegnumFx [removed this restriction](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/compare/bbb461cba879349c24c02d87872e93ec0a1a1975...f6e865df2dd46d67a49391d94e54b26e6a8af43c#diff-2c8d19ba3d13b72d110c2a9536e5e9915118ad919b38848357200e91afb683faL252), allowing it to be called multiple times.

When the system enters stability mode, the collateral ratio has fallen below the defined safe threshold. This indicates that additional base tokens need to be deposited to restore the ratio.

Allowing `mint()` during stability mode worsens the problem: each new mint increases the number of fTokens in circulation, which in turn raises the amount of base tokens required to bring the system back to a healthy state. As a result, recovery becomes more difficult, and the system may remain undercollateralized for longer.

The severity chosen for this issue is medium, because only whitelisted managers can use the function, and they are trusted entities that are not interested in making stablecoin depeg.

## Recommendations

Restrict `mint()` from being called when the system is in stabili

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/RWf(x)-security-review_2025-08-20.md)

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## rounding-patterns.md
# Rounding Security Patterns

## Overview

**Frequency**: 32 occurrences (0.06% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 17 | 15 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, OpenZeppelin

---

## Detection Checklist

- [ ] Check for rounding vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Rounding up of taker fees of constituent orders may exceed collected fee

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- OrderBook.sol#L463 
- OrderBook.sol#L478-L482 
- OrderBook.sol#L604 

## Description
If multiple orders are taken, the taker fee calculated is rounded up once, but that of each taken maker order could be rounded up as well, leading to more fees accounted for than actually taken.

### Example:
- takerFee = 100011 (10.0011%)
- 2 maker orders of amounts 400000 and 377000
- total amount = 400000 + 377000 = 777000
- Taker fee taken = 777000 * 100011 / 1000000 = 77708.547  77709 

Maker fees would be:
- 377000 * 100011 / 1000000 = 37704.147  37705
- 400000 * 100011 / 1000000 = 40004.4  40005

This results in 1 wei more than actually taken.

Below is a foundry test to reproduce the problem, which can be inserted into `Claim.t.sol`:

```solidity
function testClaimFeesFailFromRounding() public {
    _createOrderBook(0, 100011); // 10.0011% taker fee
    // create 2 orders
    uint256 orderIndex1 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    uint256 orderIndex2 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    // take both orders
    _createTakeOrder(Constants.BID, 2 * Constants.RAW_AMOUNT);
    CloberOrderBook.OrderKey[] memory ids = new CloberOrderBook.OrderKey[](2);
    ids[0] = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Constants.PRICE_INDEX,
        orderIndex: orderIndex1
    });
    ids[1] = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Const

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] User's Accrued Rewards Will Be Lost

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

If the user deposits too little GMX compared to other users (or total supply of pxGMX), the user will not be able to receive rewards after calling the `PirexRewards.claim` function. Subsequently, their accrued rewards will be cleared out (set to zero), and they will lose their rewards.

The amount of reward tokens that are claimable by a user is computed in Line 403 of the `PirexRewards.claim` function.

If the balance of pxGMX of a user is too small compared to other users (or total supply of pxGMX), the code below will always return zero due to rounding issues within solidity.

```solidity
uint256 amount = (rewardState * userRewards) / globalRewards;
```

Since the user's accrued rewards is cleared at Line 391 within the `PirexRewards.claim` function (`p.userStates[user].rewards = 0;`), the user's accrued rewards will be lost.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L373>

```solidity
File: PirexRewards.sol
368:     /**
369:         @notice Claim rewards
370:         @param  producerToken  ERC20    Producer token contract
371:         @param  user           address  User
372:     */
373:     function claim(ERC20 producerToken, address user) external {
374:         if (address(producerToken) == address(0)) revert ZeroAddress();
375:         if (user == address(0)) revert ZeroAddress();
376: 
377:         harvest();
378:         userAccrue(producerToken, user);
379: 
380:         ProducerToken s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: [H-03] Malicious Users Can Drain The Assets Of Auto Compound Vault

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L156>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L199>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L315>

### Proof of Concept

> Note: This issue affects both the AutoPxGmx and AutoPxGlp vaults. Since the root cause is the same, the PoC of AutoPxGlp vault is omitted for brevity.

The `PirexERC4626.convertToShares` function relies on the `mulDivDown` function in Line 164 when calculating the number of shares needed in exchange for a certain number of assets. Note that the computation is rounded down, therefore, if the result is less than 1 (e.g. 0.9), Solidity will round them down to zero. Thus, it is possible that this function will return zero.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L156>

```solidity
File: PirexERC4626.sol
156:     function convertToShares(uint256 assets)
157:         public
158:         view
159:         virtual
160:         returns (uint256)
161:     {
162:         uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.
163: 
164:         return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
165:     }
```

The `AutoPxGmx.previewWithdr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 4: [H-01] Bidders might fail to withdraw their unused funds after the auction was finalized because the contract doesn't have enough balance.

**Source**: Code4rena
**Protocol**: SIZE
**Impact**: HIGH

**Details**:

Bidders might fail to withdraw their unused funds after the auction was finalized because the contract doesn't have enough balance.

The main flaw is the seller might receive more quote tokens than the bidders offer after the auction was finalized.

If there is no other auctions to use the same quote token, the last bidder will fail to withdraw his funds because the contract doesn't have enough balance of quote token.

### Proof of Concept

After the auction was finalized, the seller receives the `filledQuote` amount of quote token using [data.filledBase](https://github.com/code-423n4/2022-11-size/blob/706a77e585d0852eae6ba0dca73dc73eb37f8fb6/src/SizeSealed.sol#L325).

```solidity
    // Calculate quote amount based on clearing price
    uint256 filledQuote = FixedPointMathLib.mulDivDown(clearingQuote, data.filledBase, clearingBase);
```

But when the bidders withdraw the funds using `withdraw()`, they offer the quote token [using this formula](https://github.com/code-423n4/2022-11-size/blob/706a77e585d0852eae6ba0dca73dc73eb37f8fb6/src/SizeSealed.sol#L375-L382).

```solidity
    // Refund unfilled quoteAmount on first withdraw
    if (b.quoteAmount != 0) {
        uint256 quoteBought = FixedPointMathLib.mulDivDown(baseAmount, a.data.lowestQuote, a.data.lowestBase);
        uint256 refundedQuote = b.quoteAmount - quoteBought;
        b.quoteAmount = 0;

        SafeTransferLib.safeTransfer(ERC20(a.params.quoteToken), msg.sender, refundedQuote);
    }
```

Even if they use the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-size)

---

### Example 5: [H-01] Precision loss in the invariant function can lead to loss of funds

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: HIGH

**Details**:

[src/core/Pair.sol#L56](https://github.com/code-423n4/2023-01-numoen/blob/2ad9a73d793ea23a25a381faadc86ae0c8cb5913/src/core/Pair.sol#L56)<br>

An attacker can steal the funds without affecting the invariant.

### Proof of Concept

We can say the function `Pair.invariant()` is the heart of the protocol.<br>
All the malicious trades should be prevented by this function.

```solidity
Pair.sol
52:   /// @inheritdoc IPair
53:   function invariant(uint256 amount0, uint256 amount1, uint256 liquidity) public view override returns (bool) {
54:     if (liquidity == 0) return (amount0 == 0 && amount1 == 0);
55:
56:     uint256 scale0 = FullMath.mulDiv(amount0, 1e18, liquidity) * token0Scale;//@audit-info precison loss
57:     uint256 scale1 = FullMath.mulDiv(amount1, 1e18, liquidity) * token1Scale;//@audit-info precison loss
58:
59:     if (scale1 > 2 * upperBound) revert InvariantError();
60:
61:     uint256 a = scale0 * 1e18;
62:     uint256 b = scale1 * upperBound;
63:     uint256 c = (scale1 * scale1) / 4;
64:     uint256 d = upperBound * upperBound;
65:
66:     return a + b >= c + d;
67:   }

```

The problem is there is a precision loss in the L56 and L57.<br>
The precision loss can result in the wrong invariant check result.<br>
Let's say the `token0` has 6 decimals and liquidity has more than 24 decimals.<br>
Then the first `FullMath.mulDiv` will cause significant rounding before it's converted to D18.<br>
To clarify the difference I wrote a custom function `invariant()` to see 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 6: [H-04] Division rounding can make fraction-price lower than intended (down to zero)

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by 0xA5DF, also found by 0x52, exd0tpy, horsefacts, hyh, kenzo, Lambda, minhquanym, panprog, scaraven, shenwilly, and simon135_

Divisions in EVM are rounded down, which means when the fraction price is close to 1 (e.g. 0.999) it would effectively be zero, when it's close to 2 (1.999) it would be rounded to 1 - losing close to 50% of the intended price.

*   In case the proposer had any fractions, the buyout module puts them for sale and he can lose his fractions while getting in exchange either zero or a significantly lower price than intended
*   Even when the proposer doesn't hold any fractions, if the buyout succeeds - the difference (i.e. `buyoutPrice - fractionPrice*totalSupply`) goes to those who cash out their fractions after the buyout ends.
    *   That's going to disincentivize users to sell their fractions during the buyout, because they may get more if they keep it till the buyout ends.
    *   In other words, not only that the extra money the proposer paid doesn't increase the chance of the buyout to succeed, it actually decreases it.

### Proof of Concept

I've added the following tests to `test/Buyout.t.sol`.

```solidity

    // add Eve to the list of users 
    function setUp() public {
        setUpContract();
        alice = setUpUser(111, 1);
        bob = setUpUser(222, 2);
        eve = setUpUser(333, 3);

        vm.label(address(this), "BuyoutTest");
        vm.label(alice.addr, "Alice");
        vm.label(bob.addr, "Bob");
        vm.label(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 7: [H-02] Attacker can amplify a rounding error in MagicLP to break the I invariant and cause malicious pricing

**Source**: Code4rena
**Protocol**: Abracadabra Money
**Impact**: HIGH

**Details**:

One of the two key parameters in MagicLP pools is `I`, which is defined to be the ideal ratio between the two reserves. It is set during MagicLP initialization:
`_I_ = i;`

It is used when performing the initial LP deposit, in `buyShares()`:

    if (totalSupply() == 0) {
        // case 1. initial supply
        if (quoteBalance == 0) {
            revert ErrZeroQuoteAmount();
        }
        shares = quoteBalance < DecimalMath.mulFloor(baseBalance, _I_) ? DecimalMath.divFloor(quoteBalance, _I_) : baseBalance;
        _BASE_TARGET_ = shares.toUint112();
        _QUOTE_TARGET_ = DecimalMath.mulFloor(shares, _I_).toUint112();
        if (_QUOTE_TARGET_ == 0) {
            revert ErrZeroQuoteTarget();
        }
        if (shares <= 2001) {
            revert ErrMintAmountNotEnough();
        }
        _mint(address(0), 1001);
        shares -= 1001;

The `QUOTE_TARGET` is determined by multiplying the `BASE_TARGET` with `I`.

The flaw is in the check below:
`shares = quoteBalance < DecimalMath.mulFloor(baseBalance, _I_) ? DecimalMath.divFloor(quoteBalance, _I_) : baseBalance;`
Essentially there needs to be enough `quoteBalance` at the `I` ratio to mint `baseBalance` shares, if there's not enough then shares are instead determined by dividing the `quoteBalance` with `I`.
An attacker can abuse the `mulFloor()` to create a major inconsistency.
Suppose `quoteBalance = 1`, `baseBalance = 19999`, `I = 1e14`. Then we have:
`1 < 19999 * 1e14 / 1e18 => 1 < 1 => False`
Therefore `shar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-abracadabra-money)

---

### Example 8: [H-02] Builder can halve the interest paid to a community owner due to arithmetic rounding

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by scaraven, also found by 0x52, auditor0517, Deivitto, hansfriese, Lambda, rbserver, simon135, smiling&#95;heretic, sseefried, and TrungOre_

[Community.sol#L685-L686](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L685-L686)<br>

Due to arithmetic rounding in `returnToLender()`, a builder can halve the APR paid to a community owner by paying every 1.9999 days. This allows a builder to drastically decrease the amount of interest paid to a community owner, which in turn allows them to advertise very high APR rates to secure funding, most of which they will not pay.

This issue occurs in the calculation of `noOfDays` in `returnToLender()` which calculates the number of days since interest has last been calculated. If a builder repays a very small amount of tokens every 1.9999 days, then the `noOfDays` will be rounded down to `1 days` however `lastTimestamp` is updated to the current timestamp anyway, so the builder essentially accumulates only 1 day of interest after 2 days.

I believe this is high severity because a community owner can have a drastic decrease in interest gained from a loan which counts as lost rewards. Additionally, this problem does not require a malicious builder because if a builder pays at a wrong time, the loaner receives less interest anyway.

### Proof of Concept

1.  A community owner provides a loan of 500\_000 tokens to a builder with an APR of 10% (ignoring treasury fees)

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 9: H-10: ERC721Pool's take will proceed with truncated collateral amount and full debt when borrower's collateral is fractional

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/68 

## Found by 
hyh

## Summary

Caller of take() can end up paying the debt corresponding to the fractional ERC721 collateral of a borrower, but receiving only truncated part of the this collateral in return (paying the debt for `1.9`, receiving `1.0`), with the borrower keeping the remainder.

## Vulnerability Detail

Fractional part of ERC721 collateral is gifted to the borrower in Auctions's _take() (L889-898) when `params_.collateral` doesn't allow an increase. Say when `vars.collateralAmount = params_.collateral = 1.9e18`, while taker specified collateral is `2`, it will proceed with paying the debt corresponding to `1.9e18`, which was calculated before in _calculateTakeFlowsAndBondChange(), but will pay the caller only `1e18` of collateral, leaving `0.9e18` with the borrower at caller's expense.

It happens only when `params_.collateral = borrower.collateral` isn't whole 18dp integer, the state that can periodically occur after ERC721Pool's bucketTake(), which applies _calculateTakeFlowsAndBondChange() result to the borrower's balance without rounding, so a partial bucketTake() will leave it as a 18dp fraction.

## Impact

Caller's funds will be lost as they pay borrower's debt according to the untruncated `params_.collateral` value, but receive only truncated amount of collateral.

As both take() and bucketTake() are routine operations and there are no low probability prerequisites, and given the 

*[Content truncated...]*

---

### Example 10: `VoteKickPolicy._endVote()` might revert forever due to underflow

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `onFlag()`, `targetStakeAtRiskWei[target]` might be less than the total rewards for the flagger/reviewers due to rounding.

```solidity
File: contracts\OperatorTokenomics\StreamrConfig.sol
22:     /**
23:      * Minimum amount to pay reviewers+flagger
24:      * That is: minimumStakeWei >= (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) / slashingFraction
25:      */
26:     function minimumStakeWei() public view returns (uint) {
27:         return (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) * 1 ether / slashingFraction;
28:     }
```

- Let's assume `flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei = 100, StreamrConfig.slashingFraction = 0.03e18(3%), minimumStakeWei() = 1000 * 1e18 / 0.03e18 = 10000 / 3 = 3333.`
- If we suppose `stakedWei[target] = streamrConfig.minimumStakeWei()`, then `targetStakeAtRiskWei[target] = 3333 * 0.03e18 / 1e18 = 99.99 = 99.`
- As a result, `targetStakeAtRiskWei[target]` is less than total rewards(=100), and `_endVote()` will revert during the reward distribution due to underflow.

The above scenario is possible only when there is a rounding during `minimumStakeWei` calculation. So it works properly with the default `slashingFraction = 10%`.

**Impact:** The `VoteKickPolicy` wouldn't work as expected and malicious operators won't be kicked forever.

**Recommended Mitigation:** Always round the `minimumStakeWei()` up.

**Client:** Fixed in commit [615b531](https:

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 11: [H-06] `EUSD.mint` function wrong assumption of cases when calculated sharesAmount = 0

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/token/EUSD.sol#L299-#L306> <br><https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/token/EUSD.sol#L414-#L418>

### Impact

*   `Mint` function might calculate the `sharesAmount` incorrectly.
*   User can profit by manipulating the protocol to enjoy 1-1 share-eUSD ratio even when share prices is super high.

### Proof of Concept

Currently, the function `EUSD.mint` calls function `EUSD.getSharesByMintedEUSD` to calculate the shares corresponding to the input eUSD amount:

```solidity
function mint(address _recipient, uint256 _mintAmount) external onlyMintVault MintPaused returns (uint256 newTotalShares) {
        require(_recipient != address(0), "MINT_TO_THE_ZERO_ADDRESS");

        uint256 sharesAmount = getSharesByMintedEUSD(_mintAmount);
        if (sharesAmount == 0) {
            //EUSD totalSupply is 0: assume that shares correspond to EUSD 1-to-1
            sharesAmount = _mintAmount;
        }
        ...
}
function getSharesByMintedEUSD(uint256 _EUSDAmount) public view returns (uint256) {
        uint256 totalMintedEUSD = _totalSupply;
        if (totalMintedEUSD == 0) {
            return 0;
        } else {
            return _EUSDAmount.mul(_totalShares).div(totalMintedEUSD);
        }
}
```

As you can see in the comment after `sharesAmount` is checked, `//EUSD totalSupply is 0: assume that shares correspond to EUSD 1-to-1`. The code assumes that if `shar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 12: [H-10] First vault depositor can steal other's assets

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

The first depositor can be front run by an attacker and as a result will lose a considerable part of the assets provided.

The vault calculates the amount of shares to be minted upon deposit to every user via the `convertToShares()` function:

```solidity
function deposit(uint256 assets, address receiver)
    public
    nonReentrant
    whenNotPaused
    syncFeeCheckpoint
    returns (uint256 shares)
{
    if (receiver == address(0)) revert InvalidReceiver();

    uint256 feeShares = convertToShares(
        assets.mulDiv(uint256(fees.deposit), 1e18, Math.Rounding.Down)
    );

    shares = convertToShares(assets) - feeShares;

    if (feeShares > 0) _mint(feeRecipient, feeShares);

    _mint(receiver, shares);

    asset.safeTransferFrom(msg.sender, address(this), assets);

    adapter.deposit(assets, address(this));

    emit Deposit(msg.sender, receiver, assets, shares);
}

function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

    return
        supply == 0
            ? assets
            : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
}

```

When the pool has no share supply, the amount of shares to be minted is equal to the assets provided. An attacker can abuse this situation and profit off the rounding down operation when calculating the amount of shares if the supply is non-zero. This attack is enabled by the following components: frontrunning, rou

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 13: [H-02] Division Before Multiplication Can Lead To Zero Rounding Of Return Amount

**Source**: Code4rena
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

_Submitted by kirk-baird, also found by csanuragjain, datapunk, and ladboy233_

There is a division before multiplication bug that exists in [`lend()`](https://github.com/code-423n4/2022-06-illuminate/blob/92cbb0724e594ce025d6b6ed050d3548a38c264b/lender/Lender.sol#L280) for the Swivel case.

If `order.premium` is less than `order.principal` then `returned` will round to zero due to the integer rounding.

When this occurs the user's funds are essentially lost. That is because they transfer in the underlying tokens but the amount sent to `yield(u, y, returned, address(this))` will be zero.

### Proof of Concept

```solidity
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256[] calldata a,
        address y,
        Swivel.Order[] calldata o,
        Swivel.Components[] calldata s
    ) public unpaused(p) returns (uint256) {

        // lent represents the number of underlying tokens lent
        uint256 lent;
        // returned represents the number of underlying tokens to lend to yield
        uint256 returned;

        {
            uint256 totalFee;
            // iterate through each order a calculate the total lent and returned
            for (uint256 i = 0; i < o.length; ) {
                Swivel.Order memory order = o[i];
                // Require the Swivel order provided matches the underlying and maturity market provided
                if (order.underlying != u) {
                    revert NotEqual('underlying');
           

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-illuminate)

---

### Example 14: Shares distributed to operators suffer from rounding error

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context: 
River.1.sol#L238

## Description: 
*rewardOperators* distribute a portion of the overall shares distributed to operators based on the number of active and funded validators that each operator has.

The current number of shares distributed to a validator is calculated by the following code:

```solidity
_mintRawShares(operators[idx].feeRecipient, validatorCounts[idx] * rewardsPerActiveValidator);
```

where *rewardsPerActiveValidator* is calculated as:

```solidity
uint256 rewardsPerActiveValidator = _reward / totalActiveValidators;
```

This means that in reality each operator receives:

*validatorCounts[idx] * (_reward / totalActiveValidators)* shares. Such share calculation suffers from a rounding error caused by division before multiplication.

## Recommendation: 
Consider re-writing the number of shares distributed to each operator:

```solidity
// removed --- > uint256 rewardsPerActiveValidator = _reward / totalActiveValidators;
for (uint256 idx = 0; idx < validatorCounts.length;) {
    _mintRawShares(
        operators[idx].feeRecipient,
        (validatorCounts[idx] * _reward) / totalActiveValidators
    );
    ...
}
```

Note that this will reduce the rounding error, but it adds 1 DIVgas cost (5 gas) per iteration. Also, the rounding errors favor the users/depositors.

## Alluvial: 
The whole operator rewarding system has been removed in SPEARBIT/8.

## Spearbit: 
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 15: Avoid multiple divisions when calculating operatorRewards

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
River.1.sol#L277

## Description/Recommendation
In `_onEarnings`, we calculate the `sharesToMint` and `operatorRewards` by dividing two numbers. We can reduce the number of divisions to one and also delegate this division to `_rewardOperators`. This would further avoid the rounding errors that we get when we divide two numbers in EVM. 

Here is the original code:

```solidity
uint256 globalFee = GlobalFee.get();
uint256 numerator = _amount * currentTotalSupply * globalFee;
uint256 denominator = (_assetBalance() * BASE) - (_amount * globalFee);
uint256 sharesToMint = denominator == 0 ? 0 : (numerator / denominator);
uint256 operatorRewards = (sharesToMint * OperatorRewardsShare.get()) / BASE;
uint256 mintedRewards = _rewardOperators(operatorRewards);
```

Instead of passing `operatorRewards`, we can pass two values: one for the numerator and one for the denominator. This way, we can avoid extra rounding errors introduced in `_rewardOperators`. `_rewardOperators` also needs to be changed slightly to account for these two new values.

Heres the updated code:

```solidity
uint256 globalFee = GlobalFee.get();
uint256 numerator = _amount * currentTotalSupply * globalFee * OperatorRewardsShare.get();
uint256 denominator = ((_assetBalance() * BASE) - (_amount * globalFee)) * BASE;
uint256 mintedRewards;

if (denominator != 0) { // note: this was added to avoid calling `_rewardOperators` if `denominator == 0`
    mintedRewards = _rewardOperators(n

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 16: [M-07] Oracles two-day feature can be gamed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L124


## Vulnerability details

## Impact
The two-day feature of the oracle can be gamed where you only have to manipulate the oracle for ~2 blocks.

## Proof of Concept
The oracle computes the day using:
```sol
uint day = block.timestamp / 1 days;
```

Since we're working with `uint` values here, the following is true:
$1728799 / 86400 = 1$
$172800 / 86400 = 2$

Meaning, if you manipulate the oracle at the last block of day $X$, e.g. 23:59:50, and at the first block of day $X + 1$, e.g. 00:00:02, you bypass the two-day feature of the oracle. You only have to manipulate the oracle for two blocks.

This is quite hard to pull off. I'm also not sure whether there were any instances of Chainlink oracle manipulation before. But, since you designed this feature to prevent small timeframe oracle manipulation I think it's valid to point this out.

## Tools Used
none

## Recommended Mitigation Steps
If you increase it to a three-day interval you can fix this issue. Then, the oracle has to be manipulated for at least 24 hours.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 17: [M-03] Rounding error in `buyQuote` might result in free tokens

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

In order to guarantee the contract does not become insolvent, incoming assets should be rounded up, while outgoing assets should be rounded down.

The function `buyQuote()` calculates the amount of base tokens required to buy a given amount of fractional tokens. However, this function rounds down the required amount, which is in favor of the buyer (i.e. he/she has to provide less base tokens for the amount of receiving fractional tokens.

Depending on the amount of current token reserves and the amount of fractional tokens the user wishes to buy, it might be possible to receive free fractional tokens.

Assume the following reserve state:

*   base token reserve: 0,1 WBTC (=`1e7`)
*   fractional token reserve: 10.000.000 (=`1e25`)

The user wishes to buy 0,9 fractional tokens (=`9e17`). Then, the function `buyQuote()` will calculate the amount of base tokens as follows:

`(9e17 * 1000 * 1e7) / ((1e25 - 9e17) * 997) = 0,903`

As division in Solidity will round down, the amount results in `0` amount of base tokens required (WBTC) to buy 0,9 fractional tokens.

### Impact

Using the example above, 0,9 fractional tokens is a really small amount (`0,1 BTC / 1e7 = +- $0,00017`). Moreover, if the user keeps repeating this attack, the fractional token reserve becomes smaller, which will result in a buyQuote amount of >1, after which the tokens will not be free anymore.

Additionally, as the contract incorporates a fee of 30bps, it will likely not be insolvent. The downside would be th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 18: [M-02] Users can avoid paying fees if they manage to update their accrued fees periodically

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

[DBR.sol#L287](https://github.com/code-423n4/2022-10-inverse/blob/main/src/DBR.sol#L287)<br>

While a user borrows DOLA, his debt position in the DBR contract accrues more debt over time. However, Solidity contracts cannot update their storage automatically over time; state updates must always be triggered by externally owned accounts. For this reason, the DBR contract cannot accurately represent a user's debt position in its storage at all times. Instead, the contract offers a method `accrueDueTokens` that, when called, updates the internal storage with the debts that accrued since the last update. This method is called before all critical financial operations that depend on an accurate value of the accumulated deficit in the contract's storage. On top, this method can also be invoked permissionless at any time. Suppose a borrower manages to call this function periodically and keep the time difference between updates short. In that case, a rounding error in the computation of the accrued debt can cause the expression to round down to zero. In this case, the user successfully avoided paying interest on his debt.

### Proof of Concept

For reference, here is the affected code:

```Solidity
    function accrueDueTokens(address user) public {
        uint debt = debts[user];
        if(lastUpdated[user] == block.timestamp) return;
        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;
        dueTokensAccrued[user] += accrued;
        totalDueTokensAccru

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 19: H-5: Adding liquidity can be `DoS`ed due to calculation mismatches

**Source**: Sherlock
**Protocol**: Arrakis Valantis SOT Audit
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/54 

## Found by 
KupiaSec, cu5t0mPe0, juaan, whitehair0330
## Summary

When users add liquidity, they send tokens to the `ArrakisPublicVaultRouter` contract. The `ValantisHOTModulePublic` contract then takes the required tokens from the `ArrakisPublicVaultRouter` contract. However, due to a calculation mismatch, the required amount is often greater than the user-sent amount, causing the transaction to be reverted.

## Vulnerability Detail

Let's consider following scenario:
1. The current state:
    - pool: `reserve0 = 1e18 + 1, reserve1 = 1e18 + 1`
    - vault: `totalSupply = 1e18 + 1`
2. Bob calls the `ArrakisPublicVaultRouter.addLiquidity()` function with the following parameters:
    - `amount0Max = 1e18, amount1Max = 1e18`
3. At [L139](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L139), the `_getMintAmounts()` function returns:
    - `(sharesReceived, amount0, amount1) = (1e18 - 1, 1e18 - 1, 1e18 - 1)`
4. The router contract takes `token0` and `token1` from Bob in amounts of `1e18 - 1` each and calls the `_addLiquidity()` function with above parameters.
5. In the `_addLiquidity()` function, `ArrakisMetaVaultPublic.mint(1e18 - 1, Bob)` is invoked at [L898](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L898).
6. In the `ArrakisMetaVaultPublic.mint()` function:
    - at [L58](

*[Content truncated...]*

---

### Example 20: H-2: FundingRateArbitrage contract can be drained due to rounding error

**Source**: Sherlock
**Protocol**: JOJO Exchange Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-12-jojo-exchange-update-judging/issues/57 

## Found by 
detectiveking
## Summary

In the `requestWithdraw`, rounding in the wrong direction is done which can lead to contract being drained. 

## Vulnerability Detail

In the `requestWithdraw` function in `FundingRateArbitrage`, we find the following lines of code:

```solidity
jusdOutside[msg.sender] -= repayJUSDAmount;
uint256 index = getIndex();
uint256 lockedEarnUSDCAmount = jusdOutside[msg.sender].decimalDiv(index);
require(
     earnUSDCBalance[msg.sender] >= lockedEarnUSDCAmount, "lockedEarnUSDCAmount is bigger than earnUSDCBalance"
);
withdrawEarnUSDCAmount = earnUSDCBalance[msg.sender] - lockedEarnUSDCAmount;
```

Because we round down when calculating `lockedEarnUSDCAmount`, `withdrawEarnUSDCAmount` is higher than it should be, which leads to us allowing the user to withdraw more than we should allow them to given the amount of JUSD they repaid. 

The execution of this is a bit more complicated, let's go through an example. We will assume there's a bunch of JUSD existing in the contract and the attacker is the first to deposit. 

Steps:

1. The attacker deposits 1 unit of USDC and then manually sends in another 100 * 10^6 - 1 (not through deposit, just a transfer). The share price / price per earnUSDC will now be $100. Exactly one earnUSDC is in existence at the moment. 
2. Next the attacker creates a new EOA and deposits a little over $101 worth of USDC (so that after f

*[Content truncated...]*

---

### Example 21: [H-04] Reserved token rounding can be abused to honeypot and steal user's funds

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

When the project wishes to mint reserved tokens, they call mintReservesFor which allows minting up to the amount calculated by DelegateStore's \_numberOfReservedTokensOutstandingFor. The function has this line:

    // No token minted yet? Round up to 1.
    if (_storedTier.initialQuantity == _storedTier.remainingQuantity) return 1;

In order to ease calculations, if reserve rate is not 0 and no token has been minted yet, the function allows a single reserve token to be printed. It turns out that this introduces a very significant risk for users. Projects can launch with several tierIDs of similar contribution size, and reserve rate as low as 1%. Once a victim contributes to the project, it can instantly mint a single reserve token of all the rest of the tiers. They can then redeem the reserve token and receive most of the user's contribution, without putting in any money of their own.

Since this attack does not require setting "dangerous" flags like lockReservedTokenChanges or lockManualMintingChanges, it represents a very considerable threat to unsuspecting users. Note that the attack circumvents user voting or any funding cycle changes which leave time for victim to withdraw their funds. 

### Impact

Honeypot project can instantly take most of first user's contribution.

### Proof of Concept

New project launches, with 10 tiers, of contributions 1000, 1050, 1100, ...

Reserve rate is set to 1% and redemption rate = 100%

User contributes 1100 and gets a Tier 3 NFT reward

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 22: M-7: Market Price Lower Than Expected

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/20 

## Found by 
xiaoming90

## Summary

The market price does not conform to the specification documented within the whitepaper. As a result, the computed market price is lower than expected.

## Vulnerability Detail

The following definition of the market price is taken from the whitepaper. Taken from Page 13 of the whitepaper - Definition 25

![image-20221114132609169](https://user-images.githubusercontent.com/102820284/201850739-496a5e30-bb92-40e3-acfc-6d46821a4eab.png)

The integer implementation of the market price must be rounded up per the whitepaper. This ensures that the integer implementation of the market price is greater than or equal to the real value of the market price so as to protect makers from selling tokens at a lower price than expected.

Within the `BondBaseSDA.marketPrice` function, the computation of the market price is rounded up in Line 688, which conforms to the specification.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L687

```solidity
File: BondBaseSDA.sol
687:     function marketPrice(uint256 id_) public view override returns (uint256) {
688:         uint256 price = currentControlVariable(id_).mulDivUp(currentDebt(id_), markets[id_].scale);
689: 
690:         return (price > markets[id_].minPrice) ? price : markets[id_].minPrice;
691:     }
```

However, within the `BondBaseSDA._currentMarketPrice` function, the market price is rounded

*[Content truncated...]*

---

### Example 23: [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint)

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: MEDIUM

**Details**:

Malicious users can drain the assets of the vault.

### Proof of Concept

The `withdraw` function users `convertToShares` to convert the assets to the amount of shares. These shares are burned from the users account and the assets are returned to the user.

The function `withdraw` is shown below:

```solidity
function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public nonReentrant syncFeeCheckpoint returns (uint256 shares) {
        if (receiver == address(0)) revert InvalidReceiver();

        shares = convertToShares(assets);
/// .... [skipped the code]
```

The function `convertToShares` is shown below:

```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

        return
            supply == 0
                ? assets
                : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
    }
```

It uses `Math.Rounding.Down` , but it should use `Math.Rounding.Up`

Assume that the vault with the following state:

*   Total Asset = 1000 WETH
*   Total Supply = 10 shares

Assume that Alice wants to withdraw 99 WETH from the vault. Thus, she calls the**`Vault.withdraw(99 WETH)`**function.

The calculation would go like this:

```solidity
assets = 99
return value = assets * supply / totalAssets()
return value = 99 * 10 / 1000
return value = 0
```

The value would be rounded round to zero. This will be 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 24: M-5: Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/30 

## Found by 
ctf\_sec

## Summary

Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

## Vulnerability Detail

Per EIP 4626's Security Considerations (https://eips.ethereum.org/EIPS/eip-4626)

> Finally, ERC-4626 Vault implementers should be aware of the need for specific, opposing rounding directions across the different mutable and view methods, as it is considered most secure to favor the Vault itself during calculations over its users:

> If (1) its calculating how many shares to issue to a user for a certain amount of the underlying tokens they provide or (2) its determining the amount of the underlying tokens to transfer to them for returning a certain amount of shares, it should round down.
If (1) its calculating the amount of shares a user has to supply to receive a given amount of the underlying tokens or (2) its calculating the amount of underlying tokens a user has to provide to receive a certain amount of shares, it should round up.

Then previewWithdraw in AutoRoller.sol should round up.

The original implementation for previewWithdraw in Solmate ERC4626 is:

```solidity
    function previewWithdraw(uint256 assets) public view virtual returns (uint256) {
        uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

        return supply == 0 ? assets : assets.mulDivUp(supply, totalAssets());
    }
```

It is roundi

*[Content truncated...]*

---

### Example 25: M-12: Debt Decay Faster Than Expected

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/12 

## Found by 
xiaoming90

## Summary

The debt decay at a rate faster than expected, causing market makers to sell bond tokens at a lower price than expected.  

## Vulnerability Detail

The following definition of the debt decay reference time following any purchases at time `t` taken from the whitepaper. The second variable, which is the delay increment, is rounded up. Following is taken from Page 15 of the whitepaper - Definition 27

![image-20221114170852736](https://user-images.githubusercontent.com/102820284/201844416-023c6d4f-893d-40ab-b6cb-6e33402d8e78.png)

However, the actual implementation in the codebase differs from the specification. At Line 514, the delay increment is rounded down instead.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L514

```solidity
File: BondBaseSDA.sol
513:         // Set last decay timestamp based on size of purchase to linearize decay
514:         uint256 lastDecayIncrement = debtDecayInterval.mulDiv(payout_, lastTuneDebt);
515:         metadata[id_].lastDecay += uint48(lastDecayIncrement);
```

## Impact

When the delay increment (TD) is rounded down, the debt decay reference time increment will be smaller than expected. The debt component will then decay at a faster rate. As a result, the market price will not be adjusted in an optimized manner, and the market price will fall faster than expected, causing market makers to sel

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 32
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## time-rounding-patterns.md
# Time Rounding Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Sherlock

---

## Detection Checklist

- [ ] Check for time rounding vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-1: Fixed Term Teller tokens can be created with an expiry in the past

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/34 

## Found by 
obront

## Summary

The Fixed Term Teller does not allow tokens to be created with a timestamp in the past. This is a fact that protocols using this feature will expect to hold and build their systems around. However, users can submit expiry timestamps slightly in the future, which correlate to tokenIds in the past, which allows them to bypass this check.

## Vulnerability Detail

In `BondFixedTermTeller.sol`, the `create()` function allows protocols to trade their payout tokens directly for bond tokens. The expectation is that protocols will build their own mechanisms around this. It is explicitly required that they cannot do this for bond tokens that expire in the past, only those that have yet to expire:

```solidity
if (expiry_ < block.timestamp) revert Teller_InvalidParams();
```

However, because tokenIds round timestamps down to the latest day, protocols are able to get around this check.

Here's an example:
- The most recently expired token has an expiration time of 1668524400 (correlates to 9am this morning)
- It is currently 1668546000 (3pm this afternoon)
- A protocol calls create() with an expiry of 1668546000 + 1
- This passes the check that `expiry_ >= block.timestamp`
- When the expiry is passed to `getTokenId()` it rounds the time down to the latest day, which is the day corresponding with 9am this morning
- This expiry associated with this tokenId is 9am this morning, so t

*[Content truncated...]*

---

### Example 2: M-2: Fixed Term Bond tokens can be minted with non-rounded expiry

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/32 

## Found by 
obront

## Summary

Fixed Term Tellers intend to mint tokens that expire once per day, to consolidate liquidity and create a uniform experience. However, this rounding is not enforced on the external `deploy()` function, which allows for tokens expiring at unexpected times.

## Vulnerability Detail

In `BondFixedTermTeller.sol`, new tokenIds are deployed through the `_handlePayout()` function. The function calculates the expiry (rounded down to the nearest day), uses this expiry to create a tokenId, and if that tokenId doesn't yet exist deploys it.

```solidity
...
expiry = ((vesting_ + uint48(block.timestamp)) / uint48(1 days)) * uint48(1 days);

// Fixed-term user payout information is handled in BondTeller.
// Teller mints ERC-1155 bond tokens for user.
uint256 tokenId = getTokenId(payoutToken_, expiry);

// Create new bond token if it doesn't exist yet
if (!tokenMetadata[tokenId].active) {
    _deploy(tokenId, payoutToken_, expiry);
}
...
```
This successfully consolidates all liquidity into one daily tokenId, which expires (as expected) at the time included in the tokenId.

However, if the `deploy()` function is called directly, no such rounding occurs:

```solidity
function deploy(ERC20 underlying_, uint48 expiry_)
    external
    override
    nonReentrant
    returns (uint256)
{
    uint256 tokenId = getTokenId(underlying_, expiry_);
    // Only creates token if it does not exi

*[Content truncated...]*

---

### Example 3: M-2: `optionTokens` can be expired even though the epoch is not over

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/63 

## Found by 
BenRai, qandisa
## Summary

When deploying an `optionToken` the parameter `expiry` is rounded down to the nearest day at 0000 UTC but since the end of an epoch is calculated by the `epochDuration` and the exact time the epoch has stared and the `optionToken` was created this can lead to an epoch still being active but the corresponding `optionToken` to be already expired. 

## Vulnerability Detail

When starting a new epoch, the variable `epochStart` is set to the current time (`block.timestamp`) and the end of the epoch is calculated by adding the `epochDuration` to the `epochStart` variable. 

The `optionToken` of the new epoch is deployed with the parameter `expire` calculated based on the current time stamp, the `timeUntilEligible` and the `eligibleDuration`. (`uint48(block.timestamp) + timeUntilEligible + eligibleDuration`). The final expiration date of the optionToken is rounded down to the nearest day at 0000 UTC before the token is deployed.

Since the `epochDuration` can be as close as 1 second to the sum of `timeUntilEligible + eligibleDuration` this can lead to an epoch still being active but its `optionToken` to be already expired.

Example:

epochDuration = 7 days
timeUntilEligible = 0
eligibleDuration = 7 days + 12 hours


New epoch is launched on the 01.01.2024 at 11:45 am.

=>
epochStart = block.timestamp  = 01.01.2024 at 11:45 am
epochEnd = epochStart + epochDuration =

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## overflow-underflow-patterns.md
# Overflow/Underflow Security Patterns

## Overview

**Frequency**: 43 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 21 | 22 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, Trust Security

---

## Detection Checklist

- [ ] Check for overflow/underflow vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [C-01] Withdrawal Calculation Causes Underflow, Locking All User Funds

**Source**: Shieldify
**Protocol**: Terplayer Bvt Staking&Distribution
**Impact**: HIGH

**Details**:

## Severity

Critical Risk

## Description

The withdrawal function includes the user in their own delegation list and uses ceiling division for all calculations. This causes `totalDelegatedAmount` to exceed the requested withdrawal amount, resulting in an underflow when calculating `remainingAmount = amount - totalDelegatedAmount`, which renders all withdrawals unsuccessful.

## Location of Affected Code

File: [src/BvtRewardVault.sol#L155](https://github.com/batoshidao/berabtc-vault-token/blob/c68f412b3c7dfd99d3f6302a42bdf772ededb2a3/src/BvtRewardVault.sol#L155)

```solidity
function withdraw(uint256 amount) external nonReentrant {
  // code

  // Calculate and withdraw from delegated stakes
  for (uint256 i = 0; i < users.length; i++) {
      address user = users[i];
      uint256 delegatedAmount = delegatedStakes[msg.sender][user];
      if (delegatedAmount > 0) {
          uint256 withdrawAmount = (delegatedAmount * amount + stakes[msg.sender] - 1)  / stakes[msg.sender];
          if (withdrawAmount > 0) {
              totalDelegatedAmount += withdrawAmount;
              _delegateWithdraw(msg.sender, user, withdrawAmount);
          }
      }
  }
  // Calculate remaining amount to withdraw from user's own stake
  uint256 remainingAmount = amount - totalDelegatedAmount;
  if (remainingAmount > 0) {
      _delegateWithdraw(msg.sender, msg.sender, remainingAmount);
  }
  // code
}
```

## Impact

All withdrawals fail due to underflow, permanently locking user funds.

## R

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Terplayer-BVT-Staking&Distribution-Security-Review.md)

---

### Example 2: Loss of Long-Term Swap Proceeds Likely in Pools With Decimal or Price Imbalances

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`VirtualOrders.sol#L166`

## Description
This TWAMM implementation tracks the proceeds of long-term swaps efficiently via accumulated values called "scaled proceeds" for each token. In every order block interval (OBI), the scaled proceeds for e.g. the sale of token 0 are incremented by:

```
(quantity of token 1 purchased during the OBI) * 264 = (sales rate of token 0 during the OBI)
```

Then the proceeds of any specific long-term swap can be computed as the product of the difference between the scaled proceeds at the current block (or the expiration block of the order if filled) and the last block for which proceeds were claimed for the order and the order's sales rate, divided by 264:

```
last := min(currentBlock, orderExpiryBlock)
prev := block of last proceeds collection, or block order was placed in if this is the first withdrawal
LT swap proceeds = (scaledProceeds[last] - scaledProceeds[prev]) * (order.salesRate) / 264
```

The value 264 is referred to as the "scaling factor" and is intended to reduce precision loss in the division to determine the increment to the scaled proceeds.

The addition to increment the scaled proceeds and the subtraction to compute its net change is both intentionally done with unchecked arithmeticsince only the difference matters, so long as at most one overflow occurs between claim-of-proceeds events for any given order, the computed proceeds will be correct (up to rounding errors). If two or more overfl

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 3: [H-02] Underflow of `lpPosition.points` during withdrawLP causes huge reward minting

**Source**: Code4rena
**Protocol**: Neo Tokyo
**Impact**: HIGH

**Details**:

NeoTokyoStaking allows to stake and withdraw LPs. User can stake multiple times on same position which simply results in extended lock time and user can withdraw all of these LPs once lock time is passed.

There is a scenario when withdrawing LPs results in overflow of [lpPosition.points](https://github.com/code-423n4/2023-03-neotokyo/blob/main/contracts/staking/NeoTokyoStaker.sol#L1627). After withdraw if attacker calls `getRewards()` then attacker will get more than 1e64 BYTES tokens as reward.

### Proof of Concept

Affected code block: [NeoTokyoStaker.sol#L1622-L1631](https://github.com/code-423n4/2023-03-neotokyo/blob/main/contracts/staking/NeoTokyoStaker.sol#L1622-L1631)

Affected line: [L1627](https://github.com/code-423n4/2023-03-neotokyo/blob/main/contracts/staking/NeoTokyoStaker.sol#L1627)

From below POC, you can see that Alice is staking twice and some specific amounts which will trigger underflow when Alice withdraw LP. Once staked LPs are unlocked, Alice can withdraw her LPs and call `getReward()` to trigger minting of more than 1e64 BYTES tokens.

Below test can be added in `NeoTokyoStaker.test.js` test file.

```js
		it('Unexpected rewards minting due to underflow of "points"', async function () {
			// Configure the LP token contract address on the staker.
			await NTStaking.connect(owner.signer).configureLP(LPToken.address);
			const amount1 = ethers.utils.parseEther('10.009')
			const amount2 = ethers.utils.parseEther('11.009')
			const lockingDays = 30
			

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-03-neotokyo)

---

### Example 4: Overflow in SegmentedSegmentTree464

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**Critical Risk**

## Context
**File:** SegmentedSegmentTree464.sol  
**Line:** 173

## Description
`SegmentedSegmentTree464.update` needs to perform an overflow check in case the new value is greater than the old value. This overflow check is done when adding the new difference to each node in each layer (using `addClean`). Furthermore, there's a final overflow check by adding up all nodes in the first layer in total (`core`).

However, in total, the nodes in individual groups are added using `DirtyUint64.sumPackedUnsafe`:

```solidity
function total(Core storage core) internal view returns (uint64) {
    return DirtyUint64.sumPackedUnsafe(core.layers[0][0], 0, _C)
           + DirtyUint64.sumPackedUnsafe(core.layers[0][1], 0, _C);
}
```

The nodes in a group can overflow without triggering an overflow & revert. The impact is that the order book depth and claim functionalities break for all users.

```
/ SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "../../contracts/mocks/SegmentedSegmentTree464Wrapper.sol";

contract SegmentedSegmentTree464Test is Test {
    using stdJson for string;
    uint32 private constant _MAX_ORDER = 2**15;
    SegmentedSegmentTree464Wrapper testWrapper;

    function setUp() public {
        testWrapper = new SegmentedSegmentTree464Wrapper();
    }

    function testTotalOverflow() public {
        uint64 half64 = type(uint64).max

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 5: [H-06] Repaying a line of credit with a higher than necessary claimed revenue amount will force the borrower into liquidation

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

A borrower can repay (parts) of a credit line with the `SpigotedLine.useAndRepay` function. This function will use `amount` of `unusedTokens[credit.token]` as a repayment. However, if `amount` exceeds the principal and the accrued interest, `credit.principal` will underflow without an error and set the principal value to a very large number.

This a problem because a borrower can unknowingly provide a larger than necessary `amount` to the `SpigotedLine.useAndRepay` function to make sure enough funds are used to fully repay the principal and the remaining interest.

Additionally, a lender can do the same thing as the lender can call this function.

### Impact

The `credit.principal` underflows without an error and will be set to a very large number. This will force a secured line **immediately** into liquidation. Additionally, having a principal value close to `2^256 - 1` will make it hugely expensive to repay the credit line.

### Proof of Concept

[utils/CreditLib.sol#L186](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/CreditLib.sol#L186)

```solidity
function repay(
  ILineOfCredit.Credit memory credit,
  bytes32 id,
  uint256 amount
)
  external
  returns (ILineOfCredit.Credit memory)
{ unchecked {
    if (amount <= credit.interestAccrued) {
        credit.interestAccrued -= amount;
        credit.interestRepaid += amount;
        emit RepayInterest(id, amount);
        return credit;
    } else {
        uint256 in

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 6: [H-01] implicit underflows

**Source**: Code4rena
**Protocol**: Gro Protocol
**Impact**: HIGH

**Details**:

_Submitted by gpersoon, also found by cmichel_

There are a few underflows that are converted via a typecast afterwards to the expected value. If solidity 0.8.x would be used, then the code would revert.
* `int256(a-b)` where a and b are uint: For example, if `a=1` and `b=2`, then the intermediate result would be `uint(-1) == 2**256-1`
* `int256(-x)` where x is a uint. For example, if `x=1`, then the intermediate result would be `uint(-1) == 2**256-1`

It's better not to have underflows by using the appropriate typecasts. This is especially relevant when moving to solidity 0.8.x.

From `Exposure.sol` [L178](https://github.com/code-423n4/2021-06-gro/blob/main/contracts/insurance/Exposure.sol#L178):
```solidity
function sortVaultsByDelta(..)
..
    for (uint256 i = 0; i < N_COINS; i++) {
        // Get difference between vault current assets and vault target
        int256 delta = int256(unifiedAssets[i] - unifiedTotalAssets.mul(targetPercents[i]).div(PERCENTAGE_DECIMAL_FACTOR)); // underflow in intermediate result
```

From `PnL.sol` [L112](https://github.com/code-423n4/2021-06-gro/blob/main/contracts/pnl/PnL.sol#L112):
```solidity
 function decreaseGTokenLastAmount(bool pwrd, uint256 dollarAmount, uint256 bonus)...
..
 emit LogNewGtokenChange(pwrd, int256(-dollarAmount)); // underflow in intermediate result
```

From `Buoy3Pool.sol` [L87](https://github.com/code-423n4/2021-06-gro/blob/main/contracts/pools/oracle/Buoy3Pool.sol#L87):
```solidity
function safetyCheck() external 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-gro)

---

### Example 7: [H-06] Setting new controller can break YVaultLPFarming

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/farming/yVaultLPFarming.sol#L170
https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/vaults/yVault/yVault.sol#L108


## Vulnerability details

## Impact
The accruals in `yVaultLPFarming` will fail if [`currentBalance < previousBalance`](https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/farming/yVaultLPFarming.sol#L170) in `_computeUpdate`.

```solidity
currentBalance = vault.balanceOfJPEG() + jpeg.balanceOf(address(this));
uint256 newRewards = currentBalance - previousBalance;
```

No funds can be withdrawn anymore as the `withdraw` functions first trigger an `_update`.

The `currentBalance < previousBalance` case can, for example, be triggerd by decreasing the `vault.balanceOfJPEG()` due to calling `yVault.setController`:

```solidity
function setController(address _controller) public onlyOwner {
    // @audit can reduce balanceofJpeg which breaks other masterchef contract
    require(_controller != address(0), "INVALID_CONTROLLER");
    controller = IController(_controller);
}

function balanceOfJPEG() external view returns (uint256) {
    // @audit new controller could return a smaller balance
    return controller.balanceOfJPEG(address(token));
}
```

## Recommended Mitigation Steps
Setting a new controller on a vault must be done very carefully and requires a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 8: [H-01] Truncation in `OrderValidator` can lead to resetting the fill and selling more tokens

**Source**: Code4rena
**Protocol**: OpenSea
**Impact**: HIGH

**Details**:

[OrderValidator.sol#L228](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L228)<br>
[OrderValidator.sol#L231](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L231)<br>
[OrderValidator.sol#L237](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L237)<br>
[OrderValidator.sol#L238](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L238)<br>

A partial order's fractions (`numerator` and `denominator`) can be reset to `0` due to a truncation. This can be used to craft malicious orders:

1.  Consider user Alice, who has 100 ERC1155 tokens, who approved all of their tokens to the `marketplaceContract`.
2.  Alice places a `PARTIAL_OPEN` order with 10 ERC1155 tokens and consideration of ETH.
3.  Malory tries to fill the order in the following way:
    1.  Malory tries to fill 50% of the order, but instead of providing the fraction `1 / 2`, Bob provides `2**118 / 2**119`. This sets the `totalFilled` to `2**118` and `totalSize` to `2**119`.
    2.  Malory tries to fill 10% of the order, by providing `1 / 10`. The computation `2**118 / 2**119 + 1 / 10` is done by "cross multiplying" the denominators, leading to the acutal fraction being `numerator = (2**118 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-opensea-seaport)

---

### Example 9: H-1: Underflow in ```_previewWithdraw``` could prevent withdrawals

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/106 

## Found by 
dipp, \_\_141345\_\_, Trumpero, 0x52, hansfriese, yixxas

## Summary

An underflow in the ```_previewWithdraw``` function in ```AuctionInternal.sol``` due to totalContractsSold exceeding auction.totalContracts could prevent users from withdrawing options.

## Vulnerability Detail

The ```_previewWithdraw``` function returns the fill and refund amounts for a buyer by looping over all orders. A totalContractsSold variable is used to track the amount of contracts sold as the loop iterates over all orders. If the current order's size + totalContractsSold exceeds the auction's totalContracts then the order will only be filled partially. The calculation for the partial fill (remainder) is given on [line 318](https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/AuctionInternal.sol#L318). This will lead to an underflow if totalContractsSold > the auction's totalContracts which would happen if there are multiple orders that cause the totalContractsSold variable to exceed totalContracts.

The totalContractsSold variable in ```_previewWithdraw``` could exceed the auction.totalContracts due to the contracts sold before the start of an auction through limit orders not being limited. When an order is added, _finalizeAuction is only called if the auction has started. The ```_finalizeAuction``` function will call the ```_processOrders``` function which will return tru

*[Content truncated...]*

---

### Example 10: Malicious target can make `_endVote()` revert forever by forceUnstaking/staking again

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `_endVote()`, we update `forfeitedStakeWei` or `lockedStakeWei[target]` according to the `target`'s staking status.

```solidity
File: contracts\OperatorTokenomics\SponsorshipPolicies\VoteKickPolicy.sol
179:     function _endVote(address target) internal {
180:         address flagger = flaggerAddress[target];
181:         bool flaggerIsGone = stakedWei[flagger] == 0;
182:         bool targetIsGone = stakedWei[target] == 0;
183:         uint reviewerCount = reviewers[target].length;
184:
185:         // release stake locks before vote resolution so that slashings and kickings during resolution aren't affected
186:         // if either the flagger or the target has forceUnstaked or been kicked, the lockedStakeWei was moved to forfeitedStakeWei
187:         if (flaggerIsGone) {
188:             forfeitedStakeWei -= flagStakeWei[target];
189:         } else {
190:             lockedStakeWei[flagger] -= flagStakeWei[target];
191:         }
192:         if (targetIsGone) {
193:             forfeitedStakeWei -= targetStakeAtRiskWei[target];
194:         } else {
195:             lockedStakeWei[target] -= targetStakeAtRiskWei[target]; //@audit revert after forceUnstake() => stake() again
196:         }
```

We consider the target is still active if he has a positive staking amount. But we don't know if he has unstaked and staked again, so the below scenario would be possible.

- The target staked 100 amount and a flagger reported him.
- In `on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 11: Possible overflow in `_payOutFirstInQueue`

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `_payOutFirstInQueue()`, possible revert during `operatorTokenToDataInverse()`.

```solidity
uint amountOperatorTokens = moduleCall(address(exchangeRatePolicy), abi.encodeWithSelector(exchangeRatePolicy.operatorTokenToDataInverse.selector, amountDataWei));
```

If a delegator calls `undelegate()` with `type(uint256).max`, `operatorTokenToDataInverse()` will revert due to uint overflow and the queue logic will be broken forever.

```solidity
   function operatorTokenToDataInverse(uint dataWei) external view returns (uint operatorTokenWei) {
       return dataWei * this.totalSupply() / valueWithoutEarnings();
   }
```

**Impact:** The queue logic will be broken forever because `_payOutFirstInQueue()` keeps reverting.

**Recommended Mitigation:** We should cap `amountDataWei` before calling `operatorTokenToDataInverse()`.

**Client:** Fixed in commit [c62e5d9](https://github.com/streamr-dev/network-contracts/commit/c62e5d90ce8f8c084fe3917f499c967c85a3873b).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 12: `VoteKickPolicy._endVote()` might revert forever due to underflow

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `onFlag()`, `targetStakeAtRiskWei[target]` might be less than the total rewards for the flagger/reviewers due to rounding.

```solidity
File: contracts\OperatorTokenomics\StreamrConfig.sol
22:     /**
23:      * Minimum amount to pay reviewers+flagger
24:      * That is: minimumStakeWei >= (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) / slashingFraction
25:      */
26:     function minimumStakeWei() public view returns (uint) {
27:         return (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) * 1 ether / slashingFraction;
28:     }
```

- Let's assume `flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei = 100, StreamrConfig.slashingFraction = 0.03e18(3%), minimumStakeWei() = 1000 * 1e18 / 0.03e18 = 10000 / 3 = 3333.`
- If we suppose `stakedWei[target] = streamrConfig.minimumStakeWei()`, then `targetStakeAtRiskWei[target] = 3333 * 0.03e18 / 1e18 = 99.99 = 99.`
- As a result, `targetStakeAtRiskWei[target]` is less than total rewards(=100), and `_endVote()` will revert during the reward distribution due to underflow.

The above scenario is possible only when there is a rounding during `minimumStakeWei` calculation. So it works properly with the default `slashingFraction = 10%`.

**Impact:** The `VoteKickPolicy` wouldn't work as expected and malicious operators won't be kicked forever.

**Recommended Mitigation:** Always round the `minimumStakeWei()` up.

**Client:** Fixed in commit [615b531](https:

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 13: [H-03] Risk of silent overflow in reserves update

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L230-L231> 

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L323-L324>

### Vulnerability details

The [`buy()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L211) and [`sell()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L301) functions update the `virtualBaseTokenReserves` and `virtualNftReserves` variables during each trade. However, these two variables are of type `uint128`, while the values that update them are of type `uint256`. This means that casting to a lower type is necessary, but this casting is performed without first checking that the values being cast can fit into the lower type. As a result, there is a risk of a silent overflow occurring during the casting process.

```solidity
    function buy(uint256[] calldata tokenIds, uint256[] calldata tokenWeights, MerkleMultiProof calldata proof) 
        public
        payable
        returns (uint256 netInputAmount, uint256 feeAmount, uint256 protocolFeeAmount)
    {
        // ~~~ Checks ~~~ //

        // calculate the sum of weights of the NFTs to buy
        uint256 weightSum = sumWeightsAndValidateProof(tokenIds, tokenWeights, proof);

        // calculate the required net input amount and fee amount
        (netInputAmount, feeAmount, protocolFeeAmount) = buyQuote(weightSum);
        ...
        // update the virtual reserves
        virtualBaseTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 14: [H-02] `UniswapV2PriceOracle.sol` `currentCumulativePrices()` will revert when `priceCumulative` addition overflow

**Source**: Code4rena
**Protocol**: Phuture Finance
**Impact**: HIGH

**Details**:

_Submitted by WatchPug_

[UniswapV2PriceOracle.sol#L62](https://github.com/code-423n4/2022-04-phuture/blob/594459d0865fb6603ba388b53f3f01648f5bb6fb/contracts/UniswapV2PriceOracle.sol#L62)<br>

```solidity
(uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) = address(pair).currentCumulativePrices();
```

Because the Solidity version used by the current implementation of `UniswapV2OracleLibrary.sol` is `>=0.8.7`, and there are some breaking changes in Solidity v0.8.0:

> Arithmetic operations revert on underflow and overflow.

Ref: <https://docs.soliditylang.org/en/v0.8.13/080-breaking-changes.html#silent-changes-of-the-semantics>

While in `UniswapV2OracleLibrary.sol`, subtraction overflow is desired at `blockTimestamp - blockTimestampLast` in `currentCumulativePrices()`:

<https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2OracleLibrary.sol#L25-L33>

```solidity
if (blockTimestampLast != blockTimestamp) {
    // subtraction overflow is desired
    uint32 timeElapsed = blockTimestamp - blockTimestampLast;
    // addition overflow is desired
    // counterfactual
    price0Cumulative += uint(FixedPoint.fraction(reserve1, reserve0)._x) * timeElapsed;
    // counterfactual
    price1Cumulative += uint(FixedPoint.fraction(reserve0, reserve1)._x) * timeElapsed;
}
```

In another word, `Uniswap/v2-periphery/contracts/libraries/UniswapV2OracleLibrary` only works at solidity < `0.8.0`.

As a result, when `price0Cumulative` or `price1Cumu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-phuture)

---

### Example 15: unchecked may cause under/overflows

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `LienToken.sol#L424`
- `LienToken.sol#L482`
- `PublicVault.sol#L376`
- `PublicVault.sol#L422`
- `PublicVault.sol#L439`
- `PublicVault.sol#L490`
- `PublicVault.sol#L578`
- `PublicVault.sol#L611`
- `PublicVault.sol#L527`
- `PublicVault.sol#L544`
- `PublicVault.sol#L563`
- `PublicVault.sol#L640`
- `VaultImplementation.sol#L401`
- `WithdrawProxy.sol#L254`
- `WithdrawProxy.sol#L293`

## Description
Unchecked should only be used when there is a guarantee of no underflows or overflows, or when they are taken into account. In the absence of certainty, it's better to avoid unchecked to favor correctness over gas efficiency.

For instance, if by error, `protocolFeeNumerator` is set to be greater than `protocolFeeDenominator`, this block in `_handleProtocolFee()` will underflow:

```solidity
unchecked {
    amount -= fee;
}
```

However, later this reverts due to the ERC20 transfer of an unusually high amount. This is just to demonstrate that unknown bugs can lead to under/overflows.

## Recommendation
Reason about each unchecked and remove them in absence of absolute certainty of safety.

## Astaria
Acknowledged. We'll put checks on setting protocol values to not cross unintended boundaries.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 16: [M-04] After proposed 0.8.0 upgrade kicks in, L2 finalizeInboundTransfer might not work

**Source**: Code4rena
**Protocol**: The Graph
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/l2/gateway/L2GraphTokenGateway.sol#L70


## Vulnerability details

## Description

L2GraphTokenGateway uses the onlyL1Counterpart modifier to make sure finalizeInboundTransfer is only called from L1GraphTokenGateway. Its implementation is:

```Solidity
modifier onlyL1Counterpart() {
        require(
            msg.sender == AddressAliasHelper.applyL1ToL2Alias(l1Counterpart),
            "ONLY_COUNTERPART_GATEWAY"
        );
        _;
    }
```

It uses applyL1ToL2Alias defined as:

```
uint160 constant offset = uint160(0x1111000000000000000000000000000000001111);

    /// @notice Utility function that converts the address in the L1 that submitted a tx to
    /// the inbox to the msg.sender viewed in the L2
    /// @param l1Address the address in the L1 that triggered the tx to L2
    /// @return l2Address L2 address as viewed in msg.sender
    function applyL1ToL2Alias(address l1Address) internal pure returns (address l2Address) {
        l2Address = address(uint160(l1Address) + offset);
    }
```

This behavior matches with how Arbitrum augments the sender's address to L2. The issue is that I've spoken with the team and they are [planning](https://github.com/graphprotocol/contracts/pull/725) an upgrade from Solidity 0.7.6 to 0.8.0. Their proposed [changes](https://github.com/graphprotocol/contracts/blob/c4d3cb56cb4032dbb3a0f1b7535b5d94ccf86222/contracts/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-thegraph)

---

### Example 17: H-7: Overflow in curate() function, results in permanently stuck funds

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/88 

## Found by 
dimulski, merlin
## Summary
The ``Axis-Finance`` protocol has a [curate()](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/AuctionHouse.sol#L634-L699) function that can be used to set a certain fee to a curator set by the seller for a certain auction. Typically, a curator is providing some service to an auction seller to help the sale succeed. This could be doing diligence on the project and ``vouching`` for them, or something simpler, such as listing the auction on a popular interface. A lot of memecoins have a big supply in the trillions, for example [SHIBA INU](https://etherscan.io/token/0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce#readContract#F2) has a total supply of nearly **1000 trillion tokens** and each token has 18 decimals. With a lot of new memecoins emerging every day due to the favorable bullish conditions and having supply in the trillions, it is safe to assume that  such protocols will interact with the ``Axis-Finance`` protocol. Creating auctions for big amounts, and promising big fees to some celebrities or influencers to promote their project. The funding parameter in the **Routing struct** is of type ``uint96``
```solidity
    struct Routing {
        ...
        uint96 funding; 
        ...
    }
```
The max amount of tokens with 18 decimals a ``uint96`` variable can hold is around 80 billion. The problem arises in the [curate()](h

*[Content truncated...]*

---

### Example 18: `Manager::_transferFee` returns invalid `feeShares` when `fee` is zero

**Source**: Cyfrin
**Protocol**: Yieldfi
**Impact**: MEDIUM

**Details**:

**Description:** When a user deposits directly into `Manager::deposit`, the protocol fee is calculated via the [`Manager::_transferFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L226-L242) function:

```solidity
function _transferFee(address _yToken, uint256 _shares, uint256 _fee) internal returns (uint256) {
    if (_fee == 0) {
        return _shares;
    }
    uint256 feeShares = (_shares * _fee) / Constants.HUNDRED_PERCENT;

    IERC20(_yToken).safeTransfer(treasury, feeShares);

    return feeShares;
}
```

The issue is that when `_fee == 0`, the function returns the full `_shares` amount instead of returning `0`. This leads to incorrect logic downstream in [`Manager::_deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L286-L296), where the result is subtracted from the total shares:

```solidity
// transfer fee to treasury, already applied on adjustedShares
uint256 adjustedFeeShares = _transferFee(order.yToken, adjustedShares, _fee);

// Calculate adjusted gas fee shares
uint256 adjustedGasFeeShares = (_gasFeeShares * order.exchangeRateInUnderlying) / currentExchangeRate;

// transfer gas to caller
IERC20(order.yToken).safeTransfer(_caller, adjustedGasFeeShares);

// remaining shares after gas fee
uint256 sharesAfterAllFee = adjustedShares - adjustedFeeShares - adjustedGasFeeShares;
```

If `_fee == 0`, the `adjustedFeeShares`

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### Example 19: FullMath requires overflow behavior

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Audit Summary

## Severity
**High Risk**

## Context
`FullMath.sol#L2`

## Description
UniswapV3s `FullMath.sol` is copied and migrated from an old solidity version to version 0.8, which reverts on overflows. However, the old `FullMath` relies on implicit overflow behavior. The current code will revert on overflows when it should not, which breaks the `SwapManagerUniV3` contract.

## Recommendation
Use the official `FullMath.sol` 0.8 branch that wraps the code in an unchecked statement. See #40.

## Spearbit
Fixed. The Uniswap V3 branch is added as a dependency in PR #550.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 20: [M-02] Twav.sol#_getTwav() will revert when timestamp  4294967296

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/Twav/Twav.sol#L35-L42


## Vulnerability details

```solidity
function _getTwav() internal view returns(uint256 _twav){
    if (twavObservations[TWAV_BLOCK_NUMBERS - 1].timestamp != 0) {
        uint8 _index = ((twavObservationsIndex + TWAV_BLOCK_NUMBERS) - 1) % TWAV_BLOCK_NUMBERS;
        TwavObservation memory _twavObservationCurrent = twavObservations[(_index)];
        TwavObservation memory _twavObservationPrev = twavObservations[(_index + 1) % TWAV_BLOCK_NUMBERS];
        _twav = (_twavObservationCurrent.cumulativeValuation - _twavObservationPrev.cumulativeValuation) / (_twavObservationCurrent.timestamp - _twavObservationPrev.timestamp);
    }
}
```

Since `_blockTimestamp` is `uint32`, subtraction underflow is desired at `_twavObservationCurrent.timestamp - _twavObservationPrev.timestamp`.

See: https://github.com/Uniswap/v2-periphery/blob/master/contracts/examples/ExampleOracleSimple.sol#L43

```solidity
function update() external {
    (uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) =
        UniswapV2OracleLibrary.currentCumulativePrices(address(pair));
    uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
```

Because the solidity version used by the current implementation is `0.8.10`, and there are some breaking changes in Solidity v0.8.0:

> Arithmetic operations revert on underflow and overflow

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 21: [H-02] Minting and redeeming will break for fully minted tiers with `reserveRate != 0` and `reserveRate`/`MaxReserveRate` tokens burned

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

Minting and redeeming become impossible.

### Proof of Concept

    uint256 _numberOfNonReservesMinted = _storedTier.initialQuantity -
      _storedTier.remainingQuantity -
      _reserveTokensMinted;

    uint256 _numerator = uint256(_numberOfNonReservesMinted * _storedTier.reservedRate);

    uint256 _numberReservedTokensMintable = _numerator / JBConstants.MAX_RESERVED_RATE;

    if (_numerator - JBConstants.MAX_RESERVED_RATE * _numberReservedTokensMintable > 0)
      ++_numberReservedTokensMintable;

    return _numberReservedTokensMintable - _reserveTokensMinted;

The lines above are taken from JBTiered721DelegateStore#\_numberOfReservedTokensOutstandingFor and used to calculate and return the available number of reserve tokens that can be minted. Since the return statement doesn't check that \_numberReservedTokensMintable >= \_reserveTokensMinted, it will revert under those circumstances. The issue is that there are legitimate circumstances in which this becomes false. If a tier is fully minted then all reserve tokens are mintable. When the tier begins to redeem, \_numberReservedTokensMintable will fall under \_reserveTokensMinted, permanently breaking minting and redeeming. Minting is broken because all mint functions directly call \_numberOfReservedTokensOutstandingFor. Redeeming is broken because the redeem callback (JB721Delegate#redeemParams) calls \_totalRedemtionWeight which calls \_numberOfReservedTokensOutstandingFor.

Example:

A tier has a reserveRate of 100 (

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 22: [H-05] Attacker can steal entire reserves by abusing fee calculation

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBPair.sol#L819-L829><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L202><br>

Similar to other LP pools, In Trader Joe users can call `mint()` to provide liquidity and receive LP tokens, and `burn()` to return their LP tokens in exchange for underlying assets. Users collect fees using `collectFess(account,binID)`. Fees are implemented using debt model. The fundamental fee calculation is:

        function _getPendingFees(
            Bin memory _bin,
            address _account,
            uint256 _id,
            uint256 _balance
        ) private view returns (uint256 amountX, uint256 amountY) {
            Debts memory _debts = _accruedDebts[_account][_id];

            amountX = _bin.accTokenXPerShare.mulShiftRoundDown(_balance, Constants.SCALE_OFFSET) - _debts.debtX;
            amountY = _bin.accTokenYPerShare.mulShiftRoundDown(_balance, Constants.SCALE_OFFSET) - _debts.debtY;
        }

accTokenXPerShare / accTokenYPerShare is an ever increasing amount that is updated when swap fees are paid to the current active bin.

When liquidity is first minted to user, the \_accruedDebts is updated to match current \_balance &ast; accToken&ast;PerShare. Without this step, user could collect fees for the entire growth of accToken&ast;PerShare from zero to current value. This is done in \_updateUserDebts, called b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 23: INTEGER OVERFLOW

**Source**: Halborn
**Protocol**: MonoX
**Impact**: MEDIUM

**Details**:

##### Description

An overflow happens when an arithmetic operation reaches the maximum size of a type. For instance, in `Monoswap.sol`, the `getAmountOut` method is subtracting `fees` from a fixed number and may end up overflowing the integer since the resulting value is not checked to be greater or equal 0. In computer programming, an integer overflow occurs when an arithmetic operation attempts to create a numeric value that is outside of the range that can be represented with a given number of bits  either larger than the maximum or lower than the minimum representable value.

Code Location
-------------

#### Monoswap.sol

```
function getAmountOut(address tokenIn, address tokenOut, 
    uint256 amountIn) public view returns (uint256 tokenInPrice, uint256 tokenOutPrice, 
    uint256 amountOut, uint256 tradeVusdValue) {
    require(amountIn > 0, 'Monoswap: INSUFFICIENT_INPUT_AMOUNT');

    uint256 amountInWithFee = amountIn.mul(1e5-fees)/1e5;
    address vusdAddress = address(vUSD);

```

#### Monoswap.sol

```
function getAmountIn(address tokenIn, address tokenOut, 
    uint256 amountOut) public view returns (uint256 tokenInPrice, uint256 tokenOutPrice, 
    uint256 amountIn, uint256 tradeVusdValue) {
    require(amountOut > 0, 'Monoswap: INSUFFICIENT_INPUT_AMOUNT');

    uint256 amountOutWithFee = amountOut.mul(1e5+fees)/1e5;
    address vusdAddress = address(vUSD);

```

##### Score

Impact: 3  
Likelihood: 3

##### Recommendation

**SOLVED**: MonoX is certain the int

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/monox/monox-smart-contract-security-assessment)

---

### Example 24: M-3: Repaying loans with small amounts of debt tokens can lead to underflowing in the `roll` function

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/263 

## Found by 
tsvetanovv, rvierdiiev, ck, zaskoh, Allarious, Trumpero, Breeje, berndartmueller, jonatascm, Deivitto

## Summary

Due to precision issues when repaying a loan with small amounts of debt tokens, the `loan.amount` can be reduced whereas the `loan.collateral` remains unchanged. This can lead to underflowing in the `roll` function.

## Vulnerability Detail

The `decollateralized` calculation in the `repay` function rounds down to zero if the `repaid` amount is small enough. This allows iteratively repaying a loan with very small amounts of debt tokens without reducing the collateral.

The consequence is that the `roll` function can revert due to underflowing the `newCollateral` calculation once the `loan.collateral` is greater than `collateralFor(loan.amount, req.loanToCollateral)` (`loan.amount` is reduced by repaying the loan)

As any ERC-20 tokens with different decimals can be used, this precision issue is amplified if the decimals of the collateral and debt tokens differ greatly.

## Impact

The `roll` function can revert due to underflowing the `newCollateral` calculation if the `repay` function is (iteratively) called with small amounts of debt tokens.

## Code Snippet

[Cooler.sol#L114](https://github.com/sherlock-audit/2023-01-cooler/blob/main/src/Cooler.sol#L114)

```solidity
function repay (uint256 loanID, uint256 repaid) external {
    Loan storage loan = loans[loanID];

    if

*[Content truncated...]*

---

### Example 25: M-12: PerpDepository.netAssetDeposits variable can prevent users to withdraw with underflow error

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/97 

## Found by 
rvierdiiev

## Summary
PerpDepository.netAssetDeposits variable can prevent users to withdraw with underflow error
## Vulnerability Detail
When user deposits using PerpDepository, then `netAssetDeposits` variable is increased with the base assets amount, provided by depositor.
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L283-L288
```solidity
    function _depositAsset(uint256 amount) private {
        netAssetDeposits += amount;


        IERC20(assetToken).approve(address(vault), amount);
        vault.deposit(assetToken, amount);
    }
```

Also when user withdraws, this `netAssetDeposits` variable is decreased with base amount that user has received for redeeming his UXD tokens.
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L294-L302
```solidity
    function _withdrawAsset(uint256 amount, address to) private {
        if (amount > netAssetDeposits) {
            revert InsufficientAssetDeposits(netAssetDeposits, amount);
        }
        netAssetDeposits -= amount;


        vault.withdraw(address(assetToken), amount);
        IERC20(assetToken).transfer(to, amount);
    }
```

The problem here is that when user deposits X assets, then he receives Y UXD tokens. And when later he redeems his Y UXD tokens he can receive more or less than X assets. This can lead to situation 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 43
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## truncation-patterns.md
# Truncation Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for truncation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-1: Precision is lost in depositAuction and withdrawAuction user amount due calculations

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/201 

## Found by 
CRYP70, yixxas, hyh

## Summary

Formulas for `usdcAmount`, `portion.crab`, `portion.eth` used in depositAuction() and withdrawAuction() for queued distributions perform division first, which lead to truncation and fund loss in the numerical corner cases.

## Vulnerability Detail

depositAuction() and withdrawAuction() use the same approach for USDC and crab amount calculation. Let's focus on withdrawAuction(), there it is `usdcAmount = (((withdraw.amount * 1e18) / _p.crabToWithdraw) * usdcReceived) / 1e18`.

When `_p.crabToWithdraw` is big compared to `withdraw.amount`, the `((withdraw.amount * 1e18) / _p.crabToWithdraw)` can become zero as result of integer division.

As an example there can be an ordinary user and a whale situation, for the user it can be `withdraw.amount = 900`, while `_p.crabToWithdraw = 1000e18`, `usdcReceived = 2e18`, then `usdcAmount = (((withdraw.amount * 1e18) / _p.crabToWithdraw) * usdcReceived) / 1e18 = 0`, while it should be `usdcAmount = (withdraw.amount * usdcReceived) / _p.crabToWithdraw = (900 * 2e18) / 1000e18 = 1`.

## Impact

When truncation occurs the corresponding depositor or withdrawer will experience the loss as less funds to be distributed to them.

Setting the severity to medium as this have material impact in a numerical corner cases only.

## Code Snippet

withdrawAuction() use `usdcAmount = (((withdraw.amount * 1e18) / _p.crabToWithdraw) * us

*[Content truncated...]*

---

### Example 2: [M-21] Truncation in casting can lead to a founder receiving all the base tokens

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L71-L126><br>
<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L88>

The initialize function of the `Token` contract receives an array of `FounderParams`, which contains the ownership percent of each founder as a `uint256`. The initialize function checks that the sum of the percents is not more than 100, but the value that is added to the sum of the percent is truncated to fit in `uint8`. This leads to an error because the value that is used for assigning the base tokens is the original, not truncated, `uint256` value.

This can lead to wrong assignment of the base tokens, and can also lead to a situation where not all the users will get the correct share of base tokens (if any).

### Proof of Concept

To verify this bug I created a foundry test. You can add it to the test folder and run it with `forge test --match-test testFounderGettingAllBaseTokensBug`.

This test deploys a token implementation and an `ERC1967` proxy that points to it, and initializes the proxy using an array of 2 founders, each having 256 ownership percent. The value which is added to the `totalOwnership` variable is a `uint8`, and when truncating 256 to fit in a `uint8` it will turn to 0, so this check will pass.

After the call to initialize, the test asserts that all the base token ids belongs to the first founder, w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 3: M-9: Bad debt may persist even after complete liquidation in Velo Vault due to truncation

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/174 

## Found by 
0x52

## Summary

When liquidating a user, if all their collateral is taken but it is not valuable enough to repay the entire loan they would be left with remaining debt. This is what is known as bad debt because there is no collateral left to take and the user has no obligation to pay it back. When this occurs, the vault will forgive the user's debts, clearing the bad debt. The problem is that the valuations are calculated in two different ways which can lead to truncation issue that completely liquidates a user but doesn't clear their bad debt.

## Vulnerability Detail

            uint256 totalUserCollateral = totalCollateralValue(_collateralAddress, _loanHolder);
            uint256 proposedLiquidationAmount;
            { //scope block for liquidationAmount due to stack too deep
                uint256 liquidationAmount = viewLiquidatableAmount(totalUserCollateral, 1 ether, isoUSDBorrowed, liquidatableMargin);
                require(liquidationAmount > 0 , "Loan not liquidatable");
                proposedLiquidationAmount = _calculateProposedReturnedCapital(_collateralAddress, _loanNFTs, _partialPercentage);
                require(proposedLiquidationAmount <= liquidationAmount, "excessive liquidation suggested");
            }
            uint256 isoUSDreturning = proposedLiquidationAmount*LIQUIDATION_RETURN/LOAN_SCALE;
            if(proposedLiquidationAmount >= totalUserColl

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## type-casting-patterns.md
# Type casting Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for type casting vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Typed structured data hash used for signing commitments is calculated incorrectly

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `VaultImplementation.sol#L150-L151`
- `VaultImplementation.sol#L172-L176`
- `IVaultImplementation.sol#L41`

## Description
Since  
`STRATEGY_TYPEHASH == keccak256("StrategyDetails(uint256 nonce,uint256 deadline,bytes32 root)")`  
The hash calculated in `_encodeStrategyData` is incorrect according to EIP-712. `s.strategistNonce` is of type `uint32` and the nonce type used in the type hash is `uint256`.

Also, the struct name used in the typehash collides with the `StrategyDetails` struct name defined as:
```solidity
struct StrategyDetails {
    uint8 version;
    uint256 deadline;
    address vault;
}
```

## Recommendation
We suggest the following:
1. Update the `STRATEGY_TYPEHASH` to reflect the correct type `uint32` for the nonce.
2. Keep the `STRATEGY_TYPEHASH` using the non-inlined version below since the compiler would inline the value off-chain:
   ```solidity
   bytes32 public constant STRATEGY_TYPEHASH = keccak256("StrategyDetails(uint32 nonce,uint256 deadline,bytes32 root)");
   ```
3. To avoid name collision for the two structs, rename one of the `StrategyDetails` (even though one is not defined directly).

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: [H-03] Risk of silent overflow in reserves update

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L230-L231> 

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L323-L324>

### Vulnerability details

The [`buy()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L211) and [`sell()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L301) functions update the `virtualBaseTokenReserves` and `virtualNftReserves` variables during each trade. However, these two variables are of type `uint128`, while the values that update them are of type `uint256`. This means that casting to a lower type is necessary, but this casting is performed without first checking that the values being cast can fit into the lower type. As a result, there is a risk of a silent overflow occurring during the casting process.

```solidity
    function buy(uint256[] calldata tokenIds, uint256[] calldata tokenWeights, MerkleMultiProof calldata proof) 
        public
        payable
        returns (uint256 netInputAmount, uint256 feeAmount, uint256 protocolFeeAmount)
    {
        // ~~~ Checks ~~~ //

        // calculate the sum of weights of the NFTs to buy
        uint256 weightSum = sumWeightsAndValidateProof(tokenIds, tokenWeights, proof);

        // calculate the required net input amount and fee amount
        (netInputAmount, feeAmount, protocolFeeAmount) = buyQuote(weightSum);
        ...
        // update the virtual reserves
        virtualBaseTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 3: H-9: Downcasting to uint96 can cause assets to be lost for some tokens

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/181 

## Found by 
FindEverythingX, hash, pseudoArtist
## Summary
Downcasting to uint96 can cause assets to be lost for some tokens

## Vulnerability Detail

After summing the individual bid amounts, the total bid amount is downcasted to uint96 without any checks

```solidity
            settlement_.totalIn = uint96(result.totalAmountIn);
```

uint96 can be overflowed for multiple well traded tokens:

Eg:

shiba inu :
current price = $0.00003058
value of type(uint96).max tokens ~= 2^96 * 0.00003058 / 10^18 == 2.5 million $

Hence auctions that receive more than type(uint96).max amount of tokens will be downcasted leading to extreme loss for the auctioner

## Impact

The auctioner will suffer extreme loss in situations where the auctions bring in >uint96 amount of tokens

## Code Snippet

downcasting totalAmountIn to uint96
https://github.com/sherlock-audit/2024-03-axis-finance/blob/cadf331f12b485bac184111cdc9ba1344d9fbf01/moonraker/src/modules/auctions/EMPAM.sol#L825

## Tool used

Manual Review

## Recommendation

Use a higher type or warn the user's of the limitations on the auction sizes



## Discussion

**0xJem**

Duplicate of #34 

**Oighty**

Pretty similar to #209. Might be a duplicate.

**nevillehuang**

Agree both hinges on a high `totalAmountIn`

**kosedogus**

Escalate

Since there are minutes until the end of auction period, I might miss something, if that is the case sorry about that.


*[Content truncated...]*

---

### Example 4: [M-02] The tier setting parameter are unsafely downcasted from type uint256 to type uint80 / uint48 / uint40 / uint16

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

<https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721Delegate.sol#L240><br>
<https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L628><br>
<https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L689>

The tier setting parameter are unsafely downcasted from uint256 to uint80 / uint48 / uint16

the tier is setted by owner is crucial because the parameter affect how nft is minted.

the callstack is

`JBTiered721Delegate.sol#initialize` -> `Store#recordAddTiers`

```solidity
function recordAddTiers(JB721TierParams[] memory _tiersToAdd)
```

what does the struct `JB721TierParams` look like? all parameter in `JB721TierParams` is uint256 type

```solidity
struct JB721TierParams {
  uint256 contributionFloor;
  uint256 lockedUntil;
  uint256 initialQuantity;
  uint256 votingUnits;
  uint256 reservedRate;
  address reservedTokenBeneficiary;
  bytes32 encodedIPFSUri;
  bool allowManualMint;
  bool shouldUseBeneficiaryAsDefault;
}
```

however in side the function

```solidity
// Record adding the provided tiers.
if (_pricing.tiers.length > 0) _store.recordAddTiers(_pricing.tiers);
```

all uint256 parameter are downcasted.

```solidity
// Add the tier with the iterative ID.
_storedTierOf[msg.sender][_tierId] = JBStored721Tier({
contributionFloor: uint80(_tierTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 5: [M-02] Unsafe cast in `getCollateralRatio()`

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

`LibGetters.getCollateralRatio()` might return the incorrect ratio due to the unsafe cast.

### Proof of Concept

`getCollateralRatio()` outputs the collateral ratio using the total collaterals and issued agTokens.

```solidity
    // The `stablecoinsIssued` value need to be rounded up because it is then used as a divizer when computing
    // the amount of stablecoins issued
    stablecoinsIssued = uint256(ts.normalizedStables).mulDiv(ts.normalizer, BASE_27, Math.Rounding.Up);
    if (stablecoinsIssued > 0)
        collatRatio = uint64(totalCollateralization.mulDiv(BASE_9, stablecoinsIssued, Math.Rounding.Up)); //@audit unsafe cast
    else collatRatio = type(uint64).max;
```

Typically, the `collatRatio` should be around `BASE_9` but the ratio might be larger than `type(uint64).max` during the initial stage.

Furthermore, `totalCollateralization` is calculated using the [raw balance of collaterals](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibGetters.sol#L73) and it might be manipulated when [stablecoinsIssued](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibGetters.sol#L85) is not large.

Then [collatRatio](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibGetters.sol#L87) might be cast to the wrong value.

After all, `getCollater

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 6: [M-10] Unsafe downcasting in issue(...) can be exploited to cause permanent DoS

**Source**: Code4rena
**Protocol**: Reserve
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/reserve-protocol/protocol/blob/df7ecadc2bae74244ace5e8b39e94bc992903158/contracts/p1/RToken.sol#L230-L243


## Vulnerability details

## Unsafe downcasting in `issue(...)` can be exploited to cause permanent DoS

#### Important note!
I first found this bug in `issue(...)` at first, but unsafe downcasting appears in many other areas of the codebase, and seem to also be exploitable but no PoC is provided due to time constraints. Either way, using some form of safe casting library to **replace all occurences** of unsafe downcasting will prevent all the issues. I also do not list the individual instances of unsafe downcasting as all occurences should be replaced with safe cast.

### Details
The `amtRToken` is a user supplied parameter in the `issue(uint256 amtRToken)` function
```sol
uint192 amtBaskets = uint192(
	totalSupply() > 0 ? mulDiv256(basketsNeeded, amtRToken, totalSupply()) : amtRToken
);
```
The calculated amount is unsafely downcasted into `uint192`.

This means that if the resulting calculation is a multiple of $2^{192}$, `amtBaskets = 0`

The code proceeds to the following line, where `erc20s` and `deposits` arrays will be empty since we are asking for a quote for 0. (see `quote(...)` in `BasketHandler.sol` where amounts are multiplied by zero)
```sol
(address[] memory erc20s, uint256[] memory deposits) = basketHandler.quote(
            amtBaskets,
            CEIL
        );
```
This means an attacker can call `issue(...)` with

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-reserve)

---

### Example 7: [M-21] Truncation in casting can lead to a founder receiving all the base tokens

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L71-L126><br>
<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L88>

The initialize function of the `Token` contract receives an array of `FounderParams`, which contains the ownership percent of each founder as a `uint256`. The initialize function checks that the sum of the percents is not more than 100, but the value that is added to the sum of the percent is truncated to fit in `uint8`. This leads to an error because the value that is used for assigning the base tokens is the original, not truncated, `uint256` value.

This can lead to wrong assignment of the base tokens, and can also lead to a situation where not all the users will get the correct share of base tokens (if any).

### Proof of Concept

To verify this bug I created a foundry test. You can add it to the test folder and run it with `forge test --match-test testFounderGettingAllBaseTokensBug`.

This test deploys a token implementation and an `ERC1967` proxy that points to it, and initializes the proxy using an array of 2 founders, each having 256 ownership percent. The value which is added to the `totalOwnership` variable is a `uint8`, and when truncating 256 to fit in a `uint8` it will turn to 0, so this check will pass.

After the call to initialize, the test asserts that all the base token ids belongs to the first founder, w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 8: [H-02] A malicious user can steal other user's deposits from Vault.sol

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L509-L521>
<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L407-L415>

### Impact

When the `Vault.withdraw()` function is called, a maximum of `type(uint96).max` shares are burnt subsequently: `Vault.withdraw()`-> `Vault._withdraw()`-> `Vault._burn` burns `uint96(_shares)`, see [Vault.sol line 1139](<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L1138-L1139>).

A malicious user can exploit this in the following way:

1. A malicious user deposits, for example, two times the value of `type(uint96).max` underlying assets into the Vault; calling the function `Vault.deposit()` two times. They can't deposit more in a single transaction because `type(uint96).max` is the maximum value to deposit.

2. Then, the malicious user calls `Vault.withdraw()` with a higher value of assets to withdraw more than `type(uint96).max`. For example, they withdraw (`2 * type(uint96).max`), which is the total amount of assets they deposited before.

3. Now what happens, is the Vault.sol contract only burns `type(uint96).max` shares for the user, but transfers `2 * type(uint96).max` underlying assets to the malicious user, which is the total amount they deposited before.

4. This happens because `Vault._burn()` only burns `uint96(shares)` shares of t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 9: Unsafe type-casting

**Source**: Spearbit
**Protocol**: Primitive
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
See below

## Description
Throughout the contract weve encountered various unsafe type-castings.

- **invariant**: Within the `_swap` function, the next invariant is an `int256` variable and is calculated within the `checkInvariant` function implemented in the `RMM01Portfolio`. This variable then is dangerously typecasted to `int128` and assigned to an `int256` variable in the iteration struct (L539). The down-casting from `int256` to `int128` assumes that the `nextInvariantWad` fits in an `int128`; in case it wont fit, it will overflow. The updated iteration object is passed to the `_feeSavingEffects` function, which based on the RMM implementation can lead to bad consequences.
  - `iteration.nextInvariant`
  - `_getLatestInvariantAndVirtualPrice`
  - `getNetBalance`

During account settlement, `getNetBalance` is called to compute the difference between the "physical reserves" (contract balance) and the internal reserves: `net = int256(physicalBalance) - int256(internalBalance)`. If the `internalBalance > int256.max`, it overflows into a negative value and the attacker is credited the entire physical balance + overflow upon settlement (and doesnt have to pay anything in settle). This might happen if an attacker allocates or swaps in very high amounts before settlement is called. Consider doing a safe typecast here as a legitimate possible revert would cause less issues than an actual overflow.
  - `getNetBalance`

### Encoding / Decoding

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review.pdf)

---

### Example 10: M-6: Unsafe downcasting arithmetic operation in UserManager related contract and in UToken.sol

**Source**: Sherlock
**Protocol**: Union Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-union-finance-judging/issues/96 

## Found by 
8olidity, ctf\_sec, Lambda

## Summary

The value is unsafely downcasted and truncated from uint256 to uint96 or uint128 in UserManager related contract and in UToken.sol.

## Vulnerability Detail

value can unsafely downcasted. let us look at it cast by cast.

In UserManagerDAI.sol 

```solidity
  function stakeWithPermit(
      uint256 amount,
      uint256 nonce,
      uint256 expiry,
      uint8 v,
      bytes32 r,
      bytes32 s
  ) external whenNotPaused {
      IDai erc20Token = IDai(stakingToken);
      erc20Token.permit(msg.sender, address(this), nonce, expiry, true, v, r, s);

      stake(uint96(amount));
  }
```
as we can see, the user's staking amount is downcasted from uint256 to uint96.

the same issue exists in UserManagerERC20.sol

In the context of UToken.sol, a bigger issue comes.

User invokes the borrow function in UToken.sol

```solidity
   function borrow(address to, uint256 amount) external override onlyMember(msg.sender) whenNotPaused nonReentrant {
```

and

```solidity
  // Withdraw the borrowed amount of tokens from the assetManager and send them to the borrower
  if (!assetManagerContract.withdraw(underlying, to, amount)) revert WithdrawFailed();

  // Call update locked on the userManager to lock this borrowers stakers. This function
  // will revert if the account does not have enough vouchers to cover the borrow amount. ie
  // the borrower is tryin

*[Content truncated...]*

---

### Example 11: M-7: Unsafe casting of user amount from `uint256` to `uint128`

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/018-M 

## Found by 
Lambda, Tomo, hickuphh3, IllIllI, defsec, sirhashalot

## Summary

The unsafe casting of the recovered amount from `uint256` to `uint128` means the users funds will be lost.

## Vulnerability Detail

`logIncomingERC20()` has the recovered amount as type `uint256`, but `amountStored` is of type `uint128`. There is an unsafe casting when incrementing `amountStored`:

```solidity
_erc20WithdrawalAllowances[_originalAddress][_erc20Address].amountStored += uint128(_amount);
```

It is thus possible for the amount recorded to be less than the actual amount recovered.

## Impact

Loss of funds.

## Proof of Concept

The user's balance is `type(uint128).max = 2**128`, but the incremented amount will be zero.

## Recommendation

`amountStored` should be of type `uint256`. Alternatively, use [OpenZeppelins SafeCast library](https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeCast) when casting from `uint256` to `uint128`.

## Lead Senior Watson
Not sure, any tokens which would have a token supply over `type(uint128).max` but I guess it's best to be proactive. The proposed fix does create some issues. Instead of having less tokens transferred to the vault, the contract will revert and prevent the transfer entirely. Arguably more funds would be at risk, so you may as well use `uint256` then or accept the risk and keep the slot packing.

## Harpie Team
Decided to accept the risk of reve

*[Content truncated...]*

---

### Example 12: M-7: Unsafe casting within _purchase function can result in overflow

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/204 

## Found by 
FindEverythingX
## Summary
Unsafe casting within _purchase function can result in overflow

## Vulnerability Detail
Contract: FPAM.sol

The _purchase function is invoked whenever a user wants to buy some tokens from an FPAM auction. 

Note how the amount_ parameter is from type uint96:

[https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L128](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L128)

The payout is then calculated as follows:

amount * 10^baseTokenDecimals / price

[https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L135](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L135)

The crux: The quote token can be with 6 decimals and the base token with 18 decimals.

This would then potentially result in an overflow and the payout is falsified. 

Consider the following PoC:

amount = 1_000_000_000e6 (fees can be deducted or not, this does not matter for this PoC)

baseTokenDecimals = 18

price = 1e4

This price basically means, a user will receive 1e18 BASE tokens for 1e4 (0.01) QUOTE tokens, respectively a user must provide 1e4 (0.01) QUOTE tokens to receive 1e18 BASE tokens

The calculation would be as follows:

1_000_000_000e6 * 1e18 / 1e4 = 1e29

while

*[Content truncated...]*

---

### Example 13: M-1: Unsafe type casting of `poolValue` can malfunction the whole market

**Source**: Sherlock
**Protocol**: Float Capital
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-float-capital-judging/issues/45 

## Found by 
WATCHPUG

## Summary

When `poolValue` is a negative number due to loss in `valueChange` and `funding`, the unsafe type casting from `int256` to `uint256` will result in a huge number close to `2**255` which will revert `_rebalancePoolsAndExecuteBatchedActions()` due to overflow when multiplied by 1e18 at L163.

## Vulnerability Detail

If the funding rate is 100% per year and the `EPOCH_LENGTH` is 4 days, the funding fee for each epoch can be as much as ~1% on the effectiveValue.

Plus, the loss from `valueChange` is capped at 99%, but combining both can still result in a negative `poolValue` at L146.

At L163 `uint256 price = uint256(poolValue).div(tokenSupply);` the type casting from `int256` to `uint256` will result in a huge number close to `2**255`.

`MathUintFloat.div()` will overflow when a number as large as `2**255` is multiplied by 1e18.

## Impact

`_rebalancePoolsAndExecuteBatchedActions` will revert and cause the malfunction of the whole market.

## Code Snippet

https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketCore.sol#L118-L185

## Tool used

Manual Review

## Recommendation

Consider adding a new function to properly handle the bankruptcy of a specific pool.

## Discussion

**JasoonS**

We seed the pools initially with sufficient un-extractable capital such that this shouldn't be an issue (it should never get close 

*[Content truncated...]*

---

### Example 14: [M-05] Unsafe casting from int128 can cause wrong accounting of locked amounts

**Source**: Code4rena
**Protocol**: FIAT DAO
**Impact**: MEDIUM

**Details**:

_Submitted by CertoraInc, also found by 0x1f8b, carlitox477, cRat1st0s, DecorativePineapple, joestakey, ladboy233, reassor, and rvierdiiev_

<https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L418><br>

The unsafe casting to int128 variable can cause its value to be different from the correct value. For example in the createLock function, the addition to the locked amount variable is done by `locked_.amount += int128(int256(_value))`. In that case, if `_value` is greater than `type(int128).max` which is `2**127 - 1`, then the accounting will be wrong and the amount that will be added to `locked_.amount` will be less than the amount of token that will be transferred from the user. Then the user won't be able to withdraw the tokens that he transferred, and they'll be stuck in the contract forever.

### Proof of Concept

1.  Alice tries to lock `2**128` tokens. She calls `createLock(2**128, unlockTime)` with the time she wants to lock for.
2.  The addition of the given value is done by `locked_.amount += int128(int256(_value))`, which actually does nothing to the `locked_.amount` variable and it remains 0. That's because when casting `int128(int256(2**128))` truncates to 0, and that leaves the locked amount unchanged but the tokens are transferred.

### Tools Used

Manual auditing - VS Code and me :)

### Recommended Mitigation Steps

Make sure that the values fit in the variables you are trying to assign them 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-fiatdao)

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## decimals-patterns.md
# Decimals Security Patterns

## Overview

**Frequency**: 45 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 21 | 23 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Cyfrin, Hans

---

## Detection Checklist

- [ ] Check for decimals vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Loss of Long-Term Swap Proceeds Likely in Pools With Decimal or Price Imbalances

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`VirtualOrders.sol#L166`

## Description
This TWAMM implementation tracks the proceeds of long-term swaps efficiently via accumulated values called "scaled proceeds" for each token. In every order block interval (OBI), the scaled proceeds for e.g. the sale of token 0 are incremented by:

```
(quantity of token 1 purchased during the OBI) * 264 = (sales rate of token 0 during the OBI)
```

Then the proceeds of any specific long-term swap can be computed as the product of the difference between the scaled proceeds at the current block (or the expiration block of the order if filled) and the last block for which proceeds were claimed for the order and the order's sales rate, divided by 264:

```
last := min(currentBlock, orderExpiryBlock)
prev := block of last proceeds collection, or block order was placed in if this is the first withdrawal
LT swap proceeds = (scaledProceeds[last] - scaledProceeds[prev]) * (order.salesRate) / 264
```

The value 264 is referred to as the "scaling factor" and is intended to reduce precision loss in the division to determine the increment to the scaled proceeds.

The addition to increment the scaled proceeds and the subtraction to compute its net change is both intentionally done with unchecked arithmeticsince only the difference matters, so long as at most one overflow occurs between claim-of-proceeds events for any given order, the computed proceeds will be correct (up to rounding errors). If two or more overfl

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 2: [H-08] Vault.withdraw mixes normalized and standard amounts

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.balance` function uses the `balanceOfThis` function which scales ("normalizes") all balances to 18 decimals.

```
for (uint8 i; i < _tokens.length; i++) {
    address _token = _tokens[i];
    // everything is padded to 18 decimals
    _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
}
```

Note that `balance()`'s second term `IController(manager.controllers(address(this))).balanceOf()` is not normalized, but it must be.

This leads to many issues through the contracts that use `balance` but don't treat these values as normalized values.
For example, in `Vault.withdraw`, the computed `_amount` value is normalized (in 18 decimals).
But the `uint256 _balance = IERC20(_output).balanceOf(address(this));` value is not normalized but compared to the normalized `_amount` and even subtracted:

```solidity
// @audit compares unnormalzied output to normalized output
if (_balance < _amount) {
    IController _controller = IController(manager.controllers(address(this)));
    // @audit cannot directly subtract unnormalized
    uint256 _toWithdraw = _amount.sub(_balance);
    if (_controller.strategies() > 0) {
        _controller.withdraw(_output, _toWithdraw);
    }
    uint256 _after = IERC20(_output).balanceOf(address(this));
    uint256 _diff = _after.sub(_balance);
    if (_diff < _toWithdraw) {
        _amount = _balance.add(_diff);
    }
}
```

## Impact
Imagine in `withdraw`, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 3: [H-07] Vault.balance() mixes normalized and standard amounts

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.balance` function uses the `balanceOfThis` function which scales ("normalizes") all balances to 18 decimals.

```
for (uint8 i; i < _tokens.length; i++) {
    address _token = _tokens[i];
    // everything is padded to 18 decimals
    _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
}
```

Note that `balance()`'s second term `IController(manager.controllers(address(this))).balanceOf()` is not normalized.
The code is adding a non-normalized amount (for example 6 decimals only for USDC) to a normalized (18 decimals).

## Impact
The result is that the `balance()` will be under-reported.
This leads to receiving wrong shares when `deposit`ing tokens, and a wrong amount when redeeming `tokens`.

## Recommended Mitigation Steps
The second term `IController(manager.controllers(address(this))).balanceOf()` must also be normalized before adding it.
`IController(manager.controllers(address(this))).balanceOf()` uses `_vaultDetails[msg.sender].balance` which directly uses the raw token amounts which are not normalized.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 4: [H-01] CompositeMultiOracle returns wrong decimals for prices?

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `CompositeMultiOracle.peek/get` functions seem to return wrong prices.
It's unclear what decimals `source.decimals` refers to in this case. Does it refer to `source.source` token decimals?

It chains the price arguments through `_peek` function calls and a single price is computed as:

```solidity
(priceOut, updateTimeOut) = IOracle(source.source).peek(base, quote, 10 ** source.decimals);   // Get price for one unit
// @audit shouldn't this divide by 10 ** IOracle(source.source).decimals() instead?
priceOut = priceIn * priceOut / (10 ** source.decimals);
```

Assume all oracles use 18 decimals (`oracle.decimals()` returns 18) and `source.decimals` refers to the _token decimals_ of `source.source`.

Then going from `USDC -> DAI -> USDT` (`path = [DAI]`) starts with a price of `1e18` in `peek`:
- `_peek(USDC, DAI, 1e18)`: Gets the price of `1e6 USDC` (as USDC has 6 decimals) in DAI with 18 decimals precision (because all oracle precision is set to 18): `priceOut = priceIn * 1e18 / 1e6 = 1e18 * 1e18 / 1e6 = 1e30`
- `_peek(DAI, USDT, 1e30)`: Gets the price of `1e18 DAI` (DAI has 18 decimals) with 18 decimals precision: `priceOut = priceIn * 1e18 / 1e18 = priceIn = 1e30`

It then uses `1e30` as the price to go from `USDC` to `USDT`: `value = price * amount / 1e18 = 1e30 * (1.0 USDC) / 1e18 = 1e30 * 1e6 / 1e18 = 1e18 = 1e12 * 1e6 = 1_000_000_000_000.0 USDT`. Inflating the actual `USDT` amount.

## Recommended Mitigation Steps
The i

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-08-yield)

---

### Example 5: [H-02] Wrong token allocation computation for token decimals != 18 if floor price not reached

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

In `LaunchEvent.createPair`, when the floor price is not reached (`floorPrice > wavaxReserve * 1e18 / tokenAllocated`), the tokens to be sent to the pool are lowered to match the raised WAVAX at the floor price.

Note that the `floorPrice` is supposed to have a precision of 18:

> /// @param \_floorPrice Price of each token in AVAX, scaled to 1e18

The `floorPrice > (wavaxReserve * 1e18) / tokenAllocated` check is correct but the `tokenAllocated` computation involves the `token` decimals:

```solidity
// @audit should be wavaxReserve * 1e18 / floorPrice
tokenAllocated = (wavaxReserve * 10**token.decimals()) / floorPrice;
```

This computation does not work for `token`s that don't have 18 decimals.

#### Example

Assume I want to sell `1.0 wBTC = 1e8 wBTC` (8 decimals) at `2,000.0 AVAX = 2,000 * 1e18 AVAX`.
The `floorPrice` is `2000e18 * 1e18 / 1e8 = 2e31`

Assume the Launch event only raised `1,000.0 AVAX` - half of the floor price for the issued token amount of `1.0 WBTC` (it should therefore allocate only half a WBTC) - and the token amount will be reduced as: `floorPrice = 2e31 > 1000e18 * 1e18 / 1e8 = 1e31 = actualPrice`.
Then, `tokenAllocated = 1000e18 * 1e8 / 2e31 = 1e29 / 2e31 = 0` and no tokens would be allocated, instead of `0.5 WBTC = 0.5e8 WBTC`.

The computation should be `tokenAllocated = wavaxReserve * 1e18 / floorPrice = 1000e18 * 1e18 / 2e31 = 1e39 / 2e31 = 10e38 / 2e31 = 5e7 = 0.5e8`.

#### Recommendation

The new `tokenAllocated` comp

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-trader-joe)

---

### Example 6: [H-01] Incorrect handling of `pricefeed.decimals()`

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/2175c044af98509261e4147edeb48e1036773771/src/oracles/PegOracle.sol#L46-L83>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/2175c044af98509261e4147edeb48e1036773771/src/Controller.sol#L299-L300>

### Impact

Wrong math for handling pricefeed decimals. This code will only work for pricefeeds of 8 decimals, any others give wrong/incorrect data. The maths used can be shown in three lines:

```solidity
nowPrice = (price1 * 10000) / price2;
nowPrice = nowPrice * int256(10**(18 - priceFeed1.decimals()));
return nowPrice / 1000000;
```

Line1: adds 4 decimals
Line2: adds (18 - d) decimals, (where d = pricefeed.decimals())
Line3:  removes 6 decimals

Total: adds (16 - d) decimals

when d=8, the contract correctly returns an 8 decimal number. However, when d = 6, the function will return a 10 decimal number. This is further raised by (18-d = 12) decimals when checking for depeg event, leading to a 22 decimal number which is 4 orders of magnitude incorrect.

if d=18, (like usd-eth pricefeeds) contract fails / returns 0.

All chainlink contracts which give price in eth, operate with 18 decimals. So this can cripple the system if added later.

### Proof of Concept

Running the test  AssertTest.t.sol:testPegOracleMarketCreation and changing the line on

<https://github.com/code-423n4/2022-09-y2k-finance/blob/2175c044af98509261e4147edeb48e1036773771/test/AssertTest.t.sol#L30>

to

```solidity
PegOracle pegOracle3 = new PegOra

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 7: `TokenSaleProposal::buy` implicitly assumes that buy token has 18 decimals resulting in a potential total loss scenario for Dao Pool

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** `TokenSaleProposalBuy::buy` is called by users looking to buy the DAO token using a pre-approved token. The exchange rate for this sale is pre-assigned for the specific tier. This function internally calls `TokenSaleProposalBuy::_purchaseWithCommission` to transfer funds from the buyer to the gov pool. Part of the transferred funds are used to pay the DexeDAO commission and balance funds are transferred to the `GovPool` address. To do this, `TokenSaleProposalBuy::_sendFunds` is called.

```solidity
    function _sendFunds(address token, address to, uint256 amount) internal {
        if (token == ETHEREUM_ADDRESS) {
            (bool success, ) = to.call{value: amount}("");
            require(success, "TSP: failed to transfer ether");
        } else {
  >>          IERC20(token).safeTransferFrom(msg.sender, to, amount.from18(token.decimals())); //@audit -> amount is assumed to be 18 decimals
        }
    }
```

Note that this function assumes that the `amount` of ERC20 token is always 18 decimals. The `DecimalsConverter::from18` function converts from a base decimal (18) to token decimals. Note that the amount is directly passed by the buyer and there is no prior normalisation done to ensure the token decimals are converted to 18 decimals before the `_sendFunds` is called.


**Impact:** It is easy to see that for tokens with smaller decimals, eg. USDC with 6 decimals, will cause a total loss to the DAO. In such cases amount is presumed to be 18 decimals & on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 8: H-1: Too few `ICHI` v2 farming reward tokens transferred to the user due to incorrect decimal precision

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/319 

## Found by 
berndartmueller, 0x52

## Summary

The `burn` function in the `WIchiFarm` contract transfers too few `ICHI` **v2** farming reward tokens to the caller due to using 9 decimals instead of 18 decimals for the `ICHI` **v2** token.

## Vulnerability Detail

Closing an ICHI vault spell farming position burns the wrapped ICHI vault LP tokens (`WIchiFarm` ERC-1155 tokens). Farming rewards are harvested from the ICHI farm ([see contract on Etherscan](https://etherscan.io/address/0x275dfe03bc036257cd0a713ee819dbd4529739c8)) and received as `ICHI` **v1** tokens.

The `ICHI` **v1** ERC-20 token uses **9 decimals** ([see token on Etherscan](https://etherscan.io/token/0x903bEF1736CDdf2A537176cf3C64579C3867A881)), whereas the `ICHI` **v2** ERC-20 token uses **18 decimals** ([see token on Etherscan](https://etherscan.io/token/0x111111517e4929D3dcbdfa7CCe55d30d4B6BC4d6)).

Those received `ICHI` **v1** tokens are then converted to **v2** tokens in line 134.

To calculate the user's share of eligible `ICHI` **v2** reward tokens, the reward per share accumulator `stIchiPerShare` at the time of minting the `WIchiFarm` token and the current `enIchiPerShare` accumulator is used.

However, those accumulator values are in **9 decimals** precision (please see the `ichiFarmV2.harvest` function for proof that `pool.accIchiPerShare` uses 9 decimals, otherwise the `ICHI` token transfer would fail due to inflated 

*[Content truncated...]*

---

### Example 9: H-1: debtToMint incorrectly treats feeAdjustment decimals

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/236 

## Found by 
keccak123, hyh

## Summary

_debtToMint() will return `0` decimals amounts and `sqthToSell` in depositAuction() will be insignificant, leading to ignoring the market orders used and depositing auction to be void as no external funding will be brought in.

## Vulnerability Detail

`feeAdjustment = _calcFeeAdjustment()` is `(squeethEthPrice * feeRate) / 10000` and have `18` decimals.

`wSqueethToMint = (_amount * debt) / (collateral + (debt * feeAdjustment))` will have `36` decimals in numerator and the same `36` in denominator, yielding `0` decimals figure. That figure is `sqthToSell`, so no market buying orders will be ever filled.

## Impact

depositAuction() will malfunction all the time, either reverting or producing less WETH and less CRAB than desired, i.e. there will be no deposit auction as market order part is needed to bring in the liquidity to be distributed.

Setting the severity to be high as this is system malfunction with material impact and no prerequisites.

## Code Snippet

feeAdjustment is treated as if it has no decimals:

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L476-L485

```solidity
    /**
     * @dev calculates wSqueeth minted when amount is deposited
     * @param _amount to deposit into crab
     */
    function _debtToMint(uint256 _amount) internal view returns (uint256) {
        uint256 feeAdjustment = _calcFeeA

*[Content truncated...]*

---

### Example 10: H-5: `UniV2LPOracle` will malfunction if token0 or token1's `decimals != 18`

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/026-H 
## Found by 
Lambda, WATCHPUG, 0x52, hyh

## Summary

When one of the LP token's underlying tokens `decimals` is not 18, the price of the LP token calculated by `UniV2LPOracle` will be wrong. 

## Vulnerability Detail

`UniV2LPOracle` is an implementation of Alpha Homora v2's Fair Uniswap's LP Token Pricing Formula:

> The Formula ... of combining fair asset prices and fair asset reserves:

> $$
P = 2\cdot \frac{\sqrt{r_0 \cdot r_1} \cdot \sqrt{p_0\cdot p_1}}{totalSupply},
$$

> where $r_i$ is the asset ii's pool balance and $p_i$ is the asset $i$'s fair price.

However, the current implementation wrongful assumes $r_0$ and $r_1$ are always in 18 decimals.

https://github.com/sentimentxyz/oracle/blob/59b26a3d8c295208437aad36c470386c9729a4bc/src/uniswap/UniV2LPOracle.sol#L39-L50

```solidity
function getPrice(address pair) external view returns (uint) {
    (uint r0, uint r1,) = IUniswapV2Pair(pair).getReserves();

    // 2 * sqrt(r0 * r1 * p0 * p1) / totalSupply
    return FixedPointMathLib.sqrt(
        r0
        .mulWadDown(r1)
        .mulWadDown(oracle.getPrice(IUniswapV2Pair(pair).token0()))
        .mulWadDown(oracle.getPrice(IUniswapV2Pair(pair).token1()))
    )
    .mulDivDown(2e27, IUniswapV2Pair(pair).totalSupply());
}
```

https://github.com/transmissions11/solmate/blob/main/src/utils/FixedPointMathLib.sol

```solidity
uint256 internal constant WAD = 1e18; // The scalar of ETH and

*[Content truncated...]*

---

### Example 11: H-3: Sense redeem is unavailable and funds are frozen for underlyings whose decimals are smaller than the corresponding IBT decimals

**Source**: Sherlock
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-illuminate-judging/issues/228 

## Found by 
hyh, 0x52

## Summary

Sense version of Redeemer's redeem() compares `amount` of Sense principal token Lender had on its balance vs `redeemed` amount of underlying as a slippage check, requiring that the latter be equal or greater than the former.

As these numbers have different decimals this check blocks the redeem altogether for the tokens whose decimals are smaller than decimals of the corresponding interest bearing token, freezing the funds.

## Vulnerability Detail

Sense version of redeem() assumes that Sense PT has the same decimals as underlying, performing slippage check by directly comparing the amounts.

Sense principal has decimals of the corresponding interest bearing tokens, not the decimals of the underlying. In the compound case IBT decimals are `8` and can be greater or less than underlying's.

For example, `1st July 2023 cUSDC Sense Principal Token` has `8` decimals, as cUSDC does (instead of 6 as USDC):

https://etherscan.io/token/0x869a70c198c937801b26d2701dc8e4e8c4de354a

In this case the slippage check reverts the operation. Sense PT cannot be turned to underlying and will remain on Lender's balance this way.

On the other hand, when underlying decimals are greater than IBT decimals the slippage check becomes a noop.

## Impact

Protocol users can be subject to market manipulations as Sense AMM result isn't checked for the underlyings whose decimals are higher

*[Content truncated...]*

---

### Example 12: H-4: `ERC4626Oracle` Price will be wrong when the ERC4626's `decimals` is different from the underlying tokens decimals

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/025-H 
## Found by 
Lambda, JohnSmith, WATCHPUG, 0x52, berndartmueller, Bahurum

## Summary

EIP-4626 does not require the decimals must be the same as the underlying tokens' decimals, and when it's not, `ERC4626Oracle` will malfunction.

## Vulnerability Detail

In the current implementation, `IERC4626(token).decimals()` is used as the `IERC4626(token).asset()`'s decimals to calculate the ERC4626's price.

However, while most ERC4626s are using the underlying tokens decimals as `decimals`, there are some ERC4626s use a different decimals from underlying tokens decimals since EIP-4626 does not require the decimals must be the same as the underlying tokens decimals:

> Although the convertTo functions should eliminate the need for any use of an EIP-4626 Vaults decimals variable, it is still strongly recommended to mirror the underlying tokens decimals if at all possible, to eliminate possible sources of confusion and simplify integration across front-ends and for other off-chain users.

Ref: https://eips.ethereum.org/EIPS/eip-4626

## Impact

The price of ERC4626 will be significantly underestimated when the underlying token's decimals > ERC4626's decimals, and be significantly overestimated when the underlying token's decimals < ERC4626's decimals.

## Code Snippet

https://github.com/sentimentxyz/oracle/blob/59b26a3d8c295208437aad36c470386c9729a4bc/src/erc4626/ERC4626Oracle.sol#L35-L43

```sol

*[Content truncated...]*

---

### Example 13: [H-07] Incorrect precision assumed from RdpxPriceOracle creates multiple issues related to value inflation/deflation

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/amo/UniV2LiquidityAmo.sol#L372> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/amo/UniV2LiquidityAmo.sol#L381> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/PerpetualAtlanticVault.sol#L539> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/core/RdpxV2Core.sol#L1160>

The `RdpxEthPriceOracle`, available in the audit repo [here](https://github.com/dopex-io/rdpx-eth-oracle/blob/5762c2339b1c45b87ff4db172e43cef4a0ff603a/src/RdpxEthOracle.sol), provides the `RdpxV2Core`, the `UniV2LiquidityAmo` and the `PerpetualAtlanticVault` contracts the necessary values for `rdpx` related price calculations.

The issue is that these contracts expect the returned values to be in `1e8` precision (as stated in the natspec [here](https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/core/RdpxV2Core.sol#L1224), [here](https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/amo/UniV2LiquidityAmo.sol#L378) and [here](https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/IPerpetualAtlanticVault.sol#L20C1-L24C65)). But the returned precision [is actually `1e18`](https://github.com/dopex

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 14: [H-01] Improper precision of strike price calculation can result in broken protocol

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/core/RdpxV2Core.sol#L1189-L1190> 

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/perp-vault/PerpetualAtlanticVault.sol#L576-L583>

Due to a lack of adequate precision, the calculated strike price for a PUT option for rDPX is not guaranteed to be 25% OTM, which breaks core assumptions around (1) protecting downside price movement of the rDPX which makes up part of the collateral for dpxETH & (2) not overpaying for PUT option protection.

More specifically, the price of rDPX as used in the `calculateBondCost` function of the RdpxV2Core contract is represented as ETH / rDPX, and is given in 8 decimals of precision. To calculate the strike price which is 25% OTM based on the current price, the logic calls the `roundUp` function on what is effectively 75% of the current spot rDPX price. The issue is with the `roundUp` function of the PerpetualAtlanticVault contract, which effectively imposes a minimum value of 1e6.

Considering approximate recent market prices of `$`2000/ETH and `$`20/rDPX, the current price of rDPX in 8 decimals of precision would be exactly 1e6. Then to calculate the 25% OTM strike price, we would arrive at a strike price of `1e6 * 0.75 = 75e4`. The `roundUp` function will then round up this value to `1e6` as the strike price, and issue the PUT option using that invalid strike price. Obviously this strike price is not 25% OTM, and since its an ITM option, the premium imposed will

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 15: Protocol fees are in WAD instead of token decimal units

**Source**: Spearbit
**Protocol**: Primitive
**Impact**: HIGH

**Details**:

## High Risk Report

## Severity
**High Risk**

## Context
`Portfolio.sol#L489`

## Description
When swapping, `deltaInput` is in WAD (not token decimals) units. Therefore, the `protocolFee` will also be in WAD as a percentage of `deltaInput`. This WAD amount is then credited to the REGISTRY:

```solidity
iteration.feeAmount = (deltaInput * _state.fee) / PERCENTAGE;
if (_protocolFee != 0) {
    uint256 protocolFeeAmount = iteration.feeAmount / _protocolFee;
    iteration.feeAmount -= protocolFeeAmount;
    _applyCredit(REGISTRY, _state.tokenInput, protocolFeeAmount);
}
```

The privileged registry can claim these fees using a withdrawal (draw) and the WAD units are not scaled back to token decimal units, resulting in withdrawing more fees than they should have received if the token has less than 18 decimals. This will reduce the global reserve by the increased fee amount and break the accounting and functionality of all pools using the token.

## Recommendation
Generally, some quantities are in WAD units and some in token decimals throughout the protocol. We recommend using WAD units everywhere and only converting from/to token decimal units at the "token boundary", directly at the point of interaction with the token contract through a `transfer` / `transferFrom` / `balanceOf` call.

## Primitive
Resolved in PR 335.

## Spearbit
Fixed.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review.pdf)

---

### Example 16: _slippageTol does not adjust for decimal differences

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Severity
**Medium Risk**

## Context
AssetLogic.sol#L273

## Description
Users set the slippage tolerance in percentage. The `assetLogic` calculates:

```
minReceived = (_amount * _slippageTol) / s.LIQUIDITY_FEE_DENOMINATOR
```

Then `assetLogic` uses `minReceived` in the swap functions. However, the `minReceived` does not adjust for the decimal differences between `assetIn` and `assetOut`. Users will either always hit the slippage or suffer huge slippage when `assetIn` and `assetOut` have a different number of decimals.

Assume the number of decimals of `assetIn` is 6 and the number of decimals of `assetOut` is 18. The `minReceived` will be set to `10^-12` smaller than the correct value. Users would be vulnerable to sandwich attacks in this case. 

Alternatively, if the number of decimals of `assetIn` is 18 and the number of decimals of `assetOut` is 6, the `minReceived` will be set to `10^12` larger than the correct value. Users would always hit the slippage, and the cross-chain transfer will get stuck.

### Code Snippet
```solidity
library AssetLogic {
    function _swapAsset(... ) ... {
        // Swap the asset to the proper local asset
        uint256 minReceived = (_amount * _slippageTol) / s.LIQUIDITY_FEE_DENOMINATOR;
        ...
        return (pool.swapExact(_amount, _assetIn, _assetOut, minReceived), _assetOut);
        ...
    }
}
```

## Recommendation
Recommend to adjust the value with `swapStorage.tokenPrecisionMultipliers` for inter

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 17: claim() will underflow and revert for all tokens without 18 decimals

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity
Medium Risk

## Context
WithdrawProxy.sol#238-244

## Description
In the `claim()` function, the amount to decrease the Y intercept of the vault is calculated as:

```
(s.expected - balance).mulWadDown(10**ERC20(asset()).decimals() - s.withdrawRatio)
```

`s.withdrawRatio` is represented as a WAD (18 decimals). As a result, using any token with a number of decimals under 17 (assuming the withdraw ratio is greater than 10%) will lead to an underflow and cause the function to revert.

In this situation, the token's decimals don't matter. They are captured in `s.expected` and `balance`, and are also the scale at which the vault's y-intercept is measured, so there's no need to adjust for them.

**Note**: I know this isn't a risk in the current implementation, since it's WETH only, but since you are planning to generalize to accept all ERC20s, this is important.

## Recommendation
```solidity
if (balance < s.expected) {
    PublicVault(VAULT()).decreaseYIntercept(
        (s.expected - balance).mulWadDown(
            -10**ERC20(asset()).decimals() - s.withdrawRatio
            + 1e18 - s.withdrawRatio
        )
    );
}
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 18: [M-02] Price will not always be 18 decimals, as expected and outlined in the comments

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

The `price()` function is expected to return the price of one fractional tokens, represented in base tokens, to 18 decimals of precision. This is laid out clearly in the comments:

`/// @notice The current price of one fractional token in base tokens with 18 decimals of precision.`<br>
`/// @dev Calculated by dividing the base token reserves by the fractional token reserves.`<br>
`/// @return price The price of one fractional token in base tokens * 1e18.`<br>


However, the formula incorrectly calculates the price to be represented in whatever number of decimals the base token is in. Since there are many common base tokens (such as USDC) that will have fewer than 18 decimals, this will create a large mismatch between expected prices and the prices that result from the function.

### Proof of Concept

Prices are calculated with the following formula, where `ONE = 1e18`:

```solidity
return (_baseTokenReserves() * ONE) / fractionalTokenReserves();
```

We know that `fractionalTokenReserves` will always be represented in 18 decimals. This means that the `ONE` and the
`fractionalTokenReserves` will cancel each other out, and we are left with the `baseTokenReserves` number of decimals for the final price.

As an example:

*   We have `$1000` USDC in reserves, which at 6 decimals is 1e9
*   We have 1000 fractional tokens in reserve, which at 18 decimals is 1e21
*   The price calculation is `1e9 * 1e18 / 1e21 = 1e6`
*   While the value should be 1 token, the 1e6 will be interpreted 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 19: [M-19] _handleDeposit and _handleWithdraw do not account for tokens with decimals higher than 18

**Source**: Code4rena
**Protocol**: Tigris Trade
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L650
https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L675


## Vulnerability details

## Impact 

In `Trading.sol` a [deposit](https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L675) or [withdrawal](https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L700) of tokens with decimals higher than 18 will always revert. 

This is the case e.g. for `NEAR` which is divisible into 10e24 `yocto` 

## Proof of Concept

Change [00.Mocks.js#L33](https://github.com/code-423n4/2022-12-tigris/blob/main/deploy/test/00.Mocks.js#L33) to:

```
args: ["USDC", "USDC", 24, deployer, ethers.utils.parseUnits("1000", 24)]
```

Then in [07.Trading.js](https://github.com/code-423n4/2022-12-tigris/blob/main/test/07.Trading.js):

```
Opening and closing a position with tigUSD output
Opening and closing a position with <18 decimal token output
```

are going to fail with:
```
Error: VM Exception while processing transaction: reverted with panic code 0x11 (Arithmetic operation underflowed or overflowed outside of an unchecked block)
```

## Tools Used

Visual Studio Code

## Recommended Mitigation Steps

Update calculations in the contract to account for tokens with decimals higher than 18.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-tigris)

---

### Example 20: [M-05] Tokens with lower number of decimals can result in postponed linear vesting for user

**Source**: Code4rena
**Protocol**: VTVL
**Impact**: MEDIUM

**Details**:

_Submitted by pashov_

[VTVLVesting.sol#L174](https://github.com/code-423n4/2022-09-vtvl/blob/69da6e96f94ff3e02b9bb6175e6de2b3e71d3eb0/contracts/VTVLVesting.sol#L174)<br>

In the `_baseVestedAmount` of `VTVLVesting.sol` we see the following code

```solidity
uint40 finalVestingDurationSecs = _claim.endTimestamp - _claim.startTimestamp; // length of the interval
uint112 linearVestAmount = _claim.linearVestAmount * truncatedCurrentVestingDurationSecs / finalVestingDurationSecs;
```

Lets look at `truncatedCurrentVestingDurationSecs` as just the duration passed from the start of the vesting period for the PoC (this doesnt omit important data in this context).

Now think of the following scenario:

We have a token `$TKN` that has 6 decimals (those are the decimals of both USDT & USDC). We want to distribute 10,000 of those tokens to a user vested over a 10 year period.

10 years in seconds is 315360000 &ast;&ast;&ast;&ast;(this is `finalVestingDurationSecs`)

This means that we will distribute 10,000 &ast; 10^6 = 10 000 000 000 fractions of a token for 315360000 seconds, meaning we will distribute 310 fractions of a token each second - this is `linearVestAmount`

Now, since `finalVestingDurationSecs` is so big (315360000) it will almost always round `linearVestAmount` to zero when dividing by it, up until

`_claim.linearVestAmount * truncatedCurrentVestingDurationSecs` becomes a bigger number than 315360000, but since `_claim.linearVestAmount` is 310 we will need the current ve

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-vtvl)

---

### Example 21: [M-07] Wrong calculation for `yVault` price per share if decimals != 18

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: MEDIUM

**Details**:

_Submitted by berndartmueller_

The [yVault.getPricePerFullShare()](https://github.com/code-423n4/2022-04-jpegd/blob/main/contracts/vaults/yVault/yVault.sol#L196) function calculates the price per share by multiplying with `1e18` token decimals with the assumption that the underlying token always has 18 decimals. `yVault` has the same amount of decimals as it's underlying token see ([yVault.decimals()](https://github.com/code-423n4/2022-04-jpegd/blob/main/contracts/vaults/yVault/yVault.sol#L70))

But tokens don't always have `1e18` decimals (e.g. USDC).

### Impact

The price per share calculation does not return the correct price for underlying tokens that do not have 18 decimals. This could lead to paying out too little or too much and therefore to a loss for either the protocol or the user.

### Proof of Concept

Following test will fail with the current implementation when the underlying vault token has 6 decimals:

*NOTE: `units()` helper function was adapted to accept the desired decimals.*

```typescript
it.only("should mint the correct amount of tokens for tokens with 6 decimals", async () => {
  const DECIMALS = 6;

  await token.setDecimals(DECIMALS);
  expect(await yVault.decimals()).to.equal(DECIMALS);

  expect(await yVault.getPricePerFullShare()).to.equal(0);
  await token.mint(user1.address, units(1000, DECIMALS));
  await token.connect(user1).approve(yVault.address, units(1000, DECIMALS));

  await yVault.connect(user1).deposit(units(500, DECIMALS));
  expect(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 22: H-4: The price from `StableOracleDAI` is returned with the incorrect number of decimals

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/236 

## Found by 
0xStalin, 0xeix, 0xlmanini, Bahurum, Brenzee, Dug, G-Security, PNS, Proxy, SanketKogekar, T1MOH, Vagner, WATCHPUG, ast3ros, ctf\_sec, immeas, juancito, kutugu, n33k, peanuts, pengun, qbs, qpzm, saidam017, sam\_gmk, sashik\_eth, twicek
## Summary

The price returned from the `getPriceUSD` function of the `StableOracleDAI` is scaled up by `1e10`, which results in 28 decimals instead of the intended 18.

## Vulnerability Detail

In `StableOracleDAI` the `getPriceUSD` function is defined as follows...

```solidity
    function getPriceUSD() external view override returns (uint256) {
        address[] memory pools = new address[](1);
        pools[0] = 0x60594a405d53811d3BC4766596EFD80fd545A270;
        uint256 DAIWethPrice = DAIEthOracle.quoteSpecificPoolsWithTimePeriod(
            1000000000000000000, // 1 Eth
            0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, // WETH (base token)
            0x6B175474E89094C44Da98b954EedeAC495271d0F, // DAI (quote token)
            pools, // DAI/WETH pool uni v3
            600 // period
        );

        uint256 wethPriceUSD = ethOracle.getPriceUSD();

        // chainlink price data is 8 decimals for WETH/USD, so multiply by 10 decimals to get 18 decimal fractional
        //(uint80 roundID, int256 price, uint256 startedAt, uint256 timeStamp, uint80 answeredInRound) = priceFeedDAIETH.latestRoundData();
        (, int256 price,,,) = priceFeedDAIE

*[Content truncated...]*

---

### Example 23: [M-05] Withdrawing ETH collateral with max uint256 amount value reverts transaction

**Source**: Code4rena
**Protocol**: Sturdy
**Impact**: MEDIUM

**Details**:

_Submitted by berndartmueller, also found by WatchPug_

Withdrawing ETH collateral via the `withdrawCollateral` function using `type(uint256).max` for the `_amount` parameter reverts the transaction due to `_asset` being the zero-address and `IERC20Detailed(_asset).decimals()` not working for native ETH.

#### Proof of Concept

[GeneralVault.sol#L121-L124](https://github.com/code-423n4/2022-05-sturdy/blob/78f51a7a74ebe8adfd055bdbaedfddc05632566f/smart-contracts/GeneralVault.sol#L121-L124)

```solidity
if (_amount == type(uint256).max) {
    uint256 decimal = IERC20Detailed(_asset).decimals(); // @audit-info does not work for native ETH. Transaction reverts
    _amount = _amountToWithdraw.mul(this.pricePerShare()).div(10**decimal);
}
```

### Recommended mitigation steps

Check `_asset` and use hard coded decimal value (`18`) for native ETH.

**[sforman2000 (Sturdy) confirmed](https://github.com/code-423n4/2022-05-sturdy-findings/issues/85)**

**[atozICT20 (Sturdy) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/85):**
 > [Fix the issue of transaction fails due to calculate ETH's decimals sturdyfi/code4rena-may-2022#7](https://github.com/sturdyfi/code4rena-may-2022/pull/7)

**[hickuphh3 (judge) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/85#issuecomment-1145575544):**
 > Good find! Stated in `_asset` description that null address is interpreted as ETH, which isn't a token, and therefore reverts when attempting to fetch its de

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-sturdy)

---

### Example 24: M-5: Exponential and logarithmic price adapters will return incorrect pricing when moving from higher dp token to lower dp token

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/42 

## Found by 
0x52
## Summary

The exponential and logarithmic price adapters do not work correctly when used with token pricing of different decimal places. This is because the resolution of the underlying expWad and lnWad functions is not fit for tokens that aren't 18 dp.

## Vulnerability Detail

[AuctionRebalanceModuleV1.sol#L856-L858](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L856-L858)

    function _calculateQuoteAssetQuantity(bool isSellAuction, uint256 _componentQuantity, uint256 _componentPrice) private pure returns (uint256) {
        return isSellAuction ? _componentQuantity.preciseMulCeil(_componentPrice) : _componentQuantity.preciseMul(_componentPrice);
    }

The price returned by the adapter is used directly to call _calculateQuoteAssetQuantity which uses preciseMul/preciseMulCeil to convert from component amount to quote amount. Assume we wish to sell 1 WETH for 2,000 USDT. WETH is 18dp while USDT is 6dp giving us the following price:

    1e18 * price / 1e18 = 2000e6

Solving for price gives:

    price = 2000e6

This establishes that the price must be scaled to:

    price dp = 18 - component dp + quote dp

Plugging in our values we see that our scaling of 6 dp makes sense.

[BoundedStepwiseExponentialPriceAdapter.sol#L67-L80](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-proto

*[Content truncated...]*

---

### Example 25: [H-04] Yearn token  shares conversion decimal issue

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The yearn strategy `YearnYield` converts shares to tokens by doing `pricePerFullShare * shares / 1e18`:

    function getTokensForShares(uint256 shares, address asset) public view override returns (uint256 amount) {
        if (shares == 0) return 0;
        // @audit should divided by vaultDecimals 
        amount = IyVault(liquidityToken[asset]).getPricePerFullShare().mul(shares).div(1e18);
    }

But Yearn's `getPricePerFullShare` seems to be [in `vault.decimals()` precision](https://github.com/yearn/yearn-vaults/blob/03b42dacacec2c5e93af9bf3151da364d333c222/contracts/Vault.vy#L1147), i.e., it should convert it as `pricePerFullShare * shares / (10 ** vault.decimals())`.
The vault decimals are the same [as the underlying token decimals](https://github.com/yearn/yearn-vaults/blob/03b42dacacec2c5e93af9bf3151da364d333c222/contracts/Vault.vy#L295-L296)

#### Impact

The token and shares conversions do not work correctly for underlying tokens that do not have 18 decimals.
Too much or too little might be paid out leading to a loss for either the protocol or user.

#### Recommended Mitigation Steps

Divide by `10**vault.decimals()` instead of `1e18` in `getTokensForShares`.
Apply a similar fix in `getSharesForTokens`.

**[ritik99 (Sublime) confirmed](https://github.com/code-423n4/2021-12-sublime-findings/issues/134)**

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

## Statistics

- Total findings analyzed: 45
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## wrong-math-patterns.md
# Wrong Math Security Patterns

## Overview

**Frequency**: 107 occurrences (0.21% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 67 | 38 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Hans, OpenZeppelin

---

## Detection Checklist

- [ ] Check for wrong math vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Users Receive Less Rewards Due To Miscalculations

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L305>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L281>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L373>

### Background

The amount of rewards accrued by global and user states is computed by the following steps:

1.  Calculate seconds elapsed since the last update (`block.timestamp - lastUpdate`)
2.  Calculate the new rewards by multiplying seconds elapsed by the last supply (`(block.timestamp - lastUpdate) * lastSupply`)
3.  Append the new rewards to the existing rewards (`rewards = rewards + (block.timestamp - lastUpdate) * lastSupply`)

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L305>

```solidity
/**
    @notice Update global accrual state
    @param  globalState    GlobalState  Global state of the producer token
    @param  producerToken  ERC20        Producer token contract
*/
function _globalAccrue(GlobalState storage globalState, ERC20 producerToken)
	internal
{
    uint256 totalSupply = producerToken.totalSupply();
    uint256 lastUpdate = globalState.lastUpdate;
    uint256 lastSupply = globalState.lastSupply;

    // Calculate rewards, the product of seconds elapsed and last supply
    // Only calculate and update

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 2: [H-01] Too many rewards are distributed when a draw is closed

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L178-L184><br>
<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L154-L157><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/PrizePool.sol#L366><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/abstract/TieredLiquidityDistributor.sol#L374>

A relayer completes a prize pool draw by calling `rngComplete` in `RngRelayAuction.sol`. This method closes the prize pool draw with the relayed random number and distributes the rewards to the RNG auction recipient and the RNG relay auction recipient. These rewards are calculated based on a fraction of the prize pool reserve rather than an actual value.

However, the current reward calculation mistakenly includes an extra `reserveForOpenDraw` amount just after the draw has been closed. Therefore the fraction over which the rewards are being calculated includes tokens that have not been added to the reserve and will actually only be added to the reserve when the next draw is finalised. As a result, the reward recipients are rewarded too many tokens.

### Proof of Concept

Before deciding whether or not to relay an auction result, a bot can call `computeRewards` to calculate how many rewards they'll be getting based on

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-pooltogether)

---

### Example 3: The lower bound for liquidationInitialAsk for new lines needs to be stricter

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `LienToken.sol#L376-L381`
- `AstariaRouter.sol#L516`

## Description
`params.lien.details.liquidationInitialAsk` (`Lnew`) is only compared to `params.amount` (`Anew`) whereas in `_appendStack` `newStack[j].lien.details.liquidationInitialAsk` (`Lj`) is compared to `potentialDebt`. 

`potentialDebt` is the aggregated sum of all potential owed amounts at the end of each position/lien. 

So in `_appendStack` we have:

```
onew + on + ... + oj   Lj
```

Where `oj` is `getOwed(newStack[j], newStack[j].point.end)`, which is the amount for the stack slot plus the potential interest at the end of its term. 

So it would make sense to enforce a stricter inequality for `Lnew`:

```
(1 + r(tend  tnow) / 10^18) Anew = onew  Lnew
```

The big issue regarding the current lower bound is when the borrower only takes one lien and for this lien `liquidationInitialAsk == amount` (or they are close). Then at any point during the lien term (maybe very close to the end), the borrower can atomically self-liquidate and settle the Seaport auction in one transaction. This way the borrower can skip paying any interest (they would need to pay OpenSea fees and potentially royalty fees) and plus they would receive liquidation fees.

## Recommendation
Make sure the following stricter lower bound is used instead:

```
(1 + r(tend  tnow) / 10^18) Anew = onew  Lnew
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: Strategist Interest Rewards will be 10x higher than expected due to incorrect divisor

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## High Risk Report

**Severity:** High Risk  
**Context:** PublicVault.sol#L564  
**Description:**  
`VAULT_FEE` is set as an immutable argument in the construction of new vaults and is intended to be set in basis points. However, when the strategist interest rewards are calculated in `_handleStrategistInterestReward()`, the `VAULT_FEE` is only divided by 1000. The result is that the fee calculated by the function will be 10x higher than expected, and the strategist will be dramatically overpaid.

**Recommendation:**  
```solidity
unchecked {
- uint256 fee = x.mulDivDown(VAULT_FEE(), 1000);
+ uint256 fee = x.mulDivDown(VAULT_FEE(), 10000);
s.strategistUnclaimedShares += convertToShares(fee).safeCastTo88();
}
```

**Astaria:** Resolved based on the following PR 203.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: SponsorVault sponsors full transfer amount in reimburseLiquidityFees()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

**Severity**: High Risk  
**Context**: BridgeFacet.sol#L660-L663  
**Description**: The `BridgeFacet` passes `args.amount` as `_liquidityFee` when calling `reimburseLiquidityFees`. Instead of sponsoring `liquidityFee`, the sponsor vault would sponsor the full transfer amount to the receiver. 

**Note**: Luckily, the amount in `reimburseLiquidityFees` is capped by `relayerFeeCap`.  
```solidity
function _handleExecuteTransaction(...) ... {
    ...
    (bool success, bytes memory data) = address(s.sponsorVault).call(
        abi.encodeWithSelector(s.sponsorVault.reimburseLiquidityFees.selector, _asset, _args.amount, _args.params.to), 
        ! 
    );
}
```

**Recommendation**: Pass `args.amount * (s.LIQUIDITY_FEE_DENOMINATOR - s.LIQUIDITY_FEE_NUMERATOR) / s.LIQUIDITY_FEE_DENOMINATOR` instead.  
**Connext**: Solved in PR 1551.  
**Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 6: Deriving price with balanceOf is dangerous

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`ConnextPriceOracle.sol#L109-L135`

## Description
The function `getPriceFromDex` derives the price by querying the balance of AMMs pools.

```solidity
function getPriceFromDex(address _tokenAddress) public view returns (uint256) {
    PriceInfo storage priceInfo = priceRecords[_tokenAddress];
    ...
    uint256 rawTokenAmount = IERC20Extended(priceInfo.token).balanceOf(priceInfo.lpToken);
    ...
    uint256 rawBaseTokenAmount = IERC20Extended(priceInfo.baseToken).balanceOf(priceInfo.lpToken);
    ...
}
```

Deriving the price with `balanceOf` is dangerous as `balanceOf` may be gamed. Consider Uniswap V2 as an example; exploiters can first send tokens into the pool and pump the price, then absorb the tokens that were previously donated by calling `mint`.

## Recommendation
Consider querying DEXs state through function calls such as Uniswap V2s `getReserves()` which returns the correct state of the pool.

## References
- **Connext**: Solved in PR 1649.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 7: Wrong reserve factor computation on P2P rates

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Audit Report

## Severity
**High Risk**

## Context
`MarketsManagerForAave.sol#L413-L418`

## Description
The reserve factor is taken on the entire P2P supply and borrow rates instead of just on the spread of the pool rates. Its currently overcharging suppliers and borrowers and making it possible to earn a worse rate on Morpho than the pool rates.

```solidity
supplyP2PSPY[_marketAddress] =
(meanSPY * (MAX_BASIS_POINTS - reserveFactor[_marketAddress])) /
MAX_BASIS_POINTS;

borrowP2PSPY[_marketAddress] =
(meanSPY * (MAX_BASIS_POINTS + reserveFactor[_marketAddress])) /
MAX_BASIS_POINTS;
```

## Recommendation
Fix the computation. The real reserve factor should apply only on the spread so youre right that this formula is wrong and needs to be updated: 
`a + (1/2  f)(b-a)` where f is the reserve factor.

## Spearbit
Acknowledged, fixed in PR #565.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 8: MatchingEngineForAave is using the wrong totalSupply in updateBorrowers

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Risk Assessment

## Severity
**Critical Risk**

## Context
`MatchingEngineForAave.sol#L376-L385`

## Description
The `_poolTokenAddress` is referencing `AToken`, so the `totalStaked` would be the total supply of the `AToken`. In this case, the `totalStaked` should reference the total supply of the `DebtToken`; otherwise, the user would be rewarded for a wrong amount of reward.

## Recommendation
Use the correct token address to query `scaledTotalSupply` as follows:

```solidity
address variableDebtTokenAddress = lendingPool
    .getReserveData(IAToken(_poolTokenAddress).UNDERLYING_ASSET_ADDRESS())
    .variableDebtTokenAddress;

uint256 totalStaked = IScaledBalanceToken(variableDebtTokenAddress).scaledTotalSupply();
```

## Spearbit
Fixed; recommendation was implemented in the PR #554.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 9: [H-08] Vault.withdraw mixes normalized and standard amounts

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.balance` function uses the `balanceOfThis` function which scales ("normalizes") all balances to 18 decimals.

```
for (uint8 i; i < _tokens.length; i++) {
    address _token = _tokens[i];
    // everything is padded to 18 decimals
    _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
}
```

Note that `balance()`'s second term `IController(manager.controllers(address(this))).balanceOf()` is not normalized, but it must be.

This leads to many issues through the contracts that use `balance` but don't treat these values as normalized values.
For example, in `Vault.withdraw`, the computed `_amount` value is normalized (in 18 decimals).
But the `uint256 _balance = IERC20(_output).balanceOf(address(this));` value is not normalized but compared to the normalized `_amount` and even subtracted:

```solidity
// @audit compares unnormalzied output to normalized output
if (_balance < _amount) {
    IController _controller = IController(manager.controllers(address(this)));
    // @audit cannot directly subtract unnormalized
    uint256 _toWithdraw = _amount.sub(_balance);
    if (_controller.strategies() > 0) {
        _controller.withdraw(_output, _toWithdraw);
    }
    uint256 _after = IERC20(_output).balanceOf(address(this));
    uint256 _diff = _after.sub(_balance);
    if (_diff < _toWithdraw) {
        _amount = _balance.add(_diff);
    }
}
```

## Impact
Imagine in `withdraw`, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 10: [H-07] Vault.balance() mixes normalized and standard amounts

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.balance` function uses the `balanceOfThis` function which scales ("normalizes") all balances to 18 decimals.

```
for (uint8 i; i < _tokens.length; i++) {
    address _token = _tokens[i];
    // everything is padded to 18 decimals
    _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
}
```

Note that `balance()`'s second term `IController(manager.controllers(address(this))).balanceOf()` is not normalized.
The code is adding a non-normalized amount (for example 6 decimals only for USDC) to a normalized (18 decimals).

## Impact
The result is that the `balance()` will be under-reported.
This leads to receiving wrong shares when `deposit`ing tokens, and a wrong amount when redeeming `tokens`.

## Recommended Mitigation Steps
The second term `IController(manager.controllers(address(this))).balanceOf()` must also be normalized before adding it.
`IController(manager.controllers(address(this))).balanceOf()` uses `_vaultDetails[msg.sender].balance` which directly uses the raw token amounts which are not normalized.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 11: [H-02] `newLeverage` wrongly calculated inside `requestIncreasePositionSize`

**Source**: Pashov Audit Group
**Protocol**: Gainsnetwork May
**Impact**: HIGH

**Details**:

**Severity**

**Impact:** High

**Likelihood:** Medium

**Description**

When users call `increasePositionSize` and request an increase in position size, it will eventually trigger `IncreasePositionSizeUtils.validateRequest` to validate the request. However, when calculating `newLeverage`, it incorrectly calculates `(existingPositionSizeCollateral + positionSizeCollateralDelta * 1e3) / newCollateralAmount` instead of `(existingPositionSizeCollateral + positionSizeCollateralDelta) * 1e3 / newCollateralAmount`, causing the `newLeverage` to be lower than it should be.

```solidity
    function validateRequest(
        ITradingStorage.Trade memory _trade,
        IUpdatePositionSizeUtils.IncreasePositionSizeInput memory _input
    ) internal view returns (uint256 positionSizeCollateralDelta) {
        // ....
        uint256 newCollateralAmount = _trade.collateralAmount + _input.collateralDelta;
        uint256 newLeverage = isLeverageUpdate
            ? _trade.leverage + _input.leverageDelta
>>>         : (existingPositionSizeCollateral + positionSizeCollateralDelta * 1e3) / newCollateralAmount;
        {
            uint256 borrowingFeeCollateral = TradingCommonUtils.getTradeBorrowingFeeCollateral(_trade);
            uint256 openingFeesCollateral = ((_getMultiCollatDiamond().pairOpenFeeP(_trade.pairIndex) *
                2 +
                _getMultiCollatDiamond().pairTriggerOrderFeeP(_trade.pairIndex)) *
                TradingCommonUtils.getPositionSizeCollateralBasis(
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GainsNetwork-security-review-May.md)

---

### Example 12: Wrong maths in getNonSlashRate

**Source**: Hans
**Protocol**: Meta
**Impact**: HIGH

**Details**:

**Severity:** High

**Context:** [`MetaManager.sol#L102-L107`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/MetaManager.sol#L102-L107)

**Description:**
The purpose of the `MetaManager::getNonSlashRate` function is to calculate and return the percentage of the deposit that will be redeemed for a given `timeInDays` period. The intended range for the non-slash rate is between 50% and 100%.

However, there is an error in the calculation at line 105. The math is incorrect, and the slope should be in the denominator instead of the numerator.

```solidity
function getNonSlashRate(uint8 timeInDays) internal view returns (uint8) {
uint256 minDays = minExitCycle / Constants.ONE_DAY;
uint256 slope = ((maxExitCycle - minExitCycle) * Constants.PINT) / (50 * Constants.ONE_DAY);
uint256 result = 50 + ((timeInDays - minDays) * slope) / Constants.PINT;//@audit it should be divided by slope and multipled by PINT
return uint8(result) ;
}
```

**Impact**
The incorrect calculation in the original code can result in users being slashed the wrong amount when unstaking, leading to a loss of assets.

**Recommendation:**

```diff
function getNonSlashRate(uint8 timeInDays) internal view returns (uint8) {
uint256 minDays = minExitCycle / Constants.ONE_DAY;
uint256 slope = ((maxExitCycle - minExitCycle) * Constants.PINT) / (50 * Constants.ONE_DAY);
-    uint256 result = 50 + ((timeInDays - minDays) * slope) / Constants.PINT;
+    uint256 result = 50

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 13: TRST-H-1 Incorrect implementation of getProfitSharingE18() greatly reduces Lender's yield

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
`ProfitSharingModel.getProfitSharingE18()` calculates the share of profit that Lender gets 
based on the APR of the position. According to the formula, the higher the APR, the lower 
the share of profit the Lender gets, but due to the wrong implementation of the 
`getProfitSharingE18()` function, if the APR is smaller than **MAX_ANNUALIZED_YEILD**, the 
base share of 25% is returned, actually 25% should be returned when the APR is larger than 
**MAX_ANNUALIZED_YEILD**.
Considering an APR of 5%, Lender's share of the profit should be 77%, while 
getProfitSharingE18() returns 25%, which greatly reduces Lender's share of the profit.

**Recommended Mitigation:**
Modify `getProfitSharingE18()` as follows 
```solidity
            - if (_annualizedYieldE18 < MAX_ANNUALIZED_YEILD) {
            + if (_annualizedYieldE18 >= MAX_ANNUALIZED_YEILD) { 
            return 0.25e18;
            }
```

**Team response:**
Fixed

**Mitigation Review:**
The team has fixed it as recommended to make the logic correct

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 14: [H-04] Users may be liquidated right after taking maximal debt

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

<https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L471>

<https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L317>

### Impact

Since there's no gap between the maximal LTV and the liquidation LTV, user positions may be liquidated as soon as maximal debt is taken, without leaving room for collateral and Papr token prices fluctuations. Users have no chance to add more collateral or reduce debt before being liquidated. This may eventually create more uncovered and bad debt for the protocol.

### Proof of Concept

The protocol allows users to take debt up to the maximal debt, including it ([PaprController.sol#L471](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L471)):

```solidity
if (newDebt > max) revert IPaprController.ExceedsMaxDebt(newDebt, max);
```

However, a position becomes liquidable as soon as user's debt reaches user's maximal debt ([PaprController.sol#L317](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L317)):

```solidity
if (info.debt < _maxDebt(oraclePrice * info.count, cachedTarget)) {
    revert IPaprController.NotLiquidatable();
}
```

Moreover, the same maximal debt calculation is used during borrowing and liquidating, with the same maximal LTV ([PaprController.sol#L556-L559](https://github.com/with-backed/papr/blob/9528f2711ff0c15220

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 15: Wrong P2P exchange rate calculation

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**Critical Risk**

## Context
MarketsManagerForAave.sol#L436

## Description
`_p2pDelta` is divided by `_poolIndex` and multiplied by `_p2pRate`, nevertheless it should have been multiplied by `_poolIndex` and divided by `_p2pRate` to compute the correct share of the delta. This leads to wrong P2P rates throughout all markets if supply/borrow delta is involved.

## Recommendation
Change order and adjust return values accordingly.

```solidity
uint256 shareOfTheDelta = _p2pDelta
  .wadToRay()
  - .rayMul(_p2pRate)
  - .rayDiv(_poolIndex)
  + .rayMul(_poolIndex)
  + .rayDiv(_p2pRate)
  .rayDiv(_p2pAmount.wadToRay());
```

## Morpho
Fixed in PR #536, `_computeNewP2PExchangeRate` is changed as recommended.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 16: [H-02] Wrong token allocation computation for token decimals != 18 if floor price not reached

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

In `LaunchEvent.createPair`, when the floor price is not reached (`floorPrice > wavaxReserve * 1e18 / tokenAllocated`), the tokens to be sent to the pool are lowered to match the raised WAVAX at the floor price.

Note that the `floorPrice` is supposed to have a precision of 18:

> /// @param \_floorPrice Price of each token in AVAX, scaled to 1e18

The `floorPrice > (wavaxReserve * 1e18) / tokenAllocated` check is correct but the `tokenAllocated` computation involves the `token` decimals:

```solidity
// @audit should be wavaxReserve * 1e18 / floorPrice
tokenAllocated = (wavaxReserve * 10**token.decimals()) / floorPrice;
```

This computation does not work for `token`s that don't have 18 decimals.

#### Example

Assume I want to sell `1.0 wBTC = 1e8 wBTC` (8 decimals) at `2,000.0 AVAX = 2,000 * 1e18 AVAX`.
The `floorPrice` is `2000e18 * 1e18 / 1e8 = 2e31`

Assume the Launch event only raised `1,000.0 AVAX` - half of the floor price for the issued token amount of `1.0 WBTC` (it should therefore allocate only half a WBTC) - and the token amount will be reduced as: `floorPrice = 2e31 > 1000e18 * 1e18 / 1e8 = 1e31 = actualPrice`.
Then, `tokenAllocated = 1000e18 * 1e8 / 2e31 = 1e29 / 2e31 = 0` and no tokens would be allocated, instead of `0.5 WBTC = 0.5e8 WBTC`.

The computation should be `tokenAllocated = wavaxReserve * 1e18 / floorPrice = 1000e18 * 1e18 / 2e31 = 1e39 / 2e31 = 10e38 / 2e31 = 5e7 = 0.5e8`.

#### Recommendation

The new `tokenAllocated` comp

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-trader-joe)

---

### Example 17: [H-10] An attacker can steal funds from multi-token vaults

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

WatchPug


## Vulnerability details

The total balance should NOT be simply added from different tokens' tokenAmounts, considering that the price of tokens may not be the same.

https://github.com/code-423n4/2021-09-yaxis/blob/cf7d9448e70b5c1163a1773adb4709d9d6ad6c99/contracts/v3/Vault.sol#L324

```solidity=316
function balanceOfThis()
    public
    view
    returns (uint256 _balance)
{
    address[] memory _tokens = manager.getTokens(address(this));
    for (uint8 i; i < _tokens.length; i++) {
        address _token = _tokens[i];
        _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
    }
}
```

https://github.com/code-423n4/2021-09-yaxis/blob/cf7d9448e70b5c1163a1773adb4709d9d6ad6c99/contracts/v3/controllers/Controller.sol#L396

```solidity=381
function harvestStrategy(
    address _strategy,
    uint256 _estimatedWETH,
    uint256 _estimatedYAXIS
)
    external
    override
    notHalted
    onlyHarvester
    onlyStrategy(_strategy)
{
    uint256 _before = IStrategy(_strategy).balanceOf();
    IStrategy(_strategy).harvest(_estimatedWETH, _estimatedYAXIS);
    uint256 _after = IStrategy(_strategy).balanceOf();
    address _vault = _vaultStrategies[_strategy];
    _vaultDetails[_vault].balance = _vaultDetails[_vault].balance.add(_after.sub(_before));
    _vaultDetails[_vault].balances[_strategy] = _after;
    emit Harvest(_strategy);
}
```

https://github.com/code-423n4/2021-09-yaxis/blob/cf7d9448e70b5c1163a1773adb47

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 18: [H-01] Controller.setCap sets wrong vault balance

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Controller.setCap` function sets a cap for a strategy and withdraws any excess amounts (`_diff`).
The vault balance is decreased by the entire strategy balance instead of by this `_diff`:

```
// @audit why not sub _diff?
_vaultDetails[_vault].balance = _vaultDetails[_vault].balance.sub(_balance);
```

## Impact
The `_vaultDetails[_vault].balance` variable does not correctly track the actual vault balances anymore, it will usually **underestimate** the vault balance.
This variable is used in `Controller.balanceOf()`, which in turn is used in `Vault.balance()`, which in turn is used to determine how many shares to mint / amount to receive when redeeming shares.
If the value is less, users will lose money as they can redeem fewer tokens.
Also, an attacker can `deposit` and will receive more shares than they should receive. They can then wait until the balance is correctly updated again and withdraw their shares for a higher amount than they deposited. This leads to the vault losing tokens.

## Recommended Mitigation Steps
Sub the `_diff` instead of the `balance`: `_vaultDetails[_vault].balance = _vaultDetails[_vault].balance.sub(_diff);`

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 19: [H-01] veCVXStrategy.manualRebalance has wrong logic

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

## Vulnerability Details
The `veCVXStrategy.manualRebalance` function computes two ratios `currentLockRatio` and `newLockRatio` and compares them.

However, these ratios compute different things and are not comparable:
- `currentLockRatio = balanceInLock.mul(10**18).div(totalCVXBalance)` is a **percentage value** with 18 decimals (i.e. `1e18 = 100%`). Its max value can at most be `1e18`.
- `newLockRatio = totalCVXBalance.mul(toLock).div(MAX_BPS)` is a **CVX token amount**. It's unbounded and just depends on the `totalCVXBalance` amount.

The comparison that follows does not make sense:

```solidity
if (newLockRatio <= currentLockRatio) {
  // ...
}
```

## Impact
The rebalancing is broken and does not correctly rebalance.
It usually leads to locking nearly everything if `totalCVXBalance` is high.

## Recommended Mitigation Steps
Judging from the `cvxToLock = newLockRatio.sub(currentLockRatio)` it seems the desired computation is that the "ratios" should actually be in CVX amounts and not in percentages. Therefore, `currentLockRatio` should just be `balanceInLock`. (The variables should be renamed as they aren't really ratios but absolute CVX balance amounts.)

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-bvecvx)

---

### Example 20: [H-01] Reward computation is wrong

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The `LendingPair.accrueAccount` function distributes rewards **before** updating the cumulative supply / borrow indexes as well as the index + balance for the user (by minting supply tokens / debt).
This means the percentage of the user's balance to the total is not correct as the total can be updated several times in between.

```solidity
function accrueAccount(address _account) public {
  // distributes before updating accrual state
  _distributeReward(_account);
  accrue();
  _accrueAccountInterest(_account);

  if (_account != feeRecipient()) {
    _accrueAccountInterest(feeRecipient());
  }
}
```

**Example**: Two users deposit the same amounts in the same block. Thus, after some time they should receive the same tokens.
1. User A and B deposit 1000 tokens (in the same block) and are minted 1000 tokens in return. Total supply = `2000`
2. Assume after 50,000 blocks, `A` calls `accrueAccount(A)` which first calls `_distributeReward`. A is paid out 1000/2000 = 50% of the 50,000 blocks reward since deposit. Afterwards, `accrue` + `_accrueAccountInterest(A)` is called and `A` is minted 200 more tokens due to supplier lending rate. The supply **totalSupply is now 2200**.
3. After another 50,000 blocks, `A` calls `accrueAccount(A)` again. which first calls `_distributeReward`. A is paid out 1200/2200 = **54.5454% of the 50,000 blocks reward since deposit.**

From here, you can already see that `A` receives more than 50% of the 100,000 block rewards altho

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-wildcredit)

---

### Example 21: [H-18] Old stakers can steal deposits of new stakers in StakingFundsVault

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L75
https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L123
https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L63


## Vulnerability details

## Impact
Stakers to the MEV+fees vault can steal funds from the new stakers who staked after a validator was registered and the derivatives were minted. A single staker who staked 4 ETH can steal all funds deposited by new stakers.
## Proof of Concept
`StakingFundsVault` is designed to pull rewards from a Syndicate contract and distributed them pro-rata among LP token holders ([StakingFundsVault.sol#L215-L231](https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L215-L231)):
```solidity
if (i == 0 && !Syndicate(payable(liquidStakingNetworkManager.syndicate())).isNoLongerPartOfSyndicate(_blsPubKeys[i])) {
    // Withdraw any ETH accrued on free floating SLOT from syndicate to this contract
    // If a partial list of BLS keys that have free floating staked are supplied, then partial funds accrued will be fetched
    _claimFundsFromSyndicateForDistribution(
        liquidStakingNetworkManager.syndicate(),
        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 22: [H-03] Outstanding reserved tokens are incorrectly counted in total redemption weight

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

The amounts redeemed in overflow redemption can be calculated incorrectly due to incorrect accounting of the outstanding number of reserved tokens.

### Proof of Concept

Project contributors are allowed to redeem their NFT tokens for a portion of the overflow (excessive funded amounts). The amount a contributor receives is calculated as [overflow &ast; (user's redemption rate / total redemption weight)](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/abstract/JB721Delegate.sol#L135-L142), where user's redemption weight is [the total contribution floor of all their NFTs](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L532-L539) and total redemption weight is [the total contribution floor of all minted NFTs](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L563-L566). Since the total redemption weight is the sum of individual contributor redemption weights, the amount they can redeem is proportional to their contribution.

However, the total redemption weight calculation incorrectly accounts outstanding reserved tokens ([JBTiered721DelegateStore.sol#L563-L566](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L563-L566)):

```solidity
// Add the tier's contribution 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 23: [H-04] Wrong calculation in function LBRouter._getAmountsIn make user lose a lot of tokens when swap through JoePair (most of them will gifted to JoePair freely)

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBRouter.sol#L725


## Vulnerability details


## Vulnerable detail 
Function `LBRouter._getAmountsIn` is a helper function to return the amounts in with given `amountOut`. This function will check the pair of `_token` and `_tokenNext` is `JoePair` or `LBPair` using `_binStep`.
* If `_binStep == 0`, it will be a `JoePair` otherwise it will be an `LBPair`.
```solidity=
if (_binStep == 0) {
    (uint256 _reserveIn, uint256 _reserveOut, ) = IJoePair(_pair).getReserves();
    if (_token > _tokenPath[i]) {
        (_reserveIn, _reserveOut) = (_reserveOut, _reserveIn);
    }


    uint256 amountOut_ = amountsIn[i];
    // Legacy uniswap way of rounding
    amountsIn[i - 1] = (_reserveIn * amountOut_ * 1_000) / (_reserveOut - amountOut_ * 997) + 1;
} else {
    (amountsIn[i - 1], ) = getSwapIn(ILBPair(_pair), amountsIn[i], ILBPair(_pair).tokenX() == _token);
}
```
As we can see when `_binStep == 0` and `_token < _tokenPath[i]` (in another word  we swap through `JoePair` and pair's`token0` is `_token` and `token1` is `_tokenPath[i]`), it will 
1. Get the reserve of pair (`reserveIn`, `reserveOut`) 
2. Calculate the `_amountIn` by using the formula 
```
amountsIn[i - 1] = (_reserveIn * amountOut_ * 1_000) / (_reserveOut - amountOut_ * 997) + 1
```

But unfortunately the denominator `_reserveOut - amountOut_ * 997` seem incorrect. It should be `(_reserveOut - amountOut_) 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 24: [H-02] Incorrect output amount calculation for Trader Joe V1 pools

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L891><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L896><br>

Output amount is calculated incorrectly for a Trader Joe V1 pool when swapping tokens across multiple pools and some of the pools in the chain are V1 ones. Calculated amounts will always be smaller than expected ones, which will always affect chained swaps that include V1 pools.

### Proof of Concept

[LBRouter](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L21) is a high-level contract that serves as the main contract users will interact with. The contract implements a lot of security checks and helper functions that make usage of LBPair contracts easier and more user-friendly. Some examples of such functions:

*   [swapExactTokensForTokensSupportingFeeOnTransferTokens](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L531), which makes chained swaps (i.e. swaps between tokens that don't have a pair) of tokens implementing fee on transfer (i.e. there's fee reduced from every transferred amount);
*   [swapExactTokensForAVAXSupportingFeeOnTransferTokens](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L561), which is the variation of the above function which takes AVAX as the output token;
*   [swapExactAVAXForTokensSupportingFeeOnTransferTokens](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L594),

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 25: [H-01] StandardPolicyERC1155.sol returns amount == 1 instead of amount == order.amount

**Source**: Code4rena
**Protocol**: Blur Exchange
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-blur/blob/main/contracts/matchingPolicies/StandardPolicyERC1155.sol#L12-L36
https://github.com/code-423n4/2022-10-blur/blob/main/contracts/BlurExchange.sol#L154-L161


## Vulnerability details

## Impact

The ```canMatchMakerAsk``` and ```canMatchMakerBid``` functions in ```StandardPolicyERC1155.sol``` will only return 1 as the amount instead of the order.amount value. This value is then used in the ```_executeTokenTransfer``` call during the execution flow and leads to only 1 ERC1155 token being sent. A buyer matching an ERC1155 order wih amount > 1 would expect to receive amount of tokens if they pay the order's price. The seller, who might also expect more than 1 tokens to be sent, would have set the order's price to be for the amount of tokens and not just for 1 token.

The buyer would lose overspent ETH/WETH to the seller without receiving all tokens as specified in the order.

## Proof of Concept

[StandardPolicyERC1155.sol:canMatchMakerAsk](https://github.com/code-423n4/2022-10-blur/blob/main/contracts/matchingPolicies/StandardPolicyERC1155.sol#L12-L36)

```solidity
    function canMatchMakerAsk(Order calldata makerAsk, Order calldata takerBid)
        external
        pure
        override
        returns (
            bool,
            uint256,
            uint256,
            uint256,
            AssetType
        )
    {
        return (
            (makerAsk.side != takerBid.side) &&
            (makerAsk.pay

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-blur)

---

## Statistics

- Total findings analyzed: 107
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## 1-64-rule-patterns.md
# 1/64 Rule Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 2 | 0 |

**Common Sources**: TrailOfBits, Shieldify, MixBytes, Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for 1/64 rule vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-08] Gas limit check is inaccurate, leading to an operator being able to fail a job intentionally

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L316](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L316)<br>

There's a check at line 316 that verifies that there's enough gas left to execute the `HolographBridge.bridgeInRequest()` with the `gasLimit` set by the user, however the actual amount of gas left during the call is less than that (mainly due to the `1/64` rule, see below).<br>
An attacker can use that gap to fail the job while still having the `executeJob()` function complete.

### Impact

The owner of the bridged token would loose access to the token since the job failed.

### Proof of Concept

Besides using a few units of gas between the check and the actual call, there's also a rule that only 63/64 of the remaining gas would be dedicated to an (external) function call. Since there are 2 external function calls done (`nonRevertingBridgeCall()` and the actual call to the bridge) `~2/64` of the gas isn't sent to the bridge call and can be used after the bridge call runs out of gas.

The following PoC shows that if the amount of gas left before the call is at least 1 million then the execution can continue after the bridge call fails:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ContractTest is Test {
    event FailedOperatorJob(bytes32 jobHash);
    uint256 private _inboundMessageCounter;
    mapping(bytes32 => bool) private _failedJobs;
    constr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: Withdrawal queue can be forcibly activated to hinder bridge operation

**Source**: TrailOfBits
**Protocol**: Immutable Smart Contracts
**Impact**: MEDIUM

**Details**:

## Target: RootERC20PredicateFlowRate.sol

## Description

The withdrawal queue can be forcibly activated to impede the proper operation of the bridge.

The `RootERC20PredicateFlowRate` contract implements a withdrawal queue to more easily detect and stop large withdrawals from passing through the bridge (e.g., bridging illegitimate funds from an exploit). A transaction can enter the withdrawal queue in four ways:

1. If a tokens flow rate has not been configured by the rate control admin.
2. If the withdrawal amount is larger than or equal to the large transfer threshold for that token.
3. If, during a predefined period, the total withdrawals of that token are larger than the defined token capacity.
4. If the rate controller manually activates the withdrawal queue by using the `activateWithdrawalQueue` function.

In cases 3 and 4 above, the withdrawal queue becomes active for all tokens, not just the individual transfers. Once the withdrawal queue is active, all withdrawals from the bridge must wait a specified time before the withdrawal can be finalized. As a result, a malicious actor could withdraw a large amount of tokens to forcibly activate the withdrawal queue and hinder the expected operation of the bridge.

## Exploit Scenario 1

Eve observes Alice initiating a transfer to bridge her tokens back to the mainnet. Eve also initiates a transfer, or a series of transfers to avoid exceeding the per-transaction limit, of sufficient tokens to exceed the expected flow rate. 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-08-immutable-securityreview.pdf)

---

### Example 3: Insecure storage of session data in local storage

**Source**: TrailOfBits
**Protocol**: WalletConnect v2.0 SDK
**Impact**: MEDIUM

**Details**:

## Target: Browser storage

## Description
HTML5 local storage is used to hold session data, including keychain values. Because there are no access controls on modifying and retrieving this data using JavaScript, data in local storage is vulnerable to XSS attacks.

**Figure 4.1:** Keychain data stored in a browsers localStorage

## Exploit Scenario
Alice discovers an XSS vulnerability in a dApp that supports WalletConnect. This vulnerability allows Alice to retrieve the dApps keychain data, allowing her to propose new transactions to the connected wallet.

## Recommendations
Short term, consider using cookies to store and send tokens. Enable cross-site request forgery (CSRF) libraries available to mitigate these attacks. Ensure that cookies are tagged with `httpOnly`, and preferably `secure`, to ensure that JavaScript cannot access them.

## References
- OWASP HTML5 Security Cheat Sheet: Local Storage

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-03-walletconnectv2-securityreview.pdf)

---

### Example 4: [L-08] No Way to Recover Locked Tokens in the Vault

**Source**: Shieldify
**Protocol**: Pudgystrategy
**Impact**: LOW

**Details**:

## Severity

Low Risk

## Description

The vault lacks a mechanism to recover arbitrary ERC-20 tokens accidentally sent to it. Over time, stray tokens may become irrecoverable. For example the vault expects ETH and later swaps `ETH`->`HEROSTR`. If a sale is settled in WETH (very common) and the marketplace transfers WETH (ERC-20) to the vault, it just sits there. The contract has no WETH unwrap and no generic ERC-20 withdrawal.

## Location of Affected Code

File: [NFTVault%20Final.sol](https://github.com/0xcaptainy/HEROSTR/blob/cafe69ed029aef74e874471b157afabfacb0d81c/NFTVault%20Final.sol)

## Impact

Locked tokens

## Recommendation

Add a simple, restricted rescue function:

```solidity
function rescueTokens(address token, uint256 amount, address to) external onlyController nonReentrant {
    require(token != HEROSTR, "cannot rescue HEROSTR");
    IERC20(token).transfer(to, amount);
}
```

## Team Response

**Status: FIXED**

While the vault's normal operation only involves ETH and OCH NFTs, we have implemented a basic token recovery function for edge cases where tokens might get accidentally sent to the vault (such as WETH from marketplace settlements).

**Implementation:**

```solidity
function rescueTokens(address token, uint256 amount, address to) external onlyController nonReentrant {
    require(token != HEROSTR, "cannot rescue HEROSTR");
    IERC20(token).transfer(to, amount);
}
```

## [I-01] Enforse Constraints for `swapThreshold` and `maxSwapAmount` in `setSwapBe

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/PudgyStrategy-Security-Review.md)

---

### Example 5: Remove unnecessary ETH handling logic for maker asset

**Source**: MixBytes
**Protocol**: Barter DAO
**Impact**: LOW

**Details**:

##### Description
In the [`callExecutor()`](https://github.com/BarterLab/argon/blob/f653d58132124854db42d2bd93d0c6b91da2c398/contracts/InchFusionBarterResolver.sol#L93-L123) function, there's logic that checks if the maker asset is ETH and skips token transfer:

```solidity
if (makerAsset.get() != address(0) && 
    makerAsset.get() != address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)
   ) {
    IERC20(makerAsset.get()).safeTransfer(address(executor), makingAmount);
}
```

This logic appears to be leftover code from UniswapX solver implementation and is not needed in the context of 1inch Fusion orders.
<br/>
##### Recommendation
We recommend removing unnecessary logic.

---

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Barter%20DAO/InchFusionBarterResolver/README.md#3-remove-unnecessary-eth-handling-logic-for-maker-asset)

---

### Example 6: M-19: Gas Manipulation by Malicious Winners in claimPrizes Function

**Source**: Sherlock
**Protocol**: PoolTogether: The Prize Layer for DeFi
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-05-pooltogether-judging/issues/163 

## Found by 
0x73696d616f, 0xSpearmint1, MiloTruck, infect3d, jo13
## Summary

A malicious winner can exploit the `claimPrizes` function in the `Claimer` contract by reverting the transaction through returning a huge data chunk. This manipulation can cause the transaction to run out of gas, preventing legitimate claims and allowing the malicious user to claim prizes without computing winners.

## Vulnerability Detail

- The `Claimer` contract allows users to claim prizes on behalf of others by calling the `claimPrizes` function.
- A malicious winner can exploit this function by returning a huge data chunk when called, causing the transaction's gas to be too high and revert.
- Although the function catches the revert, the remaining gas (63/64 of the original gas) is likely insufficient for the rest of the claims.
- The malicious winner can then replay the transaction to claim the fees from the first claimer's computation without needing to compute the winners themselves.

## Impact

- Legitimate claimers may lose gas fees due to transaction reverts caused by malicious winners.
- Malicious winners can exploit this to claim prizes without computing winners, undermining the fairness of the prize distribution.

## Recommendation

- Implement a gas limit check to ensure that sufficient gas remains for the rest of the claims after catching a revert.
- Consider adding a mechanism to penalize or blackl

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


