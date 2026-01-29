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
