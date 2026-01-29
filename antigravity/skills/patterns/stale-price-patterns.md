# Stale Price Security Patterns

## Overview

**Frequency**: 31 occurrences (0.06% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 24 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Hans, ZachObront

---

## Detection Checklist

- [ ] Check for stale price vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-3: Usage of `slot0` is extremely easy to manipulate

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/97 

## Found by 
BugBusters, Jaraxxus, ash, bitsurfer, kutugu, ni8mare, rogue-lion-0619, sashik\_eth, shealtielanz, stopthecap, toshii, tsvetanovv
## Summary
Usage of `slot0` is extremely easy to manipulate 

## Vulnerability Detail
Real Wagmi is using  `slot0` to calculate several variables in their codebase:

https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator/contracts/Multipool.sol#L589-L596

  [slot0](https://docs.uniswap.org/contracts/v3/reference/core/interfaces/pool/IUniswapV3PoolState#slot0) is the most recent data point and is therefore extremely easy to manipulate.

Multipool directly uses the token values returned by `getAmountsForLiquidity` 

```@solidity
 (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
                slots[i].currentSqrtRatioX96,
                TickMath.getSqrtRatioAtTick(position.lowerTick),
                TickMath.getSqrtRatioAtTick(position.upperTick),
                liquidity
            );
```

to calculate the reserves. 

```@solidity
 reserve0 += amount0;
 reserve1 += amount1;
```
Which they are used to calculate the `lpAmount` to mint from the pool. This allows a malicious user to manipulate the amount of the minted by a user.
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator/contracts/Multipool.sol#L483

https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator

*[Content truncated...]*

---

### Example 2: [H-02] Use of `slot0` to get `sqrtPriceLimitX96` can lead to price manipulation.

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: HIGH

**Details**:

In `RootBrigdeAgent.sol`, the functions `_gasSwapOut` and `_gasSwapIn` use `UniswapV3.slot0` to get the value of `sqrtPriceX96`, which is used to perform the swap. However, the `sqrtPriceX96` is pulled from `Uniswap.slot0`, which is the most recent data point and can be manipulated easily via `MEV` bots and `Flashloans` with sandwich attacks; which can cause the loss of funds when interacting with the `Uniswap.swap` function.

### Proof of Concept

You can see the `_gasSwapIn` function in `RootBrigdeAgent.sol` [here](https://github.com/code-423n4/2023-05-maia/blob/cfed0dfa3bebdac0993b1b42239b4944eb0b196c/src/ulysses-omnichain/RootBridgeAgent.sol#L674C1-L689C75):

```solidity

     //Get sqrtPriceX96
        (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(poolAddress).slot0();

        // Calculate Price limit depending on pre-set price impact
        uint160 exactSqrtPriceImpact = (sqrtPriceX96 * (priceImpactPercentage / 2)) / GLOBAL_DIVISIONER;

        //Get limit
        uint160 sqrtPriceLimitX96 =
            zeroForOneOnInflow ? sqrtPriceX96 - exactSqrtPriceImpact : sqrtPriceX96 + exactSqrtPriceImpact;

        //Swap imbalanced token as long as we haven't used the entire amountSpecified and haven't reached the price limit
        try IUniswapV3Pool(poolAddress).swap(
            address(this),
            zeroForOneOnInflow,
            int256(_amount),
            sqrtPriceLimitX96,
            abi.encode(SwapCallbackData({tokenIn: gasTokenGlobalAddress}))
```

You can a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 3: [M-24] Chainlink price feed is not sufficiently validated and can return stale price

**Source**: Code4rena
**Protocol**: Tigris Trade
**Impact**: MEDIUM

**Details**:

As mentioned by <https://docs.tigris.trade/protocol/oracle>, "Prices provided by the oracle network are also compared to Chainlink's public price feeds for additional security. If prices have more than a 2% difference the transaction is reverted." The Chainlink price verification logic in the following `TradingLibrary.verifyPrice` function serves this purpose. However, besides that `IPrice(_chainlinkFeed).latestAnswer()` uses Chainlink's deprecated `latestAnswer` function, this function also does not guarantee that the price returned by the Chainlink price feed is not stale. When `assetChainlinkPriceInt != 0` is `true`, it is still possible that `assetChainlinkPriceInt` is stale in which the Chainlink price verification would compare the off-chain price against a stale price returned by the Chainlink price feed. For a off-chain price that has more than a 2% difference when comparing to a more current price returned by the Chainlink price feed, this off-chain price can be incorrectly considered to have less than a 2% difference when comparing to a stale price returned by the Chainlink price feed. As a result, a trading transaction that should revert can go through, which makes the price verification much less secure.

<https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/utils/TradingLibrary.sol#L91-L122>

```solidity
    function verifyPrice(
        uint256 _validSignatureTimer,
        uint256 _asset,
        bool _chainlinkEnabled,
        address _chainlinkFee

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-tigris)

---

### Example 4: Missing checks for Chainlink oracle

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- ConnextPriceOracle.sol#L98
- ConnextPriceOracle.sol#L153

## Description
The `ConnextPriceOracle.getTokenPrice()` function goes through a series of oracles. At each step, it has a few validations to avoid incorrect prices. If such validations succeed, the function returns the non-zero oracle price. 

For the Chainlink oracle, `getTokenPrice()` ultimately calls `getPriceFromChainlink()`, which has the following validation:

```solidity
if (answer == 0 || answeredInRound < roundId || updateAt == 0) {
    // answeredInRound > roundId ===> ChainLink Error: Stale price
    // updatedAt = 0 ===> ChainLink Error: Round not complete
    return 0;
}
```

`updateAt` refers to the timestamp of the round. This value isn’t checked to ensure it is recent. Additionally, it is important to be aware of the `minAnswer` and `maxAnswer` of the Chainlink oracle; these values are not allowed to be reached or surpassed. See the Chainlink API reference for documentation on `minAnswer` and `maxAnswer`, as well as this piece of code: `OffchainAggregator.sol`.

## Recommendation
- Determine the tolerance threshold for `updateAt`. If `block.timestamp - updateAt` exceeds that threshold, return 0, which is consistent with how the current validations are handled.
- Consider having off-chain monitoring to identify when the market price moves out of `[minAnswer, maxAnswer]` range.

## Connext
Recency check is implemented in PR 1602. Off-chain monitoring will be consider

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 5: Chainlink price is used without checking validity

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`Helper.sol#L75-L78`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/Helper.sol#L75-L78)

**Description:**
The Meta protocol relies on a Chainlink price oracle to calculate the excess income distributed to all mUSD holders.
However, the current implementation lacks checks for the staleness of the price obtained from Chainlink.

```solidity
function getPriceOfRewardToken() external view returns (uint256) {
(,int256 price,,,) = priceFeed.latestRoundData();//@audit chainlink price feed - stale price check is missing
return (uint256(price) * Constants.PINT) / PRICE_FEED_PRECISION;
}
```

This omission can lead to issues if Chainlink starts a new round and struggles to establish consensus on the new value for the oracle. Without proper checks, consumers of this contract may continue using outdated, stale, or incorrect data if oracles are unable to submit and start a new round. Possible reasons for this could include Chainlink nodes abandoning the oracle, chain congestion, or vulnerabilities/attacks on the Chainlink system.

Additionally, it is important to check if the Arbitrum sequencer is active.
Please refer to the issue at https://github.com/sherlock-audit/2022-11-sentiment-judging/issues/3 for more information.

**Impact**
This vulnerability is classified as MEDIUM because it affects user assets only when the Chainlink oracle is in bad status.

**Recommendation:**
To address this issue, i

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 6: [M-17] Chainlink oracle data feed is not sufficiently validated and can return stale price

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L78-L105
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L112-L144
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L344-L347
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L323-L327
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L353-L363


## Vulnerability details

## Impact
Calling the `Oracle` contract's `viewPrice` or `getPrice` function executes `uint price = feeds[token].feed.latestAnswer()` and `require(price > 0, "Invalid feed price")`. Besides that Chainlink's `latestAnswer` function is deprecated, only verifying that `price > 0` is true is also not enough to guarantee that the returned `price` is not stale. Using a stale `price` can cause the calculations for the credit and withdrawal limits to be inaccurate, which, for example, can mistakenly consider a user's debt to be under water and unexpectedly allow the user's debt to be liquidated.

To avoid using a stale answer returned by the Chainlink oracle data feed, according to [Chainlink's documentation](https://docs.chain.link/docs/historical-price-data):
1. The `latestRoundData` function can be used instead of the deprecated `latestAnswer` function.
2. `roundId` and `answeredInRound` are also returned. "You can check `answeredInRound` against the current `roundId`. If `answeredInRound` is less than `roundId`, the answer is being carrie

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 7: [M-01] Oracle data feed is insufficiently validated

**Source**: Code4rena
**Protocol**: Yield
**Impact**: MEDIUM

**Details**:

_Submitted by throttle, also found by 0x1f8b, cccz, defsec, hack3r-0m, hyh, kenzo, leastwood, sirhashalot, TomFrenchBlockchain, WatchPug, and ye0lde_

Price can be stale and can lead to wrong `quoteAmount` return value

#### Proof of Concept

Oracle data feed is insufficiently validated. There is no check for stale price and round completeness.
Price can be stale and can lead to wrong `quoteAmount` return value

```javascript
function _peek(
    bytes6 base,
    bytes6 quote,
    uint256 baseAmount
) private view returns (uint256 quoteAmount, uint256 updateTime) {
    ...

    (, int256 daiPrice, , , ) = DAI.latestRoundData();
    (, int256 usdcPrice, , , ) = USDC.latestRoundData();
    (, int256 usdtPrice, , , ) = USDT.latestRoundData();

    require(
        daiPrice > 0 && usdcPrice > 0 && usdtPrice > 0,
        "Chainlink pricefeed reporting 0"
    );

    ...
}
```

#### Recommended Mitigation Steps

Validate data feed

```javascript
function _peek(
    bytes6 base,
    bytes6 quote,
    uint256 baseAmount
) private view returns (uint256 quoteAmount, uint256 updateTime) {
    ...
    (uint80 roundID, int256 daiPrice, , uint256 timestamp, uint80 answeredInRound) = DAI.latestRoundData();
    require(daiPrice > 0, "ChainLink: DAI price <= 0");
    require(answeredInRound >= roundID, "ChainLink: Stale price");
    require(timestamp > 0, "ChainLink: Round not complete");

    (roundID, int256 usdcPrice, , timestamp, answeredInRound) = USDC.latestRoundData();
    require(usdcP

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-yield)

---

### Example 8: H-4: No slippage protection during repayment due to dynamic slippage params and easily influenced `slot0()`

**Source**: Sherlock
**Protocol**: Real Wagmi #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-10-real-wagmi-judging/issues/109 

## Found by 
0x52, 0xJuda, 0xMaroutis, 0xblackskull, HHK, IceBear, Kral01, MohammedRizwan, Nyx, kaysoft, lil.eth, lucifero, p-tsanev, peanuts, pks\_, talfao, tsvetanovv
The repayment function lacks slippage protection. It relies on slot0() to calculate sqrtLimitPrice, which in turn determines amounts for restoring liquidation. The dynamic calculation of slippage parameters based on these values leaves the function without adequate slippage protection, potentially reducing profit for the repayer.

## Vulnerability Detail
The absence of slippage protection can be attributed to two key reasons. Firstly, the `sqrtPrice` is derived from `slot0()`, **which can be easily manipulated:**
```Solidity
     function _getCurrentSqrtPriceX96(
        bool zeroForA,
        address tokenA,
        address tokenB,
        uint24 fee
    ) private view returns (uint160 sqrtPriceX96) {
        if (!zeroForA) {
            (tokenA, tokenB) = (tokenB, tokenA);
        }
        address poolAddress = computePoolAddress(tokenA, tokenB, fee);
        (sqrtPriceX96, , , , , , ) = IUniswapV3Pool(poolAddress).slot0(); //@audit-issue can be easily manipulated
    }
```
The calculated `sqrtPriceX96` is used to determine the amounts for restoring liquidation and the number of holdTokens to be swapped for saleTokens:
```Solidity
(uint256 holdTokenAmountIn, uint256 amount0, uint256 amount1) = _getHoldTokenAmountIn(
          

*[Content truncated...]*

---

### Example 9: [H-01] Oracle data feed can be outdated yet used anyways which will impact payment logic

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

_Submitted by 0xNineDec, also found by 0x1f8b, 0x29A, 0x52, 0xdanial, 0xDjango, 0xf15ers, bardamu, cccz, Cheeezzyyyy, Chom, codexploder, defsec, Franfran, Alex the Entreprenerd, Green, hake, hansfriese, horsefacts, hubble, hyh, IllIllI, jonatascm, kebabsec, Meera, oyc&#95;109, pashov, rbserver, Ruhum, simon135, tabish, tintin, and zzzitron_

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBChainlinkV3PriceFeed.sol#L44>

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBPrices.sol#L57>

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBSingleTokenPaymentTerminalStore.sol#L387>

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBSingleTokenPaymentTerminalStore.sol#L585>

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBSingleTokenPaymentTerminalStore.sol#L661>

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBSingleTokenPaymentTerminalStore.sol#L830>

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBSingleTokenPaymentTerminalStore.sol#L868>

### Impact

The current implementation of `JBChainlin

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-juicebox)

---

### Example 10: UNI_V3Validator fetches spot prices that may lead to price manipulation attacks

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`UNI_V3Validator.sol#L126-L130`

## Description
`UNI_V3Validator.validateAndParse()` checks the state of the Uniswap V3 position. This includes checking the LP value through `LiquidityAmounts.getAmountsForLiquidity`.

```solidity
//get pool state
//get slot 0
(uint160 poolSQ96, , , , , , ) = IUniswapV3PoolState(
    V3_FACTORY.getPool(token0, token1, fee)
).slot0();
(uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
    poolSQ96,
    TickMath.getSqrtRatioAtTick(tickLower),
    TickMath.getSqrtRatioAtTick(tickUpper),
    liquidity
);
```
- **LiquidityAmounts.sol#L177-L221**

When we deep dive into `getAmountsForLiquidity`, we see three cases: 
1. Price is below the range 
2. Price is within the range 
3. Price is above the range

```solidity
function getAmountsForLiquidity(
    uint160 sqrtRatioX96,
    uint160 sqrtRatioAX96,
    uint160 sqrtRatioBX96,
    uint128 liquidity
) internal pure returns (uint256 amount0, uint256 amount1) {
    unchecked {
        if (sqrtRatioAX96 > sqrtRatioBX96)
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        if (sqrtRatioX96 <= sqrtRatioAX96) {
            amount0 = getAmount0ForLiquidity(
                sqrtRatioAX96,
                sqrtRatioBX96,
                liquidity
            );
        } else if (sqrtRatioX96 < sqrtRatioBX96) {
            amount0 = getAmount0ForLiquidity(
                sqrtRatioX96,
                sqrtRatioBX96,
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 11: M-12: Chainlink's latestRoundData  return stale or incorrect result

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94 

## Found by 
8olidity, tsvetanovv, WatchDogs, Nyx, Avci, obront, Aymen0909, SPYBOY, HonorLt, csanuragjain, koxuan, evan, rbserver, hl\_, peanuts, Chinmay

## Summary
https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/oracle/ChainlinkAdapterOracle.sol#L76

## Vulnerability Detail

## Impact
On ChainlinkAdapterOracle.sol, you are using latestRoundData, but there is no check if the return value indicates stale data. 
```solidity
function getPrice(address _token) external view override returns (uint256) {
        // remap token if possible
        address token = remappedTokens[_token];
        if (token == address(0)) token = _token;

        uint256 maxDelayTime = maxDelayTimes[token];
        if (maxDelayTime == 0) revert NO_MAX_DELAY(_token);

        // try to get token-USD price
        uint256 decimals = registry.decimals(token, USD);
        (, int256 answer, , uint256 updatedAt, ) = registry.latestRoundData(
            token,
            USD
        );
        if (updatedAt < block.timestamp - maxDelayTime)
            revert PRICE_OUTDATED(_token);

        return (answer.toUint256() * 1e18) / 10**decimals;
    }
```
This could lead to stale prices according to the Chainlink documentation:
https://docs.chain.link/data-feeds/price-feeds/historical-data
Related report:
https://github.com/code-423n4/2021-05-fairside-findings/issues/70

## Code Snippet
https://github.com/sh

*[Content truncated...]*

---

### Example 12: M-7: `latestRoundData()` has no check for round completeness

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/200 

## Found by 
\_\_141345\_\_, 8olidity, yixxas, caventa, HonorLt

## Summary

No check for round completeness could lead to stale prices and wrong price return value, or outdated price. The functions rely on accurate price feed might not work as expected, sometimes can lead to fund loss. 


## Vulnerability Detail

The oracle wrapper `getOraclePrice()` call out to an oracle with `latestRoundData()` to get the price of some token. Although the returned timestamp is checked, there is no check for round completeness.

According to Chainlink's documentation, this function does not error if no answer has been reached but returns 0 or outdated round data. The external Chainlink oracle, which provides index price information to the system, introduces risk inherent to any dependency on third-party data sources. For example, the oracle could fall behind or otherwise fail to be maintained, resulting in outdated data being fed to the index price calculations. Oracle reliance has historically resulted in crippled on-chain systems, and complications that lead to these outcomes can arise from things as simple as network congestion.

## Reference
Chainlink documentation:
https://docs.chain.link/docs/historical-price-data/#historical-rounds

## Impact

If there is a problem with chainlink starting a new round and finding consensus on the new value for the oracle (e.g. chainlink nodes abandon the oracle, chain cong

*[Content truncated...]*

---

### Example 13: M-1: Lack of price freshness check in `ChainlinkOracle.sol#getPrice()` allows a stale price to be used

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/002-M 
## Found by 
defsec, icedpeachtea, oyc\_109, Lambda, 0xNineDec, Avci, ladboy233, JohnSmith, jonatascm, Ruhum, csanuragjain, PwnPatrol, WATCHPUG, 0xNazgul, xiaoming90, 0x52, 0xf15ers, ellahi, pashov, rbserver, GalloDaSballo, Chom, \_\_141345\_\_, cccz, devtooligan, Bahurum, HonorLt, GimelSec, Dravee, Olivierdem

## Summary

`ChainlinkOracle` should use the `updatedAt` value from the latestRoundData() function to make sure that the latest answer is recent enough to be used.

## Vulnerability Detail

In the current implementation of `ChainlinkOracle.sol#getPrice()`, there is no freshness check. This could lead to stale prices being used.

If the market price of the token drops very quickly ("flash crashes"), and Chainlink's feed does not get updated in time, the smart contract will continue to believe the token is worth more than the market value.

Chainlink also advise developers to check for the `updatedAt` before using the price:

> Your application should track the latestTimestamp variable or use the updatedAt value from the latestRoundData() function to make sure that the latest answer is recent enough for your application to use it. If your application detects that the reported answer is not updated within the heartbeat or within time limits that you determine are acceptable for your application, pause operation or switch to an alternate operation mode while identifying the cause of the de

*[Content truncated...]*

---

### Example 14: [H-03] WrappedIbbtcEth contract will use stalled price for mint/burn if updatePricePerShare wasn’t run properly

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

## Handle

hyh


## Vulnerability details

## Impact
Malicious user can monitor SetPricePerShare event and, if it was run long enough time ago and market moved, but, since there were no SetPricePerShare fired, the contract's pricePerShare is outdated, so a user can mint() with pricePerShare that is current for contract, but outdated for market, then wait for price update and burn() with updated pricePerShare, yielding risk-free profit at expense of contract holdings.

## Proof of Concept
WrappedIbbtcEth updates pricePerShare variable by externally run updatePricePerShare function. The variable is then used in mint/burn/transfer functions without any additional checks, even if outdated/stalled. This can happen if the external function wasn't run for any reason.
The variable is used via balanceToShares function: https://github.com/code-423n4/2021-10-badgerdao/blob/main/contracts/WrappedIbbtcEth.sol#L155

This is feasible as updatePricePerShare to be run by off-chain script being a part of the system, and malfunction of this script leads to contract exposure by stalling the price. The malfunction can happen both by internal reasons (bugs) and by external ones (any system-level dependencies, network outrages).
updatePricePerShare function: https://github.com/code-423n4/2021-10-badgerdao/blob/main/contracts/WrappedIbbtcEth.sol#L72

## Recommended Mitigation Steps
The risk comes with system design. Wrapping price updates with contract level variable for gas costs minimization is a 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-badgerdao)

---

### Example 15: H-10: IchiLpOracle is extemely easy to manipulate due to how IchiVault calculates underlying token balances

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/20 

## Found by 
carrot, obront, ctf\_sec, cergyk, banditx0x, psy4n0n, 0x52

## Summary

`IchiVault#getTotalAmounts` uses the `UniV3Pool.slot0` to determine the number of tokens it has in it's position. `slot0` is the most recent data point and is therefore extremely easy to manipulate. Given that the protocol specializes in leverage, the effects of this manipulation would compound to make malicious uses even easier.

## Vulnerability Detail

[ICHIVault.sol](https://etherscan.io/token/0x683f081dbc729dbd34abac708fa0b390d49f1c39#code#L3098)

    function _amountsForLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) internal view returns (uint256, uint256) {
        (uint160 sqrtRatioX96, , , , , , ) = IUniswapV3Pool(pool).slot0();
        return
            UV3Math.getAmountsForLiquidity(
                sqrtRatioX96,
                UV3Math.getSqrtRatioAtTick(tickLower),
                UV3Math.getSqrtRatioAtTick(tickUpper),
                liquidity
            );
    }

`IchiVault#getTotalAmounts` uses the `UniV3Pool.slot0` to determine the number of tokens it has in it's position. [slot0](https://docs.uniswap.org/contracts/v3/reference/core/interfaces/pool/IUniswapV3PoolState#slot0) is the most recent data point and can easily be manipulated.

https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/oracle/IchiLpOracle.sol#L27-L36

`IchiLPOrac

*[Content truncated...]*

---

### Example 16: M-5: DAI/gOHM exchange rate may be stale

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/217 

## Found by 
IllIllI

## Summary

The `maxLTC` variable is a constant which implies a specific DAI/gOHM echange rate. The exchange rate has already changed so the current value in use will be wrong, and any value chosen now will eventually be out of date.


## Vulnerability Detail

The `ClearingHouse` allows any loan to go through (assuming the `operator` approves it, and the `operator` is likely some sort of keeper program), and decides whether the terms are fair based on the hard-coded `maxLTC`, which will be (and is already - gOHM is currently worth $2,600) out of date. 

If the code had been using a Chainlink oracle, this issue would be equivalent to not checking whether the price used to determine the loan-to-collateral ratio was stale, which is a Medium-severity issue.

It's not clear who or what exactly will be in control of the `operator` address which will make the `clear()` calls, but it will likely be a keeper which, unless programmed otherwise, would blindly approve such loans. Even if the `operator` is an actual person, the fact that there are coded checks for the `maxLTC`, means that the person/keeper can't be fully trusted, or that the code is attempting to protect against mistakes, so this category of mistake should also be added.


## Impact

Under-collateralized loans will be given, and borrowers will purposely take loans default, since they can use the loan amount to buy more coll

*[Content truncated...]*

---

### Example 17: H-5: Users are unable close or add to their Lyra vault positions when price is stale or circuit breaker is tripped

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/69 

## Found by 
0x52, rvierdiiev

## Summary

Users are unable close or add to their Lyra vault positions when price is stale or circuit breaker is tripped. This is problematic for a few reasons. First is that the circuit breaker can be tripped indefinitely which means their collateral could be frozen forever and they will be accumulating interest the entire time they are frozen. The second is that since they can't add any additional collateral to their loan, the loan may end up being underwater by the time the price is no longer stale or circuit breaker is no longer tripped. They may have wanted to add more assets and now they are liquidated, which is unfair as users who are liquidated are effectively forced to pay a fee to the liquidator.

## Vulnerability Detail

    function _checkIfCollateralIsActive(bytes32 _currencyKey) internal view override {
            
             //Lyra LP tokens use their associated LiquidityPool to check if they're active
             ILiquidityPoolAvalon LiquidityPool = ILiquidityPoolAvalon(collateralBook.liquidityPoolOf(_currencyKey));
             bool isStale;
             uint circuitBreakerExpiry;
             //ignore first output as this is the token price and not needed yet.
             (, isStale, circuitBreakerExpiry) = LiquidityPool.getTokenPriceWithCheck();
             require( !(isStale), "Global Cache Stale, can't trade");
             require(circuitB

*[Content truncated...]*

---

### Example 18: [M-14] Chainlink's `latestRoundData` may return a stale or incorrect result

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L646> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L648>

Chainlink's `latestRoundData` is used here to retrieve price feed data; however, there is insufficient protection against price staleness.

Return arguments other than `int256 answer` are necessary to determine the validity of the returned price, as it is possible for an outdated price to be received. See [here](https://ethereum.stackexchange.com/questions/133242/how-future-resilient-is-a-chainlink-price-feed/133843#133843) for reasons why a price feed might stop updating.

The return value `updatedAt` contains the timestamp at which the received price was last updated, and can be used to ensure that the price is not outdated. See more information about `latestRoundID` in the [Chainlink docs](https://docs.chain.link/data-feeds/api-reference#latestrounddata). Inaccurate price data can lead to functions not working as expected and/or loss of funds.

### Proof of Concept

```solidity
    function getPORFeedData()
        internal
        view
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        (, int256 totalETHBalanceInInt, , , ) = AggregatorV3Interface(staderConfig.getETHBalancePORFeedProxy())
            .latestRoundData();
        (, int256 totalETHXSupplyInInt, , , ) = AggregatorV3Interface(staderConfig.getETHXSupplyPORFeedProxy())
           

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 19: M-1: Calls to Oracles don't check for stale prices

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/31 

## Found by 
0x2e, 0xHati, 0xPkhatri, 0xRobocop, 0xSmartContract, 0xStalin, 0xeix, 0xlmanini, 0xyPhilic, Angry\_Mustache\_Man, Aymen0909, Bauchibred, Bauer, Brenzee, BugBusters, Delvir0, DevABDee, Diana, Dug, Fanz, GimelSec, HonorLt, J4de, Kodyvim, Kose, Lilyjjo, Madalad, MohammedRizwan, Nyx, PNS, PTolev, Pheonix, PokemonAuditSimulator, Proxy, RaymondFam, Saeedalipoor01988, SaharDevep, SanketKogekar, Schpiel, T1MOH, TheNaubit, VAD37, WATCHPUG, \_\_141345\_\_, ast3ros, berlin-101, capy\_, chainNue, chaithanya\_gali, chalex.eth, ctf\_sec, curiousapple, dacian, evilakela, georgits, giovannidisiena, immeas, josephdara, juancito, kiki\_dev, kutugu, lil.eth, martin, ni8mare, nobody2018, pavankv241, peanuts, qbs, qckhp, saidam017, sakshamguruji, sam\_gmk, sashik\_eth, sayan\_, shaka, shealtielanz, simon135, ss3434, tallo, theOwl, toshii, tsvetanovv, twicek, ustas, vagrant, w42d3n, warRoom, whiteh4t9527
## Summary
Calls to Oracles don't check for stale prices.

## Vulnerability Detail
None of the oracle calls check for stale prices, for example [StableOracleDAI.getPriceUSD()](https://github.com/sherlock-audit/2023-05-USSD/blob/main/ussd-contracts/contracts/oracles/StableOracleDAI.sol#L48):
```solidity
(, int256 price, , , ) = priceFeedDAIETH.latestRoundData();

return
    (wethPriceUSD * 1e18) /
    ((DAIWethPrice + uint256(price) * 1e10) / 2);
```

## Impact
Oracle price feeds can become stale due to a variet

*[Content truncated...]*

---

### Example 20: [M-02] Check for stale data before trusting Chainlink's response

**Source**: ZachObront
**Protocol**: Dyad
**Impact**: MEDIUM

**Details**:

Much of the math in the protocol is based on the data provided by Chainlink's ETH-USD feed.

According to [Chainlink's documentation](https://docs.chain.link/data-feeds/price-feeds/historical-data), it is important to provide additional checks that the data is fresh:

- If answeredInRound is less than roundId, the answer is being carried over.
- A timestamp with zero value means the round is not complete and should not be used.

**Recommendation**

Add the following checks to the \_getEthPrice() function to ensure the data is fresh and accurate:

```solidity
function _getEthPrice() public view returns (uint) {
(uint80 roundID, int256 price,, uint256 timeStamp, uint80 answeredInRound) = oracle.latestRoundData();
require(timeStamp != 0);
require(answeredInRound >= roundID);
return price.toUint256();
}
```

**Review**
Fix confirmed in [PR #10](https://github.com/DyadStablecoin/contracts-v3/pull/10).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-02-12-Dyad.md)

---

### Example 21: [M-13] Different Oracle issues can return outdated prices

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/oracles/PegOracle.sol#L63>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/Controller.sol#L308>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/oracles/PegOracle.sol#L126>

### Impact

Different problems have been found with the use of the oracle that can incur economic losses when the oracle is not consumed in a completely safe way.

### Proof of Concept

The problems found are:

*   The `timeStamp` check is not correct since in both cases it is done against 0, which would mean that a date of 2 years ago would be valid, so old prices can be taken.

```javascript
    function getLatestPrice(address _token)
        public
        view
        returns (int256 nowPrice)
    {
        ...
        if(timeStamp == 0)
            revert TimestampZero();
        return price;
    }
```

*   Oracle price 1 can be outdated:

The `latestRoundData` method of the `PegOracle` contract calls `priceFeed1.latestRoundData();` directly, but does not perform the necessary round or timestamp checks, and delegates them to the caller, but these checks are performed on price2 because it calls `getOracle2_Price` in this case, this inconsistency between how it take the price1 and price2 behaves favors human errors when consuming the oracle.

### Recommended Mitigation Steps

For the timestamp iss

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 22: [M-24] [NAZ-M1] Chainlink's `latestRoundData` Might Return Stale Results

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by 0xNazgul, also found by &#95;&#95;141345&#95;&#95;, 0x1f8b, ak1, brgltd, cccz, csanuragjain, Dravee, Guardian, hyh, IllIllI, itsmeSTYJ, Jujic, Lambda, pashov, peachtea, rbserver, reassor, Sm4rty, TomJ, and zzzitron_

<https://github.com/code-423n4/2022-08-olympus/blob/main/src/modules/PRICE.sol#L161><br>
<https://github.com/code-423n4/2022-08-olympus/blob/main/src/modules/PRICE.sol#L170><br>

Across these contracts, you are using Chainlink's `latestRoundData` API, but there is only a check on `updatedAt`. This could lead to stale prices according to the Chainlink documentation:

*   [Historical Price data](https://docs.chain.link/docs/historical-price-data/#historical-rounds)
*   [Checking Your returned answers](https://docs.chain.link/docs/faq/#how-can-i-check-if-the-answer-to-a-round-is-being-carried-over-from-a-previous-round)

The result of `latestRoundData` API will be used across various functions, therefore, a stale price from Chainlink can lead to loss of funds to end-users.

### Recommended Mitigation Steps

Consider adding the missing checks for stale data.

For example:

```js
(uint80 roundID ,answer,, uint256 timestamp, uint80 answeredInRound) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();

require(answer > 0, "Chainlink price <= 0"); 
require(answeredInRound >= roundID, "Stale price");
require(timestamp != 0, "Round not complete");
```

**[Oighty (Olympus) confirmed and commented](https://github.com/code-423n4/2022-08

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 23: M-2: `Chainlink.latestRoundData()` may return stale results

**Source**: Sherlock
**Protocol**: Hubble Exchange
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-hubble-exchange-judging/issues/18 

## Found by 
0x3e84fa45, 0xbepresent, 0xmuxyz, 0xpinky, 0xvj, Bauer, Breeje, BugBusters, BugHunter101, Hama, Kaiziron, MohammedRizwan, PRAISE, Vagner, carrotsmuggler, crimson-rat-reach, darkart, dimulski, dirk\_y, kutugu, lemonmon, lil.eth, minhtrng, osmanozdemir1, p-tsanev, rogue-lion-0619, shtesesamoubiq, tsvetanovv
## Summary

The [Oracle.getUnderlyingPrice()](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L24C14-L24C32) function is used to get the price of tokens, the problem is that [the function](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L33) does not check for stale results.

## Vulnerability Detail

The [Oracle.getUnderlyingPrice()](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L24C14-L24C32) function is used in [InsuranceFund](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol), [MarginAccount](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol) and [AMM](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/AMM.sol) contracts. The `Oracle.getUnderlyingPrice()` helps to determine the tokens prices managed in the contracts.

The problem is that the

*[Content truncated...]*

---

### Example 24: M-6: Chainlink price feed is `deprecated`, not sufficiently validated and can return `stale` prices.

**Source**: Sherlock
**Protocol**: Index
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-Index-judging/issues/296 

## Found by 
0x007, 0x8chars, 0xGoodess, 0xStalin, Bauchibred, Bauer, Brenzee, BugBusters, Cryptor, Diana, Madalad, MohammedRizwan, Ocean\_Sky, Oxsadeeq, Phantasmagoria, Saeedalipoor01988, ShadowForce, erictee, jasonxiale, kn0t, kutugu, lil.eth, oxchryston, rvierdiiev, saidam017, sashik\_eth, shogoki, volodya, warRoom, whitehat
## Summary
The function `_createActionInfo()` uses Chainlink's deprecated latestAnswer function, this function also does not guarantee that the price returned by the Chainlink price feed is not stale and there is no additional checks to ensure that the return values are valid.

## Vulnerability Detail

The internal function `_createActionInfo()` uses calls `strategy.collateralPriceOracle.latestAnswer()` and `strategy.borrowPriceOracle.latestAnswer()` that uses Chainlink's deprecated latestAnswer() to get the latest price. However, there is no check for if the return value is a stale data.
```solidity

function _createActionInfo() internal view returns(ActionInfo memory) {
        ActionInfo memory rebalanceInfo;

        // Calculate prices from chainlink. Chainlink returns prices with 8 decimal places, but we need 36 - underlyingDecimals decimal places.
        // This is so that when the underlying amount is multiplied by the received price, the collateral valuation is normalized to 36 decimals.
        // To perform this adjustment, we multiply by 10^(36 - 8 - underlyingDec

*[Content truncated...]*

---

### Example 25: M-1: ControllerPeggedAssetV2: outdated price may be used which can lead to wrong depeg events

**Source**: Sherlock
**Protocol**: Y2K
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-03-Y2K-judging/issues/70 

## Found by 
0xRobocop, 0xnirlin, ABA, Ch\_301, Delvir0, Saeedalipoor01988, ShadowForce, TrungOre, ast3ros, bin2chen, carrot, evan, kaysoft, lemonmon, martin, minhtrng, p0wd3r, peanuts, roguereddwarf

## Summary
The `updatedAt` timestamp in the price feed response is not checked. So outdated prices may be used.

## Vulnerability Detail
The following checks are performed for the chainlink price feed:
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol#L299-L315

As you can see the `updatedAt` timestamp is not checked.
So the price may be outdated.

## Impact
The price that is used by the Controller can be outdated. This means that a depeg event may be caused due to an outdated price which is incorrect. Only current prices must be used to check for a depeg event.

## Code Snippet
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol#L273-L318

## Tool used
Manual Review

## Recommendation
Introduce a reasonable limit for how old the price can be and revert if the price is older:
```diff
iff --git a/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol b/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol
index 0587c86..cf2dcf5 100644
--- a/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol
+++ b/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol
@@ -275,8 +275,8

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 31
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
