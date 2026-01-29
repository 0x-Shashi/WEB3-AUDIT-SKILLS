# Oracle Security Patterns

## Overview

**Frequency**: 59 occurrences (0.12% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 24 | 34 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Codehawks, Cyfrin, Hans

---

## Detection Checklist

- [ ] Check for oracle vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-05] Flash loan price manipulation in purchasePyroFlan()

**Source**: Code4rena
**Protocol**: Behodler
**Impact**: HIGH

**Details**:

## Handle

sirhashalot


## Vulnerability details

## Impact

The comment on [line 54](https://github.com/code-423n4/2022-01-behodler/blob/cedb81273f6daf2ee39ec765eef5ba74f21b2c6e/contracts/FlanBackstop.sol#L54) of FlanBackstop.sol states "the opportunity for price manipulation through flash loans exists", and I agree that this is a serious risk. While the acceptableHighestPrice variable attempts to limit the maximum price change of the flan-stablecoin LP, a flashloan sandwich attack can still occur within this limit and make up for the limitation with larger volumes or multiple flashloan attacks. Flashloan price manipulation is the cause for many major hacks, including [bZx](https://bzx.network/blog/postmortem-ethdenver), [Harvest](https://rekt.news/harvest-finance-rekt/), and others.

## Proof of Concept

[Line 83](https://github.com/code-423n4/2022-01-behodler/blob/cedb81273f6daf2ee39ec765eef5ba74f21b2c6e/contracts/FlanBackstop.sol#L83) of FlanBackstop.sol calculates the price of flan to stablecoin in the Uniswap pool based on the balances at a single point in time. Pool balances at a single point in time can be manipulated with flash loans, which can skew the numbers to the extreme. The single data point of LP balances is used to calculate [the growth variable in line 103](https://github.com/code-423n4/2022-01-behodler/blob/cedb81273f6daf2ee39ec765eef5ba74f21b2c6e/contracts/FlanBackstop.sol#L103), and the growth variable influences the quantity of pyroflan a user receives

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-behodler)

---

### Example 2: [H-09] `PriceOracle` Does Not Filter Price Feed Outliers

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: HIGH

**Details**:

_Submitted by leastwood_

#### Impact

If for whatever reason the Chainlink oracle returns a malformed price due to oracle manipulation or a malfunctioned price, the result will be passed onto users, causing unintended consequences as a result.

In the same time it's possible to construct mitigation mechanics for such cases, so user economics be affected by sustainable price movements only. As price outrages provide a substantial attack surface for the project it's worth adding some complexity to the implementation.

#### Proof of Concept

<https://github.com/code-423n4/2021-12-sublime/blob/main/contracts/PriceOracle.sol#L149-L161>
```solidity
function getLatestPrice(address num, address den) external view override returns (uint256, uint256) {
    uint256 _price;
    uint256 _decimals;
    (_price, _decimals) = getChainlinkLatestPrice(num, den);
    if (_decimals != 0) {
        return (_price, _decimals);
    }
    (_price, _decimals) = getUniswapLatestPrice(num, den);
    if (_decimals != 0) {
        return (_price, _decimals);
    }
    revert("PriceOracle::getLatestPrice - Price Feed doesn't exist");
}
```
The above code outlines how prices are utilised regardless of their actual value (assuming it is always a non-zero value).

#### Recommended Mitigation Steps

Consider querying both the Chainlink oracle and Uniswap pool for latest prices, ensuring that these two values are within some upper/lower bounds of each other. It may also be useful to track historic values and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

### Example 3: [H-01] Incorrect handling of `pricefeed.decimals()`

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

### Example 4: H-13: `BalancerPairOracle` can be manipulated using read-only reentrancy

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/141 

## Found by 
cuthalion0x
## Summary

`BalancerPairOracle.getPrice` makes an external call to `BalancerVault.getPoolTokens` without checking the Balancer Vault's reentrancy guard. As a result, the oracle can be trivially manipulated to liquidate user positions prematurely.

## Vulnerability Detail

In February, the Balancer team disclosed a read-only reentrancy vulnerability in the Balancer Vault. The detailed disclosure can be found [here](https://forum.balancer.fi/t/reentrancy-vulnerability-scope-expanded/4345). In short, all Balancer pools are susceptible to manipulation of their external queries, and all integrations must now take an extra step of precaution when consuming data. Via reentrancy, an attacker can force token balances and BPT supply to be out of sync, creating very inaccurate BPT prices.

Some protocols, such as Sentiment, remained unaware of this issue for a few months and were later [hacked](https://twitter.com/spreekaway/status/1643313471180644360) as a result.

`BalancerPairOracle.getPrice` makes a price calculation of the form `f(balances) / pool.totalSupply()`, so it is clearly vulnerable to synchronization issues between the two data points. A rough outline of the attack might look like this:

```solidity
AttackerContract.flashLoan() ->
    // Borrow lots of tokens and trigger a callback.
    SomeProtocol.flashLoan() ->
        AttackerContract.exploit()

AttackerContract.e

*[Content truncated...]*

---

### Example 5: H-1: An update gap in Chainlink's feed can malfunction the whole market

**Source**: Sherlock
**Protocol**: Float Capital
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-float-capital-judging/issues/42 

## Found by 
WATCHPUG

## Summary

The `roundId` that is used for settling the price change and pushing the `latestExecutedEpochIndex` forward is strictly limited to be in a precise period of time. When there is no such `roundId`, the system will freeze and lock everyone out.

## Vulnerability Detail

The check at L127 makes it impossible to use a roundId that was created at a later time than `relevantEpochStartTimestampWithMEWT + EPOCH_LENGTH`.

However, when the `EPOCH_LENGTH` is larger than the Chainlink feed's heartbeat length, or Chainlink failed to post a feed within the expected heartbeat for whatever reason, then it would be impossible to find a suitable roundId (as it does not exist) to push the epoch forward due to the rather strict limitation for the roundId.

## Impact

As a result, the whole system will malfunction and no one can enter or exit the market.

## Code Snippet

https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketCore.sol#L188-L195

## Tool used

Manual Review

## Recommendation

Consider allowing the `roundId` not to falls into the epoch, and use the previous roundId's price when that's the case:

```diff
    for (uint32 i = 0; i < lengthOfEpochsToExecute; i++) {
      // Get correct data
      (, int256 currentOraclePrice, uint256 currentOracleUpdateTimestamp, , ) = chainlinkOracle.getRoundData(oracleRoundIdsToExecute[i]);

*[Content truncated...]*

---

### Example 6: H-2: Requested oracle versions, which have expired, must return this oracle version as invalid, but they return it as a normal version with previous version's price instead

**Source**: Sherlock
**Protocol**: Perennial V2 Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-02-perennial-v2-3-judging/issues/6 

## Found by 
bin2chen, panprog
## Summary

Each market action requests a new oracle version which must be commited by the keepers. However, if keepers are unable to commit requested version's price (for example, no price is available at the time interval, network or keepers are down), then after a certain timeout this oracle version will be commited as invalid, using the previous valid version's price.

The issue is that when this expired oracle version is used by the market (using `oracle.at`), the version returned will be valid (`valid = true`), because oracle returns version as invalid only if `price = 0`, but the `commit` function sets the previous version's price for these, thus it's not 0.

This leads to market using invalid versions as if they're valid, keeping the orders (instead of invalidating them), which is a broken core functionality and a security risk for the protocol.

## Vulnerability Detail

When requested oracle version is commited, but is expired (commited after a certain timeout), the price of the previous valid version is set to this expired oracle version:
```solidity
function _commitRequested(OracleVersion memory version) private returns (bool) {
    if (block.timestamp <= (next() + timeout)) {
        if (!version.valid) revert KeeperOracleInvalidPriceError();
        _prices[version.timestamp] = version.price;
    } else {
        // @audit previous valid version's pr

*[Content truncated...]*

---

### Example 7: [H-07] Incorrect precision assumed from RdpxPriceOracle creates multiple issues related to value inflation/deflation

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

### Example 8: [H-05] Attacker can manipulate low TVL Uniswap V3 pool to borrow and swap to make Lending Pool in loss

**Source**: Code4rena
**Protocol**: ParaSpace
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-paraspace/blob/c6820a279c64a299a783955749fdc977de8f0449/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L176>

In Paraspace protocol, any Uniswap V3 position that are consist of ERC20 tokens that Paraspace support can be used as collateral to borrow funds from Paraspace pool. The value of the Uniswap V3 position will be sum of value of ERC20 tokens in it.

```solidity
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

    return // @audit can be easily manipulated with low TVL pool
        (((liquidityAmount0 + feeAmount0) * oracleData.token0Price) /
            10**oracleData.token0Decimal) +
        (((liquidityAmount1 + feeAmount1) * oracleData.token1Price) /
            10**oracleData.token1Decimal);
}
```

However, Uniswap V3 can have multiple pools for the **same pairs** of ERC20 tokens with **different fee**

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-paraspace)

---

### Example 9: [M-24] Chainlink price feed is not sufficiently validated and can return stale price

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

### Example 10: Missing checks for Chainlink oracle

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

### Example 11: [M-07] Oracle’s two-day feature can be gamed

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

### Example 12: Chainlink price is used without checking validity

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

### Example 13: [M-07] Last collateral check is not safe

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

Liquidation might work incorrectly.

### Proof of Concept

There is a function `purchaseLiquidationAuctionNFT()` to allow liquidators to purchase NFTs on auction.

In the line 273, the protocol checks if the current NFT is the last collateral using the `collateralValueCached`.

But it might be possible for Reservoir Oracle to return zero (for whatever reason) and in that case `collateralValueCached` will be zero even when the `_vaultInfo[auction.nftOwner][auction.auctionAssetContract].count!=0`.

One might argue that it is impossible for the Reservoir oracle to return zero output but I think it is safe not to rely on it.

```solidity
PaprController.sol
264:     function purchaseLiquidationAuctionNFT(
265:         Auction calldata auction,
266:         uint256 maxPrice,
267:         address sendTo,
268:         ReservoirOracleUnderwriter.OracleInfo calldata oracleInfo
269:     ) external override {
270:         uint256 collateralValueCached = underwritePriceForCollateral(
271:             auction.auctionAssetContract, ReservoirOracleUnderwriter.PriceKind.TWAP, oracleInfo
272:         ) * _vaultInfo[auction.nftOwner][auction.auctionAssetContract].count;
273:         bool isLastCollateral = collateralValueCached == 0;//@audit not safe
274:
275:         uint256 debtCached = _vaultInfo[auction.nftOwner][auction.auctionAssetContract].debt;
276:         uint256 maxDebtCached = isLastCollateral ? debtCached : _maxDebt(collateralValueCached, updateTarget());
277:         /// anything 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 14: [M-18] Protocol’s usability becomes very limited when access to Chainlink oracle data feed is blocked

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
Based on the current implementation, when the protocol wants to use Chainlink oracle data feed for getting a collateral token's price, the fixed price for the token should not be set. When the fixed price is not set for the token, calling the `Oracle` contract's `viewPrice` or `getPrice` function will execute `uint price = feeds[token].feed.latestAnswer()`. As https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/ mentions, it is possible that Chainlink’s "multisigs can immediately block access to price feeds at will". When this occurs, executing `feeds[token].feed.latestAnswer()` will revert so calling the `viewPrice` and `getPrice` functions also revert, which cause denial of service when calling functions like `getCollateralValueInternal` and`getWithdrawalLimitInternal`. The `getCollateralValueInternal` and`getWithdrawalLimitInternal` functions are the key elements to the core functionalities, such as borrowing, withdrawing, force-replenishing, and liquidating; with these functionalit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 15: [M-11] viewPrice doesn’t always report dampened price

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Oracle.sol#L91


## Vulnerability details

## Impact
Oracle's `viewPrice` function doesn't report a dampened price until `getPrice` is called and today's price is updated. This will impact the public read-only functions that call it:
- [getCollateralValue](https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L312);
- [getCreditLimit](https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L334) (calls `getCollateralValue`);
- [getLiquidatableDebt](https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L578) (calls `getCreditLimit`);
- [getWithdrawalLimit](https://github.com/code-423n4/2022-10-inverse/blob/3e81f0f5908ea99b36e6ab72f13488bbfe622183/src/Market.sol#L370).

These functions are used to get on-chain state and prepare values for write calls (e.g. calculate withdrawal amount before withdrawing or calculate a user's debt that can be liquidated before liquidating it). Thus, wrong values returned by these functions can cause withdrawal of a wrong amount or liquidation of a wrong debt or cause reverts.
## Proof of Concept
```solidity
// src/test/Oracle.t.sol
function test_viewPriceNoDampenedPrice_AUDIT() public {
    uint collateralFactor = market.collateralFactorBps();
    uint day = block.timestamp / 1 da

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 16: [M-01] Oracle data feed is insufficiently validated

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

### Example 17: H-5: spTKNMinimalOracle `_calculateSpTknPerBase()` does not calculate correct price for podded or fraxlend pair pairedLpTKNs.

**Source**: Sherlock
**Protocol**: Peapods
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2025-01-peapods-finance-judging/issues/445 

## Found by 
bretzel, pkqs90


### Summary

spTKNMinimalOracle `_calculateSpTknPerBase()` does not calculate correct price for podded or fraxlend pair pairedLpTKNs.

### Root Cause

First, let’s clarify the denomination: tokenA/tokenB represents how much tokenB is worth per tokenA. For example, ETH/USDC = 3000 means 1 ETH is equivalent to 3000 USDC.

The `_calculateSpTknPerBase()` function is used to calculate baseTKN/spTKN. It starts with the `_priceBasePerPTkn18` variable, which is pTKN/baseTKN.

Now, we need to convert pTKN to spTKN. Because spTKN is the Uniswap V2 LP of pTKN and pairedLpTKN, the idea is to use the Uniswap V2 LP fair pricing formula. In order to do that, we need the price of pairedLpTKN/baseTKN.

For normal pods, baseTKN is equal to pairedLpTKN (e.g USDC as pairedLpTKN). However, pods (e.g. pOHM) and fraxlend pair (self-lending pods e.g. fUSDC) tokens are also supported. The bug here is, for both podded tokens and fraxlend pair tokens, the formula is wrong.

From this doc, https://docs.google.com/document/d/1Z-T_07QpJlqXlbBSiC_YverKFfu-gcSkOBzU1icMRkM/edit?tab=t.0, the spTKN is first priced against pairedLpTKN (i.e. spTKN/pairedLpTKN), then converted to spTKN/baseTKN.

The two bugs here are:

1. The current code calculates `_basePerSpTkn18` as if pairedLpTKN/baseTKN is 1:1. However, this is incorrect. We should convert pTKN/baseTKN (which is `_priceBasePerPTkn18`) to pTK

*[Content truncated...]*

---

### Example 18: H-2: Attackers can drain the `OracleLess` contract by creating an order with a `malicious tokenIn` and executing it with a `malicious target`.

**Source**: Sherlock
**Protocol**: Oku's New Order Types Contract Contest
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-11-oku-judging/issues/357 

## Found by 
0xaxaxa, BugPull, Ragnarok, whitehair0330
### Summary

In the `OracleLess` contract, the `createOrder()` function does not verify whether the `tokenIn` is a legitimate ERC20 token, allowing attackers to create an order with a malicious token. Additionally, the `fillOrder()` function does not check if the `target` and `txData` are valid, enabling attackers to execute their order with a malicious `target` and `txData`.

### Root Cause

The [OracleLess.createOrder()](https://github.com/sherlock-audit/2024-11-oku/blob/main/oku-custom-order-types/contracts/automatedTrigger/OracleLess.sol#L38-L67) function does not verify whether `tokenIn` is a legitimate ERC20 token.

Additionally, the [OracleLess.fillOrder()](https://github.com/sherlock-audit/2024-11-oku/blob/main/oku-custom-order-types/contracts/automatedTrigger/OracleLess.sol#L103-L148) function does not check if `target` and `txData` are valid.

### Internal pre-conditions

### External pre-conditions

### Attack Path

Let's consider the following scenario:

1. Alice, the attacker, creates a malicious token.

2. Alice creates an order with her malicious token:

    - `tokenIn`: Alice's malicious token
    - `tokenOut`: `WETH`
    - `minAmountOut`: 0
3. Alice calls the `fillOrder()` function to execute her malicious order, setting parameters as follows:

    - `target`: address of `USDT`
    - `txData`: transfer all `USDT` in the `OracleLess

*[Content truncated...]*

---

### Example 19: Potential underflow vulnerability in score range calculation of `LLMOracleCoordinator::finalizeValidation`, leading to DoS.

**Source**: Codehawks
**Protocol**: Dria
**Impact**: HIGH

**Details**:

## Summary

The `LLMOracleCoordinator::finalizeValidation` function calculates the range for valid scores depending on the result of the expression `score >= _mean - _stddev`. If `_mean` is less than `_stddev`, this calculation leads to an underflow error, causing a revert that will fail the transaction. This behavior prevents successful validation completion and rewards distribution, disrupting normal contract operations and usability.

## Description

In the `LLMOracleCoordinator::finalizeValidation` function, scores are evaluated within a standard deviation range around the mean, using the criteria `(_mean - _stddev)` and `(_mean + _stddev)`, see \[<https://github.com/Cyfrin/2024-10-swan-dria/blob/main/contracts/llm/LLMOracleCoordinator.sol#L343>]:

```js
if ((score >= _mean - _stddev) && (score <= _mean + _stddev))
```

However, in cases where `_mean < _stddev`, such as some valid edge case where for example `scores[] = [0,1,0,1,2]`, the calculation of `_mean - _stddev` attempts to produce a negative value.

Since Solidity’s uint256 type does not support negative numbers, this results in an underflow, triggering an automatic revert and causing the transaction to fail. The edge case described results in `_stddev = 1` and `_mean = 0`, which causes the check `score >= _mean - _stddev` to revert, as `_mean - _stddev` evaluates to a negative result.

The same issue exists also in \[<https://github.com/Cyfrin/2024-10-swan-dria/blob/main/contracts/llm/LLMOracleCoordinator.sol#L3

*[Content truncated...]*

---

### Example 20: LibUsdOracle returns the wrong price for Uniswap Oracle

**Source**: Codehawks
**Protocol**: Beanstalk: The Finale
**Impact**: HIGH

**Details**:

## Vulnerability Details

The Generalised Oracle is broken for the external tokens that use Uniswap. This is happening for two reasons: 

1. The token passed as a base token for the `OracleLibrary.getQuoteAtTick` is incorrect. The base token should be the token the protocol wants to fetch the price from, not the quote token. Take into consideration the following scenario: Fetching the price for WBTC. 

```Solidity
            // LibUsdOracle -> getTokenPriceFromExternal
            address chainlinkToken = IUniswapV3PoolImmutables(oracleImpl.target).token0();
            chainlinkToken = chainlinkToken == token
                ? IUniswapV3PoolImmutables(oracleImpl.target).token1()
                : token;
            tokenPrice = LibUniswapOracle.getTwap(
                lookback == 0 ? LibUniswapOracle.FIFTEEN_MINUTES : uint32(lookback),
                oracleImpl.target,
@>                chainlinkToken, // @audit baseToken: chainlinkToken is USDC
                token, // @audit quoteToken - WBTC
                uint128(10) ** uint128(IERC20Decimals(token).decimals()) // @audit base token amount
```

The function getTwap: 

```Solidity
    function getTwap(
        uint32 lookback,
        address pool,
        address token1, // @audit USDC
        address token2, // @audit WBTC
        uint128 oneToken // @audit 1e8
    ) internal view returns (uint256 price) {
        (bool success, int24 tick) = consult(pool, lookback);
        if (!success) return 0;
@>        price =

*[Content truncated...]*

---

### Example 21: LibUsdOracle will compromise Beanstalk peg due to wrong price and DoS

**Source**: Codehawks
**Protocol**: Beanstalk: The Finale
**Impact**: HIGH

**Details**:

## Vulnerability Details

The function `getUsdPrice`from `LibUsdOracle` should return the token value in USD.  For example, one of its consumers is the function [`getMintFertilizerOut`](https://github.com/Cyfrin/2024-05-beanstalk-the-finale/blob/4e0ad0b964f74a1b4880114f4dd5b339bc69cd3e/protocol/contracts/beanstalk/barn/FertilizerFacet.sol#L117-L122):

`fertilizerAmountOut = tokenAmountIn.div(LibUsdOracle.getUsdPrice(barnRaiseToken));`

The goal of this function is to return the fertilizer amount with 0 decimals, therefore if the WETH value is at \$1000 and the user would provide 1 WETH:

`tokenAmountIn = 1e18.div(1e15) = 1e3 = 1000`

Another critical use case for `getUsdPrice` is: fetching the ratios to calculate the deltaB.

```solidity
 function getRatiosAndBeanIndex(
        IERC20[] memory tokens,
        uint256 lookback
    ) internal view returns (uint[] memory ratios, uint beanIndex, bool success) {
        success = true;
        ratios = new uint[](tokens.length);
        beanIndex = type(uint256).max;
        for (uint i; i < tokens.length; ++i) {
            if (C.BEAN == address(tokens[i])) {
                beanIndex = i;
                ratios[i] = 1e6;
            } else {
@>                ratios[i] = LibUsdOracle.getUsdPrice(address(tokens[i]), lookback); // @audit expect value return in USD
                if (ratios[i] == 0) {
                    success = false;
                }
            }
        }
        require(beanIndex != type(uint256).max, "Bea

*[Content truncated...]*

---

### Example 22: `LibChainlinkOracle::getTokenPrice` will always return instantaneuous prices

**Source**: Codehawks
**Protocol**: Beanstalk: The Finale
**Impact**: HIGH

**Details**:

## Summary

The `LibChainlinkOracle::getTokenPrice` function has a parameter of `lookback` in order to determine how many seconds ago do we want to obtain the twap of a chainlink price feed. However, this is implemented in a wrong way

## Relevant GitHub Links:
https://github.com/Cyfrin/2024-05-beanstalk-the-finale/blob/main/protocol/contracts/libraries/Oracle/LibChainlinkOracle.sol#L39-L48

## Vulnerability Details

When `LibChainlinkOracle::getTokenPrice` is called, it returns a different price calculation depending on the `lookback` parameter passed to the function:

```Solidity
    function getTokenPrice(
        address priceAggregatorAddress,
        uint256 maxTimeout,
        uint256 lookback
    ) internal view returns (uint256 price) {
        return
            lookback > 0
                ? getPrice(priceAggregatorAddress, maxTimeout)
                : getTwap(priceAggregatorAddress, maxTimeout, lookback);
    }
```

In this case the ternary operator returns the function `getPrice` (instantaneous price) when lookback > 0 and `getTwap` when lookback == 0. As we can see, the conditional for returning the different price computation is wrong because it returns the twap price when lookback = 0, which is basically the instantaneous price and it returns the current price when the lookback parameter is greater than 0, when it should return the twap according to the amount of lookback passed.

The correct behaviour should be that when `lookback` is set to 0, it should ret

*[Content truncated...]*

---

### Example 23: [H-01] Oracle data feed can be outdated yet used anyways which will impact payment logic

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

### Example 24: M-13: Rely On Balancer Oracle Which Is Not Updated Frequently

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/67 

## Found by 
xiaoming90

## Summary

The vault relies on Balancer Oracle which is not updated frequently.

## Vulnerability Detail

> Note: This issue affects the MetaStable2 balancer leverage vault

Within the `TwoTokenPoolUtils._getOraclePairPrice` function, it compute the pair price from the Balancer Oracle by calling the `BalancerUtils._getTimeWeightedOraclePrice` function which will in turn call the `IPriceOracle(pool).getTimeWeightedAverage` function to get the  time-weighted average pair prices (e.g. stETH/ETH). The Balancer pool that will be polled for the pair price can be found at https://etherscan.io/address/0x32296969Ef14EB0c6d29669C550D4a0449130230.

The issue is that this pool only handled ~1.5 transactions per day based on the last 5 days' data. In terms of average, the price will only be updated once every 16 hours. There are also many days that there is only 1 transaction. The following shows the number of transactions for each day within the audit period.

- 5 Oct 2022 - 3 transactions
- 4 Oct 2022 - 1 transaction
- 3 Oct 2022 - 1 transaction
- 2 Oct 2022 - 2 transactions
- 1 Oct 2022 - 1 transaction

Note that the price will only be updated whenever a transaction (e.g. swap) within the Balancer pool is triggered. Due to the lack of updates, the price provided by Balancer Oracle will not reflect the true value of the assets. Considering the stETH/ETH Balancer pool, the price of th

*[Content truncated...]*

---

### Example 25: M-10: ERC4626Oracle Vulnerable To Price Manipulation

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/133-M 
## Found by 
xiaoming90, IllIllI

## Summary

ERC4626 oracle is vulnerable to price manipulation. This allows an attacker to increase or decrease the price to carry out various attacks against the protocol.

## Vulnerability Detail

The `getPrice` function within the `ERC4626Oracle` contract is vulnerable to price manipulation because the price can be increased or decreased within a single transaction/block.

Based on the `getPrice` function, the price of the LP token of an ERC4626 vault is dependent on the `ERC4626.previewRedeem` and `oracleFacade.getPrice` functions. If the value returns by either `ERC4626.previewRedeem` or `oracleFacade.getPrice` can be manipulated within a single transaction/block, the price of the LP token of an ERC4626 vault is considered to be vulnerable to price manipulation.

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/oracle/src/erc4626/ERC4626Oracle.sol#L8

```solidity
File: ERC4626Oracle.sol
35:     function getPrice(address token) external view returns (uint) {
36:         uint decimals = IERC4626(token).decimals();
37:         return IERC4626(token).previewRedeem(
38:             10 ** decimals
39:         ).mulDivDown(
40:             oracleFacade.getPrice(IERC4626(token).asset()),
41:             10 ** decimals
42:         );
43:     }
```

It was observed that the `ERC4626.previewRedeem` couldbe manipulated within a single transaction/block.

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 59
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
