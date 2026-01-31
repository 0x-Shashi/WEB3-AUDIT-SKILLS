---
id: PAT-CHAINLINK
title: Chainlink Security Patterns
category: oracle
severity: high
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - chainlink
  - price-feed
  - aggregator

finding_count: 25
last_updated: 2026-01-31
---
# Chainlink Security Patterns

## Overview

**Frequency**: 25 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 21 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Halborn, Codehawks, Hans

---

## Detection Checklist

- [ ] Check for chainlink vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-1: An update gap in Chainlink's feed can malfunction the whole market

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

### Example 2: [M-24] Chainlink price feed is not sufficiently validated and can return stale price

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

### Example 3: Missing checks for Chainlink oracle

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

`updateAt` refers to the timestamp of the round. This value isnt checked to ensure it is recent. Additionally, it is important to be aware of the `minAnswer` and `maxAnswer` of the Chainlink oracle; these values are not allowed to be reached or surpassed. See the Chainlink API reference for documentation on `minAnswer` and `maxAnswer`, as well as this piece of code: `OffchainAggregator.sol`.

## Recommendation
- Determine the tolerance threshold for `updateAt`. If `block.timestamp - updateAt` exceeds that threshold, return 0, which is consistent with how the current validations are handled.
- Consider having off-chain monitoring to identify when the market price moves out of `[minAnswer, maxAnswer]` range.

## Connext
Recency check is implemented in PR 1602. Off-chain monitoring will be consider

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: Chainlink price is used without checking validity

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

### Example 5: [M-01] Oracle data feed is insufficiently validated

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

### Example 6: H-1: Users will lock raffle prizes on the `WinnablesPrizeManager` contract by calling `WinnablesTicketManager::propagateRaffleWinner` with wrong CCIP inputs

**Source**: Sherlock
**Protocol**: Winnables Raffles
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-08-winnables-raffles-judging/issues/50 

## Found by 
0rpse, 0x0bserver, 0x73696d616f, 0xAadi, 0xbrivan, 0xrex, CatchEmAll, DrasticWatermelon, Feder, Galturok, IMAFVCKINSTARRRRRR, KungFuPanda, Oblivionis, Offensive021, Oxsadeeq, PNS, PTolev, Paradox, Penaldo, PeterSR, S3v3ru5, SadBase, SovaSlava, Trooper, Waydou, akiro, araj, dany.armstrong90, dimulski, dinkras\_, durov, dy, gajiknownnothing, iamnmt, irresponsible, jennifer37, joshuajee, matejdb, neko\_nyaa, ogKapten, philmnds, rsam\_eth, sakshamguruji, shaflow01, shikhar, tofunmi, turvec, utsav
### Summary

The [`WinnablesTicketManager::propagateRaffleWinner`](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L334) function is vulnerable to misuse, where incorrect CCIP inputs can lead to assets being permanently locked in the `WinnablesPrizeManager` contract. The function does not have input validation for the `address prizeManager` and `uint64 chainSelector` parameters. If called with incorrect values, it will fail to send the message to `WinnablesPrizeManager`, resulting in the assets not being unlocked.


### Root Cause

The root cause of the issue lies in the design of the `propagateRaffleWinner` function:
1. The function is responsible for sending a message to WinnablesPrizeManager to unlock the raffle assets.
2. The function is marked as external, so anyone can call it.
3. The function receives `addr

*[Content truncated...]*

---

### Example 7: [H-01] Oracle data feed can be outdated yet used anyways which will impact payment logic

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

### Example 8: M-4: No check for active Arbitrum Sequencer in WSTETH Oracle

**Source**: Sherlock
**Protocol**: Sentiment Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sentiment-judging/issues/3 

## Found by 
pashov, obront

## Summary

Chainlink recommends that all Optimistic L2 oracles consult the Sequencer Uptime Feed to ensure that the sequencer is live before trusting the data returned by the oracle. This check is implemented in ArbiChainlinkOracle.sol, but is skipped in WSTETHOracle.sol.

## Vulnerability Detail

If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 optimistic rollup contract. You can review Chainlink docs on [L2 Sequencer Uptime Feeds](https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds/) for more details on this.

As a result, users may be able to use the protocol while oracle feeds are stale. This could cause many problems, but as a simple example:
- A user has an account with 100 tokens, valued at 1 ETH each, and no borrows
- The Arbitrum sequencer goes down temporarily
- While it's down, the price of the token falls to 0.5 ETH each
- The current value of the user's account is 50 ETH, so they should be able to borrow a maximum of 200 ETH to keep account healthy (`(200 + 50) / 200 = 1.2`)
- Because of the stale price, the protocol lets them borrow 400 ETH (`(400 + 100) / 400 = 1.2`)

## Impact

If the Arbitrum sequencer goes down, the protocol will allow users to continue to operate at the previous (stale) rates.

## 

*[Content truncated...]*

---

### Example 9: M-13: Rely On Balancer Oracle Which Is Not Updated Frequently

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

### Example 10: Unhandled Exceptions in CCIP Message Processing Can Lead to Cross-Chain Communication Failure

**Source**: Halborn
**Protocol**: Contracts V1
**Impact**: MEDIUM

**Details**:

##### Description

The `CCIPAdapter` contract in the LucidLabs protocol uses Chainlink's Cross-Chain Interoperability Protocol (CCIP) to facilitate cross-chain communication. However, the implementation fails to handle exceptions gracefully in the receiving contracts, specifically in `VotingControllerUpgradeable` and `AssetController`.

```
function _ccipReceive(Client.Any2EVMMessage memory any2EvmMessage) internal override {
    _registerMessage(bytes32ToAddress(_originSender), _callData, chainId);
}
```

  

This function calls `registerMessage()` on `VotingControllerUpgradeable` and `AssetController`, which can revert due to various reasons:

```
function castCrossChainVote(...) external {
    //E @AUDIT can revert because of state(proposalId) , timepoint is not the good
    if ((adapter != msg.sender) || (state(proposalId) != ProposalState.Active) || (proposalSnapshot(proposalId) != timepoint) || (chainTokens[chainId] != sourceToken))
        revert Governor_WrongParams();
// ...
    _countVote(proposalId, voter, support, votes, voteData, chainId);
// ...
}

function _countVote(
        uint256 proposalId,
        address account,
        uint8 support,
        uint256 totalWeight,
        bytes memory voteData, //E when called from LucidGovernor{Timelock} it is not implemented => _countVoteNominal is called
        uint256 chainId 
    ) internal virtual {
        
        if (totalWeight == 0) revert GovernorCrossCountingFractionalUpgradeable_NoWeight();

        if (_p

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/lucid-labs/contracts-v1)

---

### Example 11: M-16: ChainlinkAdapterOracle will return the wrong price for asset if underlying aggregator hits minAnswer

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18 

## Found by 
0x52

## Summary

Chainlink aggregators have a built in circuit breaker if the price of an asset goes outside of a predetermined price band. The result is that if an asset experiences a huge drop in value (i.e. LUNA crash) the price of the oracle will continue to return the minPrice instead of the actual price of the asset. This would allow user to continue borrowing with the asset but at the wrong price. This is exactly what happened to [Venus on BSC when LUNA imploded](https://rekt.news/venus-blizz-rekt/). 

## Vulnerability Detail

ChainlinkAdapterOracle uses the [ChainlinkFeedRegistry](https://etherscan.io/address/0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf) to obtain the price of the requested tokens.

    function latestRoundData(
      address base,
      address quote
    )
      external
      view
      override
      checkPairAccess()
      returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
      )
    {
      uint16 currentPhaseId = s_currentPhaseId[base][quote];
      //@audit this pulls the Aggregator for the requested pair
      AggregatorV2V3Interface aggregator = _getFeed(base, quote);
      require(address(aggregator) != address(0), "Feed not found");
      (
        roundId,
        answer,
        startedAt,
        updatedAt,
        answeredInRound
      ) = aggregator.lates

*[Content truncated...]*

---

### Example 12: M-3: _validateAndGetPrice() doesn't check If Arbitrum sequencer is down in Chainlink feeds

**Source**: Sherlock
**Protocol**: Bond Protocol Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-bond-judging/issues/1 

## Found by 
Avci

## Summary
When utilizing Chainlink in L2 chains like Arbitrum, it's important to ensure that the prices provided are not falsely perceived as fresh, even when the sequencer is down. This vulnerability could potentially be exploited by malicious actors to gain an unfair advantage.

## Vulnerability Detail
There is no check: 
```soldity
solidity function _validateAndGetPrice(AggregatorV2V3Interface feed_, uint48 updateThreshold_)
        internal
        view
        returns (uint256)
    {
        // Get latest round data from feed
        (uint80 roundId, int256 priceInt, , uint256 updatedAt, uint80 answeredInRound) = feed_
            .latestRoundData();
        // @audit check if Arbitrum L2 sequencer is down in Chainlink feeds: medium
        // Validate chainlink price feed data
        // 1. Answer should be greater than zero
        // 2. Updated at timestamp should be within the update threshold
        // 3. Answered in round ID should be the same as the round ID
        if (
            priceInt <= 0 ||
            updatedAt < block.timestamp - uint256(updateThreshold_) ||
            answeredInRound != roundId
        ) revert BondOracle_BadFeed(address(feed_));
        return uint256(priceInt);
    }
```
## Impact
could potentially be exploited by malicious actors to gain an unfair advantage.
## Code Snippet
https://github.com/sherlock-audit/2023-02-bond-0xdanial/blob/0d6f

*[Content truncated...]*

---

### Example 13: M-2: An update gap in Chainlink's feed can malfunction the whole market

**Source**: Sherlock
**Protocol**: Float Capital
**Impact**: MEDIUM

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

### Example 14: [M-14] Chainlink's `latestRoundData` may return a stale or incorrect result

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

### Example 15: [M-12] During oracle outages or feeder outages/disagreement, the ParaSpaceFallbackOracle is not used

**Source**: Code4rena
**Protocol**: ParaSpace
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-paraspace/blob/c6820a279c64a299a783955749fdc977de8f0449/paraspace-core/contracts/misc/ParaSpaceOracle.sol#L114-L136


## Vulnerability details

## Impact
If the feeders haven't updated their prices within the default six-hour time window, the floor oracle will revert when requests are made to get the current price, and these reverts are not caught by the wrapper oracle which handles the fallback oracle, so rather than using the fallback oracle in these cases, the calls will revert, leading to liquidations to fail (see my other submission for the full chain from the floor oracle to the liquidation function).

Additionally, the code uses the deprecated chainlink `latestAnswer()` API for its token requests, which may revert once it is no longer supported

## Proof of Concept
`getPrice()` will fail if the values are stale:
```solidity
File: /paraspace-core/contracts/misc/NFTFloorOracle.sol   #1

236      function getPrice(address _asset)
237          external
238          view
239          override
240          returns (uint256 price)
241      {
242 @>       uint256 updatedAt = assetPriceMap[_asset].updatedAt;
243          require(
244              (block.number - updatedAt) <= config.expirationPeriod,
245 @>           "NFTOracle: asset price expired"
246          );
247          return assetPriceMap[_asset].twap;
248:     }
```
https://github.com/code-423n4/2022-11-paraspace/blob/c6820a279c64a299a783955749fdc977de8f0449/par

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-paraspace)

---

### Example 16: [M-24] [NAZ-M1] Chainlink's `latestRoundData` Might Return Stale Results

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

### Example 17: M-6: The `Vault._to_usd_oracle_price()` function uses the same `ORACLE_FRESHNESS_THRESHOLD` for all token prices feeds which is incorrect

**Source**: Sherlock
**Protocol**: Unstoppable
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-unstoppable-judging/issues/104 

## Found by 
0xbepresent, 0xpinky, TheNaubit, n33k, pengun, stopthecap, twicek
## Summary

The same `ORACLE_FRESHNESS_THRESHOLD` is used for all the token prices feeds which can be dangerous because different pairs of tokens have different freshness intervals.

## Vulnerability Detail

The [ORACLE_FRESHNESS_THRESHOLD](https://github.com/sherlock-audit/2023-06-unstoppable/blob/main/unstoppable-dex-audit/contracts/margin-dex/Vault.vy#L55) is 24 hours constant. It is used to check if the [Oracle price is fresh](https://github.com/sherlock-audit/2023-06-unstoppable/blob/main/unstoppable-dex-audit/contracts/margin-dex/Vault.vy#L580) in the 580 code line.

```python
File: Vault.vy
562: def _to_usd_oracle_price(_token: address) -> uint256:
...
...
576:     round_id, answer, started_at, updated_at, answered_in_round = ChainlinkOracle(
577:         self.to_usd_oracle[_token]
578:     ).latestRoundData()
579: 
580:     assert (block.timestamp - updated_at) < ORACLE_FRESHNESS_THRESHOLD, "oracle not fresh"
...
...
```

The problem is that different pairs have diferrent `heartbeats`. For example the [LINK/USD](https://data.chain.link/arbitrum/mainnet/crypto-usd/link-usd) has a `heartbeat` of 3600 seconds so since the `ORACLE_FRESHNESS_THRESHOLD` is set to `24 hours`, the check for `LINK/USD` is useless since the its hearbeat is 3600 seconds. The same behaivour in [CRV/USD](https://data.chain.link/arbitrum/m

*[Content truncated...]*

---

### Example 18: M-2: `Chainlink.latestRoundData()` may return stale results

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

### Example 19: M-6: Chainlink price feed is `deprecated`, not sufficiently validated and can return `stale` prices.

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

### Example 20: M-5: getPriceFromChainlink() doesn't check If Arbitrum sequencer is down in Chainlink feeds

**Source**: Sherlock
**Protocol**: Iron Bank
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-ironbank-judging/issues/440 

## Found by 
0x52, 0xMAKEOUTHILL, Angry\_Mustache\_Man, Arabadzhiev, Arz, Aymen0909, BenRai, Breeje, Brenzee, BugBusters, Delvir0, HexHackers, Ignite, Jaraxxus, Kodyvim, Madalad, MohammedRizwan, Ocean\_Sky, Proxy, R-Nemes, SovaSlava, berlin-101, bin2chen, bitsurfer, branch\_indigo, deadrxsezzz, devScrooge, josephdara, kutugu, n1punp, n33k, ni8mare, p0wd3r, plainshift-2, rvierdiiev, santipu\_, sashik\_eth, shaka, simon135, sl1, toshii, tsvetanovv, turvec, vagrant
## Summary
When utilizing Chainlink in L2 chains like Arbitrum, it's important to ensure that the prices provided are not falsely perceived as fresh, even when the sequencer is down. This vulnerability could potentially be exploited by malicious actors to gain an unfair advantage.

## Vulnerability Detail
There is no check:
getPriceFromChainlink
```solidity
    function getPriceFromChainlink(address base, address quote) internal view returns (uint256) {
@>      (, int256 price,,,) = registry.latestRoundData(base, quote);
        require(price > 0, "invalid price");

        // Extend the decimals to 1e18.
        return uint256(price) * 10 ** (18 - uint256(registry.decimals(base, quote)));
    }
```


## Impact

could potentially be exploited by malicious actors to gain an unfair advantage.

## Code Snippet

https://github.com/sherlock-audit/2023-05-ironbank/blob/main/ib-v2/src/protocol/oracle/PriceOracle.sol#L66-L72

## Tool used

Manual 

*[Content truncated...]*

---

### Example 21: M-2: PriceOracle will use the wrong price if the Chainlink registry returns price outside min/max range

**Source**: Sherlock
**Protocol**: Iron Bank
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-ironbank-judging/issues/25 

## Found by 
0x52, 0x8chars, Angry\_Mustache\_Man, Bauchibred, BenRai, BugBusters, Jaraxxus, Madalad, R-Nemes, bitsurfer, branch\_indigo, deadrxsezzz, shaka, thekmj, tsvetanovv
## Summary

Chainlink aggregators have a built in circuit breaker if the price of an asset goes outside of a predetermined price band. The result is that if an asset experiences a huge drop in value (i.e. LUNA crash) the price of the oracle will continue to return the minPrice instead of the actual price of the asset. This would allow user to continue borrowing with the asset but at the wrong price. This is exactly what happened to [Venus on BSC when LUNA imploded](https://rekt.news/venus-blizz-rekt/).

## Vulnerability Detail

Note there is only a check for `price` to be non-negative, and not within an acceptable range.

```solidity
function getPriceFromChainlink(address base, address quote) internal view returns (uint256) {
    (, int256 price,,,) = registry.latestRoundData(base, quote);
    require(price > 0, "invalid price");

    // Extend the decimals to 1e18.
    return uint256(price) * 10 ** (18 - uint256(registry.decimals(base, quote)));
}
```
https://github.com/sherlock-audit/2023-05-ironbank/blob/main/ib-v2/src/protocol/oracle/PriceOracle.sol#L66-L72

A similar issue is seen [here](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18).

## Impact

The wrong price may be returned in the event of a 

*[Content truncated...]*

---

### Example 22: M-1: ControllerPeggedAssetV2: outdated price may be used which can lead to wrong depeg events

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

### Example 23: M-2: Chainlink's `latestRoundData` might return stale or incorrect results

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/137 

## Found by 
Jeiwan, csanuragjain, berndartmueller, jayphbee, joestakey, Olivierdem, Ruhum, GalloDaSballo, \_\_141345\_\_, Trumpero, ArbitraryExecution, hansfriese, ali\_shehab, cccz, 0xNazgul, ak1, ctf\_sec, minhquanym

## Summary

Chainlink's `latestRoundData()` is used but there is no check if the return value indicates stale data. This could lead to stale prices according to the Chainlink documentation:

- https://docs.chain.link/docs/historical-price-data/#historical-rounds

## Vulnerability Detail

The `PricerInternal._latestAnswer64x64` function uses Chainlink's `latestRoundData()` to get the latest price. However, there is no check if the return value indicates stale data.

## Impact

The `PricerInternal` could return stale price data for the underlying asset.

## Code Snippet

[PricerInternal.\_latestAnswer64x64](https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/pricer/PricerInternal.sol#L50-L52)

```solidity
/**
  * @notice gets the latest price of the underlying denominated in the base
  * @return price of underlying asset as 64x64 fixed point number
  */
function _latestAnswer64x64() internal view returns (int128) {
    (, int256 basePrice, , , ) = BaseSpotOracle.latestRoundData();
    (, int256 underlyingPrice, , , ) =
        UnderlyingSpotOracle.latestRoundData();

    return ABDKMath64x64.divi(underlyingPrice, basePrice);
}
```

## Tool Used

Manual revi

*[Content truncated...]*

---

### Example 24: M-12: chainlinkAdaptor uses the same heartbeat for both feeds which is highly dangerous

**Source**: Sherlock
**Protocol**: JOJO Exchange
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-jojo-judging/issues/449 

## Found by 
0x52, ast3ros
## Summary
chainlinkAdaptor uses the same heartbeat for both feeds when checking if the data feed is fresh. The issue with this is that the [USDC/USD](https://data.chain.link/ethereum/mainnet/stablecoins/usdc-usd) oracle has a 24 hour heartbeat, whereas the [average](https://data.chain.link/ethereum/mainnet/crypto-usd/eth-usd) has a heartbeat of 1 hour. Since they use the same heartbeat the heartbeat needs to be slower of the two or else the contract would be nonfunctional most of the time. The issue is that it would allow the consumption of potentially very stale data from the non-USDC feed.

## Vulnerability Detail

See summary

## Impact

Either near constant downtime or insufficient staleness checks

## Code Snippet

https://github.com/sherlock-audit/2023-04-jojo/blob/main/smart-contract-EVM/contracts/adaptor/chainlinkAdaptor.sol#L43-L55

## Tool used

Manual Review

## Recommendation

Use two separate heartbeat periods



## Discussion

**JoscelynFarr**

The contract are trying to get the latest price in here:https://github.com/sherlock-audit/2023-04-jojo/blob/main/smart-contract-EVM/contracts/adaptor/chainlinkAdaptor.sol#LL47C1-L47C1

And the heartbeat is trying to prevent chainlink stop updating. It is the same as chainlink's heartbeat.
https://docs.chain.link/data-feeds/price-feeds/addresses/?network=arbitrum#Arbitrum%20Mainnet

**iamjakethehuman**

Escalate for 10 U

*[Content truncated...]*

---

### Example 25: Insufficient Gas Limit Specification for Cross-Chain Transfers in _buildCCIPMessage() method. WrappedTokenBridge.sol #210

**Source**: Codehawks
**Protocol**: stake.link
**Impact**: LOW

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/549b2b8c4a5b841686fceb9c311dca9ac58225df/contracts/core/ccip/WrappedTokenBridge.sol#L157">https://github.com/Cyfrin/2023-12-stake-link/blob/549b2b8c4a5b841686fceb9c311dca9ac58225df/contracts/core/ccip/WrappedTokenBridge.sol#L157</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/549b2b8c4a5b841686fceb9c311dca9ac58225df/contracts/core/ccip/WrappedTokenBridge.sol#L210">https://github.com/Cyfrin/2023-12-stake-link/blob/549b2b8c4a5b841686fceb9c311dca9ac58225df/contracts/core/ccip/WrappedTokenBridge.sol#L210</a>


## Summary
The _buildCCIPMessage() function in the WrappedTokenBridge contract does not specify a gasLimit for the execution of the ccipReceive() function on the destination blockchain. This omission can lead to unpredictable gas costs and potential failure of the message processing due to out-of-gas errors.

## Vulnerability Details
The Client.EVM2AnyMessage struct created by _buildCCIPMessage() is used to define the details of a cross-chain message, including the tokens to be transferred and the receiver's address. However, the struct lacks a gasLimit field in the extraArgs, which is crucial for determining the maximum amount of gas that can be consumed when the ccipReceive() function is called on the destination chain.

Without a specified gasLimit, the default gas limit set by the CCIP router or the dest

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 25
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

