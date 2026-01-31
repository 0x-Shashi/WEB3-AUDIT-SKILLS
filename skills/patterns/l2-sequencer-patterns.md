---
id: PAT-L2-SEQUENCER
title: L2 Sequencer Security Patterns
category: layer2
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - l2
  - sequencer
  - bridge

finding_count: 6
last_updated: 2026-01-31
---
# L2 Sequencer Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 6 | 0 | 0 |

**Common Sources**: Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for l2 sequencer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Missing L2 sequencer uptime check in `OracleAdapter`

**Source**: Cyfrin
**Protocol**: Yieldfi
**Impact**: MEDIUM

**Details**:

**Description:** On L2, the `YToken` exchange rate is provided by custom Chainlink oracles. The exchange rate is queried in [`OracleAdapter::fetchExchangeRate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/OracleAdapter.sol#L52-L77):

```solidity
function fetchExchangeRate(address token) external view override returns (uint256) {
    address oracle = oracles[token];
    require(oracle != address(0), "Oracle not set");

    (, /* uint80 roundId */ int256 answer, , /* uint256 startedAt */ uint256 updatedAt /* uint80 answeredInRound */, ) = IOracle(oracle).latestRoundData();

    require(answer > 0, "Invalid price");
    require(updatedAt > 0, "Round not complete");
    require(block.timestamp - updatedAt < staleThreshold, "Stale price");

    // Get decimals and normalize to 1e18 (PINT)
    uint8 decimals = IOracle(oracle).decimals();

    if (decimals < 18) {
        return uint256(answer) * (10 ** (18 - decimals));
    } else if (decimals > 18) {
        return uint256(answer) / (10 ** (decimals - 18));
    } else {
        return uint256(answer);
    }
}
```

However, this protocol is intended to be deployed on L2 networks such as Arbitrum and Optimism, where it's important to verify that the [sequencer is up](https://docs.chain.link/data-feeds/l2-sequencer-feeds). Without this check, if the sequencer goes down, the latest round data may appear fresh, when in fact it is stale, for advanced users submitting transactions

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### Example 2: M-4: No check for active Arbitrum Sequencer in WSTETH Oracle

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

### Example 3: M-3: _validateAndGetPrice() doesn't check If Arbitrum sequencer is down in Chainlink feeds

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

### Example 4: M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/82 

## Found by 
ctf\_sec, qandisa
## Summary

Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

## Vulnerability Detail

In the current implementation, if the option token expires, the user is not able to [exerise the option at strike price](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L336)

```solidity
    // Validate that option token is not expired
        if (uint48(block.timestamp) >= expiry) revert Teller_OptionExpired(expiry);
```

if the option token expires, the user lose rewards from OTLM as well when [claim the reward](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/liquidity-mining/OTLM.sol#L496)

```solidity
    function _claimRewards() internal returns (uint256) {
        // Claims all outstanding rewards for the user across epochs
        // If there are unclaimed rewards from epochs where the option token has expired, the rewards are lost

        // Get the last epoch claimed by the user
        uint48 userLastEpoch = lastEpochClaimed[msg.sender];

```

and

```solidity
    // If the option token has expired, then the rewards are zero
        if (uint256(optionToken.expiry()) < block.timestamp) return 0;
```

And in the onchain context, the protocol intends to deploy the contract in arbitr

*[Content truncated...]*

---

### Example 5: M-3: No check for sequencer uptime can lead to dutch auctions executing at bad prices

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/40 

## Found by 
0x52
## Summary

When purchasing from dutch auctions on L2s there is no considering of sequencer uptime. When the sequencer is down, all transactions must originate from the L1. The issue with this is that these transactions use an aliased address. Since the set token contracts don't implement any way for these aliased addressed to interact with the protocol, no transactions can be processed during this time even with force L1 inclusion. If the sequencer goes offline during the the auction period then the auction will continue to decrease in price while the sequencer is offline. Once the sequencer comes back online, users will be able to buy tokens from these auctions at prices much lower than market price.

## Vulnerability Detail

See summary.

## Impact

Auction will sell/buy assets at prices much lower/higher than market price leading to large losses for the set token

## Code Snippet

[AuctionRebalanceModuleV1.sol#L772-L836](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L772-L836)

## Tool used

Manual Review

## Recommendation

Check sequencer uptime and invalidate the auction if the sequencer was ever down during the auction period



## Discussion

**pblivin0x**

What exactly is the remediation here? To check an external uptime feed https://docs.chain.link/data-feeds/l2-sequencer-feeds ?

Not sur

*[Content truncated...]*

---

### Example 6: M-13: Missing checks for whether Arbitrum Sequencer is active

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/142 

## Found by 
0xepley, Bauchibred, Bauer, Brenzee, J4de, ctf\_sec, deadrxsezzz, tallo, tsvetanovv
## Summary

Missing checks for whether Arbitrum Sequencer is active

## Vulnerability Detail

the onchain deployment context is changed, in prev contest the protocol only attemps to deploy the code to ethereum while in the current contest

the protocol intends to deploy to arbtrium as well!

Chainlink recommends that users using price oracles, check whether the Arbitrum sequencer is active

https://docs.chain.link/data-feeds#l2-sequencer-uptime-feeds

If the sequencer goes down, the index oracles may have stale prices, since L2-submitted transactions (i.e. by the aggregating oracles) will not be processed.

## Impact

Stale prices, e.g. if USDC were to de-peg while the sequencer is offline, stale price is used and can result in false liquidation or over-borrowing.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L76-L98

## Tool used

Manual Review

## Recommendation

Use sequencer oracle to determine whether the sequencer is offline or not, and don't allow orders to be executed while the sequencer is offline.

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

