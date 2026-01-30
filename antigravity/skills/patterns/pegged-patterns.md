# Pegged Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for pegged vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-07] Risk users are required to payout if the price of the pegged asset goes higher than underlying

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

Insurance is to protect the user in case the pegged asset drops significantly below the underlying but risk users are required to payout if the pegged asset is worth more than the underlying.

### Proof of Concept

        if (price1 > price2) {
            nowPrice = (price2 * 10000) / price1;
        } else {
            nowPrice = (price1 * 10000) / price2;
        }

The above lines calculates the ratio using the lower of the two prices, which means that in the scenario, the pegged asset is worth more than the underlying, a depeg event will be triggered. This is problematic for two reasons. The first is that many pegged assets are designed to maintain at least the value of the underlying. They put very strong incentives to keep the asset from going below the peg but usually use much looser policies to bring the asset down to the peg, since an upward break from the peg is usually considered benign. The second is that when a pegged asset moves above the underlying, the users who are holding the asset are benefiting from the appreciation of the asset; therefore the insurance is not needed.

Because of these two reasons, it is my opinion that sellers would demand a higher premium from buyers as a result of the extra risk introduced by the possibility of having to pay out during an upward depeg. It is also my opinion that these higher premiums would push users seeking insurance to other cheaper products that don't include this risk.

### Recommended Mitigation Steps

The ratio

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 2: M-6: Dangerous assumption on the peg of USDC can lead to manipulations

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/224 

## Found by 
Deivitto, yixxas, Jeiwan

## Summary
Dangerous assumption on the peg of USDC can lead to manipulations
## Vulnerability Detail
When pricing liquidity of a Velodrome USDC pool, it's assumed that hte price of USDC is exactly $1 ([DepositReceipt_USDC.sol#L100](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Velo-Deposit-Tokens/contracts/DepositReceipt_USDC.sol#L100), [DepositReceipt_USDC.sol#L123](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Velo-Deposit-Tokens/contracts/DepositReceipt_USDC.sol#L123)). However, in reality, there's no hard peg, the price can go both above or below $1 (https://coinmarketcap.com/currencies/usd-coin/).

The volatility of USDC will also affect the price of the other token in the pool since it's priced in USDC ([DepositReceipt_USDC.sol#L87](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Velo-Deposit-Tokens/contracts/DepositReceipt_USDC.sol#L87), [DepositReceipt_USDC.sol#L110](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Velo-Deposit-Tokens/contracts/DepositReceipt_USDC.sol#L110)) and then compared to its USD price from a Chainlink oracle ([DepositReceipt_USDC.sol#L90-L98](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Velo-Deposit-Tokens/contracts/DepositReceipt_USDC.sol#L90-L98)).

This issue is also applicable to the hard coded peg of sU

*[Content truncated...]*

---

### Example 3: [M-16] dETH / ETH / LPTokenETH can become depegged due to ETH 2.0 reward slashing

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

I want to quote the info from the doc:

> SavETH Vault - users can pool up to `24 ETH` where protected staking ensures no-loss. dETH can be redeemed after staking

and

> Allocate savETH <> dETH to `savETH Vault` (24 dETH)

However, the main risk in ETH 2.0 POS staking is the slashing penalty, in that case the ETH will not be pegged and the validator cannot maintain a minimum 32 ETH staking balance.

<https://cryptobriefing.com/ethereum-2-0-validators-slashed-staking-pool-error/>

### Recommended Mitigation Steps

We recommand the protocol to add mechanism to ensure the dETH is pegged via burning if case the ETH got slashed.

And consider when the node do not maintain a minmum 32 ETH staking balance, who is in charge of adding the ETH balance to increase the staking balance or withdraw the ETH and distribute the fund.

**Please note: the following comment occurred after judging and awarding were finalized.**

**[vince0656 (Stakehouse) disputed and commented](https://github.com/code-423n4/2022-11-stakehouse-findings/issues/164#issuecomment-1384355141):**
> There is no peg associated with dETH. Users can redeem underlying staked ETH by rage quitting Stakehouse protocol. This is taken care of by the Stakehouse protocol through SLOT (which protects) dETH due to redemption rate mechanics and further special exit penalty. Please see audit reports for Stakehouse:<br>
> Audit report 1: https://github.com/runtimeverification/publications/blob/main/reports/smart-contracts/Blockswap_Sta

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 4: M-9: Price disparities between spot and perpetual pricing can heavily destabilize UXD

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/305 

## Found by 
0x52

## Summary

When minting UXD using PerpDepository.sol the amount of UXD minted corresponds to the amount of vUSD gained from selling the deposited ETH. This is problematic given that Perp Protocol is a derivative rather than a spot market, which means that price differences cannot be directly arbitraged with spot markets. The result is that derivative markets frequently trade at a price higher or lower than the spot price. The result of this is that UXD is actually pegged to vUSD rather than USD. This key difference can cause huge strain on a USD peg and likely depegging. 

## Vulnerability Detail

    function deposit(
        address asset,
        uint256 amount
    ) external onlyController returns (uint256) {
        if (asset == assetToken) {
            _depositAsset(amount);
            (, uint256 quoteAmount) = _openShort(amount);
            return quoteAmount; // @audit this mint UXD equivalent to the amount of vUSD gained
        } else if (asset == quoteToken) {
            return _processQuoteMint(amount);
        } else {
            revert UnsupportedAsset(asset);
        }
    }

PerpDepository#deposit shorts the deposit amount and returns the amount of vUSD resulting from the swap, which effectively pegs it to vUSD rather than USD. When the perpetual is trading at a premium arbitrage will begin happening between the spot and perpetual asset and the profit will be ta

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

