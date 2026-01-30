# Read-only Reentrancy Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Cyfrin, Spearbit, ConsenSys

---

## Detection Checklist

- [ ] Check for read-only reentrancy vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Read-only reentrancy

**Source**: Cyfrin
**Protocol**: Beanstalk Wells
**Impact**: HIGH

**Details**:

**Description:** The current implementation is vulnerable to read-only reentrancy, especially in [Wells::removeLiquidity](https://github.com/BeanstalkFarms/Wells/blob/e5441fc78f0fd4b77a898812d0fd22cb43a0af55/src/Well.sol#L440).
The implementation does not strictly follow the [Checks-Effects-Interactions (CEI) pattern](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) as it is setting the new reserve values after sending out the tokens. This is not an immediate risk to the protocol itself due to the `nonReentrant` modifier, but this is still vulnerable to [read-only reentrancy](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/).

Malicious attackers and unsuspecting ecosystem participants can deploy Wells with ERC-777 tokens (which have a callback that can take control) and exploit this vulnerability. This will lead to critical vulnerabilities given that the Wells are to be extended with price functions as defined by pumps - third-party protocols that integrate these on-chain oracles will be at risk.

Pumps are updated before token transfers; however, reserves are only set after. Therefore, pump functions will likely be incorrect on a re-entrant read-only call if `IWell(well).getReserves()` is called but reserves have not been correctly updated. The implementation of `GeoEmaAndCumSmaPump` appears not to be vulnerable, but given that each pump can choose its approach for recording a well's reserves over time, this remains a possible

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-06-16-Beanstalk wells.md)

---

### Example 2: H-13: `BalancerPairOracle` can be manipulated using read-only reentrancy

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

### Example 3: H-1: H-01 wstETH-ETH Curve LP Token Price can be manipulated to Cause Unexpected Liquidations

**Source**: Sherlock
**Protocol**: Sentiment Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-12-sentiment-judging/issues/7 

## Found by 
Bahurum, GalloDaSballo

## Summary

The wsteETH-ETH LP token is priced via it's [`virtual_price`](https://github.com/sherlock-audit/2022-12-sentiment/blob/main/oracle/src/curve/StableCurveEthOracle.sol#L72)

Through what [Chainalysis called View only Reentrancy](https://chainsecurity.com/heartbreaks-curve-lp-oracles/), we can reduce the value of `virtual_price`, causing the RiskEngine to trigger a liquidation event.

## Vulnerability Detail

Per some testing I made, we know that the Debt for such an account will be denominated in WETH, this price cannot be tampered.

However, the price of the ETH-wstETH LP Token can be manipulated by calling the RiskEngine while reEntering from the `POOL.remove_liquidity` function.

This is possible because the function will send ETH first, before updating it's internal wstETH balances.

To test the maximum impact I simulated borrowing an infinite amount of WETH (by impersonating the GMX Vault).

If that amount of ETH were available on Arbitrum, we can achieve over 10x in price suppression, effectively making any "normal" account instantly liquidatable.

The estimated cost of the attack is 60 BPS of the total ETH used (due to price impact)

## Impact

Because of the price manipulation, we can trigger unfair liquidations to our advantage, because the cost of manipulation is in the 50BPS range, any time a big enough deposit is made, it becomes profitable

*[Content truncated...]*

---

### Example 4: [M-03] Read-only reentrancy is possible

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/facets/Swapper.sol#L206> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/facets/Redeemer.sol#L131> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/savings/SavingsVest.sol#L110>

The agToken might be minted wrongly as rewards due to the reentrancy attack.

### Proof of Concept

There are `redeem/swap` logics in the `transmuter` contract and all functions don't have a `nonReentrant` modifier.

So the typical reentrancy attack is possible during `redeem/swap` as I mentioned in my other report.

But besides that, the read-only reentrancy attack is possible from the `SavingsVest` contract, and the agToken might be minted/burnt incorrectly like this.

1.  The [collatRatio](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/savings/SavingsVest.sol#L108) is `BASE_9(100%)` now and Alice starts a swap from collateral to agToken in `Swapper` contract.
2.  In `_swap()`, it mints the agToken after depositing the collaterals.

```solidity
    if (mint) {
        uint128 changeAmount = (amountOut.mulDiv(BASE_27, ts.normalizer, Math.Rounding.Up)).toUint128();
        // The amount of stablecoins issued from a collateral are not stored as absolute variables, but
        // as variables no

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 5: Balancer Read-Only Reentrancy Vulnerability (Changes from dev team added to audit.)

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Security Advisory

**Severity:** High Risk  
**Context:** CronV1Pool.sol#L1250  

**Description:**  
Balancer's read-only reentrancy vulnerability potentially affects the following Cron-Fi TWAMM functions:
- `getVirtualReserves`
- `getVirtualPriceOracle`
- `executeVirtualOrdersToBlock`  

A mitigation was provided by the Balancer team that uses a minimum amount of gas to trigger a reentrancy check. The Balancer vulnerability is discussed in greater detail [here](https://example.com/reentrancy-vulnerability-scope-expanded/4345).

**Recommendation:**  
Install the mitigation into the aforementioned methods, changing them to non-view functions, but documenting that they do not meaningfully modify state. If possible, confirm that the mitigation is not needed by testing the methods without it and removing it if shown to not be a problem.

**TWAMM:** Addressed in commit 5a529da.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 6: Potential Reentrancy Into Strategies

**Source**: ConsenSys
**Protocol**: EigenLabs — EigenLayer
**Impact**: MEDIUM

**Details**:

#### Resolution



*EigenLabs Quick Summary:* The `StrategyBase` contract may be vulnerable to a token contract that employs some sort of callback to a function like `sharesToUnderlyingView`, before the balance change is reflected in the contract. The shares have been decremented, which would lead to an incorrect return value from `sharesToUnderlyingView`.


*EigenLabs Response:* As noted in the report, this is not an issue if the token contract being used does not allow for reentrancy. For now, we will make it clear both in the contracts as well as the docs that our implementation of `StrategyBase.sol` does not support tokens with reentrancy. Because of the way our system is designed, anyone can choose to design a strategy with this in mind!




#### Description


The `StrategyManager` contract is the entry point for deposits into and withdrawals from strategies. More specifically, to deposit into a strategy, a staker calls `depositIntoStrategy` (or anyone calls `depositIntoStrategyWithSignature` with the staker’s signature) then the asset is transferred from the staker to the strategy contract. After that, the strategy’s `deposit` function is called, followed by some bookkeeping in the `StrategyManager`. For withdrawals (and slashing), the `StrategyManager` calls the strategy’s `withdraw` function, which transfers the given amount of the asset to the given recipient. Both token transfers are a potential source of reentrancy if the token allows it.


The `StrategyManager` us

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2023/03/eigenlabs-eigenlayer/)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

