---
id: PAT-FLASH-LOAN
title: Flash Loan Security Patterns
category: flash-loan
severity: high
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - atomic
  - liquidity
  - arbitrage

finding_count: 25
last_updated: 2026-01-31
---
# Flash Loan Security Patterns

## Overview

**Frequency**: 25 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 16 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Shieldify, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for flash loan vulnerabilities in all external functions
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

### Example 2: Attacker can combine flashloan with delegated voting to decide a proposal and withdraw their tokens while the proposal is still in Locked state

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can combine a flashloan with delegated voting to bypass the existing flashloan mitigations, allowing the attacker to decide a proposal & withdraw their tokens while the proposal is still in the Locked state. The entire attack can be performed in 1 transaction via an attack contract.

**Impact:** Attacker can bypass existing flashloan mitigations to decide the outcome of proposals by combining flashloan with delegated voting.

**Proof of Concept:** Add the attack contract to `mock/utils/FlashDelegationVoteAttack.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../../interfaces/gov/IGovPool.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract FlashDelegationVoteAttack {
    //
    // how the attack contract works:
    //
    // 1) use flashloan to acquire large amount of voting tokens
    //    (caller transfer tokens to contract before calling to simplify PoC)
    // 2) deposit voting tokens into GovPool
    // 3) delegate voting power to slave contract
    // 4) slave contract votes with delegated power
    // 5) proposal immediately reaches quorum and moves into Locked state
    // 6) undelegate voting power from slave contract
    //    since undelegation works while Proposal is in locked state
    // 7) withdraw voting tokens from GovPool while proposal still in Locked state
    // 8) all in 1 txn
    //

    function attack(address govPoolAddress, address tokenAddress, uint256 proposalId) ext

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 3: [H-05] Vault treats all tokens exactly the same that creates (huge) arbitrage opportunities.

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

_Submitted by jonah1005, also found by cmichel and itsmeSTYJ_

#### Impact
The v3 vault treats all valid tokens exactly the same. Depositing 1M DAI would get the same share as depositing 1M USDT. User can withdraw their share in another token. Though there's `withdrawalProtectionFee` (0.1 percent), the vault is still a no slippage stable coin exchange.

Also, I notice that 3crv_token is added to the vault in the test. Treating 3crv_token and all other stable coins the same would make the vault vulnerable to flashloan attack. 3crv_token is an lp token and at the point of writing, the price of it is 1.01. The arbitrage space is about 0.8 percent and makes the vault vulnerable to flashloan attacks.

Though the team may not add crv_token and dai to the same vault, its design makes the vault vulnerable. Strategies need to be designed with super caution or the vault would be vulnerable to attackers.

Given the possibility of a flashloan attack, I consider this a high-risk issue.

#### Proof of Concept
The issue locates at the deposit function ([Vault.sol#L147-L180](https://github.com/code-423n4/2021-09-yaxis/blob/main/contracts/v3/Vault.sol#L147-L180)).
The share is minted according to the calculation here

```solidity
_shares = _shares.add(_amount);
```

The share is burned at [Vault.sol L217](https://github.com/code-423n4/2021-09-yaxis/blob/main/contracts/v3/Vault.sol#L217)
```solidity
uint256 _amount = (balance().mul(_shares)).div(totalSupply());
```

Here's a sample exploit in 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 4: H-1: Pool can be drained

**Source**: Sherlock
**Protocol**: WOOFi Swap
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/68 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
## Summary
The pool can be drained just as it was during the incident that occurred previously.
## Vulnerability Detail
`maxNotionalSwap` and `maxGamma` and the new math formula do not prevent the pool being drainable. Same attack vector that happent previously is still applicable:
https://woo.org/blog/en/woofi-spmm-exploit-post-mortem
https://rekt.news/woo-rekt/

Flashloan 99989999999999999990000 (99_990) WOO
Sell WOO partially (in 10 pieces) assuming maxGamma |maxNotionalSwap doesnt allow us to do it in one go
Sell 20 USDC and get 199779801821639475527975 (199_779) WOO
Repay flashloan, pocket the rest of the 100K WOO.

**Coded PoC:**
```solidity
function test_Exploit() public {
        // Flashloan 99989999999999999990000 (99_990) WOO
        // Sell WOO partially (in 10 pieces) assuming maxGamma |maxNotionalSwap doesnt allow us to do it in one go
        // Sell 20 USDC and get 199779801821639475527975 (199_779) WOO
        // Repay flashloan, pocket the rest of the 100K WOO. 

        // Reference values: 
        // s = 0.1, p = 1, c = 0.0001 

        // bootstrap the pool 
        uint usdcAmount = 100_0000_0_0000000000000_000;
        deal(USDC, ADMIN, usdcAmount);
        deal(WOO, ADMIN, usdcAmount);
        deal(WETH, ADMIN, usdcAmount);
        vm.startPrank(ADMIN);
        IERC20(USDC).approve(address(pool), typ

*[Content truncated...]*

---

### Example 5: H-13: `BalancerPairOracle` can be manipulated using read-only reentrancy

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

### Example 6: [H-03] Users Can Use `Flashloan` to Increase Voting Power of Expired Positions and Execute Proposal for Their Benefits

**Source**: Shieldify
**Protocol**: Guanciale Stake
**Impact**: HIGH

**Details**:

## Severity

High Risk

## Description

If we assume the Medium-01 from the report is fixed in the `increaseAndStake()` function which allows users to add the amount to their stake without updating the lock duration then the below scenario might be executable:

- Assume Alice's `lockUntil` reached the current `block.timestamp`.

- Alice got a huge flashloan of GUAN token (can get another token as flashloan and then swap it to GUAN) and called the `increaseAndStake()` function with the flashloan amount.

- If we assume the Medium-01 issue is fixed then the transaction will be executed without reverting since Alice increased the stake amount only.

- The `veGUAN` core logic allows the stakes to have voting power depending on their stake amount even if the lock duration expired, this is clearly shown in the function below:

```solidity
function _calculateVotingPower(
  UD60x18 votingPowerCurveAFactorX18,
  UD60x18 remainingLockDurationX18,
  UD60x18 positionStakeX18
)
  internal
  pure
  returns (uint256 scalingFactor, uint256 votingPower)
{
  // calculate the lock multiplier as explained in the function's natspec
  UD60x18 scalingFactorX18 = votingPowerCurveAFactorX18.mul(remainingLockDurationX18).add(UNIT); // @audit 1e18 get added even if the calc = 0

  // return the scaling factor and voting power
  scalingFactor = scalingFactorX18.intoUint256();
  votingPower = positionStakeX18.mul(scalingFactorX18).intoUint256();
}
```

- This way Alice can have huge voting power due to h

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Guanciale-Stake-Security-Review.md)

---

### Example 7: [H-05] V3Proxy swapTokensForExactETH does not send back to the caller the unused input tokens

**Source**: Code4rena
**Protocol**: Good Entry
**Impact**: HIGH

**Details**:

The `V3Proxy` `swapTokensForExactETH` function swaps an unspecified amount of a given ERC-20 for a specified amount of the native currency. After the swap happens, however, the difference between the amount taken from the caller (`amountInMax`) and the actual swapped amount (`amounts[0]`) is not given back to the caller and remains locked in the contract.

### Impact

Any user of the `swapTokensForExactETH` will always pay `amountInMax` for swaps even if part of it was not used for the swap. This part is lost, locked in the `V3Proxy` contract.

### Proof of Concept

*   Call `swapTokensForExactETH` with an excessively high `amountInMax`
*   Check that any extra input tokens are sent back - this check will fail

```Solidity
    function testV3ProxyKeepsTheChange() public {
        IQuoter q = IQuoter(0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6);
        ISwapRouter r = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);

        V3Proxy v3proxy = new V3Proxy(r, q, 500);
        vm.label(address(v3proxy), "V3Proxy");

        address[] memory path = new address[](2);
        path[0] = address(USDC);
        path[1] = address(WETH);

        address[] memory path2 = new address[](2);
        path2[0] = address(WETH);
        path2[1] = address(USDC);


        // fund Alice
        vm.prank(tokenWhale);
        USDC.transfer(alice, 1870e6);

        // Alice initiates a swap
        uint256[] memory amounts; 
        uint256 balanceUsdcBefore = USDC.balanceOf(alice);
       

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-goodentry)

---

### Example 8: [H-04] TokenisableRange's incorrect accounting of non-reinvested fees in "deposit" exposes the fees to a flash-loan attack

**Source**: Code4rena
**Protocol**: Good Entry
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-08-goodentry/blob/71c0c0eca8af957202ccdbf5ce2f2a514ffe2e24/contracts/TokenisableRange.sol#L190>

<https://github.com/code-423n4/2023-08-goodentry/blob/71c0c0eca8af957202ccdbf5ce2f2a514ffe2e24/contracts/TokenisableRange.sol#L268>

### Vulnerability details

The `TokenisableRange` is designed to always collect trading fees from the Uniswap V3 pool, whenever there is a liquidity event (`deposit` or `withdraw`). These fees may be reinvested in the pool, or may be held in form of `fee0` and `fee1` ERC-20 balance held by the TokenisableRange contract.

When a user deposits liquidity in the range, they pay asset tokens, and receive back liquidity tokens, which give them a share of the TokenisableRange assets (liquidity locked in Unisvap V3, plus fee0, and fee1).

To prevent users from stealing fees, there are several mechanisms in place:

1.  fees are, as said, always collected whenever liquidity is added or removed, and whenever they exceed 1% of the liquidity in the pool, they are re-invested in Uniswap V3. The intention of this check seems to be limiting the value locked in these fees
2.  whenever a user deposits liquidity to the range, the LP tokens given to them are scaled down by the value of the fees, so the participation in fees "is not given away for free"

Both of these mechanisms can however be worked around:

1.  the 1% check is done on the `fee0` and `fee1` **amounts** compared to the theoretical pool amounts, and **not on the total v

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-goodentry)

---

### Example 9: [H-02] CurveVolatileCollateral Collateral status can be manipulated by flashloan attack

**Source**: Code4rena
**Protocol**: Reserve
**Impact**: HIGH

**Details**:

Attacker can make the CurveVolatileCollateral enter the status of IFFY/DISABLED. It will cause the basket to rebalance and sell off all the CurveVolatileCollateral.

### Proof of Concept

The `CurveVolatileCollateral` overrides the `_anyDepeggedInPool` function to check if the distribution of capital is balanced. If the any part of underlying token exceeds the expected more than `_defaultThreshold`, return true, which means the volatile pool has been depeg:

```solidity
uint192 expected = FIX_ONE.divu(nTokens); // {1}
for (uint8 i = 0; i < nTokens; i++) {
    uint192 observed = divuu(vals[i], valSum); // {1}
    if (observed > expected) {
        if (observed - expected > _defaultThreshold) return true;
    }
}
```

And the coll status will be updated in the super class `CurveStableCollateral.refresh()`:

    if (low == 0 || _anyDepeggedInPool() || _anyDepeggedOutsidePool()) {
        markStatus(CollateralStatus.IFFY);
    }

The attack process is as follows:

1.  Assumption: There is a CurveVolatileCollateral bases on a TriCrypto ETH/WBTC/USDT, and the value of them should be 1:1:1, and the `_defaultThreshold` of the CurveVolatileCollateral is 5%. And at first, there are 1000 USDT in the pool and the pool is balanced.

2.  The attacker uses flash loan to deposit 500 USDT to the pool. Now, the USDT distribution is `1500/(1500+1000+1000) = 42.86%`.

3.  Attacker refresh the CurveVolatileCollateral. Because the USDT distribution \- expected = 42.86% \- 33.33% = 9.53% > 5% \_def

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-reserve)

---

### Example 10: [M-03] Flashloan fee collection mechanism can be easily manipulated

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: MEDIUM

**Details**:

[`LBPair.flashLoan()`](https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBPair.sol#L415-L456) utilizes an unfair fee mechanism in which the whole pair liquidity can be loaned but only the liquidity providers of the active bin receive the fees. Although one can argue that this unfair structure is to incentivize greater liquidity around the active price range, it nonetheless opens up a way to easily manipulate fees. The current structure allows a user to provide liquidity to an active bin right before a flashloan to receive most of the fees. This trick can be used both by the borrower themselves, or by a third party miner or a node operator frontrunning the flashloan transactions. In either case, this is in detriment to the liquidity providers, who would be providing the bulk of the flashloan, but receiving a much less fraction of the fees.

### Proof of Concept

`LBPair.flashLoan()` function [enables borrowing the entire balance of a pair](https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBPair.sol#L435-L436).

```solidity
        tokenX.safeTransfer(_to, _amountXOut);
        tokenY.safeTransfer(_to, _amountYOut);
```

This means that a liquidity providers tokens can be used regardless of which bin their liquidity is in. However, the loan fee [is only paid to the active bins liquidity providers](https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 11: H-1: MarginTrading.sol: Missing flash loan initiator check allows attacker to open trades, close trades and steal funds

**Source**: Sherlock
**Protocol**: DODO Margin Trading
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-dodo-judging/issues/34 

## Found by 
0xHati, BAHOZ, Bauer, BowTiedOriole, CRYP70, Jiamin, Juntao, Quantish, Tendency, VAD37, alexzoid, carrotsmuggler, circlelooper, curiousapple, nobody2018, oot2k, pengun, qbs, roguereddwarf, rvierdiiev, sashik\_eth, shaka, shogoki, smiling\_heretic, theOwl
## Summary
The `MarginTrading.executeOperation` function is called when a flash loan is made (and it can only be called by the `lendingPool`).

The wrong assumption by the protocol is that the flash loan can only be initiated by the `MarginTrading` contract itself.

However this is not true. A flash loan can be initiated for any `receiverAddress`.

This is actually a known mistake that devs make and the aave docs warn about this (although admittedly the warning is not very clear):
https://docs.aave.com/developers/v/2.0/guides/flash-loans

![2023-05-11_12-43](https://github.com/sherlock-audit/2023-05-dodo-roguereddwarf/assets/118631472/1bc59eb4-407b-4b5f-a38b-9c415932caf1)

So an attacker can execute a flash loan with the `MarginTrading` contract as `receiverAddress`. Also the funds that are needed to pay back the flash loan are pulled from the `receiverAddress` and NOT from the `initiator`:

https://github.com/aave/protocol-v2/blob/30a2a19f6d28b6fb8d26fc07568ca0f2918f4070/contracts/protocol/lendingpool/LendingPool.sol#L532-L536

This means the attacker can close a position or repay a position in the `MarginTrading` contract.

By crafting a

*[Content truncated...]*

---

### Example 12: UNI_V3Validator fetches spot prices that may lead to price manipulation attacks

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

### Example 13: M-10: ERC4626Oracle Vulnerable To Price Manipulation

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

### Example 14: [H-06] LPs of VaderPoolV2 can manipulate pool reserves to extract funds from the reserve.

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

## Handle

TomFrenchBlockchain


## Vulnerability details

(Resubmission as the form crashed apologies if this is a duplicate)

## Impact
Impermanent loss protection can be exploited to drain the reserve.

## Proof of Concept
In `VaderPoolV2.burn` we calculate the current losses that the LP has made to impermanent loss.

https://github.com/code-423n4/2021-12-vader/blob/fd2787013608438beae361ce1bb6d9ffba466c45/contracts/dex-v2/pool/VaderPoolV2.sol#L265-L296

These losses are then refunded to the LP in VADER tokens from the reserve.

https://github.com/code-423n4/2021-12-vader/blob/fd2787013608438beae361ce1bb6d9ffba466c45/contracts/dex-v2/router/VaderRouterV2.sol#L220

This loss is calculated by the current reserves of the pool so if an LP can manipulate the pool's reserves they can artificially engineer a huge amount of IL in order to qualify for a payout up to the size of their LP position.

https://github.com/code-423n4/2021-12-vader/blob/fd2787013608438beae361ce1bb6d9ffba466c45/contracts/dex/math/VaderMath.sol#L72-L92

The attack is then as follows.
1. Be an LP for a reasonable period of time (IL protection scales linearly up to 100% after a year)
2. Flashloan a huge amount of one of the pool's assets.
3. Trade against the pool with the flashloaned funds to unbalance it such that your LP position has huge IL.
4. Remove your liquidity and receive compensation from the reserve for the IL you have engineered.
5. Re-add your liquidity back to the pool.
6. Trade against the pool

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-vader)

---

### Example 15: M-7: Gain From Balancer Vaults Can Be Stolen

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/83 

## Found by 
xiaoming90

## Summary

The BPT gain (rewards) of the vault can be stolen by an attacker.

## Vulnerability Detail

At T0 (Time 0), assume that the state of the WETH/wstETH MetaPool Vault is as follows:

- totalBPTHeld = 1000 BPT
- totalStrategyTokenGlobal = 1000
- 1 Strategy Token can claim 1 BPT
- Alice holds 1000 Strategy Tokens, and she is the only person invested in the vault at this point in time

Assume that if the `reinvestReward` is called, it will reinvest 1000 BPT back into the vault. Thus, if the `reinvestReward` is called, the `totalBPTHeld ` of the vault will become 2000 BPT.

Following is the description of the attack:

1. The attacker notice that if the `reinvestReward` is called, it will result in a large increase in the total BPT held by the vault
2. The attacker flash-loan a large amount of WETH (e.g. 1,000,000) from a lending protocol (e.g. dydx)
3. Enter the vault by depositing 1,000,000 WETH by calling the `VaultAccountAction.enterVault` function. However, do not borrow any cash from Notional by setting the `fCash` parameter of the `VaultAccountAction.enterVault` function to `0`.
4. There is no need to borrow from Notional as the attacker could already flash-loan a large amount of WETH with a non-existence fee rate (e.g. 1 Wei in dydx). Most importantly, the vault fee will only be charged if the user borrows from Notional. The fee is assessed within the `VaultAcco

*[Content truncated...]*

---

### Example 16: H-1: Flashloan `TEL` tokens to stake and exit in the same block can fake a huge amount of stake with minimal material cost

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/83 

## Found by 
WATCHPUG

## Summary

`Checkpoints#getAtBlock()` can be faked with falshloan as it may return the value of the first checkpoint in the same block.

## Vulnerability Detail

`Checkpoints#getAtBlock()` will return the value on check point #0 when there are two check points in the same block (#0 and #1).

Therefore, one can take a falshloan of TEL tokens to stake and exit in the same block, which will create two checkpoints.

## Impact

Malicious user can fake their stake to gain a high percentage rewards with falshloan and avoid slashing.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L147-L149

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L403-L406

## Tool used

Manual Review

## Recommendation

Consider requiring the `exit` to be at least 1 block later than the blocknumber of the original stake.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/9

---

### Example 17: [H-03] Vaults with non-UST underlying asset vulnerable to flash loan attack on curve pool

**Source**: Code4rena
**Protocol**: Sandclock
**Impact**: HIGH

**Details**:

_Submitted by camden, also found by cccz, cmichel, danb, defsec, harleythedog, hyh, kenzo, leastwood, palina, pauliax, pmerkleplant, Ruhum, WatchPug, and ye0lde_

In short, the `NonUSTStrategy` is vulnerable to attacks by flash loans on curve pools.

Here's an outline of the attack:

*   Assume there is a vault with DAI underlying and a `NonUSTStrategy` with a DAI / UST curve pool
*   Take out a flash loan of DAI
*   Exchange a ton of DAI for UST
*   The exchange rate from DAI to UST has gone up (!!)
*   Withdraw or deposit from vault with more favorable terms than market
*   Transfer back UST to DAI
*   Repay flash loan

#### Proof of Concept

Here is my proof of concept:
<https://gist.github.com/CamdenClark/932d5fbeecb963d0917cb1321f754132>

I can provide a full forge repo. Just ping me on discord.

Exploiting this line: <https://github.com/code-423n4/2022-01-sandclock/blob/a90ad3824955327597be00bb0bd183a9c228a4fb/sandclock/contracts/strategy/NonUSTStrategy.sol#L135>

#### Tools Used

Forge

#### Recommended Mitigation Steps

Use an oracle

**[naps62 (Sandclock) confirmed](https://github.com/code-423n4/2022-01-sandclock-findings/issues/7)**

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-sandclock)

---

### Example 18: [M-02] All yield generated in the IBT vault can be drained by performing a vault deflation attack using the flash loan functionality of the Principal Token contract

**Source**: Code4rena
**Protocol**: Spectra
**Impact**: MEDIUM

**Details**:

The current implementation of the `PrincipalToken` has a flash lending functionality:

```solidity
    function flashLoan(
        IERC3156FlashBorrower _receiver,
        address _token,
        uint256 _amount,
        bytes calldata _data
    ) external override returns (bool) {
        if (_amount > maxFlashLoan(_token)) revert FlashLoanExceedsMaxAmount();

        uint256 fee = flashFee(_token, _amount);
        _updateFees(fee);

        // Initiate the flash loan by lending the requested IBT amount
        IERC20(ibt).safeTransfer(address(_receiver), _amount);

        // Execute the flash loan
        if (_receiver.onFlashLoan(msg.sender, _token, _amount, fee, _data) != ON_FLASH_LOAN)
            revert FlashLoanCallbackFailed();

        // Repay the debt + fee
        IERC20(ibt).safeTransferFrom(address(_receiver), address(this), _amount + fee);

        return true;
    }
```

And as of now, this functionality is implemented in such a way, that it allows users to borrow the whole IBT balance of the `PrincipalToken` permissionlessly:

```solidity
    function maxFlashLoan(address _token) public view override returns (uint256) {
        if (_token != ibt) {
            return 0;
        }
        // Entire IBT balance of the contract can be borrowed
        return IERC4626(ibt).balanceOf(address(this));
    }
```

This is fine on it's own and it works as it should. However there is a specific case where it can be abused. If the IBT vault prices its shares using the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-spectra)

---

### Example 19: [M-16] PrivatePool.flashLoan() takes fee from the wrong address

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L623


## Vulnerability details

## Impact
Instead of taking the fee from the receiver of the flashloan callback, it pulls it from `msg.sender`.

As specified in [EIP-3156](https://eips.ethereum.org/EIPS/eip-3156#lender-specification):
> After the callback, the flashLoan function MUST take the amount + fee token from the receiver, or revert if this is not successful.

This will be an unexpected loss of funds for the caller if they have the pool pre-approved to spend funds (e.g. they previously bought NFTs) and are not the owner of the flashloan contract they use for the callback.

Additionally, for ETH pools, it expects the caller to pay the fee upfront. But, the fee is generally paid with the profits made using the flashloaned tokens.

## Proof of Concept
If `baseToken` is ETH, it expects the fee to already be sent with the call to `flashLoan()`. If it's an ERC20 token, it will pull it from `msg.sender` instead of `receiver`:
```sol
    function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 tokenId, bytes calldata data)
        external
        payable
        returns (bool)
    {
        // ...

        // calculate the fee
        uint256 fee = flashFee(token, tokenId);

        // if base token is ETH then check that caller sent enough for the fee
        if (baseToken == address(0) && msg.value < fee) revert InvalidEthAmount();
        
        // ...

        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 20: [M-15] Pool tokens can be stolen via PrivatePool.flashLoan function from previous owner

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L461
https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L623-L654


## Vulnerability details

## Impact
`PrivatePool.sol` ERC721 and ERC20 tokens can be stolen by the previous owner via `execute` and `flashLoan` functions (or by malicious approval by the current owner via `execute`)

## Proof of Concept
Let's say that Bob is the attacker and Alice is a regular user.

1.Bob creates a `PrivatePool.sol` where he deposits 5 ERC721 tokens and 500 USDC.
2.Then Bob creates a malicious contract (let's call it `PrivatePoolExploit.sol`) and this contract contains `onFlashLoan` (IERC3156FlashBorrower), `transferFrom` ,`ownerOf`, `onERC721Received` functions (like ERC721 does) and an additional `attack` function.
3.Via `PrivatePool.execute` function Bob approves USDC spending (`type(uint).max`) and `setApprovalForAll` for ERC721 tokens
4.Since the ownership of `PrivatePool` is stored in `Factory.sol` as an ERC721 token, ownership can be sold on any ERC721 marketplace. Alice decides to buy Bob's `PrivatePool` and ownership is transferred to Alice.
5.Right after the ownership is transferred, Bob runs `PrivatePoolExploit.attack` function, which calls `PrivatePool.flashLoan` where `PrivatePoolExploit.transferFrom` will be called since the flash loan can be called on any address.
6. All the funds are stolen by Bob and Alice's`PrivatePool` is left with nothing.

### Here is a 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 21: [M-12] Prohibition to create private pools with the factory NFT

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L157>

<https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L623>

<https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L514>

### Impact

Any [Factory NFTs](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L37) deposited into a Factory-PrivatePool can have all assets in the corresponding PrivatePools stolen by malicious users.

### Proof of Concept

Suppose there are two PrivatePools p1 and p2, `p1.nft = address(Factory)`, and `uint256(p1)` and `uint256(p2)` are deposited into p1.<br>
Malicious users can use [flashloan()](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L623) to steal all the base tokens in p1 and p2:

1.  Call `p1.flashloan()` to borrow the Factory NFT - `uint256(p1)` from p1.
2.  In the flashloan callback, call `p1.withdraw()` to withdraw all the base tokens and the factory NFT - `uint256(p2)` from p1.
3.  Return `uint256(p1)` to p1.

Suppose there are two PrivatePools p1 and p2, `p1.nft = address(Factory)`, and `uint256(p2)` is deposited into p1.<br>
Malicious users can use [flashloan()](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L623) to steal 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 22: H-9: Uniswap v3 pool token balance proportion does not necessarily correspond to the price, and it is easy to manipulate.

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/808 

## Found by 
0xRan4212, Bahurum, VAD37, WATCHPUG, curiousapple, mahdikarimi, n33k, nobody2018, simon135
## Summary

`getSupplyProportion()` retrieves Uniswap v3 pool balances, but the proportion of pool tokens doesn't always correspond to the price. If `ownval` is less than `1e6 - threshold`, `USSDamount` may be lower than `DAIamount`, causing L97 `USSDamount - DAIamount` to revert due to underflow. Proportion can be easily manipulated, which can be exploited by attackers.

## Vulnerability Detail

`getSupplyProportion()` retrieves the balances of the Uniswap v3 pool. However, due to the different designs of Uniswap v3 and Uniswap v2, the proportion of pool tokens does not necessarily correspond to the price.

As a result, if `ownval` is less than `1e6 - threshold` (e.g. 0.95), `USSDamount` may be lower than `DAIamount`, causing L97 `USSDamount - DAIamount` to revert due to underflow.

Additionally, the pool contract holds accumulative fees on its balances, which are not impacted by price changes.

---

Furthermore, the proportion can be easily manipulated with minimal cost, which can be exploited by attackers.

If the price of USSD goes over-peg (which can happen naturally), an attacker can take advantage by following these steps:

1. Add single leg liquidity of DAI to the DAI/USSD pool at an exorbitantly high price range, such as 1 DAI == 1000-2000 USSD.
2. Manipulate the price of the collateral ass

*[Content truncated...]*

---

### Example 23: H-5: ConvexSpell#closePositionFarm removes liquidity without any slippage protection

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/124 

## Found by 
0x52, Breeje, Ch\_301, n1punp
## Summary

ConvexSpell#closePositionFarm removes liquidity without any slippage protection allowing withdraws to be sandwiched and stolen. Curve liquidity has historically been strong but for smaller pairs their liquidity is getting low enough that it can be manipulated via flashloans. 

## Vulnerability Detail

[ConvexSpell.sol#L204-L208](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L204-L208)

            ICurvePool(pool).remove_liquidity_one_coin(
                amountPosRemove,
                int128(tokenIndex),
                0
            );

Liquidity is removed as a single token which makes it vulnerable to sandwich attacks but no slippage protection is implemented. The same issue applies to CurveSpell.

## Impact

User withdrawals can be sandwiched

## Code Snippet

[ConvexSpell.sol#L147-L230](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L147-L230)

[CurveSpell.sol#L143-L223](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/CurveSpell.sol#L143-L223)

## Tool used

Manual Review

## Recommendation

Allow user to specify min out

---

### Example 24: H-4: Potential flash loan attack vulnerability in `getPrice` function of CurveOracle

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/123 

## Found by 
Bauer, helpMePlease
## Summary
During a security review of the `getPrice` function in the CurveOracle, a potential flash loan attack vulnerability was identified.

## Vulnerability Detail
The `getPrice` function retrieves the spot price of each token in a Curve LP pool, calculates the minimum price among them, and multiplies it by the virtual price of the LP token to determine the USD value of the LP token. If the price of one or more tokens in the pool is manipulated, this can cause the minimum price calculation to be skewed, leading to an incorrect USD value for the LP token. This can be exploited by attackers to make a profit at the expense of other users.

## Impact
This vulnerability could potentially allow attackers to manipulate the price of tokens in Curve LP pools and profit at the expense of other users. If exploited, this vulnerability could result in significant financial losses for affected users.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/96eb1829571dc46e1a387985bd56989702c5e1dc/blueberry-core/contracts/oracle/CurveOracle.sol#L122

## Tool used

Manual Review

## Recommendation
use TWAP to determine the prices of the underlying assets in the pool.

---

### Example 25: [M-01] Low data feed frequency from Tellor makes your protocol vulnerable to flash loan attacks

**Source**: Code4rena
**Protocol**: Ethos Reserve
**Impact**: MEDIUM

**Details**:

An attacker can stale Tellor Oracle for several hours cheaply and perform a flash loan attack to profit.

### Proof of Concept

To explain this issue I will first compare Chainlink to Tellor.

Most ERC-20 tokens are in general much more volatile than ETH and BTC. In Chainlink,  there are triggers of 0,5% for BTC and ETH and 1% for other assets. This is to ensure that you are cutting error by those values.

Tellor, on the other hand, is an *optimistic oracle*. Stakers use the oracle system to put data on chain `submitValue(..)` that are directly shown in the oracle. The security lies the fact that data consumers should wait some **dispute windows** in order to give time to others to dispute data and remove incorrect or malicious data.

This is what happened in a Liquity bug found last year, they were reading instant data.\[2]

Being explained this and back to your code you have essentially two bugs

### First bug: Default disputetime = 20 minutes

In `TellorCaller.sol` you have the following statement

`(bytes memory data, uint256 timestamp) = getDataBefore(_queryId, block.timestamp - 20 minutes)`

Maybe you are using 20 minutes because this is the default value in Tellor documentation. However, in Liquity they are using 15 minutes for ETH because they say that have been made an analysis of ETH volatility behaviour.\[2]

Basically there is a tradeoff between the volatility of an asset and the dispute time. More time is safer to have time to dipute but more likely to read a so 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-02-ethos)

---

## Statistics

- Total findings analyzed: 25
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

