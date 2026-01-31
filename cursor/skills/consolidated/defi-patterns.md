---
id: PAT-DEFI
title: Defi Security Patterns
category: general
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - security
  - vulnerability
related_patterns:
  - vulnerability
finding_count: 25
last_updated: 2026-01-31
---
# DeFi Security Patterns (Consolidated)

> **DeFi protocols are the primary target for exploits. Over $3B lost in DeFi hacks.**

---

## Quick Summary

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| Flash Loan Attack | Borrow, manipulate, profit, repay in one tx | Critical |
| Oracle Manipulation | Corrupt price feeds for profit | Critical |
| First Depositor | Inflate share price to steal deposits | High |
| Sandwich Attack | Front-run + back-run swaps for MEV | High |
| Liquidation Exploit | Abuse liquidation mechanics | High |
| Vault Inflation | Donate to vault to manipulate shares | High |
| Slippage Bypass | No minOut allows value extraction | High |

---

## Detection Strategy

### Flash Loan Attack Patterns
```solidity
// VULNERABLE: Price read during flash loan is manipulated
function getPrice() public view returns (uint) {
    return reserve0 / reserve1;  //  Can be manipulated in same block
}

// SAFER: Use TWAP or external oracle with staleness check
function getPrice() public view returns (uint) {
    (, int price,, uint updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < 1 hours, "Stale price");
    return uint(price);
}
```

### Oracle Manipulation Detection
```solidity
// DANGEROUS: Spot price from AMM
uint price = reserve0 / reserve1;  //  Flash loan manipulable

// DANGEROUS: No staleness check
(, int price,,,) = feed.latestRoundData();  //  Could be hours old

// SAFE: Full Chainlink validation
(uint80 roundId, int price,, uint updatedAt, uint80 answeredInRound) = feed.latestRoundData();
require(price > 0, "Invalid price");
require(updatedAt > 0, "Round not complete");
require(answeredInRound >= roundId, "Stale price");
require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Price too old");
```

### First Depositor Attack
```solidity
// VULNERABLE: First deposit can be manipulated
function deposit(uint assets) external returns (uint shares) {
    shares = totalSupply == 0 ? assets : (assets * totalSupply) / totalAssets();
    // Attacker: deposit 1 wei  donate 1M tokens  next depositor gets 0 shares
}

// SAFE: Virtual offset or minimum deposit
function deposit(uint assets) external returns (uint shares) {
    require(assets >= MIN_DEPOSIT, "Too small");
    shares = ((assets + 1) * (totalSupply + 1e18)) / (totalAssets() + 1);
}
```

### Audit Checklist
- [ ] Price source: Single AMM? TWAP? Chainlink? Multiple sources?
- [ ] Staleness: Does oracle check updatedAt and roundId?
- [ ] Flash loan: Can any function be exploited in single tx?
- [ ] First depositor: Is there minimum deposit or virtual offset?
- [ ] Slippage: Is minAmountOut enforced on all swaps?
- [ ] MEV: Can txs be sandwiched? Deadline enforced?
- [ ] Liquidation: Can partial liquidation be gamed?
- [ ] Share calculation: Rounding direction favor protocol?

---

## Real-World Exploits

| Protocol | Loss | Attack Type | Year |
|----------|------|-------------|------|
| bZx | $8M | Flash loan + oracle | 2020 |
| Harvest Finance | $34M | Flash loan + price manipulation | 2020 |
| Cream Finance | $130M | Flash loan + reentrancy | 2021 |
| Mango Markets | $114M | Oracle manipulation | 2022 |
| Euler Finance | $197M | Donation attack | 2023 |

---

## Included Pattern Files

This consolidated file contains full content from:
- flash-loan-patterns.md, liquidation-patterns.md, lending-pool-patterns.md
- vault-patterns.md, erc4626-patterns.md, eip-4626-patterns.md
- swap-patterns.md, uniswap-patterns.md, 0x-patterns.md
- slippage-patterns.md, sandwich-attack-patterns.md, front-running-patterns.md
- oracle-patterns.md, chainlink-patterns.md, twap-patterns.md, stale-price-patterns.md
- first-depositor-issue-patterns.md, share-inflation-patterns.md, initial-deposit-patterns.md
- collateral-factor-patterns.md, protocol-reserve-patterns.md, pegged-patterns.md

---

## Full Pattern Details

---
## flash-loan-patterns.md
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


---
## liquidation-patterns.md
# Liquidation Security Patterns

## Overview

**Frequency**: 42 occurrences (0.08% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 25 | 17 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Cantina, Pashov Audit Group, Codehawks

---

## Detection Checklist

- [ ] Check for liquidation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Borrowers may earn auction proceeds without filling the debt shortfall

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

The proceeds from the collateral auctions will not be used to fill the debt shortfall, but be transferred directly to the borrower.

### Proof of Concept

Assume N is an allowed NFT, B is a borrower, the vault V is `_vaultInfo[B][N]`:

1.  B add two NFTs (N-1 and N-2) as collaterals to vault V.
2.  B [increaseDebt()](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L138) of vault V.
3.  The vault V becomes liquidatable.
4.  Someone calls [startLiquidationAuction()](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L297) to liquidate collateral N-1.
5.  No one buys N-1 because the price of N is falling.
6.  After [liquidationAuctionMinSpacing - 2days](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L41), someone calls [startLiquidationAuction()](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L297) to liquidate collateral N-2.
7.  Someone calls [purchaseLiquidationAuctionNFT](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L264) to purchase N-1. Partial of the debt is filled, while the remaining (shortfall) is burnt:

```solidity
if (isLastCollateral && remaining != 0) {
    /// there will be debt left with no NFTs, set it to 0
    _reduceDebtWithoutBurn(auction.nftOwner, auction.auctionAssetContract

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 2: [H-04] Users may be liquidated right after taking maximal debt

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

### Example 3: Owner of a bad ShortRecord can front-run flagShort calls AND liquidateSecondary and prevent liquidation

**Source**: Codehawks
**Protocol**: DittoETH
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47">https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/facets/ERC721Facet.sol#L162C17-L162C17">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/facets/ERC721Facet.sol#L162C17-L162C17</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L132">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L132</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L224C10-L224C10">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortR

*[Content truncated...]*

---

### Example 4: H-7: Users can be liquidated prematurely because calculation understates value of underlying position

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/126 

## Found by 
obront

## Summary

When the value of the underlying asset is calculated in `getPositionRisk()`, it uses the `underlyingAmount`, which is the amount of tokens initially deposited, without any adjustment for the interest earned. This can result in users being liquidated early, because the system undervalues their assets.

## Vulnerability Detail

A position is considered liquidatable if it meets the following criteria: 

```solidity
((borrowsValue - collateralValue) / underlyingValue) >= underlyingLiqThreshold
```
The value of the underlying tokens is a major factor in this calculation. However, the calculation of the underlying value is performed with the following function call:
```solidity
uint256 cv = oracle.getUnderlyingValue(
    pos.underlyingToken,
    pos.underlyingAmount
);
```
If we trace it back, we can see that `pos.underlyingAmount` is set when `lend()` is called (ie when underlying assets are deposited). This is the only place in the code where this value is moved upward, and it is only increased by the amount deposited. It is never moved up to account for the interest payments made on the deposit, which can materially change the value.

## Impact

Users can be liquidated prematurely because the value of their underlying assets are calculated incorrectly.

## Code Snippet

https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/BlueBerryBank.sol#L485-L48

*[Content truncated...]*

---

### Example 5: H-7: Possible to liquidate past the debt outstanding above the min borrow without liquidating the entire debt outstanding

**Source**: Sherlock
**Protocol**: Notional V3
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-03-notional-judging/issues/194 

## Found by 
xiaoming90
## Summary

It is possible to liquidate past the debt outstanding above the min borrow without liquidating the entire debt outstanding. Thus, leaving accounts with small debt that are not profitable to unwind if it needs to liquidate.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/vaults/VaultValuation.sol#L251

```solidity
File: VaultValuation.sol
250:         // NOTE: deposit amount is always positive in this method
251:         if (depositUnderlyingInternal < maxLiquidatorDepositLocal) {
252:             // If liquidating past the debt outstanding above the min borrow, then the entire
253:             // debt outstanding must be liquidated.
254: 
255:             // (debtOutstanding - depositAmountUnderlying) is the post liquidation debt. As an
256:             // edge condition, when debt outstanding is discounted to present value, the account
257:             // may be liquidated to zero while their debt outstanding is still greater than the
258:             // min borrow size (which is normally enforced in notional terms -- i.e. non present
259:             // value). Resolving this would require additional complexity for not much gain. An
260:             // account within 20% of the minBorrowSize in a vault that has fCash discounting enabled
261:             // may experience a full liquidation 

*[Content truncated...]*

---

### Example 6: Inability to liquidate non-locked collateral in LendingPool

**Source**: MixBytes
**Protocol**: Liquorice
**Impact**: HIGH

**Details**:

##### Description

Argument `isLockedCollateral` was removed from the function `LendingPool.liquidate()`, making it impossible to liquidate non-locked collateral:
```
function liquidate(
    address _user,
    LiquidateParams[] memory _withdrawalParams,
    LiquidateParams[] memory _repayParams,
    bytes memory _receiverData
)
```
https://github.com/Liquorice-HQ/contracts/blob/85c1eb77f404b0421bd3d1bdec548085006a3945/src/contracts/LendingPool.sol#L278-L283

##### Recommendation

We recommend restoring the argument `isLockedCollateral` in liquidation functions.

***

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Liquorice/README.md#6-inability-to-liquidate-non-locked-collateral-in-lendingpool)

---

### Example 7: [H-01] `executeIsolateLiquidate()` `totalBidAmout/availableLiquidity` incorrect accounting

**Source**: Code4rena
**Protocol**: BendDAO
**Impact**: HIGH

**Details**:

Code reference: [IsolateLogic.sol# L499](https://github.com/code-423n4/2024-12-benddao/blob/489f8dd0f8e86e5a7550cc6b81f9edfe79efbf4e/src/libraries/logic/IsolateLogic.sol# L499)

When `executeIsolateLiquidate()` is executed, it will account `totalBidAmout/availableLiquidity`.

The main accounting code is as follows:
```

    function executeIsolateLiquidate(InputTypes.ExecuteIsolateLiquidateParams memory params) internal {
...

        InterestLogic.updateInterestRates(poolData, debtAssetData, vars.totalBorrowAmount, 0);

        if (vars.totalExtraAmount > 0) {
            // transfer underlying asset from caller to pool
@>          VaultLogic.erc20TransferInLiquidity(debtAssetData, params.msgSender, vars.totalExtraAmount);
        }

        // bid already in pool and now repay the borrow but need to increase liquidity
@>      VaultLogic.erc20TransferOutBidAmountToLiqudity(debtAssetData, vars.totalBorrowAmount);

        // transfer erc721 to winning bidder
        if (params.supplyAsCollateral) {
            VaultLogic.erc721TransferIsolateSupplyOnLiquidate(
                nftAssetData,
                vars.winningBidder,
                params.nftTokenIds,
                true
            );
        } else {
            VaultLogic.erc721DecreaseIsolateSupplyOnLiquidate(nftAssetData, params.nftTokenIds);

            VaultLogic.erc721TransferOutLiquidity(nftAssetData, vars.winningBidder, params.nftTokenIds);
        }

function erc20TransferInLiquidity(DataTypes.AssetData 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-12-benddao-invitational)

---

### Example 8: Bad Debt Redistribution Not Happening Between Liquidations in Batch Mode 

**Source**: Cantina
**Protocol**: Bima
**Impact**: HIGH

**Details**:

## Context 
(No context files were provided by the reviewer)

## Description
The issue lies in how liquidations handle debt redistribution in `LiquidationManager.sol`. Here's the problematic flow:

```solidity
function batchLiquidateTroves(ITroveManager troveManager, address[] memory _troveArray) public {
    LiquidationValues memory singleLiquidation;
    LiquidationTotals memory totals;
    // First iteration round
    while (troveIter < length && troveCount > 1) {
        address account = _troveArray[troveIter];
        uint256 ICR = troveManager.getCurrentICR(account, troveManagerValues.price);
        if (ICR <= _100pct) {
            singleLiquidation = _liquidateWithoutSP(troveManager, account);
        } else if (ICR < troveManagerValues.MCR) {
            singleLiquidation = _liquidateNormalMode(troveManager, account, debtInStabPool, sunsetting);
        }
        // Problem: Redistribution happens at the end of batch, not after each liquidation
        _applyLiquidationValuesToTotals(totals, singleLiquidation);
    }
    // Redistribution only happens here, after all liquidations
    troveManager.finalizeLiquidation(
        msg.sender,
        totals.totalDebtToRedistribute,
        totals.totalCollToRedistribute,
        totals.totalCollSurplus,
        totals.totalDebtGasCompensation,
        totals.totalCollGasCompensation
    );
}
```

## The problem occurs in this sequence:
1. When a CDP creates bad debt after liquidation, that debt should be redistributed im

*[Content truncated...]*

**Reference**: [View Original Finding](https://cdn.cantina.xyz/reports/cantina_competition_bima_december2024.pdf)

---

### Example 9: LiquidationManager does not correctly maintain entireSystemColl and calculates TCR incor- rectly when performing liquidation 

**Source**: Cantina
**Protocol**: Bima
**Impact**: HIGH

**Details**:

## Liquidation Issue in Recovery Mode

## Context
(No context files were provided by the reviewer)

## Description
When performing liquidation in recovery mode, after liquidating each Trove, the Total Collateral Ratio (TCR) is recalculated to ensure that it remains below the Critical Collateral Ratio (CCR) so that liquidation can continue. The issue arises because TCR is incorrectly calculated due to an error in calculating the `entireSystemColl`, leading to incorrect recovery mode liquidation checks.

`entireSystemColl` is intended to represent the total amount of system collateral during liquidation. It correctly subtracts the collateral sent to the Stability Pool and the surplus collateral amount; however, it fails to account for the collateral gas compensation.

### Example
Consider a Trove with 10,000 collateral and 9,900 debt that is liquidated by the Stability Pool. The collateral gas compensation is calculated as:
```
10000 * 0.5% = 50
```
Thus, 9,950 of collateral gets sent to the Stability Pool. The bug is in the calculation of `entireSystemColl`, where we should subtract 10,000, but the current implementation only subtracts 9,950. As more Troves and collateral are liquidated, the discrepancy in `entireSystemColl` increases, which results in a TCR that is higher than the actual value. This means that potential liquidations that should have occurred may not happen.

Note that the original code of LiquityV1 does not contain this bug (see `liquity/.../TroveManager.sol#

*[Content truncated...]*

**Reference**: [View Original Finding](https://cdn.cantina.xyz/reports/cantina_competition_bima_december2024.pdf)

---

### Example 10: [H-01] Liquidations can be prevented by frontrunning and liquidating 1 debt (or more) due to wrong assumption in POS\_MANAGER

**Source**: Code4rena
**Protocol**: INIT Capital
**Impact**: HIGH

**Details**:

Users can avoid being liquidated if they frontrun liquidation calls with a liquidate call with 1 wei. Or, they may do a partial liquidation and avoid being liquidated before the interest reaches the value of the debt pre liquidation. The total interest stored in `__posBorrInfos[_posId].borrExtraInfos[_pool].totalInterest` would also be wrong.

### Proof of Concept

The `POS_MANAGER` stores the total interest in `__posBorrInfos[_posId].borrExtraInfos[_pool].totalInterest`. Function `updatePosDebtShares()` [assumes](https://github.com/code-423n4/2023-12-initcapital/blob/main/contracts/core/PosManager.sol#L175) that `ILendingPool(_pool).debtShareToAmtCurrent(currDebtShares)` is always increasing, but this is not the case, as a liquidation may happen that reduces the current debt amount. This leads to calls to `updatePosDebtShares()` reverting.

The most relevant is when liquidating, such that users could liquidate themselves for small amounts (1) and prevent liqudiations in the same block. This is because the debt accrual happens over time, so if the block.timestamp is the same, no debt accrual will happen. Thus, if a liquidate call with 1 amount frontruns a liquidate call with any amount, the second call will revert.

A user could still stop liquidations for as long as the accrued interest doesn't reach the last debt value before liquidation, if the user liquidated a bigger part of the debt.

Add the following test to `TestInitCore.sol`:

```solidity
function test_POC_Liquidate

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-initcapital)

---

### Example 11: [M-04] Withdrawing uncollateralized deposits is possible even though the position is in liquidation mode

**Source**: Code4rena
**Protocol**: Wise Lending
**Impact**: MEDIUM

**Details**:

Users can withdraw uncollateralized deposits even though their position is liquidable, [as opposed to the README](https://github.com/code-423n4/2024-02-wise-lending/blob/main/README.md?plain=1#L137). If the position is in liquidation mode, users should use their uncollateralized deposits to avoid liquidation instead of removing them.

### Proof of Concept

When withdrawing deposits from public pools, at the end of the tx is executed the [`WiseLending._healthStateCheck() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseLending.sol#L77-L90), which depending on the value of the `powerFarmCheck` will determine if the position's collateral is enough to cover the borrows.

- If `powerFarmCheck` is true, it will use the `bare` value of the collateral; meaning, the `collateralFactor` is not applied to the collateral's value.
- If `powerFarmCheck` is false, it will use the `weighted` value of the collateral; meaning, the `collateralFactor` is applied to the collateral's value.

When withdrawing an uncollateralized deposit, the [`WiseCore._coreWithdrawToken() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseCore.sol#L44-L100) calls the [`WiseSecurity.checksWithdraw() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseSecurity/WiseSecurity.sol#L237-L270) to determine the value of the `powerFarmCheck`. If the pool from where the tokens are being withdrawn is uncollateralized, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-wise-lending)

---

### Example 12: [M-08] User fund loss because function purchaseLiquidationAuctionNFT() takes extra liquidation penalty when users last collateral is liquidated, (set wrong value for maxDebtCached when isLastCollateral is true)

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L264-L294


## Vulnerability details

## Impact
Function `purchaseLiquidationAuctionNFT()` purchases a liquidation auction with the controller's papr token. the liquidator pays the papr amount which is equal to price of the auction and receives the auctioned  NFT. contract would transfer paid papr and  pay borrower debt and if there is extra papr left it would be transferred to the user. for extra papr that is not required for brining user debt under max debt, contract gets liquidation penalty but in some cases (when the auctioned NFT is user's last collateral) contract take penalty from all of the transferred papr and not just the extra. so users would lose funds in those situations because of this and the fund could be big because the penalty is 10% of the price of the auction and in most cases user would lose 10% of his debt (the value of the NFT).

## Proof of Concept
This is `purchaseLiquidationAuctionNFT()` code:
```
    function purchaseLiquidationAuctionNFT(
        Auction calldata auction,
        uint256 maxPrice,
        address sendTo,
        ReservoirOracleUnderwriter.OracleInfo calldata oracleInfo
    ) external override {
        uint256 collateralValueCached = underwritePriceForCollateral(
            auction.auctionAssetContract, ReservoirOracleUnderwriter.PriceKind.TWAP, oracleInfo
        ) * _vaultInfo[auction.nftOwner][auction.aucti

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 13: [M-10] Liquidation should make a borrower healthier

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L559
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L591


## Vulnerability details

## Impact

For a lending pool, borrower's debt healthness can be decided by the health factor, i.e. the collateral value divided by debt. ($C/D$)

The less the health factor is, the borrower's collateral is more risky of being liquidated.

Liquidation is supposed to make the borrower healthier (by paying debts and claiming some collateral), or else continuous liquidations can follow up and this can lead to a so-called [liquidation crisis](https://medium.com/coinmonks/what-is-liquidation-in-defi-lending-and-borrowing-platforms-3326e0ba8d0).

In a normal lending protocol, borrower's debt is limited by collateral factor in any case.

For this protocol, users can force replenishment for the addresses in deficit and the replenishment increases the borrower's debt.

And in the current implementation the replenishment is limited so that the new debt is not over than the collateral value.

As we will see below, this limitation is not enough and if the borrower's debt is over some threshold (still less than collateral value), liquidation makes the borrower debt "unhealthier".

And repeating liquidation can lead to various problems and we will even show an example that the attacker can take the DOLA out of the market.

## Proof of Concept

### Terminology

$C_f$ - collateralFactorBps / 10000

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 14: H-4: When account is liquidated (protected), liquidator can increase account's position to any value up to `2**62 - 1` breaking all market accounting and stealing all market funds.

**Source**: Sherlock
**Protocol**: Perennial V2 Update #4
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2025-01-perennial-v2-4-update-judging/issues/32 

## Found by 
panprog

### Summary

Previously, there was a check which enforced position to only decrease during liquidation. However, the check is gone and in the current code only the condition of `pending.negative == latestPosition.magnitude`:
```solidity
  if (!context.pendingLocal.neg().eq(context.latestPositionLocal.magnitude())) return false; // no pending zero-cross, liquidate with full close
```

If account (before liquidation) is already in this state (for example, user has closed his position fully, but it's still pending - in this case `pendingLocal.neg()` will equal `latestPositionLocal.magnitude()` before the liquidation), then liquidator can increase position, and since it doesn't influence neither latest position nor pending negative (closing), it's allowed. Moreover, all collateral and position size checks are ignored during liquidation, so account position can be increased to any value, including max that can be stored: 2**62 - 1. If this is done, all market accounting is messed up as any slight price change will create huge profit or loss for makers and the liquidated account. This can be abused by attacker to steal all market funds.

### Root Cause

Incorrect check when liquidating the account (lack of enforcement to only reduce the position):
https://github.com/sherlock-audit/2025-01-perennial-v2-4-update/blob/main/perennial-v2/packages/core/contracts/libs/Invarian

*[Content truncated...]*

---

### Example 15: H-1: Lenders and borrowers can not claim liquidation token after NFT collateral auction sold

**Source**: Sherlock
**Protocol**: Debita Finance V3
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-10-debita-judging/issues/156 

## Found by 
0xc0ffEE
### Summary

The incorrect logic in function `veNFTAerodrome::getDataByReceipt()` will cause the lenders and borrowers unable to claim liquidation token after the NFT auction sold

### Root Cause

- The function [`DebitaV3Loan::claimCollateralAsNFTLender()`](https://github.com/sherlock-audit/2024-11-debita-finance-v3/blob/main/Debita-V3-Contracts/contracts/DebitaV3Loan.sol#L379-L397) allows the lenders to claim the liquidation token after the NFT collateral auction is sold.
- The function [`DebitaV3Loan::claimCollateralNFTAsBorrower()`](https://github.com/sherlock-audit/2024-11-debita-finance-v3/blob/main/Debita-V3-Contracts/contracts/DebitaV3Loan.sol#L666-L692) allows the borrower to claim the liquidation token in case partial default
- The 2 functions above call `veNFTAerodrome::getDataByReceipt()` to retrieve the liquidation token's decimals to calculate the payment amount
- These 2 flows above can be reverted because of unhandled case in the [function veNFTAerodrome::getDataByReceipt()](https://github.com/sherlock-audit/2024-11-debita-finance-v3/blob/main/Debita-V3-Contracts/contracts/Non-Fungible-Receipts/veNFTS/Aerodrome/Receipt-veNFT.sol#L243-L264). The mentioned unhandled case is when there is no owner of the receipt token, such that `ownerOf(receiptID)` reverts because of non-exist token.
```solidity
    function getDataByReceipt(
        uint receiptID
    ) public vi

*[Content truncated...]*

---

### Example 16: H-7: Liquidation can be blocked by incrementing the nonce

**Source**: Sherlock
**Protocol**: Symmetrical
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/233 

## Found by 
0xcrunch, AkshaySrivastav, Jiamin, Juntao, Ruhum, berndartmueller, bin2chen, cergyk, circlelooper, mstpr-brainbot, nobody2018, p0wd3r, rvierdiiev, shaka, simon135, volodya, xiaoming90
## Summary

Malicious users could block liquidators from liquidating their accounts, which creates unfairness in the system and lead to a loss of profits to the counterparty.

## Vulnerability Detail

#### Instance 1 - Blocking liquidation of PartyA

A liquidatable PartyA can block liquidators from liquidating its account.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

```solidity
File: LiquidationFacetImpl.sol
20:     function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
21:         MAStorage.Layout storage maLayout = MAStorage.layout();
22: 
23:         LibMuon.verifyPartyAUpnl(upnlSig, partyA);
24:         int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
25:             upnlSig.upnl,
26:             partyA
27:         );
28:         require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
29:         maLayout.liquidationStatus[partyA] = true;
30:         maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
31:         AccountStorage.layout().liquidators[partyA].push(msg.sender);
32:     }
```

Within the `liquidatePartyA` function, it call

*[Content truncated...]*

---

### Example 17: [H-01] Call to declareInsolvent() would revert when contract status reaches liquidation point after repayment of credit position 1

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/modules/credit/LineOfCredit.sol#L143
https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/modules/credit/LineOfCredit.sol#L83-L86


## Vulnerability details

## Impact
The modifier `whileBorrowing()` is used along in the call to LineOfCredit.declareInsolvent(). However this check reverts when count == 0 or `credits[ids[0]].principal == 0` . Within the contract, any lender can add credit which adds an entry in credits array, credits[ids]. 

Assume, when borrower chooses lender positions including credits[ids[0]] to draw on, and repays back the loan fully for credits[ids[1]], then the call to declareInsolvent() by the arbiter would revert since it does not pass the `whileBorrowing()` modifier check due to the ids array index shift in the call to  stepQ(), which would shift ids[1] to ids[0], thereby making the condition for `credits[ids[0]].principal == 0` be true causing the revert.



## Proof of Concept
1. LineOfCredit contract is set up and 5 lenders have deposited into the contract.
2. Alice, the borrower borrows credit from these 5 credit positions including by calling LineOfCredit.borrow() for the position ids.
3. Later Alice pays back the loan for  credit position id 1 just before the contract gets liquidated
4. At the point where ids.stepQ() is called in _repay(), position 1 is moved to ids[0]
4. When contract status is LIQUIDATABLE, no lo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 18: [H-03] LendingPair.liquidateAccount fails if tokens are lent out

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `LendingPair.liquidateAccount` function tries to pay out underlying supply tokens to the liquidator using `_safeTransfer(IERC20(supplyToken), msg.sender, supplyOutput)` but there's no reason why there should be enough `supplyOutput` amount in the contract, the contract only ensures `minReserve`.

## Impact
No liquidations can be performed if all tokens are lent out.
Example: User A supplies 1k$ WETH, User B supplies 1.5k$ DAI and borrows the ~1k$ WETH (only leaves `minReserve`). The ETH price drops but user B cannot be liquidated as there's not enough WETH in the pool anymore to pay out the liquidator.

## Recommendation
Mint LP supply tokens to `msg.sender` instead, these are the LP supply tokens that were burnt from the borrower. This way the liquidator basically seizes the borrower's LP tokens.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-wildcredit)

---

### Example 19: [M-05] Possible DoS When calling `GammaTradeMarket::_removePosition` will cause user position to not be able to get liquidated

**Source**: Code4rena
**Protocol**: Predy
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2024-05-predy/blob/a9246db5f874a91fb71c296aac6a66902289306a/src/markets/gamma/ArrayLib.sol#L20-L32><br><https://github.com/code-423n4/2024-05-predy/blob/a9246db5f874a91fb71c296aac6a66902289306a/src/markets/gamma/GammaTradeMarket.sol#L146-L149>

### Impact

Griefing/DOS attack is possible when, a malicious user creates many very small positions, which could cause excessive gas consumed and even transactions reverted when other users are trying to liquidate any of the user's positions.

### Proof of Concept

The function `GammaTradeMarket.sol:_removePosition` is using the `ArrayLib::removeItem`, which is currently just looping over the items, until it finds the one it's looking for.

```solidity
function _removePosition(uint256 positionId) internal {x
        address trader = userPositions[positionId].owner;

@>        positionIDs[trader].removeItem(positionId);
    }
```

```solidity
 function removeItem(uint256[] storage items, uint256 item) internal {
        uint256 index = getItemIndex(items, item);

        removeItemByIndex(items, index);
    }
...

    function getItemIndex(uint256[] memory items, uint256 item) internal pure returns (uint256) {
        uint256 index = type(uint256).max;

        //@review - If items length is bigger, it could revert due to reaching block gas limit
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i] == item) {
                index = i;
                break;
            }
        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-05-predy)

---

### Example 20: M-16: `originationFee` may result in the borrower account becoming liquidatable immediately

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/501-M 
## Found by 
WATCHPUG

## Summary

Note: This issue is a part of the extra scope added by Sentiment AFTER the audit contest. This scope was only reviewed by WatchPug and relates to these three PRs:

1. [Lending deposit cap](https://github.com/sentimentxyz/protocol/pull/234)
2. [Fee accrual modification](https://github.com/sentimentxyz/protocol/pull/233)
3. [CRV staking](https://github.com/sentimentxyz/controller/pull/41)

`originationFee` may result in the borrower account becoming liquidatable immediately.

## Vulnerability Detail

When checking `riskEngine.isBorrowAllowed()`, the `originationFee` of the borrow is not considered. Thus, when `originationFee` is large enough, the borrower account becomes liquidatable immediately.

For example:

Let's say USDC's `originationFee` is 30%;

Alice has `100 USDC`, and 0 debt in her account;
Alice borrowed `400 USDC`, received only `280 USDC` after the `originationFee`;
Alice's account is now liquidatable.
Actually, in the case above, Alice's account won't even get liquidated as all the assets are worth (380 USDC) less than the total debt (`400 USDC`).

## Impact

`originationFee` may result in the borrower account becoming liquidatable immediately.

## Code Snippet
https://github.com/sentimentxyz/protocol/blob/f5a9089e87752986af522cc952f95beb037491c8/src/tokens/LToken.sol#L243-L245

```solidity
function updateOriginationFee(uint _originationFee) ext

*[Content truncated...]*

---

### Example 21: H-4: Malicious user can DOS pool and avoid liquidation by creating secondary liquidity pool for Velodrome token pair

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/72 

## Found by 
0x52

## Summary

For every Vault_Velo interaction the vault attempts to price the liquidity of the user. This calls priceLiquidity in the corresponding DepsoitReciept. The prices the underlying assets by swapping them through the Velodrome router. Velodrome can have both a stable and volatile pool for each asset pair. When calling the router directly it routes through the pool that gives the best price. In priceLiquidity the transaction will revert if the router routes through the wrong pool (i.e. trading the volatile pool instead of the stable pool). A malicious user can use this to their advantage to avoid being liquidated.  They could manipulate the price of the opposite pool so that any call to liquidate them would route through the wrong pool and revert.

## Vulnerability Detail

        uint256 amountOut; //amount received by trade
        bool stablePool; //if the traded pool is stable or volatile.
        (amountOut, stablePool) = router.getAmountOut(HUNDRED_TOKENS, token1, USDC);
        require(stablePool == stable, "pricing occuring through wrong pool" );

DepositReceipt uses the getAmountOut call the estimate the amountOut. The router will return the best rate between the volatile and stable pool. If the wrong pool give the better rate then the transaction will revert. Since pricing is called during liquidation, a malicious user could manipulate the price of the wrong pool

*[Content truncated...]*

---

### Example 22: H-5: Users are unable close or add to their Lyra vault positions when price is stale or circuit breaker is tripped

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

### Example 23: [M-01] Incorrect calculation of new liquidation price

**Source**: Pashov Audit Group
**Protocol**: Gainsnetwork May
**Impact**: MEDIUM

**Details**:

**Severity**

**Impact:** Medium

**Likelihood:** Medium

**Description**

When calculating the newLiqPrice in `IncreasePositionSizeUtils.prepareCallbackValues`, the function uses `newCollateralAmount` and `newLeverage`.

```solidity
  function prepareCallbackValues(
        ITradingStorage.Trade memory _existingTrade,
        ITradingStorage.Trade memory _partialTrade,
        ITradingCallbacks.AggregatorAnswer memory _answer
    ) internal view returns (IUpdatePositionSizeUtils.IncreasePositionSizeValues memory values) {
        ...
        values.newLiqPrice = _getMultiCollatDiamond().getTradeLiquidationPrice(
            IBorrowingFees.LiqPriceInput(
                _existingTrade.collateralIndex,
                _existingTrade.user,
                _existingTrade.pairIndex,
                _existingTrade.index,
                uint64(values.newOpenPrice),
                _existingTrade.long,
                values.newCollateralAmount, // @audit use newCollateralAmount & newLeverage => borrowing fee is overstated
                values.newLeverage
            )
        );
        ...
    }
```

To calculate the liquidation price, the current borrowing fee amount needs to be considered. Using `newCollateralAmount` and `newLeverage` as inputs can lead to overstating the borrowing fee if these values are higher than the current collateral and leverage. This results in an incorrect new liquidation price, making it higher for long positions and lower for short positions. This 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GainsNetwork-security-review-May.md)

---

### Example 24: [M-01] Zero amount token transfers may cause a denial of service during liquidations

**Source**: Code4rena
**Protocol**: Particle Protocol
**Impact**: MEDIUM

**Details**:

Some ERC20 implementations revert on zero value transfers. Since liquidation rewards are based on a fraction of the available position's premiums, this may cause an accidental denial of service that prevents the successful execution of liquidations.

### Impact

Liquidations in the LAMM protocol are incentivized by a reward that is calculated as a fraction of the premiums available in the position.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L348-L354>

```solidity
348:         // calculate liquidation reward
349:         liquidateCache.liquidationRewardFrom =
350:             ((closeCache.tokenFromPremium) * LIQUIDATION_REWARD_FACTOR) /
351:             uint128(Base.BASIS_POINT);
352:         liquidateCache.liquidationRewardTo =
353:             ((closeCache.tokenToPremium) * LIQUIDATION_REWARD_FACTOR) /
354:             uint128(Base.BASIS_POINT);
```

These amounts are later transferred to the caller, the liquidator, at the end of the `liquidatePosition()` function.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L376-L378>

```solidity
376:         // reward liquidator
377:         TransferHelper.safeTransfer(closeCache.tokenFrom, msg.sender, liquidateCache.liquidationRewardFrom);
378:         TransferHelper.safeTransfer(closeCache.tokenTo, msg.sender, liquidateCache.liquidationReward

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-particle)

---

### Example 25: Attacker Can Grief Liquidations And Repayments

**Source**: Zokyo
**Protocol**: Creditswap
**Impact**: HIGH

**Details**:

**Severity** - Critical

**Status** - Resolved 

**Description**

To liquidate an unhealthy loan position the liquidate() function inside CreditorNFT can be called by anyone where the debtAmount of debt token is paid out by the liquidator.
This function in turn calls the liquidate function of LoanVault at L133.

Inside LoanVault.sols liquidate() it is checked if the debtAmount (initial debt amount when loan was created) is now equal to the balance of debt token in the vault , if not revert (L163)

An attacker can see a liquidation() call in the mempool and ->

a.) Frontruns this call to send the lowest amount of debt token to the vault , say 1
b.) Now when the liquidator tries to liquidate he sends out debtAmount of tokens to the vault , lets say they were 100
c.) It is checked that debt amount and balance of debt token balance in the vault is equal
d.) But they are not since there are a total of 101 debt tokens now , liquidation reverts.

Due to this the vault/loan position can never be liquidated and the protocol will continue to incur huge losses as the collateral value falls down.

The same problem lies in repay functionality , at L150 in LoanVault.sol it will revert due to the same case as above and make it impossible for a debtor to repay their loan , resulting in forced liquidations.

**Recommendation**:

Have an internal accounting system or change the condition to if the balance in the vault is less than debt amount, then revert instead of a strict equality.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Zokyo/2023-12-22-CreditSwap.md)

---

## Statistics

- Total findings analyzed: 42
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## lending-pool-patterns.md
# Lending Pool Security Patterns

## Overview

**Frequency**: 17 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 10 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for lending pool vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Liquidity providers may lose funds when adding liquidity

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

Liquidity providers may lose a portion of provided liquidity in either of the pair tokens. While the `minLpTokenAmount` protects from slippage when adding liquidity, it doesn't protect from providing liquidity at different K.

### Proof of Concept

The `Pair` contract is designed to receive liquidity from liquidity providers ([Pair.sol#L63](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L63)). First liquidity provider in a pool may provide arbitrary token amounts and set the initial price ([Pair.sol#L425-L426](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L425-L426)), but all other liquidity providers must provide liquidity proportionally to current pool reserves ([Pair.sol#L420-L423](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L420-L423)). Since a pool is made of two tokens and liquidity is provided in both tokens, there's a possibility for a discrepancy: token amounts may be provided in different proportions. When this happens, the smaller of the proportions is chosen to calculate the amount of LP tokens minted ([Pair.sol#L420-L423](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L420-L423)):

```solidity
// calculate amount of lp tokens as a fraction of existing reserves
uint256 baseTokenShare = (baseTokenAmount * lpTokenSupply) / baseTokenReserv

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 2: H-1: Pool can be drained

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

### Example 3: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec
## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and

*[Content truncated...]*

---

### Example 4: [M-05] Pair price may be manipulated by direct transfers

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L391> <br><https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L479-L480> <br><https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L384>

An attacker may manipulate the price of a pair by transferring tokens directly to the pair. Since the `Pair` contract exposes the `price` function, it maybe be used as a price oracle in third-party integrations. Manipulating the price of a pair may allow an attacker to steal funds from such integrations.

### Proof of Concept

The `Pair` contract is a pool of two tokens, a base token and a fractional token. Its main purpose is to allow users to swap the tokens at a fair price. Since the price is calculated based on the reserves of a pair, it can only be changed in two cases:

1.  when initial liquidity is added: the first liquidity provider sets the price of a pool ([Pair.sol#L85-L97](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L85-L97)); other liquidity providers cannot change the price ([Pair.sol#L421-L423](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L421-L423));
2.  during trades: trading adds and removes tokens from a pool, ensuring the K constant invariant is respected ([Pair.sol#L194-L204](https://github.com/cod

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 5: [H-21] bringUnusedETHBackIntoGiantPool in GiantMevAndFeesPool can be used to steal LPTokens

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126


## Vulnerability details

## Impact
real `LPTokens` can be transferred out of `GiantMevAndFeesPool` through fake `_stakingFundsVaults` provided by an attacker.
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126

## Proof of Concept
`bringUnusedETHBackIntoGiantPool` takes in `_stakingFundsVaults`, `_oldLPTokens`, `_newLPTokens` and rotate `_amounts` from old to new tokens. The tokens are thoroughly verified by `burnLPForETH` in `ETHPoolLPFactory`. 
However, theres is no checking for the validity of `_stakingFundsVaults`, nor the relationship between `LPTokens` and `_stakingFundsVaults`. Therefore, an attacker can create fake contracts for `_stakingFundsVaults`, with `burnLPTokensForETH`, that takes `LPTokens` as parameters. The `msg.sender` in `burnLPTokensForETH` is `GiantMevAndFeesPool`, thus the attacker can transfer `LPTokens` that belongs to `GiantMevAndFeesPool` to any addresses it controls.

## Tools Used
manual

## Recommended Mitigation Steps
Always passing liquid staking manager address, checking its real and then requesting either the savETH vault or staking funds vault is a good idea to prove the validity of vaults.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 6: M-16: `originationFee` may result in the borrower account becoming liquidatable immediately

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/501-M 
## Found by 
WATCHPUG

## Summary

Note: This issue is a part of the extra scope added by Sentiment AFTER the audit contest. This scope was only reviewed by WatchPug and relates to these three PRs:

1. [Lending deposit cap](https://github.com/sentimentxyz/protocol/pull/234)
2. [Fee accrual modification](https://github.com/sentimentxyz/protocol/pull/233)
3. [CRV staking](https://github.com/sentimentxyz/controller/pull/41)

`originationFee` may result in the borrower account becoming liquidatable immediately.

## Vulnerability Detail

When checking `riskEngine.isBorrowAllowed()`, the `originationFee` of the borrow is not considered. Thus, when `originationFee` is large enough, the borrower account becomes liquidatable immediately.

For example:

Let's say USDC's `originationFee` is 30%;

Alice has `100 USDC`, and 0 debt in her account;
Alice borrowed `400 USDC`, received only `280 USDC` after the `originationFee`;
Alice's account is now liquidatable.
Actually, in the case above, Alice's account won't even get liquidated as all the assets are worth (380 USDC) less than the total debt (`400 USDC`).

## Impact

`originationFee` may result in the borrower account becoming liquidatable immediately.

## Code Snippet
https://github.com/sentimentxyz/protocol/blob/f5a9089e87752986af522cc952f95beb037491c8/src/tokens/LToken.sol#L243-L245

```solidity
function updateOriginationFee(uint _originationFee) ext

*[Content truncated...]*

---

### Example 7: [H-06] LPs of VaderPoolV2 can manipulate pool reserves to extract funds from the reserve.

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

### Example 8: M-16: Auction timers following liquidity can fall through the floor price causing pool insolvency

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/76 

## Found by 
CRYP70

## Summary
When a borrower cannot pay their debt in an ERC20 pool, their position is liquidated and their assets enter an auction for other users to purchase small pieces of their assets. Because of the incentive that users wish to not pay above the standard market price for a token, users will generally wait until assets on auction are as cheap as possible to purchase however, this is flawed because this guarantees a loss for all lenders participating in the protocol with each user that is liquidated.

## Vulnerability Detail
Consider a situation where a user decides to short a coin through a loan and refuses to take the loss to retain the value of their position. When the auction is kicked off using the `kick()` function on this user, as time moves forward, the price for puchasing these assets becomes increasingly cheaper. These prices can fall through the floor price of the lending pool which will allow anybody to buy tokens for only a fraction of what they were worth originally leading to a state where the pool cant cover the debt of the user who has not paid their loan back with interest. The issue lies in the `_auctionPrice()` function of the `Auctions.sol` contract which calculates the price of the auctioned assets for the taker. This function does not consider the floor price of the pool. The proof of concept below outlines this scenario:

*Proof of Concept:*
```solidity
  

*[Content truncated...]*

---

### Example 9: M-9: Protocol Reserve Within A LToken Vault Can Be Lent Out

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/122-M 
## Found by 
xiaoming90

## Summary

Protocol reserve, which serves as a liquidity backstop or to compensate the protocol, within a LToken vault can be lent out to the borrowers.

## Vulnerability Detail

The purpose of the protocol reserve within a LToken vault is to compensate the protocol or serve as a liquidity backstop. However, based on the current setup, it is possible for the protocol reserve within a Ltoken vault to be lent out.

The following functions within the `LToken` contract show that the protocol reserve is intentionally preserved by removing the protocol reserve from the calculation of total assets within a LToken vault. As such, whenever the Liquidity Providers (LPs) attempt to redeem their LP token, the protocol reserves will stay intact and will not be withdrawn by the LPs.

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L191

```solidity
function totalAssets() public view override returns (uint) {
    return asset.balanceOf(address(this)) + getBorrows() - getReserves();
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L195

```solidity
function getBorrows() public view returns (uint) {
    return borrows + borrows.mulWadUp(getRateFactor());
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L176

```solidity
function getReserve

*[Content truncated...]*

---

### Example 10: M-4: Users can fail to closePositionFarm and lose their funds

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/64 

## Found by 
Bauer
## Summary
If self.is_killed in the curve pool contract  becomes true, user may be unable to call the `CurveSpell.closePositionFarm()` function to  repay his debt, resulting in his assets being liquidated.


## Vulnerability Detail
The `CurveSpell.closePositionFarm()` function is used to unwind a position on a strategy that involves farming CRV rewards through staking LP tokens in a Curve pool. Inside the function, the protocol swaps the harvested CRV tokens to the debt token, and calculates the actual amount of LP tokens to remove from the Curve pool. It then removes the LP tokens using the remove_liquidity_one_coin function of the Curve pool. 
```solidity
   int128 tokenIndex;
            for (uint256 i = 0; i < tokens.length; i++) {
                if (tokens[i] == pos.debtToken) {
                    tokenIndex = int128(uint128(i));
                    break;
                }
            }

            ICurvePool(pool).remove_liquidity_one_coin(
                amountPosRemove,
                int128(tokenIndex),
                0
            );
        }

        // 5. Withdraw isolated collateral from Bank
        _doWithdraw(param.collToken, param.amountShareWithdraw);

        // 6. Repay
        {
            // Compute repay amount if MAX_INT is supplied (max debt)
            uint256 amountRepay = param.amountRepay;
            if (amountRepay == type(uint256).max) {

*[Content truncated...]*

---

### Example 11: M-2: AuraSpell openPositionFarm does not join pool

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/46 

## Found by 
Ch\_301, cducrest-brainbot, cuthalion0x, nobody2018
## Summary

The function to open a position for the AuraSpell does not join the pool due to wrong conditional check.

## Vulnerability Detail

The function deposits collateral into the bank, borrow tokens, and attempts to join the pool:

```solidity
    function openPositionFarm(
        OpenPosParam calldata param
    )
        external
        existingStrategy(param.strategyId)
        existingCollateral(param.strategyId, param.collToken)
    {
        ...
        // 1. Deposit isolated collaterals on Blueberry Money Market
        _doLend(param.collToken, param.collAmount);

        // 2. Borrow specific amounts
        uint256 borrowBalance = _doBorrow(
            param.borrowToken,
            param.borrowAmount
        );

        // 3. Add liquidity on Balancer, get BPT
        {
            IBalancerVault vault = wAuraPools.getVault(lpToken);
            _ensureApprove(param.borrowToken, address(vault), borrowBalance);

            (address[] memory tokens, uint256[] memory balances, ) = wAuraPools
                .getPoolTokens(lpToken);
            uint[] memory maxAmountsIn = new uint[](2);
            maxAmountsIn[0] = IERC20(tokens[0]).balanceOf(address(this));
            maxAmountsIn[1] = IERC20(tokens[1]).balanceOf(address(this));

            uint totalLPSupply = IBalancerPool(lpToken).totalSupply();
            // 

*[Content truncated...]*

---

### Example 12: [M-06] Withdrawing wrong LPToken from GiantPool leads to loss of funds

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

The `GiantPoolBase.withdrawLPTokens` function (<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L69>) allows to withdraw LP tokens from a GiantPool by burning an equal amount of GiantLP.

This allows a user to handle the LP tokens directly without the need for a GiantPool as intermediary.

It is not checked however whether the LP tokens to be withdrawn were transferred to the GiantPool in exchange for staking ETH.

I.e. whether the LP token are of any value.

There are two issues associated with this behavior.

1.  A malicious user can create and mint his own LP Token and send it to the GiantPool. Users that want to withdraw LP tokens from the GiantPool can then be tricked into withdrawing worthless attacker LP tokens, thereby burning their GiantLP tokens that are mapped 1:1 to ETH. (-> loss of funds)

2.  This can also mess up internal accounting logic. For every LP token that is owned by a GiantPool there should be a corresponding GiantLP token. Using the described behavior this ratio can be broken such that there are LP token owned by the GiantPool for which there is no GiantLP token. This means some LP token cannot be transferred from the GiantPool and there will always be some amount of LP token "stuck" in the GiantPool.

### Proof of Concept

1.  The attacker deploys his own LPToken contract and sends a huge amount of LP tokens to the GiantPool to pass the check in `GiantPoolBase._

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 13: H-8: UserData for balancer pool exits is malformed and will permanently trap users

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/129 

## Found by 
0x52, cuthalion0x
## Summary

UserData for balancer pool exits is malformed and will result in all withdrawal attempts failing, trapping the user permanently. 

## Vulnerability Detail

[AuraSpell.sol#L184-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L184-L189)

    wAuraPools.getVault(lpToken).exitPool(
        IBalancerPool(lpToken).getPoolId(),
        address(this),
        address(this),
        IBalancerVault.ExitPoolRequest(tokens, minAmountsOut, "", false)
    );

We see above that UserData is encoded as "". This is problematic as it doesn't contain the proper data for exiting the pool, causing all exit request to fail and trap the user permanently.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F9#L50

    function exactBptInForTokenOut(bytes memory self) internal pure returns (uint256 bptAmountIn, uint256 tokenIndex) {
        (, bptAmountIn, tokenIndex) = abi.decode(self, (WeightedPool.ExitKind, uint256, uint256));
    }

UserData is decoded into the data shown above when using ExitKind = 0. Since the exit uses "" as the user data this will be decoded as 0 a.k.a [EXACT_BPT_IN_FOR_ONE_TOKEN_OUT](https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L50). This is problematic because the token index and bptAmountIn should also be encoded in user data f

*[Content truncated...]*

---

### Example 14: H-4: Potential flash loan attack vulnerability in `getPrice` function of CurveOracle

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

### Example 15: M-1: Calculation underflow/overflow in BalancerPairOracle, which will affect pools in Aura Finance

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/11 

## Found by 
n1punp
## Summary
LP price calculation for Balancer Pair in BalancerPairOracle will produce calculation underflow/overflow (so Aura pools won't work too).

## Vulnerability Detail
- The values r0, r1 can underflow, e.g. if resA < resB --> r0 = 0, so it'll go to the else case --> and so `ratio` will be 0 --> `fairResA` calculation will revert upon dividing by 0.
- There are also other math calculations there that will cause reverts, e.g. ratio ** wB will lead to overflow. What you'd need here is Balancer's implementation of `bpow` or similar.

## Impact
LP price for Balancer-like collateral token will revert in most cases, if not all.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/BalancerPairOracle.sol#L53-L64

## Tool used

Manual Review

## Recommendation
- Change the calculation logic so it aligns with Alpha's original implementation (with precision control), e.g. https://github.com/AlphaFinanceLab/alpha-homora-v2-contract/blob/master/contracts/oracle/BalancerPairOracle.sol#L42-L53 (you can see there's BONE extra precision in each step)



## Discussion

**n1punp**

Escalate for 10 USDC.
I think this is incorrectly **excluded**. The issue is not related to **flashloan** via **BalancerPairOracle**, but rather an organic math overflow/underflow, since the implementation is directly using 0.8.x's default SafeMath mode. Up

*[Content truncated...]*

---

### Example 16: M-6: `LendingPool#flashAction` is broken when trying to refinance position across `LendingPools` due to improper access control

**Source**: Sherlock
**Protocol**: Arcadia
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-12-arcadia-judging/issues/145 

## Found by 
0x52
## Summary

When refinancing an account, `LendingPool#flashAction` is used to facilitate the transfer. However due to access restrictions on `updateActionTimestampByCreditor`, the call made from the new creditor will revert, blocking any account transfers. This completely breaks refinancing across lenders which is a core functionality of the protocol.

## Vulnerability Detail

[LendingPool.sol#L564-L579](https://github.com/sherlock-audit/2023-12-arcadia/blob/main/lending-v2/src/LendingPool.sol#L564-L579)

    IAccount(account).updateActionTimestampByCreditor();

    asset.safeTransfer(actionTarget, amountBorrowed);

    {
        uint256 accountVersion = IAccount(account).flashActionByCreditor(actionTarget, actionData);
        if (!isValidVersion[accountVersion]) revert LendingPoolErrors.InvalidVersion();
    }

We see above that `account#updateActionTimestampByCreditor` is called before `flashActionByCreditor`.

[AccountV1.sol#L671](https://github.com/sherlock-audit/2023-12-arcadia/blob/main/accounts-v2/src/accounts/AccountV1.sol#L671)

    function updateActionTimestampByCreditor() external onlyCreditor updateActionTimestamp { }

When we look at this function, it can only be called by the current creditor. When refinancing a position, this function is actually called by the pending creditor since the `flashaction` should originate from there. This will cause the call to revert,

*[Content truncated...]*

---

### Example 17: M-12: rewardTokens removed from WAuraPool/WConvexPools will be lost forever

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/128 

## Found by 
0x52
## Summary

pendingRewards pulls a fresh count of reward tokens each time it is called. This is problematic if reward tokens are ever removed from the the underlying Aura/Convex pools because it means that they will no longer be distributed and will be locked in the contract forever.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength();
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

In the lines above we can see that only tokens that are currently available 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 17
- Examples shown: 17
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## vault-patterns.md
# Vault Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 6 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for vault vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-04] Users who deposit in one vault can lose all deposits and receive nothing when counterparty vault has no deposits

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Controller.sol#L148-L192>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Vault.sol#L350-L352>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Vault.sol#L203-L234>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Vault.sol#L378-L426>

### Impact

For a market, if users only deposit in the hedge vault or only deposit in the risk vault but not in both, then these users will lose their deposits and receive nothing when they call the following `withdraw` function after the depeg event occurs.

If the vault that has deposits is called Vault A, and the counterparty vault that has no deposit is called Vault B, then:

*   As shown by the `triggerDepeg` function below, when executing `insrVault.sendTokens(epochEnd, address(riskVault))` and `riskVault.sendTokens(epochEnd, address(insrVault))`, the deposits of Vault A are transferred to Vault B but nothing is transferred to Vault A since Vault B has no deposit;
*   When `triggerDepeg` executes `insrVault.setClaimTVL(epochEnd, riskVault.idFinalTVL(epochEnd))` and `riskVault.setClaimTVL(epochEnd, insrVault.idFinalTVL(epochEnd))`, Vault B's `idClaimTVL[id]` is set to Vault A's `idFinalTVL(epochEnd))` but Vault A's `idClaimTVL[id]` is set to 0 because Vault B's `idFinalTVL(epochEnd)` is 0.

Because of these, calling the `beforeWithdraw` function below will return a 0 `entitledAmount`, and calling `withdraw` then transfers th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 2: H-4: Victim's fund can be stolen due to rounding error and exchange rate manipulation

**Source**: Sherlock
**Protocol**: Napier
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/94 

The protocol has acknowledged this issue.

## Found by 
Bandit, LTDingZhen, cawfree, jennifer37, xAlismx, xiaoming90
## Summary

Victim's funds can be stolen by malicious users by exploiting the rounding error and through exchange rate manipulation.

## Vulnerability Detail

The LST Adaptor attempts to guard against the well-known vault inflation attack by reverting the TX when the amount of shares minted is rounded down to zero in Line 78 below.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/adapters/BaseLSTAdapter.sol#L71

```solidity
File: BaseLSTAdapter.sol
71:     function prefundedDeposit() external nonReentrant returns (uint256, uint256) {
72:         uint256 bufferEthCache = bufferEth; // cache storage reads
73:         uint256 queueEthCache = withdrawalQueueEth; // cache storage reads
74:         uint256 assets = IWETH9(WETH).balanceOf(address(this)) - bufferEthCache; // amount of WETH deposited at this time
75:         uint256 shares = previewDeposit(assets);
76: 
77:         if (assets == 0) return (0, 0);
78:         if (shares == 0) revert ZeroShares();
```

However, this control alone is not sufficient to guard against vault inflation attacks. 

Let's assume the following scenario (ignoring fee for simplicity's sake):

1. The victim initiates a transaction that deposits 10 ETH as the underlying asset when there are no issued estETH shares.
2. The attacker obse

*[Content truncated...]*

---

### Example 3: H-2: AutoRoller#eject can be used to steal all the yield from vault's YTs

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/22 

## Found by 
0x52

## Summary

AutoRoller#eject collects all the current yield of the YTs, combines the users share of the PTs and YTs then sends the user the entire target balance of the contract. The problem is that combine claims the yield for ALL YTs, which sends the AutoRoller target assets. Since it sends the user the entire target balance of the contract it accidentally sends the user the yield from all the pool's YTs. 

## Vulnerability Detail

    function eject(
        uint256 shares,
        address receiver,
        address owner
    ) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {

        ...

        //@audit call of interest
        (excessBal, isExcessPTs) = _exitAndCombine(shares);

        _burn(owner, shares); // Burn after percent ownership is determined in _exitAndCombine.

        if (isExcessPTs) {
            pt.transfer(receiver, excessBal);
        } else {
            yt.transfer(receiver, excessBal);
        }

        //@audit entire asset (adapter.target) balance transferred to caller, which includes collected YT yield and combined
        asset.transfer(receiver, assets = asset.balanceOf(address(this)));

        emit Ejected(msg.sender, receiver, owner, assets, shares,
            isExcessPTs ? excessBal : 0,
            isExcessPTs ? 0 : excessBal
        );
    }

    function _exitAndCombine(uint256 shares) internal returns (uint256, bool) {

*[Content truncated...]*

---

### Example 4: H-3: AutoRoller#eject can be used to steal all the yield from vault's YTs

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/22 

## Found by 
0x52

## Summary

AutoRoller#eject collects all the current yield of the YTs, combines the users share of the PTs and YTs then sends the user the entire target balance of the contract. The problem is that combine claims the yield for ALL YTs, which sends the AutoRoller target assets. Since it sends the user the entire target balance of the contract it accidentally sends the user the yield from all the pool's YTs. 

## Vulnerability Detail

    function eject(
        uint256 shares,
        address receiver,
        address owner
    ) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {

        ...

        //@audit call of interest
        (excessBal, isExcessPTs) = _exitAndCombine(shares);

        _burn(owner, shares); // Burn after percent ownership is determined in _exitAndCombine.

        if (isExcessPTs) {
            pt.transfer(receiver, excessBal);
        } else {
            yt.transfer(receiver, excessBal);
        }

        //@audit entire asset (adapter.target) balance transferred to caller, which includes collected YT yield and combined
        asset.transfer(receiver, assets = asset.balanceOf(address(this)));

        emit Ejected(msg.sender, receiver, owner, assets, shares,
            isExcessPTs ? excessBal : 0,
            isExcessPTs ? 0 : excessBal
        );
    }

    function _exitAndCombine(uint256 shares) internal returns (uint256, bool) {

*[Content truncated...]*

---

### Example 5: [H-05] Fee calculation mismatch in `mint`, `deposit`, `redeem` and `withdraw`

**Source**: Pashov Audit Group
**Protocol**: Astrolab
**Impact**: HIGH

**Details**:

**Severity**

**Impact:** Medium, fee will be a little higher/lower

**Likelihood:** High, because it happens in every call to mint and deposit functions

**Description**

When users calls `mint(shares)` code calls `_deposit(previewMint(_shares), _shares` and `previewMint(shares) = convertToAssets(shares).addBp()`.
When users calls `deposit(amount)` code calls `_deposit(_amount, previewDeposit(_amount)` and `previewDeposit(amount) = convertToShares(amount).subBp`.

Let's assume that price is 1:1 and fee is 10% and check the both case:

1. If user wants to mint 100 share then he would call `mint(100)` and code would calculate `amount = previewMint(100) = convertToAssets(100).addBp(10%) = 110`. So in the end user would pay 110 asset and receive 100 shares and 10 asset will be fee.
2. If users wants to deposit 110 asset then he would call `deposit(110)` and code would calculate `share = previewDeposit(110) = convertToShare(110).subBp(10%) = 99`. So in the end user would pay 11 asset and receive 99 share and 11 asset will be fee.

As you can see the `deposit()` call overcharge the user. The reason is that code calculates fee based on user-specified amount by using `subBp()` but user-specified amount is supposed to be `amount + fee` so the calculation for fee should be `.... * base / (base +fee)`.

---

When users call `redeem(shares)` code calls `_withdraw(previewRedeem(_shares), _shares)` and `previewRdeem(shares) = convertToAssets(_shares).subBp()`.

When users call `withdraw()

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Astrolab-security-review.md)

---

### Example 6: Inflation attack can cause early users to lose their deposit

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 7: M-8: asking for the wrong address for `balanceOf()`

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/116 

## Found by 
Ch\_301
## Summary

## Vulnerability Detail
ShortLongSpell.[openPosition()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L143-L150) pass to `_doPutCollateral()` wrong value of `balanceOf()`
```solidity
        // 5. Put collateral - strategy token
        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );
```
the balance should be of `address(vault)`

## Impact
- `openPosition()` will never work

## Code Snippet

## Tool used

Manual Review

## Recommendation
```diff
        // 5. Put collateral - strategy token
        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
-            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
-                address(this)
+                IERC20Upgradeable(vault).balanceOf(address(this))
            )
        );
```



## Discussion

**Ch-301**

Escalate for 10 USDC

This is a simple finding when you know that `SoftVault` is transferring all `uToken` to Compound to generate yield 

Also of wonder the judge set this as invalid but he submitted both this and #114  in the next contest **Blueberry Update 2**

**sherlock-admin**

 > Escalate for 10 USDC
> 
> This 

*[Content truncated...]*

---

### Example 8: Users depositing to a pool with unrealized losses will take on the losses

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `pool-v2::Pool.sol#L278`
- `pool-v2::Pool.sol#L275`

## Description
The pool share price used for deposits is always the `totalAssets() / totalSupply`. However, the pool share price when redeeming is `totalAssets() - unrealizedLosses() / totalSupply`. The `unrealizedLosses` value is increased by loan impairments (`LM.impairLoan`) or when starting to trigger a default with a liquidation (`LM.triggerDefault`). The `totalAssets` are only reduced by this value when the loss is realized in `LM.removeLoanImpairment` or `LM.finishCollateralLiquidation`.

This leads to a time window where deposits use a much higher share price than current redemptions and future deposits. Users depositing to the pool during this time window are almost guaranteed to incur losses when they are realized. In the worst case, a `Pool.deposit` might even be (accidentally) front-run by a loan impairment or liquidation.

## Recommendation
Make it very clear to the users when there are unrealized losses and communicate that it is a bad time to deposit. Furthermore, consider adding an `expectedMinimumShares` parameter that is checked against the actual minted shares. This ensures that users don't accidentally lose shares when front-run. Note that this would need to be a new `deposit(uint256 assets_, address receiver_, uint256 expectedMinimumShares_)` function to not break the ERC4626 compatibility. 

The `Pool.mint` function has a similar issue, whereas the `Pool.mintWithP

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 9: [M-01] Vault rebalancing can be exploited if two vaults rebalance into the same vault

**Source**: Code4rena
**Protocol**: Mimo DeFi
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52, also found by ayeslick_

User funds stolen.

### Proof of Concept

Swap data is completely arbitrary and can be used to swap though malicious ERC20 tokens allowing control transfer. This control transfer would allow the attacker to call rebalance on a second vault and exploit both as long as both vaults rebalance into the same vault.

Assumptions:<br>
Vault A and C both rebalance into vault B (i.e. value is transferred from vault A and C to vault B)<br>
Vault A and C are both eligible for rebalances<br>

Vault A -<br>
Value: $100<br>
Flashloan value: 50<br>

Vault B -<br>
Value: $100<br>

Vault C -<br>
Value: $100<br>
Flashloan value: 50<br>

1.  User calls rebalance on vault A to trigger it rebalancing to vault B, storing vault B's value as $100

2.  During the swap control is transferred due to use of malicious ERC20 specified in swap data

3.  Malicious token calls rebalance on vault C to trigger a rebalancing to vault B, storing vault B's value as $100 because Vault B's value hasn't been modified yet.

4.  Swap data in vault C rebalance swaps flashloan C to $50 worth of asset B

5.  Vault C rebalance deposits swap funds into vault B

6.  Vault C rebalance withdraws from vault C to pay back flashloan C

7.  Vault C rebalance validates that the value of B = $150 ( 100 + 50 ) and finishes, resuming Vault A rebalance

8.  Vault A rebalance finishes its swap, siphoning off the swapped funds to attacker through the malicious pool

9.  Vault A rebalance doesn

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-mimo)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## erc4626-patterns.md
# ERC4626 Security Patterns

## Overview

**Frequency**: 28 occurrences (0.06% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 10 | 16 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for erc4626 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: An attacker can freeze all incoming deposits and brick the oracle members' reporting system with only 1 wei

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

**Context:** SharesManager.1.sol#L195-L206

**Description:** An attacker can brick or lock all deposited user funds and also prevent oracle members from reaching a quorum when there are earnings to be distributed as rewards. Consider the following scenario:

1. The attacker forcefully sends 1 wei to the River contract using, e.g., `selfdestruct`. The attacker must ensure this transaction occurs before any other users deposit their funds in the contract. The attacker can observe the mempool and front-run the initial user deposit. Now, `b = _assetBalance() > 0` is at least 1 wei.
   
2. An allowed user tries to deposit funds into the River protocol. The call eventually ends up in `_mintShares(o, x)` and in the first line, `oldTotalAssetBalance = _assetBalance() - x`. Here, `_assetBalance()` represents the updated River balance after accounting for the user deposit `x`. So, `_assetBalance()` is now `b + x + ...` and `oldTotalAssetBalance = b + ...` where the `...` includes the beacon balance sum, deposited amounts for validators in the queue, etc. (which is probably 0 by this point). Therefore, `oldTotalAssetBalance > 0` means that the following if block is skipped:

   ```javascript
   if (oldTotalAssetBalance == 0) {
       _mintRawShares(_owner, _underlyingAssetValue);
       return _underlyingAssetValue;
   }
   ```

   It goes directly to the else block for the first allowed user deposit:

   ```javascript
   else {
       uint256 sharesToMint = 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 2: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`WithdrawProxy.sol#L172-L175`

## Description
Anytime there is a withdrawal pending (i.e., someone holds WithdrawProxy shares), shares may be redeemed as long as `totalAssets() > 0` and `s.finalAuctionEnd == 0`. Under normal operating conditions, `totalAssets()` becomes greater than 0 when the `PublicVault` calls `transferWithdrawReserve`. 

`totalAssets()` can also be increased to a non-zero value by anyone transferring WETH to the contract. If this occurs and a user attempts to redeem, they will receive a smaller share than they are owed.

### Exploit Scenario
- Depositor redeems from `PublicVault` and receives WithdrawProxy shares.
- Malicious actor deposits a small amount of WETH into the WithdrawProxy.
- Depositor accidentally redeems, or is tricked into redeeming, from the WithdrawProxy while `totalAssets()` is smaller than it should be.
- `PublicVault` properly processes epoch and full `withdrawReserve` is sent to the WithdrawProxy.
- All remaining holders of WithdrawProxy shares receive an outsized share as the previous shares were redeemed for the incorrect value.

## Recommendation

### Option 1
Consider being explicit in opening the WithdrawProxy for redemptions (`redeem/withdraw`) by requiring `s.withdrawReserveReceived` to be a non-zero value:

```solidity
if (s.finalAuctionEnd != 0) {
    // Updated condition
    if (s.finalAuctionEnd != 0 || s.withdrawReserveReceived == 0) {
        // if finalAuctionEnd is 0, no auctions were

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 3: [H-04] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

_Submitted by MiloTruck, also found by cccz, oyc_109, VAD37, PP1004, SmartSek, minhquanym, unforgiven, berndartmueller, WatchPug, CertoraInc, and sorrynotsorry_

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

In `BathToken.sol:569-571`, the allocation of shares is calculated as follows:

```js
(totalSupply == 0) ? shares = assets : shares = (
    assets.mul(totalSupply)
).div(_pool);
```

An early attacker can exploit this by:

*   Attacker calls `openBathTokenSpawnAndSignal()` with `initialLiquidityNew = 1`, creating a new bath token with `totalSupply = 1`
*   Attacker transfers a large amount of underlying tokens to the bath token contract, such as `1000000`
*   Using `deposit()`, a victim deposits an amount less than `1000000`, such as `1000`:
    *   `assets = 1000`
    *   `(assets * totalSupply) / _pool = (1000 * 1) / 1000000 = 0.001`, which would round down to `0`
    *   Thus, the victim receives no shares in return for his deposit

To avoid minting 0 shares, subsequent depositors have to deposit equal to or more than the amount transferred by the attacker. Otherwise, their deposits accrue to the attacker who holds the only share.

```js
it("Victim

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 4: [H-01] ERC4626 mint uses wrong `amount`

**Source**: Code4rena
**Protocol**: Tribe
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by 0xliumin, CertoraInc, Picodes, and Ruhum_

> The docs/video say `ERC4626.sol` is in scope as its part of `TurboSafe`

The `ERC4626.mint` function mints `amount` instead of `shares`.
This will lead to issues when the `asset <> shares` are not 1-to-1 as will be the case for most vaults over time.
Usually, the asset amount is larger than the share amount as vaults receive asset yield.
Therefore, when minting, `shares` should be less than `amount`.
Users receive a larger share amount here which can be exploited to drain the vault assets.

```solidity
function mint(uint256 shares, address to) public virtual returns (uint256 amount) {
    amount = previewMint(shares); // No need to check for rounding error, previewMint rounds up.

    // Need to transfer before minting or ERC777s could reenter.
    asset.safeTransferFrom(msg.sender, address(this), amount);
    _mint(to, amount);

    emit Deposit(msg.sender, to, amount, shares);

    afterDeposit(amount, shares);
}
```

### Proof of Concept

Assume `vault.totalSupply() = 1000`, `totalAssets = 1500`

*   call `mint(shares=1000)`. Only need to pay `1000` asset amount but receive `1000` shares => `vault.totalSupply() = 2000`, `totalAssets = 2500`.
*   call `redeem(shares=1000)`. Receive `(1000 / 2000) * 2500 = 1250` amounts. Make a profit of `250` asset tokens.
*   repeat until `shares <> assets` are 1-to-1

### Recommended Mitigation Steps

In `deposit`:

```diff
function mint(uint256 shares, addr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-tribe-turbo)

---

### Example 5: H-1: Attacker can manipulate the pricePerShare to profit from future users' deposits

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/001-H 

## Found by 
Ruhum, ctf\_sec, cccz, joestakey, ellahi, \_\_141345\_\_, 8olidity, hansfriese, minhquanym, 0x52, caventa, rvierdiiev, Sm4rty, rbserver, IllIllI, sorrynotsorry, JohnSmith, defsec, WATCHPUG, berndartmueller, ak1

## Summary

By manipulating and inflating the pricePerShare to a super high value, the attacker can cause all future depositors to lose a significant portion of their deposits to the attacker due to precision loss.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `LINK` token as the first depositor of the Vault, and get `(1 * STARTING_SHARES_PER_LINK) wei` of shares.

Then the attacker can send `STARTING_SHARES_PER_LINK - 1` of `LINK` tokens and inflate the price per share from `1 / STARTING_SHARES_PER_LINK` to 1.0000 .

Then the attacker call `withdraw()` to withdraw `STARTING_SHARES_PER_LINK - 1` shares, and send `1e22` of `LINK` token and inflate the price per share from 1.000 to 1.000e22.

As a result, the future user who deposits `9999e18` will only receive `0` (from `9999e18 * 1 / 10000e18`) of shares token.

They will immediately lose all of their deposits.

## Impact

Users may suffer a significant portion or even 100% of the funds they deposited to the Vault.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-142

```solidity
    function deposit(uint256 _amount) exter

*[Content truncated...]*

---

### Example 6: H-4: `ERC4626Oracle` Price will be wrong when the ERC4626's `decimals` is different from the underlying tokens decimals

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

### Example 7: H-4: Victim's fund can be stolen due to rounding error and exchange rate manipulation

**Source**: Sherlock
**Protocol**: Napier
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/94 

The protocol has acknowledged this issue.

## Found by 
Bandit, LTDingZhen, cawfree, jennifer37, xAlismx, xiaoming90
## Summary

Victim's funds can be stolen by malicious users by exploiting the rounding error and through exchange rate manipulation.

## Vulnerability Detail

The LST Adaptor attempts to guard against the well-known vault inflation attack by reverting the TX when the amount of shares minted is rounded down to zero in Line 78 below.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/adapters/BaseLSTAdapter.sol#L71

```solidity
File: BaseLSTAdapter.sol
71:     function prefundedDeposit() external nonReentrant returns (uint256, uint256) {
72:         uint256 bufferEthCache = bufferEth; // cache storage reads
73:         uint256 queueEthCache = withdrawalQueueEth; // cache storage reads
74:         uint256 assets = IWETH9(WETH).balanceOf(address(this)) - bufferEthCache; // amount of WETH deposited at this time
75:         uint256 shares = previewDeposit(assets);
76: 
77:         if (assets == 0) return (0, 0);
78:         if (shares == 0) revert ZeroShares();
```

However, this control alone is not sufficient to guard against vault inflation attacks. 

Let's assume the following scenario (ignoring fee for simplicity's sake):

1. The victim initiates a transaction that deposits 10 ETH as the underlying asset when there are no issued estETH shares.
2. The attacker obse

*[Content truncated...]*

---

### Example 8: Multiple ERC4626Router and ERC4626RouterBase functions will always revert

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `ERC4626Router.sol#L49-58`
- `ERC4626RouterBase.sol#L47`
- `ERC4626RouterBase.sol#L60`

## Description
The intention of the `ERC4626Router.sol` functions is that they are approval-less ways to deposit and redeem:

> For the below, no approval needed, assumes vault is already max approved.

As long as the user has approved the `TRANSFER_PROXY` for WETH, this works for the `depositToVault` function:
- WETH is transferred from the user to the router with `pullTokens`.
- The router approves the vault for the correct amount of WETH.
- `vault.deposit()` is called, which uses `safeTransferFrom` to transfer WETH from the router into the vault.

However, for the `redeemMax` function, it doesn't work:
- Approves the vault to spend the router's WETH.
- `vault.redeem()` is called, which tries to transfer vault tokens from the router to the vault, and then mints withdraw proxy tokens to the receiver.

This error occurs assuming that the vault tokens would be burned, in which case the logic would work. But since they are transferred into the vault until the end of the epoch, we require approvals.

The same issue also exists in these two functions in `ERC4626RouterBase.sol`:
- `redeem()`: this is where the incorrect approval lives, so the same issue occurs when it is called directly.
- `withdraw()`: the same faulty approval exists in this function.

## Recommendation
`redeemMax` should follow the same flow as `deposit` to make this work:
- `redeemMax` 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 9: H-1: A malicious early user/attacker can manipulate the LToken's pricePerShare to take an unfair share of future users' deposits

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/004-H 
## Found by 
kankodu, JohnSmith, PwnPatrol, WATCHPUG, berndartmueller, hyh, \_\_141345\_\_, IllIllI, TomJ

## Summary

A well known attack vector for almost all shares based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `asset` token as the first depositor of the LToken, and get `1 wei` of shares.

Then the attacker can send `10000e18 - 1` of `asset` tokens and inflate the price per share from 1.0000 to an extreme value of 1.0000e22 ( from `(1 + 10000e18 - 1) / 1`) .

As a result, the future user who deposits `19999e18` will only receive `1 wei` (from `19999e18 * 1 / 10000e18`) of shares token.

They will immediately lose `9999e18` or half of their deposits if they `redeem()` right after the `deposit()`.

## Impact

The attacker can profit from future users' deposits. While the late users will lose part of their funds to the attacker.

## Code Snippet

https://github.com/sentimentxyz/protocol/blob/4e45871e4540df0f189f6c89deb8d34f24930120/src/tokens/utils/ERC4626.sol#L48-L60

```solidity
function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
    beforeDeposit(assets, shares);

    // Check for rounding error since we round d

*[Content truncated...]*

---

### Example 10: [M-16] `vMaia` is ERC-4626 compliant, but the `maxWithdraw` & `maxRedeem` functions are not fully up to EIP-4626's specification

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

The `maxWithdraw` & `maxRedeem` functions should return the `0` when the withdrawal is paused. But here, it's returning `balanceOf[user]`.

### Proof of Concept

`vMaia Withdrawal` is only allowed once per month during the 1st Tuesday (UTC+0) of the month.

It's checked by the below function:

```

     102       function beforeWithdraw(uint256, uint256) internal override {
                /// @dev Check if unstake period has not ended yet, continue if it is the case.
                if (unstakePeriodEnd >= block.timestamp) return;
        
                uint256 _currentMonth = DateTimeLib.getMonth(block.timestamp);
                if (_currentMonth == currentMonth) revert UnstakePeriodNotLive();
        
                (bool isTuesday, uint256 _unstakePeriodStart) = DateTimeLib.isTuesday(block.timestamp);
                if (!isTuesday) revert UnstakePeriodNotLive();
        
                currentMonth = _currentMonth;
                unstakePeriodEnd = _unstakePeriodStart + 1 days;
    114        }
```

<https://github.com/code-423n4/2023-05-maia/blob/main/src/maia/vMaia.sol#L102C1-L114C6>

```

    173            function maxWithdraw(address user) public view virtual override returns (uint256) {
                      return balanceOf[user];
                  }
              
                  /// @notice Returns the maximum amount of assets that can be redeemed by a user.
                  /// @dev Assumes that the user has already forfeited all utility tokens.
      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 11: M-15: LToken's implmentation is not fully up to EIP-4626's specification

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/500-M 
## Found by 
WATCHPUG

## Summary

Note: This issue is a part of the extra scope added by Sentiment AFTER the audit contest. This scope was only reviewed by WatchPug and relates to these three PRs:

1. [Lending deposit cap](https://github.com/sentimentxyz/protocol/pull/234)
2. [Fee accrual modification](https://github.com/sentimentxyz/protocol/pull/233)
3. [CRV staking](https://github.com/sentimentxyz/controller/pull/41)

LToken's implmentation is not fully up to EIP-4626's specification. This issue is would actually be considered a Low issue if it were a part of a Sherlock contest. 

## Vulnerability Detail

https://github.com/sentimentxyz/protocol/blob/ccfceb2805cf3595a95198c97b6846c8a0b91506/src/tokens/utils/ERC4626.sol#L185-L187

```solidity
function maxMint(address) public view virtual returns (uint256) {
    return type(uint256).max;
}
```

MUST return the maximum amount of shares mint would allow to be deposited to receiver and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary). This assumes that the user has infinite assets, i.e. MUST NOT rely on balanceOf of asset.

https://eips.ethereum.org/EIPS/eip-4626#:~:text=MUST%20return%20the%20maximum%20amount%20of%20shares,NOT%20rely%20on%20balanceOf%20of%20asset

maxMint() and maxDeposit() should reflect the limitation of maxSupply.

## Impact

Could cause unexp

*[Content truncated...]*

---

### Example 12: M-10: ERC4626Oracle Vulnerable To Price Manipulation

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

### Example 13: [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint)

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

### Example 14: M-5: Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

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

### Example 15: M-12: Vault Share/Strategy Token Calculation Can Be Broken By First User/Attacker

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/70 

## Found by 
xiaoming90

## Summary

A well-known attack vector for almost all shares-based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

> Note: This issue affects MetaStable2 and Boosted3 balancer leverage vaults

For simplicity's sake, we will simplify the strategy token minting formula as follows. Also, assume that the 1 vault share is equivalent to 1 strategy token for this particular strategy vault, therefore, we will use the term `vault share` and `strategy token` interchangeably here.

```solidity
strategyToken = (totalBPTHeld == 0) ?  bptClaim : (bptClaim * totalStrategyToken) / totalBPTHeld
```

The vault minting formula is taken from the following:

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/strategy/StrategyUtils.sol#L27

```solidity
File: StrategyUtils.sol
26:     /// @notice Converts BPT to strategy tokens
27:     function _convertBPTClaimToStrategyTokens(StrategyContext memory context, uint256 bptClaim)
28:         internal pure returns (uint256 strategyTokenAmount) {
29:         if (context.totalBPTHeld == 0) {
30:             // Strategy tokens are in 8 decimal precision, BPT is in 18. Scale the minted amount down.
31:             retu

*[Content truncated...]*

---

### Example 16: [M-02] Slippage controls for calling `bHermes` contract's `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions are missing

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

[EIPS](<https://eips.ethereum.org/EIPS/eip-4626#security-considerations>) mentions that "if implementors intend to support EOA account access directly, they should consider adding an additional function call for `deposit`/`mint`/`withdraw`/`redeem` with the means to accommodate slippage loss or unexpected deposit/withdrawal limits, since they have no other means to revert the transaction if the exact output amount is not achieved."

Using the `bHermes` contract that inherits the `ERC4626DepositOnly` contract, EOAs can call the `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions directly. However, because no slippage controls can be specified when calling these functions, these function's `shares` and `assets` outputs can be less than expected to these EOAs.

<https://github.com/code-423n4/2023-05-maia/blob/53c7fe9d5e55754960eafe936b6cb592773d614c/src/erc-4626/ERC4626DepositOnly.sol#L32-L44>

```solidity
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        address(asset).safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
```

<https://github.com/code-423n4/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 17: H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/50 

## Found by 
ak1

## Summary
Most of the share based vault implementation will face this issue.
The vault is based on the ERC4626 where the shares are calculated based on the deposit value.
By depositing large amount as initial deposit, initial depositor can influence the future depositors value.

## Vulnerability Detail

Shares are minted based on the deposit value.
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L59-L79
Public vault is based on the ERC4626 where the shares are calculated based on the deposit value.

By depositing large amount as initial deposit, first depositor can take advantage over other depositors.

I am sharing reference for this type of issue that already reported and acknowledged. This explain how the share price could be manipulated to  large value.

https://github.com/sherlock-audit/2022-08-sentiment-judging#issue-h-1-a-malicious-early-userattacker-can-manipulate-the-ltokens-pricepershare-to-take-an-unfair-share-of-future-users-deposits:~:text=Issue%20H%2D1%3A%20A%20malicious%20early%20user/attacker%20can%20manipulate%20the%20LToken%27s%20pricePerShare%20to%20take%20an%20unfair%20share%20of%20future%20users%27%20deposits

ERC4626 implementation
    function mint(uint256 shares, address receiver) public virtual returns (uint256 assets) {
        assets = previewMint(shares); // No need to check for rounding error, previewMint round

*[Content truncated...]*

---

### Example 18: [M-07] `PrizeVault.maxDeposit()` doesn't take into account produced fees

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L368-L392><br>
<https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L685><br>
<https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L619>

### Summary

Currently, `PrizeVault.maxDeposit()` calculates the maximum possible amount of deposit without taking into account produced fees. That means if there is already maxed deposited amount of asset that is calculated by the current implementation in `PrizeVault.maxDeposit()`, `yieldFeeRecipient` can't withdraw shares with `PrizeVault.claimYieldFeeShares()` because in that case `_mint()` will revert because of overflow. A lot of low-price tokens can exceed the limit of `type(uint96).max` with ease. For example, to make a deposit with `maxDeposit()` value with LADYS token it's needed only `$13568` (as of 08-03-2024).

### Impact

If a user makes a maximum allowed deposit that is calculated by the current implementation of `PrizeVault.maxDeposit()`, `yieldFeeRecipient` can't withdraw fees if they are available.

### Proof of Concept

Add this test to `PrizeVault.t.sol` and run with:

```
    forge test --match-contract PrizeVaultTest --match-test testMaxDeposit_CalculatesWithoutTakingIntoAccountGeneratedFees
```

```solidity
    function _deposit(address accou

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

### Example 19: [M-06] Funds locked due to missing transfer check

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

All of the user's funds are unretrievably locked in the `PrizeVault` contract.

A combination of issues allows for the following scenario:

1. Alice invokes [`_withdraw(receiver, assets)`](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L925-L941) (via `burn()` or `withdraw()`).
2. The contract [computes the number of shares to redeem](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L933-L934), via `previewWithdraw(assets)`.
3. The contract [redeems as many shares](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L935-L936), but the ERC 4626-compliant vault returns fewer shares than expected. At this point, the contract holds fewer than `assets` tokens.
4. The contract [attempts to `transfer` assets to the receiver](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L939). This fails due to insufficient funds, but the ERC 20-compliant token does not revert (only returns `false`).
5. At this point, Alice's assets are locked in the `PrizeVault` contract. They cannot be withdrawn at a later point, because the corresponding prize vault and yield vault shares have been burned.

The exploit relies on insufficient handling of two corner cases of [ERC-20](https://eips.ether

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

### Example 20: [M-07] ```trancheTokenAmount``` should be rounded UP when proceeding to a withdrawal or previewing a withdrawal

**Source**: Code4rena
**Protocol**: Centrifuge
**Impact**: MEDIUM

**Details**:

This is good practice when implementing the EIP-4626 vault standard as it is more secure to favour the vault than its users in that case.<br>
This can also lead to issues down the line for other protocol integrating Centrifuge, that may assume that rounding was handled according to EIP-4626 best practices.

### Proof of Concept

When calling the [`processWithdraw`](https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/InvestmentManager.sol#L515) function, the `trancheTokenAmount` is computed through the [`_calculateTrancheTokenAmount`](https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/InvestmentManager.sol#L591) function, which rounds DOWN the number of shares required to be burnt to receive the `currencyAmount` payout/withdrawal.

```solidity
/// @dev Processes user's tranche token redemption after the epoch has been executed on Centrifuge.
/// In case user's redempion order was fullfilled on Centrifuge during epoch execution MaxRedeem and MaxWithdraw
/// are increased and LiquidityPool currency can be transferred to user's wallet on calling processRedeem or processWithdraw.
/// Note: The trancheTokenAmount required to fullfill the redemption order was already locked in escrow upon calling requestRedeem and burned upon collectRedeem.
/// @notice trancheTokenAmount return value is type of uint256 to be compliant with EIP4626 LiquidityPool interface
/// @return trancheTokenAmount the amount of trancheTokens redeemed/burned required to receive the currency

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-centrifuge)

---

### Example 21: [M-01] If the underlying asset is a fee on transfer token, it could break the internal accounting of the vault

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

The `Vault._deposit` function is used by the users to deposit `_assets` to the vault and mint vault shares to the `recipient` address. The amount of `_assets` are transferred to the `Vault` as follows:

      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? _assetsDeposit : _assets
      );

The `Vault.deposit` function uses this `_assets` amount to calculate the number of `shares` to be minted to the `_recipient` address.

The issue here is if the underlying `_asset` is a fee on transfer token then the actual received amount to the vault will be less than what is referred in the `Vault.deposit` function `_assets` input parameter. But the shares to mint is calculated using the entire `_assets` amount.

This issue could be further aggravated since the `_asset` is again `deposited` to the `_yieldVault` and when needing to be redeemed, will be `withdrawn` from the `_yieldVault` as well. These operations will again charge a fee if the `_asset` is a fee on transfer token. Hence, the actual `_asset` amount left for a particular user will be less than the amount they initially transferred in.

Hence, when the user `redeems` the minted shares back to the `_assets`, the contract will not have enough assets to transfer to the `redeemer`, thus reverting the transaction.

### Proof of Concept

```solidity
      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 22: [M-22] `ERC4626RouterBase.withdraw` can only be called once

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

ERC4626RouterBase.withdraw will approve an amount of vault tokens to the vault, but the amount represents the number of asset tokens taken out by vault.withdraw, not the required number of vault tokens, and since it normally requires less than 1 vault token to take out 1 asset token, it will prevent ERC4626RouterBase.withdraw from using all approved vault tokens.

```solidity
  function withdraw(
    IERC4626 vault,
    address to,
    uint256 amount,
    uint256 maxSharesOut
  ) public payable virtual override returns (uint256 sharesOut) {

    ERC20(address(vault)).safeApprove(address(vault), amount);
    if ((sharesOut = vault.withdraw(amount, to, msg.sender)) > maxSharesOut) {
      revert MaxSharesError();
    }
  }
```

and since safeApprove cannot approve a non-zero value to a non-zero value, the second call to ERC4626RouterBase.withdraw will fails in safeApprove.

```solidity
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 23: [M-06] For a public vault, minimum deposit requirement that is enforced by `ERC4626Cloned.deposit` function can be bypassed by `ERC4626Cloned.mint` function or vice versa when share price does not equal one

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

The following `ERC4626Cloned.deposit` function has `require(shares > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement, and the `ERC4626Cloned.mint` function below has `require(assets > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement. For a public vault, when the share price becomes different than 1, these functions' minimum deposit requirements are no longer the same. For example, given `S` is the `shares` input value for the `ERC4626Cloned.mint` function and `A` equals `ERC4626Cloned.previewMint(S)`, when the share price is bigger than 1 and `A` equals `minDepositAmount() + 1`, such `A` will violate the `ERC4626Cloned.deposit` function's minimum deposit requirement but the corresponding `S` will not violate the `ERC4626Cloned.mint` function's minimum deposit requirement; in this case, the user can just ignore the `ERC4626Cloned.deposit` function and call `ERC4626Cloned.mint` function to become a liquidity provider. Thus, when the public vault's share price is different than 1, the liquidity provider can call the less restrictive function out of the two so the minimum deposit requirement enforced by one of the two functions is not effective at all; this can result in unexpected deposit amounts and degraded filtering of who can participate as a liquidity provider.

<https://github.com/AstariaXYZ/astaria-gpl/blob/main/src/ERC4626-Cloned.sol#L19-L36>

```solidity
  function deposit(uint256 assets, address receiver)
    public


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 24: H-3: Early depositors to BufferBinaryPool can manipulate exchange rates to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/81 

## Found by 
dipp, gandu, rvierdiiev, Ruhum, hansfriese, cccz, 0x52, ctf\_sec, joestakey

## Summary

To calculate the exchange rate for shares in BufferBinaryPool it divides the total supply of shares by the totalTokenXBalance of the vault. The first deposit can mint a very small number of shares then donate tokenX to the vault to grossly manipulate the share price. When later depositor deposit into the vault they will lose value due to precision loss and the adversary will profit.

## Vulnerability Detail

    function totalTokenXBalance()
        public
        view
        override
        returns (uint256 balance)
    {
        return tokenX.balanceOf(address(this)) - lockedPremium;
    }

Share exchange rate is calculated using the total supply of shares and the totalTokenXBalance, which leaves it vulnerable to exchange rate manipulation. As an example, assume tokenX == USDC. An adversary can mint a single share, then donate 1e8 USDC. Minting the first share established a 1:1 ratio but then donating 1e8 changed the ratio to 1:1e8. Now any deposit lower than 1e8 (100 USDC) will suffer from precision loss and the attackers share will benefit from it.

## Impact

Adversary can effectively steal funds from later users through precision loss

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L405-L412

## Tool used

Manual Revie

*[Content truncated...]*

---

### Example 25: M-1: Vault Inflation Attack

**Source**: Sherlock
**Protocol**: Smilee Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-smilee-finance-judging/issues/22 

## Found by 
kfx, santipu\_

## Summary

An attacker can be the first and only depositor on the vault during the first epoch in order to execute an inflation attack that will steal the deposited funds of all depositors in the next epoch. 

## Vulnerability Detail

A malicious user can perform a donation to execute a classic first depositor/ERC4626 inflation Attack against the new Smilee vaults. The general process of this attack is well-known, and a detailed explanation of this attack can be found in many of the resources such as the following:

- https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks
- https://mixbytes.io/blog/overview-of-the-inflation-attack

In short, to kick-start the attack, the malicious user will often usually mint the smallest possible amount of shares (e.g., 1 wei) and then donate significant assets to the vault to inflate the number of assets per share. Subsequently, it will cause a rounding error when other users deposit.

However, in Smilee there's the problem that the deposits are not processed until the epoch is finished. Therefore, the attacker would need to be the only depositor on the first epoch of the vault; after the second epoch starts, all new depositors will lose all the deposited funds due to a rounding error. 

This scenario may happen for newly deployed vaults with a short maturity period (e.g., 1 day) and/or for vaults with 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 28
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## eip-4626-patterns.md
# EIP-4626 Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 7 | 0 | 0 |

**Common Sources**: Code4rena, Pashov Audit Group, Spearbit

---

## Detection Checklist

- [ ] Check for eip-4626 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`WithdrawProxy.sol#L172-L175`

## Description
Anytime there is a withdrawal pending (i.e., someone holds WithdrawProxy shares), shares may be redeemed as long as `totalAssets() > 0` and `s.finalAuctionEnd == 0`. Under normal operating conditions, `totalAssets()` becomes greater than 0 when the `PublicVault` calls `transferWithdrawReserve`. 

`totalAssets()` can also be increased to a non-zero value by anyone transferring WETH to the contract. If this occurs and a user attempts to redeem, they will receive a smaller share than they are owed.

### Exploit Scenario
- Depositor redeems from `PublicVault` and receives WithdrawProxy shares.
- Malicious actor deposits a small amount of WETH into the WithdrawProxy.
- Depositor accidentally redeems, or is tricked into redeeming, from the WithdrawProxy while `totalAssets()` is smaller than it should be.
- `PublicVault` properly processes epoch and full `withdrawReserve` is sent to the WithdrawProxy.
- All remaining holders of WithdrawProxy shares receive an outsized share as the previous shares were redeemed for the incorrect value.

## Recommendation

### Option 1
Consider being explicit in opening the WithdrawProxy for redemptions (`redeem/withdraw`) by requiring `s.withdrawReserveReceived` to be a non-zero value:

```solidity
if (s.finalAuctionEnd != 0) {
    // Updated condition
    if (s.finalAuctionEnd != 0 || s.withdrawReserveReceived == 0) {
        // if finalAuctionEnd is 0, no auctions were

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: [H-08] Vault.sol is not EIP-4626 compliant

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/Vault.sol#L244-L252>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L205-L213>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L237-L239>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L244-L246>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L251-L258>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L263-L270>

### Impact

Other protocols that integrate with Y2K may wrongly assume that the functions are EIP-4626 compliant. Thus, it might cause integration problems in the future that can lead to wide range of issues for both parties.

### Proof of Concept

All official EIP-4626 requirements can be found on it's [official page](https://eips.ethereum.org/EIPS/eip-4626#methods). Non-compliant functions are listed below along with the reason they are not compliant:

The following functions are missing but should be present:

1.  mint(uint256, address) returns (uint256)
2.  redeem(uint256, address, address) returns (uint256)

The following functions are non-compliant because they don't account for withdraw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 3: [M-16] `vMaia` is ERC-4626 compliant, but the `maxWithdraw` & `maxRedeem` functions are not fully up to EIP-4626's specification

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

The `maxWithdraw` & `maxRedeem` functions should return the `0` when the withdrawal is paused. But here, it's returning `balanceOf[user]`.

### Proof of Concept

`vMaia Withdrawal` is only allowed once per month during the 1st Tuesday (UTC+0) of the month.

It's checked by the below function:

```

     102       function beforeWithdraw(uint256, uint256) internal override {
                /// @dev Check if unstake period has not ended yet, continue if it is the case.
                if (unstakePeriodEnd >= block.timestamp) return;
        
                uint256 _currentMonth = DateTimeLib.getMonth(block.timestamp);
                if (_currentMonth == currentMonth) revert UnstakePeriodNotLive();
        
                (bool isTuesday, uint256 _unstakePeriodStart) = DateTimeLib.isTuesday(block.timestamp);
                if (!isTuesday) revert UnstakePeriodNotLive();
        
                currentMonth = _currentMonth;
                unstakePeriodEnd = _unstakePeriodStart + 1 days;
    114        }
```

<https://github.com/code-423n4/2023-05-maia/blob/main/src/maia/vMaia.sol#L102C1-L114C6>

```

    173            function maxWithdraw(address user) public view virtual override returns (uint256) {
                      return balanceOf[user];
                  }
              
                  /// @notice Returns the maximum amount of assets that can be redeemed by a user.
                  /// @dev Assumes that the user has already forfeited all utility tokens.
      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 4: [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint)

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

### Example 5: [M-02] Slippage controls for calling `bHermes` contract's `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions are missing

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

[EIPS](<https://eips.ethereum.org/EIPS/eip-4626#security-considerations>) mentions that "if implementors intend to support EOA account access directly, they should consider adding an additional function call for `deposit`/`mint`/`withdraw`/`redeem` with the means to accommodate slippage loss or unexpected deposit/withdrawal limits, since they have no other means to revert the transaction if the exact output amount is not achieved."

Using the `bHermes` contract that inherits the `ERC4626DepositOnly` contract, EOAs can call the `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions directly. However, because no slippage controls can be specified when calling these functions, these function's `shares` and `assets` outputs can be less than expected to these EOAs.

<https://github.com/code-423n4/2023-05-maia/blob/53c7fe9d5e55754960eafe936b6cb592773d614c/src/erc-4626/ERC4626DepositOnly.sol#L32-L44>

```solidity
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        address(asset).safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
```

<https://github.com/code-423n4/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 6: [M-22] `ERC4626RouterBase.withdraw` can only be called once

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

ERC4626RouterBase.withdraw will approve an amount of vault tokens to the vault, but the amount represents the number of asset tokens taken out by vault.withdraw, not the required number of vault tokens, and since it normally requires less than 1 vault token to take out 1 asset token, it will prevent ERC4626RouterBase.withdraw from using all approved vault tokens.

```solidity
  function withdraw(
    IERC4626 vault,
    address to,
    uint256 amount,
    uint256 maxSharesOut
  ) public payable virtual override returns (uint256 sharesOut) {

    ERC20(address(vault)).safeApprove(address(vault), amount);
    if ((sharesOut = vault.withdraw(amount, to, msg.sender)) > maxSharesOut) {
      revert MaxSharesError();
    }
  }
```

and since safeApprove cannot approve a non-zero value to a non-zero value, the second call to ERC4626RouterBase.withdraw will fails in safeApprove.

```solidity
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 7: [M-06] For a public vault, minimum deposit requirement that is enforced by `ERC4626Cloned.deposit` function can be bypassed by `ERC4626Cloned.mint` function or vice versa when share price does not equal one

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

The following `ERC4626Cloned.deposit` function has `require(shares > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement, and the `ERC4626Cloned.mint` function below has `require(assets > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement. For a public vault, when the share price becomes different than 1, these functions' minimum deposit requirements are no longer the same. For example, given `S` is the `shares` input value for the `ERC4626Cloned.mint` function and `A` equals `ERC4626Cloned.previewMint(S)`, when the share price is bigger than 1 and `A` equals `minDepositAmount() + 1`, such `A` will violate the `ERC4626Cloned.deposit` function's minimum deposit requirement but the corresponding `S` will not violate the `ERC4626Cloned.mint` function's minimum deposit requirement; in this case, the user can just ignore the `ERC4626Cloned.deposit` function and call `ERC4626Cloned.mint` function to become a liquidity provider. Thus, when the public vault's share price is different than 1, the liquidity provider can call the less restrictive function out of the two so the minimum deposit requirement enforced by one of the two functions is not effective at all; this can result in unexpected deposit amounts and degraded filtering of who can participate as a liquidity provider.

<https://github.com/AstariaXYZ/astaria-gpl/blob/main/src/ERC4626-Cloned.sol#L19-L36>

```solidity
  function deposit(uint256 assets, address receiver)
    public


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 8: [M-02] The ERC4626 standard is not followed correctly

**Source**: Pashov Audit Group
**Protocol**: Florence Finance
**Impact**: MEDIUM

**Details**:

**Impact:**
Medium, as functionality is not working as expected but without a value loss

**Likelihood:**
Medium, as multiple methods are not compliant with the standard

**Description**

As per EIP-4626, the `maxDeposit` method "MUST factor in both global and user-specific limits, like if deposits are entirely disabled (even temporarily) it MUST return 0.". This is not the case currently, as even if the contract is paused, the `maxDeposit` method will still return what it usually does.

When it comes to the `decimals` method, the EIP says: "Although the convertTo functions should eliminate the need for any use of an EIP-4626 Vaults decimals variable, it is still strongly recommended to mirror the underlying tokens decimals if at all possible, to eliminate possible sources of confusion and simplify integration across front-ends and for other off-chain users."
The `LoanVault` contract has hardcoded the value of 18 to be returned when `decimals` are called, but it should be the decimals of the underlying token (it might not be 18 in some case maybe).

**Recommendations**

Go through [the standard](https://eips.ethereum.org/EIPS/eip-4626) and follow it for all methods that `override` methods from the inherited ERC4626 implementation.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-04-01-Florence Finance.md)

---

### Example 9: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## swap-patterns.md
# Swap Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 12 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for swap vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Tokens are left in the protocol when the swap at the destination chain fails

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
- AmarokFacet.sol#L55-L94
- StargateFacet.sol#L149-L187
- NXTPFacet.sol#L86-L117
- Executor.sol#L125-L221
- XChainExecFacet.sol#L17-L51

## Description
LiFi protocol finds the best bridge route for users. In some cases, it helps users do a swap at the destination chain. With the help of the bridge protocols, the LiFi protocol assists users in triggering `swapAndComplete-BridgeTokensVia{Services}` or `CompleteBridgeTokensVia{Services}` at the destination chain to perform the swap.

Some bridge services will send the tokens directly to the receiver address when the execution fails. For example, Stargate, Amarok, and NXTP conduct the external call in a try-catch clause and send the tokens directly to the receiver when it fails. The tokens will remain in the LiFi protocol in this scenario. If the receiver is the Executor contract, users can freely pull the tokens. 

**Note:** Exploiters can pull the tokens from the LiFi protocol. Please refer to the issue **"Remaining tokens can be swept from the LiFi Diamond or the Executor," Issue #82**. Exploiters can take a more aggressive strategy and force the victim's swap to revert. A possible exploit scenario:

- A victim wants to swap 10K optimisms BTC into Ethereum mainnet USDC.
- Since DEXs on the mainnet have the best liquidity, the LiFi protocol helps users swap on the mainnet.
- The transaction on the source chain (optimism) succeeds, and the bridge services try to call `Co

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: swapOut allows overwrite of token balance

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**Critical Risk**

## Context
- **StableSwapFacet.sol**: Lines 266-281
- **SwapUtils.sol**: Lines 740-781, Lines 417-473

## Description
The `StableSwapFacet` has the function `swapExactOut()` where a user could supply the same `assetIn` address as `assetOut`, which means the indexes for `tokenIndexFrom` and `tokenIndexTo` in the function `swapOut()` are the same.

In the function `swapOut()`, a temporary array is used to store balances. When updating these balances, first `self.balances[tokenIndexFrom]` is updated and then `self.balances[tokenIndexTo]` is updated afterward. 

However, when `tokenIndexFrom == tokenIndexTo`, the second update overwrites the first update, causing token balances to be arbitrarily lowered. This also skews the exchange rates, allowing for swaps where value can be extracted.

**Note:** The protection against this problem is located in the function `getY()`. However, this function is not called from `swapOut()`.

**Note:** The same issue exists in `swapInternalOut()`, which is called from `swapFromLocalAssetIfNeededForExactOut()` via `_swapAssetOut()`. However, via this route, it is not possible to specify arbitrary token indexes. Therefore, there isnt an immediate risk here.

### Code Snippets
```solidity
contract StableSwapFacet is BaseConnextFacet {
    ...
    function swapExactOut(..., address assetIn, address assetOut, ...) ... {
        return s.swapStorages[canonicalId].swapOut(
            getSwapTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: [H-16] VaderRouter.calculateOutGivenIn calculates wrong swap

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The 3-path hop in `VaderRouter.calculateOutGivenIn` is supposed to first swap **foreign** assets to native assets **in pool0**, and then the received native assets to different foreign assets again **in pool1**.

The first argument of `VaderMath.calculateSwap(amountIn, reserveIn, reserveOut)` must refer to the same token as the second argument `reserveIn`.
The code however mixes these positions up and first performs a swap in `pool1` instead of `pool0`:

```solidity
function calculateOutGivenIn(uint256 amountIn, address[] calldata path)
    external
    view
    returns (uint256 amountOut)
{
  if(...) {
  } else {
    return
        VaderMath.calculateSwap(
            VaderMath.calculateSwap(
                // @audit the inner trade should not be in pool1 for a forward swap. amountIn foreign => next param should be foreignReserve0
                amountIn,
                nativeReserve1,
                foreignReserve1
            ),
            foreignReserve0,
            nativeReserve0
        );
  }

 /** @audit instead should first be trading in pool0!
    VaderMath.calculateSwap(
        VaderMath.calculateSwap(
            amountIn,
            foreignReserve0,
            nativeReserve0
        ),
        nativeReserve1,
        foreignReserve1
    );
  */
```

## Impact
All 3-path swaps computations through `VaderRouter.calculateOutGivenIn` will return the wrong result.
Smart contracts or off-chain scripts/frontends th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 4: [H-15] VaderRouter._swap performs wrong swap

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The 3-path hop in `VaderRouter._swap` is supposed to first swap **foreign** assets to native assets, and then the received native assets to different foreign assets again.

The `pool.swap(nativeAmountIn, foreignAmountIn)` accepts the foreign amount as the **second** argument.
The code however mixes these positional arguments up and tries to perform a `pool0` foreign -> native swap by using the **foreign** amount as the **native amount**:

```solidity
function _swap(
    uint256 amountIn,
    address[] calldata path,
    address to
) private returns (uint256 amountOut) {
    if (path.length == 3) {
      // ...
      // @audit calls this with nativeAmountIn = amountIn. but should be foreignAmountIn (second arg)
      return pool1.swap(0, pool0.swap(amountIn, 0, address(pool1)), to);
    }
}

// @audit should be this instead
return pool1.swap(pool0.swap(0, amountIn, address(pool1)), 0, to);
```

## Impact
All 3-path swaps through the `VaderRouter` fail in the pool check when `require(nativeAmountIn = amountIn <= nativeBalance - nativeReserve = 0)` is checked, as foreign amount is sent but _native_ amount is specified.

## Recommended Mitigation Steps
Use `return pool1.swap(pool0.swap(0, amountIn, address(pool1)), 0, to);` instead.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 5: [H-04] Swaps are not split when trade crosses target price

**Source**: Code4rena
**Protocol**: Boot Finance
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by gzeon_

The protocol uses two amplifier values A1 and A2 for the swap, depending on the target price, see `SwapUtils.determineA`.
The swap curve is therefore a join of two different curves at the target price.
When doing a trade that crosses the target price, it should first perform the trade partially with A1 up to the target price, and then the rest of the trade order with A2.

However, the `SwapUtils.swap / _calculateSwap` function does not do this, it only uses the "new A", see `getYC` step 5.

```solidity
// 5. Check if we switched A's during the swap
if (aNew == a){     // We have used the correct A
    return y;
} else {    // We have switched A's, do it again with the new A
    return getY(self, tokenIndexFrom, tokenIndexTo, x, xp, aNew, d);
}
```

#### Impact

Trades that cross the target price and would lead to a new amplifier being used are not split up and use the new amplifier for the *entire trade*.
This can lead to a worse (better) average execution price than manually splitting the trade into two transactions, first up to but below the target price, and a second one with the rest of the trader order size, using both A1 and A2 values.

In the worst case, it could even be possible to make the entire trade with one amplifier and then sell the swap result again using the other amplifier making a profit.

#### Recommended Mitigation Steps

Trades that lead to a change in amplifier value need to be split up into two trades using 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-bootfinance)

---

### Example 6: Pulling tokens by LibSwap.swap() is counterintuitive

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

### Severity
**Medium Risk**

### Context
- `LibSwap.sol#L30-L68`
- `SwapperV2.sol#L67-L81`
- `Swapper.sol#L65-L78`
- `Executor.sol#L323-L333`

### Description
The function `LibSwap.swap()` pulls in tokens via `transferFromERC20()` from `msg.sender` when needed. When put in a loop, through `_executeSwaps()`, it can pull in multiple different tokens. It also doesnt detect accidentally sending native tokens along with ERC20 tokens. This approach is counterintuitive and leads to risks.

Suppose someone wants to swap 100 USDC to 100 DAI and then 100 DAI to 100 USDT. If the first swap somehow gives back fewer tokens (for example, 90 DAI), then `LibSwap.swap()` pulls in 10 extra DAI from `msg.sender`. **Note**: This requires the `msg.sender` to have given multiple allowances to the LiFi Diamond.

Another risk is that an attacker could trick a user into signing a transaction for the LiFi protocol. Within one transaction, it can sweep multiple tokens from the user, potentially clearing out the entire wallet. **Note**: This also requires the `msg.sender` to have given multiple allowances to the LiFi Diamond.

In `Executor.sol`, the tokens are already deposited, so the "pull" functionality is not needed and can even result in additional issues. In `Executor.sol`, it tries to "pull" tokens from `msg.sender` itself. In the best-case scenario of ERC20 implementations (like OpenZeppelin and Solmate), this has no effect. However, some non-standard ERC20 implementat

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 7: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec
## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and

*[Content truncated...]*

---

### Example 8: [H-07] Missing slippage checks

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by tensors_

There are no minimum amounts out, or checks that frontrunning/slippage is sufficiently mitigated.
This means that anyone with enough capital can force arbitrarily large slippage by sandwiching transactions, close to 100%. See issue page for referenced code.

Recommend adding a minimum amount out parameter. The function reverts if the minimum amount isn't obtained.

**[verifyfirst (Spartan) acknowledge:](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-884593067)**
> We acknowledge the issue for the protocol's AMM, but if this becomes a large issue in the future, the router is easily upgradeable to include a minimum rate parameter.

**[SamusEldburg (Spartan) confirmed and disagreed with severity:](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-889638485)**
> Have changed this to confirmed; even though we already were aware of it; we have discussed and are happy to add in a UI-handed arg for minAmount now rather than reactively in the future. Disagree with severity though; this wasn't a problem with V1 at all.

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-894863717):**
> I'll keep high risk as sandwich attacks are very common and risk of getting a bad swap is real.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 9: Check slippage of swaps

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
OmniBridgeFacet.sol#L63-L65

## Description
Several bridges check that the output of swaps isnt 0. However, it could also happen that a swap gives a positive output, but still lower than expected due to slippage, sandwiching, or MEV. Several AMMs will have a mechanism to limit slippage, but it might be useful to add a generic mechanism as multiple swaps in sequence might have a relatively large slippage.

```solidity
function swapAndStartBridgeTokensViaOmniBridge(...) {
    ...
    uint256 amount = _executeAndCheckSwaps(_lifiData, _swapData, payable(msg.sender));
    if (amount == 0) {
        revert InvalidAmount();
    }
    _startBridge(_lifiData, _bridgeData, amount, true);
}
```

## Recommendation
Consider adding a slippage check by specifying a minimum amount of expected tokens. At least add a check for `amount == 0` in all bridges.

## LiFi
Fixed with PR #75.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 10: SwapManager assumes Morpho token is token0 of every token pair

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`SwapManagerUniV2.sol#L106`

## Description
The `consult` function wrongly assumes that the Morpho token is always the first token (`token0`) in the Morpho <> Reward token token pair. This could lead to inverted prices and a denial of service attack when claiming rewards, as the wrongly calculated expected amount slippage check reverts.

## Recommendation
Consider using similar code to the example UniswapV2 oracle. Note that depending on how this issue is fixed in `consult`, the caller of this function needs to be adjusted as well to return a Morpho token amount as `amountOut`.

## Morpho
Fixed in PR #585.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 11: [H-04] Members lose SPARTA tokens in removeLiquiditySingle()

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

0xRajeev


## Vulnerability details

## Impact

When a member calls removeLiquiditySingle() requesting only SPARTA in return, i.e. toBASE = true, the LP tokens are transferred to the Pool to withdraw the constituent SPARTA and TOKENs back to the Router. The withdrawn TOKENs are then transferred back to the Pool to convert to SPARTA and directly transferred to the member from the Pool. However, the members SPARTA are left behind in the Router instead of being returned along with converted SPARTA from the Pool. 

In other words, the _member's BASE SPARTA tokens that were removed from the Pool along with the TOKENs are never sent back to the _member because the _token's transferred to the Pool are converted to SPARTA and only those are sent back to member directly from the Pool via swapTo(). 

This effectively results in member losing the SPARTA component of their Pool LP tokens which get left behind in the Router and are possibly claimed by future transactions that remove SPARTA from Router.

## Proof of Concept

LPs sent to Pool: https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Router.sol#L121

SPARTA and TOKENs withdrawn from Pool to Router: https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Router.sol#L122

TOKENs from Router sent to Pool: https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Router.sol#L126

TOKE

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 12: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/132 

## Found by 
0x52
## Summary

The sqrtRatioLimit for UniV3 doesn't cause the swap to revert upon reaching that value. Instead it just cause the swap to partially fill. This is a [known issue](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L641) with using sqrtRatioLimit as can be seen here where the swap ends prematurely when it has been reached. This is problematic as this is meant to provide the user with slippage protection but doesn't.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L209-L223

        if (amountToSwap > 0) {
            SWAP_POOL = IUniswapV3Pool(vault.pool());
            uint160 deltaSqrt = (param.sqrtRatioLimit *
                uint160(param.sellSlippage)) / uint160(Constants.DENOMINATOR);
            SWAP_POOL.swap(
                address(this),
                // if withdraw token is Token0, then swap token1 -> token0 (false)
                !isTokenA,
                amountToSwap.toInt256(),
                isTokenA
                    ? param.sqrtRatioLimit + deltaSqrt
                    : param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
                abi.encode(address(this))
            );
        }

sqrtRatioLimit is used as slippage protection for the user but is ineffective and depending on what tokens are 

*[Content truncated...]*

---

### Example 13: H-1: Attacker can steal the accumulated topup fees in the `topupproxy` contract's balance

**Source**: Sherlock
**Protocol**: Mover
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mover-judging/issues/112 

## Found by 
minhquanym, Jeiwan, 0x52, hansfriese, WATCHPUG, GalloDaSballo, berndartmueller

## Summary

The accumulated fees in the `topupproxy` contract's balance can be stolen by an attacker by using malicious `_bridgeTxData` and using `1inch`'s as `targetAddress`.

## Vulnerability Detail

This attack vector is enabled by multiple traits of the `topupproxy` contract:

#### 1. Shared whitelist

Per to deploy script, the same `trustedregistry` will be shared among `exchangeproxy` and `topupproxy`.

Therefore, the 2 whitelisted swap aggregator contracts will also be allowed to be called on `topupproxy`:

- 0x Proxy
- 1inch Proxy

And the 2 whitelisted bridge contracts can be called on `exchangeproxy`:

- Synapse
- Across

#### 2. Unlimited allowance rather than only the amount of the current topup to the bridge's `targetAddress`

At L414, the `targetAddress` will be granted an unlimited allowance rather than just the amount of the current transaction.

https://github.com/sherlock-audit/2022-10-mover/blob/main/cardtopup_contract/contracts/HardenedTopupProxy.sol#L414

#### 3. `1inch` can be used to pull an arbitrary amount of funds from the caller and execute arbitrary call

The design of `1inch`'s `AggregationRouterV4` can be used to pull funds from the `topupproxy` and execute arbitrary external call:

https://polygonscan.com/address/0x1111111254fb6c44bAC0beD2854e76F90643097d#code

See L2309-2321.



*[Content truncated...]*

---

### Example 14: [M-03] Anyone can call AutoPxGmx.compound and perform sandwich attacks with control parameters

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

AutoPxGmx.compound allows anyone to call to compound the reward and get the incentive.

However, AutoPxGmx.compound calls `SWAP_ROUTER`.exactInputSingle with some of the parameters provided by the caller, which allows the user to perform a sandwich attack for profit.

For example, a malicious user could provide the fee parameter to make the token swap occur in a small liquid pool, and could make the amountOutMinimum parameter 1 to make the token swap accept a large slippage, thus making it easier to perform a sandwich attack.

### Proof of Concept

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L242-L278>

### Recommended Mitigation Steps

Consider using poolFee as the fee and using an onchain price oracle to calculate the amountOutMinimum.

**[Picodes (judge) commented](https://github.com/code-423n4/2022-11-redactedcartel-findings/issues/91#issuecomment-1337106500):**
 > Flagging as best as the warden identifies that the main risk is not the possibility to increase fees but the fact that some of the pools will be highly illiquid.

**[drahrealm (Redacted Cartel) disagreed with severity and commented](https://github.com/code-423n4/2022-11-redactedcartel-findings/issues/91#issuecomment-1342052424):**
 > Please refer to:
> https://github.com/code-423n4/2022-11-redactedcartel-findings/issues/185#issuecomment-1341252133

**[Picodes (judge) commented](https://github.com/code-423n4/2022-11-redactedcartel-f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 15: [M-02] Preventing any user from calling the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx`

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

It is possible that an attacker can prevent any user from calling the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx` by just manipulating the balance of token `gmxBaseReward`, so that during the function `compound` the swap will be reverted.

### Proof of Concept

Whenever a user calls the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx`, the function `compound` is called:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L321>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L345>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L379>

The function `compound` claims token `gmxBaseReward` from `rewardModule`:
<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L262>

Then, if the balance of the token `gmxBaseReward` in custodian of the contract `AutoPxGmx` is not zero, the token `gmxBaseReward` will be swapped to token `GMX` thrrough uniswap V3 by calling the function `exactInputSingle`. Then the total amount of token `GMX` in custodian of the contract `AutoPxGmx` will be deposited in the contract `PirexGmx` to receive token `pxGMX`:

    if (gmxBaseRewardAmountIn != 0) {
                gmxAmountOut = SWAP_ROUTER.exactInputSingle(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 16: H-10: Balance check for swapToken in ShortLongSpell#_deposit is incorrect and will result in nonfunctional contract

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/133 

## Found by 
0x52, Ch\_301, sinarette
## Summary

The balance checks on ShortLongSpell#_withdraw are incorrect and will make contract basically nonfunctional 

## Vulnerability Detail

swapToken is always vault.uToken. borrowToken is always required to be vault.uToken which means that swapToken == borrowToken. This means that the token borrowed is always required to be swapped. 

[ShortLongSpell.sol#L83-L89](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L83-L89)

        uint256 strTokenAmt = _doBorrow(param.borrowToken, param.borrowAmount);

        // 3. Swap borrowed token to strategy token
        IERC20Upgradeable swapToken = ISoftVault(strategy.vault).uToken();
        // swapData.fromAmount = strTokenAmt;
        PSwapLib.megaSwap(augustusSwapper, tokenTransferProxy, swapData);
        strTokenAmt = swapToken.balanceOf(address(this)) - strTokenAmt; <- @audit-issue will always revert on swap

Because swapToken == borrowToken if there is ever a swap then the swapToken balance will decrease. This causes L89 to always revert when a swap happens, making the contract completely non-functional

## Impact

ShortLongSpell is nonfunctional

## Code Snippet

[ShortLongSpell.sol#L160-L202](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Revi

*[Content truncated...]*

---

### Example 17: M-20: UniV2Adapter#getExecutionData doesn't properly handle native ETH swaps

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/33 

## Found by 
Chom, 0x52

## Summary

UniV2Adapter#getExecutionData doesn't properly account for native ETH trades which makes them impossible. Neither method selected supports direct ETH trades, and sender/target are not set correctly for TradingUtils_executeTrade to automatically convert

## Vulnerability Detail

    spender = address(Deployments.UNIV2_ROUTER);
    target = address(Deployments.UNIV2_ROUTER);
    // msgValue is always zero for uniswap

    if (
        tradeType == TradeType.EXACT_IN_SINGLE ||
        tradeType == TradeType.EXACT_IN_BATCH
    ) {
        executionCallData = abi.encodeWithSelector(
            IUniV2Router2.swapExactTokensForTokens.selector,
            trade.amount,
            trade.limit,
            data.path,
            from,
            trade.deadline
        );
    } else if (
        tradeType == TradeType.EXACT_OUT_SINGLE ||
        tradeType == TradeType.EXACT_OUT_BATCH
    ) {
        executionCallData = abi.encodeWithSelector(
            IUniV2Router2.swapTokensForExactTokens.selector,
            trade.amount,
            trade.limit,
            data.path,
            from,
            trade.deadline
        );
    }

UniV2Adapter#getExecutionData either returns the swapTokensForExactTokens or swapExactTokensForTokens, neither of with support native ETH. It also doesn't set spender and target like UniV3Adapter, so _executeTrade won't automatically co

*[Content truncated...]*

---

### Example 18: M-11: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/122 

## Found by 
0x52
## Summary

AuraSpell#closePositionFarm requires users to swap all reward tokens through same router. This is problematic as it is very unlikely that a UniswapV2 router will have good liquidity sources for all tokens and will result in users experiencing forced losses to their reward token.  

## Vulnerability Detail

[AuraSpell.sol#L193-L203
](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L193-L203)

        for (uint256 i = 0; i < rewardTokens.length; i++) {
            uint256 rewards = _doCutRewardsFee(rewardTokens[i]);
            _ensureApprove(rewardTokens[i], address(swapRouter), rewards);
            swapRouter.swapExactTokensForTokens(
                rewards,
                0,
                swapPath[i],
                address(this),
                type(uint256).max
            );
        }

All tokens are forcibly swapped through a single router.

## Impact

Users will be forced to swap through a router even if it doesn't have good liquidity for all tokens

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow users to use an aggregator like paraswap or multiple routers instead of only one single UniswapV2 router.

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## uniswap-patterns.md
# Uniswap Security Patterns

## Overview

**Frequency**: 22 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 12 | 9 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Trust Security

---

## Detection Checklist

- [ ] Check for uniswap vulnerabilities in all external functions
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

### Example 2: [H-17] Second per liquidity inside could overflow `uint256` causing the LP position to be locked in `UniswapV3Staker`

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: HIGH

**Details**:

`UniswapV3Staker` depends on the second per liquidity inside values from the `Uniswap V3 Pool` to calculate the amount of rewards a position should receive. This value represents the amount of second liquidity inside a tick range that is "active" (`tickLower < currentTick < tickUpper`). The second per liquidity inside a specific tick range is supposed to always increase over time.

In the `RewardMath` library, the seconds inside are calculated by taking the current timestamp value and subtracting the value at the moment the position is staked. Since this value increases over time, it should be normal. Additionally, this implementation is similar to [Uniswap Team's implementation](https://github.com/Uniswap/v3-staker/blob/4328b957701de8bed83689aa22c32eda7928d5ab/contracts/libraries/RewardMath.sol#L35).

```solidity
function computeBoostedSecondsInsideX128(
    uint256 stakedDuration,
    uint128 liquidity,
    uint128 boostAmount,
    uint128 boostTotalSupply,
    uint160 secondsPerLiquidityInsideInitialX128,
    uint160 secondsPerLiquidityInsideX128
) internal pure returns (uint160 boostedSecondsInsideX128) {
    // this operation is safe, as the difference cannot be greater than 1/stake.liquidity
    uint160 secondsInsideX128 = (secondsPerLiquidityInsideX128 - secondsPerLiquidityInsideInitialX128) * liquidity;
    // @audit secondPerLiquidityInsideX128 could smaller than secondsPerLiquidityInsideInitialX128
    ...
}
```

However, even though the second per liquidity inside 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 3: [H-02] Use of `slot0` to get `sqrtPriceLimitX96` can lead to price manipulation.

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

### Example 4: [H-06] Discrepency in the Uniswap V3 position price calculation because of decimals

**Source**: Code4rena
**Protocol**: ParaSpace
**Impact**: HIGH

**Details**:

When the squared root of the Uniswap V3 position is calculated from the [`_getOracleData()` function](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L221-L280), the price may return a very high number (in the case that the token1 decimals are strictly superior to the token0 decimals). See: <https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L249-L260>

The reason is that at the denominator, the `1E9` (10&ast;&ast;9) value is hard-coded, but should take into account the delta between both decimals.<br>
As a result, in the case of `token1Decimal > token0Decimal`, the [`getAmountsForLiquidity()`](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/dependencies/uniswap/LiquidityAmounts.sol#L172-L205) is going to return a huge value for the amount of token0 and token1 as the user position liquidity.

The [`getTokenPrice()`](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L156), using this amount of liquidity to [calculate the token price](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L176-L180) is as its turn going to return a huge value.

### Proof of Concept

This POC demonstrates in which case the returned squared root price of the position is over inflated

```solidity
// SPDX-Licens

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-paraspace)

---

### Example 5: H-4: No slippage protection during repayment due to dynamic slippage params and easily influenced `slot0()`

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

### Example 6: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec
## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and

*[Content truncated...]*

---

### Example 7: [H-09] UniswapV3 tokens of certain pairs will be wrongly valued, leading to liquidations

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

### Example 8: UNI_V3Validator fetches spot prices that may lead to price manipulation attacks

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

### Example 9: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/132 

## Found by 
0x52
## Summary

The sqrtRatioLimit for UniV3 doesn't cause the swap to revert upon reaching that value. Instead it just cause the swap to partially fill. This is a [known issue](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L641) with using sqrtRatioLimit as can be seen here where the swap ends prematurely when it has been reached. This is problematic as this is meant to provide the user with slippage protection but doesn't.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L209-L223

        if (amountToSwap > 0) {
            SWAP_POOL = IUniswapV3Pool(vault.pool());
            uint160 deltaSqrt = (param.sqrtRatioLimit *
                uint160(param.sellSlippage)) / uint160(Constants.DENOMINATOR);
            SWAP_POOL.swap(
                address(this),
                // if withdraw token is Token0, then swap token1 -> token0 (false)
                !isTokenA,
                amountToSwap.toInt256(),
                isTokenA
                    ? param.sqrtRatioLimit + deltaSqrt
                    : param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
                abi.encode(address(this))
            );
        }

sqrtRatioLimit is used as slippage protection for the user but is ineffective and depending on what tokens are 

*[Content truncated...]*

---

### Example 10: H-10: IchiLpOracle is extemely easy to manipulate due to how IchiVault calculates underlying token balances

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

### Example 11: [M-16] Inaccurate swap amount calculation in ReLP leads to stuck tokens and lost liquidity

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: MEDIUM

**Details**:

`ReLPContract` contains logic that removes WETH-RDPX liquidity from Uniswap V2, swaps some amount WETH to RDPX and re-adds the liquidity.

The calculation logic for the amount of tokens to swap is unreliable and sometimes reverts or leaves dust WETH in the reLP contract. WETH cannot be recovered unless another reLP operation is triggered. However, since reLP-ing is accessible to all users in the bonding logic in `RdpxV2Core`, the contract may be **griefed on an ongoing basis, intentional or not.**

The presence of excess WETH also means that the total value of the LP decreases abnormally after each reLP operation.

### Proof of Concept

The following Foundry test demonstrates the vulnerability.

*   Paste the code in a new file `PoC.t.sol` under `tests/`
*   Run the test with `forge test --match-test test_poc_relp_dust -vvv`

<details>

```

    // File: PoC.t.sol
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.19;

    import "forge-std/Test.sol";
    import "forge-std/console.sol";

    import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
    import {IERC20WithBurn} from "contracts/interfaces/IERC20WithBurn.sol";
    import {MockToken} from "contracts/mocks/MockToken.sol";
    import {MockRdpxEthPriceOracle} from "contracts/mocks/MockRdpxEthPriceOracle.sol";
    import {ReLPContract} from "contracts/reLP/ReLPContract.sol";
    import {RdpxReserve} from "contracts/reserve/RdpxReserve.sol";
    import {IUniswapV2Factory} from "contracts/unisw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 12: [H-02] Liquidation can be escaped by depositing a Uni v3 position with 0 liquidity

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

_Submitted by WatchPug_.

When the liquidator is trying to liquidate a undercolldarezed loan by calling `liquidateAccount()`, it calls `_unwrapUniPosition()` -> `uniV3Helper.removeLiquidity()` -> `positionManager.decreaseLiquidity()`.

However, when the Uni v3 position has 0 liquidity, `positionManager.decreaseLiquidity()` will fail.

See: <https://github.com/Uniswap/v3-periphery/blob/main/contracts/NonfungiblePositionManager.sol#L265>

Based on this, a malicious user can escaped liquidation by depositing a Uni v3 position with 0 liquidity.

##### Impact

Undercollateralized debts cannot be liquidated and it leads to bad debts to the protocol.

A malicious user can take advantage of this by creating long positions on the collateral assets and take profit on the way up, and keep taking more debt out of the protocol, while when the price goes down, the debt can not be liquidated and the risks of bad debt are paid by the protocol.

##### Proof of Concept

1.  A malicious user deposits some collateral assets and borrow the max amount of debt;
2.  The user deposits a Uni v3 position with 0 liquidity;
3.  When the market value of the collateral assets decreases, the liquadation will fail as `positionManager.decreaseLiquidity()` reverts.

##### Recommendation

Check if liquidity > 0 when removeLiquidity.

**[talegift (Wild Credit) confirmed](https://github.com/code-423n4/2021-09-wildcredit-findings/issues/30#issuecomment-932861833):**
 > Valid issue. Good catch.
> 
> Severity should

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-wildcredit)

---

### Example 13: M-3: JalaPair potential permanent DoS due to overflow

**Source**: Sherlock
**Protocol**: Jala Swap
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-jala-swap-judging/issues/186 

The protocol has acknowledged this issue.

## Found by 
0k, 0xMojito, 0xRstStn, 0xloscar01, Stoicov, ZanyBonzy, den\_sosnovskyi, deth, fibonacci, giraffe, mahmud, n1punp, santiellena, sunill\_eth, tank
## Summary

In the `JalaPair::_update` function, overflow is intentionally desired in the calculations for `timeElapsed` and `priceCumulative`. This is forked from the UniswapV2 source code, and its meant and known to overflow. UniswapV2 was developed using Solidity 0.6.6, where arithmetic operations overflow and underflow by default. However, Jala utilizes Solidity >=0.8.0, where such operations will automatically revert.

## Vulnerability Detail

```solidity
uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
    // * never overflows, and + overflow is desired
    price0CumulativeLast += uint256(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
    price1CumulativeLast += uint256(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
}
```

## Impact

This issue could potentially lead to permanent denial of service for a pool. All the core functionalities such as `mint`, `burn`, or `swap` would be broken. Consequently, all funds would be locked within the contract.

I think issue with High impact and a Low probability (merely due to the extended timeframe for the event's occurrence, it's impo

*[Content truncated...]*

---

### Example 14: [M-04] Wrong init code hash

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: MEDIUM

**Details**:

An init code hash is used to calculate the address of UniswapV2 pair contract. But the init code hash is not same as the latest UniswapV2 repository.

### Proof of Concept

UniswapV2Library.pairFor uses the following value as the init code hash of UniswapV2Pair.

        hex"e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303" // init code hash

But it is different from the [init code hash](https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2Library.sol#L24) of the uniswap v2 repository.

I tested this using one of the top UniswapV2 pairs. DAI-USDC is in the third place [here](https://v2.info.uniswap.org/pairs).

The token addresses are as follows:

DAI: 0x6B175474E89094C44Da98b954EedeAC495271d0F

USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

And the current UniswapV2Factory address is 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f [here](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/factory).

The pair address calculated is 0x6983E2Da04353C31c7C42B0EA900a40B1D5bf845. And we can't find pair contract in the address.

So I think the old version of UniswapV2Factory and pair are used here. And it can cause a risk when liquidity is not enough for the pair.

### Recommended Mitigation Steps

Integrate the latest version of UniswapV2.

**[kyscott18 (Numoen) acknowledged and commented](https://github.com/code-423n4/2023-01-numoen-findings/issues/206#issuecomment-1423227359):**
 > I should have been more specific, but the ini

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 15: H-9: Uniswap v3 pool token balance proportion does not necessarily correspond to the price, and it is easy to manipulate.

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

### Example 16: H-7: Not using slippage parameter or deadline while swapping on UniswapV3

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/673 

## Found by 
0xPkhatri, 0xRan4212, 0xRobocop, 0xSmartContract, 0xStalin, 0xeix, 0xpinky, 0xyPhilic, Angry\_Mustache\_Man, Auditwolf, Bahurum, Bauchibred, Bauer, BlockChomper, Brenzee, BugBusters, BugHunter101, CodeFoxInc, Delvir0, Dug, Fanz, HonorLt, J4de, JohnnyTime, Juntao, Kodyvim, Kose, Lilyjjo, Madalad, MohammedRizwan, Nyx, PokemonAuditSimulator, Proxy, RaymondFam, Saeedalipoor01988, Schpiel, SensoYard, T1MOH, TheNaubit, Tricko, Viktor\_Cortess, WATCHPUG, \_\_141345\_\_, anthony, ast3ros, berlin-101, blackhole, blockdev, carrotsmuggler, chaithanya\_gali, chalex.eth, coincoin, ctf\_sec, curiousapple, dacian, evilakela, eyexploit, immeas, innertia, jah, jprod15, juancito, kie, kiki\_dev, kutugu, lil.eth, m4ttm, martin, n33k, ni8mare, nobody2018, peanuts, qbs, qckhp, qpzm, saidam017, sakshamguruji, sam\_gmk, sashik\_eth, shaka, shealtielanz, shogoki, simon135, slightscan, tallo, theOwl, toshii, twicek, warRoom
## Summary

While making a swap on UniswapV3 the caller should use the slippage parameter `amountOutMinimum` and `deadline` parameter to avoid losing funds.

## Vulnerability Detail

[`UniV3SwapInput()`](https://github.com/sherlock-audit/2023-05-USSD/blob/main/ussd-contracts/contracts/USSD.sol#L227-L240) in `USSD` contract does not use the slippage parameter [`amountOutMinimum`](https://github.com/sherlock-audit/2023-05-USSD/blob/main/ussd-contracts/contracts/USSD.sol#L237)  nor [`deadline`](h

*[Content truncated...]*

---

### Example 17: M-20: UniV2Adapter#getExecutionData doesn't properly handle native ETH swaps

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/33 

## Found by 
Chom, 0x52

## Summary

UniV2Adapter#getExecutionData doesn't properly account for native ETH trades which makes them impossible. Neither method selected supports direct ETH trades, and sender/target are not set correctly for TradingUtils_executeTrade to automatically convert

## Vulnerability Detail

    spender = address(Deployments.UNIV2_ROUTER);
    target = address(Deployments.UNIV2_ROUTER);
    // msgValue is always zero for uniswap

    if (
        tradeType == TradeType.EXACT_IN_SINGLE ||
        tradeType == TradeType.EXACT_IN_BATCH
    ) {
        executionCallData = abi.encodeWithSelector(
            IUniV2Router2.swapExactTokensForTokens.selector,
            trade.amount,
            trade.limit,
            data.path,
            from,
            trade.deadline
        );
    } else if (
        tradeType == TradeType.EXACT_OUT_SINGLE ||
        tradeType == TradeType.EXACT_OUT_BATCH
    ) {
        executionCallData = abi.encodeWithSelector(
            IUniV2Router2.swapTokensForExactTokens.selector,
            trade.amount,
            trade.limit,
            data.path,
            from,
            trade.deadline
        );
    }

UniV2Adapter#getExecutionData either returns the swapTokensForExactTokens or swapExactTokensForTokens, neither of with support native ETH. It also doesn't set spender and target like UniV3Adapter, so _executeTrade won't automatically co

*[Content truncated...]*

---

### Example 18: M-21: Deployments.sol uses the wrong address for UNIV2 router which causes all Uniswap V2 calls to fail

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/32 

## Found by 
0x52

## Summary

Deployments.sol accidentally uses the Uniswap V3 router address for UNIV2_ROUTER which causes all Uniswap V2 calls to fail

## Vulnerability Detail

    IUniV2Router2 internal constant UNIV2_ROUTER = IUniV2Router2(0xE592427A0AEce92De3Edee1F18E0157C05861564);

The constant UNIV2_ROUTER contains the address for the Uniswap V3 router, which doesn't contain the "swapExactTokensForTokens" or "swapTokensForExactTokens" methods. As a result, all calls made to Uniswap V2 will revert.

## Impact

Uniswap V2 is totally unusable

## Code Snippet

[Deployments.sol#L25](https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/global/Deployments.sol#L25)

## Tool used

Manual Review

## Recommendation

Change UNIV2_ROUTER to the address of the V2 router:

    IUniV2Router2 internal constant UNIV2_ROUTER = IUniV2Router2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

## Discussion

**jeffywu**

@weitianjie2000 I believe this has been fixed subsequently

---

### Example 19: M-1: Calculation underflow/overflow in BalancerPairOracle, which will affect pools in Aura Finance

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/11 

## Found by 
n1punp
## Summary
LP price calculation for Balancer Pair in BalancerPairOracle will produce calculation underflow/overflow (so Aura pools won't work too).

## Vulnerability Detail
- The values r0, r1 can underflow, e.g. if resA < resB --> r0 = 0, so it'll go to the else case --> and so `ratio` will be 0 --> `fairResA` calculation will revert upon dividing by 0.
- There are also other math calculations there that will cause reverts, e.g. ratio ** wB will lead to overflow. What you'd need here is Balancer's implementation of `bpow` or similar.

## Impact
LP price for Balancer-like collateral token will revert in most cases, if not all.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/BalancerPairOracle.sol#L53-L64

## Tool used

Manual Review

## Recommendation
- Change the calculation logic so it aligns with Alpha's original implementation (with precision control), e.g. https://github.com/AlphaFinanceLab/alpha-homora-v2-contract/blob/master/contracts/oracle/BalancerPairOracle.sol#L42-L53 (you can see there's BONE extra precision in each step)



## Discussion

**n1punp**

Escalate for 10 USDC.
I think this is incorrectly **excluded**. The issue is not related to **flashloan** via **BalancerPairOracle**, but rather an organic math overflow/underflow, since the implementation is directly using 0.8.x's default SafeMath mode. Up

*[Content truncated...]*

---

### Example 20: TRST-M-1 multiplication overflow in getPoolPrice() likely

**Source**: Trust Security
**Protocol**: Rysk Uniswapv3Rangeorderreactor
**Impact**: MEDIUM

**Details**:

**Description:**
`getPoolPrice()` is used in hedgeDelta to get the price directly from Uniswap v3 pool:
```solidity 
    function getPoolPrice() public view returns (uint256 price, uint256 
         inversed){
            (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        uint256 p = uint256(sqrtPriceX96) * uint256(sqrtPriceX96) * (10 
        ** token0.decimals());
     // token0/token1 in 1e18 format
          price = p / (2 ** 192);
              inversed = 1e36 / price;
         }

```
The issue is that calculation of p is likely to overflow. sqrtPriceX96 has 96 bits for decimals, 
10** `token0.decimals()` will have 60 bits when decimals is 18, therefore there is only 
(256  2 * 96  60) / 2 = 2 bits for non-decimal part of sqrtPriceX96. 

**Recommended Mitigation:**
Consider converting the sqrtPrice to a 60x18 format and performing arithmetic operations 
using the PRBMathUD60x18 library.

**Team Response:**
Fixed

**Mitigation Review**
Calculations are now performed safely using the standard FullMath library

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2022-12-23-rysk UniswapV3RangeOrderReactor.md)

---

### Example 21: M-11: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/122 

## Found by 
0x52
## Summary

AuraSpell#closePositionFarm requires users to swap all reward tokens through same router. This is problematic as it is very unlikely that a UniswapV2 router will have good liquidity sources for all tokens and will result in users experiencing forced losses to their reward token.  

## Vulnerability Detail

[AuraSpell.sol#L193-L203
](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L193-L203)

        for (uint256 i = 0; i < rewardTokens.length; i++) {
            uint256 rewards = _doCutRewardsFee(rewardTokens[i]);
            _ensureApprove(rewardTokens[i], address(swapRouter), rewards);
            swapRouter.swapExactTokensForTokens(
                rewards,
                0,
                swapPath[i],
                address(this),
                type(uint256).max
            );
        }

All tokens are forcibly swapped through a single router.

## Impact

Users will be forced to swap through a router even if it doesn't have good liquidity for all tokens

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow users to use an aggregator like paraswap or multiple routers instead of only one single UniswapV2 router.

---

### Example 22: [L-08] UniswapV3Oracle: Reduce minObservations to uint16

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: LOW

**Details**:

## Handle

greiart


## Vulnerability details

## Impact

Will help prevent erraneous `minObservations` values from being set (ie. `> 65535`) by the owner without needing checks. Otherwise, the `isPoolValid` will always return false, causing reverts in calling `tokenPrice` and `addPool` functions (and other functions calling these).

## Referenced Codelines

[https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L25](https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L25)

[https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L101](https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L101)

## Proof Of Concept

The maximum number of observations available is `65535` (see [https://github.com/Uniswap/uniswap-v3-core/blob/main/contracts/UniswapV3Pool.sol#L39](https://github.com/Uniswap/uniswap-v3-core/blob/main/contracts/UniswapV3Pool.sol#L39)), which is equivalent to `type(uint16).max`.

Hence, 

- `uint public minObservations` can be reduced to `uint16 public minObservations`.
- `(, , , , uint observationSlots , ,) = IUniswapV3Pool(poolAddress).slot0();` becomes `(, , , , uint16 observationSlots , ,) = IUniswapV3Pool(poolAddress).slot0();`

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-wildcredit)

---

## Statistics

- Total findings analyzed: 22
- Examples shown: 22
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## 0x-patterns.md
# 0x Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 3 | 0 |

**Common Sources**: Code4rena, MixBytes, Shieldify, Sherlock

---

## Detection Checklist

- [ ] Check for 0x vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

_Submitted by GreyArt, also found by 0xDjango, CertoraInc, cmichel, rayn, TomFrenchBlockchain, and WatchPug_

[Collateral.sol#L82-L91](https://github.com/code-423n4/2022-03-prepo/blob/main/contracts/core/Collateral.sol#L82-L91)<br>

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

*   Attacker deposits 2 wei (so that it is greater than min fee) to mint 1 share
*   Attacker transfers exorbitant amount to `_strategyController` to greatly inflate the shares price. Note that the `_strategyController` deposits its entire balance to the strategy when its `deposit()` function is called.
*   Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

```jsx
it("will cause 0 share issuance", async () => {
	// 1. first user deposits 2 wei because 1 wei will be deducted for fee
	let firstDepositAmount = ethers.BigNumber.from(2)
	await transferAndApproveForDeposit(
	    user,
	    collateral.address,
	    firstDepositAmount
	)
	
	await collateral
	    .connect(user)
	    .deposit(firstDepositAmount)
	
	// 2. do huge transfer of 1M to strategy to controller
	// to 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-prepo)

---

### Example 2: H-4: Bought/Purchased Token Can Be Sent To Attacker's Wallet Using 0x Adaptor

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/75 

## Found by 
xiaoming90

## Summary

The lack of recipient validation against the 0x order within the 0x adaptor (`ZeroExAdapter`) allows the purchased/output tokens of the trade to be sent to the attacker's wallet.

## Vulnerability Detail

#### Background

**How does the emergency vault settlement process work?**

1. Anyone can call the `settleVaultEmergency` function to trigger the emergency vault settlement as it is permissionless
2. The `_getEmergencySettlementParams` function will calculate the excess BPT tokens within the vault to be settled/sold
3. The amount of excess BPT tokens will be converted to an equivalence amount of strategy tokens to be settled
4. The strategy tokens will be settled by withdrawing staked BPT tokens from Aura Finance back to the vault for redemption.
5. The vault will then redeem the BTP tokens from Balancer to redeem its underlying assets (WETH and stETH)
6. The primary and secondary assets of the vault are WETH and stETH respectively. The secondary asset (stETH) will be traded for the primary asset (WETH) in one of the supported DEXes. In the end, only the primary assets (WETH) should remain within the vault.
7. The WETH within the vault will be sent to Notional, and Notional will mint the asset tokens (cEther) for the vault in return.
8. After completing the emergency vault settlement process, the vault will gain asset tokens (cEther) after settling/selling its 

*[Content truncated...]*

---

### Example 3: [M-04] `CidNFT`: Broken `tokenURI` function

**Source**: Code4rena
**Protocol**: Canto Identity Protocol
**Impact**: MEDIUM

**Details**:

[`CidNFT#tokenURI`](https://github.com/code-423n4/2023-01-canto-identity/blob/dff8e74c54471f5f3b84c217848234d474477d82/src/CidNFT.sol#L133-L142) does not convert the `uint256 _id` argument to a string before interpolating it in the token URI:

```solidity
    /// @notice Get the token URI for the provided ID
    /// @param _id ID to retrieve the URI for
    /// @return tokenURI The URI of the queried token (path to a JSON file)
    function tokenURI(uint256 _id) public view override returns (string memory) {
        if (ownerOf[_id] == address(0))
            // According to ERC721, this revert for non-existing tokens is required
            revert TokenNotMinted(_id);
        return string(abi.encodePacked(baseURI, _id, ".json"));
    }

```

This means the raw bytes of the 32-byte ABI encoded integer `_id` will be interpolated into the token URI, e.g. `0x0000000000000000000000000000000000000000000000000000000000000001` for ID `#1`.

Most of the resulting UTF-8 strings will be malformed, incorrect, or invalid URIs. For example, token ID `#1` will show up as the invisible "start of heading" control character, and ID `#42` will show as the asterisk symbol `*`. URI-unsafe characters will break the token URIs altogether.

### Impact

*   `CidNFT` tokens will have invalid `tokenURI`s. Offchain tools that read the `tokenURI` view may break or display malformed data.

### Suggestion

Convert the `_id` to a string before calling `abi.encodePacked`. Latest Solmate includes a `LibStri

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-canto-identity)

---

### Example 4: [M-04] Lender can trade claimToken in a malicious way to steal the borrowers money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/modules/credit/SpigotedLine.sol#L106-L112
https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/utils/SpigotedLineLib.sol#L75-L85


## Vulnerability details

## Impact

Lender can trade claimToken in a malicious way to steal the borrower's money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData.

In the design of the protocol, the lender can use the function claimAndRepay(), the lender can take claimToken by spigot.claimEscrow and then trade the claimToken to the CreditTOken via ZeroEx exchange, then repay the credit. 

```
function claimAndRepay(address claimToken, bytes calldata zeroExTradeData) external
        whileBorrowing
        nonReentrant
        returns (uint256) { 

...
// Line 106 - Line 112
uint256 newTokens = claimToken == credit.token ?
          spigot.claimEscrow(claimToken) :  // same asset. dont trade
          _claimAndTrade(                   // trade revenue token for debt obligation
              claimToken,
              credit.token,
              zeroExTradeData
          );
...
// Line 128 - Line 130 
 credits[id] = _repay(credit, id, repaid);

        emit RevenuePayment(claimToken, repaid);

...

}

```

```
function _claimAndTrade(
      address claimToken,
      address targetToken,
      bytes calldata zeroExTradeData
    )
        internal
        returns (uint256)
    {
        (uint256 tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 5: [L-03] Merkle Root Is Mutable Mid-Airdrop

**Source**: Shieldify
**Protocol**: Spellborne S2Airdrop
**Impact**: LOW

**Details**:

## Severity

Low Risk

## Description

The owner can change `merkleRoot` at any time. Already-registered users remain unaffected (state stored), but future registrations switch to the new root, which can change eligibility without warning.

## Location of Affected Code

File: [src/S2Airdrop.sol#L160-L163](https://github.com/SlothFi/s2-airdrop/blob/fa331efe0bc68794537d6df645241f61be14be7b/src/S2Airdrop.sol#L160-L163)

```solidity
function setMerkleRoot(bytes32 root) public onlyOwner {
    merkleRoot = root;
    emit MerkleRootSet(root);
}
```

## Impact

Trust/governance risk: operator can exclude/replace users mid-campaign; users and integrators cannot assume a stable eligibility set after launch.

## Recommendation

Freeze the root after a start time, or gate changes behind a timelock/multisig and communicate immutability guarantees. Optionally add a phase ID and store it to make root changes explicit on-chain.

## Team Response

Acknowledged.

## [I-01] Hardcoded Token Address Limits Deployment To A Specific Chain

## Severity

Informational Risk

## Description

The contract uses a hardcoded token address `0x133879524DDb38582cf0b93D10aDB789601Ff397` as a constant, which corresponds to the BORNE ERC-20 token on [Avalanche mainnet](https://avascan.info/blockchain/c/token/0x133879524DDb38582cf0b93D10aDB789601Ff397). This implementation prevents the contract from being deployed on other blockchain networks where the BORNE token exists at different addresses.

For example, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Spellborne-S2Airdrop-Security-Review.md)

---

### Example 6: Remove unnecessary ETH handling logic for maker asset

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

### Example 7: Redundant `afterInitialize()` Function

**Source**: MixBytes
**Protocol**: Algebra Finance
**Impact**: LOW

**Details**:

##### Description
The `LimitOrderManager.afterInitialize` function exposed to plugins duplicates the exact same initialization that `LimitOrderManager.place()` already performs for any uninitialized pool. Since `place()` calls `_initialize()` when `initialized[pool] == false`, there is no scenario in which a pool remains uninitialized by the time a limit order is placed. Keeping `afterInitialize` merely expands the public API surface and increases maintenance complexity without providing any real benefit.
<br/>
##### Recommendation
We recommend removing the `afterInitialize` endpoint and relying exclusively on the in-place initialization logic within `place()`.

> **Client's Commentary:**
> Commit: https://github.com/cryptoalgebra/plugins-monorepo/commit/f8103fde4248decd05975e5523174e5d199c9574

---

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Algebra%20Finance/Limit%20Order%20Plugin/README.md#11-redundant-afterinitialize-function)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## slippage-patterns.md
# Slippage Security Patterns

## Overview

**Frequency**: 36 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 21 | 14 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Codehawks, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for slippage vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Overpayment of one side of LP Pair onJoinPool due to sandwich or user error

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`CronV1Pool.sol#L2048-L2051`

## Description
Only one of the two incoming tokens is used to determine the amount of pool tokens minted (`amountLP`) on join:

```solidity
amountLP = Math.min(
    _token0InU112.mul(supplyLP).divDown(_token0ReserveU112),
    _token1InU112.mul(supplyLP).divDown(_token1ReserveU112)
);
```

In the event the price moves between the time a minter sends their transaction and when it is included in a block, they may overpay for one of `_token0InU112` or `_token1InU112`. This can occur due to user error, or due to being sandwiched.

### Concrete Example:
```solidity
pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;
import "forge-std/Test.sol";
import "../HelperContract.sol";
import { C } from "../../Constants.sol";
import { ExecVirtualOrdersMem } from "../../Structs.sol";

contract JoinSandwich is HelperContract {
    uint256 WAD = 10**18;

    function testManualJoinSandwich() public {
        address userA = address(this);
        address userB = vm.addr(1323);
        
        // Add some base liquidity from the future attacker.
        addLiquidity(pool, userA, userA, 10**7 * WAD, 10**7 * WAD, 0);
        assertEq(CronV1Pool(pool).balanceOf(userA), 10**7 * WAD - C.MINIMUM_LIQUIDITY);
        
        // Give userB some tokens to LP with.
        token0.transfer(userB, 1_000_000 * WAD);
        token1.transfer(userB, 1_000_000 * WAD);
        addLiquidity(pool, userB, userB, 10**6

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] Hard-coded slippage may freeze user funds during market turbulence

**Source**: Code4rena
**Protocol**: Sturdy
**Impact**: HIGH

**Details**:

_Submitted by jonah1005, also found by berndartmueller, Picodes, IllIllI, sorrynotsorry, and WatchPug_

[GeneralVault.sol#L125](https://github.com/code-423n4/2022-05-sturdy/blob/main/smart-contracts/GeneralVault.sol#L125)<br>
GeneralVault set a hardcoded slippage control of 99%. However, the underlying yield tokens price may go down.<br>
If Luna/UST things happen again, users' funds may get locked.<br>

[LidoVault.sol#L130-L137](https://github.com/code-423n4/2022-05-sturdy/blob/main/smart-contracts/LidoVault.sol#L130-L137)<br>
Moreover, the withdrawal of the lidoVault takes a swap from the curve pool. 1 stEth worth 0.98 ETH at the time of writing.<br>
The vault can not withdraw at the current market.<br>

Given that users' funds would be locked in the lidoVault, I consider this a high-risk issue.

### Proof of Concept

[1 stEth  = 0.98 Eth](https://twitter.com/hasufl/status/1524717773959700481/photo/1)

[LidoVault.sol#L130-L137](https://github.com/code-423n4/2022-05-sturdy/blob/main/smart-contracts/LidoVault.sol#L130-L137)

### Recommended Mitigation Steps

There are different ways to set the slippage.

The first one is to let users determine the maximum slippage they're willing to take.
The protocol front-end should set the recommended value for them.

```solidity
  function withdrawCollateral(
    address _asset,
    uint256 _amount,
    address _to,
    uint256 _minReceiveAmount
  ) external virtual {
      // ...
    require(withdrawAmount >= _minReceiveAmount, Errors.VT_

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-sturdy)

---

### Example 3: H-11: The deposit / withdraw / trade transaction lack of expiration timestamp check and slippage control

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/39 

## Found by 
ctf\_sec

## Summary

The deposit / withdraw / trade transaction lack of expiration timestamp and slippage control

## Vulnerability Detail

Let us look into the heavily forked Uniswap V2 contract addLiquidity function implementation

https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L61

```solidity
// **** ADD LIQUIDITY ****
function _addLiquidity(
	address tokenA,
	address tokenB,
	uint amountADesired,
	uint amountBDesired,
	uint amountAMin,
	uint amountBMin
) internal virtual returns (uint amountA, uint amountB) {
	// create the pair if it doesn't exist yet
	if (IUniswapV2Factory(factory).getPair(tokenA, tokenB) == address(0)) {
		IUniswapV2Factory(factory).createPair(tokenA, tokenB);
	}
	(uint reserveA, uint reserveB) = UniswapV2Library.getReserves(factory, tokenA, tokenB);
	if (reserveA == 0 && reserveB == 0) {
		(amountA, amountB) = (amountADesired, amountBDesired);
	} else {
		uint amountBOptimal = UniswapV2Library.quote(amountADesired, reserveA, reserveB);
		if (amountBOptimal <= amountBDesired) {
			require(amountBOptimal >= amountBMin, 'UniswapV2Router: INSUFFICIENT_B_AMOUNT');
			(amountA, amountB) = (amountADesired, amountBOptimal);
		} else {
			uint amountAOptimal = UniswapV2Library.quote(amountBDesired, reserveB, reserveA);
			assert(amountAOptimal <= amountADesired);
			require(amountAOptimal >= amountAMin

*[Content truncated...]*

---

### Example 4: User may not be able to override slippage on destination

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
BridgeFacet.sol#L741-L746

## Description
If `BridgeFacet.execute()` is executed before `BridgeFacet.forceUpdateSlippage()`, the user won't be able to update slippage on the destination chain. In this case, the slippage specified on the source chain is used. Due to different conditions on these chains, a user may want to specify different slippage values. This can result in user loss, as a slippage higher than necessary will result in the swap trade being sandwiched.

## Recommendation
`xcall()` can take different parameters for source and destination slippage:

```solidity
function xcall(
    uint32 _destination,
    address _to,
    address _asset,
    address _delegate,
    uint256 _amount,
    // uint256 _slippage,
    uint256 _sourceSlippage,
    uint256 _destinationSlippage,
    bytes calldata _callData
) external payable returns (bytes32);
```

Then, `TransferInfo` params should be encoded with `_destinationSlippage` and `_sourceSlippage` should be passed separately to `_xcall()`.

## Connext
We previously had the slippage implemented as separate values but decided to change it back for a couple of reasons:
1. Since the messages chains have variable latency, the `destinationChainSlippage` would be hard to predict at the time of `xcall`, especially for authenticated messages. Users can override this using `forceUpdateSlippage`, but it requires an additional transaction.
2. Adding two parameters to the interface clutters it, and we st

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 5: [M-06] Assets may be lost when calling unprotected `AutoPxGlp::compound` function

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/vaults/AutoPxGlp.sol#L210>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/PirexGmx.sol#L497-L516>

### Impact

Compounded assets may be lost because `AutoPxGlp::compound` can be called by anyone and minimum amount of Glp and USDG are under caller's control. The only check concerning minValues is that they are not zero (1 will work, however from the perspective of real tokens e.g. 1e6, or 1e18 it's virtually zero). Additionally, internal smart contract functions use it as well with minimal possible value (e.g. `beforeDeposit` function).

### Proof of Concept

`compound` function calls PirexGmx::depositGlp, that uses external GMX reward router to mint and stake GLP.

<https://snowtrace.io/address/0x82147c5a7e850ea4e28155df107f2590fd4ba327#code>

```solidity
141:     function mintAndStakeGlpETH(uint256 _minUsdg, uint256 _minGlp) external payable nonReentrant returns (uint256) {
    ...
148: uint256 glpAmount = IGlpManager(glpManager).addLiquidityForAccount(address(this), account, weth, msg.value, _minUsdg, _minGlp);
```

Next `GlpManager::addLiquidityForAccount` is called
<https://github.com/gmx-io/gmx-contracts/blob/master/contracts/core/GlpManager.sol#L103>

        function addLiquidityForAccount(address _fundingAccount, address _account, address _token, uint256 _amount, uint256 _minUsdg, uint256 _minGlp) external override nonReentrant returns (uint256) {
            _validateHandler();


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 6: H-4: No slippage protection during repayment due to dynamic slippage params and easily influenced `slot0()`

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

### Example 7: H-4: Deposit transactions lose funds to front-running when multiple fee tiers are available

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/105 

## Found by 
crimson-rat-reach
## Summary
Deposit transactions lose funds to front-running when multiple fee tiers are available 

## Vulnerability Detail
The deposit transaction takes in minimum parameters for amount0 and amount1 of tokens that the user wishes to deposit, but no parameter for the minimum number of LP tokens the user expects to receive. A malicious actor can limit the number of LP tokens that the user receives in the following way:

A user Alice submits a transaction to deposit tokens into Multipool where (amount0Desired, amount0Min) > (amount1Desired, amount1Min)

A malicious actor Bob can front-run this transaction if there are multiple feeTiers:
- by first moving the price of feeTier1 to make tokenA very cheap (lots of tokenA in the pool) 
- then moving the price of feeTier2 in opposite direction to make tokenB very cheap (lots of tokenB in the pool) 

This results in reserves being balanced accross feeTiers, and the amounts resulting from `_optimizeAmounts` are balanced as well:
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L780-L808

So the minimum amounts checks pass and but results as less LP tokens minted, because even though the reserves are balanced, they are also overinflated due to the large swap, and the ratio:
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c

*[Content truncated...]*

---

### Example 8: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec
## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and

*[Content truncated...]*

---

### Example 9: H-6: ShortLongSpell#_withdraw checks slippage limit but never applies it making it useless

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/126 

## Found by 
0x52, Ch\_301
## Summary

Slippage limits protect the protocol in the event that a malicious user wants to extract value via swaps, this is an important protection in the event that a user finds a way to trick collateral requirements. Currently the sell slippage is checked but never applied so it is useless.

## Vulnerability Detail

See summary.

## Impact

Slippage limit protections are ineffective for ShortLongSpell

## Code Snippet

[ShortLongSpell.sol#L160-L20](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Review

## Recommendation

Apply sell slippage after it is checked



## Discussion

**securitygrid**

Escalate for 10 USDC
This is not a valid M/H. The toAmont and expectedAmount in the off-chain parameter [MegaSwapSellData](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/libraries/Paraswap/Utils.sol#L30-L42) structure are the real slippage protection parameters. Just like ExactInputParams/ExactOutputParams of uniswapV3 pool.

**sherlock-admin**

 > Escalate for 10 USDC
> This is not a valid M/H. The toAmont and expectedAmount in the off-chain parameter [MegaSwapSellData](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/libraries/Paraswap/Utils.sol#L30-L42) structure are the real slippage protection par

*[Content truncated...]*

---

### Example 10: [H-07] Missing slippage checks

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by tensors_

There are no minimum amounts out, or checks that frontrunning/slippage is sufficiently mitigated.
This means that anyone with enough capital can force arbitrarily large slippage by sandwiching transactions, close to 100%. See issue page for referenced code.

Recommend adding a minimum amount out parameter. The function reverts if the minimum amount isn't obtained.

**[verifyfirst (Spartan) acknowledge:](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-884593067)**
> We acknowledge the issue for the protocol's AMM, but if this becomes a large issue in the future, the router is easily upgradeable to include a minimum rate parameter.

**[SamusEldburg (Spartan) confirmed and disagreed with severity:](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-889638485)**
> Have changed this to confirmed; even though we already were aware of it; we have discussed and are happy to add in a UI-handed arg for minAmount now rather than reactively in the future. Disagree with severity though; this wasn't a problem with V1 at all.

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-894863717):**
> I'll keep high risk as sandwich attacks are very common and risk of getting a bad swap is real.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 11: Check slippage of swaps

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
OmniBridgeFacet.sol#L63-L65

## Description
Several bridges check that the output of swaps isnt 0. However, it could also happen that a swap gives a positive output, but still lower than expected due to slippage, sandwiching, or MEV. Several AMMs will have a mechanism to limit slippage, but it might be useful to add a generic mechanism as multiple swaps in sequence might have a relatively large slippage.

```solidity
function swapAndStartBridgeTokensViaOmniBridge(...) {
    ...
    uint256 amount = _executeAndCheckSwaps(_lifiData, _swapData, payable(msg.sender));
    if (amount == 0) {
        revert InvalidAmount();
    }
    _startBridge(_lifiData, _bridgeData, amount, true);
}
```

## Recommendation
Consider adding a slippage check by specifying a minimum amount of expected tokens. At least add a check for `amount == 0` in all bridges.

## LiFi
Fixed with PR #75.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 12: deposit and withdraw functions are susceptible to sandwich attacks

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Vulnerability Report

**Severity:** High Risk  
**Context:** AeraVaultV1.sol#L402-L453, AeraVaultV1.sol#L456-L514  
**Description:** Transactions calling the `deposit()` function are susceptible to sandwich attacks where an attacker can extract value from deposits. A similar issue exists in the `withdraw()` function but the minimum check on the pool holdings limits the attacks impact.

## Scenario Example
(Assuming swap fees are ignored for simplicity):

1. Suppose the Balancer pool contains two tokens, WETH and DAI, with weights of 0.5 each. Currently, there is 1 WETH and 3k DAI in the pool, and the WETH spot price is 3k.
2. The Treasury wants to add another 3k DAI into the Aera vault, so it calls the `deposit()` function.
3. The attacker front-runs the Treasurys transaction. They swap 3k DAI into the Balancer pool and receive 0.5 WETH. The weights remain 0.5 and 0.5, but because WETH and DAI balances become 0.5 and 6k, WETHs spot price now becomes 12k.
4. At this point, the Treasurys transaction adds 3k DAI into the Balancer pool and changes the weights to 0.6 and 0.4.
5. The attacker back-runs the transaction and swaps the 0.5 WETH acquired in step 3 back to DAI, recovering WETHs spot price to slightly above 3k. According to the current weights, they can receive 9k * (1 - 1/r) = 3.33k DAI from the pool, where r = (2^0.4)^(1/0.6).
6. As a result, the attacker profits 3.33k - 3k = 0.33k DAI.

## Recommendations
Potential mitigations include:

- Adopting a t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 13: Users are forced to accept any slippage on the destination chain

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
BridgeFacet.sol#L28

## Description
The documentation mentioned that there is a cancel function on the destination domain that allows users to send the funds back to the origin domain, accepting the loss incurred by slippage from the origin pool. However, this feature is not found in the current codebase. If the high slippage rate persists continuously on the destination domain, the users will be forced to accept the high slippage rate. Otherwise, their funds will be stuck in Connext.

## Recommendation
Implement the cancel function on the destination domain to allow users to send funds back to the origin domain if they choose not to accept the high slippage rate on the destination domain.

## Connext
Solved in PR 2456.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 14: Routers are exposed to extreme slippage if they attempt to repay debt before being reconciled

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- NomadFacet.sol#L188-L209
- NomadFacet.sol#L269-L320
- AssetLogic.sol#L228-L250
- AssetLogic.sol#L308-L362

## Description
When routers are reconciled, the local asset may need to be exchanged for the adopted asset in order to repay the unbacked Aave loan. `AssetLogic.swapFromLocalAssetIfNeededForExactOut()` takes two key arguments:
- **_amount**: representing exactly how much of the adopted asset should be received.
- **_maxIn**: which is used to limit slippage and limit how much of the local asset is used in the swap.

Upon failure to swap, the protocol will reset the values for unbacked Aave debt and distribute local tokens to the router. However, if this router partially paid off some of the unbacked Aave debt before being reconciled, **_maxIn** will diverge from **_amount**, allowing value to be extracted in the form of slippage. As a result, routers may receive less than the amount of liquidity they initially provided, leading to router insolvency.

## Recommendation
Instead of using **_amount** to represent **_maxIn**, consider using some sort of user slippage amount. Alternatively, it may be easier/safer to restrict who can use Aave unbacked debt as there is a lot of added complexity in integrating unbacked debt into the protocol.

## Connext
Solved in PR 1585.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 15: M-11: Withdrawals from IchiVaultSpell have no slippage protection so can be frontrun, stealing all user funds

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/130 

## Found by 
rvierdiiev, obront, koxuan, ctf\_sec, tives, cergyk, berndartmueller, 0x52

## Summary

When a user withdraws their position through the `IchiVaultSpell`, part of the unwinding process is to trade one of the released tokens for the other, so the borrow can be returned. This trade is done on Uniswap V3. The parameters are set in such a way that there is no slippage protection, so any MEV bot could see this transaction, aggressively sandwich attack it, and steal the majority of the user's funds.

## Vulnerability Detail

Users who have used the `IchiVaultSpell` to take positions in Ichi will eventually choose to withdraw their funds. They can do this by calling `closePosition()` or `closePositionFarm()`, both of which call to `withdrawInternal()`, which follows loosely the following logic:
- sends the LP tokens back to the Ichi vault for the two underlying tokens (one of which was what was borrowed)
- swaps the non-borrowed token for the borrowed token on UniV3, to ensure we will be able to pay the loan back
- withdraw our underlying token from the Compound fork
- repay the borrow token loan to the Compound fork
- validate that we are still under the maxLTV for our strategy
- send the funds (borrow token and underlying token) back to the user

The issue exists in the swap, where Uniswap is called with the following function:
```solidity
if (amountToSwap > 0) {
    swapPool = IUniswapV3

*[Content truncated...]*

---

### Example 16: [H-01] Minting and burning synths exposes users to unlimited slippage

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

_Submitted by TomFrenchBlockchain, also found by cmichel_

#### Impact

The amount of synths minted / assets received when minting or burning synths can be manipulated to an unlimited extent by manipulating the reserves of the pool

#### Proof of Concept

See `VaderPool.mintSynth`:
<https://github.com/code-423n4/2021-11-vader/blob/607d2b9e253d59c782e921bfc2951184d3f65825/contracts/dex-v2/pool/VaderPoolV2.sol#L126-L167>

Here a user sends `nativeDeposit` to the pool and the equivalent amount of `foreignAsset` is minted as a synth to be sent to the user. However the user can't specify the minimum amount of synth that they would accept. A frontrunner can then manipulate the reserves of the pool in order to make `foreignAsset` appear more valuable than it really is so the user receives synths which are worth much less than what `nativeDeposit` is worth. This is equivalent to a swap without a slippage limit.

Burning synths essentially runs the same process in behalf so manipulating the pool in the opposite direction will result in the user getting fewer of `nativeAsset` than they expect.

#### Recommended Mitigation Steps

Add a argument for the minimum amount of synths to mint or nativeAsset to receive.

**[SamSteinGG (Vader) acknowledged and disagreed with severity](https://github.com/code-423n4/2021-11-vader-findings/issues/2#issuecomment-979099464):**
 > We believe the severity should be set to medium as there are no loss of funds and its exploit requires special circumstance

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 17: [M-02] Slippage controls for calling `bHermes` contract's `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions are missing

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

[EIPS](<https://eips.ethereum.org/EIPS/eip-4626#security-considerations>) mentions that "if implementors intend to support EOA account access directly, they should consider adding an additional function call for `deposit`/`mint`/`withdraw`/`redeem` with the means to accommodate slippage loss or unexpected deposit/withdrawal limits, since they have no other means to revert the transaction if the exact output amount is not achieved."

Using the `bHermes` contract that inherits the `ERC4626DepositOnly` contract, EOAs can call the `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions directly. However, because no slippage controls can be specified when calling these functions, these function's `shares` and `assets` outputs can be less than expected to these EOAs.

<https://github.com/code-423n4/2023-05-maia/blob/53c7fe9d5e55754960eafe936b6cb592773d614c/src/erc-4626/ERC4626DepositOnly.sol#L32-L44>

```solidity
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        address(asset).safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
```

<https://github.com/code-423n4/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 18: M-1: `rebalanceLite` should provide a slippage protection

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/429 

## Found by 
HollaDieWaldfee, hansfriese

## Summary
Users can lose funds while rebalancing.

## Vulnerability Detail
The protocol provides two kinds of rebalancing functions - `rebalance()` and `rebalanceLite()`.
While the function `rebalance()` is protected from an unintended slippage because the caller can specify `amountOutMinimum`, `rebalanceLite()` does not have this protection.
This makes the user vulnerable to unintended slippage due to various scenarios.
```solidity
PerpDepository.sol
597:     function rebalanceLite(
598:         uint256 amount,
599:         int8 polarity,
600:         uint160 sqrtPriceLimitX96,
601:         address account
602:     ) external nonReentrant returns (uint256, uint256) {
603:         if (polarity == -1) {
604:             return
605:                 _rebalanceNegativePnlLite(amount, sqrtPriceLimitX96, account);
606:         } else if (polarity == 1) {
607:             // disable rebalancing positive PnL
608:             revert PositivePnlRebalanceDisabled(msg.sender);
609:             // return _rebalancePositivePnlLite(amount, sqrtPriceLimitX96, account);
610:         } else {
611:             revert InvalidRebalance(polarity);
612:         }
613:     }
614:
615:     function _rebalanceNegativePnlLite(
616:         uint256 amount,
617:         uint160 sqrtPriceLimitX96,
618:         address account
619:     ) private returns (uint256, uint256) {
620:         uin

*[Content truncated...]*

---

### Example 19: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/132 

## Found by 
0x52
## Summary

The sqrtRatioLimit for UniV3 doesn't cause the swap to revert upon reaching that value. Instead it just cause the swap to partially fill. This is a [known issue](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L641) with using sqrtRatioLimit as can be seen here where the swap ends prematurely when it has been reached. This is problematic as this is meant to provide the user with slippage protection but doesn't.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L209-L223

        if (amountToSwap > 0) {
            SWAP_POOL = IUniswapV3Pool(vault.pool());
            uint160 deltaSqrt = (param.sqrtRatioLimit *
                uint160(param.sellSlippage)) / uint160(Constants.DENOMINATOR);
            SWAP_POOL.swap(
                address(this),
                // if withdraw token is Token0, then swap token1 -> token0 (false)
                !isTokenA,
                amountToSwap.toInt256(),
                isTokenA
                    ? param.sqrtRatioLimit + deltaSqrt
                    : param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
                abi.encode(address(this))
            );
        }

sqrtRatioLimit is used as slippage protection for the user but is ineffective and depending on what tokens are 

*[Content truncated...]*

---

### Example 20: H-6: User specified slippage allows frontrunning

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/192 

## Found by 
zeroknots, minhtrng, keccak123, peanuts, ck, HollaDieWaldfee, HonorLt, koxuan, GimelSec, wagmi, yixxas, jonatascm

## Summary

`rebalance` and `rebalanceLite` can be called by any user. Assets are taken from a user specified `account` address which has approved PerpDepository. If an address has a non-zero approval for PerpDepository, a frontrunner can use `rebalance` to transfer funds and profit by sandwiching the Uniswap pool swap.

## Vulnerability Detail

When `mint` or `redeem` is called in UXDController, `msg.sender` is where the value is coming from. But `rebalance` allows for the caller to specify [the `account` where funds are coming from](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L452). This means `msg.sender` can be any address. This allows for different scenarios where a frontrunner can profit with these steps.
1. a frontrunner detects a call of `rebalance` transaction in the mempool for a certain account address
2. the frontrunner duplicates the transaction but increases the gas amount (to allow frontrunning the original transaction) and changes the `amountOutMinimum` value to zero
3. the frontrunner can profit by sandwiching the Uniswap swap which now has no slippage setting
4. The user will lose value 

## Impact

An account that is used in `rebalance` can lose value

## Code Snippet

`rebalance` can be frontrun
htt

*[Content truncated...]*

---

### Example 21: H-5: Settlement slippage is not implemented correctly which may lead to some vaults being impossible to settle

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/42 

## Found by 
0x52

## Summary

The contract is supposed to implement a different max slippage value depending on the settlement type, but these values have no impact because they are never actually applied. Instead, regardless of settlement type or function inputs, max slippage will always be limited to the value of balancerPoolSlippageLimitPercent. This can be problematic because the default value allows only 1% slippage. If settlement slippage goes outside of 1% then settlement of any kind will become impossible. 

## Vulnerability Detail

[Boosted3TokenAuraHelper.sol#L95-L99](https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/external/Boosted3TokenAuraHelper.sol#L95-L99)

        params.minPrimary = poolContext._getTimeWeightedPrimaryBalance(
            oracleContext, strategyContext, bptToSettle
        );

        params.minPrimary = params.minPrimary * strategyContext.vaultSettings.balancerPoolSlippageLimitPercent / 
            uint256(BalancerConstants.VAULT_PERCENT_BASIS);

Boosted3TokenAuraHelper#_executeSettlement first sets params.minPrimary overwriting any value from function input. Next it adjusts minPrimary by balancerPoolSlippageLimitPercent, which is a constant set at pool creation; however it doesn't ever adjust it by Params.DynamicTradeParams.oracleSlippagePercent. This means that the max possible slippage regardless of settle

*[Content truncated...]*

---

### Example 22: [M-01] No slippage protection for Market functions

**Source**: Code4rena
**Protocol**: Canto
**Impact**: MEDIUM

**Details**:

### Proof of Concept

Price for shares inside `Market` is calculated using bonding curve. Currently, `LinearBondingCurve` is supported. This bonging curve [increases each next shares with fixed amount](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L21) and also [uses `10% / log2(shareIndex)` to calculate fee](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L35) for the share.

In order to calculate price to [buy shares `getBuyPrice` is used](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/Market.sol#L152) and to calculate price to [`sell` shares `getSellPrice` is used](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/Market.sol#L175).

<https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/Market.sol#L132-L145>

```solidity
    function getBuyPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {
        // If id does not exist, this will return address(0), causing a revert in the next line
        address bondingCurve = shareData[_id].bondingCurve;
        (price, fee) = IBondingCurve(bondingCurve).getPriceAndFee(shareData[_id].tokenCount + 1, _amount);
    }

    function getSellPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {
        // If id does not exist, this will return address(0), causing

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-11-canto)

---

### Example 23: [M-18] Volatile prices and lack of checks on `rigidRedemption()` can cause users to purchase stETH at unwanted prices

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Impact

Volatile prices can cause issue when users try to do [`rigidRedemption`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/pools/base/LybraPeUSDVaultBase.sol#L157-L168).

### Proof of Concept

Volatile prices can cause slippage loss when users use `rigidRedemption()`. This function takes PeUSD (stable coin) amount and converts it to WstETH/stETH (variable price). Unfortunately, `rigidRedemption()` does not include `timestamp` or `minAmount` received, meaning this trade can be executed later in time and at a different price than user previously expected.

**Example:**

*   Provider has 100 **wstETH** and **wstETH** price is `$`2000.
*   User wants to buy 10 **wstETH** and has 20,000 in PeUSD, so they calls [`rigidRedemption`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/pools/base/LybraPeUSDVaultBase.sol#L157-L168).
*   Now, due to congestion on **ETH** and volatile prices, the transaction could remain stuck in the mempool for a long time.
*   Finally, the transaction gets executed, but now the wstETH price is `$`2100, not the original `$`2000, so the user receives 9.52 **wstETH** instead of 10 (not counting fees)!

### Recommended Mitigation Steps

Because of this scenario and others like it, it is recommended to use some sort of slippage protection when users execute trades.

```jsx
    function rigidRedemption(address provider, uint256 eusdAmount,uint256 minAmountReceived) external virtual {
        depositedAsset[pro

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 24: H-7: User specified slippage allows frontrunning

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/192 

## Found by 
HonorLt, minhtrng, jonatascm, koxuan, yixxas, wagmi, ck, HollaDieWaldfee, zeroknots, GimelSec, peanuts, keccak123

## Summary

`rebalance` and `rebalanceLite` can be called by any user. Assets are taken from a user specified `account` address which has approved PerpDepository. If an address has a non-zero approval for PerpDepository, a frontrunner can use `rebalance` to transfer funds and profit by sandwiching the Uniswap pool swap.

## Vulnerability Detail

When `mint` or `redeem` is called in UXDController, `msg.sender` is where the value is coming from. But `rebalance` allows for the caller to specify [the `account` where funds are coming from](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L452). This means `msg.sender` can be any address. This allows for different scenarios where a frontrunner can profit with these steps.
1. a frontrunner detects a call of `rebalance` transaction in the mempool for a certain account address
2. the frontrunner duplicates the transaction but increases the gas amount (to allow frontrunning the original transaction) and changes the `amountOutMinimum` value to zero
3. the frontrunner can profit by sandwiching the Uniswap swap which now has no slippage setting
4. The user will lose value 

## Impact

An account that is used in `rebalance` can lose value

## Code Snippet

`rebalance` can be frontrun
htt

*[Content truncated...]*

---

### Example 25: [H-02] No slippage protection when interacting with AMM

**Source**: Pashov Audit Group
**Protocol**: GammaSwap_2024-12-30
**Impact**: HIGH

**Details**:

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

- It was noticed that the `amount0Min` & `amount1Min` are set to zero during interactions with the AMM router (Uniswap) for swaps and liquidity additions. These parameters are intended to protect against slippage; setting them to zero exposes transactions to slippage, potentially resulting in receiving or adding smaller amounts than intended.

- This issue was identified across all interactions with the AMM (Uniswap), when swapping, adding liquidity and removing liquidity, where these different interactions has different impacts on the protocol:

\_depositAsset()
\_increaseLiquidity()
\_addMissingAmountsToHedge()
\_decreaseLiquidity()
\_depositAsset()
processWithdrawals()
rebalanceCollateralToRatio()

## Recommendations

Instead of hard-coding the minimum amounts to zero, introduce a state variable to control the slippage percentage (e.g., 80% of the swapped or added amounts, with a setter to update the slippage during high market volatility) and utilize it when interacting with the AMM.

Or, it's recommended to set a minLiquidity received and revert if the total liquidity received of the whole transaction is less than minLiquidity. The minLiquidity can be determined by simulation using current (no manipulated) price.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GammaSwap-security-review_2024-12-30.md)

---

## Statistics

- Total findings analyzed: 36
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## sandwich-attack-patterns.md
# Sandwich Attack Security Patterns

## Overview

**Frequency**: 19 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 13 | 6 | 0 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group, Code4rena, Spearbit, Codehawks

---

## Detection Checklist

- [ ] Check for sandwich attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] `_swap()` is vulnerable to sandwich attacks

**Source**: Pashov Audit Group
**Protocol**: Gacha_2025-01-27
**Impact**: HIGH

**Details**:

## Severity

**Impact:** High

**Likelihood:** High

## Description

Anyone can buy a ticket from a specified pool, a certain payment token will be used to swap for meme tokens. The swapping process is implemented as below:

```solidity
    function _swap(
        address token,
        uint256 cost
    ) private returns (uint256 actualTokens) {
        Storage storage $ = _getOwnStorage();
        IUniswapV2Router01 uni = IUniswapV2Router01($.uniswapRouter);
        IUniswapV2Factory factory = IUniswapV2Factory($.uniswapFactory);

        address pair = factory.getPair($.paymentToken, token);
        (uint256 wethReserve, uint256 tokenReserve, ) = IUniswapV2Pair(pair)
            .getReserves();
        if (wethReserve == 0 || tokenReserve == 0) revert InvalidPair();

@>      uint256 maxTokens = uni.getAmountOut(cost, wethReserve, tokenReserve); // includes 0.3%
@>      uint256 minTokens = Math.mulDiv(maxTokens, 95, 100); // 5% slippage

        address[] memory path = new address[](2);
        path[0] = $.paymentToken;
        path[1] = token;

        IERC20($.paymentToken).approve($.uniswapRouter, cost);
        uint256[] memory amounts = uni.swapExactTokensForTokens(
            cost,
@>          minTokens,
            path,
            address(this),
            block.timestamp + 1
        );
        actualTokens = amounts[amounts.length - 1];
    }
```

Before swapping for meme tokens using `uni.swapExactTokensForTokens()`, a `minTokens` amount is calculated. This valu

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Gacha-security-review_2025-01-27.md)

---

### Example 2: Use of spot price in SponsorVault leads to sandwich attack.

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
**File:** SponsorVault.sol  
**Line:** 208

## Description
There is a special role sponsor in the protocol. Sponsors can cover the liquidity fee and transfer fee for users, making it more favorable for users to migrate to the new chain. Sponsors can either provide liquidity for each adopted token or provide the native token in the `SponsorVault`. If the native token is provided, the `SponsorVault` will swap to the adopted token before transferring it to users.

```solidity
contract SponsorVault is ISponsorVault, ReentrancyGuard, Ownable {
    ...
    function reimburseLiquidityFees(
        address _token,
        uint256 _liquidityFee,
        address _receiver
    ) external override onlyConnext returns (uint256) {
        ...
        uint256 amountIn = tokenExchange.getInGivenExpectedOut(_token, _liquidityFee);
        amountIn = currentBalance >= amountIn ? amountIn : currentBalance;
        // sponsored fee may end being less than _liquidityFee due to slippage
        sponsoredFee = tokenExchange.swapExactIn{value: amountIn}(_token, msg.sender);
        ...
    }
}
```

The spot AMM price is used when doing the swap. Attackers can manipulate the value of `getInGivenExpectedOut` and make `SponsorVault` sell the native token at a bad price. By executing a sandwich attack, the exploiters can drain all native tokens in the sponsor vault.

For the sake of the following example, assume that `_token` is USDC and the native token is ETH. Th

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: Use of spot dex price when repay portal debt leads to sandwich attacks

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- `NomadFacet.sol#L286-L290`
- `NomadFacet.sol#L204-L209`

## Description
When the `NomadFacet` repays the portal debt, it has to convert local assets into adopted assets. It first calculates how many assets it needs to swap and then converts the local assets into the adopted assets.

### Function: _reconcileProcessPortal
```solidity
function _reconcileProcessPortal(
    bytes32 _canonicalId,
    uint256 _amount,
    address _local,
    bytes32 _transferId
) private returns (uint256) {
    // Calculates the amount to be repaid to the portal in adopted asset
    (uint256 totalRepayAmount, uint256 backUnbackedAmount, uint256 portalFee) =
        _calculatePortalRepayment(
            _canonicalId,
            _amount,
            _transferId,
            _local
        );
    ...
    //@audit totalRepayAmount is dependent on the AMM spot price. The swap will not hit the slippage
    (bool swapSuccess, uint256 amountIn, address adopted) =
        AssetLogic.swapFromLocalAssetIfNeededForExactOut(
            _canonicalId,
            _local,
            totalRepayAmount,
            _amount
        );
```

### Function: _calculatePortalRepayment
```solidity
function _calculatePortalRepayment(
    bytes32 _canonicalId,
    uint256 _localAmount,
    bytes32 _transferId,
    address _local
) internal returns (uint256, uint256, uint256) {
    // @audit A manipulated spot price might be used. availableAmount might be extremely small
    (uint256 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: H-12: Sandwich attack to accruePremiumAndExpireProtections()

**Source**: Sherlock
**Protocol**: Carapace
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-carapace-judging/issues/26 

## Found by 
libratus, monrel, jkoppel, chaduke, immeas, 0Kage

## Summary
``accruePremiumAndExpireProtections()`` will increase ``totalSTokenUnderlying``, and thus increase the exchange rate of the ``ProtectionPool``. A malicious user can launch a sandwich attack and profit. This violates the ``Fair Distribution`` principle of the protocol: 
[https://www.carapace.finance/WhitePaper#premium-pricing](https://www.carapace.finance/WhitePaper#premium-pricing)

## Vulnerability Detail
Let's show how a malicious user, Bob, can launch a sandwich attack to ``accruePremiumAndExpireProtections()`` and profit. 

1. Suppose there are 1,000,000 underlying tokens for the ``ProtectionPool``, and ``totalSupply = 1,000,000``, therefore the exchange rate is 1/1 share. Suppose Bob has 100,000 shares. 

2. Suppose ``accruePremiumAndExpireProtections()`` is going to be called and add 100,000 to ``totalSTokenUnderlying`` at L346. 

[https://github.com/sherlock-audit/2023-02-carapace/blob/main/contracts/core/pool/ProtectionPool.sol#L279-L354](https://github.com/sherlock-audit/2023-02-carapace/blob/main/contracts/core/pool/ProtectionPool.sol#L279-L354)

3) Bob front-runs ``accruePremiumAndExpireProtections()`` and calls ``deposit()`` to deposit 100,000 underlying tokens into the contract. The check for ``ProtectionPoolPhase`` will pass for an open phase. As a result, there are 1,100,000 underlying tokens, and 1,100,000 sh

*[Content truncated...]*

---

### Example 5: Attacker can drain protocol tokens by sandwich attacking owner call to `setPositionWidth` and `unpause` to force redeployment of Beefy's liquidity into an unfavorable range

**Source**: Cyfrin
**Protocol**: Beefy Finance
**Impact**: HIGH

**Details**:

**Description:** When the owner of the `StrategyPassiveManagerUniswap` contract calls `setPositionWidth` and `unpause` an attacker can sandwich attack these calls to drain the protocol's tokens. This is possible because `setPositionWidth` and `unpause` redeploy Beefy's liquidity into a new range based off the current tick and don't check the `onlyCalmPeriods` modifier, so an attacker can use this to force Beefy to re-deploy liquidity into an unfavorable range.

**Impact:** Attacker can sandwich attack owner call to `setPositionWidth` and `unpause` to drain protocol tokens.

**Proof of Concept:** Add a new test file `test/forge/ConcLiqTests/ConcLiqWBTCUSDC.t.sol:`
```solidity
pragma solidity 0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin-4/contracts/token/ERC20/ERC20.sol";
import {BeefyVaultConcLiq} from "contracts/protocol/concliq/vault/BeefyVaultConcLiq.sol";
import {BeefyVaultConcLiqFactory} from "contracts/protocol/concliq/vault/BeefyVaultConcLiqFactory.sol";
import {StrategyPassiveManagerUniswap} from "contracts/protocol/concliq/uniswap/StrategyPassiveManagerUniswap.sol";
import {StrategyFactory} from "contracts/protocol/concliq/uniswap/StrategyFactory.sol";
import {StratFeeManagerInitializable} from "contracts/protocol/beefy/StratFeeManagerInitializable.sol";
import {IStrategyConcLiq} from "contracts/interfaces/beefy/IStrategyConcLiq.sol";
import {IUniswapRouterV3} from "contracts/interfaces/exchanges/IUniswapRouterV3.sol";

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2024-04-06-cyfrin-beefy-finance.md)

---

### Example 6: [H-04] If insider deposits and unlocks in quick succession, attacker can steal their NFT and their deposit funds

**Source**: ZachObront
**Protocol**: Dyad
**Impact**: HIGH

**Details**:

The dNFT contract allows the owner to mint a predefined quantity of "insider" NFTs without any deposit attached to them. These NFTs begin in a locked state, which stops them from being immediately liquidated due to their lack of deposits.

The protocol enforces that, in order for insider's to mint any DYAD, they must unlock their NFTs (so that they will be subject to liquidation, like all other users).

However, there is no safety check for the opposite case, where an insider unlocks their NFT before making a deposit. In this situation, any user could liquidate them and steal their NFT.

This is especially dangerous because if a user calls both of these functions in quick succession, they may both be in the mempool at the same time. If this is the case, a malicious attacker can create a flashbots bundle to sandwich their liquidation transaction between the unlock() and deposit() transactions, with the result that:

- The attacker will successfully liquidate and steal the insider's NFT
- The deposit transaction will deposit the insider's ETH to the stolen NFT, securing it for the attacker

**Recommendation**

I would recommend adding a check to the unlock() function to ensure this situation is avoided:

```solidity
function unlock(uint id)
external
isNftOwner(id)
{
if (!id2Locked[id]) revert NotLocked();
if (id2Shared[id] == 0) revert MustDepositFirst();
id2Locked[id] = false;
emit Unlocked(id);
}
```

Note: This requires adding a MustDepositFirst() error to IDNft.sol.

**Revi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-02-12-Dyad.md)

---

### Example 7: [M-01] `withdraw` operation is prone to sandwich attacks

**Source**: Pashov Audit Group
**Protocol**: Hyperbloom_2025-06-24
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

Inside `withdraw` operation of `StrategyPassiveManagerHyperswap` and `StrategyPassiveManagerKittenswap`, `_onlyCalmPeriods` will be checked only when `calmAction` is false and `lastDeposit` is equal to `block.timestamp`.

```solidity
    function withdraw(uint256 _amount0, uint256 _amount1) external {
        _onlyVault();

>>>     if (block.timestamp == lastDeposit && !calmAction) _onlyCalmPeriods();

        if (_amount0 > 0) IERC20Metadata(lpToken0).safeTransfer(vault, _amount0);
        if (_amount1 > 0) IERC20Metadata(lpToken1).safeTransfer(vault, _amount1);

        if (!_isPaused()) _addLiquidity();
    
        (uint256 bal0, uint256 bal1) = balances();
        calmAction = false;

        emit TVL(bal0, bal1);
    }
```

An attacker can exploit this by depositing dust amount, waiting for the next block, then performing a swap to manipulate the price. After that, they can call `withdraw` to trigger `_removeLiquidity` and `_addLiquidity`, causing the strategy to add liquidity using the manipulated price.

```solidity
    function _addLiquidity() private {
        _whenStrategyNotPaused();

        (uint256 bal0, uint256 bal1) = balancesOfThis();

        uint160 sqrtprice = sqrtPrice();
        uint128 liquidity = LiquidityAmounts.getLiquidityForAmounts(
            sqrtprice,
            TickMath.getSqrtRatioAtTick(positionMain.tickLower),
            TickMath.getSqrtRatioAtTick(positionMain.tick

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Hyperbloom-security-review_2025-06-24.md)

---

### Example 8: Sandwich attack to steal all ERC-20 tokens in the Fees contract

**Source**: Codehawks
**Protocol**: Beedle - Oracle free perpetual lending
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Fees.sol#L38-L39">https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Fees.sol#L38-L39</a>


## Summary

The `Fees::sellProfits()` lacks slippage protection, resulting in being attacked by a sandwich attack to drain all locked ERC-20 tokens.

## Vulnerability Details

The `sellProfits()` is a permissionless function that can be called by anyone. The function lacks [slippage protection](https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Fees.sol#L38-L39) (the parameters `amountOutMinimum` and `sqrtPriceLimitX96` are set to 0) when swapping tokens through Uniswap's pools. 

In this way, an attacker can launch a sandwich attack with a flash loan to drain all ERC-20 tokens (e.g., USDC, DAI, CRV, etc.) locked in the `Fees` contract. 

For instance, to drain all USDC, consider the following proof-of-concept.
1. Attacker borrows a flash loan for USDC and buys WETH from Uniswap's WETH/USDC pool.
2. Attacker executes the `sellProfits(USDC)`.
3. The `sellProfits()` will spend all locked USDC for buying WETH at a very high price.
4. Attacker sells the previously obtained WETH for USDC at the same pool and repays the flash loan.
5. Attacker takes all locked USDC as profit.

Moreover, an attacker can perform steps 1-5 above to steal other ERC-20 tokens l

*[Content truncated...]*

---

### Example 9: H-1: User can perform sandwich attack on withdrawReserves for profit

**Source**: Sherlock
**Protocol**: DODO V3
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/22 

## Found by 
dirk\_y, kutugu
## Summary
A malicious user could listen to the mempool for calls to `withdrawReserves`, at which point they can perform a sandwich attack by calling `userDeposit` before the withdraw reserves transaction and then `userWithdraw` after the withdraw reserves transaction. They can accomplish this using a tool like flashbots and make an instantaneous profit due to changes in exchange rates.

## Vulnerability Detail
When a user deposits or withdraws from the vault, the exchange rate of the token is calculated between the token itself and its dToken. As specified in an inline comment, the exchange rate is calculated like so:

```solidity
// exchangeRate = (cash + totalBorrows -reserves) / dTokenSupply
```

where `reserves = info.totalReserves - info.withdrawnReserves`. When the owner of the vault calls `withdrawReserves` the withdrawnReserves value increases, so the numerator of the above formula increases, and thus the exchange rate increases. An increase in exchange rate means that the same number of dTokens is now worth more of the underlying ERC20.

Below is a diff to the existing test suite that demonstrates the sandwich attack in action:

```diff
diff --git a/new-dodo-v3/test/DODOV3MM/D3Vault/D3Vault.t.sol b/new-dodo-v3/test/DODOV3MM/D3Vault/D3Vault.t.sol
index a699162..337d1f5 100644
--- a/new-dodo-v3/test/DODOV3MM/D3Vault/D3Vault.t.sol
+++ b/new-dodo-v3/test/DODOV3MM/D3Va

*[Content truncated...]*

---

### Example 10: deposit and withdraw functions are susceptible to sandwich attacks

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Vulnerability Report

**Severity:** High Risk  
**Context:** AeraVaultV1.sol#L402-L453, AeraVaultV1.sol#L456-L514  
**Description:** Transactions calling the `deposit()` function are susceptible to sandwich attacks where an attacker can extract value from deposits. A similar issue exists in the `withdraw()` function but the minimum check on the pool holdings limits the attacks impact.

## Scenario Example
(Assuming swap fees are ignored for simplicity):

1. Suppose the Balancer pool contains two tokens, WETH and DAI, with weights of 0.5 each. Currently, there is 1 WETH and 3k DAI in the pool, and the WETH spot price is 3k.
2. The Treasury wants to add another 3k DAI into the Aera vault, so it calls the `deposit()` function.
3. The attacker front-runs the Treasurys transaction. They swap 3k DAI into the Balancer pool and receive 0.5 WETH. The weights remain 0.5 and 0.5, but because WETH and DAI balances become 0.5 and 6k, WETHs spot price now becomes 12k.
4. At this point, the Treasurys transaction adds 3k DAI into the Balancer pool and changes the weights to 0.6 and 0.4.
5. The attacker back-runs the transaction and swaps the 0.5 WETH acquired in step 3 back to DAI, recovering WETHs spot price to slightly above 3k. According to the current weights, they can receive 9k * (1 - 1/r) = 3.33k DAI from the pool, where r = (2^0.4)^(1/0.6).
6. As a result, the attacker profits 3.33k - 3k = 0.33k DAI.

## Recommendations
Potential mitigations include:

- Adopting a t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 11: H-1: Adversary can sandwich oracle updates to exploit vault

**Source**: Sherlock
**Protocol**: Olympus Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-03-olympus-judging/issues/1 

## Found by 
0x52

## Summary

BLVaultLido added a mechanism to siphon off all wstETH obtained from mismatched pool and oracle prices. This was implemented to fix the problem that the vault could be manipulated to the attackers gain. This mitigation however does not fully address the issue and the same issue is still exploitable by sandwiching oracle update.

## Vulnerability Detail

[BLVaultLido.sol#L232-L240](https://github.com/sherlock-audit/2023-03-olympus/blob/main/sherlock-olympus/src/policies/BoostedLiquidity/BLVaultLido.sol#L232-L240)

        uint256 wstethOhmPrice = manager.getTknOhmPrice();
        uint256 expectedWstethAmountOut = (ohmAmountOut * wstethOhmPrice) / _OHM_DECIMALS;

        // Take any arbs relative to the oracle price for the Treasury and return the rest to the owner
        uint256 wstethToReturn = wstethAmountOut > expectedWstethAmountOut
            ? expectedWstethAmountOut
            : wstethAmountOut;
        if (wstethAmountOut > wstethToReturn)
            wsteth.safeTransfer(TRSRY(), wstethAmountOut - wstethToReturn);

In the above lines we can see that the current oracle price is used to calculate the expected amount of wstETH to return to the user. In theory this should prevent the attack but an attacker can side step this sandwiching the oracle update.

Example:

The POC is very similar to before except now it's composed of two transactions sandwiching the orac

*[Content truncated...]*

---

### Example 12: [M-04] Sandwich attack for `turnEmpirePointPriceDown()`

**Source**: Pashov Audit Group
**Protocol**: Primodium_2024-10-02
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

Admins call `turnEmpirePointPriceDown()` and reduce the price of an empire's points:

```solidity
  function turnEmpirePointPriceDown(EEmpire _empire) internal {
    P_PointConfigData memory config = P_PointConfig.get();
    uint256 newPointPrice = Empire.getPointPrice(_empire);
    if (newPointPrice >= config.minPointPrice + config.pointGenRate) {
      newPointPrice -= config.pointGenRate;
    } else {
      newPointPrice = config.minPointPrice;
    }
    Empire.setPointPrice(_empire, newPointPrice);
    HistoricalPointPrice.set(_empire, block.timestamp, newPointPrice);
  }
```

The issue is that the code subtracts an absolute value from the empire's point's price. So if the price of the points was lower then the percentage price decrease would be higher and users can use this to profit from price decrease by sandwich attacks. Users can't buy points directly and they need to buy override but the result is the same. Users can time their override buys with the admin's transaction and perform the sandwich attack to benefit from the admin's transactions.
This is the POC: (buying points means buying some override which results in buying points)

1. Suppose an empire's point's price is 100.
2. User1 has 50 points in that empire and if he buys one more token it would cost 100.
3. Admins call `turnEmpirePointPriceDown()` to reduce the price by 10 units.
4. User1 would perform a sandwich attack for the admin's 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Primodium-security-review_2024-10-02.md)

---

### Example 13: [M-02] Exploiter can avoid negative Lido rebases stealing funds from EUSD vaults

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

Lybra keeps the exact amount of collateral as deposited ignoring any lido rebases.

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L79><br>
<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L103>

That allows malicious users to sandwich negative rebase transactions with depositing and withdrawing their stETH saving the exact amount as before negative rebase. The user can wait for 3 days or have a fee discount using `rigidRedemption` of self, which it makes applicable to a fee `(safeCollateralRatio - 100) / safeCollateralRatio * redemptionFee` part of the deposit.

### Impact

The protocol will have additional losses in that case because the negative rebase decreases the cost of stETH share and the protocol withdraws the same amount of stETH as deposited to the malicious user, transferring more shares than deposited.

### Proof of Concept

Should be launched with mainnet fork:

<details>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {LybraProxy} from "@lybra/Proxy/LybraProxy.sol";
import {LybraProxyAdmin} from "@lybra/Proxy/LybraProxyAdmin.sol";
// import {AdminTimelock} from "@lybra/governance/AdminTimelock.sol";
import {GovernanceTimelock} from "@lybra/governance/GovernanceTimelock.sol";
// import {LybraWBETHVault} from "@lybra/pools/LybraWb

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 14: [H-12] feePool is vulnerable to sandwich attack.

**Source**: Code4rena
**Protocol**: Mochi
**Impact**: HIGH

**Details**:

## Handle

jonah1005


## Vulnerability details

## Impact
There's a permissionless function `distributeMochi` in FeePoolV0. Since everyone can trigger this function, an attacker can launch a sandwich attack with flashloan to steal the funds.
[FeePoolV0.sol#L55-L62](https://github.com/code-423n4/2021-10-mochi/blob/main/projects/mochi-core/contracts/feePool/FeePoolV0.sol#L55-L62)
The devs have mentioned this concern in the comment. An attacker can steal the funds with a flash loan attack. 

Attackers can steal all the funds in the pool. I consider this is a high-risk issue. 

## Proof of Concept
[FeePoolV0.sol#L55-L62](https://github.com/code-423n4/2021-10-mochi/blob/main/projects/mochi-core/contracts/feePool/FeePoolV0.sol#L55-L62)

Please refer to [yDai Incident](https://peckshield.medium.com/the-ydai-incident-analysis-forced-investment-2b8ac6058eb5) to check the severity of a `harvest` function without slippage control.

Please refer to [Mushrooms-finance-theft]( https://medium.com/immunefi/mushrooms-finance-theft-of-yield-bug-fix-postmortem-16bd6961388f) to check how likely this kind of attack might happen.

## Tools Used

None

## Recommended Mitigation Steps
If the dev wants to make this a permissionless control, the contract should calculate a min return based on TWAP and check the slippage.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-mochi)

---

### Example 15: M-5: Dilution of Donations in Tranche

**Source**: Sherlock
**Protocol**: Arcadia
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-12-arcadia-judging/issues/121 

The protocol has acknowledged this issue.

## Found by 
Atharv, erosjohn, pash0k
## Summary
In this attack, the attacker takes advantage of the non-atomic nature of the donation and the share valuation process. By strategically placing deposit and withdrawal transactions around the donation transaction, the attacker can temporarily inflate their share of the pool to capture a large portion of the donated funds, which they then quickly exit with, leaving the pool with their original investment plus extra value extracted from the donation.

## Vulnerability Detail
Though there is no reasonable flow where users will just 'donate' assets to others, Risk Manager may needs to call `donateToTranche` to compensate the jrTranche after an auction didn't get sold and was manually liquidated after cutoff time or in case of bad debt. 

`donateToTranche` function of a lending pool smart contract, allows for a sandwich attack that can be exploited by a malicious actor to dilute the impact of donations made to a specific tranche. This attack involves front-running a detected donation transaction with a large deposit and following it up with an immediate withdrawal after the donation is processed.

The lending pool contract in question allows liquidity providers (LPs) to deposit funds into tranches, which represent slices of the pool's capital with varying risk profiles. The `donateToTranche` function permits exter

*[Content truncated...]*

---

### Example 16: H-5: ConvexSpell#closePositionFarm removes liquidity without any slippage protection

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

### Example 17: [M-09] Vulnerability to MEV sandwich attacks in point purchase and sale system

**Source**: Pashov Audit Group
**Protocol**: Primodium_2024-10-02
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

The current design of the point system, where the price of points increases with each purchase and decreases with each sale, makes it vulnerable to MEV (Maximal Extractable Value) sandwich attacks. MEV bots can monitor the mempool and front-run legitimate buyers or sellers.

- **Front-running a buyer:** MEV bots can detect a point purchase in the mempool, purchase points ahead of the legitimate buyer, causing the price to increase. As a result, the legitimate buyer is forced to pay a higher price for their purchase and the bot can then sell at a higher price.
- **Front-running a seller:** MEV bots can detect a point sale in the mempool, and sell their points ahead of the legitimate seller at a higher price, causing the price to decrease. This would lead to the legitimate seller receiving a lower sale value for their points. The bot can then buy back at a reduced price, extracting value at the expense of the legitimate seller.

This dynamic can severely affect user experience by increasing costs for buyers and decreasing returns for sellers. It poses a significant risk, especially in high-value transactions.

## Recommendations

To mitigate the risk of MEV sandwich attacks, it is recommended that slippage protection mechanisms be introduced in both purchase and sale functions. This would allow users to specify the minimum or maximum acceptable price when buying or selling points, protecting them from sign

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Primodium-security-review_2024-10-02.md)

---

### Example 18: [M-01] Guaranteed citadel profit

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: MEDIUM

**Details**:

_Submitted by georgypetrov_

User can sandwich `mintAndDistribute` function if mintable is high enough

*   Deposit before
*   Withdraw after
*   Take after 21 days citadels

### Proof of Concept

`mintAndDistribute` increase a price of staking share, that allows to withdraw more than deposited.
user takes part of distributed citadels, so different users have smaller profit from distribution

### Recommended Mitigation Steps

Call `mintAndDistribute` through flashbots

**[GalloDaSballo (BadgerDAO) confirmed, disagreed with severity and commented](https://github.com/code-423n4/2022-04-badger-citadel-findings/issues/71#issuecomment-1107167747):**
 > My interpretation of the finding is that there's no linear vesting in the way more rewards are distributed so they can be frontrun.
> 
> I have to disagree in that taking 21 days of exposure to a random token in order to gain a small sub 1% gain is probably not what I'd call a smart move.
> 
> That said, I believe the front-running finding to be valid, and while I disagree with High I believe the finding to have validity

**[jack-the-pug (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2022-04-badger-citadel-findings/issues/71#issuecomment-1140386812):**
 > Downgrading to `Medium` as this attack vector is not economically profitable in practice (because of the 21 days vesting).



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-badger-citadel)

---

## Statistics

- Total findings analyzed: 19
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## front-running-patterns.md
# Front-Running Security Patterns

## Overview

**Frequency**: 106 occurrences (0.21% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 39 | 67 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, MixBytes, Trust Security

---

## Detection Checklist

- [ ] Check for front-running vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Lack of transferId Verification Allows an Attacker to Front-Run Bridge Transfers

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: Critical Risk  

## Context  
- `NomadFacet.sol#L99-L149`  
- `BridgeRouter.sol#L176-L199`  
- `BridgeRouter.sol#L347-L381`  

## Description  
The `onReceive()` function does not verify the integrity of `transferId` against all other parameters. Although the `onlyBridgeRouter` modifier checks that the call originates from another BridgeRouter (assuming a correct configuration of the whitelist) to the `onReceive()` function, it does not check that the call originates from another Connext Diamond.

This allows anyone to send arbitrary data to `BridgeRouter.sendToHook()`, which is later interpreted as the `transferId` on Connexts `NomadFacet.sol` contract. This can be abused by a front-running attack as described in the following scenario:

- **Alice** is a bridge user and makes an honest call to transfer funds over to the destination chain.  
- **Bob** does not make a transfer but instead calls the `sendToHook()` function with the same `_extraData` but passes an `_amount` of `1 wei`.  
- Both Alice and Bob have their tokens debited on the source chain and must wait for the Nomad protocol to optimistically verify incoming `TransferToHook` messages.  
- Once the messages have been replicated onto the destination chain, Bob processes the message before Alice, causing `onReceive()` to be called on the same `transferId`.  
- However, because `_amount` is not verified against the `transferId`, Alice receives significantly fewer tokens, and the `s.reconciledTransfers` m

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] Attacker can frontrun a victim's `mint`+`add` transaction to steal NFT

**Source**: Code4rena
**Protocol**: Canto Identity Protocol
**Impact**: HIGH

**Details**:

[CidNFT.sol#L147](https://github.com/code-423n4/2023-01-canto-identity/blob/main/src/CidNFT.sol#L147)<br>
[CidNFT.sol#L165](https://github.com/code-423n4/2023-01-canto-identity/blob/main/src/CidNFT.sol#L165)<br>
[CidNFT.sol#L237](https://github.com/code-423n4/2023-01-canto-identity/blob/main/src/CidNFT.sol#L237)

High - an attacker can steal deposited NFTs from victims using the `mint()` + `add()` functionality in `CidNFT.sol`

### Proof of Concept

One of the core features of CID Protocol is the ability for users to attach Subprotocol NFTs to their `CidNFT`. The `CidNFT` contract custodies these attached NFTs, and they are regarded as "traits" of the user.

The protocol currently includes functionality for a user to mint a `CidNFT` as their identity and then optionally add a subprotocol NFT to that `CidNFT` in the same transaction. This occurs in the `mint()` function of `CidNFT.sol`, which takes a byte array of `add()` parameters and includes a loop where `add()` can be repeatedly called with these parameters to attach subprotocol NFTs to the `CidNFT`.

```

function mint(bytes[] calldata _addList) external {
    _mint(msg.sender, ++numMinted); 
    bytes4 addSelector = this.add.selector;
    for (uint256 i = 0; i < _addList.length; ++i) {
        (bool success /*bytes memory result*/, ) = address(this)
            .delegatecall(abi.encodePacked(addSelector, _addList[i]));
        if (!success) revert AddCallAfterMintingFailed(i);
    }
}
```

One of the arguments for `add(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-canto-identity)

---

### Example 3: [H-09] BathPair.sol#rebalancePair() can be front run to steal the pending rebalancing amount

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L756-L759


## Vulnerability details

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L756-L759

```solidity
function underlyingBalance() public view returns (uint256) {
    uint256 _pool = IERC20(underlyingToken).balanceOf(address(this));
    return _pool.add(outstandingAmount);
}
```

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L294-L303

```solidity
function removeFilledTradeAmount(uint256 amt) external onlyPair {
    outstandingAmount = outstandingAmount.sub(amt);
    emit LogRemoveFilledTradeAmount(
        IERC20(underlyingToken),
        amt,
        underlyingBalance(),
        outstandingAmount,
        totalSupply
    );
}
```

For `BathToken`, there will be non-underlyingToken assets sitting on the contract that have filled to the contract and are awaiting rebalancing by strategists.

We assume the rebalance will happen periodically, between one rebalance to the next rebalance, `underlyingBalance()` will decrease over time as the orders get filled, so that the price per share will get lower while the actual equity remain relatively stable. This kind of price deviation will later be corrected by rebalancing.

Every time a `BathPair.sol#rebalancePair()` get ca

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 4: [H-06] Gas price spikes cause the selected operator to be vulnerable to frontrunning and be slashed

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L354](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L354)<br>

```solidity
require(gasPrice >= tx.gasprice, "HOLOGRAPH: gas spike detected");
```

```solidity
        /**
         * @dev select operator that failed to do the job, is slashed the pod base fee
         */
        _bondedAmounts[job.operator] -= amount;
        /**
         * @dev the slashed amount is sent to current operator
         */
        _bondedAmounts[msg.sender] += amount;
```

Since you have designed a mechanism to prevent other operators to slash the operator due to "the selected missed the time slot due to a gas spike". It can induce that operators won't perform their job if a gas price spike happens due to negative profit.

But your designed mechanism has a vulnerability. Other operators can submit their transaction to the mempool and queue it using `gasPrice in bridgeInRequestPayload`. It may get executed before the selected operator as the selected operator is waiting for the gas price to drop but doesn't submit any transaction yet. If it doesn't, these operators lose a little gas fee. But a slashed reward may be greater than the risk of losing a little gas fee.

```solidity
require(timeDifference > 0, "HOLOGRAPH: operator has time");
```

Once 1 epoch has passed, selected operator is vulnerable to slashing and frontrunning.

### Recommended Mitigation Steps

Modify your operator node software t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 5: [H-03] `fillOrder` executor can be front-run by the order creator by changing order's `limitPrice_e36`, the executor's assets can be stolen

**Source**: Code4rena
**Protocol**: Init Capital
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L539-L563> 

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L387>

`limitPrice_e36` acts as slippage protection for the order creator, depending on the trade/order position (whether long or short). A higher or lower limit price impacts the `tokenOut` amount that needs to be transferred to the order's creator. However, when the executor executes `fillOrder`, it can be front-run by the order creator to update `limitPrice_e36` and steal tokens from the executor.

### Proof of Concept

When `fillOrder` is executed, it will calculate the `amtOut` that needs to be transferred to `order.recipient` by calling `_calculateFillOrderInfo`.

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L532-L564>

```solidity
    function _calculateFillOrderInfo(Order memory _order, MarginPos memory _marginPos, address _collToken)
        internal
        returns (uint amtOut, uint repayShares, uint repayAmt)
    {
        (repayShares, repayAmt) = _calculateRepaySize(_order, _marginPos);
        uint collTokenAmt = ILendingPool(_marginPos.collPool).toAmtCurrent(_order.collAmt);
        // NOTE: all roundings favor the order owner (amtOut)
        if (_collToken == _order.tokenOut) {
            if (_marginPos.isLongBaseAsset) {
                // long eth hold eth


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-init-capital-invitational)

---

### Example 6: [H-04] Initial pool deposit can be stolen

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug_

Note that the `PoolTemplate.initialize` function, called when creating a market with `Factory.createMarket`, calls a vault function to transfer an initial deposit amount (`conditions[1]`) *from* the initial depositor (`_references[4]`):

```solidity
// PoolTemplate
function initialize(
     string calldata _metaData,
     uint256[] calldata _conditions,
     address[] calldata _references
) external override {
     // ...

     if (_conditions[1] > 0) {
          // @audit vault calls asset.transferFrom(_references[4], vault, _conditions[1])
          _depositFrom(_conditions[1], _references[4]);
     }
}

function _depositFrom(uint256 _amount, address _from)
     internal
     returns (uint256 _mintAmount)
{
     require(
          marketStatus == MarketStatus.Trading && paused == false,
          "ERROR: DEPOSIT_DISABLED"
     );
     require(_amount > 0, "ERROR: DEPOSIT_ZERO");

     _mintAmount = worth(_amount);
     // @audit vault calls asset.transferFrom(_from, vault, _amount)
     vault.addValue(_amount, _from, address(this));

     emit Deposit(_from, _amount, _mintAmount);

     //mint iToken
     _mint(_from, _mintAmount);
}
```

The initial depositor needs to first approve the vault contract for the `transferFrom` to succeed.

An attacker can then frontrun the `Factory.createMarket` transaction with their own market creation (it does not have access restrictions) and create a market *with different parameters* but st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

### Example 7: Owner of a bad ShortRecord can front-run flagShort calls AND liquidateSecondary and prevent liquidation

**Source**: Codehawks
**Protocol**: DittoETH
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47">https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/facets/ERC721Facet.sol#L162C17-L162C17">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/facets/ERC721Facet.sol#L162C17-L162C17</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L132">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L132</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L224C10-L224C10">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortR

*[Content truncated...]*

---

### Example 8: H-3: CryptoPunks NFTs may be stolen via deposit frontrunning

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/140 

## Found by 
Jeiwan

## Summary
Depositing of CryptoPunks NFTs may be front run, a malicious actor may deposit someone else's CryptoPunks NFT.
## Vulnerability Detail
Due to the CryptoPunks NFT collection not implementing the ERC721 standard, depositing of CryptoPunks NFTs is implemented via a direct sale:
1. token owner needs to call [offerPunkForSaleToAddress](https://etherscan.io/address/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb#code) and set the `toAddress` value to the address of the pool the token will be deposited to;
1. token owner then calls the [addCollateral](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L251) function of the ERC721 pool;
1. the pool [buys the token](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577) from its owner.

However, `addCollateral` can be called by anyone: the pool will buy the token and will deposit it on the caller's account even if the caller is not the owner of the token.
## Impact
CryptoPunks NFTs owner may lose their NFTs when trying to deposit them to an ERC721 pool. A malicious actor may front run the depositing and deposit the NFTs to their account. The malicious actor may then withdraw the NFTs.
## Code Snippet
[ERC721Pool.sol#L577](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577)
[CryptoPunksMarket](https://etherscan.io/address/0x

*[Content truncated...]*

---

### Example 9: H-1: If a user approves junior vault tokens to WithdrawPeriphery, anyone can withdraw/redeem his/her token

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/79 

## Found by 
simon135, cccz, Nyx, GimelSec, clems4ever

## Summary

If users want to withdraw/redeem tokens by WithdrawPeriphery, they should approve token approval to WithdrawPeriphery, then call `withdrawToken()` or `redeemToken()`.
But if users approve `dnGmxJuniorVault` to WithdrawPeriphery, anyone can withdraw/redeem his/her token.

## Vulnerability Detail

Users should approve `dnGmxJuniorVault` before calling `withdrawToken()` or `redeemToken()`:

```solidity
    function withdrawToken(
        address from,
        address token,
        address receiver,
        uint256 sGlpAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.withdraw(sGlpAmount, address(this), from);
...

    function redeemToken(
        address from,
        address token,
        address receiver,
        uint256 sharesAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.redeem(sharesAmount, address(this), from);
...
```

For better user experience, we always use `approve(WithdrawPeriphery, type(uint256).max)`. It means that if Alice approves the max amount, anyone can withdraw/redeem her tokens anytime.
Another scenario is that if Alice approves 30 amounts, she wants to call `withdrawToken` to withdraw 30 tokens. But in this case Alice sho

*[Content truncated...]*

---

### Example 10: H-2: Attacker will prevent any raffles by calling `WinnablesTicketManager::cancelRaffle` before admin starts raffle

**Source**: Sherlock
**Protocol**: Winnables Raffles
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-08-winnables-raffles-judging/issues/57 

## Found by 
0rpse, 0x0bserver, 0x73696d616f, 0xAadi, 0xShahilHussain, 0xarno, 0xbrivan, AllTooWell, BitcoinEason, Bluedragon, CatchEmAll, KaligoAudits, Oblivionis, Offensive021, PNS, PTolev, Paradox, S3v3ru5, Silvermist, TessKimy, Trident-Audits, ZC002, aman, araj, charles\_\_cheerful, denzi\_, dimi6oni, dimulski, dinkras\_, dobrevaleri, durov, eeshenggoh, frndz0ne, iamnmt, jennifer37, neko\_nyaa, ogKapten, p0wd3r, philmnds, phoenixv110, rsam\_eth, sakshamguruji, shaflow01, shikhar, shui, tjonair, utsav, vinica\_boy, y4y
### Summary

The [`WinnablesTicketManager::cancelRaffle`](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L278) function is vulnerable to abuse because it is an external function that allows anyone to cancel a raffle if its status is set to PRIZE_LOCKED. An attacker could exploit this by repeatedly calling `cancelRaffle` whenever a new raffle is available to be started, effectively preventing any raffles from ever being initiated.

### Root Cause

The root cause of this issue lies in the design of the function:
1. The function is external, meaning it can be called by anyone.
2. When called, it checks the underlying function `WinnablesTicketManager::_checkShouldCancel`, which allows cancellation of a raffle if the [status is PRIZE_LOCKED](https://github.com/sherlock-audit/2024-08-winnables-raffles/

*[Content truncated...]*

---

### Example 11: DoS of an account using frontrun

**Source**: MixBytes
**Protocol**: Kinto
**Impact**: HIGH

**Details**:

##### Description

- https://github.com/KintoXYZ/kinto-core/blob/f7dd98f66b9dfba1f73758703b808051196e740b/src/wallet/KintoWalletFactory.sol#L130

In `KintoWalletFactory`, a hacker can make a `deployContract` frontrun before calling `createAccount`. Thus, `deployContract` will create a valid `KintoWallet` without configuring the `walletTs` value.

The following is an example:
```solidity
vm.prank(_hackerWithKYC);
bytes memory a = abi.encodeWithSelector(
    KintoWallet.initialize.selector,
    _owner,
    _owner
);                   
_walletFactory.deployContract(
    0,
    abi.encodePacked(
        type(SafeBeaconProxy).creationCode,
        abi.encode(address(_beacon), a)
    ),
    bytes32(someSalt)
);
vm.startPrank(_owner);

// create2 will not be called
_kintoWalletv1 = 
    _walletFactory.createAccount(
        _owner, _owner, someSalt);

// _walletFactory.getWalletTimestamp(
// address(_kintoWalletv1)
// ) == 0
```

If the user sends tokens to it by mistake, they will be permanently blocked.

Such a contract cannot be recovered in any way, and also the `Recovery` mechanism will not work, since there is no way to call `KintoWallet` via `EntryPoint` on any `owners`.

##### Recommendation
We recommend not allowing `KintoWallet` accounts to be created via the `deployContract` method. A single fake-KYC or leaked account can create potential problems for all members of the Kinto network.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Kinto/README.md#3-dos-of-an-account-using-frontrun)

---

### Example 12: [H-02] Order's creator can update `tokenOut` to arbitrary token

**Source**: Code4rena
**Protocol**: Init Capital
**Impact**: HIGH

**Details**:

When an order is created, it checks whether the `order.tokenOut` is equal to `marginPos.baseAsset` or `_tokenOut` is equal to `marginPos.quoteAsset`. However, when `tokenOut` is updated via `updateOrder`, it can be changed to an arbitrary token. This has the potential to be exploited by changing `tokenOut` to a high-value token right before the executor executes the `fillOrder`.

### Proof of Concept

It can be observed that order's creator can update `order.tokenOut` to arbitrary token.

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L504-L526>

```solidity
    function updateOrder(
        uint _posId,
        uint _orderId,
        uint _triggerPrice_e36,
        address _tokenOut,
        uint _limitPrice_e36,
        uint _collAmt
    ) external {
        _require(_collAmt != 0, Errors.ZERO_VALUE);
        Order storage order = __orders[_orderId];
        _require(order.status == OrderStatus.Active, Errors.INVALID_INPUT);
        uint initPosId = initPosIds[msg.sender][_posId];
        _require(initPosId != 0, Errors.POSITION_NOT_FOUND);
        MarginPos memory marginPos = __marginPositions[initPosId];
        uint collAmt = IPosManager(POS_MANAGER).getCollAmt(initPosId, marginPos.collPool);
        _require(_collAmt <= collAmt, Errors.INPUT_TOO_HIGH);

        order.triggerPrice_e36 = _triggerPrice_e36;
        order.limitPrice_e36 = _limitPrice_e36;
        order.collAmt = _collAmt;
        order.tokenOu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-init-capital-invitational)

---

### Example 13: [H-02] The first disputer might lose funds although his dispute is valid

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: HIGH

**Details**:

Users can dispute the current tree using `disputeTree()` and the governor refunds the dispute funds if the dispute is valid in `resolveDispute()`.

```solidity
    function disputeTree(string memory reason) external {
        if (block.timestamp >= endOfDisputePeriod) revert InvalidDispute();
        IERC20(disputeToken).safeTransferFrom(msg.sender, address(this), disputeAmount);
        disputer = msg.sender;
        emit Disputed(reason);
    }

    /// @notice Resolve the ongoing dispute, if any
    /// @param valid Whether the dispute was valid
    function resolveDispute(bool valid) external onlyGovernorOrGuardian {
        if (disputer == address(0)) revert NoDispute();
        if (valid) {
            IERC20(disputeToken).safeTransfer(disputer, disputeAmount);
            // If a dispute is valid, the contract falls back to the last tree that was updated
            _revokeTree();
        } else {
            IERC20(disputeToken).safeTransfer(msg.sender, disputeAmount);
            endOfDisputePeriod = _endOfDisputePeriod(uint48(block.timestamp));
        }
        disputer = address(0);
        emit DisputeResolved(valid);
    }
```

But `disputeTree()` can be called again by another disputer although there is an active disputer and `resolveDispute()` refunds to the last disputer only.

In the worst case, a valid disputer might lose the dispute funds by malicious frontrunners.

1.  A valid disputer creates a dispute using `disputeTree()`.
2.  As it's valid, the govern

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 14: TRST-H-4 First depositor can steal asset tokens of others

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
The first depositor can be front run by an attacker and as a result will lose a considerable 
part of the assets provided.
When the pool has no share supply, in `_mintInternal()`, the amount of shares to be minted is 
equal to the assets provided. An attacker can abuse of this situation and profit of the 
rounding down operation when calculating the amount of shares if the supply is non-zero. 
```solidity
        function _mintInternal(address _receiver, uint _balanceIncreased, uint _totalAsset
             ) internal returns (uint mintShares) {
                unfreezeTime[_receiver] = block.timestamp + mintFreezeInterval;
        if (freezeBuckets.interval > 0) {
             FreezeBuckets.addToFreezeBuckets(freezeBuckets, _balanceIncreased.toUint96());
        }
                 uint _totalSupply = totalSupply();
                    if (_totalAsset == 0 || _totalSupply == 0) {
                     mintShares = _balanceIncreased + _totalAsset;
                 } else {
             mintShares = (_balanceIncreased * _totalSupply) / _totalAsset;
             }
            if (mintShares == 0) {
        revert ZeroAmount();
        }
        _mint(_receiver, mintShares);
        }
``` 
Consider the following scenario.
1. Alice wants to deposit 2M * 1e6 USDC to a pool.
2. Bob observes Alice's transaction, frontruns to deposit 1 wei USDC to mint 1 wei share, and 
transfers 1 M * 1e6 USDC to the pool.
3. Alice's transaction is executed, since **_totalAsset = 1M *

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 15: TRST-H-3 The liquidated person can make the liquidator lose premium by adding collateral in advance

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
When the position with **debtRatioE18 >= 1e18** or **startLiqTimestamp ! = 0**, the position can 
be liquidated. On liquidation, the liquidator needs to pay premium, but the profit is related 
to the position's health factor and **deltaTime**, and when **discount == 0**, the liquidator loses 
premium.
```solidity
            uint deltaTime;
            // 1.1 check the amount of time since position is marked
            if (pos.startLiqTimestamp > 0) {
                 deltaTime = Math.max(deltaTime, block.timestamp - pos.startLiqTimestamp);
            }
            // 1.2 check the amount of time since position is past the deadline
             if (block.timestamp > pos.positionDeadline) {
                    deltaTime = Math.max(deltaTime, block.timestamp - pos.positionDeadline);
            }
            // 1.3 cap time-based discount, as configured
              uint timeDiscountMultiplierE18 = Math.max(
                IConfig(config).minLiquidateTimeDiscountMultiplierE18(),
                     ONE_E18 - deltaTime * IConfig(config).liquidateTimeDiscountGrowthRateE18()
            );
            // 2. calculate health-based discount factor
            uint curHealthFactorE18 = (ONE_E18 * ONE_E18) /
             getPositionDebtRatioE18(_positionManager, _user, _posId);
                 uint minDesiredHealthFactorE18 = IConfig(config).minDesiredHealthFactorE18s(strategy);
            // 2.1 interpolate linear health discount factor (according to the diagr

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 16: [H-01] Challenges can be frontrun with de-leveraging to cause lossses for challengers

**Source**: Code4rena
**Protocol**: Frankencoin
**Impact**: HIGH

**Details**:

Challenges, once created, cannot be closed. Thus once a challenge is created, the challenger has already transferred in a collateral amount and is thus open for losing their collateral to a bidding war which will most likely close below market price, since otherwise buying from the market would be cheaper for bidders.

Position owners can take advantage of this fact and frontrun a `launchChallenge` transaction with an `adjustPrice` transaction. The `adjustPrice` function lets the user lower the price of the position, and can pass the collateral check by sending collateral tokens externally.

As a worst case scenario, consider a case where a position is open with 1 ETH collateral and 1500 ZCHF minted. A challenger challenges the position and the owner frontruns the challenger by sending the contract 1500 ZCHF and calling `repay()` and then calling `adjustPrice` with value 0, all in one transaction with a contract. Now, the price in the contract is set to 0, and the collateral check passes since the outstanding minted amount is 0. The challenger's transaction gets included next, and they are now bidding away their collateral, since any amount of bid will pass the avert collateral check.

The position owner themselves can backrun the same transaction with a bid of 1 wei and take all the challenger's collateral, since every bid checks for the `tryAvertChallenge` condition.

```solidity
if (_bidAmountZCHF * ONE_DEC18 >= price * _collateralAmount)
```

Since price is set to 0, any 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-frankencoin)

---

### Example 17: [H-01] Anyone can frontrun fixed price signature mints to waste claim ticket

**Source**: ZachObront
**Protocol**: Sound.Xyz
**Impact**: HIGH

**Details**:

When NFTs are minted using the `FixedPriceSignatureMinterV2.sol` contract, the user is able to input any quantity to mint. As long as this amount is less than the quantity that has been signed for, the transaction will succeed and the claim ticket will be used up.

The signed ticket includes the following details:

- Buyer
- Mint ID
- Claim Ticket
- Signed Quantity
- Affiliate

When `mintTo()` is called, these values are all filled in entirely from the arguments passed to the function, as we can see here:

```solidity
bytes32 digest = keccak256(
abi.encodePacked(
"\x19\x01",
DOMAIN_SEPARATOR(),
keccak256(abi.encode(MINT_TYPEHASH, to, mintId, claimTicket, signedQuantity, affiliate))
)
);
```

This leaves us with two facts:

1. The signature used by Alice to claim her NFTs could equally have been used by Bob to send NFTs to Alice, because there is no reference to who the `msg.sender` is when checking the signature.

2. The signature used to claim `signedQuantity` NFTs could also have been used to claim any amount `x` (where 0 < `x` <= `signedQuantity`), because there is no reference to the quantity claimed in the signature.

As a result, any user who is claiming a large number of NFTs is vulnerable to being frontrun. Bob can watch the mempool for Alice's transaction, copy the signature, and replay his own version of the transaction, sending just 1 NFT to Alice instead of the full `signedQuantity`.

Once this action has been taken, Alice's ticket will be claimed, and she will be

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-04-12-Sound.xyz.md)

---

### Example 18: [H-10] First vault depositor can steal other's assets

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

### Example 19: Initialization functions can be front-run

**Source**: TrailOfBits
**Protocol**: Advanced Blockchain
**Impact**: HIGH

**Details**:

## Type: Timing

## Difficulty: Medium

### Target: Throughout the contracts

### Description
The `CrosslayerPortal` contracts have initializer functions that can be front-run, allowing an attacker to incorrectly initialize the contracts. Due to the use of the `delegatecall` proxy pattern, these contracts cannot be initialized with their own constructors, and they have initializer functions:

```solidity
function initialize() public initializer {
    __Ownable_init();
    __Pausable_init();
    __ReentrancyGuard_init();
}
```

*Figure 1.1: The `initialize` function in `MsgSender:126-130`*

An attacker could front-run these functions and initialize the contracts with malicious values. This issue affects the following system contracts:

- `contracts/core/BridgeAggregator`
- `contracts/core/InvestmentStrategyBase`
- `contracts/core/MosaicHolding`
- `contracts/core/MosaicVault`
- `contracts/core/MosaicVaultConfig`
- `contracts/core/functionCalls/MsgReceiverFactory`
- `contracts/core/functionCalls/MsgSender`
- `contracts/nfts/Summoner`
- `contracts/protocols/aave/AaveInvestmentStrategy`
- `contracts/protocols/balancer/BalancerV1Wrapper`
- `contracts/protocols/balancer/BalancerVaultV2Wrapper`
- `contracts/protocols/bancor/BancorWrapper`
- `contracts/protocols/compound/CompoundInvestmentStrategy`
- `contracts/protocols/curve/CurveWrapper`
- `contracts/protocols/gmx/GmxWrapper`
- `contracts/protocols/sushiswap/SushiswapLiquidityProvider`
- `contracts/protocols/synapse/ISynapseSwap`
-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/AdvancedBlockchain.pdf)

---

### Example 20: Winning pods can be frontrun with large deposits

**Source**: ConsenSys
**Protocol**: PoolTogether - Pods
**Impact**: HIGH

**Details**:

#### Description


`Pod.depositTo()` grants users shares of the pod pool in exchange for `tokenAmount` of `token`.


**code/pods-v3-contracts/contracts/Pod.sol:L266-L288**



```
function depositTo(address to, uint256 tokenAmount)
    external
    override
    returns (uint256)
{
    require(tokenAmount > 0, "Pod:invalid-amount");

    // Allocate Shares from Deposit To Amount
    uint256 shares = \_deposit(to, tokenAmount);

    // Transfer Token Transfer Message Sender
    IERC20Upgradeable(token).transferFrom(
        msg.sender,
        address(this),
        tokenAmount
    );

    // Emit Deposited
    emit Deposited(to, tokenAmount, shares);

    // Return Shares Minted
    return shares;
}

```
The winner of a prize pool is typically determined by an off-chain random number generator, which requires a request to first be made on-chain. The result of this RNG request can be seen in the mempool and frontrun. In this case, an attacker could identify a winning `Pod` contract and make a large deposit, diluting existing user shares and claiming the entire prize.


#### Recommendation


The modifier `pauseDepositsDuringAwarding` is included in the `Pod` contract but is unused.


**code/pods-v3-contracts/contracts/Pod.sol:L142-L148**



```
modifier pauseDepositsDuringAwarding() {
    require(
        !IPrizeStrategyMinimal(\_prizePool.prizeStrategy()).isRngRequested(),
        "Cannot deposit while prize is being awarded"
    );
    \_;
}

```
Add this modifier to the `depos

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2021/03/pooltogether-pods/)

---

### Example 21: [M-05] BkdLocker#depositFees() can be front run to steal the newly added rewardToken

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/BkdLocker.sol#L90-L100


## Vulnerability details

Every time the `BkdLocker#depositFees()` gets called, there will be a surge of rewards per locked token for the existing stakeholders.

This enables a well-known attack vector, in which the attacker will take a large portion of the shares before the surge, then claim the rewards and exit immediately.

While the `_WITHDRAW_DELAY` can be set longer to mitigate this issue in the current implementation, it is possible for the admin to configure it to a very short period of time or even `0`.

In which case, the attack will be very practical and effectively steal the major part of the newly added rewards.

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/BkdLocker.sol#L90-L100

```solidity
function depositFees(uint256 amount) external override {
    require(amount > 0, Error.INVALID_AMOUNT);
    require(totalLockedBoosted > 0, Error.NOT_ENOUGH_FUNDS);
    IERC20(rewardToken).safeTransferFrom(msg.sender, address(this), amount);

    RewardTokenData storage curRewardTokenData = rewardTokenData[rewardToken];

    curRewardTokenData.feeIntegral += amount.scaledDiv(totalLockedBoosted);
    curRewardTokenData.feeBalance += amount;
    emit FeesDeposited(amount);
}
```

### PoC

Given:

- Current `totalLockedBoosted()` is `100,000 govToken`;
- Pending dis

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-backd)

---

### Example 22: Decrementing the quorum in Oracle in some scenarios can open up a frontrunning/backrunning opportunity for some oracle members

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- Oracle.1.sol#L338-L370
- Oracle.1.sol#L260
- Oracle.1.sol#L156 @ 030b52feb5af2dd2ad23da0d512c5b0e55eb8259

## Description
Assume there are 2 groups of oracle members A and B where they have voted for report variants \(V_a\) and \(V_b\) respectively. Let's also assume the count for these variants \(C_a\) and \(C_b\) are equal and are the highest variant vote counts among all possible variants. If the Oracle admin changes the quorum to a number less than or equal to \(C_a + 1 = C_b + 1\), any oracle member can backrun this transaction by the admin to decide which report variant \(V_a\) or \(V_b\) gets pushed to the River. This is because when a lower quorum is submitted by the admin and there exist two variants that have the highest number of votes, in the `_getQuorumReport` function the returned `isQuorum` parameter would be false since `repeat == 0` is false:

```solidity
return (maxval >= _quorum && repeat == 0, variants[maxind]);
```

Note that this issue also exists in the commit hash 030b52feb5af2dd2ad23da0d512c5b0e55eb8259 and can be triggered by the admin either by calling `setQuorum` or `addMember` when the abovementioned conditions are met. Also, note that the free oracle member agent can frontrun the admin transaction to decide the quorum earlier in the scenario above. Thus this way `_getQuorumReport` would actually return that it is a quorum.

## Recommendation
This issue is similar to "The reportBeacon is prone to front-runnin

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 23: [M-03] Grieving attack by failing users transactions

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L486


## Vulnerability details

## Impact

An attacker can apply grieving attack by preventing users from interacting with some of the protocol functions. In other words whenever a user is going to reduce his debt, or buy and reduce his debt in one tx, it can be failed by the attacker.

## Proof of Concept
In the following scenario, I am explaining how it is possible to fail user's transaction to reduce their debt fully. Failing other transaction (buy and reduce the debt in one tx) can be done similarly.

 - Suppose Alice (an honest user) has debt of 1000 `PaprToken` and she intends to repay her debt fully: 
 - So, she calls the function `reduceDebt` with the following parameters:
   - `account`: Alice's address
   - `asset`: The NFT which was used as collateral
   - `amount`: 1000 * 10**18 (decimal of `PaprToken` is 18).
```
function reduceDebt(address account, ERC721 asset, uint256 amount) external override {
        _reduceDebt({account: account, asset: asset, burnFrom: msg.sender, amount: amount});
    }
```
https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L148
 - Bob (a malicious user who owns a small amount of `PaprToken`) notices Alice's transaction in the Mempool. So, Bob applies front-run attack and calls the function `reduceDebt` with the following parameters:
   - `account`: Alice's addre

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 24: [M-03] Frontrunning for unallowed minting of Short and Long tokens

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L68>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L109>

### Vulnerability details

#### Unallowed minting of Short and Long tokens

The documentation states that minting of the Short and Long tokens should only be done by the governance.

```solidity
File: apps/smart-contracts/core/contracts/interfaces/IPrePOMarket.sol
73:    * Minting will only be done by the team, and thus relies on the `_mintHook`
74:    * to enforce access controls. This is also why there is no fee for `mint()`
75:    * as opposed to `redeem()`.
```

The problem is, that as long as the **\_mintHook** is not set via **setMintHook**, everyone can use the mint function and mint short and long tokens.
At the moment the **\_mintHook** is not set in the contructor of PrePOMarket and so the transaction that will set the **\_mintHook** can be front run to mint short and long tokens for the attacker.

### Proof of Concept

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L68>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L109>

This test shows how an attacker could frontrun the **setMintHook** function:

```node
  describe('# mint front run attack', () => {
    let mintHook: Fa

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 25: [M-12] Attacker can grift syndicate staking by staking a small amount

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/a0558ed7b12e1ace1fe5c07970c7fc07eb00eebd/contracts/liquid-staking/LiquidStakingManager.sol#L882><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/23c3cf65975cada7fd2255a141b359a6b31c2f9c/contracts/syndicate/Syndicate.sol#L22>

`LiquidStakingManager._autoStakeWithSyndicate` always stakes a fixed amount of 12 ETH. However, `Syndicate.stake` only allows a total staking amount of 12 ETH and reverts otherwise:

```solidity
if (_sETHAmount + totalStaked > 12 ether) revert InvalidStakeAmount();
```

An attacker can abuse this and front-run calls to `mintDerivatives` (which call `_autoStakeWithSyndicate` internally). Because `Syndicate.stake` can be called by everyone, he can stake the minimum amount (1 gwei) such that the `mintDerivatives` call fails.

### Proof Of Concept

As soon as there is a `mintDerivatives` call in the mempool, an attacker (that owns sETH) calls `Syndicate.stake` with an amount of 1 gwei. `_autoStakeWithSyndicate` will still call `Syndicate.stake` with 12 ether. However, `_sETHAmount + totalStaked > 12 ether` will then be true, meaning that the call will revert.

### Recommended Mitigation Steps

Only allow staking through the LiquidStakingManager, i.e. add access control to `Syndicate.stake`.


**[vince0656 (Stakehouse) confirmed](https://github.com/code-423n4/2022-11-stakehouse-findings/issues/146#issuecomment-1329482113)**


***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 106
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## oracle-patterns.md
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

`updateAt` refers to the timestamp of the round. This value isnt checked to ensure it is recent. Additionally, it is important to be aware of the `minAnswer` and `maxAnswer` of the Chainlink oracle; these values are not allowed to be reached or surpassed. See the Chainlink API reference for documentation on `minAnswer` and `maxAnswer`, as well as this piece of code: `OffchainAggregator.sol`.

## Recommendation
- Determine the tolerance threshold for `updateAt`. If `block.timestamp - updateAt` exceeds that threshold, return 0, which is consistent with how the current validations are handled.
- Consider having off-chain monitoring to identify when the market price moves out of `[minAnswer, maxAnswer]` range.

## Connext
Recency check is implemented in PR 1602. Off-chain monitoring will be consider

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 11: [M-07] Oracles two-day feature can be gamed

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

### Example 14: [M-18] Protocols usability becomes very limited when access to Chainlink oracle data feed is blocked

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
Based on the current implementation, when the protocol wants to use Chainlink oracle data feed for getting a collateral token's price, the fixed price for the token should not be set. When the fixed price is not set for the token, calling the `Oracle` contract's `viewPrice` or `getPrice` function will execute `uint price = feeds[token].feed.latestAnswer()`. As https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/ mentions, it is possible that Chainlinks "multisigs can immediately block access to price feeds at will". When this occurs, executing `feeds[token].feed.latestAnswer()` will revert so calling the `viewPrice` and `getPrice` functions also revert, which cause denial of service when calling functions like `getCollateralValueInternal` and`getWithdrawalLimitInternal`. The `getCollateralValueInternal` and`getWithdrawalLimitInternal` functions are the key elements to the core functionalities, such as borrowing, withdrawing, force-replenishing, and liquidating; with these functionalit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 15: [M-11] viewPrice doesnt always report dampened price

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

First, lets clarify the denomination: tokenA/tokenB represents how much tokenB is worth per tokenA. For example, ETH/USDC = 3000 means 1 ETH is equivalent to 3000 USDC.

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

Since Soliditys uint256 type does not support negative numbers, this results in an underflow, triggering an automatic revert and causing the transaction to fail. The edge case described results in `_stddev = 1` and `_mean = 0`, which causes the check `score >= _mean - _stddev` to revert, as `_mean - _stddev` evaluates to a negative result.

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

The function `getUsdPrice`from `LibUsdOracle`should return the token value in USD. For example, one of its consumers is the function [`getMintFertilizerOut`](https://github.com/Cyfrin/2024-05-beanstalk-the-finale/blob/4e0ad0b964f74a1b4880114f4dd5b339bc69cd3e/protocol/contracts/beanstalk/barn/FertilizerFacet.sol#L117-L122):

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


---
## chainlink-patterns.md
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


---
## twap-patterns.md
# TWAP Security Patterns

## Overview

**Frequency**: 10 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Pashov Audit Group, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for twap vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: P2P rate can be manipulated as its a lazy-updated snapshot

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Severity: High Risk
## Context
MarketsManagerForAave.sol#L408-L411

## Description
The P2P rate is lazy-updated upon interactions with the Morpho protocol. It takes the mid-rate of the current Aave supply and borrow rate. Its possible to manipulate these rates before triggering an update on Morpho.
```solidity
function _updateSPYs(address _marketAddress) internal {
    DataTypes.ReserveData memory reserveData = lendingPool.getReserveData(
        IAToken(_marketAddress).UNDERLYING_ASSET_ADDRESS()
    );
    uint256 meanSPY = Math.average(
        reserveData.currentLiquidityRate,
        reserveData.currentVariableBorrowRate
    ) / SECONDS_PER_YEAR; // In ray
}
```

## Example
Assume an attacker has a P2P supply position on Morpho and wants to earn a very high APY on it. He does the following actions in a single transaction:
- Borrow all funds on the desired Aave market. (This can be done by borrowing against flashloaned collateral).
- The utilisation rate of the market is now 100%. The borrow rate is the max borrow rate, and the supply rate is `(1.0 - reserveFactor) * maxBorrowRate`. The max borrow rate can be higher than 100% APY, see Aave docs.
- The attacker triggers an update to the P2P rate, for example, by supplying 1 token to the pool `Positions-ManagerForAave.supply(poolTokenAddress, 1, ...)`, triggering `marketsManager.updateSPYs(_poolTokenAddress)`.
- The new mid-rate is computed, which will be `(2.0 - reserveFactor) * maxBorrowRate / 2 ~ maxBorrowRate`.
- The

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 2: [H-05] Synth realise is vulnerable to flash loan attacks

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

jonah1005


## Vulnerability details

## Impact
Synth `realise` function calculates `baseValueLP` and `baseValueSynth` base on AMM spot price which is vulnerable to flash loan attack. Synth's lp is subject to `realise` whenever the AMM ratio is different than Synth's debt ratio. 

The attack is not necessarily required flash loan. Big whale of the lp token holders could keep calling realse by shifting token ratio of AMM pool back and forth.


## Proof of Concept
The vulnerability locates at:
https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Synth.sol#L187-L199

Where the formula here is dangerous:
https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Utils.sol#L114-L126

https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Utils.sol#L210-L217
Here's a script for conducting flashloan attack
```python
flashloan_amount = init_amount
user = w3.eth.accounts[0]
marked_token.functions.transfer(user, flashloan_amount).transact()
marked_token.functions.transfer(token_pool.address, flashloan_amount).transact({'from': user})
token_pool.functions.addForMember(user).transact({'from': user})
received_lp = token_pool.functions.balanceOf(user).call() 
synth_balance_before_realise = token_synth.functions.mapSynth_LPBalance(token_pool.address).call()
token_synth.functions.realise(token_pool.address).transact()
token_pool.functions.trans

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 3: [H-05] Flash loan price manipulation in purchasePyroFlan()

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

### Example 4: [H-09] `PriceOracle` Does Not Filter Price Feed Outliers

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

### Example 5: [H-04] Vader TWAP averages wrong

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The vader price in `LiquidityBasedTWAP.getVaderPrice` is computed using the `pastLiquidityWeights` and `pastTotalLiquidityWeight` return values of the `syncVaderPrice`.

The `syncVaderPrice` function does not initialize all weights and the total liquidity weight does not equal the sum of the individual weights because it skips initializing the pair with the previous data if the TWAP update window has not been reached yet:

```solidity
function syncVaderPrice()
    public
    override
    returns (
        uint256[] memory pastLiquidityWeights,
        uint256 pastTotalLiquidityWeight
    )
{
    uint256 _totalLiquidityWeight;
    uint256 totalPairs = vaderPairs.length;
    pastLiquidityWeights = new uint256[](totalPairs);
    pastTotalLiquidityWeight = totalLiquidityWeight[uint256(Paths.VADER)];

    for (uint256 i; i < totalPairs; ++i) {
        IUniswapV2Pair pair = vaderPairs[i];
        ExchangePair storage pairData = twapData[address(pair)];
        // @audit-info lastMeasurement is set in _updateVaderPrice to block.timestamp
        uint256 timeElapsed = block.timestamp - pairData.lastMeasurement;
        // @audit-info update period depends on pair
        // @audit-issue if update period not reached => does not initialize pastLiquidityWeights[i]
        if (timeElapsed < pairData.updatePeriod) continue;

        uint256 pastLiquidityEvaluation = pairData.pastLiquidityEvaluation;
        uint256 currentLiquidityEvaluation = _updateVaderPrice(
  

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-vader)

---

### Example 6: H-3: Usage of `slot0` is extremely easy to manipulate

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

### Example 7: [M-04] Ineffective TWAV Implementation

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

_Submitted by xiaoming90, also found by hyh_

The current TWAV implementation consists of an array of 4 observations/valuations called `twavObservations`. Whenever, the new valuation is updated, the new cumulative valuation will be appended to the `twavObservations` array and the oldest observation/valuation will be removed from the `twavObservations` array.

Description of current TWAV implementation can be found at <https://github.com/NibblNFT/nibbl-smartcontracts#twavsol>

> *   Time-weighted average valuation
> *   Uses an array of length 4 which stores cumulative valuation and timestamp.
> *   TWAV is calculated between the most and least recent observations recorded in the array.
> *   TWAV array is updated only when the system is in buyout state. In case of buyout rejection, the array is reset.

<https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/Twav/Twav.sol#L11>

```solidity
/// @notice current index of twavObservations index
uint8 public twavObservationsIndex;
uint8 private constant TWAV_BLOCK_NUMBERS = 4; //TWAV of last 4 Blocks 
uint32 public lastBlockTimeStamp;

/// @notice record of TWAV 
TwavObservation[TWAV_BLOCK_NUMBERS] public twavObservations;

/// @notice updates twavObservations array
/// @param _blockTimestamp timestamp of the block
/// @param _valuation current valuation
function _updateTWAV(uint256 _valuation, uint32 _blockTimestamp) internal {
    uint32 _timeElapsed; 
    unchecked {
        _timeElap

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 8: [H-06] SynthVault rewards can be gamed

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

## Vulnerability Details

The `SynthVault._deposit` function adds `weight` for the user that depends on the spot value of the deposit synth amount in `BASE`.
This spot price can be manipulated and the cost of manipulation is relative to the pool's liquidity.
However, the reward (see `calcReward`) is measured in BASE tokens unrelated to the pool.
Therefore, if the pool's liquidity is low and the reward reserve is high, the attack can be profitable:

1. Manipulate the pool spot price of the `iSYNTH(_synth).LayerONE()` pool by dripping a lot of `BASE` into it repeatedly (sending lots of smaller trades is less costly due to the [path-independence of the continuous liquidity model](https://docs.thorchain.org/thorchain-finance/continuous-liquidity-pools)). This increases the `BASE` per `token` price.
2. Call `SynthVault.depositForMember` and deposit a _small_ amount of synth token. The `iUTILS(_DAO().UTILS()).calcSpotValueInBase(iSYNTH(_synth).LayerONE(), _amount)` will return an inflated weight due to the price.
3. Optionally drip more `BASE` into the pool and repeat the deposits
4. Drip back `token` to the pool to rebalance it

The user's `weight` is now inflated compared to the deposited / locked-up amount and they can claim a large share of the rewards.

## Impact
The cost of the attack depends on the pool's liquidity and the profit depends on the reserve.
It could therefore be profitable under certain circumstances.

## Recommende

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 9: [M-08] "TWAP" used is an observation-weighted-average-price, not a time-weighted one

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI_

While users are incentivized to call the heartbeat, the incentive may be removed later, or it may be more profitable to use old prices, so users may not call the heartbeat during unfavorable prices, leading to the TWAP price being incorrect, and users getting the wrong price for their assets.

A similar case of an incomplete TWAP algorithm was found to be of [Medium](https://github.com/code-423n4/2022-06-nibbl-findings/issues/191) risk.

### Proof of Concept

A TWAP is a Time-Weighted average price, but the algorithm below does not take into account the time between observations:

```solidity
File: /src/modules/PRICE.sol   #1

134          // Calculate new moving average
135          if (currentPrice > earliestPrice) {
136              _movingAverage += (currentPrice - earliestPrice) / numObs;
137          } else {
138              _movingAverage -= (earliestPrice - currentPrice) / numObs;
139          }
140  
141          // Push new observation into storage and store timestamp taken at
142          observations[nextObsIndex] = currentPrice;
143          lastObservationTime = uint48(block.timestamp);
144:         nextObsIndex = (nextObsIndex + 1) % numObs;
```

<https://github.com/code-423n4/2022-08-olympus/blob/b5e139d732eb4c07102f149fb9426d356af617aa/src/modules/PRICE.sol#L134-L144>

While the `Heart` policy enforces an upper bound on how frequently updates are added to the average, there is no guarantee that users call `beat()` in a timely manner:


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 10: [M-01] TWAP price manipulation

**Source**: Pashov Audit Group
**Protocol**: TitanX
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

The `_getTwaPrice` function in FarmKeeper and `getQuote` function in UniversalBuyAndBurn are vulnerable to price manipulation in Uniswap V3 pools with low observation cardinality. This vulnerability can lead to inaccurate price calculations, potentially resulting in unfair token swaps or liquidity provisions.

When getting the twap price to prevent slippage in liquidity providing and swapping, the `_getTwaPrice` and `getQuote` functions fallback to the oldest observation if the requested time window is greater than the available price history.

It's a problem because it doesn't consider the pool cardinality. In newly created pools with cardinality initialized to 1, the oldest observation can be manipulated to be the current `block.timestamp`, setting the TWAP price to the current (potentially manipulated) price. Because in uniswap v3 pool, an oracle observation is written by the first swap or liquidity provision in the block. Let's say before the UniversalBuyAndBurn contract performs the swap, a malicious actor front-runs and swaps to manipulate the price because the cardinality is 1, and the oldest observation is 0.

Another consequence is that the `oldestObservation` can be equal to `cardianility * 12 seconds (time per block)` if liquidity changes each block. It means that the TWAP period can be shorter than intended if `oldestObservation < secondsAgo`, potentially increasing slippage risk.

```solidity
  f

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/TitanX-security-review.md)

---

## Statistics

- Total findings analyzed: 10
- Examples shown: 10
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## stale-price-patterns.md
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

`updateAt` refers to the timestamp of the round. This value isnt checked to ensure it is recent. Additionally, it is important to be aware of the `minAnswer` and `maxAnswer` of the Chainlink oracle; these values are not allowed to be reached or surpassed. See the Chainlink API reference for documentation on `minAnswer` and `maxAnswer`, as well as this piece of code: `OffchainAggregator.sol`.

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

### Example 14: [H-03] WrappedIbbtcEth contract will use stalled price for mint/burn if updatePricePerShare wasnt run properly

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


---
## first-depositor-issue-patterns.md
# First Depositor Issue Security Patterns

## Overview

**Frequency**: 26 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 20 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, Trust Security

---

## Detection Checklist

- [ ] Check for first depositor issue vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

In `Pair.add()`, the amount of LP token minted is calculated as

```solidity
function addQuote(uint256 baseTokenAmount, uint256 fractionalTokenAmount) public view returns (uint256) {
    uint256 lpTokenSupply = lpToken.totalSupply();
    if (lpTokenSupply > 0) {
        // calculate amount of lp tokens as a fraction of existing reserves
        uint256 baseTokenShare = (baseTokenAmount * lpTokenSupply) / baseTokenReserves();
        uint256 fractionalTokenShare = (fractionalTokenAmount * lpTokenSupply) / fractionalTokenReserves();
        return Math.min(baseTokenShare, fractionalTokenShare);
    } else {
        // if there is no liquidity then init
        return Math.sqrt(baseTokenAmount * fractionalTokenAmount);
    }
}
```

An attacker can exploit using these steps

1.  Create and add `1 wei baseToken - 1 wei quoteToken` to the pair. At this moment, attacker is minted `1 wei LP token` because `sqrt(1 * 1) = 1`
2.  Transfer large amount of `baseToken` and `quoteToken` directly to the pair, such as `1e9 baseToken - 1e9 quoteToken`. Since no new LP token is minted, `1 wei LP token` worths `1e9 baseToken - 1e

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 2: [H-05] Underlying assets stealing in `AutoPxGmx` and `AutoPxGlp` via share price manipulation

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L156-L165>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L167-L176>

### Impact

pxGMX and pxGLP tokens can be stolen from depositors in `AutoPxGmx` and `AutoPxGlp` vaults by manipulating the price of a share.

### Proof of Concept

ERC4626 vaults are subject to a share price manipulation attack that allows an attacker to steal underlying tokens from other depositors (this is a [known issue](https://github.com/transmissions11/solmate/issues/178) of Solmate's ERC4626 implementation). Consider this scenario (this is applicable to `AutoPxGmx` and `AutoPxGlp` vaults):

1.  Alice is the first depositor of the `AutoPxGmx` vault;
2.  Alice deposits 1 wei of pxGMX tokens;
3.  in the `deposit` function ([PirexERC4626.sol#L60](https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L60)), the amount of shares is calculated using the `previewDeposit` function:

    ```solidity
    function previewDeposit(uint256 assets)
        public
        view
        virtual
        returns (uint256)
    {
        return convertToShares(assets);
    }

    function convertToShares(uint256 assets)
        public
        view
        virtual
        returns (uint256)
    {
        uint256 supply = totalSupply; // Saves an e

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: First pool depositor can be front-run and have part of their deposit stolen

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- **File:** pool-v2::Pool.sol
- **Line:** #L73

## Description
The first deposit with a `totalSupply` of zero shares will mint shares equal to the deposited amount. This makes it possible to deposit the smallest unit of a token and profit off a rounding issue in the computation for the minted shares of the next depositor:

```
(shares_ * totalAssets()) / totalSupply_
```

### Example
- The first depositor (victim) wants to deposit **2M USDC** (`2e12`) and submits the transaction.
- The attacker front runs the victim's transaction by calling `deposit(1)` to get 1 share. They then transfer **1M USDC** (`1e12`) to the contract, such that `totalAssets = 1e12 + 1`, `totalSupply = 1`.
- When the victim's transaction is mined, they receive:

```
2e12 / (1e12 + 1) * totalSupply = 1 share
```
(rounded down from `1.9999...`).
- The attacker withdraws their 1 share and gets:

```
3M USDC * 1 / 2 = 1.5M USDC
```
making a **0.5M profit**.

During the migration, an `initialSupply` of shares to be airdropped are already minted at initialization and are not affected by this attack.

## Recommendation
Require a minimum initial shares amount for the first deposit by adjusting the initial mint (when `totalSupply == 0`) such that:
- Mint an `INITIAL_BURN_AMOUNT` of shares to a dead address like address zero.
- Only mint `depositAmount - INITIAL_BURN_AMOUNT` to the recipient.

`INITIAL_BURN_AMOUNT` needs to be chosen large enough such that the cost of the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 4: [H-04] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

_Submitted by MiloTruck, also found by cccz, oyc_109, VAD37, PP1004, SmartSek, minhquanym, unforgiven, berndartmueller, WatchPug, CertoraInc, and sorrynotsorry_

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

In `BathToken.sol:569-571`, the allocation of shares is calculated as follows:

```js
(totalSupply == 0) ? shares = assets : shares = (
    assets.mul(totalSupply)
).div(_pool);
```

An early attacker can exploit this by:

*   Attacker calls `openBathTokenSpawnAndSignal()` with `initialLiquidityNew = 1`, creating a new bath token with `totalSupply = 1`
*   Attacker transfers a large amount of underlying tokens to the bath token contract, such as `1000000`
*   Using `deposit()`, a victim deposits an amount less than `1000000`, such as `1000`:
    *   `assets = 1000`
    *   `(assets * totalSupply) / _pool = (1000 * 1) / 1000000 = 0.001`, which would round down to `0`
    *   Thus, the victim receives no shares in return for his deposit

To avoid minting 0 shares, subsequent depositors have to deposit equal to or more than the amount transferred by the attacker. Otherwise, their deposits accrue to the attacker who holds the only share.

```js
it("Victim

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 5: [H-01] yVault: First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: HIGH

**Details**:

_Submitted by hickuphh3, also found by 0xDjango, berndartmueller, cmichel, hyh, and WatchPug_

[yVault.sol#L148-L153](https://github.com/code-423n4/2022-04-jpegd/blob/main/contracts/vaults/yVault/yVault.sol#L148-L153)<br>

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

*   Attacker deposits 1 wei to mint 1 share
*   Attacker transfers exorbitant amount to the `StrategyPUSDConvex` contract to greatly inflate the shares price. Note that the strategy deposits its entire balance into Convex when its `deposit()` function is called.
*   Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

Insert this test into [`yVault.ts`](https://github.com/code-423n4/2022-04-jpegd/blob/main/tests/yVault.ts).

```jsx
it.only("will cause 0 share issuance", async () => {
  // mint 10k + 1 wei tokens to user1
  // mint 10k tokens to owner
  let depositAmount = units(10_000);
  await token.mint(user1.address, depositAmount.add(1));
  await token.mint(owner.address, depositAmount);
  // token approval to yVault
  await token.connect(user1).approve(yVault.address, 1);
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 6: [H-02] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

_Submitted by GreyArt, also found by 0xDjango, CertoraInc, cmichel, rayn, TomFrenchBlockchain, and WatchPug_

[Collateral.sol#L82-L91](https://github.com/code-423n4/2022-03-prepo/blob/main/contracts/core/Collateral.sol#L82-L91)<br>

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

*   Attacker deposits 2 wei (so that it is greater than min fee) to mint 1 share
*   Attacker transfers exorbitant amount to `_strategyController` to greatly inflate the shares price. Note that the `_strategyController` deposits its entire balance to the strategy when its `deposit()` function is called.
*   Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

```jsx
it("will cause 0 share issuance", async () => {
	// 1. first user deposits 2 wei because 1 wei will be deducted for fee
	let firstDepositAmount = ethers.BigNumber.from(2)
	await transferAndApproveForDeposit(
	    user,
	    collateral.address,
	    firstDepositAmount
	)
	
	await collateral
	    .connect(user)
	    .deposit(firstDepositAmount)
	
	// 2. do huge transfer of 1M to strategy to controller
	// to 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-prepo)

---

### Example 7: [H-05] Making `_totalSupply` and `_totalShares` imbalance significantly by providing fake income leads to stealing fund

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

If the project has just started, a malicious user can make the `_totalSupply` and `_totalShares` imbalance significantly by providing fake income. By doing so, later, when innocent users deposit and mint, the malicious user can steal protocol's stETH without burning any shares. Moreover, the protocol's income can be stolen as well.

### Proof of Concept

Suppose nothing is deposited in the protocol (it is day 0).

Bob (a malicious user) deposits `$`1000 worth of ether (equal to 1 ETH, assuming ETH price is `$`1000) to mint `200e18 + 1` eUSD. The state will be:
*   `shares[Bob] = 200e18 + 1`
*   `_totalShares = 200e18 + 1`
*   `_totalSupply = 200e18 + 1`
*   `borrowed[Bob] = 200e18 + 1`
*   `poolTotalEUSDCirculation = 200e18 + 1`
*   `depositAsset[Bob] = 1e18`
*   `totalDepositedAsset = 1e18`
*   `stETH.balanceOf(protocol) = 1e18`

<https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/LybraStETHVault.sol#L37>

Then, Bob transfers directly `0.2stETH` (worth `$`200) to the protocol. By doing so, Bob is providing a fake excess income in the protocol. So, the state will be:
*   `shares[Bob] = 200e18 + 1`
*   `_totalShares = 200e18 + 1`
*   `_totalSupply = 200e18 + 1`
*   `borrowed[Bob] = 200e18 + 1`
*   `poolTotalEUSDCirculation = 200e18 + 1`
*   `depositAsset[Bob] = 1e18`
*   `totalDepositedAsset = 1e18`
*   `stETH.balanceOf(protocol) = 1e18 + 2e17`

Then, Bob calls `excessIncomeDistribution` to buy this excess income. As

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 8: [H-01] An attacker can manipulate the preDepositvePrice to steal from other users

**Source**: Code4rena
**Protocol**: Asymmetry Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L79><br>
<https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L98>

### Impact

The first user that stakes can manipulate the total supply of sfTokens and by doing so create a rounding error for each subsequent user. In the worst case, an attacker can steal all the funds of the next user.

### Proof of Concept

When the first user enters totalSupply is set to 1e18 on [L79](https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L79):

```solidity
if (totalSupply == 0)
            preDepositPrice = 10 ** 18; // initializes with a price of 1
        else preDepositPrice = (10 ** 18 * underlyingValue) / totalSupply;
```

But the user can immediately unstake most of his safETH such that totalSupply <<  1e18. The attacker can then transfer increase the underlying amount by transferring derivative tokens to the derivative contracts.

For subsequent users, the preDepositPrice will be heavily inflated and the calculation of mintAmount on [L98](https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L98):

```solidity
uint256 mintAmount = (totalStakeValueEth * 10 ** 18) / preDepositPrice;
```

can be very inaccurate. In the worst case it rounds down to 0 for users t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-03-asymmetry)

---

### Example 9: H-1: Attacker can manipulate the pricePerShare to profit from future users' deposits

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/001-H 

## Found by 
Ruhum, ctf\_sec, cccz, joestakey, ellahi, \_\_141345\_\_, 8olidity, hansfriese, minhquanym, 0x52, caventa, rvierdiiev, Sm4rty, rbserver, IllIllI, sorrynotsorry, JohnSmith, defsec, WATCHPUG, berndartmueller, ak1

## Summary

By manipulating and inflating the pricePerShare to a super high value, the attacker can cause all future depositors to lose a significant portion of their deposits to the attacker due to precision loss.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `LINK` token as the first depositor of the Vault, and get `(1 * STARTING_SHARES_PER_LINK) wei` of shares.

Then the attacker can send `STARTING_SHARES_PER_LINK - 1` of `LINK` tokens and inflate the price per share from `1 / STARTING_SHARES_PER_LINK` to 1.0000 .

Then the attacker call `withdraw()` to withdraw `STARTING_SHARES_PER_LINK - 1` shares, and send `1e22` of `LINK` token and inflate the price per share from 1.000 to 1.000e22.

As a result, the future user who deposits `9999e18` will only receive `0` (from `9999e18 * 1 / 10000e18`) of shares token.

They will immediately lose all of their deposits.

## Impact

Users may suffer a significant portion or even 100% of the funds they deposited to the Vault.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-142

```solidity
    function deposit(uint256 _amount) exter

*[Content truncated...]*

---

### Example 10: H-4: Victim's fund can be stolen due to rounding error and exchange rate manipulation

**Source**: Sherlock
**Protocol**: Napier
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/94 

The protocol has acknowledged this issue.

## Found by 
Bandit, LTDingZhen, cawfree, jennifer37, xAlismx, xiaoming90
## Summary

Victim's funds can be stolen by malicious users by exploiting the rounding error and through exchange rate manipulation.

## Vulnerability Detail

The LST Adaptor attempts to guard against the well-known vault inflation attack by reverting the TX when the amount of shares minted is rounded down to zero in Line 78 below.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/adapters/BaseLSTAdapter.sol#L71

```solidity
File: BaseLSTAdapter.sol
71:     function prefundedDeposit() external nonReentrant returns (uint256, uint256) {
72:         uint256 bufferEthCache = bufferEth; // cache storage reads
73:         uint256 queueEthCache = withdrawalQueueEth; // cache storage reads
74:         uint256 assets = IWETH9(WETH).balanceOf(address(this)) - bufferEthCache; // amount of WETH deposited at this time
75:         uint256 shares = previewDeposit(assets);
76: 
77:         if (assets == 0) return (0, 0);
78:         if (shares == 0) revert ZeroShares();
```

However, this control alone is not sufficient to guard against vault inflation attacks. 

Let's assume the following scenario (ignoring fee for simplicity's sake):

1. The victim initiates a transaction that deposits 10 ETH as the underlying asset when there are no issued estETH shares.
2. The attacker obse

*[Content truncated...]*

---

### Example 11: [H-03] The price of rsETH could be manipulated by the first staker

**Source**: Code4rena
**Protocol**: Kelp DAO
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-11-kelp/blob/c5fdc2e62c5e1d78769f44d6e34a6fb9e40c00f0/src/LRTDepositPool.sol#L95-L110><br>
<https://github.com/code-423n4/2023-11-kelp/blob/c5fdc2e62c5e1d78769f44d6e34a6fb9e40c00f0/src/LRTOracle.sol#L52-L79>

The first staker can potentially manipulate the price of rsETH through a donation attack, causing subsequent stakers to receive no rsETH after depositing. The first staker can exploit this method to siphon funds from other users.

### Proof of Concept

The mining amount of rsETH is calculated in function `getRsETHAmountToMint` which directly utilizes the total value of the asset divided by the price of a single rsETH.

```solidity
    function getRsETHAmountToMint(
        address asset,
        uint256 amount
    )
        public
        view
        override
        returns (uint256 rsethAmountToMint)
    {
        // setup oracle contract
        address lrtOracleAddress = lrtConfig.getContract(LRTConstants.LRT_ORACLE);
        ILRTOracle lrtOracle = ILRTOracle(lrtOracleAddress);

        // calculate rseth amount to mint based on asset amount and asset exchange rate
        rsethAmountToMint = (amount * lrtOracle.getAssetPrice(asset)) / lrtOracle.getRSETHPrice();
    }
```

Subsequently, the price of rsETH is related to its totalSupply and the total value of deposited assets.

```solidity
    function getRSETHPrice() external view returns (uint256 rsETHPrice) {
        address rsETHTokenAddress = lrtConfig.rsETH();
        uint256 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-11-kelp)

---

### Example 12: TRST-H-4 First depositor can steal asset tokens of others

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
The first depositor can be front run by an attacker and as a result will lose a considerable 
part of the assets provided.
When the pool has no share supply, in `_mintInternal()`, the amount of shares to be minted is 
equal to the assets provided. An attacker can abuse of this situation and profit of the 
rounding down operation when calculating the amount of shares if the supply is non-zero. 
```solidity
        function _mintInternal(address _receiver, uint _balanceIncreased, uint _totalAsset
             ) internal returns (uint mintShares) {
                unfreezeTime[_receiver] = block.timestamp + mintFreezeInterval;
        if (freezeBuckets.interval > 0) {
             FreezeBuckets.addToFreezeBuckets(freezeBuckets, _balanceIncreased.toUint96());
        }
                 uint _totalSupply = totalSupply();
                    if (_totalAsset == 0 || _totalSupply == 0) {
                     mintShares = _balanceIncreased + _totalAsset;
                 } else {
             mintShares = (_balanceIncreased * _totalSupply) / _totalAsset;
             }
            if (mintShares == 0) {
        revert ZeroAmount();
        }
        _mint(_receiver, mintShares);
        }
``` 
Consider the following scenario.
1. Alice wants to deposit 2M * 1e6 USDC to a pool.
2. Bob observes Alice's transaction, frontruns to deposit 1 wei USDC to mint 1 wei share, and 
transfers 1 M * 1e6 USDC to the pool.
3. Alice's transaction is executed, since **_totalAsset = 1M *

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 13: [H-10] First vault depositor can steal other's assets

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

### Example 14: First vault deposit can cause excessive rounding

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## ERC4626 Clone Analysis

## Severity
**Medium Risk**

## Context
`ERC4626-Cloned.sol#L130`

## Description
Aside from storage layout/getters, the context above notes the other major departure from Solmate's ERC4626 implementation. The modification requires the initial mint to cost 10 full WETH.

### Code Snippet
```solidity
function mint(
    uint256 shares,
    address receiver
) public virtual returns (uint256 assets) {
    // assets is 10e18, or 10 WETH, whenever totalSupply() == 0
    assets = previewMint(shares); // No need to check for rounding error, previewMint rounds up.
    // Need to transfer before minting or ERC777s could reenter.
    // minter transfers 10 WETH to the vault
    ERC20(asset()).safeTransferFrom(msg.sender, address(this), assets);
    // shares received are based on user input
    _mint(receiver, shares);
    emit Deposit(msg.sender, receiver, assets, shares);
    afterDeposit(assets, shares);
}
```

Astaria highlighted that the code diff from Solmate is in relation to this finding from the previous Sherlock audit. However, the deposit is still unchanged, and the initial deposit may be 1 wei worth of WETH, in return for 1 wad worth of vault shares.

Furthermore, the previously cited issue may still surface by calling `mint` in a way that sets the price per share high (e.g., 10 shares for 10 WETH produces a price per of 1:1e18). Albeit, it comes at a higher cost to the minter to set the initial price that high.

## Recommendation
- Revert the hard

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 15: [H-05] Inflation of ggAVAX share price by first depositor

**Source**: Code4rena
**Protocol**: GoGoPool
**Impact**: HIGH

**Details**:

Inflation of `ggAVAX` share price can be done by depositing as soon as the vault is created.

Impact:

1.  Early depositor will be able steal other depositors funds
2.  Exchange rate is inflated. As a result depositors are not able to deposit small funds.

### Proof of Concept

If `ggAVAX` is not seeded as soon as it is created, a malicious depositor can deposit 1 WEI of AVAX to receive 1 share.<br>
The depositor can donate WAVAX to the vault and call `syncRewards`. This will start inflating the price.

When the attacker front-runs the creation of the vault, the attacker:

1.  Calls `depositAVAX` to receive 1 share
2.  Transfers `WAVAX` to `ggAVAX`
3.  Calls `syncRewards` to inflate exchange rate

The issue exists because the exchange rate is calculated as the ratio between the `totalSupply` of shares and the `totalAssets()`.<br>
When the attacker transfers `WAVAX` and calls `syncRewards()`, the `totalAssets()` increases gradually and therefore the exchange rate also increases.

` convertToShares  `: <https://github.com/code-423n4/2022-12-gogopool/blob/aec9928d8bdce8a5a4efe45f54c39d4fc7313731/contracts/contract/tokens/upgradeable/ERC4626Upgradeable.sol#L123>

    	function convertToShares(uint256 assets) public view virtual returns (uint256) {
    		uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

    		return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    	}

Its important to note that while it is true that cycle length

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-gogopool)

---

### Example 16: [H-03] StakedCitadel depositors can be attacked by the first depositor with depressing of vault token denomination

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by hyh, also found by VAD37, cmichel, 0xDjango, berndartmueller, and danb_

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L881-L892>

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L293-L295>

### Impact

An attacker can become the first depositor for a recently created StakedCitadel contract, providing a tiny amount of Citadel tokens by calling `deposit(1)` (raw values here, `1` is `1 wei`, `1e18` is `1 Citadel` as it has 18 decimals). Then the attacker can directly transfer, for example, `10^6*1e18 - 1` Citadel to StakedCitadel, effectively setting the cost of `1` of the vault token to be `10^6 * 1e18` Citadel. The attacker will still own 100% of the StakedCitadel's pool being the only depositor.

All subsequent depositors will have their Citadel token investments rounded to `10^6 * 1e18`, due to the lack of precision which initial tiny deposit caused, with the remainder divided between all current depositors, i.e. the subsequent depositors lose value to the attacker.

For example, if the second depositor brings in `1.9*10^6 * 1e18` Citadel, only `1` of new vault to be issued as `1.9*10^6 * 1e18` divided by `10^6 * 1e18` will yield just `1`, which means that `2.9*10^6 * 1e18` total Citadel pool will be divided 50/50 between the second depositor and the attacker, as each have 1 wei of the total 2 wei of vault tokens, i.e. the depositor lost and the attacker gained `0.45*10^6 * 1e18` Cit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-badger-citadel)

---

### Example 17: [H-03] InsuranceFund depositors can be priced out & deposits can be stolen

**Source**: Code4rena
**Protocol**: Hubble
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by danb_

<https://github.com/code-423n4/2022-02-hubble/blob/8c157f519bc32e552f8cc832ecc75dc381faa91e/contracts/InsuranceFund.sol#L44-L54><br>

The `InsuranceFund.deposit` function mints initial `shares` equal to the deposited amount.<br>
The deposit / withdraw functions also use the VUSD contract balance for the shares computation. (`balance() = vusd.balanceOf(address(this))`)

It's possible to increase the share price to very high amounts and price out smaller depositors.

### Proof of Concept

*   `deposit(_amount = 1)`: Deposit the smallest unit of VUSD as the first depositor. Mint 1 share and set the total supply and VUSD balance to `1`.
*   Perform a direct transfer of `1000.0` VUSD to the `InsuranceFund`. The `balance()` is now `1000e6 + 1`
*   Doing any deposits of less than `1000.0` VUSD will mint zero shares: `shares = _amount * _totalSupply / _pool = 1000e6 * 1 / (1000e6 + 1) = 0`.
*   The attacker can call `withdraw(1)` to burn their single share and receive the entire pool balance, making a profit. (`balance() * _shares / totalSupply() = balance()`)

I give this a high severity as the same concept can be used to always steal the initial insurance fund deposit by frontrunning it and doing the above-mentioned steps, just sending the frontrunned deposit amount to the contract instead of the fixed `1000.0`.
They can then even repeat the steps to always frontrun and steal any deposits.

### Recommended Mitigation Steps

The way [Unisw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-hubble)

---

### Example 18: M-12: Vault Share/Strategy Token Calculation Can Be Broken By First User/Attacker

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/70 

## Found by 
xiaoming90

## Summary

A well-known attack vector for almost all shares-based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

> Note: This issue affects MetaStable2 and Boosted3 balancer leverage vaults

For simplicity's sake, we will simplify the strategy token minting formula as follows. Also, assume that the 1 vault share is equivalent to 1 strategy token for this particular strategy vault, therefore, we will use the term `vault share` and `strategy token` interchangeably here.

```solidity
strategyToken = (totalBPTHeld == 0) ?  bptClaim : (bptClaim * totalStrategyToken) / totalBPTHeld
```

The vault minting formula is taken from the following:

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/strategy/StrategyUtils.sol#L27

```solidity
File: StrategyUtils.sol
26:     /// @notice Converts BPT to strategy tokens
27:     function _convertBPTClaimToStrategyTokens(StrategyContext memory context, uint256 bptClaim)
28:         internal pure returns (uint256 strategyTokenAmount) {
29:         if (context.totalBPTHeld == 0) {
30:             // Strategy tokens are in 8 decimal precision, BPT is in 18. Scale the minted amount down.
31:             retu

*[Content truncated...]*

---

### Example 19: H-2: Vault is vulnerable to inflation attack which can cause complete loss of user funds

**Source**: Sherlock
**Protocol**: Numa
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/253 

## Found by 
0xlucky, Abhan1041, AestheticBhai, KupiaSec, Oblivionis, ZZhelev, blutorque, jokr, juaan, novaman33, smbv-1923

### Summary

Attacker can attack the first depositors in the vault and can steal all users funds. this attack is also famously known has first deposit bug too. while doing this attack , there is no loss of attacker funds, but there is complete loss of user funds. he can complete this attack by front running and then backrunning , means sandwiching user funds. this problem takes place , due to improper use of exchange rate when total supply is 0. 

### Root Cause

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CErc20.sol#L60C1-L63C6

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CToken.sol#L510C1-L515C1

here root cause is total cash in formula is being calculated with balanceOF(address(this)), which can donated direclty too. and price can be inflated

### Internal pre-conditions

_No response_

### External pre-conditions

In this attack , attacker should be the first depositor,  and while deploying on ethereum, he can frontrun and can be the first depositor. 

### Attack Path

while depositing when , total supply of minting token is 0, attacker will deposit , 1 wei of asset and will be minted with 1 wei of share.

so now total supply would be 1 wei. 

now , he wil

*[Content truncated...]*

---

### Example 20: H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/50 

## Found by 
ak1

## Summary
Most of the share based vault implementation will face this issue.
The vault is based on the ERC4626 where the shares are calculated based on the deposit value.
By depositing large amount as initial deposit, initial depositor can influence the future depositors value.

## Vulnerability Detail

Shares are minted based on the deposit value.
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L59-L79
Public vault is based on the ERC4626 where the shares are calculated based on the deposit value.

By depositing large amount as initial deposit, first depositor can take advantage over other depositors.

I am sharing reference for this type of issue that already reported and acknowledged. This explain how the share price could be manipulated to  large value.

https://github.com/sherlock-audit/2022-08-sentiment-judging#issue-h-1-a-malicious-early-userattacker-can-manipulate-the-ltokens-pricepershare-to-take-an-unfair-share-of-future-users-deposits:~:text=Issue%20H%2D1%3A%20A%20malicious%20early%20user/attacker%20can%20manipulate%20the%20LToken%27s%20pricePerShare%20to%20take%20an%20unfair%20share%20of%20future%20users%27%20deposits

ERC4626 implementation
    function mint(uint256 shares, address receiver) public virtual returns (uint256 assets) {
        assets = previewMint(shares); // No need to check for rounding error, previewMint round

*[Content truncated...]*

---

### Example 21: [M-09]  A malicious early depositor can manipulate the `LP-Token` price per share to take an unfair share of future user deposits

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/perp-vault/PerpetualAtlanticVaultLP.sol#L118> 

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/perp-vault/PerpetualAtlanticVaultLP.sol#L283>

A  malicious early depositor can profit from future depositors' deposits. While the late depositors will lose part of their funds to the attacker.

### Vulnerability Details

The first depositor can buy a small number of shares and next he should wait until   owner  settle an options through `RdpxCore` so it will result in calling `addRDPX` in `PerpetualAtlanticVaultLP` by transfering rdpxTokens into it and updating `_rdpxCollateral`, as `rdpx Token` has 18 decimals `https://arbiscan.io/token/0x32eb7902d4134bf98a28b963d26de779af92a212` even small amount of rdpx token result in giving a higher `totalVaultCollateral()` so then it calculates `assets.mulDivDown(supply,totalVaultCollateral);` , then it  will make shares very expensive for the next depositors,

### POC

`copy this test into  /tests/perp-vault/Integration.t.sol`<br>
`forge test --match-path  ./tests/perp-vault/Integration.t.sol   -vvvv`

```js
 function test_second_user_loss_share() external {
  //=============================
  address  hecer  = makeAddr("Hecer");
  address  investor = makeAddr("investor");
  //=============================

 setApprovals(hecer);
 setApprovals(investor);

    mintWeth(1 wei, hecer); // hecker starts with 1 wei 
    mintWeth(20 ether, investor);
 
 
 consol

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 22: Inflation attack can cause early users to lose their deposit

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 23: M-1: Vault Inflation Attack

**Source**: Sherlock
**Protocol**: Smilee Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-smilee-finance-judging/issues/22 

## Found by 
kfx, santipu\_

## Summary

An attacker can be the first and only depositor on the vault during the first epoch in order to execute an inflation attack that will steal the deposited funds of all depositors in the next epoch. 

## Vulnerability Detail

A malicious user can perform a donation to execute a classic first depositor/ERC4626 inflation Attack against the new Smilee vaults. The general process of this attack is well-known, and a detailed explanation of this attack can be found in many of the resources such as the following:

- https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks
- https://mixbytes.io/blog/overview-of-the-inflation-attack

In short, to kick-start the attack, the malicious user will often usually mint the smallest possible amount of shares (e.g., 1 wei) and then donate significant assets to the vault to inflate the number of assets per share. Subsequently, it will cause a rounding error when other users deposit.

However, in Smilee there's the problem that the deposits are not processed until the epoch is finished. Therefore, the attacker would need to be the only depositor on the first epoch of the vault; after the second epoch starts, all new depositors will lose all the deposited funds due to a rounding error. 

This scenario may happen for newly deployed vaults with a short maturity period (e.g., 1 day) and/or for vaults with 

*[Content truncated...]*

---

### Example 24: H-2: First depositor can abuse exchange rate to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Surge
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-surge-judging/issues/125 

## Found by 
0Kage, 0x52, 0xAsen, 0xc0ffEE, 0xhacksmithh, Ace-30, Bobface, Breeje, CRYP70, Chinmay, Cryptor, GimelSec, Juntao, MalfurionWhitehat, RaymondFam, SunSec, TrungOre, VAD37, \_\_141345\_\_, ak1, banditx0x, bin2chen, bytes032, carrot, cccz, chaduke, chainNue, ck, ctf\_sec, dingo, gandu, gryphon, peanuts, rvi, unforgiven, usmannk, y1cunhui
## Summary

Classic issue with vaults. First depositor can deposit a single wei then donate to the vault to greatly inflate share ratio. Due to truncation when converting to shares this can be used to steal funds from later depositors.

## Vulnerability Detail

See summary.

## Impact

First depositor can steal funds due to truncation

## Code Snippet

https://github.com/sherlock-audit/2023-02-surge/blob/main/surge-protocol-v1/src/Pool.sol#L307-L343

## Tool used

[Solidity YouTube Tutorial](https://www.youtube.com/watch?v=dQw4w9WgXcQ)

## Recommendation

Either during creation of the vault or for first depositor, lock a small amount of the deposit to avoid this.



## Discussion

**xeious**

GG. We left this one intentionally. Glad to see this many duplicates.

**xeious**

Fixed

**xeious**

https://github.com/Surge-fi/surge-protocol-v1/commit/35e725cc25a97c0ee4a76fc5523ede90ac4ea130

**IAm0x52**

Fix looks good. First deposit now creates a minimum liquidity that make advantageous manipulation nearly impossible

---

### Example 25: M-5: Early depositors to DnGmxSeniorVault can manipulate exchange rates to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/37 

## Found by 
rvierdiiev, tives, peanuts, joestakey, cccz, ctf\_sec, \_\_141345\_\_, 0x52, GimelSec, clems4ever

## Summary

To calculate the exchange rate for shares in DnGmxSeniorVault it divides the total supply of shares by the totalAssets of the vault. The first deposit can mint a very small number of shares then donate aUSDC to the vault to grossly manipulate the share price. When later depositor deposit into the vault they will lose value due to precision loss and the adversary will profit.

## Vulnerability Detail

    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

        return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    }

Share exchange rate is calculated using the total supply of shares and the totalAsset. This can lead to exchange rate manipulation. As an example, an adversary can mint a single share, then donate 1e8 aUSDC. Minting the first share established a 1:1 ratio but then donating 1e8 changed the ratio to 1:1e8. Now any deposit lower than 1e8 (100 aUSDC) will suffer from precision loss and the attackers share will benefit from it.

This same vector is present in DnGmxJuniorVault.

## Impact

Adversary can effectively steal funds from later users

## Code Snippet

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/d

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 26
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## share-inflation-patterns.md
# Share Inflation Security Patterns

## Overview

**Frequency**: 12 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 8 | 4 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, MixBytes, Spearbit

---

## Detection Checklist

- [ ] Check for share inflation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Inflation attack on empty ticks

**Source**: MixBytes
**Protocol**: Curve Finance
**Impact**: HIGH

**Details**:

##### Description

Each AMM tick represents an empty vault, where shares are issued for collateral. A hacker can manipulate a tick so that it contains just 1 wei share and any amount of collateral. For example, suppose the hacker initially inflates the tick so that it contains 1 wei share and 1 ETH. Next, the hacker sees a victim's transaction in the mempool, which is going to deposit 20 ETH into this tick. The hacker then needs to inflate the tick to contain 1 wei share and 10 ETH + 1 wei right before the victim's transaction.

How many shares will the victim receive in this tick? The victim receives 1 wei share due to a rounding error:
```
1 wei share * 20 ETH / (10 ETH + 1 wei) = 1 wei share
```

Now there are 2 wei shares in total in this tick, one for the victim and one for the hacker.

The hacker then self-liquidates and receives 50% of the ether from the entire tick, which is 15 ETH, even though they initially invested 10 ETH. The profit is +5 ETH.

**How does the hacker inflate the collateral in the tick?**

Step 1. Before the frontrunning, the hacker ensures that the tick contains 1 share and 100+ wei ETH. They can do it using the AMM fee, performing `exchange()` back and forth. This is a heavy operation, plus there may be fees if there are other positions before the hacker's ticks. Therefore, this must be done in advance. After that the hacker self-liquidates 99% of their position, leaving one share. If there are no other positions before the hacker, they only spend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Curve%20Finance/Curve%20Stablecoin%20(crvUSD)/README.md#2-inflation-attack-on-empty-ticks)

---

### Example 2: [H-01] ERC4626 mint uses wrong `amount`

**Source**: Code4rena
**Protocol**: Tribe
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by 0xliumin, CertoraInc, Picodes, and Ruhum_

> The docs/video say `ERC4626.sol` is in scope as its part of `TurboSafe`

The `ERC4626.mint` function mints `amount` instead of `shares`.
This will lead to issues when the `asset <> shares` are not 1-to-1 as will be the case for most vaults over time.
Usually, the asset amount is larger than the share amount as vaults receive asset yield.
Therefore, when minting, `shares` should be less than `amount`.
Users receive a larger share amount here which can be exploited to drain the vault assets.

```solidity
function mint(uint256 shares, address to) public virtual returns (uint256 amount) {
    amount = previewMint(shares); // No need to check for rounding error, previewMint rounds up.

    // Need to transfer before minting or ERC777s could reenter.
    asset.safeTransferFrom(msg.sender, address(this), amount);
    _mint(to, amount);

    emit Deposit(msg.sender, to, amount, shares);

    afterDeposit(amount, shares);
}
```

### Proof of Concept

Assume `vault.totalSupply() = 1000`, `totalAssets = 1500`

*   call `mint(shares=1000)`. Only need to pay `1000` asset amount but receive `1000` shares => `vault.totalSupply() = 2000`, `totalAssets = 2500`.
*   call `redeem(shares=1000)`. Receive `(1000 / 2000) * 2500 = 1250` amounts. Make a profit of `250` asset tokens.
*   repeat until `shares <> assets` are 1-to-1

### Recommended Mitigation Steps

In `deposit`:

```diff
function mint(uint256 shares, addr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-tribe-turbo)

---

### Example 3: [H-03] The price of rsETH could be manipulated by the first staker

**Source**: Code4rena
**Protocol**: Kelp DAO
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-11-kelp/blob/c5fdc2e62c5e1d78769f44d6e34a6fb9e40c00f0/src/LRTDepositPool.sol#L95-L110><br>
<https://github.com/code-423n4/2023-11-kelp/blob/c5fdc2e62c5e1d78769f44d6e34a6fb9e40c00f0/src/LRTOracle.sol#L52-L79>

The first staker can potentially manipulate the price of rsETH through a donation attack, causing subsequent stakers to receive no rsETH after depositing. The first staker can exploit this method to siphon funds from other users.

### Proof of Concept

The mining amount of rsETH is calculated in function `getRsETHAmountToMint` which directly utilizes the total value of the asset divided by the price of a single rsETH.

```solidity
    function getRsETHAmountToMint(
        address asset,
        uint256 amount
    )
        public
        view
        override
        returns (uint256 rsethAmountToMint)
    {
        // setup oracle contract
        address lrtOracleAddress = lrtConfig.getContract(LRTConstants.LRT_ORACLE);
        ILRTOracle lrtOracle = ILRTOracle(lrtOracleAddress);

        // calculate rseth amount to mint based on asset amount and asset exchange rate
        rsethAmountToMint = (amount * lrtOracle.getAssetPrice(asset)) / lrtOracle.getRSETHPrice();
    }
```

Subsequently, the price of rsETH is related to its totalSupply and the total value of deposited assets.

```solidity
    function getRSETHPrice() external view returns (uint256 rsETHPrice) {
        address rsETHTokenAddress = lrtConfig.rsETH();
        uint256 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-11-kelp)

---

### Example 4: H-15: Illuminate PTs can be used to mint other Illuminate PTs

**Source**: Sherlock
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-illuminate-judging/issues/108 

## Found by 
pashov, Bnke0x0, Jeiwan, IllIllI, cccz, kenzo, HonorLt, Nyx, 0x52

## Summary

Attackers can inflate away all PT value by unlimited minting


## Vulnerability Detail

`Lender.mint()` allows anyone to exchange any supported PT for an Illuminate PT, and Illuminate PTs themselves are supported PTs by the function. By minting Illuminate PTs by providing other Illuminate PTs, an attacker can increase the total supply of Illuminate PTs without the new tokens having any asset backing. Redemptions are based on shares of the total Illuminate PT supply, rather than being redemptions of one underlying for one Illuminate PT, so as the total supply grows, the value of each share decreases.


## Impact

_Permanent freezing of funds_

An attacker is able to inflate away the value of Illuminate PTs, making redemptions worthless, which means lenders of the protocol lose all deposited principal. Since the objective of the project is to convert other projects' PTs into Illuminate PTs, PTs of all underlyings and all maturities are affected, meaning 100% of deposited/lent principal are at risk.

While the Illuminate project does have an emergency `withdraw()` function that would allow an admin to rescue the funds and manually distribute them if they're still in the `Lender` contract, an attacker can wait for `Redeemer.redeem()` to have been called, at which point all PTs of the maturity and underlying w

*[Content truncated...]*

---

### Example 5: [H-05] Inflation of ggAVAX share price by first depositor

**Source**: Code4rena
**Protocol**: GoGoPool
**Impact**: HIGH

**Details**:

Inflation of `ggAVAX` share price can be done by depositing as soon as the vault is created.

Impact:

1.  Early depositor will be able steal other depositors funds
2.  Exchange rate is inflated. As a result depositors are not able to deposit small funds.

### Proof of Concept

If `ggAVAX` is not seeded as soon as it is created, a malicious depositor can deposit 1 WEI of AVAX to receive 1 share.<br>
The depositor can donate WAVAX to the vault and call `syncRewards`. This will start inflating the price.

When the attacker front-runs the creation of the vault, the attacker:

1.  Calls `depositAVAX` to receive 1 share
2.  Transfers `WAVAX` to `ggAVAX`
3.  Calls `syncRewards` to inflate exchange rate

The issue exists because the exchange rate is calculated as the ratio between the `totalSupply` of shares and the `totalAssets()`.<br>
When the attacker transfers `WAVAX` and calls `syncRewards()`, the `totalAssets()` increases gradually and therefore the exchange rate also increases.

` convertToShares  `: <https://github.com/code-423n4/2022-12-gogopool/blob/aec9928d8bdce8a5a4efe45f54c39d4fc7313731/contracts/contract/tokens/upgradeable/ERC4626Upgradeable.sol#L123>

    	function convertToShares(uint256 assets) public view virtual returns (uint256) {
    		uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

    		return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    	}

Its important to note that while it is true that cycle length

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-gogopool)

---

### Example 6: [H-02] Withdrawers can get more value returned than expected with reentrant call

**Source**: Code4rena
**Protocol**: Sandclock
**Impact**: HIGH

**Details**:

_Submitted by camden, also found by cmichel and harleythedog_

The impact of this is that users can get significantly more UST withdrawn than they would be alotted if they had done non-reentrant withdraw calls.

#### Proof of Concept

Here's an outline of the attack:

Assume the vault has 100 UST in it.
The attacker makes two deposits of 100UST and waits for them to be withdrawable.
The attacker triggers a withdraw one of their deposit positions.
The vault code executes until it reaches this point: <https://github.com/code-423n4/2022-01-sandclock/blob/a90ad3824955327597be00bb0bd183a9c228a4fb/sandclock/contracts/Vault.sol#L565>
Since the attacker is the claimer, the vault will call back to the attacker.
Inside `onDepositBurned`, trigger another 100 UST deposit.
Since `claimers.onWithdraw` has already been called, reducing the amount of shares, but the UST hasn't been transferred yet, the vault will compute the amount of UST to be withdrawn based on an unexpected value for `_totalUnderlyingMinusSponsored` (300).
<https://github.com/code-423n4/2022-01-sandclock/blob/a90ad3824955327597be00bb0bd183a9c228a4fb/sandclock/contracts/Vault.sol#L618>

After the attack, the attacker will have significantly more than if they had withdrawn without reentrancy.

Here's my proof of concept showing a very similar exploit with `deposit`, but I think it's enough to illustrate the point. I have a forge repo if you want to see it, just ping me on discord.
<https://gist.github.com/CamdenClark/abc67b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-sandclock)

---

### Example 7: [M-04] Malicious users can front-run to cause a denial of service (DoS) for StakedUSDe due to MinShares checks

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

Malicious users can transfer `USDe` token to `StakedUSDe` protocol directly lead to a denial of service (DoS) for StakedUSDe due to the limit shares check.

### Proof of Concept

User deposit `USDe` token to `StakedUSDe` protocol to get share via invoke external `deposit` function. Let's see how share is calculate:

```solidity
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
        return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
    }
```

Since `decimalsOffset() == 0` and totalAssets equal the balance of `USDe` in this protocol

```solidity
    function totalAssets() public view virtual override returns (uint256) {
        return _asset.balanceOf(address(this));
    }
```

$$
f(share) = (USDeAmount \ast totalSupply) / (totalUSDeAssets() + 1)
$$

The minimum share is set to 1 ether.

```solidity
  uint256 private constant MIN_SHARES = 1 ether;
```

Assuming malicious users transfer 1 ether of `USDe` into the protocol and receive ZERO shares, how much tokens does the next user need to pay if they want to exceed the minimum share limit of 1 ether? That would be 1 ether times 1 ether, which is a substantial amount.

I add a test case in `StakedUSDe.t.sol`:

```solidity
  function testMinSharesViolation() public {
    address malicious = vm.addr(100);

    usdeToken.mint(malicious, 1 ether);
    usdeToken.mint(alice, 1000 ether);

    //assume malicious user deposit 1 ethe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

### Example 8: Inflation attack can cause early users to lose their deposit

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 9: [H-01] StakedCitadel doesn't use correct balance for internal accounting

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by Ruhum, also found by cccz, wuwe1, VAD37, TrungOre, shenwilly, minhquanym, kyliek, danb, gs8nrv, and rayn_

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L291-L295>

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L772-L776>

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L881-L893>

### Impact

The StakedCitadel contract's `balance()` function is supposed to return the balance of the vault + the balance of the strategy. But, it only returns the balance of the vault. The balance is used to determine the number of shares that should be minted when depositing funds into the vault and the number of shares that should be burned when withdrawing funds from it.

Since most of the funds will be located in the strategy, the vault's balance will be very low. Some of the issues that arise from this:

**You can't deposit to a vault that already minted shares but has no balance of the underlying token**:

1.  fresh vault with 0 funds and 0 shares
2.  Alice deposits 10 tokens. She receives 10 shares back (<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L887-L888>)
3.  Vault's tokens are deposited into the strategy (now `balance == 0` and `totalSupply == 10`)
4.  Bob tries to deposit but the transaction fails because the contract tries to divide by zero: <https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/Sta

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-badger-citadel)

---

### Example 10: SharesManager._mintShares - Depositors may receive zero shares due to front-running

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Medium Risk Report

## Severity 
Medium Risk

## Context 
SharesManager.1.sol#L202

## Description 
The number of shares minted to a depositor is determined by 

\[
\text{shares} = \frac{\text{underlyingAssetValue} \times \text{totalSupply()}}{\text{oldTotalAssetBalance}}
\]

Potential attackers can spot a call to `UserDepositManagerV1._deposit` and front-run it with a transaction that sends wei to the contract (by self-destructing another contract and sending the funds to it), causing the victim to receive fewer shares than expected. 

More specifically, if `oldTotalAssetBalance()` is greater than `underlyingAssetValue * totalSupply()`, then the number of shares the depositor receives will be 0, although `underlyingAssetValue` will still be pulled from the depositors balance. 

An attacker with access to enough liquidity and the mempool data can spot a call to `UserDepositManagerV1._deposit` and front-run it by sending at least 

\[
\text{totalSupplyBefore} \times (\text{underlyingAssetValue} - 1) + 1 \text{ wei}
\]

to the contract. This way, the victim will get 0 shares, but `underlyingAssetValue` will still be pulled from their account balance. 

In this case, the attacker does not necessarily have to be a whitelisted user, and it is important to mention that the funds sent by them cannot be directly claimed back; rather, they will increase the price of the share.

The attack vector mentioned above is the general front-run case. The most profitable attack vector will 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 11: M-4: Front run `distributeRewards()` can steal the newly added rewards

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/106 

## Found by 
WATCHPUG, hickuphh3, hyh

## Summary

A surge of pointsPerShare on each `distributeRewards()` call can be used by the attacker to steal part of the newly added rewards.

## Vulnerability Detail

Every time the `distributeRewards()` gets called, there will be a surge of `pointsPerShare` for the existing stakeholders.

This enables a well-known attack vector, in which the attacker will deposit a huge amount of underlying tokens and take a large portion of the pool, then trigger the surge, and exit right after.

## Impact

While the existence of the `MIN_LOCK_DURATION` prevented the usage of flashloan, it's still possible for the attackers with sufficient funds or can acquire sufficient funds in other ways.

In which case, the attack is quite practical and effectively steal the major part of the newly added rewards

## Code Snippet

https://github.com/sherlock-audit/2022-10-merit-circle/blob/main/merit-liquidity-mining/contracts/base/BasePool.sol#L95-L98

https://github.com/sherlock-audit/2022-10-merit-circle/blob/main/merit-liquidity-mining/contracts/base/AbstractRewards.sol#L89-L99

## Tool used

Manual Review

## Recommendation

Consider using a `rewardRate`-based gradual release model, pioneered by Synthetix's StakingRewards contract.

See: https://github.com/Synthetixio/synthetix/blob/develop/contracts/StakingRewards.sol#L113-L132

## Discussion

**federava**

Raising the MIN_LO

*[Content truncated...]*

---

### Example 12: M-5: First user can inflate `pointsPerShare` and cause `_correctPoints()` to revert due to overflow

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/103 

## Found by 
WATCHPUG, bin2chen

## Summary

`pointsPerShare` can be manipulated by the first user and cause `_correctPoints()` to revert later.

## Vulnerability Detail

`POINTS_MULTIPLIER` is an unusually large number as a precision fix for `pointsPerShare`: `type(uint128).max ~= 3.4e38`.

This makes it possible for the first user to manipulate the `pointsPerShare` to near `type(int256).max` and a later regular user can trigger the overflow of `_shares * _shares * ` in `_correctPoints()`.

### PoC

1. `deposit(1 wei)` lock for 10 mins, `mint()` 1 wei of shares;
2. `distributeRewards(1000e18)`, `pointsPerShare += 1000e18 * type(uint128).max / 1` == 3e59;
3. the victim `deposit(100e18)` for 1 year, `mint()` 150e18 shares;
3. `_shares * pointsPerShare == -150e18 * 3e59 == -4.5e+79` which exceeds `type(int256).min`, thus the transaction will revert.

The attacker can also manipulate `pointsPerShare` to a slightly smaller number, so that `_shares * pointsPerShare` will only overflow after a certain amount of deposits.

## Impact

By manipulating the `pointPerShare` precisely, the attacker can make it possible for the system to run normally for a little while and only to explode after a certain amount of deposits, as the `pointsPerShare` will be too large by then and all the `_mint` and `_burn` will revert due to overflow in `_correctPoints()`.

The users who deposited before will be unable to wit

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 12
- Examples shown: 12
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## initial-deposit-patterns.md
# Initial Deposit Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 3 | 1 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group, Cyfrin

---

## Detection Checklist

- [ ] Check for initial deposit vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-1: Attacker can manipulate the pricePerShare to profit from future users' deposits

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/001-H 

## Found by 
Ruhum, ctf\_sec, cccz, joestakey, ellahi, \_\_141345\_\_, 8olidity, hansfriese, minhquanym, 0x52, caventa, rvierdiiev, Sm4rty, rbserver, IllIllI, sorrynotsorry, JohnSmith, defsec, WATCHPUG, berndartmueller, ak1

## Summary

By manipulating and inflating the pricePerShare to a super high value, the attacker can cause all future depositors to lose a significant portion of their deposits to the attacker due to precision loss.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `LINK` token as the first depositor of the Vault, and get `(1 * STARTING_SHARES_PER_LINK) wei` of shares.

Then the attacker can send `STARTING_SHARES_PER_LINK - 1` of `LINK` tokens and inflate the price per share from `1 / STARTING_SHARES_PER_LINK` to 1.0000 .

Then the attacker call `withdraw()` to withdraw `STARTING_SHARES_PER_LINK - 1` shares, and send `1e22` of `LINK` token and inflate the price per share from 1.000 to 1.000e22.

As a result, the future user who deposits `9999e18` will only receive `0` (from `9999e18 * 1 / 10000e18`) of shares token.

They will immediately lose all of their deposits.

## Impact

Users may suffer a significant portion or even 100% of the funds they deposited to the Vault.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-142

```solidity
    function deposit(uint256 _amount) exter

*[Content truncated...]*

---

### Example 2: H-1: A malicious early user/attacker can manipulate the LToken's pricePerShare to take an unfair share of future users' deposits

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/004-H 
## Found by 
kankodu, JohnSmith, PwnPatrol, WATCHPUG, berndartmueller, hyh, \_\_141345\_\_, IllIllI, TomJ

## Summary

A well known attack vector for almost all shares based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `asset` token as the first depositor of the LToken, and get `1 wei` of shares.

Then the attacker can send `10000e18 - 1` of `asset` tokens and inflate the price per share from 1.0000 to an extreme value of 1.0000e22 ( from `(1 + 10000e18 - 1) / 1`) .

As a result, the future user who deposits `19999e18` will only receive `1 wei` (from `19999e18 * 1 / 10000e18`) of shares token.

They will immediately lose `9999e18` or half of their deposits if they `redeem()` right after the `deposit()`.

## Impact

The attacker can profit from future users' deposits. While the late users will lose part of their funds to the attacker.

## Code Snippet

https://github.com/sentimentxyz/protocol/blob/4e45871e4540df0f189f6c89deb8d34f24930120/src/tokens/utils/ERC4626.sol#L48-L60

```solidity
function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
    beforeDeposit(assets, shares);

    // Check for rounding error since we round d

*[Content truncated...]*

---

### Example 3: M-12: Vault Share/Strategy Token Calculation Can Be Broken By First User/Attacker

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/70 

## Found by 
xiaoming90

## Summary

A well-known attack vector for almost all shares-based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

> Note: This issue affects MetaStable2 and Boosted3 balancer leverage vaults

For simplicity's sake, we will simplify the strategy token minting formula as follows. Also, assume that the 1 vault share is equivalent to 1 strategy token for this particular strategy vault, therefore, we will use the term `vault share` and `strategy token` interchangeably here.

```solidity
strategyToken = (totalBPTHeld == 0) ?  bptClaim : (bptClaim * totalStrategyToken) / totalBPTHeld
```

The vault minting formula is taken from the following:

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/strategy/StrategyUtils.sol#L27

```solidity
File: StrategyUtils.sol
26:     /// @notice Converts BPT to strategy tokens
27:     function _convertBPTClaimToStrategyTokens(StrategyContext memory context, uint256 bptClaim)
28:         internal pure returns (uint256 strategyTokenAmount) {
29:         if (context.totalBPTHeld == 0) {
30:             // Strategy tokens are in 8 decimal precision, BPT is in 18. Scale the minted amount down.
31:             retu

*[Content truncated...]*

---

### Example 4: H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/50 

## Found by 
ak1

## Summary
Most of the share based vault implementation will face this issue.
The vault is based on the ERC4626 where the shares are calculated based on the deposit value.
By depositing large amount as initial deposit, initial depositor can influence the future depositors value.

## Vulnerability Detail

Shares are minted based on the deposit value.
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L59-L79
Public vault is based on the ERC4626 where the shares are calculated based on the deposit value.

By depositing large amount as initial deposit, first depositor can take advantage over other depositors.

I am sharing reference for this type of issue that already reported and acknowledged. This explain how the share price could be manipulated to  large value.

https://github.com/sherlock-audit/2022-08-sentiment-judging#issue-h-1-a-malicious-early-userattacker-can-manipulate-the-ltokens-pricepershare-to-take-an-unfair-share-of-future-users-deposits:~:text=Issue%20H%2D1%3A%20A%20malicious%20early%20user/attacker%20can%20manipulate%20the%20LToken%27s%20pricePerShare%20to%20take%20an%20unfair%20share%20of%20future%20users%27%20deposits

ERC4626 implementation
    function mint(uint256 shares, address receiver) public virtual returns (uint256 assets) {
        assets = previewMint(shares); // No need to check for rounding error, previewMint round

*[Content truncated...]*

---

### Example 5: H-3: Early depositors to BufferBinaryPool can manipulate exchange rates to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/81 

## Found by 
dipp, gandu, rvierdiiev, Ruhum, hansfriese, cccz, 0x52, ctf\_sec, joestakey

## Summary

To calculate the exchange rate for shares in BufferBinaryPool it divides the total supply of shares by the totalTokenXBalance of the vault. The first deposit can mint a very small number of shares then donate tokenX to the vault to grossly manipulate the share price. When later depositor deposit into the vault they will lose value due to precision loss and the adversary will profit.

## Vulnerability Detail

    function totalTokenXBalance()
        public
        view
        override
        returns (uint256 balance)
    {
        return tokenX.balanceOf(address(this)) - lockedPremium;
    }

Share exchange rate is calculated using the total supply of shares and the totalTokenXBalance, which leaves it vulnerable to exchange rate manipulation. As an example, assume tokenX == USDC. An adversary can mint a single share, then donate 1e8 USDC. Minting the first share established a 1:1 ratio but then donating 1e8 changed the ratio to 1:1e8. Now any deposit lower than 1e8 (100 USDC) will suffer from precision loss and the attackers share will benefit from it.

## Impact

Adversary can effectively steal funds from later users through precision loss

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L405-L412

## Tool used

Manual Revie

*[Content truncated...]*

---

### Example 6: Inflation attack can cause early users to lose their deposit

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 7: M-5: First user can inflate `pointsPerShare` and cause `_correctPoints()` to revert due to overflow

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/103 

## Found by 
WATCHPUG, bin2chen

## Summary

`pointsPerShare` can be manipulated by the first user and cause `_correctPoints()` to revert later.

## Vulnerability Detail

`POINTS_MULTIPLIER` is an unusually large number as a precision fix for `pointsPerShare`: `type(uint128).max ~= 3.4e38`.

This makes it possible for the first user to manipulate the `pointsPerShare` to near `type(int256).max` and a later regular user can trigger the overflow of `_shares * _shares * ` in `_correctPoints()`.

### PoC

1. `deposit(1 wei)` lock for 10 mins, `mint()` 1 wei of shares;
2. `distributeRewards(1000e18)`, `pointsPerShare += 1000e18 * type(uint128).max / 1` == 3e59;
3. the victim `deposit(100e18)` for 1 year, `mint()` 150e18 shares;
3. `_shares * pointsPerShare == -150e18 * 3e59 == -4.5e+79` which exceeds `type(int256).min`, thus the transaction will revert.

The attacker can also manipulate `pointsPerShare` to a slightly smaller number, so that `_shares * pointsPerShare` will only overflow after a certain amount of deposits.

## Impact

By manipulating the `pointPerShare` precisely, the attacker can make it possible for the system to run normally for a little while and only to explode after a certain amount of deposits, as the `pointsPerShare` will be too large by then and all the `_mint` and `_burn` will revert due to overflow in `_correctPoints()`.

The users who deposited before will be unable to wit

*[Content truncated...]*

---

### Example 8: M-4: Frontrun `deposit()` can cause the depositor to lose all the funds

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/029-M 

## Found by 
ctf\_sec, Lambda, CRYP70, 8olidity, bin2chen, hansfriese, innertia, dipp, rbserver, CodingNameKiki, WATCHPUG

## Summary

The attacker can frontrun the first depositor's `deposit()` transaction and transfer LINK tokens to the Vault contract directly and cause the depositor (and all the future depositors) to lose all the funds.

## Vulnerability Detail

In `onTokenTransfer()`, if there are some existing balance in the Vault contract, say 1 wei of LINK token, `supplyBeforeTransfer` will be `1`, since `totalShares == 0`, `newShares` will always be `0`.

The same applies for `deposit()`.

## Impact

The depositor who got frontrun by the attacker will lose all their funds. And all the future depositors.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L252-L276

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-L142

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L614-L620


## Tool used

Manual Review

## Recommendation

It should check if `totalShares == 0` to decide whether this is the first mint.

---

### Example 9: [L-04] Frontrunnable Initialization

**Source**: Pashov Audit Group
**Protocol**: Enclave_2025-10-25
**Impact**: LOW

**Details**:

_Acknowledged_

The `initialize` instruction creates the global `fund_pool` PDA (`seed = b"fund_pool"`) and sets `initial_admin` to an arbitrary public key supplied by the caller. There is no access control restricting who may invoke this first-use initializer. An attacker can front-run deployment, initialize the pool, and seize control over all admin- and signer-gated operations for the lifetime of the program (until redeploy).

**Recommendations**

Implement a robust access control mechanism that ensures only a trusted entity, such as the program's deployer or a predefined address, can call the `initialize` function. This restriction can be enforced by verifying the caller's identity or using a specific signature during initialization.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Enclave-security-review_2025-10-25.md)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## collateral-factor-patterns.md
# Collateral Factor Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 0 | 0 |

**Common Sources**: Sherlock, ZachObront, Code4rena

---

## Detection Checklist

- [ ] Check for collateral factor vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Collateralization ratio can be broken by users redeeming deposits for ETH

**Source**: ZachObront
**Protocol**: Dyad
**Impact**: HIGH

**Details**:

A key property of the DYAD system is that the collateralization ratio (300%) is maintained. This means that for every 1 DYAD in circulation, there is 3x as much ETH (priced in USD) in the vault.

This invariant is enforced in the withdraw() function, which stops users from minting more DYAD when such a mint would break the invariant:

```solidity
function withdraw(uint from, address to, uint amount) external
isNftOwnerOrHasPermission(from, Permission.WITHDRAW)
isUnlocked(from)
{
_subDeposit(from, amount);

uint collatVault    = address(this).balance * _getEthPrice()/1e8;
uint newCollatRatio = collatVault.divWadDown(dyad.totalSupply() + amount);
if (newCollatRatio < MIN_COLLATERIZATION_RATIO) { revert CrTooLow(); }
...
}
```

However, the same check is not enforced when redeeming ETH out of the contract. Since a key goal is keeping the ratio of circulating DYAD and ETH bounded by this ratio, it is crucial that we enforce this check on both DYAD minting and ETH redeeming.

**Proof of Concept**

Here is a test showing that we can get the collateralization ratio as low as 1:1 by withdrawing all non-minted deposits:

```solidity
function test_CollateralizationRatioBrokenOnRedeemDeposit() public {
// We deposit 5000 in totalDeposit and mint 1000 of them. Ratio is $5000 of ETH / 1000 supply.
uint id1 = dNft.mint{value: 5 ether}(address(this));
dNft.withdraw(id1, address(this), 1000e18);
console.log(_calculateCollateralizationRatio()); // returns 5e18 - success

// We can now withdra

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-02-12-Dyad.md)

---

### Example 2: H-8: Cross available value is not accounting the position fees

**Source**: Sherlock
**Protocol**: Elfi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-05-elfi-protocol-judging/issues/42 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
## Summary
Cross available value is the maximum margin that an account can open a position. This value currently subtracts if the account has any losses but not assumes the fees which can be negative as well. This makes the account have a greater maximum margin than it should be.
## Vulnerability Detail
Cross available value is calculated in AccountProcess::getCrossAvailableValue() function as follows:
```solidity
            (totalNetValue + cache.totalIMUsd + accountProps.orderHoldInUsd).toInt256() -
            totalUsedValue.toInt256() +
            (cache.totalPnl >= 0 ? int256(0) : cache.totalPnl) -
            (cache.totalIMUsdFromBalance + totalBorrowingValue).toInt256();
```

As we can observe in above code snippet if there is a negative PnL it is subtracted from the positions available cross value. The reason for this is that if the account has a negative PnL that means when the position is realized accounts net value will drop hence, it is critical to account anything that can/will drop the accounts net value such as sum PnL of the positions account has. However, this calculation missing a key factor that also can drop the accounts net value which is the fees; closeFee, borrowingFee and fundingFee. When the position is settled these fees will added on top of the PnL so it can be assumed that it will affect the us

*[Content truncated...]*

---

### Example 3: [M-04] Undercollateralized loans possible

**Source**: Code4rena
**Protocol**: Duality Focus
**Impact**: MEDIUM

**Details**:

_Submitted by cmichel_

[Comptroller.sol#L1491](https://github.com/code-423n4/2022-04-dualityfocus/blob/f21ef7708c9335ee1996142e2581cb8714a525c9/contracts/compound_rari_fork/Comptroller.sol#L1491)<br>

The `_setPoolCollateralFactors` function does not check that the collateral factor is < 100%.<br>
It's possible that it's set to 200% and then borrows more than the collateral is worth, stealing from the pool.

### Recommended Mitigation Steps

Disable the possibility of ever having a collateral factor > 100% by checking:

```diff
for (uint256 i = 0; i < pools.length; i++) {
+   require(collateralFactorsMantissa[i] <= 1e18, "CF > 100%");
    poolCollateralFactors[pools[i]] = collateralFactorsMantissa[i];
}
```

**[0xdramaone (Duality Focus) confirmed, but disagreed with Medium severity and commented](https://github.com/code-423n4/2022-04-dualityfocus-findings/issues/12#issuecomment-1094732426):**
 > We agree, we should have a max setting for collateral factor of pools to provide confidence to users. That said, this would only be abusable by admins, and so we consider low risk (since controlled by multisig).

**[Jack the Pug (judge) commented](https://github.com/code-423n4/2022-04-dualityfocus-findings/issues/12#issuecomment-1097569137):**
 > Good catch!
> 
> Unbounded `collateralFactor` configuration made it possible for malicious/compromised privileged roles to rug the users, which I consider a real and very practical threat that should be addressed from the smart contract lev

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-dualityfocus)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## protocol-reserve-patterns.md
# Protocol Reserve Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Pashov Audit Group, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for protocol reserve vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Wrong reserve factor computation on P2P rates

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

### Example 2: M-9: Protocol Reserve Within A LToken Vault Can Be Lent Out

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/122-M 
## Found by 
xiaoming90

## Summary

Protocol reserve, which serves as a liquidity backstop or to compensate the protocol, within a LToken vault can be lent out to the borrowers.

## Vulnerability Detail

The purpose of the protocol reserve within a LToken vault is to compensate the protocol or serve as a liquidity backstop. However, based on the current setup, it is possible for the protocol reserve within a Ltoken vault to be lent out.

The following functions within the `LToken` contract show that the protocol reserve is intentionally preserved by removing the protocol reserve from the calculation of total assets within a LToken vault. As such, whenever the Liquidity Providers (LPs) attempt to redeem their LP token, the protocol reserves will stay intact and will not be withdrawn by the LPs.

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L191

```solidity
function totalAssets() public view override returns (uint) {
    return asset.balanceOf(address(this)) + getBorrows() - getReserves();
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L195

```solidity
function getBorrows() public view returns (uint) {
    return borrows + borrows.mulWadUp(getRateFactor());
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L176

```solidity
function getReserve

*[Content truncated...]*

---

### Example 3: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

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

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## pegged-patterns.md
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


---
## deposit-reward-tokens-patterns.md
# Deposit/Reward tokens Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 13 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for deposit/reward tokens vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-09] Attacker can steal 99% of total balance from any reward token in any Staking contract

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L108-L110>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L483-L503> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L296-L315>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L351-L360> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L377-L378>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L390-L399>

### Impact

Attacker can steal 99% of the balance of a reward token of any Staking contract in the blockchain. An attacker can do this by modifying the reward speed of the target reward token.

So an attacker gets access to `changeRewardSpeed`, he will need to deploy a vault using the target Staking contract as its Staking contract. Since the Staking contract is now attached to the attacker's created vault, he can now successfully `changeRewardSpeed`. Now with `changeRewardSpeed`, attacker can set the `rewardSpeed` to any absurdly large amount that allows them to drain 99% of the balance (dust usually remains due to rounding issues) after some seconds (12 seconds in the PoC.)

### Proof of Concept

This attack is made possible by the following issues:

1.  Any user can deploy a Vault that uses any existing Staking contract - <https://github.com/code-423n4/2023-01-popcorn/blob/mai

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 2: [H-02] Malicious Users Can Transfer Vault Collateral To Other Accounts To Extract Additional Yield From The Protocol

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

_Submitted by leastwood_

`ConvexYieldWrapper.sol` is a wrapper contract for staking convex tokens on the user's behalf, allowing them to earn rewards on their deposit. Users will interact with the `Ladle.sol` contract's `batch()` function which:

*   Approves Ladle to move the tokens.
*   Transfers the tokens to `ConvexYieldWrapper.sol`.
*   Wraps/stakes these tokens.
*   Updates accounting and produces debt tokens within `Ladle.sol`.

`_getDepositedBalance()` takes into consideration the user's total collateral stored in all of their owned vaults. However, as a vault owner, you are allowed to give the vault to another user, move collateral between vaults and add/remove collateral. Therefore, it is possible to manipulate the result of this function by checkpointing one user's balance at a given time, transferring ownership to another user and then create a new checkpoint with this user.

As a result, a user is able to generate protocol yield multiple times over on a single collateral amount. This can be abused to effectively extract all protocol yield.

#### Proof of Concept

Consider the following exploit scenario:

*   Alice owns a vault which has 100 tokens worth of collateral.
*   At that point in time, `_getDepositedBalance()` returns 100 as its result. A checkpoint has also been made on this balance, giving Alice claim to her fair share of the rewards.
*   Alice then calls `Ladle.give()`, transferring the ownership of the vault to Bob and calls `ConvexYieldWrapper.addV

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-yield)

---

### Example 3: [H-02] Tokens can be stolen when depositToken == rewardToken

**Source**: Code4rena
**Protocol**: Streaming Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Streaming` contract allows the `deposit` and `reward` tokens to be the same token.

> I believe this is intended, think Sushi reward on Sushi as is the case with `xSushi`.

The reward and deposit balances are also correctly tracked independently in `depositTokenAmount` and `rewardTokenAmount`.
However, when recovering tokens this leads to issues as the token is recovered twice, once for deposits and another time for rewards:

```solidity
function recoverTokens(address token, address recipient) public lock {
    // NOTE: it is the stream creators responsibility to save
    // tokens on behalf of their users.
    require(msg.sender == streamCreator, "!creator");
    if (token == depositToken) {
        require(block.timestamp > endDepositLock, "time");
        // get the balance of this contract
        // check what isnt claimable by either party
        // @audit-info depositTokenAmount updated on stake/withdraw/exit, redeemedDepositTokens increased on claimDepositTokens
        uint256 excess = ERC20(token).balanceOf(address(this)) - (depositTokenAmount - redeemedDepositTokens);
        // allow saving of the token
        ERC20(token).safeTransfer(recipient, excess);

        emit RecoveredTokens(token, recipient, excess);
        return;
    }
    
    if (token == rewardToken) {
        require(block.timestamp > endRewardLock, "time");
        // check current balance vs internal balance
        //
        // NOTE: if a 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-streaming)

---

### Example 4: H-3: LP tokens are not sent back to withdrawing user

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/151 

## Found by 
rvierdiiev, minhtrng, Dug, Jeiwan, obront, chaduke, koxuan, sinarette, Ch\_301, cergyk, evan, berndartmueller, 0x52, Bauer

## Summary

When users withdraw their assets from `IchiVaultSpell.sol`, the function unwinds their position and sends them back their assets, but it never sends them back the amount they requested to withdraw, leaving the tokens stuck in the Spell contract.

## Vulnerability Detail

When a user withdraws from `IchiVaultSpell.sol`, they either call `closePosition()` or `closePositionFarm()`, both of which make an internal call to `withdrawInternal()`.

The following arguments are passed to the function:
- strategyId: an index into the `strategies` array, which specifies the Ichi vault in question
- collToken: the underlying token, which is withdrawn from Compound
- amountShareWithdraw: the number of underlying tokens to withdraw from Compound
- borrowToken: the token that was borrowed from Compound to create the position, one of the underlying tokens of the vault
- amountRepay: the amount of the borrow token to repay to Compound
- amountLpWithdraw: the amount of the LP token to withdraw, rather than trade back into borrow tokens

In order to accomplish these goals, the contract does the following...

1) Removes the LP tokens from the ERC1155 holding them for collateral.
```solidity
doTakeCollateral(strategies[strategyId].vault, lpTakeAmt);
```
2) Calculates the n

*[Content truncated...]*

---

### Example 5: H-2: Users who deposit extra funds into their Ichi farming positions will lose all their ICHI rewards

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/158 

## Found by 
carrot, rvierdiiev, minhtrng, obront, sinarette, tives, berndartmueller, 0x52

## Summary

When a user deposits extra funds into their Ichi farming position using `openPositionFarm()`, the old farming position will be closed down and a new one will be opened. Part of this process is that their ICHI rewards will be sent to the `IchiVaultSpell.sol` contract, but they will not be distributed. They will sit in the contract until the next user (or MEV bot) calls `closePositionFarm()`, at which point they will be stolen by that user.

## Vulnerability Detail

When Ichi farming positions are opened via the `IchiVaultSpell.sol` contract, `openPositionFarm()` is called. It goes through the usual deposit function, but rather than staking the LP tokens directly, it calls `wIchiFarm.mint()`. This function deposits the token into the `ichiFarm`, encodes the deposit as an ERC1155, and sends that token back to the Spell:
```solidity
function mint(uint256 pid, uint256 amount)
    external
    nonReentrant
    returns (uint256)
{
    address lpToken = ichiFarm.lpToken(pid);
    IERC20Upgradeable(lpToken).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
    if (
        IERC20Upgradeable(lpToken).allowance(
            address(this),
            address(ichiFarm)
        ) != type(uint256).max
    ) {
        // We only need to do this once per pool, as LP token's all

*[Content truncated...]*

---

### Example 6: H-1: Too few `ICHI` v2 farming reward tokens transferred to the user due to incorrect decimal precision

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

### Example 7: [H-01] Holders array can be manipulated by transferring or burning with amount 0, stealing rewards or bricking certain functions

**Source**: Code4rena
**Protocol**: Althea Liquid Infrastructure
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/main/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L214-L231>

### Impact

`LiquidInfrastructureERC20._beforeTokenTransfer()` checks if the `to` address has a balance of `0`, and if so, adds the address to the holders array.

[LiquidInfrastructureERC20#L142-145](https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/main/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L142-L145)

```solidity
bool exists = (this.balanceOf(to) != 0);
if (!exists) {
    holders.push(to);
}
```

However, the ERC20 contract allows for transferring and burning with `amount = 0`, enabling users to manipulate the holders array.

An approved user that has yet to receive tokens can initiate a transfer from another address to themself with an amount of `0`. This enables them to add their address to the holders array multiple times. Then, `LiquidInfrastructureERC20.distribute()` will loop through the user multiple times and give the user more rewards than it should.

```solidity
for (i = nextDistributionRecipient; i < limit; i++) {
    address recipient = holders[i];
    if (isApprovedHolder(recipient)) {
        uint256[] memory receipts = new uint256[](
            distributableERC20s.length
        );
        for (uint j = 0; j < distributableERC20s.length; j++) {
            IERC20 toDistribute = IERC20(distributableERC20s[j]);
            uint256 entitlement = er

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-althea-liquid-infrastructure)

---

### Example 8: H-1: attackers will keep stealing the `rewards` from Convex SPELL

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/101 

## Found by 
Bauer, Ch\_301
## Summary
On [WConvexPools.burn()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235) transfer [CRV + CVX + the extra rewards](https://docs.convexfinance.com/convexfinance/general-information/why-convex/convex-for-liquidity-providers) to Convex SPELL 


## Vulnerability Detail
But [ConvexSpell.openPositionFarm()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L67-L138) only refund CVX to the user.
So the rest rewards will stay in the SPELL intel if someone (could be an attacker) invokes `_doRefund()` within `closePositionFarm()` with the same address tokens 

## Impact
- Convex SPELL steals the user rewards 
- the protocol will lose some fees 
- attackers will keep stealing the rewards from Convex SPELL

## Code Snippet
`WConvexPools.burn()` transfer CRV + CVX + the extra rewards
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235
```solidity
        // Transfer LP Tokens
        IERC20Upgradeable(lpToken).safeTransfer(msg.sender, amount);

        // Transfer Reward Tokens
        (rewardTokens, rewards) = pendingRewards(id, amount);

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                

*[Content truncated...]*

---

### Example 9: H-10: Immediately start getting rewards belonging to others after staking

**Source**: Sherlock
**Protocol**: Tokemak
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/603 

## Found by 
0x73696d616f, 0xGoodess, 0xJuda, 0xTheC0der, 0xdeadbeef, 0xvj, Ch\_301, Kalyan-Singh, MrjoryStewartBaxter, VAD37, berndartmueller, bin2chen, caelumimperium, carrotsmuggler, jecikpo, l3r0ux, lemonmon, pengun, saidam017, talfao, wangxx2026, xiaoming90

Malicious users could abuse the accounting error to immediately start getting rewards belonging to others after staking, leading to a loss of reward tokens.

## Vulnerability Detail

> **Note**
> This issue affects both LMPVault and DV since they use the same underlying reward contract.

Assume a new user called Bob mints 100 LMPVault or DV shares. The ERC20's `_mint` function will be called, which will first increase Bob's balance at Line 267 and then trigger the `_afterTokenTransfer` hook at Line 271.

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/0457042d93d9dfd760dbaa06a4d2f1216fdbe297/contracts/token/ERC20/ERC20.sol#L259

```solidity
File: ERC20.sol
259:     function _mint(address account, uint256 amount) internal virtual {
..SNIP..
262:         _beforeTokenTransfer(address(0), account, amount);
263: 
264:         _totalSupply += amount;
265:         unchecked {
266:             // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.
267:             _balances[account] += amount;
268:         }
..SNIP..
271:         _afterTokenTransfer(address(0), account, amount);
272:     }
`

*[Content truncated...]*

---

### Example 10: [H-01] Malicious Users Can Duplicate Protocol Earned Yield By Transferring wCVX Tokens To Another Account

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

## Handle

leastwood


## Vulnerability details

## Impact

`ConvexYieldWrapper.sol` is a wrapper contract for staking convex tokens on the user's behalf, allowing them to earn rewards on their deposit. Users will interact with the `Ladle.sol` contract's `batch()` function which:
- Approves Ladle to move the tokens.
- Transfers the tokens to `ConvexYieldWrapper.sol`.
- Wraps/stakes these tokens.
- Updates accounting and produces debt tokens within `Ladle.sol`.

During `wrap()` and `unwrap()` actions, `_checkpoint()` is used to update the rewards for the `from_` and `to_` accounts. However, the [reference](https://github.com/convex-eth/platform/blob/main/contracts/contracts/wrappers/ConvexStakingWrapper.sol#L395-L397) contract implements a `_beforeTokenTransfer()` function which has been removed from Yield Protocol's custom implementation.

As a result, it is possible to transfer `wCVX` tokens to another account after an initial checkpoint has been made. By manually calling `user_checkpoint()` on the new account, this user is able to update its deposited balance of the new account while the sender's balance is not updated. This can be repeated to effectively replicate a user's deposited balance over any number of accounts. To claim yield generated by the protocol, the user must only make sure that the account calling `getReward()` holds the tokens for the duration of the call.

## Proof of Concept

The exploit can be outlined through the following steps:
- Alice receives 100 `

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-yield)

---

### Example 11: H-4: Fail to accrue interests on multiple token positions

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/140 

## Found by 
cducrest-brainbot, rvierdiiev, Jeiwan

## Summary

In `BlueBerryBank.sol` the functions `borrow`, `repay`, `lend`, or `withdrawLend` call `poke(token)` to trigger interest accrual on concerned token, but fail to do so for other token debts of the concerned position.  This could lead to wrong calculation of position's debt and whether the position is liquidatable.

## Vulnerability Detail

Whether a position is liquidatable or not is checked at the end of the `execute` function, the execution should revert if the position is liquidatable. 

The calculation of whether a position is liquidatable takes into account all the different debt tokens within the position. However, the debt accrual has been triggered only for one of these tokens, the one concerned by the executed action. For other tokens, the value of `bank.totalDebt` will be lower than what it should be. This results in the debt value of the position being lower than what it should be and a position seen as not liquidatable while it should be liquidatable. 

## Impact

Users may be able to operate on their position leading them in a virtually liquidatable state while not reverting as interests were not applied. This will worsen the debt situation of the bank and lead to overall more liquidatable positions.

## Code Snippet

execute checking isLiquidatable without triggering interests:

https://github.com/sherlock-audit/2023-02-

*[Content truncated...]*

---

### Example 12: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 13: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/29 

## Found by 
0x52, nobody2018
## Summary

When a user adds to an existing position on AuraSpell, the contract burns their current position and remints them a new one. The issues is that WAuraPool will send all reward tokens to the contract but it only sends Aura back to the user, causing all other rewards to be lost.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L256-L261

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                msg.sender,
                rewards[i]
            );
        }

Inside WAuraPools#burn reward tokens are sent to the user.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L130-L140

        IBank.Position memory pos = bank.getCurrentPositionInfo();
        if (pos.collateralSize > 0) {
            (uint256 pid, ) = wAuraPools.decodeId(pos.collId);
            if (param.farmingPoolId != pid)
                revert Errors.INCORRECT_PID(param.farmingPoolId);
            if (pos.collToken != address(wAuraPools))
                revert Errors.INCORRECT_COLTOKEN(pos.collToken);
            bank.takeCollateral(pos.collateralSize);
            wAuraPools.burn(pos.collId, pos.collateralSize);
            _doRefundRewards(AURA);
        }

We see above that t

*[Content truncated...]*

---

### Example 14: M-3: The protocol  will not be able to add liquidity on the curve with another token with a balance.

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/47 

## Found by 
Bauer, nobody2018
## Summary
The `CurveSpell` protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.

## Vulnerability Detail
The  `openPositionFarm()` function enables user to open a leveraged position in a yield farming strategy by borrowing funds and using them to add liquidity to a Curve pool, while also taking into account certain risk management parameters such as maximum LTV and position size. When add liquidity on curve ,the protocol use the borrowed token and the collateral token, it checks the number of tokens in the pool and creates an array of the supplied token amounts to be passed to the add_liquidity function. Then the curve will transfer the tokens from the protocol and mint lp tokens to the protocol. However, the protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.
```solidity
 // 3. Add liquidity on curve
        _ensureApprove(param.borrowToken, pool, borrowBalance);
        if (tokens.length == 2) {
            uint256[2] memory suppliedAmts;
            for (uint256 i = 0; i < 2; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_

*[Content truncated...]*

---

### Example 15: claimToTreasury(COMP) steals users' COMP rewards

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Medium Risk**

## Context
`compound/MorphoGovernance.sol#L414`

## Description
The `claimToTreasury` function can send a market's underlying tokens that have been accumulated in the contract to the treasury. This is intended to be used for the reserve amounts that accumulate in the contract from P2P matches. However, Compound also pays out rewards in COMP, and COMP is a valid Compound market. 

Sending the COMP reserves will also send the COMP rewards. This is especially concerning as anyone can claim COMP rewards on behalf of Morpho at any time, and the rewards will be sent to the contract. An attacker could even frontrun a `claimToTreasury(cCOMP)` call with a `Comptroller.claimComp(morpho, [cComp])` call to sabotage the reward system, resulting in users being unable to claim their rewards.

## Recommendation
If Morpho wants to support the COMP market, consider separating the COMP reserve from the COMP rewards.

## Morpho Response
Given the changes required and the small likelihood of setting a reserve factor for the COMP asset, and our awareness of this issue, we have decided not to implement it.

## Spearbit Response
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MorphoV1-Spearbit-Security-Review.pdf)

---

### Example 16: H-3: Users are forced to swap all reward tokens with no slippage protection

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/121 

## Found by 
0x52, Bauer, Breeje, J4de, ctf\_sec, n1punp, nobody2018
## Summary

AuraSpell forces users to swap their reward tokens to debt token but doesn't allow them to specify any slippage values.

## Vulnerability Detail

[AuraSpell.sol#L193-L203
](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L193-L203)

        for (uint256 i = 0; i < rewardTokens.length; i++) {
            uint256 rewards = _doCutRewardsFee(rewardTokens[i]);
            _ensureApprove(rewardTokens[i], address(swapRouter), rewards);
            swapRouter.swapExactTokensForTokens(
                rewards,
                0,
                swapPath[i],
                address(this),
                type(uint256).max
            );
        }

Above all reward tokens are swapped and always use 0 for min out meaning that deposits will be sandwiched and stolen.

## Impact

All reward tokens can be sandwiched and stolen

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow user to specify slippage parameters for all reward tokens

---

### Example 17: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

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

### Example 18: M-12: rewardTokens removed from WAuraPool/WConvexPools will be lost forever

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/128 

## Found by 
0x52
## Summary

pendingRewards pulls a fresh count of reward tokens each time it is called. This is problematic if reward tokens are ever removed from the the underlying Aura/Convex pools because it means that they will no longer be distributed and will be locked in the contract forever.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength();
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

In the lines above we can see that only tokens that are currently available 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## defi-vulnerabilities.md
# DeFi Vulnerability Patterns

> **AI Skill**: This file contains real-world DeFi vulnerability patterns extracted from audit reports. Use these patterns to identify similar vulnerabilities in code you're reviewing.

## Quick Reference Index

| Category | Pattern | Severity |
|----------|---------|----------|
| [Pools](#1-liquidity-pool-vulnerabilities) | Slippage Protection, LP Manipulation | High-Medium |
| [Oracles](#2-oracle-vulnerabilities) | TWAP vs Spot, Price Manipulation | Critical-High |
| [Liquidation](#3-liquidation-vulnerabilities) | Cooldown Bypass, Bad Debt | High |
| [Tokens](#4-token-vulnerabilities) | Rebasing, Fee-on-Transfer | High-Medium |
| [Lending](#5-lending-vulnerabilities) | Interest Calculation, Debt Auctions | High |
| [Hooks](#6-hook-vulnerabilities) | Hook Reentrancy, Hook DoS | High-Medium |
| [Math](#7-math-vulnerabilities) | Division, Rounding, Precision | Critical-High |

---

## 1. Liquidity Pool Vulnerabilities

### 1.1 Missing Slippage Protection in Withdraw/Redeem

**Vulnerability**: Vault withdraw/redeem functions allow users to receive fewer assets than expected when underlying yield vault incurs losses.

**Pattern to Look For**:
```solidity
// VULNERABLE: No slippage parameter
function withdraw(uint256 assets) external returns (uint256 shares) {
    shares = previewWithdraw(assets);
    _burn(msg.sender, shares);
    asset.transfer(msg.sender, assets);
}

// VULNERABLE: Exchange rate can change
function convertToAssets(uint256 shares) public view returns (uint256) {
    if (_totalAssets >= totalDebt) {
        return shares;
    } else {
        // Proportional reduction - user may receive less
        return shares.mulDiv(_totalAssets, totalDebt, Math.Rounding.Down);
    }
}
```

**Secure Pattern**:
```solidity
function withdraw(uint256 assets, uint256 minShares) external returns (uint256 shares) {
    shares = previewWithdraw(assets);
    require(shares >= minShares, "Slippage too high");
    // ...
}
```

**Audit Checklist**:
- [ ] Does withdraw/redeem have slippage protection?
- [ ] Can underlying vault incur losses?
- [ ] Is user protected from exchange rate changes?

---

### 1.2 Protocol Assumes Full Liquidity Ownership

**Vulnerability**: Protocol calculates amounts based on total pool reserves instead of protocol-owned liquidity.

**Pattern to Look For**:
```solidity
// VULNERABLE: Uses total reserves, not protocol balance
function reLP() external {
    (uint256 reserveA, uint256 reserveB) = pair.getReserves();
    uint256 lpToRemove = (reserveA * factor) / 1e18;  // Wrong!
    // Should use: pair.balanceOf(address(this))
}
```

**Impact**: If protocol doesn't own majority of LP, calculations fail or revert with underflow.

**Audit Checklist**:
- [ ] Does protocol track its own LP balance separately?
- [ ] Are calculations based on protocol-owned vs total reserves?
- [ ] Can external LPs affect protocol operations?

---

## 2. Oracle Vulnerabilities

### 2.1 TWAP vs Spot Price Mismatch

**Vulnerability**: Using spot prices (manipulable) vs TWAP (resistant) creates arbitrage opportunities and enables liquidation attacks.

**Pattern to Look For**:
```solidity
// VULNERABLE: Chainlink = instant spot, AMM = manipulable spot
function getPrice() public view returns (uint256) {
    uint256 chainlinkPrice = chainlinkFeed.latestAnswer();
    uint256 ammPrice = getAmmSpotPrice();  // Manipulable!
    return (chainlinkPrice + ammPrice) / 2;
}
```

**Attack Scenario**:
1. Flash loan large amount
2. Manipulate AMM spot price
3. Trigger liquidation or arbitrage
4. Repay flash loan with profit

**Secure Pattern**:
```solidity
function getPrice() public view returns (uint256) {
    // Use TWAP for on-chain prices
    uint256 twap = oracle.consult(token, 30 minutes);
    // Or use only trusted oracle with heartbeat checks
    require(block.timestamp - lastUpdate < HEARTBEAT, "Stale price");
}
```

**Audit Checklist**:
- [ ] Is price source TWAP or spot?
- [ ] Can price be manipulated within one transaction?
- [ ] Is there a fallback if oracle fails?
- [ ] Is heartbeat/staleness checked?

---

### 2.2 Stablecoin Depeg During Minting

**Vulnerability**: Protocol assumes stablecoin = $1 USD without validation, allowing excessive minting during depeg events.

**Pattern to Look For**:
```solidity
// VULNERABLE: Assumes USDC = $1
function mint(uint256 usdcAmount) external returns (uint256 tokens) {
    uint256 price = oracle.getRWAPrice();  // Only checks RWA price
    tokens = usdcAmount * 1e18 / price;     // Assumes 1 USDC = 1 USD
    _mint(msg.sender, tokens);
}
```

**Impact**: If USDC depegs to $0.90, attacker mints 11% more tokens than deserved.

**Secure Pattern**:
```solidity
function mint(uint256 usdcAmount) external returns (uint256 tokens) {
    uint256 usdcPrice = usdcOracle.getPrice();  // Check USDC price too
    require(usdcPrice >= MIN_USDC_PRICE, "USDC depeg");
    uint256 actualValue = usdcAmount * usdcPrice / 1e18;
    tokens = actualValue * 1e18 / rwaPrice;
}
```

---

## 3. Liquidation Vulnerabilities

### 3.1 Cooldown Manipulation to Evade Liquidation

**Vulnerability**: Depositing small amounts resets cooldown timer, blocking liquidation.

**Pattern to Look For**:
```solidity
// VULNERABLE: Any deposit resets cooldown
function deposit(uint256 amount) external {
    require(amount >= DUST, "Too small");
    balances[msg.sender] += amount;
    cooldownExpiration[msg.sender] = block.timestamp + COOLDOWN;  // Reset!
}

function liquidate(address user) external {
    require(block.timestamp > cooldownExpiration[user], "Cooldown active");
    // ... liquidation logic
}
```

**Attack**: User front-runs liquidation tx with dust deposit, resetting cooldown.

**Secure Pattern**:
```solidity
function liquidate(address user) external {
    // Check position health regardless of cooldown
    require(isUndercollateralized(user), "Position healthy");
    // Skip cooldown check for underwater positions
    // ... liquidation logic
}
```

---

### 3.2 Bad Debt Creation Cascade

**Vulnerability**: Creating bad debt (credit markdown) forces other auctions to also create bad debt due to snapshot-based debt calculation.

**Pattern to Look For**:
```solidity
// VULNERABLE: Debt snapshot at auction start
function startAuction(bytes32 loanId) external {
    uint256 debt = getLoanDebt(loanId);
    auctions[loanId] = Auction({
        callDebt: debt,  // Snapshot - doesn't update if creditMultiplier changes
        startTime: block.timestamp
    });
}
```

**Problem**: If `creditMultiplier` decreases during auction, `callDebt` underestimates actual debt.

**Audit Checklist**:
- [ ] Is debt calculated dynamically or snapshot?
- [ ] Can external factors change debt during auction?
- [ ] Does bad debt in one loan affect others?

---

### 3.3 USDS Repayment to Wrong Address (POL Exhaustion)

**Vulnerability**: Repaid stablecoins sent to wrong address, forcing Protocol Owned Liquidity to cover the gap.

**Pattern to Look For**:
```solidity
function repay(uint256 amount) external {
    usds.transferFrom(msg.sender, WRONG_ADDRESS);  // Not Liquidizer!
    usdsThatShouldBeBurned += amount;  // Counter increases
    // Liquidizer never receives USDS but counter increases
    // Forces POL to be sold to cover burns
}
```

**Impact**: Attacker can exhaust POL by repeatedly borrowing and repaying.

---

## 4. Token Vulnerabilities

### 4.1 Rebasing Token Approval Exploit

**Vulnerability**: Rebasing tokens change balances based on factor; approvals calculated incorrectly.

**Pattern to Look For**:
```solidity
// VULNERABLE: Approval based on fragments, not gons
function transferAllowance(address router, uint256 amount) external {
    token.approve(router, amount);  // Fixed fragment amount
    // After rebase, this approval allows more/fewer gons
}
```

**Attack Scenario**:
1. Deposit 1000 tokens when rebase factor = 1
2. Wait for rebase factor = 2 (balances halved)
3. Approval still allows transferring 1000 fragments
4. But 1000 fragments now = 2000 gons worth of value

**Audit Checklist**:
- [ ] Does protocol support rebasing tokens?
- [ ] Are approvals gon-based or fragment-based?
- [ ] Is balance tracking gon-based?

---

### 4.2 Fee-on-Transfer Token Handling

**Vulnerability**: Protocol assumes received amount equals sent amount; fee-on-transfer tokens break this.

**Pattern to Look For**:
```solidity
// VULNERABLE: Assumes full amount received
function _transferOutAndCallV5(address token, uint256 amount) internal {
    token.transfer(aggregator, amount);
    aggregator.swapOut(amount);  // Aggregator may receive less!
}
```

**Secure Pattern**:
```solidity
function safeTransfer(address token, uint256 amount) internal returns (uint256 received) {
    uint256 balanceBefore = token.balanceOf(recipient);
    token.transfer(recipient, amount);
    received = token.balanceOf(recipient) - balanceBefore;
    // Use 'received' for subsequent operations
}
```

---

## 5. Lending Vulnerabilities

### 5.1 Zero Interest Partial Repay Blocked

**Vulnerability**: Partial repay requires non-zero interest, blocking repayment for zero-interest loans.

**Pattern to Look For**:
```solidity
// VULNERABLE: interestRepaid check
function _partialRepay(bytes32 loanId, uint256 amount) internal {
    uint256 interestRepaid = calculateInterest(loanId, amount);
    require(interestRepaid != 0, "repay too small");  // Blocks 0% loans!
    // ... repayment logic
}
```

**Fix**: Remove `interestRepaid != 0` check or handle zero-interest case separately.

---

### 5.2 Gauge Weight Manipulation

**Vulnerability**: Tolerance factor allows unstaking despite full debt allocation.

**Pattern to Look For**:
```solidity
// Protocol allows 120% debt ceiling via tolerance
function getDebtCeiling(address gauge) public view returns (uint256) {
    uint256 gaugeWeight = getGaugeWeight(gauge);
    uint256 ceiling = (gaugeWeight * totalBorrowed) / totalWeight;
    return ceiling * 120 / 100;  // 20% tolerance
}
```

**Attack**: Exploit tolerance to unstake ~16.6% of weight each time, eventually unstaking 90%+ while debt remains at "100%".

---

## 6. Hook Vulnerabilities

### 6.1 Prize Claim Fee Theft via Hooks

**Vulnerability**: Hook allows user to claim prize directly, avoiding claimer fees.

**Pattern to Look For**:
```solidity
// VULNERABLE: beforeClaimPrize hook can claim directly
function beforeClaimPrize(address winner, uint8 tier, uint32 prizeIndex) external {
    // Malicious hook claims prize here, returns winner address
    prizePool.claimPrize(winner, tier, prizeIndex, winner, 0, address(0));
    // Claimer's subsequent claim fails - prize already claimed
}
```

**Defense**: Check prize state before/after hook execution; revert if claimed during hook.

---

### 6.2 BeforeSend Hook DoS Attack

**Vulnerability**: Token creator sets BeforeSendHook to invalid address, blocking all transfers.

**Pattern to Look For**:
```go
// VULNERABLE: Any address can be hook
func (k Keeper) SetBeforeSendHook(denom string, hookAddr string) error {
    // No validation that hookAddr is valid contract
    k.beforeSendHooks[denom] = hookAddr
}
```

**Impact**: Staking rewards distribution fails, ABCI processes break.

**Defense**: Whitelist valid hook contracts or require hook address validation.

---

## 7. Math Vulnerabilities

### 7.1 Missing Remainder < Divisor Constraint

**Vulnerability**: Division opcode doesn't verify remainder is less than divisor.

**zkSync/ZK Context**:
```rust
// VULNERABLE: No constraint that remainder < divisor
let (q, r) = src0.div_mod(src1);
// Attacker can submit invalid proof with r >= divisor
```

**Impact**: Malicious validator can manipulate DEX calculations, steal assets.

---

### 7.2 Debt Calculation with Changing Multiplier

**Vulnerability**: Debt snapshot doesn't account for credit multiplier changes during auction.

**Pattern**:
```solidity
// At auction start: debt = principal * creditMultiplier_start
// If creditMultiplier decreases during auction:
// Actual debt = principal * creditMultiplier_current < callDebt
// But callDebt is frozen at snapshot value
```

**Fix**: Calculate debt dynamically using current `creditMultiplier`.

---

## 8. EVM Data Location Vulnerabilities

### 8.1 Storage vs Memory Confusion

**Vulnerability**: Using `memory` when `storage` is needed causes updates to not persist.

**Pattern to Look For**:
```solidity
// VULNERABLE: Creates memory copy, original unchanged
function updateUser(address user) internal {
    User memory userData = users[user];  // Memory copy!
    userData.balance += 100;
    // Changes lost - should be `storage`
}

// CORRECT
function updateUser(address user) internal {
    User storage userData = users[user];
    userData.balance += 100;  // Persists
}
```

---

### 8.2 Log Sorter Queue Manipulation

**Vulnerability**: Sorted queue in log sorter can be manipulated to emit reverted logs.

**zkSync Context**: Two adjacent logs with same timestamp can be submitted as `wr rw wr rw` pattern, causing reverted logs to appear in result queue.

---

## Audit Integration Prompts

### For Pool Audits
```
Analyze this pool contract for:
1. Slippage protection in withdraw/redeem
2. Proper tracking of protocol-owned vs total liquidity
3. LP token handling edge cases
4. Flash loan attack vectors on reserves
```

### For Oracle Audits
```
Check this oracle integration for:
1. TWAP vs spot price usage
2. Staleness/heartbeat validation
3. Fallback oracle availability
4. Stablecoin depeg handling
5. Multi-block manipulation resistance
```

### For Lending Audits
```
Review this lending protocol for:
1. Interest calculation in edge cases (0% APR)
2. Debt snapshot vs dynamic calculation
3. Bad debt cascade scenarios
4. Collateral value during liquidation
5. Cooldown manipulation vectors
```

### For Token Audits
```
Check token integration for:
1. Rebasing token support
2. Fee-on-transfer handling
3. Approval amount vs actual transfer
4. Balance tracking accuracy
5. Hook attack surfaces
```

---

## Cross-Reference Sources

| Pattern | Source Report | Protocol |
|---------|--------------|----------|
| Slippage Protection | Code4rena 2024-03 | PoolTogether |
| LP Manipulation | Code4rena 2023-08 | Dopex |
| TWAP vs Spot | Code4rena 2024-01 | Salty |
| Cooldown Bypass | Code4rena 2024-01 | Salty |
| Bad Debt Cascade | Code4rena 2023-12 | Ethereum Credit Guild |
| Rebasing Tokens | Code4rena 2024-06 | THORChain |
| Fee-on-Transfer | Code4rena 2024-06 | THORChain |
| Hook DoS | Code4rena 2024-11 | MANTRA Chain |
| Zero Interest | Code4rena 2023-12 | Ethereum Credit Guild |
| Gauge Manipulation | Code4rena 2023-12 | Ethereum Credit Guild |

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - General vulnerability patterns
- [severity-scoring.md](severity-scoring.md) - How to score findings
- [comprehensive-checklist.md](../checklists/comprehensive-checklist.md) - Full audit checklist


