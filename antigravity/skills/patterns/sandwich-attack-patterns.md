---
id: PAT-SANDWICH-ATTACK
title: Sandwich Attack Security Patterns
category: mev
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - sandwich
  - mev
  - front-running

finding_count: 19
last_updated: 2026-01-31
---
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

