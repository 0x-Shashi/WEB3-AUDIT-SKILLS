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

### Example 12: [M-08] User fund loss because function purchaseLiquidationAuctionNFT() takes extra liquidation penalty when user’s last collateral is liquidated, (set wrong value for maxDebtCached when isLastCollateral is true)

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

Inside LoanVault.sol’s liquidate() it is checked if the debtAmount (initial debt amount when loan was created) is now equal to the balance of debt token in the vault , if not revert (L163)

An attacker can see a liquidation() call in the mempool and ->

a.) Frontruns this call to send the lowest amount of debt token to the vault , say 1
b.) Now when the liquidator tries to liquidate he sends out debtAmount of tokens to the vault , let’s say they were 100
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
