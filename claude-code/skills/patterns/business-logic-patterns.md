---
id: PAT-BUSINESS-LOGIC
title: Business Logic Security Patterns
category: logic
severity: high
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - logic
  - flow
  - condition

finding_count: 234
last_updated: 2026-01-31
---
# Business Logic Security Patterns

## Overview

**Frequency**: 234 occurrences (0.46% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 100 | 127 | 7 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, Pashov Audit Group, Trust Security

---

## Detection Checklist

- [ ] Check for business logic vulnerabilities in all external functions
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

### Example 2: [H-01] Too many rewards are distributed when a draw is closed

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L178-L184><br>
<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L154-L157><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/PrizePool.sol#L366><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/abstract/TieredLiquidityDistributor.sol#L374>

A relayer completes a prize pool draw by calling `rngComplete` in `RngRelayAuction.sol`. This method closes the prize pool draw with the relayed random number and distributes the rewards to the RNG auction recipient and the RNG relay auction recipient. These rewards are calculated based on a fraction of the prize pool reserve rather than an actual value.

However, the current reward calculation mistakenly includes an extra `reserveForOpenDraw` amount just after the draw has been closed. Therefore the fraction over which the rewards are being calculated includes tokens that have not been added to the reserve and will actually only be added to the reserve when the next draw is finalised. As a result, the reward recipients are rewarded too many tokens.

### Proof of Concept

Before deciding whether or not to relay an auction result, a bot can call `computeRewards` to calculate how many rewards they'll be getting based on

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-pooltogether)

---

### Example 3: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

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

### Example 4: Refactor _paymentAH()

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: 
**High Risk**

## Context: 
**LienToken.sol#L571**

## Description: 
The `_paymentAH()` function has several vulnerabilities:

- The `stack` parameter is defined as a memory parameter, so any updates made to `stack` do not reflect back in the corresponding storage variable.
- There is no need to update `stack[position]` as it is deleted later.
- The function `decreaseEpochLienCount()` is always passed `0`, as `stack[position]` has already been deleted. Furthermore, `decreaseEpochLienCount()` expects `epoch`, but `end` is passed instead.
- The if/else block can be merged. The function `updateAfterLiquidationPayment()` expects `msg.sender` to be `LIEN_TOKEN`, which should work as expected.

## Recommendation:
Apply the following diff:

```solidity
function _paymentAH(
    LienStorage storage s,
    uint256 collateralId,
    - AuctionStack[] memory stack,
    + AuctionStack[] storage stack,
    uint256 position,
    uint256 payment,
    address payer
) internal returns (uint256) {
    uint256 lienId = stack[position].lienId;
    uint256 end = stack[position].end;
    uint256 owing = stack[position].amountOwed;

    //checks the lien exists
    address owner = ownerOf(lienId);
    address payee = _getPayee(s, lienId);

    - if (owing > payment.safeCastTo88()) {
    -     stack[position].amountOwed -= payment.safeCastTo88();
    - } else {
    + if (owing < payment.safeCastTo88()) {
        payment = owing;
    }

    s.TRANSFER_PROXY.tokenT

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: Incorrect auction end validation in liquidatorNFTClaim()

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`CollateralToken.sol#L119`

## Description
The function `liquidatorNFTClaim()` includes a check to determine if a Seaport auction has ended:

```solidity
if (block.timestamp < params.endTime) {
    // auction hasn't ended yet
    revert InvalidCollateralState(InvalidCollateralStates.AUCTION_ACTIVE);
}
```

In this scenario, `params` is completely controlled by users. To bypass this check, the caller can set `params.endTime` to a value less than `block.timestamp`. 

A possible exploit scenario occurs when `AstariaRouter.liquidate()` is called to list the underlying asset on Seaport, which also sets the liquidator address. Consequently, anyone can call `liquidatorNFTClaim()` to transfer the underlying asset to the liquidator by setting `params.endTime < block.timestamp`.

## Recommendation
The parameter passed to `liquidatorNFTClaim()` should be validated against the parameters created for the Seaport auction. To achieve this:

- Update the `collateralIdToAuction` mapping, which currently maps `collateralId` to a boolean value indicating an active auction, to instead map from `collateralId` to the Seaport order hash.
- All usages of `collateralIdToAuction` should be updated. For instance, `isValidOrder()` and `isValidOrderIncludingExtraData()` should be modified as follows:

```solidity
return
    s.collateralIdToAuction[uint256(zoneHash)] == orderHash
        ? ZoneInterface.isValidOrder.selector
        : bytes4(0xffffffff);
```

- The `liqu

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 6: VaultImplementation.buyoutLien can be DoSed by calls to LienToken.buyoutLien

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
- LienToken.sol#L102
- LienToken.sol#L121
- VaultImplementation.sol#L305

### Description
Anyone can call into `LienToken.buyoutLien` and provide params of the type `LienActionBuyout`:  
`params.incoming` is not used, so for example, vault signatures or strategy validation is skipped. There are a few checks for `params.encumber`.

Let's define the following variables:

| Parameter | Value |
|-----------|-------|
| i         | params.position |
| kj        | params.encumber.stack[j].point.position |
| tj        | params.encumber.stack[j].point.last |
| ej        | params.encumber.stack[j].point.end |
| e0       | itnow+D0 |
| i         | lj params.encumber.stack[j].point.lienId |
| l0       | ih(N0 i,V0 i,S0 i,c0 i, (A0max i,r0 i,D0 i,P0 i,L0 i)) where h is the keccak256 of the encoding |
| rj        | params.encumber.stack[j].lien.details.rate : old rate |
| r0       | params.encumber.lien.details.rate : new rate |
| c         | params.encumber.collateralId |

| Parameter | Value |
|-----------|-------|
| cj        | params.encumber.stack[j].lien.collateralId |
| c0       | params.encumber.lien.collateralId |
| Aj        | params.encumber.stack[j].point.amount |
| A0       | params.encumber.amount |
| Amax     | params.encumber.stack[j].lien.details.maxAmount |
| A0max    | params.encumber.lien.details.maxAmount |
| R         | params.encumber.receiver |
| Nj        | params.encumber.stack[j].lien.token |
| N0      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 7: OperatorsRegistry._getNextValidatorsFromActiveOperators can DOS Alluvial staking if there's anoperator with funded==stopped and funded == min(limit, keys)

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
OperatorsRegistry.1.sol#L403-L454

## Description
This issue is also related to `OperatorsRegistry._getNextValidatorsFromActiveOperators` which should not consider stopped when picking a validator.

Consider a scenario where we have:

### Operators
- **Op at index 0**
  - Name: `op1`
  - Active: `true`
  - Limit: `10`
  - Funded: `10`
  - Stopped: `10`
  - Keys: `10`

- **Op at index 1**
  - Name: `op2`
  - Active: `true`
  - Limit: `10`
  - Funded: `0`
  - Stopped: `0`
  - Keys: `10`

In this case:
- Op1 got all 10 keys funded and exited. Because it has `keys=10` and `limit=10`, it means that it has no more keys to get funded again.
- Op2 instead has still 10 approved keys to be funded.

Because of how the selection of the picked validator works:

```solidity
uint256 selectedOperatorIndex = 0;
for (uint256 idx = 1; idx < operators.length;) {
    if (
        operators[idx].funded - operators[idx].stopped <
        operators[selectedOperatorIndex].funded - operators[selectedOperatorIndex].stopped
    ) {
        selectedOperatorIndex = idx;
    }
    unchecked {
        ++idx;
    }
}
```

When the function finds an operator with `funded == stopped`, it will pick that operator because `0 < operators[selectedOperatorIndex].funded - operators[selectedOperatorIndex].stopped`.

After the loop ends, `selectedOperatorIndex` will be the index of an operator that has no more validators to be funded (for this scenario). Because of this, the follo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 8: [H-01] Borrowers may earn auction proceeds without filling the debt shortfall

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

### Example 9: Missing mirrorConnector check on Optimism hub connector

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`OptimismHubConnector.sol#L69-L121`

## Description
The `processMessageFromRoot()` function calls `_processMessage()` to process messages for the "fast" path. However, `_processMessage()` can also be invoked by the AMB in the slow path. 

The second call to `_processMessage()` is unnecessary and could lead to double processing of the message. This issue is mitigated somewhat by the `processed[]` mapping, which prevents double processing. However, the second call (from the AMB directly to `_processMessage()`) does not properly verify the origin of the message, potentially allowing for the insertion of fraudulent messages.

```solidity
function processMessageFromRoot(...) {
    ...
    _processMessage(abi.encode(_data));
    ...
}

function _processMessage(bytes memory _data) internal override {
    // sanity check root length
    require(_data.length == 32, "!length");
    // get root from data
    bytes32 root = bytes32(_data);
    if (!processed[root]) {
        // set root to processed
        processed[root] = true;
        // update the root on the root manager
        IRootManager(ROOT_MANAGER).aggregate(MIRROR_DOMAIN, root);
    } // otherwise root was already sent to root manager
}
```

## Recommendation
Remove the second path.

## Connext
Solved in PR 2447.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 10: swapInternal() shouldn't use msg.sender

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- BridgeFacet.sol#L337-L369
- BridgeFacet.sol#L659-L750
- AssetLogic.sol#L150-L182
- AssetLogic.sol#L229-L262
- SwapUtils.sol#L798-L826

## Description
As reported by the Connext team, the internal stable swap checks if `msg.sender` has sufficient funds in `onexecute()`. This `msg.sender` is the relayer which normally wouldn't have these funds, so the swaps would fail. The local funds should come from the Connext diamond itself.

### BridgeFacet.sol
```solidity
function execute(ExecuteArgs calldata _args) external nonReentrant whenNotPaused returns (bytes32) {
    ...
    (uint256 amountOut, address asset, address local) = _handleExecuteLiquidity(...);
    ...
}
```

### AssetLogic.sol
```solidity
function swapFromLocalAssetIfNeeded(...) ... {
    ...
    return _swapAsset(...);
}
```

### SwapUtils.sol
```solidity
function swapInternal(...) ... {
    IERC20 tokenFrom = self.pooledTokens[tokenIndexFrom];
    require(dx <= tokenFrom.balanceOf(msg.sender), "more than you own"); // msg.sender is the relayer
    ...
}
```

## Recommendation
Don't use the balance of `msg.sender`.

## Connext
Solved in PR 2120.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 11: [H-08] function withdrawETH from GiantMevAndFeesPool can steal most of eth because of idleETH is reduced before burning token

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantPoolBase.sol#L57-L60
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L176-L178
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L76-L90


## Vulnerability details

## Impact

The contract GiantMevAndFeesPool override the function totalRewardsReceived:
```
return address(this).balance + totalClaimed - idleETH;
```
The function totalRewardsReceived is used as the current rewards balance to caculate the unprocessed rewards in the function `SyndicateRewardsProcessor._updateAccumulatedETHPerLP`
```
uint256 received = totalRewardsReceived();
uint256 unprocessed = received - totalETHSeen;
```
But it will decrease the `idleETH` first and then burn the lpTokenETH in the function `GiantMevAndFeesPool.withdrawETH`. The lpTokenETH burn option will trigger `GiantMevAndFeesPool.beforeTokenTransfer` which will call _updateAccumulatedETHPerLP and send the accumulated rewards to the msg sender. Because of the diminution of the idleETH, the `accumulatedETHPerLPShare` is added out of thin air. So the attacker can steal more eth from the GiantMevAndFeesPool.

## Proof of Concept
I wrote a test file for proof, but there is another bug/vulnerability which will make the `GiantMevAndFeesPool.withdrawETH` function break down. I submitted it as the other finding named "Gian

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 12: [H-05] Borrower can craft a borrow that cannot be liquidated, even by arbiter. 

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L516-L538


## Vulnerability details

## Description

LineOfCredit manages an array of open credit line identifiers called `ids`. Many interactions with the Line operate on ids\[0\], which is presumed to be the oldest borrow which has non zero principal. For example, borrowers must first deposit and repay to ids\[0\] before other credit lines.

The list is managed by several functions:

1.  CreditListLib.removePosition - deletes parameter id in the ids array
2.  CreditListLib.stepQ - rotates all ids members one to the left, with the leftmost becoming the last element
3.  _sortIntoQ - most complex function, finds the smallest index which can swap identifiers with the parameter id, which satisfies the conditions:
    1.  target index is not empty
    2.  there is no principal owed for the target index's credit

The idea I had is that if we could corrupt the ids array so that ids\[0\] would be zero, but after it there would be some other active borrows, it would be a very severe situation. The whileBorrowing() modifier assumes if the first element has no principal, borrower is not borrowing.

```
modifier whileBorrowing() {
    if(count == 0 || credits[ids[0]].principal == 0) { revert NotBorrowing(); }
    _;
}
```

It turns out there is a simple sequence of calls which allows borrowing while ids\[0\] is deleted, and does not re-ar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 13: [H-04] Borrower can close a credit without repaying debt

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

A borrower can close a credit without repaying the debt to the lender. The lender will be left with a bad debt and the borrower will keep the borrowed amount and the collateral.

### Proof of Concept

The `close` function of `LineOfCredit` doesn't check whether a credit exists or not. As a result, the `count` variable is decreased in the internal `_close` function when the `close` function is called with an non-existent credit ID:
[LineOfCredit.sol#L388](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L388):

```solidity
function close(bytes32 id) external payable override returns (bool) {
    Credit memory credit = credits[id];
    address b = borrower; // gas savings
    if(msg.sender != credit.lender && msg.sender != b) {
      revert CallerAccessDenied();
    }

    // ensure all money owed is accounted for. Accrue facility fee since prinicpal was paid off
    credit = _accrue(credit, id);
    uint256 facilityFee = credit.interestAccrued;
    if(facilityFee > 0) {
      // only allow repaying interest since they are skipping repayment queue.
      // If principal still owed, _close() MUST fail
      LineLib.receiveTokenOrETH(credit.token, b, facilityFee);

      credit = _repay(credit, id, facilityFee);
    }

    _close(credit, id); // deleted; no need to save to storage

    return true;
}
```

[LineOfCredit.sol#L483](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8da

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 14: [H-03] addCredit / increaseCredit cannot be called by lender first when token is ETH

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

<https://github.com/debtdao/Line-of-Credit/blob/f32cb3eeb08663f2456bf6e2fba21e964da3e8ae/contracts/modules/credit/LineOfCredit.sol#L234>

<https://github.com/debtdao/Line-of-Credit/blob/f32cb3eeb08663f2456bf6e2fba21e964da3e8ae/contracts/modules/credit/LineOfCredit.sol#L270>

### Impact

The functions `addCredit` and `increaseCredit` both ahve a `mutualConsent` or `mutualConsentById` modifier. Furthermore, these functions are `payable` and the lender needs to send the corresponding ETH with each call. However, if we look at the mutual consent modifier works, we can have a problem:

```solidity
modifier mutualConsent(address _signerOne, address _signerTwo) {
      if(_mutualConsent(_signerOne, _signerTwo))  {
        // Run whatever code needed 2/2 consent
        _;
      }
}

function _mutualConsent(address _signerOne, address _signerTwo) internal returns(bool) {
        if(msg.sender != _signerOne && msg.sender != _signerTwo) { revert Unauthorized(); }

        address nonCaller = _getNonCaller(_signerOne, _signerTwo);

        // The consent hash is defined by the hash of the transaction call data and sender of msg,
        // which uniquely identifies the function, arguments, and sender.
        bytes32 expectedHash = keccak256(abi.encodePacked(msg.data, nonCaller));

        if (!mutualConsents[expectedHash]) {
            bytes32 newHash = keccak256(abi.encodePacked(msg.data, msg.sender));

            mutualConsents[newHash] = true;

            emit MutualConsentRegist

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 15: [H-02] Non-existing revenue contract can be passed to claimRevenue to send all tokens to treasury

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

Neither `SpigotLib.claimRevenue` nor `SpigotLib._claimRevenue` check that the provided `revenueContract` was registered before. If this is not the case, `SpigotLib._claimRevenue` assumes that this is a revenue contract with push payments (because `self.settings[revenueContract].claimFunction` is 0) and just returns the difference since the last call to `claimRevenue`:

```solidity
       if(self.settings[revenueContract].claimFunction == bytes4(0)) {
            // push payments

            // claimed = total balance - already accounted for balance
            claimed = existingBalance - self.escrowed[token]; //@audit Rebasing tokens
            // underflow revert ensures we have more tokens than we started with and actually claimed revenue
        }
```

`SpigotLib.claimRevenue` will then read `self.settings[revenueContract].ownerSplit`, which is 0 for non-registered revenue contracts:

```solidity
uint256 escrowedAmount = claimed * self.settings[revenueContract].ownerSplit / 100;
```

Therefore, the whole `claimed` amount is sent to the treasury.

This becomes very problematic for revenue tokens that use push payments. An attacker (in practice the borrower) can just regularly call `claimRevenue` with this token and a non-existing revenue contract. All of the tokens that were sent to the spigot since the last call will be sent to the treasury and none to the escrow, i.e. a borrower can ensure that no revenue will be available for the lender, no matter what the configured s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 16: reimburseLiquidityFees send tokens twice

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## High Risk Report

## Severity 
High Risk

## Context 
- **Files**: 
  - BridgeFacet.sol (Lines 644-675)
  - SponsorVault.sol (Lines 197-226)
  - ITokenExchange.sol (Lines 18-24)

## Description 
The function `reimburseLiquidityFees()` is called from the `BridgeFacet`, making the `msg.sender` within this function to be the `BridgeFacet`. 

When using token exchanges via `swapExactIn()`, tokens are sent to `msg.sender`, which is the `BridgeFacet`. Then, tokens are sent again to `msg.sender` via `safeTransfer()`, which is also the `BridgeFacet`. Therefore, tokens end up being sent to the `BridgeFacet` twice.

**Note:** The check `...balanceOf(...) != starting + sponsored` should fail too.

**Note:** The fix in C4 seems to introduce this issue: `code4rena-246`.

### Code Snippet
```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction(...) ... {
        ...
        uint256 starting = IERC20(_asset).balanceOf(address(this));
        ...
        (bool success, bytes memory data) = address(s.sponsorVault).call(
            abi.encodeWithSelector(s.sponsorVault.reimburseLiquidityFees.selector, _asset, _args.amount, _args.params.to)
        );
        if (success) {
            uint256 sponsored = abi.decode(data, (uint256));
            // Validate correct amounts are transferred
            if (IERC20(_asset).balanceOf(address(this)) != starting + sponsored) { // this should fail now
                revert BridgeFacet__handleExecuteTransaction

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 17: SponsorVault sponsors full transfer amount in reimburseLiquidityFees()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

**Severity**: High Risk  
**Context**: BridgeFacet.sol#L660-L663  
**Description**: The `BridgeFacet` passes `args.amount` as `_liquidityFee` when calling `reimburseLiquidityFees`. Instead of sponsoring `liquidityFee`, the sponsor vault would sponsor the full transfer amount to the receiver. 

**Note**: Luckily, the amount in `reimburseLiquidityFees` is capped by `relayerFeeCap`.  
```solidity
function _handleExecuteTransaction(...) ... {
    ...
    (bool success, bytes memory data) = address(s.sponsorVault).call(
        abi.encodeWithSelector(s.sponsorVault.reimburseLiquidityFees.selector, _asset, _args.amount, _args.params.to), 
        ! 
    );
}
```

**Recommendation**: Pass `args.amount * (s.LIQUIDITY_FEE_DENOMINATOR - s.LIQUIDITY_FEE_NUMERATOR) / s.LIQUIDITY_FEE_DENOMINATOR` instead.  
**Connext**: Solved in PR 1551.  
**Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 18: Executor reverts on receiving native tokens from BridgeFacet

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- **File:** Executor.sol 
- **Line:** BridgeFacet.sol#L696, AssetLogic.sol#L127-L151

## Description
When doing an external call in `execute()`, the `BridgeFacet` provides liquidity into the `Executor` contract before calling `Executor.execute`. The `BridgeFacet` transfers a native token when an `address(wrapper)` is provided. However, the `Executor` does not have a fallback or receive function. Hence, the transaction will revert when the `BridgeFacet` tries to send the native token to the `Executor` contract.

```solidity
function _handleExecuteTransaction(
    ...
    AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
    (bool success, bytes memory returnData) = s.executor.execute(...);
    ...
}
```

```solidity
function transferAssetFromContract(...) {
    ...
    if (_assetId == address(s.wrapper)) {
        // If dealing with wrapped assets, make sure they are properly unwrapped
        // before sending from contract
        s.wrapper.withdraw(_amount);
        Address.sendValue(payable(_to), _amount);
    } else {
        ...
    }
}
```

## Recommendation
It is recommended to add a receive function in the `Executor` contract:

```solidity
receive() payable external {
    require(msg.sender == connext);
}
```

Alternatively, unwrap the native asset and send it along with the call to the executor.

- **Connext:** Ether sent along with the call. Solved in PR 1532.
- **Spearbit:** Verified.
- **Connext:** Alter

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 19: Executor andAssetLogic deals with the native tokens inconsistently that breaks execute()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
- `Executor.sol#L142`
- `AssetLogic.sol#L127-L151`
- `BridgeFacet.sol#L644-L718`

### Description
When dealing with an external callee, the `BridgeFacet` will transfer liquidity to the `Executor` before calling `Executor.execute`.

In order to send the native token:
- The `Executor` checks for `_args.assetId == address(0)`.
- `AssetLogic.transferAssetFromContract()` disallows `address(0)`.

**Note:** Also see the issue: "Executor reverts on receiving native tokens from BridgeFacet."

```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction() ... {
        ...
        AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount); // _asset may not be 0, !
        (bool success, bytes memory returnData) = s.executor.execute(
            IExecutor.ExecutorArgs(
                ...
                _asset, // assetId parameter from ExecutorArgs // must be 0 for Native asset
                ...
            )
        );
        ...
    }
}
```

```solidity
library AssetLogic {
    function transferAssetFromContract(address _assetId, ...) {
        ...
        // No native assets should ever be stored on this contract
        if (_assetId == address(0)) revert AssetLogic__transferAssetFromContract_notNative();
        if (_assetId == address(s.wrapper)) {
            // If dealing with wrapped assets, make sure they are properly unwrapped before sending from contract
       

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 20: _handleExecuteTransaction() doesnt handle native assets correctly

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

**Severity:** High Risk  
**Context:** BridgeFacet.sol#L644-L718, Executor.sol#L142-L243  

**Description:**  
The function `_handleExecuteTransaction()` sends any native tokens to the executor contract first, and then calls `s.executor.execute()`. This means that within that function, `msg.value` will always be 0. As a result, the associated logic that uses `msg.value` doesnt work as expected, leading to incorrect handling of native assets.

**Note:**  
Also see issue "Executor reverts on receiving native tokens from BridgeFacet".

```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction(...) {
        ...
        AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
        (bool success, bytes memory returnData) = s.executor.execute(...); // no native tokens sent
    }
}
```

```solidity
contract Executor is IExecutor {
    function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
        ...
        if (isNative && msg.value != _args.amount) { // msg.value is always 0
            ...
        }
    }
}
```

**Recommendation:**  
Change the code of `execute()` to handle previously sent native assets. Alternatively, send the native assets along with the call to `execute()`.

**Connext:** Solved in PR 1532.  
**Spearbit:** Verified.  
**Connext:** Alternate approach: removed native asset handling. Implemented in PR 31.  
**Spearbit:** Verified

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 21: Upon failing to back unbacked debt _reconcileProcessPortal() will leave the converted asset in the contract

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
`NomadFacet.sol#L225-L242`

## Description
When routers front liquidity for the protocols users, they are later reconciled once the bridge has optimistically verified transfers from the source chain. Upon being reconciled, the `_reconcileProcessPortal()` attempts to first pay back Aave debt before distributing the rest back to the router. However, `_reconcileProcessPortal()` will not convert the adopted asset back to the local asset in the case where the call to the Aave pool fails.

Instead, the function will set `amountIn = 0` and continue to distribute the local asset to the router.

```solidity
if (success) {
    emit AavePortalRepayment(_transferId, adopted, backUnbackedAmount, portalFee);
} else {
    // Reset values
    s.portalDebt[_transferId] += backUnbackedAmount;
    s.portalFeeDebt[_transferId] += portalFee;
    // Decrease the allowance
    SafeERC20.safeDecreaseAllowance(IERC20(adopted), s.aavePool, totalRepayAmount);
    // Update the amount repaid to 0, so the amount is credited to the router
    amountIn = 0;
    emit AavePortalRepaymentDebt(_transferId, adopted, s.portalDebt[_transferId],
                                 s.portalFeeDebt[_transferId]);
}
```

## Recommendation
It might be useful to convert the adopted asset amount back to the local asset such that subsequent swaps do not fail due to an insufficient amount of local asset. Alternatively, if the attempt to back unbacked debt fails, cons

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 22: Deriving price with balanceOf is dangerous

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`ConnextPriceOracle.sol#L109-L135`

## Description
The function `getPriceFromDex` derives the price by querying the balance of AMMs pools.

```solidity
function getPriceFromDex(address _tokenAddress) public view returns (uint256) {
    PriceInfo storage priceInfo = priceRecords[_tokenAddress];
    ...
    uint256 rawTokenAmount = IERC20Extended(priceInfo.token).balanceOf(priceInfo.lpToken);
    ...
    uint256 rawBaseTokenAmount = IERC20Extended(priceInfo.baseToken).balanceOf(priceInfo.lpToken);
    ...
}
```

Deriving the price with `balanceOf` is dangerous as `balanceOf` may be gamed. Consider Uniswap V2 as an example; exploiters can first send tokens into the pool and pump the price, then absorb the tokens that were previously donated by calling `mint`.

## Recommendation
Consider querying DEXs state through function calls such as Uniswap V2s `getReserves()` which returns the correct state of the pool.

## References
- **Connext**: Solved in PR 1649.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 23: MatchingEngineForAave is using the wrong totalSupply in updateBorrowers

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Risk Assessment

## Severity
**Critical Risk**

## Context
`MatchingEngineForAave.sol#L376-L385`

## Description
The `_poolTokenAddress` is referencing `AToken`, so the `totalStaked` would be the total supply of the `AToken`. In this case, the `totalStaked` should reference the total supply of the `DebtToken`; otherwise, the user would be rewarded for a wrong amount of reward.

## Recommendation
Use the correct token address to query `scaledTotalSupply` as follows:

```solidity
address variableDebtTokenAddress = lendingPool
    .getReserveData(IAToken(_poolTokenAddress).UNDERLYING_ASSET_ADDRESS())
    .variableDebtTokenAddress;

uint256 totalStaked = IScaledBalanceToken(variableDebtTokenAddress).scaledTotalSupply();
```

## Spearbit
Fixed; recommendation was implemented in the PR #554.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 24: Order of calls to removeValidators can affect the resulting validator keys set

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
OperatorsRegistry.1.sol#L310

## Description
If two entities A and B (which can be either the admin or the operator O with the index I) send a call to `removeValidators` with 2 different sets of parameters:

- T1: (I, R1)
- T2: (I, R2)

Then, depending on the order of transactions, the resulting set of validators for this operator might be different. Since either party might not know a priori if any other transaction is going to be included on the blockchain after they submit their transaction, they don't have a 100 percent guarantee that their intended set of validator keys are going to be removed.

This also opens an opportunity for either party to DoS the other party's transaction by frontrunning it with a call to remove enough validator keys to trigger the `InvalidIndexOutOfBounds` error:

```solidity
OperatorsRegistry.1.sol#L324-L326:
if (keyIndex >= operator.keys) {
    revert InvalidIndexOutOfBounds();
}
```

## Recommendation
We can send a snapshot block parameter to `removeValidators` and compare it to a stored field for the operator to ensure there have not been any changes to the validator key set since that snapshot block. Alluvial has introduced such a mechanism for `setOperatorLimits` in `030b52feb5af2dd2ad23da0d512c5b0e55eb8259`. A similar technique can be used here.

## Alluvial's Perspective
Alluvial: *Don't think this is really an issue.*  
On a regular basis, the admin would not remove the keys but would request the Node O

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 25: TRST-H-1 Incorrect implementation of getProfitSharingE18() greatly reduces Lender's yield

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
`ProfitSharingModel.getProfitSharingE18()` calculates the share of profit that Lender gets 
based on the APR of the position. According to the formula, the higher the APR, the lower 
the share of profit the Lender gets, but due to the wrong implementation of the 
`getProfitSharingE18()` function, if the APR is smaller than **MAX_ANNUALIZED_YEILD**, the 
base share of 25% is returned, actually 25% should be returned when the APR is larger than 
**MAX_ANNUALIZED_YEILD**.
Considering an APR of 5%, Lender's share of the profit should be 77%, while 
getProfitSharingE18() returns 25%, which greatly reduces Lender's share of the profit.

**Recommended Mitigation:**
Modify `getProfitSharingE18()` as follows 
```solidity
            - if (_annualizedYieldE18 < MAX_ANNUALIZED_YEILD) {
            + if (_annualizedYieldE18 >= MAX_ANNUALIZED_YEILD) { 
            return 0.25e18;
            }
```

**Team response:**
Fixed

**Mitigation Review:**
The team has fixed it as recommended to make the logic correct

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

## Statistics

- Total findings analyzed: 234
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

