---
id: PAT-PAUSE
title: Pause Security Patterns
category: access-control
severity: low
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - pause
  - emergency
  - circuit-breaker

finding_count: 10
last_updated: 2026-01-31
---
# Pause Security Patterns

## Overview

**Frequency**: 10 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cantina, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for pause vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: The off-chain mechanism must be ensured to work in a correct order strictly

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `PriorityPool` contract relies on the distribution oracle for accounting and the accounting calculation is done off-chain.

According to the communication with the protocol team, the correct workflow for queued deposits can be described as below:
- Whenever there is a new room for deposit in the staking pool, the function `depositQueuedTokens` is called.
- The `PriorityPool` contract is paused by calling `pauseForUpdate()`.
- Accounting calculations happen off-chain using the function `getAccountData()` and `getDepositsSinceLastUpdate()`(`depositsSinceLastUpdate`) variable to compose the latest Merkle tree.
- The distribution oracle calls the function `updateDistribution()` and this will resume the `PriorityPool`.

The only purpose of pausing the queue contract is to prevent unqueue until the accounting status are updated.
Through an analysis we found that the off-chain mechanism MUST follow the order very strictly or else user funds can be stolen.
While we acknowledge that the protocol team will ensure it, we decided to keep this finding as a medium risk because we can not verify the off-chain mechanism.

**Impact:** If the off-chain mechanism occurs in a wrong order by any chance, user funds can be stolen.
Given the likelihood is low, we evaluate the impact to be Medium.

**Proof of Concept:** The below test case shows the attack scenario.
```javascript
  it('Cyfrin: off-chain mechanism in an incorrect order can lead to user funds 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 2: A market could be deprecated but still prevent liquidators to liquidate borrowers if isLiquidateBorrowPaused istrue

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context 
- aave-v2/MorphoGovernance.sol#L358-L366 
- compound/MorphoGovernance.sol#L368-L376 

## Description 
Currently, when a market must be deprecated, Morpho checks that borrowing has been paused before applying the new value for the flag.

```solidity
function setIsDeprecated(address _poolToken, bool _isDeprecated)
external
onlyOwner
isMarketCreated(_poolToken)
{
    if (!marketPauseStatus[_poolToken].isBorrowPaused) revert BorrowNotPaused();
    marketPauseStatus[_poolToken].isDeprecated = _isDeprecated;
    emit IsDeprecatedSet(_poolToken, _isDeprecated);
}
```

The same check should be done in `isLiquidateBorrowPaused`, allowing the deprecation of a market only if `isLiquidateBorrowPaused == false`, otherwise liquidators would not be able to liquidate borrowers on a deprecated market.

## Recommendation 
Prevent the deprecation of a market if the `isLiquidateBorrowPaused` flag is set to true. Consider also checking the `isDeprecated` flag in the `setIsLiquidateBorrowPaused` to prevent pausing the liquidation if the market is deprecated. If Morpho implements the specific behavior, it should also be aware of the issue described in "setIsPausedForAllMarkets" bypassing the check done in `setIsBorrowPaused` and allowing resuming borrow on a deprecated market.

## Morpho 
We acknowledge this issue. The reason behind this is the following: given what @MathisGD said, if we want to be consistent, we should prevent pausing the liquidation borrow on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MorphoV1-Spearbit-Security-Review.pdf)

---

### Example 3: [M-03] User Could Change The State Of The System While In Pause Mode

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/NibblVault.sol#L443


## Vulnerability details

## Proof-of-Concept

Calling `NibblVault.updateTWAP` function will change the state of the system. It will cause the TWAP to be updated and buyout to be rejected in certain condition.

When the system is in `Pause` mode, the system state should be frozen. However, it was possible someone to call the `NibblVault.updateTWAP` function during the `Pause` mode, thus making changes to the system state.

[https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/NibblVault.sol#L443](https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/NibblVault.sol#L443)

```solidity
/// @notice Updates the TWAV when in buyout
/// @dev TWAV can be updated only in buyout state
function updateTWAV() external override {
    require(status == Status.buyout, "NibblVault: Status!=Buyout");
    uint32 _blockTimestamp = uint32(block.timestamp % 2**32);
    if (_blockTimestamp != lastBlockTimeStamp) {
        _updateTWAV(getCurrentValuation(), _blockTimestamp);   
        _rejectBuyout(); //For the case when TWAV goes up when updated externally
    }
}
```

## Recommended Mitigation Steps

Ensure that the `NibblVault.updateVault` function cannot be called when the system is in `Pause` mode.

Add the `whenNotPaused` modifier to the function.

```solidity
///

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 4: Inconsistent pause enforcement in WrappedBitcornNativeOFTAdapter 

**Source**: Cantina
**Protocol**: Bitcorn
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Context
(No context files were provided by the reviewer)

## Description
The `_credit` function in the `WrappedBitcornNativeOFTAdapter.sol` contract lacks the `whenNotPaused` modifier, allowing token credits even when the contract is paused. This enables users to receive tokens through cross-chain transfers during a pause, undermining the effectiveness of the emergency pause mechanism. It also creates an inconsistent state, with some operations blocked while others continue after an emergency pause.

## Recommendation
Add the `whenNotPaused` modifier to the `_credit` function to ensure consistent pause behavior across all token operations:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
internal
virtual
override
+ whenNotPaused
returns (uint256 amountReceivedLD)
{
    (bool success,) = _to.call{value: _amountLD}("");
    if (!success) {
        revert WithdrawalFailed();
    }
    return _amountLD;
}
```

## Status
- Bitcorn: Fixed in 4adafa00
- Cantina Managed: Verified fix.

**Reference**: [View Original Finding](https://cdn.cantina.xyz/reports/cantina_bitcorn_december2024.pdf)

---

### Example 5: [M-02] `pause/unpause` functionalities not implemented in many pausable contracts

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/SocializingPool.sol#L21> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/Auction.sol#L14> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L17><br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/OperatorRewardsCollector.sol#L16>

The following contracts: `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` are supposed to be pausable (as they all inherit from `PausableUpgradeable`), but they don't implement the external `pause/unpause` functionalities which means it will never be possible to pause them.

### Proof of Concept

All the following contracts `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` inherit from the openzeppelin `PausableUpgradeable` extension which means that they contain internal functions `_pause` and `_unpause`.

Because those functions are internal, the contract must implement two other public/external `pause` and `unpause` functions to allow the manager to pause and unpause the contracts when necessary. None of the aforementioned contracts implement those functions, which means even if those contracts are supposed to be pausable (and have the `pause/unpause` functionalities), none of them can be paused.

### Recommended Mitigation Steps

Add public/external `pause` and `unpause` functions in the aforementioned contracts to allow them to be pausable, this can be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 6: [M-08] Builders must pay more interest when the system is paused.

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: MEDIUM

**Details**:

_Submitted by hansfriese, also found by 0x52, 0xNazgul, and rbserver_

[Community.sol#L455](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L455)<br>
[Community.sol#L484](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L484)<br>
[Community.sol#L509](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L509)<br>

Builders can't repay when the system is paused so they must pay more interest for the paused period.

### Proof of Concept

Builders can repay to lenders using 3 functions, [repayLender()](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L455), [reduceDebt()](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L484), and [escrow()](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L509).

But they all don't work when the system is paused and builders have no way to avoid it.

Furthermore, the HomeFi admin is the main lender of builders and there is no assurance that the admin would pause the community for a while to get more interest.

### Tools Used

Solidity Visual Developer of VSCode

### Recommended Mitigation Steps

Recommend thinking of an approach to make 3 repay functions work for pa

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 7: [M-05] StakingRewards.sol#stake is intended to be pausable but isn't

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: MEDIUM

**Details**:

Staking is unable to be paused as intended.

### Proof of Concept

StakingRewards.sol inherits pausable and implements the whenNotPaused modifier on stake, but doesn't implement any method to actually pause or unpause the contract. Pausable.sol only implements internal functions, which requires external or public functions to be implemented to wrap them. Since nothing like this has been implemented, the entire pausing system is rendered useless and staking cannot be paused as is intended.

### Recommended Mitigation Steps

Create simple external pause and unpause functions that can be called by owner.

**[MiguelBits (Y2K Finance) disputed](https://github.com/code-423n4/2022-09-y2k-finance-findings/issues/38)** 

**[HickupHH3 (judge) commented](https://github.com/code-423n4/2022-09-y2k-finance-findings/issues/38#issuecomment-1280395938):**
 > Great catch!
> 
> While the contract is taken from Synthetix's StakingRewards; note that they use a [different version of Pausable](https://github.com/Synthetixio/synthetix/blob/develop/contracts/Pausable.sol) that comes with a `setPaused()` function. This is notably absent from OZ's implementation; one has to have the pause and unpause function explicitly created.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 8: [M-03] Contract inherits from `Pausable` but does not expose pausing/unpausing functionality

**Source**: Pashov Audit Group
**Protocol**: Parcel Payroll
**Impact**: MEDIUM

**Details**:

**Impact:**
Low, as methods do not have `whenNotPaused` modifier

**Likelihood:**
High, as it is certain that contract can't be paused at all

**Description**

The `Organizer` smart contract inherits from OpenZeppelin's `Pausable` contract, but the `_pause` and `_unpause` methods are not exposed externally to be callable and also no method actually uses the `whenNotPaused` modifier. This shows that `Pausable` was used incorrectly and is possible to give out a false sense of security when actually contract is not pausable at all.

**Recommendations**

Either remove `Pausable` from the contract or add `whenNotPaused` modifier to the methods that you want to be safer and also expose the `_pause` and `_unpause` methods externally with access control.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-02-01-Parcel Payroll.md)

---

### Example 9: M-3: The protocol shouldn't charge interests when paused

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/234 

## Found by 
hansfriese, rvierdiiev



## Summary
The protocol charges interest from users using `virtualPrice` and it increases when the protocol is paused.

As a result, users would be forced to pay more interests and experience an unexpected liquidation.

## Vulnerability Detail
The protocol has 3 kinds of the vault and each one has `pause/unpause` option by `pausers`.

Also, each collateral would be paused using `CollateralBook.pauseCollateralType()`.

But it updates the `virtualPrice` during the paused period and the below scenarios would be possible.

#### Scenario 1
1. A user `Alice` opened a loan using some collaterals.
2. The vault was paused for a while for some unexpected reason.
3. Meanwhile, her loan was changed to a `liquidatable` one but she can't add collaterals(or close the loan) in the paused state.
4. After the protocol is unpaused, she's trying to protect her loan by adding collaterals but `Bob` can liquidate her loan with front running.
5. Even if her loan isn't liquidated, she should pay interests during the paused period and it's not fair for her.

#### Scenario 2
1. A user `Alice` opened a loan with `minOpeningMargin = 101%`.
2. After the protocol was paused for some reason, the admin decided to change `minOpeningMargin = 105%`.
3. `Alice` wants to close her loan before it's applied because it's too high for her but she can't because it's paused.
4. After the new `minOpenin

*[Content truncated...]*

---

### Example 10: M-3: User withdrawals are dependent on admin actions

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/83 

## Found by 
Deivitto, dipp, Jeiwan, thec00n

## Summary
Users can deposit USDC and Crabv2 tokens at any time, but there are limitations around withdrawals. Users could have permanently locked up their funds if specific owner actions are not triggered. 

## Vulnerability Detail
The owner can call `toggleAuctionLive()` and prevent any withdrawals from occurring. User withdrawals are only enabled again when the owner calls `withdrawAuction()` or `depositAuction()`. If the owner loses their key or becomes malicious and never calls these functions, then the users have no way of withdrawing their funds. 

## Impact
Users could get their funds locked up in the `Netting` contract without a way to withdraw them again.

## Code Snippet
https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L276-L283

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L321-L327

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L223-L226

## Tool used
Manual Review

## Recommendation
Lock up times are necessary for the system to work but users should always be able to withdraw their funds eventually without any dependecy of the owner.  When users deposit tokens, a meaningful expiry timestamp should be set by the contract. Before the expiry deposits are locked and the funds can be used during auctions. After expiry de

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 10
- Examples shown: 10
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

