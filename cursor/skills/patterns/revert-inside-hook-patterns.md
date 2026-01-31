---
id: PAT-REVERT-INSIDE-HOOK
title: Revert Inside Hook Security Patterns
category: error-handling
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - revert
  - error
  - exception

finding_count: 4
last_updated: 2026-01-31
---
# Revert Inside Hook Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 1 | 0 | 0 |

**Common Sources**: Code4rena

---

## Detection Checklist

- [ ] Check for revert inside hook vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-07] GiantLP with a transferHookProcessor cant be burned, users funds will be stuck in the Giant Pool

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantLP.sol#L39-L47
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L73-L78
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L51-L57


## Vulnerability details

## Impact
The GiantLP with a transferHookProcessor will call `transferHookProcessor.beforeTokenTransfer(_from, _to, _amount)` when it's transferred / minted / burned. 

But the `to` address is address(0x00) in the erc20 `_burn` function. The GiantMevAndFeesPool.beforeTokenTransfer will call the function `SyndicateRewardsProcessor._distributeETHRewardsToUserForToken` will a zero address check in the first line:
```
function _distributeETHRewardsToUserForToken(...) internal {
    require(_recipient != address(0), "Zero address");
```

So any withdraw function with a operation of burning the GiantLP token with a transferHookProcessor will revert because of the zero address check. The users' funds will be stuck in the Giant Pool contracts.

## Proof of Concept
I wrote a test about `GiantMevAndFeesPool.withdrawETH` function which is used to withdraw eth from the Giant Pool. It will be reverted.

test/foundry/LpBurn.t.sol
```
pragma solidity ^0.8.13;

// SPDX-License-Identifier: MIT
import {GiantPoolTests} from "./GiantPools.t.sol";

contract LpBurnTests is GiantPoolTests {
    function testburn() pub

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 2: [M-11] Lender can reject closing a position

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

A credit line can be closed by using the `LineOfCredit.depositAndClose()` or `LineOfCredit.close`. The remaining funds deposited by the lender (`credit.deposit`) and the accumulated and paid interest are transferred to the lender.

However, if the used credit token `credit.token` is native ETH (or an ERC-777 token with receiver hooks, and under the assumption that the oracle supports this asset in the first place), the lender can reject the closing of the credit by reverting the token transfer.

### Impact

The lender can prevent the borrower from closing the credit line. This leads to the following consequences:

*   Migrating (rollover) to a new line is not possible (it requires all credits to be closed, see [SecuredLine.sol#L55](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/SecuredLine.sol#L55))
*   Releasing a spigot and transferring ownership to the borrower is not possible (see [SpigotedLineLib.sol#L195](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/SpigotedLineLib.sol#L195))
*   Sweeping remaining tokens (e.g. revenue tokens) in the Spigot to the borrower is not possible (see [SpigotedLineLib.sol#L220](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/SpigotedLineLib.sol#L220>))

### Proof of Concept

[modules/credit/LineOfCredit.sol#L489-L493](https://github.com/debtdao/Line-of-Credit/blob/e8

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 3: [H-03] A majority attack can easily bypass Zora auction stage in OpenseaProposal and steal the NFT from the party.

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Trust_

The PartyGovernance system has many defenses in place to protect against a majority holder stealing the NFT. One of the main protections is that before listing the NFT on Opensea for a proposal-supplied price, it must first try to be auctioned off on Zora. To move from Zora stage to Opensea stage, `\_settleZoraAuction()` is called when executing ListedOnZora step in ListOnOpenseaProposal.sol. If the function returns false, the next step is executed which lists the item on Opensea. It is assumed that if majority attack proposal reaches this stage, it can steal the NFT for free, because it can list the item for negligible price and immediately purchase it from a contract that executes the Opensea proposal.

Indeed, attacker can always make `settleZoraAuction()` return false. Looking at  the code:

    try ZORA.endAuction(auctionId) {
                // Check whether auction cancelled due to a failed transfer during
                // settlement by seeing if we now possess the NFT.
                if (token.safeOwnerOf(tokenId) == address(this)) {
                    emit ZoraAuctionFailed(auctionId);
                    return false;
                }
            } catch (bytes memory errData) {

As the comment already hints, an auction can be cancelled if the NFT transfer to the bidder fails. This is the relevant AuctionHouse code (endAuction):

    {
                // transfer the token to the winner and pay out the participants below
                tr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 4: [H-02] Rewards of GiantMevAndFeesPool can be locked for all users

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L172
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantLP.sol#L8


## Vulnerability details

## Impact
Any malicious user could make the rewards in GiantMevAndFeesPool inaccessible to all other users...

## Proof of Concept

https://gist.github.com/clems4ever/9b05391cc2192c1b6e8178faa38dfe41

Copy the file in the test suite and run the test.

## Tools Used

forge test

## Recommended Mitigation Steps

Protect the inherited functions of the ERC20 tokens (GiantLP and LPToken) because `transfer` is not protected and can trigger the `before` and `after` hooks. There is the same issue with LPToken and StakingFundsVault.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

