---
id: PAT-NFT
title: Nft Security Patterns
category: nft
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - nft
  - metadata
  - royalty

finding_count: 19
last_updated: 2026-01-31
---
# NFT Security Patterns

## Overview

**Frequency**: 19 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 9 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, ZachObront

---

## Detection Checklist

- [ ] Check for nft vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Stealing fund by applying reentrancy attack on removeCollateral, startLiquidationAuction, and purchaseLiquidationAuctionNFT

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L444


## Vulnerability details

## Impact

By applying reentrancy attack involving the functions `removeCollateral`, `startLiquidationAuction`, and `purchaseLiquidationAuctionNFT`, an Attacker can steal large amount of fund.

## Proof of Concept

 - Bob (a malicious user) deploys a contract to apply the attack. This contract is called `BobContract`. Please note that all the following transactions are going to be done in one transaction.
 - BobContract takes a flash loan of 500K USDC.
 - BobContract buys 10 NFTs with ids 1 to 10 from collection which are allowed to be used as collateral in this project. Suppose, each NFT has price of almost 50k USDC.
 - BobContract adds those NFTs as collateral by calling the function `addCollateral`. So `_vaultInfo[BobContract][collateral.addr].count = 10`.
```
function addCollateral(IPaprController.Collateral[] calldata collateralArr) external override {
        for (uint256 i = 0; i < collateralArr.length;) {
            _addCollateralToVault(msg.sender, collateralArr[i]);
            collateralArr[i].addr.transferFrom(msg.sender, address(this), collateralArr[i].id);
            unchecked {
                ++i;
            }
        }
    }
```
https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L98
 - BobContract borrows the max allowed amount of `PaprToken` that is

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 2: Missing owner check on from when transferring tokens

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Security Report

## Severity: High Risk

### Context
`OrderNFT.sol#L207`

### Description
The `OrderNFT.transferFrom`/`safeTransferFrom` methods use the internal `_transfer` function. While they check approvals on `msg.sender` through `_isApprovedOrOwner(msg.sender, tokenId)`, it is never checked that the specified `from` parameter is actually the owner of the NFT. 

An attacker can decrease other users' NFT balances, making them unable to cancel or claim their NFTs and locking users' funds. The attacker transfers their own NFT passing the victim as `from` by calling `transferFrom(from=victim, to=attackerAccount, tokenId=attackerTokenId)`. This passes the `_isApprovedOrOwner` check but reduces `from`'s balance.

### Recommendation
Add the following check to `_transfer`:

```solidity
require(ownerOf(tokenId) == from, Errors.ACCESS);
```

### Clober
Fixed PR 310.

### Spearbit
Verified. Ownership check added.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 3: [H-03] `saleReceiver` and `feeReceiver` can steal refunds after sale has ended

**Source**: Code4rena
**Protocol**: Escher
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L67-L68>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L81-L88>

First, lets go over how a buy happens.

A buyer can buy NFTs at a higher price and then once the auction ends they can use `refund()` to return the over payments. The effect is that they bought the NFTs at the lowest price (Lowest Price Dutch Auction).

Now, let's move on to what happens when the sale ends:

The sale is considered ended when the last NFT is sold which triggers the payout to the seller and fee collector:

```javascript
81:        if (newId == temp.finalId) {
82:            sale.finalPrice = uint80(price);
83:            uint256 totalSale = price * amountSold;
84:            uint256 fee = totalSale / 20;
85:            ISaleFactory(factory).feeReceiver().transfer(fee);
86:            temp.saleReceiver.transfer(totalSale - fee);
87:            _end();
88:        }
```

Earlier there's also a check that you cannot continue buying once the `currentId` has reached `finalId`:

```javascript
67:        uint48 newId = amount + temp.currentId;
68:        require(newId <= temp.finalId, "TOO MANY");
```

However, it is still possible to buy `0` NFTs for whichever price you want even after the sale has ended. Triggering the "end of sale" snippet again, since `newId` will still equal `temp.finalId`.

The attacker, `saleReceiver` (or `feeReceiver`), buys `0` NFTs for the delta between `totalSale` and th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-escher)

---

### Example 4: An allowed signer can sign mints with malicious parameters

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context 
- SeaDrop.sol#L259-L266 
- SeaDrop.sol#L318-L319 

## Description 
An allowed signer (SeaDrop.sol#L318-L319) can sign mints that have either:
- `mintParams.feeBps` equal to 0.
- A custom `feeRecipient` with `mintParams.restrictFeeRecipients` equal to false to circumvent the check at SeaDrop.sol#L469.

This allows the signer to avoid the protocol fee being paid or enables the protocol fee to be sent to a desired address determined by the signer.

**Note:** The `ERC721SeaDrop` owner can allow signers by calling `ERC721SeaDrop.updateSigner`. Thus, the owner can permit an address they control as a signer and sign mints that have either of the above characteristics.

## OpenSea 
This is correct; currently, any signer has ultimate control over the parameters of a mint, and this should be understood by parties who wish to use a centralized signer, i.e., self-hosted or in a legal agreement with a marketplace.

However, we could make it slightly less "trustful" by storing a struct of validation parameters rather than a simple boolean in the mapping.

### Proposed Struct
```solidity
struct SignedMintParams {
    uint80 minMintPrice;
    uint24 maxMaxTotalMintableByWallet;
    uint48 minStartTime;
    uint48 maxEndTime;
    uint40 maxMaxTokenSupplyForStage;
    uint16 maxFeeBps;
}
```
Assume `restrictFeeRecipients == true`.

## Spearbit
That could work. If this solution is implemented, all instances of `mintParams.<FIELDS>` would need to be replaced b

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 5: Attacker can destroy user voting power by setting `ERC721Power::totalPower` and all existing NFTs `currentPower` to 0

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can destroy user voting power by setting `ERC721Power::totalPower` & all existing nfts' `currentPower` to 0 via a permission-less attack contract by exploiting a discrepancy ("<" vs "<=") in `ERC721Power` [L144](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L144) & [L172](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L172):

```solidity
function recalculateNftPower(uint256 tokenId) public override returns (uint256 newPower) {
    // @audit execution allowed to continue when
    // block.timestamp == powerCalcStartTimestamp
    if (block.timestamp < powerCalcStartTimestamp) {
        return 0;
    }
    // @audit getNftPower() returns 0 when
    // block.timestamp == powerCalcStartTimestamp
    newPower = getNftPower(tokenId);

    NftInfo storage nftInfo = nftInfos[tokenId];

    // @audit as this is the first update since power
    // calculation has just started, totalPower will be
    // subtracted by nft's max power
    totalPower -= nftInfo.lastUpdate != 0 ? nftInfo.currentPower : getMaxPowerForNft(tokenId);
    // @audit totalPower += 0 (newPower = 0 in above line)
    totalPower += newPower;

    nftInfo.lastUpdate = uint64(block.timestamp);
    // @audit will set nft's current power to 0
    nftInfo.currentPower = newPower;
}

function getNftPower(uint256 tokenId) public view ove

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 6: [H-03] Collateral NFT deposited to a wrong address, when transferred directly to PaprController

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L159


## Vulnerability details

## Impact
Users will lose collateral NFTs when they are transferred to `PaprController` by an approved address or an operator.
## Proof of Concept
The `PaprController` allows users to deposit NFTs as collateral to borrow Papr tokens. One of the way of depositing is by transferring an NFT to the contract directly via a call to `safeTransferFrom`: the contract implements the `onERC721Received` hook that will handle accounting of the transferred NFT ([PaprController.sol#L159](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L159)). However, the hook implementation uses a wrong argument to identify token owner: the first argument, which is used by the contract to identify token owner, is the address of the `safeTransferFrom` function caller, which may be an approved address or an operator. The actual owner address is the second argument ([ERC721.sol#L436](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L436)):
```solidity
try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {
```

Thus, when an NFT is sent by an approved address or an operator, it'll be deposited to the vault of the approved address or operator:
```solidity
// test/paprController/OnERC721ReceivedTest.sol

f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 7: [H-04] If insider deposits and unlocks in quick succession, attacker can steal their NFT and their deposit funds

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

### Example 8: [M-07] Royalty recipients will not get fair share of royalties

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

Recipients of NFTs who accept royalties will not get their fair share of royalties. This is because royalties are calculated by dividing the sales price equally amongst all sold NFTs in that purchase. The issue with this is that it assumes all NFTs cost the same amount when it comes time to deal out royalties. If NFTs cost different amounts, then they should be getting an amount of royalties based on that weight relative to the other NFTs. The impact of this is that Royalties will not be distributed evenly at the expense of the more expensive NFT. Meaning that recipients of the expensive NFT will always receive less than they are owed. And the cheaper ones will get more than owed. In short, this is a loss of funds or misdistribution of funds.

### Proof of Concept

The easiest way to test this will to be add this snippet into Milady.sol.

Using this to have access to ERC2981's `setRoyaltyInfo()`:

```solidity
file: Milady.sol
    function setRoyaltyInfo(
        uint256 _royaltyFeeRate,
        address _royaltyRecipient
    ) public {
        royaltyFeeRate = _royaltyFeeRate;
        royaltyRecipient = _royaltyRecipient;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC2981, ERC721) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function royaltyInfo(
        uint256 id,
        uint256 salePrice
    ) public view override returns (address, uint256) {
        return super.royaltyInfo(id, salePrice

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 9: Order owner isn't zeroed after burning

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `OrderBook.sol#L821-L823`
- `OrderNFT.sol#L78-L82`
- `OrderNFT.sol#L189`

## Description
The order's owner is not zeroed out when the NFT is burnt. As a result, while the `onBurn()` method records the NFT to have been transferred to the zero address, `ownerOf()` still returns the current order's owner. This allows for unexpected behaviour, like being able to call `approve()` and `safeTransferFrom()` functions on non-existent tokens.

A malicious actor could sell such resurrected NFTs on secondary exchanges for profit even though they have no monetary value. Such NFTs will revert on cancellation or claim attempts since `openOrderAmount` is zero.

### Code Example
```solidity
function testNFTMovementAfterBurn() public {
    _createOrderBook(0, 0);
    address attacker2 = address(0x1337);
    // Step 1: make 2 orders to avoid bal sub overflow when moving burnt NFT in step 3
    uint256 orderIndex1 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    CloberOrderBook.OrderKey memory orderKey = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Constants.PRICE_INDEX,
        orderIndex: orderIndex1
    });
    uint256 tokenId = orderToken.encodeId(orderKey);
    // Step 2: burn 1 NFT by cancelling one of the orders
    vm.startPrank(Constants.MAKER);
    orderBook.cancel(Constants.MAKER, _toArray(orderKey));
    // verify ownership is still mak

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 10: [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

Many ERC721/ERC1155 tokens, including well-known games such as Axie Infinity, have a pause functionality inside the contract. This pause functionality will cause the `stopRent` call to always revert and could cause issues, especially for the `PAY` order type.

### Proof of Concept

When `stopRent` /`stopRentBatch` is called, it will eventually trigger `  _reclaimRentedItems ` and execute `reclaimRentalOrder` from the safe to send back tokens to lender.

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L353> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L293> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L183>



```solidity
    function _reclaimRentedItems(RentalOrder memory order) internal {
        // Transfer ERC721s from the renter back to lender.
        bool success = ISafe(order.rentalWallet).execTransactionFromModule(
            // Stop policy inherits the reclaimer package.
            address(this),
            // value.
            0,
            // The encoded call to the `reclaimRentalOrder` function.
            abi.encodeWithSelector(this.reclaimRentalOrder.selector, order),
            // Safe must delegate call to the stop policy so that it is the msg.sender.
            Enum.Operation.DelegateCall
        );

        // Assert that the transfer back to the len

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 11: [H-05] ArbitraryCallsProposal.sol and ListOnOpenseaProposal.sol safeguards can be bypassed by cancelling in-progress proposal allowing the majority to steal NFT

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by 0x52_

Note: PartyDAO acknowledges that "canceling an InProgress proposal (mid-step) can leave the governance party in a vulnerable or undesirable state because there is no cleanup logic run during a cancel" in the "Known Issues / Topics" section of the contest readme. I still believe that this vulnerability needs to be mitigated as it can directly lead to loss of user funds.

### Impact

Majority vote can abuse cancel functionality to steal an NFT owned by the party.

### Proof of Concept

ArbitraryCallsProposal.sol implements the following safeguards for arbitrary proposals that are not unanimous:

1.  Prevents the ownership of any NFT changing during the call. It does this by checking the the ownership of all NFTs before and after the call.

2.  Prevents calls that would change the approval status of any NFT. This is done by disallowing the "approve" and "setApprovalForAll" function selectors.

Additionally ListOnOpenseaProposal.sol implements the following safeguards:

1.  NFTs are first listed for auction on Zora so that if they are listed for a very low price then the auction will keep them from being purchased at such a low price.

2.  At the end of the auction the approval is revoked when `\_cleanUpListing` is called.

These safeguards are ultimately ineffective though. The majority could use the following steps to steal the NFT:

1.  Create ListOnOpenseaProposal with high sell price and short cancel delay

2.  Vote to approve proposal with majority vote

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 12: [H-03] A majority attack can easily bypass Zora auction stage in OpenseaProposal and steal the NFT from the party.

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

### Example 13: M-1: [Tomo-M3] Use safeMint instead of mint for ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/65 

## Found by 
Tomo

## Summary

Use safeMint instead of mint for ERC721

## Vulnerability Detail

The`msg.sender`will be minted as a proof of staking NFT when`_stakeToken()`is called. 

However, if`msg.sender` is a contract address that does not support ERC721, the NFT can be frozen in the contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.
> 

Ref:[https://eips.ethereum.org/EIPS/eip-721](https://eips.ethereum.org/EIPS/eip-721)

As per the documentation of ERC721.sol by Openzeppelin

Ref: [https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285)

```solidity
/**
 * @dev Mints `tokenId` and transfers it to `to`.
 *
 * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
 *
 * Requirements:
 *
 * - `tokenId` must not exist.
 * - `to` cannot be the zero address.
 *
 * Emits a {Transfer} event.
 */
function _mint(address to, uint256 tokenId) internal virtual {
```

## Impact

Users possibly lose their NFTs

## Code Snippet
https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L411
``` solidity
  _mint(msg.sender, _tokenId);
```
## Tool used

Manual Review

## Recommendation

Us

*[Content truncated...]*

---

### Example 14: [M-08] Assets in a Safe can be lost

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

The `Guard.sol` contract is enabled on Safe's and uses the [`_checkTransaction`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293) function to ensure that transactions that the Safe executes do not transfer the asset out of the Safe.

The `checkTransaction` function achieves this by isolating the function selector and checking that it is not a disallowed function selector. For instance: `safeTransferFrom`, `transferFrom`, `approve`, `enableModule`, etc.

The list does not, however, check for calls to `burn` the token, neither does it check if it is a `permit`. The sponsor has noted the following:

> The [Guard](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol) contract can only protect against the transfer of tokens that faithfully
implement the ERC721/ERC1155 spec.

But this does not acknowledge the fact that an ERC721/ERC1155 implementation can still be an honest implementation and have extra functionality. In particular, the `burn` function is a common addition to many ERC721 contracts, usually granted through inheriting `ERC721Burnable`.

For example, the following projects all have a `burn` function, and Safe's protected by `Guard.sol` that hold these NFTs will be vulnerable to loss of assets via a malicious renter:

*   [Pudgy Penguins](https://etherscan.io/address/0xbd3531da5cf5857e7cfaa92426877b022e612cf8#writeContract)
*   [Lil Pudgies

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 15: [M-04] Possible to bypass saleConfig.limitPerAccount

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by itsmeSTYJ, also found by 0x1f8b, 0x52, 0xDjango, auditor0517, byndooa, cccz, Ch&#95;301, Chom, csanuragjain, KIntern&#95;NA, ladboy233, nine9, PwnedNoMore, shenwilly, thank&#95;you, Treasure-Seeker, wagmi, yixxas, and zkhorse_

It is possible to bypass the `saleConfig.limitPerAccount` set by the creator by transferring the NFTs out. For highly sought after NFT drops, a single smart contract can buy out the entire drop simply by calling `mintFromFixedPriceSale` then transferring the NFTs out and repeating the process multiple times.

### Proof of Concept

Modify the `FixedPriceDrop.sol` Foundry test with the following changes.

```diff
diff --git a/FixedPriceDrop.sol.orig b/FixedPriceDrop.sol
index 0a6d698..56808f8 100644
--- a/FixedPriceDrop.sol.orig
+++ b/FixedPriceDrop.sol
@@ -71,14 +71,26 @@ contract TestFixedPriceDrop is Test {
 
     /** List for sale **/
     uint80 price = 0.5 ether;
-    uint16 limitPerAccount = 10;
+    uint16 limitPerAccount = 3;
     vm.prank(creator);
     nftDropMarket.createFixedPriceSale(address(nftDropCollection), price, limitPerAccount);
 
     /** Mint from sale **/
     uint16 count = 3;
     vm.deal(collector, 999 ether);
-    vm.prank(collector);
+    vm.startPrank(collector);
+    nftDropMarket.mintFromFixedPriceSale{ value: price * count }(address(nftDropCollection), count, payable(0));
+
+    // Check that available count for collector is 0
+    uint256 remaining = nftDropMarket.getAvailableCountFromFixedPriceSale(address

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-foundation)

---

### Example 16: [M-04] It's possible to swap NFT token ids without fee and also attacker can wrap unwrap all the NFT token balance of the Pair contract and steal their air drops for those token ids

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L217-L243> <br><https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L248-L262>

Users can `wrap()` their NFT tokens (which id is whitelisted) and receive `1e18` fractional token or they can pay `1e18` fractional token and unwrap NFT token. there is two issue here:

1.  anyone can swap their NFT token id with another NFT token id without paying any fee(both ids should be whitelisted). it's swap without fee.
2.  attacker can swap his NFT token(with whitelisted id) for all the NFT balance of contract and steal those NFT tokens airdrop all in one transaction.

### Proof of Concept

This is `wrap()` and `unwrap()` code:

        function wrap(uint256[] calldata tokenIds, bytes32[][] calldata proofs)
            public
            returns (uint256 fractionalTokenAmount)
        {
            // *** Checks *** //

            // check that wrapping is not closed
            require(closeTimestamp == 0, "Wrap: closed");

            // check the tokens exist in the merkle root
            _validateTokenIds(tokenIds, proofs);

            // *** Effects *** //

            // mint fractional tokens to sender
            fractionalTokenAmount = tokenIds.length * ONE;
            _mint(msg.sender, fractionalTokenAmount);

            // *** Interactions *** //

            // transfer nfts from sender
            for (uint256 i = 0;

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 17: M-3: Using `ERC721.transferFrom()` instead of `safeTransferFrom()` may cause the user's NFT to be frozen in a contract that does not support ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/55 

## Found by 
saian, rvierdiiev, WATCHPUG, Tomo, Bnke0x0, Nyx

## Summary

There are certain smart contracts that do not support ERC721, using `transferFrom()` may result in the NFT being sent to such contracts.

## Vulnerability Detail

In `unstake()`, `_to` is param from user's input.

However, if `_to` is a contract address that does not support ERC721, the NFT can be frozen in that contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.

Ref: https://eips.ethereum.org/EIPS/eip-721

## Impact

The NFT may get stuck in the contract that does support ERC721.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L463-L489

## Tool used

Manual Review

## Recommendation

Consider using `safeTransferFrom()` instead of `transferFrom()`.

## Discussion

**zobront**

Fixed: https://github.com/Solidity-Guild/FrankenDAO/pull/10

---

### Example 18: [M-02] A malicious borrower can hijack any NFT with `permit()` function he rents.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **ERC-4494: Permit for ERC-721 NFTs**: ERC721-Permit is very similar to ERC20-permit (EIP-2612). ERC721 Permit adds a new `permit()` function. It allows user can sign an ERC721 approve transaction off-chain producing a signature that anyone could use and submit to the permit function. When permit is executed, it will execute the approve function. This allows for meta-transaction support of ERC721 transfers, but it also simply gets rid of the annoyance of needing two transactions: `approve` and `transferFrom`. Additionally, ERC721-Permit, just like ERC20 permit, prevents misuse and replay attacks. A replay attack is when a valid signature is used several times or in places where it's not intended to be used in.

    You can find an implementation of it here, by uniswap: <https://github.com/Uniswap/v3-periphery/blob/main/contracts/base/ERC721Permit.sol>

***

### The Vulnerability & Exploitation Steps

***

ReNFT doesn't account for ERC721 implementing the `permit()` function, allowing a malicious borrower to hijack the token by producing a signature and feeding it to the `permit()` function requesting it to approve his address to transfer the token

**Exploitation Steps**

1.  The attacker rents the NFT token in his rental safe
2.  The attacker creates a signature which he will need to feed to the `permit()` function. The signature is a signed data including info like: 1. the deadline (until when t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 19: M-7: Minting inconsistencies on FootiumPlayer and FootiumClub

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/342 

## Found by 
0xAsen, 0xHati, 0xLook, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xhacksmithh, BAHOZ, Bauchibred, Bauer, Dug, GalloDaSballo, Koolex, PTolev, Phantasmagoria, TheNaubit, Tricko, ali\_shehab, cergyk, chaithanya\_gali, ctf\_sec, cuthalion0x, deadrxsezzz, descharre, indijanc, jasonxiale, kiki\_dev, lewisbroadhurst, nzm\_, oualidpro, sashik\_eth, shame, shogoki, tsueti\_, tsvetanovv, wzrdk3lly
## Summary

The `FootiumClub.sol` contract when minting uses `_mint()` instead of `_safeMint()` which can cause to mint a club to a contract who does not support nfts. On the other hand `FootiumPlayer.sol` uses `_safeMint()`.

## Vulnerability Detail

See summary.

## Impact

`FootiumClub.sol` might mint a club NFT to a contract that cannot handle nfts.

## Code Snippet

https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumClub.sol#L65

## Tool used

Manual Review

## Recommendation

Use `_safeMint()` as in FootiumPlayer.

---

## Statistics

- Total findings analyzed: 19
- Examples shown: 19
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

