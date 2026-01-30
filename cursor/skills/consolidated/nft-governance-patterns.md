# NFT & Governance Security Patterns (Consolidated)

> **Flash loan governance attacks can pass malicious proposals in one block.**

---

## Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Flash Loan Voting | Borrow tokens, vote, return same block | Critical |
| Checkpoint Missing | Historical balance not tracked | High |
| Vote Manipulation | Incorrect voting power calculation | High |
| Unsafe NFT Mint | mint() doesn't check receiver | Medium |
| Royalty Bypass | Marketplace avoids creator royalties | Medium |
| Proposal Frontrun | Attacker frontrun proposal execution | High |

---

## Detection Strategy

### Flash Loan Governance
```solidity
// VULNERABLE: Uses current balance for voting
function vote(uint proposalId, bool support) external {
    uint votes = token.balanceOf(msg.sender);  // Flash loan inflated!
    _vote(proposalId, support, votes);
}

// SAFE: Use checkpointed balance at proposal creation
function vote(uint proposalId, bool support) external {
    uint snapshotId = proposals[proposalId].snapshotId;
    uint votes = token.balanceOfAt(msg.sender, snapshotId);
    _vote(proposalId, support, votes);
}
```

### NFT Safe Minting
```solidity
// VULNERABLE: Receiver might not handle NFTs
function mint(address to, uint tokenId) external {
    _mint(to, tokenId);  // If 'to' is contract, NFT could be locked
}

// SAFE: Check receiver can handle NFTs
function mint(address to, uint tokenId) external {
    _safeMint(to, tokenId);  // Calls onERC721Received
}
```

### Governance Security
```solidity
// Essential protections
contract SecureGovernor {
    uint public constant VOTING_DELAY = 1 days;    // Time before voting starts
    uint public constant VOTING_PERIOD = 3 days;   // Duration of voting
    uint public constant TIMELOCK_DELAY = 2 days;  // Delay before execution
    uint public constant QUORUM = 4;               // 4% of supply needed
    
    // Snapshot at proposal creation prevents flash loans
    function propose(...) external returns (uint proposalId) {
        uint snapshotId = token.snapshot();
        // ...
    }
}
```

### Audit Checklist
- [ ] Voting power uses checkpointed/snapshot balance
- [ ] Snapshot taken at proposal creation time
- [ ] Voting delay prevents last-minute token acquisition
- [ ] Timelock on proposal execution
- [ ] Quorum requirements appropriate
- [ ] Using _safeMint for NFTs to contracts
- [ ] Royalty calculation in marketplace enforced

---

## Included Pattern Files

- nft-patterns.md, royalty-patterns.md
- dao-patterns.md, vote-patterns.md, checkpoint-patterns.md
- auction-patterns.md, cooldown-patterns.md

---

## Full Pattern Details

---
## nft-patterns.md
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


---
## royalty-patterns.md
# Royalty Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for royalty vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-07] Royalty recipients will not get fair share of royalties

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

### Example 2: [M-16] Inappropriate support of EIP-2981

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by WatchPug_

[NFTMarketCreators.sol#L65-L82](https://github.com/code-423n4/2022-02-foundation/blob/4d8c8931baffae31c7506872bf1100e1598f2754/contracts/mixins/NFTMarketCreators.sol#L65-L82)<br>

```solidity
if (nftContract.supportsERC165Interface(type(IRoyaltyInfo).interfaceId)) {
  try IRoyaltyInfo(nftContract).royaltyInfo{ gas: READ_ONLY_GAS_LIMIT }(tokenId, BASIS_POINTS) returns (
    address receiver,
    uint256 /* royaltyAmount */
  ) {
    if (receiver != address(0)) {
      recipients = new address payable[](1);
      recipients[0] = payable(receiver);
      // splitPerRecipientInBasisPoints is not relevant when only 1 recipient is defined
      if (receiver == seller) {
        return (recipients, splitPerRecipientInBasisPoints, true);
      }
    }
  } catch // solhint-disable-next-line no-empty-blocks
  {
    // Fall through
  }
}
```

The current implementation of EIP-2981 support will always pass a constant `BASIS_POINTS` as the `_salePrice`.

As a result, the recipients that are supposed to receive less than 1 BPS of the salePrice may end up not receiving any royalties.

Furthermore, for the NFTs with the total royalties rate set less than 10% for some reason, the current implementation will scale it up to 10%.

### Recommended Mitigation Steps

1.  Instead of passing a constant of 10,000 as the `_salePrice`, we suggest using the actual `_salePrice`, so there the royalties can be paid for recipients with less than 1 BPS of the royalties.
2.  When the t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-foundation)

---

### Example 3: M-5: Template implementations doesn't validate configurations properly

**Source**: Sherlock
**Protocol**: NFTPort
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-nftport-judging/issues/83 

## Found by 
ElKu, rvierdiiev, obront, pashov, ctf\_sec, joestakey, ak1, JohnnyTime, GimelSec, Dravee, JohnSmith, cccz

## Summary

In past audits, we have seen contract admins claim that invalidated configuration setters are fine since admins are trustworthy. However, cases such as [Nomad got drained for over $150M](https://twitter.com/samczsun/status/1554260106107179010) and [Misconfiguration in the Acala stablecoin project allows attacker to steal 1.2 billion aUSD](https://web3isgoinggreat.com/single/misconfiguration-in-the-acala-stablecoin-project-allows-attacker-to-steal-1-2-billion-ausd) have shown again and again that even trustable entities can make mistakes. Thus any fields that might potentially result in insolvency of protocol should be thoroughly checked.

NftPort template implementations often ignore checks for config fields. For the rest of the issue, we take `royalty` related fields as an example to illustrate potential consequences of misconfigurations. Notably, lack of check is not limited to `royalty`, but exists among most config fields.

Admins are allowed to set a wrong `royaltiesBps` which is higher than `ROYALTIES_BASIS`. `royaltyInfo()` will accept this invalid `royaltiesBps` and users will pay a large amount of royalty.

## Vulnerability Detail

EIP-2981 (NFT Royalty Standard) defines `royaltyInfo()` function that specifies how much to pay for a given sale price. In genera

*[Content truncated...]*

---

### Example 4: [M-03] Forget to check "Some manifolds contracts of ERC-2981 return (address(this), 0) when royalties are not defined" in 3rd priority - MarketFees.sol

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by KIntern&#95;NA, also found by bin2chen and Lambda_

Wrong return of `cretorShares` and `creatorRecipients` can make real royalties party can't gain the revenue of sale.

### Proof of concept

Function `getFees()` firstly [call](https://github.com/code-423n4/2022-08-foundation/blob/792e00df429b0df9ee5d909a0a5a6e72bd07cf79/contracts/mixins/shared/MarketFees.sol#L422-L430) to function `internalGetImmutableRoyalties` to get the list of `creatorRecipients` and `creatorShares` if the `nftContract` define ERC2981 royalties.

```solidity
try implementationAddress.internalGetImmutableRoyalties(nftContract, tokenId) returns (
  address payable[] memory _recipients,
  uint256[] memory _splitPerRecipientInBasisPoints
) {
  (creatorRecipients, creatorShares) = (_recipients, _splitPerRecipientInBasisPoints);
} catch // solhint-disable-next-line no-empty-blocks
{
  // Fall through
}
```

***

In the [1st priority](https://github.com/code-423n4/2022-08-foundation/blob/792e00df429b0df9ee5d909a0a5a6e72bd07cf79/contracts/mixins/shared/MarketFees.sol#L236-L255) it check the `nftContract` define the function `royaltyInfo` or not. If yes, it get the return value `receiver` and `royaltyAmount`. In some manifold contracts of erc2981, it `return (address(this), 0)` when royalties are not defined. So we ignore it when the `royaltyAmount = 0`

```solidity
  try IRoyaltyInfo(nftContract).royaltyInfo{ gas: READ_ONLY_GAS_LIMIT }(tokenId, BASIS_POINTS) returns (
    address receiver,
    uint

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-foundation)

---

### Example 5: [M-08] Loss of funds for traders due to accounting error in royalty calculations

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L237-L281>

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L328-L355>

### Impact

The `PrivatePool.buy` and `PrivatePool.sell` functions intend to distribute royalty amount whenever NFTs are traded. The implementation of buy and sell looks like this:

```solidity
    function buy(uint256[] calldata tokenIds, uint256[] calldata tokenWeights, MerkleMultiProof calldata proof)
        public
        payable
        returns (uint256 netInputAmount, uint256 feeAmount, uint256 protocolFeeAmount)
    {
        // ...

        // calculate the sale price (assume it's the same for each NFT even if weights differ)
        uint256 salePrice = (netInputAmount - feeAmount - protocolFeeAmount) / tokenIds.length;
        uint256 royaltyFeeAmount = 0;
        for (uint256 i = 0; i < tokenIds.length; i++) {
            // transfer the NFT to the caller
            ERC721(nft).safeTransferFrom(address(this), msg.sender, tokenIds[i]);

            if (payRoyalties) {
                // get the royalty fee for the NFT
                (uint256 royaltyFee,) = _getRoyalty(tokenIds[i], salePrice);

                // add the royalty fee to the total royalty fee amount
                royaltyFeeAmount += royaltyFee;
            }
        }

        // add the royalty fee amount to the net input aount
        netInputAmount += royaltyFeeAmount;

        // ...

        if (payRoyalties) {
         

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 6: [M-03] `RoyaltyVault.sol` is Not Equipped to Handle On-Chain Royalties From Secondary Sales

**Source**: Code4rena
**Protocol**: Joyn
**Impact**: MEDIUM

**Details**:

_Submitted by leastwood_

<https://github.com/code-423n4/2022-03-joyn/blob/main/core-contracts/contracts/CoreCollection.sol>

<https://github.com/code-423n4/2022-03-joyn/blob/main/royalty-vault/contracts/RoyaltyVault.sol>

### Impact

The Joyn documentation mentions that Joyn royalty vaults should be equipped to handle revenue generated on a collection's primary and secondary sales. Currently, `CoreCollection.sol` allows the collection owner to receive a fee on each token mint, however, there is no existing implementation which allows the owner of a collection to receive fees on secondary sales.

After discussion with the Joyn team, it appears that this will be gathered from Opensea which does not have an on-chain royalty mechanism. As such, each collection will need to be added manually on Opensea, introducing further centralisation risk. It is also possible for users to avoid paying the secondary fee by using other marketplaces such as Foundation.

### Recommended Mitigation Steps

Consider implementing the necessary functionality to allow for the collection of fees through an on-chain mechanism. `ERC2981` outlines the appropriate behaviour for this.


**[sofianeOuafir (Joyn) confirmed and commented](https://github.com/code-423n4/2022-03-joyn-findings/issues/130#issuecomment-1099679515):**
 > This is a great observation. Something we are aware of and intend to fix as well.  



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-joyn)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## dao-patterns.md
# DAO Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 0 | 0 |

**Common Sources**: Sherlock

---

## Detection Checklist

- [ ] Check for dao vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: `Staking.unstake()` doesn't decrease the original voting power that was used in `Staking.stake()`.

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/70 

## Found by 
Haruxe, 0x52, hansfriese

## Summary
`Staking.unstake()` doesn't decrease the original voting power that was used in `Staking.stake()`.

## Vulnerability Detail
When users stake/unstake the underlying NFTs, it calculates the token voting power using [getTokenVotingPower()](https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L507-L515) and increases/decreases their voting power accordingly.

```solidity
    function getTokenVotingPower(uint _tokenId) public override view returns (uint) {
      if (ownerOf(_tokenId) == address(0)) revert NonExistentToken();

      // If tokenId < 10000, it's a FrankenPunk, so 100/100 = a multiplier of 1
      uint multiplier = _tokenId < 10_000 ? PERCENT : monsterMultiplier;
      
      // evilBonus will return 0 for all FrankenMonsters, as they are not eligible for the evil bonus
      return ((baseVotes * multiplier) / PERCENT) + stakedTimeBonus[_tokenId] + evilBonus(_tokenId);
    }
```

But `getTokenVotingPower()` uses some parameters like `monsterMultiplier` and `baseVotes` and the output would be changed for the same `tokenId` after the admin changed these settings.

Currently, `_stake()` and `_unstake()` calculates the token voting power independently and the below scenario would be possible.

- At the first time, `baseVotes = 20, monsterMultiplier = 50`.
- A user staked a `FrankenMonsters` and his voting power = 10 [

*[Content truncated...]*

---

### Example 2: H-1: The total community voting power is updated incorrectly when a user delegates.

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/91 

## Found by 
Trumpero, curiousapple, hansfriese

## Summary
When a user delegates their voting power from staked tokens, the total community voting power should be updated. But the update logic is not correct, the the total community voting power could be wrong values.

## Vulnerability Detail

```solidity
    tokenVotingPower[currentDelegate] -= amount;
    tokenVotingPower[_delegatee] += amount; 

    // If a user is delegating back to themselves, they regain their community voting power, so adjust totals up
    if (_delegator == _delegatee) {
      _updateTotalCommunityVotingPower(_delegator, true);

    // If a user delegates away their votes, they forfeit their community voting power, so adjust totals down
    } else if (currentDelegate == _delegator) {
      _updateTotalCommunityVotingPower(_delegator, false);
    }
```
When the total community voting power is increased in the first if statement, `_delegator`'s token voting power might be positive already and community voting power might be added to total community voting power before.

Also, `currentDelegate`'s token voting power might be still positive after delegation so we shouldn't remove the communitiy voting power this time.

## Impact
The total community voting power can be incorrect.

## Code Snippet
https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L293-L313

## Tool used
Manual Review

## Recommendati

*[Content truncated...]*

---

### Example 3: M-6: Delegate can keep can keep delegatee trapped indefinitely

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/23 

## Found by 
rvierdiiev, 0x52

## Summary

Users are allowed to delegate their votes to other users. Since staking does not implement checkpoints, users are not allowed to delegate or unstake during an active proposal if their delegate has already voted. A malicious delegate can abuse this by creating proposals so that there is always an active proposal and their delegatees are always locked to them.

## Vulnerability Detail

    modifier lockedWhileVotesCast() {
      uint[] memory activeProposals = governance.getActiveProposals();
      for (uint i = 0; i < activeProposals.length; i++) {
        if (governance.getReceipt(activeProposals[i], getDelegate(msg.sender)).hasVoted) revert TokenLocked();
        (, address proposer,) = governance.getProposalData(activeProposals[i]);
        if (proposer == getDelegate(msg.sender)) revert TokenLocked();
      }
      _;
    }

The above modifier is applied when unstaking or delegating. This reverts if the delegate of msg.sender either has voted or currently has an open proposal. The result is that under those conditions, the delgatee cannot unstake or delegate. A malicious delegate can abuse these conditions to keep their delegatees forever delegated to them. They would keep opening proposals so that delegatees could never unstake or delegate. A single users can only have a one proposal opened at the same time so they would use a secondary account to al

*[Content truncated...]*

---

### Example 4: M-5: castVote can be called by anyone even those without votes

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/25 

## Found by 
Trumpero, 0x52, hansfriese

## Summary

Governance#castVote can be called by anyone, even users that don't have any votes. Since the voting refund is per address, an adversary could use a large number of addresses to vote with zero votes to drain the vault.

## Vulnerability Detail

    function _castVote(address _voter, uint256 _proposalId, uint8 _support) internal returns (uint) {
        // Only Active proposals can be voted on
        if (state(_proposalId) != ProposalState.Active) revert InvalidStatus();
        
        // Only valid values for _support are 0 (against), 1 (for), and 2 (abstain)
        if (_support > 2) revert InvalidInput();

        Proposal storage proposal = proposals[_proposalId];

        // If the voter has already voted, revert        
        Receipt storage receipt = proposal.receipts[_voter];
        if (receipt.hasVoted) revert AlreadyVoted();

        // Calculate the number of votes a user is able to cast
        // This takes into account delegation and community voting power
        uint24 votes = (staking.getVotes(_voter)).toUint24();

        // Update the proposal's total voting records based on the votes
        if (_support == 0) {
            proposal.againstVotes = proposal.againstVotes + votes;
        } else if (_support == 1) {
            proposal.forVotes = proposal.forVotes + votes;
        } else if (_support == 2) {
            pr

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## vote-patterns.md
# Vote Security Patterns

## Overview

**Frequency**: 22 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 14 | 8 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, Spearbit, Shieldify

---

## Detection Checklist

- [ ] Check for vote vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] Multiple vote checkpoints per block will lead to incorrect vote accounting

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: HIGH

**Details**:

_Submitted by berndartmueller, also found by 0x52, 0xSky, bin2chen, cccz, Chom, davidbrai, elprofesor, izhuer, m9800, PwnPatrol, and rvierdiiev_

Voting power for each NFT owner is persisted within timestamp-dependent checkpoints. Every voting power increase or decrease is recorded. However, the implementation of `ERC721Votes` creates separate checkpoints with the same timestamp for each interaction, even when the interactions happen in the same block/timestamp.

### Impact

Checkpoints with the same `timestamp` will cause issues within the `ERC721Votes.getPastVotes(..)` function and will return incorrect votes for a given `_timestamp`.

### Proof of Concept

[lib/token/ERC721Votes.sol#L252-L253](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/lib/token/ERC721Votes.sol#L252-L253)

```solidity
/// @dev Records a checkpoint
/// @param _account The account address
/// @param _id The checkpoint id
/// @param _prevTotalVotes The account's previous voting weight
/// @param _newTotalVotes The account's new voting weight
function _writeCheckpoint(
    address _account,
    uint256 _id,
    uint256 _prevTotalVotes,
    uint256 _newTotalVotes
) private {
    // Get the pointer to store the checkpoint
    Checkpoint storage checkpoint = checkpoints[_account][_id];

    // Record the updated voting weight and current time
    checkpoint.votes = uint192(_newTotalVotes);
    checkpoint.timestamp = uint64(block.timestamp);

    emit Dele

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 2: Oracle.removeMember could, in the same epoch, allow members to vote multiple times and other members to not vote at all

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Oracle Vulnerability Report

**Severity:** High Risk  
**Context:** Oracle.1.sol#L213-L222  

## Description

The current implementation of `removeMember` is introducing an exploit that allows an oracle member to vote multiple times in the same epoch, while preventing another oracle that has never voted from casting a vote during the same epoch.

Due to the implementation of `OracleMembers.deleteItem`, the last item of the array is swapped with the item that is being deleted, and then the last element is popped.

### Example Scenario

1. At T0, add member `m0` to the list of members: `members[0] = m0`.
2. At T1, add member `m1` to the list of members: `members[1] = m1`.
3. At T3, `m0` calls `reportBeacon(...)`. This action triggers a call to `ReportsPositions.register(uint256(0));` which registers that the member at index 0 has voted.
4. At T4, the oracle admin calls `removeMember(m0)`. This operation swaps `m0`s address from the last position of the array with the position of the member being deleted. After this, it pops the last position of the array. The state changes from:
   - `members[0] = m0; members[1] = m1`
   - to `members[0] = m1;`.

At this point, the oracle member `m1` will not be able to vote during this epoch because when he/she calls `reportBeacon(...)`, the function will check:

```solidity
if (ReportsPositions.get(uint256(memberIndex))) {
    revert AlreadyReported(_epochId, msg.sender);
}
```

This is because `int256 memberIndex = OracleMembers.indexOf(

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 3: Attacker can destroy user voting power by setting `ERC721Power::totalPower` and all existing NFTs `currentPower` to 0

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

### Example 4: Attacker can combine flashloan with delegated voting to decide a proposal and withdraw their tokens while the proposal is still in Locked state

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

### Example 5: [H-01] PartyGovernance: Can vote multiple times by transferring NFT in same block as proposal

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Lambda, also found by Trust_

`PartyGovernanceNFT` uses the voting power at the time of proposal when calling `accept`. The problem with that is that a user can vote, transfer the NFT (and the voting power) to a different wallet, and then vote from this second wallet again during the same block that the proposal was created.
This can also be repeated multiple times to get an arbitrarily high voting power and pass every proposal unanimously.

The consequences of this are very severe. Any user (no matter how small his voting power is) can propose and pass arbitrary proposals animously and therefore steal all assets (including the precious tokens) out of the party.

### Proof Of Concept

This diff shows how a user with a voting power of 50/100 gets a voting power of 100/100 by transferring the NFT to a second wallet that he owns and voting from that one:

```diff
--- a/sol-tests/party/PartyGovernanceUnit.t.sol
+++ b/sol-tests/party/PartyGovernanceUnit.t.sol
@@ -762,6 +762,7 @@ contract PartyGovernanceUnitTest is Test, TestUtils {
         TestablePartyGovernance gov =
             _createGovernance(100e18, preciousTokens, preciousTokenIds);
         address undelegatedVoter = _randomAddress();
+        address recipient = _randomAddress();
         // undelegatedVoter has 50/100 intrinsic VP (delegated to no one/self)
         gov.rawAdjustVotingPower(undelegatedVoter, 50e18, address(0));
 
@@ -772,38 +773,13 @@ contract PartyGovernanceUnitTest is Test, TestUtils {

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 6: H-1: "Votes" balance can be increased indefinitely in multiple contracts

**Source**: Sherlock
**Protocol**: Tokensoft
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-tokensoft-judging/issues/41 

## Found by 
0xDanielH, 0xDjango, 0xbranded, 0xlx, AkshaySrivastav, BenRai, Czar102, Musaka, VAD37, Yuki, caventa, dany.armstrong90, jah, jkoppel, kutugu, magellanXtrachev, ni8mare, p-tsanev, p12473, pengun, r0bert, stopthecap, twicek, y1cunhui
## Summary
The "voting power" can be easily manipulated in the following contracts:
- `ContinuousVestingMerkle`
- `PriceTierVestingMerkle`
- `PriceTierVestingSale_2_0`
- `TrancheVestingMerkle`
- `CrosschainMerkleDistributor`
- `CrosschainContinuousVestingMerkle`
- `CrosschainTrancheVestingMerkle`
- All the contracts inheriting from the contracts listed above

This is caused by the public `initializeDistributionRecord()` function that can be recalled multiple times without any kind of access control:
```solidity
  function initializeDistributionRecord(
    uint32 _domain, // the domain of the beneficiary
    address _beneficiary, // the address that will receive tokens
    uint256 _amount, // the total claimable by this beneficiary
    bytes32[] calldata merkleProof
  ) external validMerkleProof(_getLeaf(_beneficiary, _amount, _domain), merkleProof) {
    _initializeDistributionRecord(_beneficiary, _amount);
  }
```

## Vulnerability Detail
The `AdvancedDistributor` abstract contract which inherits from the `ERC20Votes`, `ERC20Permit` and `ERC20` contracts, distributes tokens to beneficiaries with voting-while-vesting and administrative controls. Basically, 

*[Content truncated...]*

---

### Example 7: [H-03] Users Can Use `Flashloan` to Increase Voting Power of Expired Positions and Execute Proposal for Their Benefits

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

### Example 8: Attacker can at anytime dramatically lower `ERC721Power::totalPower` close to 0

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can at anytime dramatically lower `ERC721Power::totalPower` close to 0 using a permission-less attack contract by taking advantage of being able to call `ERC721Power::recalculateNftPower()` & `getNftPower()` for non-existent nfts:

```solidity
function getNftPower(uint256 tokenId) public view override returns (uint256) {
    if (block.timestamp <= powerCalcStartTimestamp) {
        return 0;
    }

    // @audit 0 for non-existent tokenId
    uint256 collateral = nftInfos[tokenId].currentCollateral;

    // Calculate the minimum possible power based on the collateral of the nft
    // @audit returns default maxPower for non-existent tokenId
    uint256 maxNftPower = getMaxPowerForNft(tokenId);
    uint256 minNftPower = maxNftPower.ratio(collateral, getRequiredCollateralForNft(tokenId));
    minNftPower = maxNftPower.min(minNftPower);

    // Get last update and current power. Or set them to default if it is first iteration
    // @audit both 0 for non-existent tokenId
    uint64 lastUpdate = nftInfos[tokenId].lastUpdate;
    uint256 currentPower = nftInfos[tokenId].currentPower;

    if (lastUpdate == 0) {
        lastUpdate = powerCalcStartTimestamp;
        // @audit currentPower set to maxNftPower which
        // is just the default maxPower even for non-existent tokenId!
        currentPower = maxNftPower;
    }

    // Calculate reduction amount
    uint256 powerReductionPercent = reductionPercent * (block.timestamp - lastUpdate);
    uint256 p

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 9: [H-02] Single host can unfairly skip veto period for proposal that does not have full host support

**Source**: Code4rena
**Protocol**: Party Protocol
**Impact**: HIGH

**Details**:

After a proposal passes the vote threshold, there is a delay before it can be executed so that hosts get a chance to `veto` it if they wish. If all hosts voting in favour of the proposal, then this veto period is skipped.

However, a single host can ensure the veto period is skipped even if no other hosts `accept` the proposal. The veto period is in place to prevent harmful/exploitative proposals from being executed, even if they are passed; therefore, a malicious/compromised host being able to skip the veto period can be seriously harmful to the protocol and its users. The [Tornado Cash governance hack](https://medium.com/coinmonks/tornado-cash-governance-hack-ec77ebb3aa68) from May 2023 is a relevant example, during which the attacker was able to steal around `$`1 million worth of assets.

This attack has a very low cost and a very high potential impact. If a malicious proposal is crafted in the same way used by the Tornado Cash attacker using hidden `CREATE2` and `SELFDESTRUCT` operations, then it is entirely feasible that it would meet the voting threshold, as many voters may not be savvy enough to spot the red flags.

### Proof of Concept

`PartyGovernance#abdicateHost` is a function that allows a host to renounce their host privileges, and transfer them to another address.

```solidity
File: contracts\party\PartyGovernance.sol

457:     /// @notice Transfer party host status to another.
458:     /// @param newPartyHost The address of the new host.
459:     function abdi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-party)

---

### Example 10: Decrementing the quorum in Oracle in some scenarios can open up a frontrunning/backrunning opportunity for some oracle members

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

### Example 11: [M-09] `activateProposal()` need time delay

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by &#95;&#95;141345&#95;&#95;, also found by 0x1f8b, Trust, V&#95;B, and zzzitron_

<https://github.com/code-423n4/2022-08-olympus/blob/b5e139d732eb4c07102f149fb9426d356af617aa/src/policies/Governance.sol#L205-L262><br>

There is no time lock or delay when activating a proposal, the previous one could be replaced immediately. In `vote()` call, a user might want to vote for the previous proposal, but if the `vote()` call and the `activateProposal()` is very close or even in the same block, it is quite possible that the user actually voted for another proposal without much knowledge of. A worse case is some malicious user watching the mempool, and front run a big vote favor/against the `activeProposal`, effectively influence the voting result.

These situations are not what the governance intends to deliver, and might also affect the results of 2 proposals.

### Proof of Concept

`activateProposal()` can take effect right away, replacing the `activeProposal`. And `vote()` does not specify which `proposalId` to vote for, but the `activeProposal` could be different from last second.

src/policies/Governance.sol

```solidity
    function activateProposal(uint256 proposalId_) external {
        ProposalMetadata memory proposal = getProposalMetadata[proposalId_];

        if (msg.sender != proposal.submitter) {
            revert NotAuthorizedToActivateProposal();
        }

        if (block.timestamp > proposal.submissionTimestamp + ACTIVATION_DEADLINE) {
            re

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 12: H-1: `QVSimpleStrategy` never updates `allocator.voiceCredits`.

**Source**: Sherlock
**Protocol**: Allo V2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-09-Gitcoin-judging/issues/150 

## Found by 
0x00ffDa, 0x3b, 0xMAKEOUTHILL, 0xarno, 0xbepresent, 0xkaden, Arz, BenRai, GimelSec, HChang26, HHK, Kodyvim, Kow, Kral01, Martians, Nyx, WATCHPUG, ZdravkoHr., al88nsk, alexxander, ashirleyshe, ast3ros, bronze\_pickaxe, carrotsmuggler, chaduke, coffiasd, cu5t0mPe0, dany.armstrong90, detectiveking, dipp, fibonacci, jah, jkoppel, jovi, lemonmon, lil.eth, nobody2018, osmanozdemir1, pengun, pontifex, qbs, rvierdiiev, sandNallani, seeques, simon135, tnquanghuy0512, toshii, wangxx2026
Every allocator in `QVSimpleStrategy` has a maximum credit limit. An allocator should not be able to bypass the limit. However, `QVSimpleStrategy` fails to record the allocated votes. An allocator can vote as many as possible.

## Vulnerability Detail

`QVSimpleStrategy._allocate` calls `_hasVoiceCreditsLeft` to check that the recipient has voice credits left to allocate.
https://github.com/sherlock-audit/2023-09-Gitcoin/blob/main/allo-v2/contracts/strategies/qv-simple/QVSimpleStrategy.sol#L121
```solidity
    function _allocate(bytes memory _data, address _sender) internal virtual override {
        

        // check that the recipient has voice credits left to allocate
        if (!_hasVoiceCreditsLeft(voiceCreditsToAllocate, allocator.voiceCredits)) revert INVALID();

        _qv_allocate(allocator, recipient, recipientId, voiceCreditsToAllocate, _sender);
    }
```

`QVSimpleStrategy._hasVoiceCreditsLeft` c

*[Content truncated...]*

---

### Example 13: [H-05] ArbitraryCallsProposal.sol and ListOnOpenseaProposal.sol safeguards can be bypassed by cancelling in-progress proposal allowing the majority to steal NFT

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

### Example 14: [H-04] Old delegatee not deleted when delegating to new tokenId

**Source**: Code4rena
**Protocol**: Golom
**Impact**: HIGH

**Details**:

[VoteEscrowDelegation.sol#L80](https://github.com/code-423n4/2022-07-golom/blob/8f198624b97addbbe9602a451c908ea51bd3357c/contracts/vote-escrow/VoteEscrowDelegation.sol#L80)<br>

In `delegate`, when a user delegates to a new tokenId, the tokenId is not removed from the current delegatee. Therefore, one user can easily multiply his voting power, which makes the toking useless for voting / governance decisions.

### Proof Of Concept

Bob owns the token with ID 1 with a current balance of 1000. He also owns tokens 2, 3, 4, 5. Therefore, he calls `delegate(1, 2)`, `delegate(1, 3)`, `delegate(1, 4)`, `delegate(1, 5)`. Now, if there is a governance decision and `getVotes` is called, Bobs balance of 1000 is included in token 2, 3, 4, and 5. Therefore, he quadrupled the voting power of token 1.

### Recommended Mitigation Steps

Remove the entry in `delegatedTokenIds` of the old delegatee or simply call `removeDelegation` first.

**[zeroexdead (Golom) confirmed](https://github.com/code-423n4/2022-07-golom-findings/issues/169)**

**[zeroexdead (Golom) commented](https://github.com/code-423n4/2022-07-golom-findings/issues/169#issuecomment-1238345165):**
 > Fixed. 
> 
> Ref: https://github.com/golom-protocol/contracts/commit/c74d95b4105eeb878d2781982178db5ca08a1a9b



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 15: [H-07] Attacker can DOS private party by donating ETH then calling buy

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by 0x52_

Party is DOS'd and may potentially lose access to NFT.

### Proof of Concept

[Crowdfund.sol#L280-L298](https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/crowdfund/Crowdfund.sol#L280-L298)

    party = party_ = partyFactory
        .createParty(
            address(this),
            Party.PartyOptions({
                name: name,
                symbol: symbol,
                governance: PartyGovernance.GovernanceOpts({
                    hosts: governanceOpts.hosts,
                    voteDuration: governanceOpts.voteDuration,
                    executionDelay: governanceOpts.executionDelay,
                    passThresholdBps: governanceOpts.passThresholdBps,
                    totalVotingPower: _getFinalPrice().safeCastUint256ToUint96(),
                    feeBps: governanceOpts.feeBps,
                    feeRecipient: governanceOpts.feeRecipient
                })
            }),
            preciousTokens,
            preciousTokenIds
        );

[BuyCrowdfundBase.sol#L166-L173](https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/crowdfund/BuyCrowdfundBase.sol#L166-L173)

    function _getFinalPrice()
        internal
        override
        view
        returns (uint256)
    {
        return settledPrice;
    }

When BuyCrowdFund.sol successfully completes a buy, totalVotingPower is set to `\_getFinalPrice` which in the case of BuyCrowd

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 16: H-4: Staking#_unstake removes votes from wrong person if msg.sender != owner

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/30 

## Found by 
0x52, cccz

## Summary

Staking#_unstake allows any msg.sender to unstake tokens for any owner that has approved them. The issue is that even when msg.sender != owner the votes are removed from msg.sender instead of owner. The result is that the owner keeps their votes and msg.sender loses theirs. This could be abused to hijack or damage voting.

## Vulnerability Detail

    address owner = ownerOf(_tokenId);
    if (msg.sender != owner && !isApprovedForAll[owner][msg.sender] && msg.sender != getApproved[_tokenId]) revert NotAuthorized();

Staking#_unstake allows any msg.sender to unstake tokens for any owner that has approved them.

    uint lostVotingPower;
    for (uint i = 0; i < numTokens; i++) {
        lostVotingPower += _unstakeToken(_tokenIds[i], _to);
    }

    votesFromOwnedTokens[msg.sender] -= lostVotingPower;
    // Since the delegate currently has the voting power, it must be removed from their balance
    // If the user doesn't delegate, delegates(msg.sender) will return self
    tokenVotingPower[getDelegate(msg.sender)] -= lostVotingPower;
    totalTokenVotingPower -= lostVotingPower;

After looping through _unstakeToken all accumulated votes are removed from msg.sender. The problem with this is that msg.sender is allowed to unstake tokens for users other than themselves and in these cases they will lose votes rather than the user who owns the token.

Example:
User 

*[Content truncated...]*

---

### Example 17: [M-03] Burning an NFT can be used to block voting

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

A new validation in the `accept()` function has been introduced in order to mitigate a potential attack to the party governance.

By burning an NFT, a party member can reduce the total voting power of the party just before creating a proposal and voting for it. Since the snapshot used to vote is previous to this action, this means the user can still use their burned voting power while voting in a proposal with a reduced total voting power. This is stated in the comment attached to the new validation:

<https://github.com/code-423n4/2023-05-party/blob/main/contracts/party/PartyGovernance.sol#L589-L598>

```solidity
589:         // Prevent voting in the same block as the last burn timestamp.
590:         // This is to prevent an exploit where a member can burn their card to
591:         // reduce the total voting power of the party, then propose and vote in
592:         // the same block since `getVotingPowerAt()` uses `values.proposedTime - 1`.
593:         // This would allow them to use the voting power snapshot just before
594:         // their card was burned to vote, potentially passing a proposal that
595:         // would have otherwise not passed.
596:         if (lastBurnTimestamp == block.timestamp) {
597:             revert CannotRageQuitAndAcceptError();
598:         }
```
This change can be abused by a bad actor in order to DoS the voting of a proposal. The call to `accept()` can be front-runned with a call to `burn()`, which would trigger the revert in the origin

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-party)

---

### Example 18: [M-07] `totalVotingPower` needs to be snapshotted for each proposal because it can change and thereby affect consensus when accepting / vetoing proposals

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-04-party/blob/440aafacb0f15d037594cebc85fd471729bcb6d9/contracts/party/PartyGovernance.sol#L598-L605>

<https://github.com/code-423n4/2023-04-party/blob/440aafacb0f15d037594cebc85fd471729bcb6d9/contracts/proposals/VetoProposal.sol#L46-L51>

This issue does not manifest itself in a limited segment of the code.

Instead it spans multiple contracts and derives its impact from the interaction of these contracts.

In the PoC section I will do my best in explaining how this results in an issue.

I discussed this with the sponsor and they explained to me that this issue is due to a PR that has unintentionally not been merged.

![Discord message](https://user-images.githubusercontent.com/118979828/231990051-b9f731f1-1678-43e3-81e4-7ec0164bdc10.png)

So they have already written the code that is necessary to fix this issue. It's just not been merged with this branch. So since the sponsor knows about this already and it's just the PR that has gone missing it's not necessary for me to provide the full Solidity code to fix this issue.

In short, this issue is due to the fact that the `totalVotingPower` is not snapshotted when a proposal is created.

The votes that are used to vote for a proposal (or veto it) are based on a specific snapshot (1 block prior to the proposal being created).

When the `totalVotingPower` changes this leads to unintended consequences.

When `totalVotingPower` decreases, votes become more valuable than they should be.

And whe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-party)

---

### Example 19: M-1: User Can Vote Even When They Have 0 Locked Mento (Edge Case)

**Source**: Sherlock
**Protocol**: Mento
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-mento-judging/issues/14 

## Found by 
ComposableSecurity, HHK, Kose, ParthMandale, sakshamguruji, slylandro, y4y
## Summary

There exists an edge case where the user will be withdrawing his entire locked MENTO amount and even then will be able to vote , this is depicted by a PoC to make things clearer.

## Vulnerability Detail

The flow to receiving voting power can be understood in simple terms as follows ->

Users locks his MENTO and chooses a delegate-> received veMENTO which gives them(delegatee) voting power (there's cliff and slope at play too)

The veMENTO is not a standard ERC20 , it is depicted through "lines" , voting power declines ( ie. slope period) with time
and with time you can withdraw more of your MENTO.

The edge case where the user will be withdrawing his entire locked MENTO amount and even then will be able
to vote is as follows ->

1.) User has locked his MENTO balance in the Locking.sol

2.) The owner of the contract "stops" the contract for some emergency reason.

3.) In this stopped state the user calls withdraw() which calls getAvailableForWithdraw() here https://github.com/sherlock-audit/2024-02-mento/blob/main/mento-core/contracts/governance/locking/Locking.sol#L97

4.) Since the contract is stopped , the `getAvailableForWithdraw` will return the entire locked amount of the user as withdrawable 

```solidity
function getAvailableForWithdraw(address account) public view returns (uint96) {
    uint96

*[Content truncated...]*

---

### Example 20: M-7: castVote can be called by anyone even those without votes

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/25 

## Found by 
hansfriese, 0x52, Trumpero

## Summary

Governance#castVote can be called by anyone, even users that don't have any votes. Since the voting refund is per address, an adversary could use a large number of addresses to vote with zero votes to drain the vault.

## Vulnerability Detail

    function _castVote(address _voter, uint256 _proposalId, uint8 _support) internal returns (uint) {
        // Only Active proposals can be voted on
        if (state(_proposalId) != ProposalState.Active) revert InvalidStatus();
        
        // Only valid values for _support are 0 (against), 1 (for), and 2 (abstain)
        if (_support > 2) revert InvalidInput();

        Proposal storage proposal = proposals[_proposalId];

        // If the voter has already voted, revert        
        Receipt storage receipt = proposal.receipts[_voter];
        if (receipt.hasVoted) revert AlreadyVoted();

        // Calculate the number of votes a user is able to cast
        // This takes into account delegation and community voting power
        uint24 votes = (staking.getVotes(_voter)).toUint24();

        // Update the proposal's total voting records based on the votes
        if (_support == 0) {
            proposal.againstVotes = proposal.againstVotes + votes;
        } else if (_support == 1) {
            proposal.forVotes = proposal.forVotes + votes;
        } else if (_support == 2) {
            pr

*[Content truncated...]*

---

### Example 21: M-8: Adversary can abuse delegating to lower quorum

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/24 

## Found by 
0x52

## Summary

When a user delegates to another user they surrender their community voting power. The quorum threshold for a vote is determined when it is created. Users can artificially lower quorum by delegating to other users then creating a proposal. After it's created they can self delegate and regain all their community voting power to reach quorum easier. 

## Vulnerability Detail

    // If a user is delegating back to themselves, they regain their community voting power, so adjust totals up
    if (_delegator == _delegatee) {
      _updateTotalCommunityVotingPower(_delegator, true);

    // If a user delegates away their votes, they forfeit their community voting power, so adjust totals down
    } else if (currentDelegate == _delegator) {
      _updateTotalCommunityVotingPower(_delegator, false);
    }

When a user delegates to user other than themselves, they forfeit their community votes and lowers the total number of votes. When they self delegate again they will recover all their community voting power.

        newProposal.id = newProposalId.toUint96();
        newProposal.proposer = msg.sender;
        newProposal.targets = _targets;
        newProposal.values = _values;
        newProposal.signatures = _signatures;
        newProposal.calldatas = _calldatas;

        //@audit quorum votes locked at creation

        newProposal.quorumVotes = quorumVotes().toUint24(

*[Content truncated...]*

---

### Example 22: M-5: castVote can be called by anyone even those without votes

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/25 

## Found by 
Trumpero, 0x52, hansfriese

## Summary

Governance#castVote can be called by anyone, even users that don't have any votes. Since the voting refund is per address, an adversary could use a large number of addresses to vote with zero votes to drain the vault.

## Vulnerability Detail

    function _castVote(address _voter, uint256 _proposalId, uint8 _support) internal returns (uint) {
        // Only Active proposals can be voted on
        if (state(_proposalId) != ProposalState.Active) revert InvalidStatus();
        
        // Only valid values for _support are 0 (against), 1 (for), and 2 (abstain)
        if (_support > 2) revert InvalidInput();

        Proposal storage proposal = proposals[_proposalId];

        // If the voter has already voted, revert        
        Receipt storage receipt = proposal.receipts[_voter];
        if (receipt.hasVoted) revert AlreadyVoted();

        // Calculate the number of votes a user is able to cast
        // This takes into account delegation and community voting power
        uint24 votes = (staking.getVotes(_voter)).toUint24();

        // Update the proposal's total voting records based on the votes
        if (_support == 0) {
            proposal.againstVotes = proposal.againstVotes + votes;
        } else if (_support == 1) {
            proposal.forVotes = proposal.forVotes + votes;
        } else if (_support == 2) {
            pr

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 22
- Examples shown: 22
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## checkpoint-patterns.md
# CheckPoint Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 0 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for checkpoint vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] Multiple vote checkpoints per block will lead to incorrect vote accounting

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: HIGH

**Details**:

_Submitted by berndartmueller, also found by 0x52, 0xSky, bin2chen, cccz, Chom, davidbrai, elprofesor, izhuer, m9800, PwnPatrol, and rvierdiiev_

Voting power for each NFT owner is persisted within timestamp-dependent checkpoints. Every voting power increase or decrease is recorded. However, the implementation of `ERC721Votes` creates separate checkpoints with the same timestamp for each interaction, even when the interactions happen in the same block/timestamp.

### Impact

Checkpoints with the same `timestamp` will cause issues within the `ERC721Votes.getPastVotes(..)` function and will return incorrect votes for a given `_timestamp`.

### Proof of Concept

[lib/token/ERC721Votes.sol#L252-L253](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/lib/token/ERC721Votes.sol#L252-L253)

```solidity
/// @dev Records a checkpoint
/// @param _account The account address
/// @param _id The checkpoint id
/// @param _prevTotalVotes The account's previous voting weight
/// @param _newTotalVotes The account's new voting weight
function _writeCheckpoint(
    address _account,
    uint256 _id,
    uint256 _prevTotalVotes,
    uint256 _newTotalVotes
) private {
    // Get the pointer to store the checkpoint
    Checkpoint storage checkpoint = checkpoints[_account][_id];

    // Record the updated voting weight and current time
    checkpoint.votes = uint192(_newTotalVotes);
    checkpoint.timestamp = uint64(block.timestamp);

    emit Dele

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 2: [H-04] ERC20ConvictionScore._writeCheckpoint` does not write to storage on same block

**Source**: Code4rena
**Protocol**: FairSide
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

In `ERC20ConvictionScore._writeCheckpoint`, when the checkpoint is overwritten (`checkpoint.fromBlock == blockNumber`), the new value is set to the `memory checkpoint` structure and never written to storage.

```solidity
// @audit this is MEMORY, setting new convictionScore doesn't write to storage
Checkpoint memory checkpoint = checkpoints[user][nCheckpoints - 1];

if (nCheckpoints > 0 && checkpoint.fromBlock == blockNumber) {
    checkpoint.convictionScore = newCS;
}
```

Users that have their conviction score updated several times in the same block will only have their first score persisted.

###### POC
*   User updates their conviction with `updateConvictionScore(user)`
*   **In the same block**, the user now redeems an NFT conviction using `acquireConviction(id)`. This calls `_increaseConvictionScore(user, amount)` which calls `_writeCheckpoint(..., prevConvictionScore + amount)`. The updated checkpoint is **not** written to storage, and the user lost their conviction NFT. (The conviction/governance totals might still be updated though, leading to a discrepancy.)

#### Impact
Users that have their conviction score updated several times in the same block will only have their first score persisted.

This also applies to the total conviction scores `TOTAL_CONVICTION_SCORE` and `TOTAL_GOVERNANCE_SCORE` (see `_updateConvictionTotals`) which is a big issue as these are updated a lot of times each block.

It can also be used for inflating a user's convic

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-fairside)

---

### Example 3: H-1: Bypass the blacklist restriction because the blacklist check is not done when minting or burning

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/64 

## Found by 
ctf\_sec, dirk\_y, p-tsanev, toshii
## Summary

Bypass the blacklist restriction because the blacklist check is not done when minting or burning

## Vulnerability Detail

In the whitepaper:

> the protocol emphasis that they implement a blacklist feature for enforcing OFAC, AML and other account security requirements
A blacklisted will not able to send or receive tokens

the protocol want to use the whitelist feature to be compliant to not let the blacklisted address send or receive dSahres

For this reason, before token transfer, the protocol check if address from or address to is blacklisted and the blacklisted address can still create buy order or sell order

```solidity
   function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // Restrictions ignored for minting and burning
        // If transferRestrictor is not set, no restrictions are applied

        // @audit
        // why don't you not apply mint and burn in blacklist?
        if (from == address(0) || to == address(0) || address(transferRestrictor) == address(0)) {
            return;
        }

        // Check transfer restrictions
        transferRestrictor.requireNotRestricted(from, to);
    }
```

this is calling

```solidity
function requireNotRestricted(address from, address to) external view virtual {
	// Check if either account is restricted
	if (blacklist[from] || blackl

*[Content truncated...]*

---

### Example 4: H-1: Flashloan `TEL` tokens to stake and exit in the same block can fake a huge amount of stake with minimal material cost

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

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## auction-patterns.md
# Auction Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 10 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Spearbit

---

## Detection Checklist

- [ ] Check for auction vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] User can bypass `MAX_EXPIRATION` when extend expiration

**Source**: Code4rena
**Protocol**: Initia
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2025-01-initia-move/blob/a96f5136c4808f6968564a4592fe2d6ac243a233/usernames-module/sources/name_service.move# L483>

### Finding Description and Impact

In the `extend_expiration` function, the validation for the duration is incorrect, allowing the user to bypass `MAX_EXPIRATION`:
```

 let expiration_date = metadata::get_expiration_date(token);
        let new_expiration_date = if (expiration_date > timestamp) {
            expiration_date + duration
        } else {
            timestamp + duration
        };

        assert!(
=>            new_expiration_date - expiration_date <= MAX_EXPIRATION,
            error::invalid_argument(EMIN_DURATION),
        );

        metadata::update_expiration_date(token, new_expiration_date);
```

The issue arises because the code subtracts `new_expiration_date - expiration_date` for validation.

Assume a user registers a domain and the `expiration_date` is equal to `MAX_EXPIRATION` `+` timestamp. Then, the user performs `extend_expiration` with a `duration` value equal to the `MAX_EXPIRATION`, the `new_expiration_date` becomes `expiration_date + duration`.

This leads to the following verification check passing:
```

assert!(
    new_expiration_date - expiration_date <= MAX_EXPIRATION,
    error::invalid_argument(EMIN_DURATION),
);
```

Since the `new_expiration_date` is calculated using `expiration_date` `+` `duration`, the subtraction `(new_expiration_date - expiration_date)` will always be less than to `

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2025-01-initia-move)

---

### Example 2: [H-03] `saleReceiver` and `feeReceiver` can steal refunds after sale has ended

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

### Example 3: settleAuction() doesn't check if the auction was successful

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Risk Report

## Severity
**High Risk**

## Context
`CollateralToken.sol#L600`

## Description
The `settleAuction()` function is a privileged functionality called by `LienToken.payDebtViaClearingHouse()`. It is intended to be called on a successful auction, but it lacks verification to ensure this is the case. 

Anyone can create a fake Seaport order with one of its considerations set as the `CollateralToken`, as described in Issue 93. Another potential issue arises if the Seaport orders can be "Restricted" in the future. In that scenario, an authorized entity could force the execution of `settleAuction()` on `CollateralToken`, and when Seaport tries to call back on the zone to validate, it would likely fail.

## Recommendation
The following validations can be performed:

- `CollateralToken` doesn't own the underlying NFT.
- `collateralIdToAuction[collateralId]` is active.

By implementing these checks, `settleAuction()` can only be called upon the successful completion of the Seaport auction created by the Astaria protocol.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: [H-14] Fund will be stuck if a buyout is started while there are pending migration proposals

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by shenwilly, also found by 0x52, codexploder, dipp, kenzo, Lambda, MEP, panprog, smiling&#95;heretic, Treasure-Seeker, TrungOre, xiaoming90, and zzzitron_

Funds in migration proposals could potentially be stuck forever if a buyout auction on the same vault is started by other party.

Most of the functions within `Migration.sol` can only be executed depending on the state of buyout auction in `Buyout.sol`. When there is no buyout happening, a migration proposal can be made and anyone can contribute to the proposal. However, it is possible that a buyout auction is started by another party while a pending proposal is not commited yet.

When this scenario happens, there is no action that could be taken to interact with the pending proposal. All funds that have been contributed cannot be withdrawn. This is because the functions only check for the state of the buyout auction, instead of also considering whether the buyout auction's proposer is `Migration.sol`:

    (address token, uint256 id) = IVaultRegistry(registry).vaultToToken(_vault);
    if (id == 0) revert NotVault(_vault);
    // Reverts if buyout state is not inactive
    (, , State current, , , ) = IBuyout(buyout).buyoutInfo(_vault);
    State required = State.INACTIVE;
    if (current != required) revert IBuyout.InvalidState(required, current);

Proposal contributors have to wait until the buyout failed before they can withdraw their funds. In case the buyout succeeded, their funds will be stuck forever.

#

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 5: M-1: Auction fails if the 'Honorarium Rate' is 0%

**Source**: Sherlock
**Protocol**: RadicalxChange
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-radicalxchange-judging/issues/31 

## Found by 
Al-Qa-qa, sammy
## Summary
The Honorarium Rate is the required percentage of a winning Auction Pitch bid that the Steward makes to the Creator Circle at the beginning of each Stewardship Cycle. 

`$$ Winning Bid * Honorarium Rate = Periodic Honorarium $$`

To mimic the dynamics of private ownership, the _Creator Circle_ may choose a 0% _Honorarium Rate_. However, doing so breaks the functionality of the protocol.
## Vulnerability Detail
To place a bid, a user must call the [`placeBid`](https://github.com/RadicalxChange/pco-art/blob/4acd6b06840028ba616b6200439ce0d6aa1e6276/contracts/auction/facets/EnglishPeriodicAuctionFacet.sol#L153) function in `EnglishPeriodicAuctionFacet.sol` and deposit collateral(`collateralAmount`) equal to `bidAmount + feeAmount`. The `feeAmount` here represents the _Honorarium Rate_ mentioned above. 
The `placeBid` function calls the [`_placeBid`](https://github.com/RadicalxChange/pco-art/blob/4acd6b06840028ba616b6200439ce0d6aa1e6276/contracts/auction/EnglishPeriodicAuctionInternal.sol#L286) internal function in `EnglishPeriodicAuctionInternal.sol` which calculates the  `totalCollateralAmount` as follows : 
```solidity
uint256 totalCollateralAmount = bid.collateralAmount + collateralAmount;
```
Here, `bid.collateralAmount` is the cumulative collateral deposited by the bidder in previous bids during the current auction round(i.e, zero if no bids were place

*[Content truncated...]*

---

### Example 6: M-16: Auction timers following liquidity can fall through the floor price causing pool insolvency

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

### Example 7: M-12: Deposits are eliminated before currently unclaimed reserves when there is no reserve auction

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/102 

## Found by 
hyh

## Summary

Reserves that were unclaimed during last reserve auction that's now ended are not utilized for bad debt coverage and are treated as liabilities despite it is the free reserve funds of the pool.

Due to that deposits are being written off when there are still reserve funds exist and deposits' turn as a last resort liquidity source aren't came yet.

## Vulnerability Detail

Suppose auctioned reserves weren't taken for any reason: say no market participants were there for that particular pool in the period when reserve auction implied Ajna token price was above market. Then there is no liability, i.e. that amount is free pool funds and to be used ahead of HPB deposits to cover any deficits.

Currently that's not happening, instead unclaimed reserves are frozen and aren't used. I.e. system treats these funds as being liable (while they aren't, auction is ended), so only very last reserve funds, that weren't yet added to the reserve auctions pot, can be used to cover bad debt. When there are not enough such funds, deposits are written off.

## Impact

Deposit holders take a loss when the pool in fact do have reserve funds to cover bad debt. This loss isn't a part of the declared mechanics of the protocol.

Reserve auction can end up with not all auctioned reserves taken frequently enough due to, for example:
- short period of time when Ajna token were overpriced in it,
- or th

*[Content truncated...]*

---

### Example 8: [M-10] Bidder Funds Can Become Unrecoverable Due to 1 second Overlap in `participateToAuction()` and `claimAuction()`

**Source**: Code4rena
**Protocol**: NextGen
**Impact**: MEDIUM

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-10-nextgen/blob/main/smart-contracts/AuctionDemo.sol#L57><br>
<https://github.com/code-423n4/2023-10-nextgen/blob/main/smart-contracts/AuctionDemo.sol#L104>

### Impact

Bidder funds may become irretrievable if the `participateToAuction()` function is executed after `claimAuction()` during a 1-second overlap.

### Proof of Concept

The protocol allows bidders to use the `participateToAuction()` function up to the auction's end time.

```solidity
    function participateToAuction(uint256 _tokenid) public payable {
      ->require(msg.value > returnHighestBid(_tokenid) && block.timestamp <= minter.getAuctionEndTime(_tokenid) && minter.getAuctionStatus(_tokenid) == true);
        auctionInfoStru memory newBid = auctionInfoStru(msg.sender, msg.value, true);
        auctionInfoData[_tokenid].push(newBid);
    }
```

However, the issue arises when an auction winner immediately calls `claimAuction()` right after the auction concludes, creating a 1-second window during which both `claimAuction()` and `participateToAuction()` can be executed.

```solidity
    function claimAuction(uint256 _tokenid) public WinnerOrAdminRequired(_tokenid,this.claimAuction.selector){
      ->require(block.timestamp >= minter.getAuctionEndTime(_tokenid) && auctionClaim[_tokenid] == false && minter.getAuctionStatus(_tokenid) == true);
        auctionClaim[_tokenid] = true;
        uint256 highestBid = returnHighestBid(_tokenid);
        address ownerOf

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-nextgen)

---

### Example 9: [M-04] Auction won't work correctly with fee-on-transfer & rebasing tokens

**Source**: Pashov Audit Group
**Protocol**: Rolling Dutch Auction
**Impact**: MEDIUM

**Details**:

**Impact:**
High, as it can lead to a loss of value

**Likelihood:**
Low, as such tokens are not so common

**Description**

The code in `createAuction` does the following:

```solidity
IERC20(reserveToken).transferFrom(msg.sender, address(this), reserveAmount);
...
...
state.reserves = reserveAmount;
```

so it basically caches the expected transferred amount. This will not work if the `reserveToken` has a fee-on-transfer mechanism, since the actual received amount will be less because of the fee. It is also a problem if the token used had a rebasing mechanism, as this can mean that the contract will hold less balance than what it cached in `state.reserves` for the auction, or it will hold more, which will be stuck in the protocol.

**Recommendations**

You can either explicitly document that you do not support tokens with a fee-on-transfer or rebasing mechanism or you can do the following:

1. For fee-on-transfer tokens, check the balance before and after the transfer and use the difference as the actual amount received.
2. For rebasing tokens, when they go down in value, you should have a method to update the cached `reserves` accordingly, based on the balance held. This is a complex solution.
3. For rebasing tokens, when they go up in value, you should add a method to actually transfer the excess tokens out of the protocol.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-03-01-Rolling Dutch Auction.md)

---

### Example 10: M-7: Malicious users can exploit the auction and make profit when the SetToken is not locked.

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/57 

## Found by 
ast3ros
## Summary

The SetToken can be minted and redeemed by anyone when it is not locked during rebalancing. This can allow malicious users to front-run and back-run the bidders and manipulate the auction outcome.

## Vulnerability Detail

When rebalancing, the token manager can configure if the SetToken is locked or not. If the SetToken is not locked, anyone can mint and redeem the SetToken using BasicIssuanceModule. The token manager can also configure the pricing mechanism via the priceAdapter. There are some mechanisms:
- ConstantPriceAdapter: the price is fixed - similar to place limit orders.
- BoundedStepWise adapters: like Dutch Auction which the price can increase/decrease over time.

Let's see an example: 

The current price of WETH is 1940 USDC.
Total supply of the SetToken is 10.

A Set Token with component WETH and current unit(1 WETH) wants to achieve target unit (0.5 WETH - 975 USDC).
- Current unit: 1 WETH => Current notional: 10 WETH
- Target unint: 0.5 WETH - 975 USDC => Target notional: (5 WETH - 9750 USDC)

To achieve this, it needs to sell WETH to buy USDC. The manager starts rebalancing using linear price curve: start at $2000, lower to minimum $1900, take steps of $0.1 every minute. It also chooses USDC as the quote token.

Assuming when the price of WETH reaches 1950 USDC, a bidder bids for all of the available WETH for the rebalance process, which is 0.5 WETH p

*[Content truncated...]*

---

### Example 11: M-6: Target raises can be highly damaging for dutch auctions with multiple components

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/45 

## Found by 
0x52
## Summary

Multi-component dutch auctions are fundamentally incompatible with target raises and will lead to inefficient pricing causing loss to set token.

## Vulnerability Detail

The AuctionRebalanceModuleV1 allows targets to be increased when all component targets have been met and there is still excess quote token. When combined with multiple components, it his highly likely that these target raises will lead to inefficient pricing which will cause loss to the set token.

Consider the following a set token has the following composition that has target raises enabled:

40% USDC
30% WBTC
30% WETH

The manager wishes to rebalance the set to the following using USDC as the quote token:

20% USDC
40% WBTC
40% WETH

Assume the WETH portion of the execute within the first hour of the auction. The WBTC on the other hand doesn't execute until 12 hours in. Assume there is excess quote so the target is increased. The issue is that now because of the change in time, the WETH auction is now well above the market price. This buys the WETH for a large loss compared to the market price of WETH.

## Impact

Pricing after target raises will likely be heavily skewed from market prices for some components lead to set token losses

## Code Snippet

[AuctionRebalanceModuleV1.sol#L359-L380](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionR

*[Content truncated...]*

---

### Example 12: M-4: Full inventory asset purchases can be DOS'd via frontrunning

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/41 

## Found by 
0x52, Arabadzhiev
## Summary

Users who attempt to swap the entire component value can be frontrun with a very small bid making their transaction revert

## Vulnerability Detail

[AuctionRebalanceModuleV1.sol#L795-L796](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L795-L796)

        // Ensure that the component quantity in the bid does not exceed the available auction quantity.
        require(_componentQuantity <= bidInfo.auctionQuantity, "Bid size exceeds auction quantity");

When creating a bid, it enforces the above requirement. This prevents users from buying more than they should but it is also a source of an easy DOS attack. Assume a user is trying to buy the entire balance of a component, a malicious user can frontrun them buying only a tiny amount. Since they requested the entire balance, the call with fail. This is a useful technique if an attacker wants to DOS other buyers to pass the time and get a better price from the dutch auction.

## Impact

Malicious user can DOS legitimate users attempting to purchase the entire amount of component

## Code Snippet

[AuctionRebalanceModuleV1.sol#L772-L836](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L772-L836)

## Tool used

Manual Review

## Recommendation

Allow

*[Content truncated...]*

---

### Example 13: [M-07] Attacker can force AuctionCrowdfunds to bid their entire contribution up to maxBid

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

_Submitted by Trust, also found by cccz_

AuctionCrowdfund's `bid()` allows any user to compete on an auction on the party's behalf. The code in `bid()` forbids placing a bid if party is already winning the auction:

    if (market.getCurrentHighestBidder(auctionId_) == address(this)) {
                revert AlreadyHighestBidderError();
            }

However, it does not account for attackers placing bids from their own wallet, and then immediately overbidding them using the party's funds. This can be used in two ways:

1.  Attacker which lists an NFT, can force the party to spend all its funds up to maxBid on the auction, even if the party could have purchased the NFT for much less.
2.  Attackers can grief random auctions, making them pay the absolute maximum for the item. Attackers can use this to drive the prices of NFT items up, profiting from this using secondary markets.

### Impact

Parties can be stopped from buying items at a good value without any risk to the attacker.

### Proof of Concept

1.  Attacker places an NFT for sale, valued at X
2.  Attacker creates an AuctionCrowdfund, with maxBid = Y such that Y = 2X
3.  Current bid for the NFT is X - AUCTION_STEP
4.  Users contribute to the fund, which now has 1.5X
5.  Users call `bid()` to bid X  for the NFT
6.  Attacker bids for the item externally for 1.5X - AUCTION_STEP
7.  Attacker calls `bid()` to bid 1.5X for the NFT
8.  Attacker sells his NFT for 1.5X although no one apart from the party was interested in buy

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 14: [L-04] Frontrunnable Initialization

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

### Example 15: M-3: No check for sequencer uptime can lead to dutch auctions executing at bad prices

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/40 

## Found by 
0x52
## Summary

When purchasing from dutch auctions on L2s there is no considering of sequencer uptime. When the sequencer is down, all transactions must originate from the L1. The issue with this is that these transactions use an aliased address. Since the set token contracts don't implement any way for these aliased addressed to interact with the protocol, no transactions can be processed during this time even with force L1 inclusion. If the sequencer goes offline during the the auction period then the auction will continue to decrease in price while the sequencer is offline. Once the sequencer comes back online, users will be able to buy tokens from these auctions at prices much lower than market price.

## Vulnerability Detail

See summary.

## Impact

Auction will sell/buy assets at prices much lower/higher than market price leading to large losses for the set token

## Code Snippet

[AuctionRebalanceModuleV1.sol#L772-L836](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L772-L836)

## Tool used

Manual Review

## Recommendation

Check sequencer uptime and invalidate the auction if the sequencer was ever down during the auction period



## Discussion

**pblivin0x**

What exactly is the remediation here? To check an external uptime feed https://docs.chain.link/data-feeds/l2-sequencer-feeds ?

Not sur

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## cooldown-patterns.md
# Cooldown Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for cooldown vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: The vault manager has unchecked power to create arbitrage using setSwapFees

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Vulnerability Report

## Severity
**High Risk**

## Context
- AeraVaultV1.sol: Lines 663-679
- BasePool.sol: Lines 58-59

## Description
A previously known issue was that a malicious vault manager could arbitrage the vault like in the below scenario:

1. Set the swap fees to a high value by calling `setSwapFee` (10% is the maximum).
2. Wait for the market price to move against the spot price.
3. In the same transaction, reduce the swap fees to ~0 (0.0001% is the minimum) and arbitrage the vault.

The proposed fix was to limit the percentage change of the swap fee to a maximum of `MAXIMUM_SWAP_FEE_PERCENT_CHANGE` each time. However, because there is no restriction on how many times the `setSwapFee` function can be called in a block or transaction, a malicious manager can still call it multiple times in the same transaction and eventually set the swap fee to the value they want.

## Recommendation
Enforce a cooldown period of reasonable length between two consecutive `setSwapFee` function calls.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] The `redeem` related functions are likely to be blocked

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L615>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L685>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L712>

### Impact

The following `redeem` related functions are likely to be blocked, users will not be able to retrieve their funds.

    function _redeemPxGlp(
        address token,
        uint256 amount,
        uint256 minOut,
        address receiver
    );
    function redeemPxGlpETH(
        uint256 amount,
        uint256 minOut,
        address receiver
    );
    function redeemPxGlp(
        address token,
        uint256 amount,
        uint256 minOut,
        address receiver
    );

### Proof of Concept

The `GlpManager` contract of GMX has a `cooldownDuration` limit on redeem/unstake (`\_removeLiquidity()`). While there is at least one deposit/stake (`\_addLiquidity()`) operation in the past `cooldownDuration` time, redemption would fail. Obviously this limitation is user-based,  and `PirexGmx` contract is one such user.

<https://github.com/gmx-io/gmx-contracts/blob/c3618b0d6fc1b88819393dc7e6c785e32e78c72b/contracts/core/GlpManager.sol#L234>

    Current setting of `cooldownDuration` is 15 minutes, the max value is 2 days.

<https://arbiscan.io/address/0x321f653eed006ad1c29d174e17d96351bde22649#readC

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: [M-03] users still forced to follow previously set cooldownDuration even when cooldown is off (set to zero) before unstaking

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

The `StakedUSDeV2` contract can enforces coolDown periods for users before they are able to unstake/ take out their funds from the silo contract if coolDown is on. Based on the presence of the modifiers `ensureCooldownOff` and `ensureCooldownOn`, it is known that the coolDown state of the `StakedUSDeV2` contract can be toggled on or off.
In a scenario where coolDown is on (always turned on by default) and Alice and Bob deposits, two days after Alice wants to withdraw/redeem. Alice is forced to wait for 90 days before completing withdrawal/getting her tokens from the silo contract because Alice must call  coolDownAsset()/coolDownShares() fcns respectively. Bob decides to wait an extra day.

On the third day, Bob decides to withdraw/redeem. Contract admin also toggles the coolDown off (sets cooldownDuration to 0), meaning there is no longer a coolDown period and all withdrawals should be sent to the users immediately. Bob now calls calls the redeem()/withdraw() fcn to withdraw instantly to his address instead of the silo address since there is no coolDown.

Alice sees Bob has gotten his tokens but Alice cant use the redeem()/withdraw() because her `StakedUSDeV2` were already burned and her underlying assets were sent to the silo contract for storage. Alice cannot sucessfully call `unstake()` because her `userCooldown.cooldownEnd`  value set to \~ 90 days. Now Alice has to unfairly wait out the 90 days even though coolDowns have been turned off and everyone else has unrestricted

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


