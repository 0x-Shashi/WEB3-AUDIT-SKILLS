---
id: PAT-ROYALTY
title: Royalty Security Patterns
category: nft
severity: low
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - royalty
  - erc2981
  - creator

finding_count: 6
last_updated: 2026-01-31
---
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

