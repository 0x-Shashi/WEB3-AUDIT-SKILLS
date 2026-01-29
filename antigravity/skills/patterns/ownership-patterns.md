# Ownership Security Patterns

## Overview

**Frequency**: 13 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Cyfrin, Sherlock

---

## Detection Checklist

- [ ] Check for ownership vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: OrderNFT theft due to controlling future and past tokens of same order index

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- `OrderBook.sol#L410`
- `OrderNFT.sol#L285`

## Description
The order queue is implemented as a ring buffer. To retrieve an order (`Orderbook.getOrder`), the index in the queue is computed as `orderIndex % _MAX_ORDER`. The owner of an `OrderNFT` also uses this function.

```solidity
function _getOrder(OrderKey calldata orderKey) internal view returns (Order storage) {
    return _getQueue(orderKey.isBid, orderKey.priceIndex).orders[orderKey.orderIndex & _MAX_ORDER_M];
}
```

`CloberOrderBook(market).getOrder(decodeId(tokenId)).owner`

As a result, the current owner of the NFT of `orderIndex` also owns all NFTs with `orderIndex + k * _MAX_ORDER`.

An attacker can set approvals of future token IDs to themselves. These approvals are not cleared on `OrderNFT.onMint`. When a victim mints this future token ID, the attacker can steal the NFT and cancel the NFT to claim their tokens.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../../../contracts/interfaces/CloberMarketSwapCallbackReceiver.sol";
import "../../../../contracts/mocks/MockQuoteToken.sol";
import "../../../../contracts/mocks/MockBaseToken.sol";
import "../../../../contracts/mocks/MockOrderBook.sol";
import "../../../../contracts/markets/VolatileMarket.sol";
import "../../../../contracts/OrderNFT.sol";
import "../utils/MockingFactoryTest.sol";
import "./Constants.sol";

contract ExploitsTest is Test, CloberMarketSw

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

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

### Example 3: [M-01] `isOwner` / `onlyOwner` checks can be bypassed by attacker in ERC721/ERC20 implementations

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[ERC721H.sol#L185](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/abstract/ERC721H.sol#L185)<br>
[ERC721H.sol#L121](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/abstract/ERC721H.sol#L121)<br>

ERC20H and ERC721H are base contracts for NFTs / coins to inherit from. They supply the modifier onlyOwner and function isOwner which are used in the implementations for access control. However, there are several functions which when using these the answer may be corrupted to true by an attacker.

The issue comes from confusion between calls coming from HolographERC721's fallback function, and calls from actually implemented functions.

In the fallback function, the enforcer appends an additional 32 bytes of `msg.sender`:

    assembly {
      calldatacopy(0, 0, calldatasize())
      mstore(calldatasize(), caller())
      let result := call(gas(), sload(_sourceContractSlot), callvalue(), 0, add(calldatasize(), 32), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch result
      case 0 {
        revert(0, returndatasize())
      }
      default {
        return(0, returndatasize())
      }
    }

Indeed these are the bytes read as msgSender:

    function msgSender() internal pure returns (address sender) {
      assembly {
        sender := calldataload(sub(calldatasize(), 0x20))
      }
    }

and isOwner simply compares these to the stored owner:

    functi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: Renouncing ownership or admin role could affect the normal operation of Connext

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Assessment Report

## Severity: High Risk

### Context
- Affected Contracts: `WatcherClient.sol`, `WatchManager.sol`, `Merkle.sol`, `RootManager.sol`, `ConnextPriceOracle.sol`, `Upgrade-BeaconController.sol`, `ProposedOwnableFacet.sol#L276-L285`

### Description
Consider the following scenarios:

#### Instance 1 - Renouncing Ownership
All the contracts that extend from `ProposedOwnable` or `ProposedOwnableUpgradeable` inherit a method called `renounceOwnership`. The owner of the contract can use this method to give up their ownership, thereby leaving the contract without an owner. If that were to happen, it would not be possible to perform any owner-specific functionality on that contract anymore.

The following is a summary of the affected contracts and their impact if the ownership has been renounced. One of the most significant impacts is that Connext's message system cannot recover after a fraud has been resolved since there is no way to unpause and add the connector back to the system.

#### Instance 2 - Renouncing Admin Role
All the contracts that extend from `ProposedOwnableFacet` inherit a method called `revokeRole`. 

1. Assume that the Owner has renounced its power and the only Admin remaining used `revokeRole` to renounce its Admin role.
2. Now the contract is left with Zero Owner & Admin.
3. All swap operations collect admin fees via the `SwapUtils.sol` contract. In the absence of any Admin & Owner, these fees will get stuck in the contract with no way

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 5: M-1: Transferring Ownership Might Break The Market

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/41 

## Found by 
xiaoming90

## Summary

After the transfer of the market ownership, the market might stop working, and no one could purchase any bond token from the market leading to a loss of sale for the market makers.

## Vulnerability Detail

The `callbackAuthorized` mapping contains a list of whitelisted market owners authorized to use the callback. When the users call the `purchaseBond` function, it will check at Line 390 if the current market owner is still authorized to use a callback. Otherwise, the function will revert.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L379

```solidity
File: BondBaseSDA.sol
379:     function purchaseBond(
380:         uint256 id_,
381:         uint256 amount_,
382:         uint256 minAmountOut_
383:     ) external override returns (uint256 payout) {
384:         if (msg.sender != address(_teller)) revert Auctioneer_NotAuthorized();
385: 
386:         BondMarket storage market = markets[id_];
387:         BondTerms memory term = terms[id_];
388: 
389:         // If market uses a callback, check that owner is still callback authorized
390:         if (market.callbackAddr != address(0) && !callbackAuthorized[market.owner])
391:             revert Auctioneer_NotAuthorized();
```

However, if the market owner transfers the market ownership to someone else. The market will stop working because the new market owner might not be on the

*[Content truncated...]*

---

### Example 6: Centralization risk

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol has an owner with privileged rights to perform admin tasks that can affect users.
Especially, the owner can change the fee settings and reward handler address.

1. Validation is missing for admin fee setter functions.

```solidity
FeeData.sol
31:     function setFeeValue(uint256 feeValue) external onlyOwner {
32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");
33:         _feeValue = feeValue;
34:     }

43:
44:     function setFixedFee(uint256 fixedFee) external onlyOwner {//@audit-issue validate min/max
45:         _fixedFee = fixedFee;
46:     }
```

2. Important changes initiated by admin should be logged via events.

```solidity
File: helpers/FeeData.sol

31:     function setFeeValue(uint256 feeValue) external onlyOwner {

36:     function setMaxHops(uint256 maxHops) external onlyOwner {

40:     function setMaxSwaps(uint256 maxSwaps) external onlyOwner {

44:     function setFixedFee(uint256 fixedFee) external onlyOwner {

48:     function setFeeToken(address feeTokenAddress) public onlyOwner {

53:     function setFeeTokens(address[] memory feeTokenAddresses) public onlyOwner {

60:     function clearFeeTokens() public onlyOwner {

```

```solidity
File: helpers/TransferHelper.sol

86:     function setRewardHandler(address rewardAddress) external onlyOwner {

92:     function setRewardsActive(bool _rewardsActive) external onlyOwner {

```

**Impact:** While the protocol owner is rega

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 7: setContractOwner() is insufficient to lock down the owner

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

**Context:** MakeLiFiDiamondImmutable.s.sol#L14-L17. LibDiamond.sol#L70-L75, OwnershipFacet.sol#L66-L73

**Description:**  
The function `transferOwnershipToZeroAddress()` is meant to make the Diamond immutable. It sets the contract owner to 0. However, the contract owner can still be changed if there happens to be a `pendingOwner`. In that case, `confirmOwnershipTransfer()` can still change the contract owner.

```solidity
function transferOwnershipToZeroAddress() external {
    // transfer ownership to 0 address
    LibDiamond.setContractOwner(address(0));
}

function setContractOwner(address _newOwner) internal {
    DiamondStorage storage ds = diamondStorage();
    address previousOwner = ds.contractOwner;
    ds.contractOwner = _newOwner;
    emit OwnershipTransferred(previousOwner, _newOwner);
}

function confirmOwnershipTransfer() external {
    Storage storage s = getStorage();
    address _pendingOwner = s.newOwner;
    if (msg.sender != _pendingOwner) revert NotPendingOwner();
    emit OwnershipTransferred(LibDiamond.contractOwner(), _pendingOwner);
    LibDiamond.setContractOwner(_pendingOwner);
    s.newOwner = LibAsset.NULL_ADDRESS;
}
```

**Recommendation:** Possible solutions  
- First call `cancelOwnershipTransfer()` (and ignore reverts)  
- Reset `s.newOwner` of the `OwnershipFacet`  
- Also remove `OwnershipFacet` (but then function `owner()` is no longer accessible)  

**LiFi:** Solved in PR 250.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 8: Lack of two-step role transfer

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Security Advisory

## Severity
**Medium Risk**

## Context
- `MarketFactory.sol#L146-L152`
- `MarketFactory.sol#L137-L140`

## Description
The contracts lack two-step role transfer functionality. Both the ownership of the `MarketFactory` and the change of a market's host are implemented as single-step functions. The basic validation checks whether the address is not a zero address for a market, but it does not properly account for scenarios where the address receiving the role is inaccessible.

Given that `handOverHost` can be invoked by anyone who created the market, it is possible to unintentionally or intentionally make a typo. An attacker could exploit this situation to disrupt fees collection, as the host affects `collectFees` in `OrderBook` (which is documented as a separate issue).

While ownership transfer should ideally be less error-prone—being conducted by a DAO with care—implementing a two-step role transfer remains preferable.

## Recommendation
It is recommended to implement a two-step role transfer where:
1. The role recipient is set.
2. The recipient must then claim that role to finalize the transfer.

## Clober
Fixed in PR 322.

## Spearbit
Verified. Two-step role transfers added for the contract's owner and the market's host.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 9: [M-04] It's possible to swap NFT token ids without fee and also attacker can wrap unwrap all the NFT token balance of the Pair contract and steal their air drops for those token ids

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

### Example 10: [M-07] OwnableSmartWallet: Multiple approvals can lead to unwanted ownership transfers

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L94><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L105-L106>

The `OwnableSmartWallet` contract employs a mechanism for the owner to approve addresses that can then claim ownership (<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L94>) of the contract.

The source code has a comment included which states that "Approval is revoked, in order to avoid unintended transfer allowance if this wallet ever returns to the previous owner" (<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L105-L106>).

This means that when ownership is transferred from User A to User B, the approvals that User A has given should be revoked.

The existing code does not however revoke all approvals that User A has given. It only revokes one approval.

This can lead to unwanted transfers of ownership.

### Proof of Concept

1.  User A approves User B and User C to claim ownership
2.  User B claims ownership first
3.  Only User A's approval for User B is revoked, not however User A's approval for User C
4.  User B transfers ownerhsip back to User A
5.  Now User C can claim ownership eve

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 11: [M-01] `wrapETH2LD` permissioning is over-extended

**Source**: Code4rena
**Protocol**: ENS
**Impact**: MEDIUM

**Details**:

Undesired use of ENS wrapper.

### Proof of Concept

[NameWrapper.sol#L219-L223](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L219-L223)<br>

Current permissioning for wrapETH2LD allows msg.senders who are not owner to call it if they are EITHER approved for all on the ERC721 registrar or approved on the wrapper. Allowing users who are approved for the ERC721 registrar makes sense. By giving them approval, you are giving them approval to do what they wish with the token. Any other restrictions are moot regardless because they could use approval to transfer themselves the token anyways and bypass them as the new owner. The issue is allowing users who are approved for the wrapper contract to wrap the underlying domain. By giving approval to the contract the user should only be giving approval for the wrapped domains. As it is currently setup, once a user has given approval on the wrapper contract they have essentially given approval for every domain, wrapped or unwrapped, because any unwrapped domain can be wrapped and taken control of. This is an over-extension of approval which should be limited to the tokens managed by the wrapper contract and not extend to unwrapped domains

### Recommended Mitigation Steps

Remove L221.

**[Arachnid (ENS) disagreed with severity and commented](https://github.com/code-423n4/2022-07-ens-findings/issues/51#issuecomment-1196225256):**
 > This was by design, but the wa

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-ens)

---

### Example 12: [M-12] No Transfer Ownership Pattern

**Source**: Code4rena
**Protocol**: Boot Finance
**Impact**: MEDIUM

**Details**:

## Handle

defsec


## Vulnerability details

## Impact

The current ownership transfer process involves the current owner calling Swap.transferOwnership(). This function checks the new owner is not the zero address and proceeds to write the new owner's address into the owner's state variable. If the nominated EOA account is not a valid account, it is entirely possible the owner may accidentally transfer ownership to an uncontrolled account, breaking all functions with the onlyOwner() modifier.

## Proof of Concept

1. Navigate to "https://github.com/code-423n4/2021-11-bootfinance/blob/7c457b2b5ba6b2c887dafdf7428fd577e405d652/customswap/contracts/Swap.sol#L30"
2. The contract has many onlyOwner function.
3. The contract is inherited from the Ownable which includes transferOwnership.

## Tools Used

None

## Recommended Mitigation Steps

Implement zero address check and Consider implementing a two step process where the owner nominates an account and the nominated account needs to call an acceptOwnership() function for the transfer of ownership to fully succeed. This ensures the nominated EOA account is a valid and active account.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-bootfinance)

---

### Example 13: [M-03] onlyOwner Role Can Unintentionally Influence settleAuction()

**Source**: Code4rena
**Protocol**: Kuiper
**Impact**: MEDIUM

**Details**:

## Handle

leastwood


## Vulnerability details

## Impact

The `onlyOwner` role is able to make changes to the protocol with an immediate affect, while other changes made in `Basket.sol` and `Auction.sol` incur a one day timelock. As a result, an `onlyOwner` role may unintentionally frontrun a `settleAuction()` transaction by making changes to `auctionDecrement` and `auctionMultiplier`, potentially causing the auction bonder to over compensate during a rebalance. Additionally, there is no way for an auction bonder to recover their tokens in the event this does happen.

## Proof of Concept

https://github.com/code-423n4/2021-09-defiProtocol/blob/main/contracts/contracts/Factory.sol#L39-L59
https://github.com/code-423n4/2021-09-defiProtocol/blob/main/contracts/contracts/Auction.sol#L89-L99

## Tools Used

Manual code review

## Recommended Mitigation Steps

Consider adding a timelock delay to all functions affecting protocol execution. Alternatively, `bondForRebalance()` can set state variables for any external calls made to `Factory.sol` (i.e. `factory.auctionMultiplier()` and `factory.auctionDecrement()`), ensuring that `settleAuction()` is called according to these expected results.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-defiprotocol)

---

## Statistics

- Total findings analyzed: 13
- Examples shown: 13
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
