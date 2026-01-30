# Broken Loop Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for broken loop vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: _removeStackPosition() always reverts

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
`LienToken.sol#L823-L828`

## Description
The function `removeStackPosition()` always reverts since it calls the stack array for an index beyond its length:

```solidity
for (i; i < length; ) {
unchecked {
newStack[i] = stack[i + 1];
++i;
}
}
```

Notice that for `i == length - 1`, `stack[length]` is called. This reverts since length is the length of the stack array.

Additionally, the intention is to delete the element from the stack at `indexPosition` and shift left the elements appearing after this index. However, an additional increment to the loop index `i` results in `newStack[position]` being empty, and the shift of other elements doesn't happen.

## Recommendation
Apply the following diff to `LienToken.sol#L823-L831`:

```diff
- unchecked {
- ++i;
- }
- for (i; i < length; ) {
+ for (i; i < length - 1; ) {
unchecked {
newStack[i] = stack[i + 1];
++i;
}
}
```

## Note
This issue has to be considered in conjunction with the following issue:
- `makePayment` doesn't properly update stack, so most payments don't pay off debt.

### Astaria
Fixed in PRs 202 and 265.

### Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] Unbounded loop in _removeNft could lead to a griefing/DOS attack

**Source**: Code4rena
**Protocol**: Visor
**Impact**: HIGH

**Details**:

## Handle

shw


## Vulnerability details

## Impact

Griefing/DOS attack is possible when a malicious NFT contract sends many NFTs to the vault, which could cause excessive gas consumed and even transactions reverted when other users are trying to unlock or transfer NFTs.

## Proof of Concept

1. The function `_removeNft` uses an unbounded loop, which iterates the array `nfts` until a specific one is found. If the NFT to be removed is at the very end of the `nfts` array, this function could consume a large amount of gas.
2. The function `onERC721Received` is permissionless. The vault accepts any NFTs from any NFT contract and pushes the received NFT into the array `nfts`.
3. A malicious user could write an NFT contract, which calls `onERC721Received` of the vault many times to make to array `nfts` grow to a large size. Besides, the malicious NFT contract reverts when anyone tries to transfer (e.g., `safeTransferFrom`) its NFT.
4. The vault then has no way to remove the transferred NFT from the malicious NFT contract. The two only functions to remove NFTs, `transferERC721` and `timeUnlockERC721`, fail since the malicious NFT contract reverts all `safeTransferFrom` calls.
5. As a result, benign users who unlock or transfer NFTs would suffer from large and unnecessary gas consumption. The consumed gas could even exceed the block gas limit and cause the transaction to fail every time.

Referenced code:
[Visor.sol#L127-L140](https://github.com/code-423n4/2021-05-visorfinance/blob

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 3: Large number of inbound roots can DOS the RootManager

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
RootManager.sol#L154-L163

## Description
It is possible to perform a DOS against the RootManager by exploiting the `dequeueVerified` function or `insert` function of the RootManager.sol. The following describes the possible attack path:

1. Assume that a malicious user calls the permissionless `GnosisSpokeConnector.send` function 1000 times (or any number of times that will cause an Out-of-Gas error later) within a single transaction/block on Gnosis, causing a large number of Gnosis's outboundRoots to be forwarded to `GnosisHubConnector` on Ethereum.
2. Since the 1000 outboundRoots were sent at the same transaction/block earlier, all of them should arrive at the `GnosisHubConnector` within the same block/transaction on Ethereum.
3. For each of the 1000 outboundRoots received, the `GnosisHubConnector.processMessage` function will be triggered to process it, which will in turn call the `RootManager.aggregate` function to add the received outboundRoot into the pendingInboundRoots queue. As a result, 1000 outboundRoots with the same commit block will be added to the pendingInboundRoots queue.
4. After the delay period, the `RootManager.propagate` function will be triggered. The function will call the `dequeueVerified` function to dequeue 1000 verified outboundRoots from the pendingInboundRoots queue by looping through the queue. This might result in an Out-of-Gas error and cause a revert.
5. If the above `dequeueVerified` function does not reve

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 4: [H-03] Denial of Service by wrong `BatchRequests.removeAddress` logic

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: HIGH

**Details**:

_Submitted by 0x1f8b, also found by rfa, berndartmueller, BowTiedWardens, csanuragjain, Lambda, neumo, and StErMi_

**Note: issues #[283](https://github.com/code-423n4/2022-06-yieldy-findings/issues/283), [115](https://github.com/code-423n4/2022-06-yieldy-findings/issues/115), [82](https://github.com/code-423n4/2022-06-yieldy-findings/issues/82), [89](https://github.com/code-423n4/2022-06-yieldy-findings/issues/89), [61](https://github.com/code-423n4/2022-06-yieldy-findings/issues/61), and [241](https://github.com/code-423n4/2022-06-yieldy-findings/issues/241) were originally broken out as a separate medium issue. Approximately 1 week after judging and awarding were finalized, the judging team re-assessed that these should have all been grouped under H-03. Accordingly, the 6 warden names have been added as submitters above.**

<https://github.com/code-423n4/2022-06-yieldy/blob/34774d3f5e9275978621fd20af4fe466d195a88b/src/contracts/BatchRequests.sol#L93>

<https://github.com/code-423n4/2022-06-yieldy/blob/34774d3f5e9275978621fd20af4fe466d195a88b/src/contracts/BatchRequests.sol#L57>

<https://github.com/code-423n4/2022-06-yieldy/blob/34774d3f5e9275978621fd20af4fe466d195a88b/src/contracts/BatchRequests.sol#L37>

### Impact

The `BatchRequests.removeAddress` logic is wrong and it will produce a denial of service.

### Proof of Concept

Removing the element from the array is done using the `delete` statement, but this is not the proper way to remove an entry from an array, it will

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 5: M-10: `BondAggregator.findMarketFor` Function Will Break In Certain Conditions

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/14 

## Found by 
xiaoming90

## Summary

`BondAggregator.findMarketFor` function will break when the `BondBaseSDA.payoutFor` function within the for-loop reverts under certain conditions.

## Vulnerability Detail

The `BondBaseSDA.payoutFor` function will revert if the computed payout is larger than the market's max payout. Refer to Line 711 below.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L699

```solidity
File: BondBaseSDA.sol
699:     function payoutFor(
700:         uint256 amount_,
701:         uint256 id_,
702:         address referrer_
703:     ) public view override returns (uint256) {
704:         // Calculate the payout for the given amount of tokens
705:         uint256 fee = amount_.mulDiv(_teller.getFee(referrer_), 1e5);
706:         uint256 payout = (amount_ - fee).mulDiv(markets[id_].scale, marketPrice(id_));
707: 
708:         // Check that the payout is less than or equal to the maximum payout,
709:         // Revert if not, otherwise return the payout
710:         if (payout > markets[id_].maxPayout) {
711:             revert Auctioneer_MaxPayoutExceeded();
712:         } else {
713:             return payout;
714:         }
715:     }
```

The `BondAggregator.findMarketFor` function will call the `BondBaseSDA.payoutFor` function at Line 245. The `BondBaseSDA.payoutFor` function will revert if the final computed payout is larger than the `markets[

*[Content truncated...]*

---

### Example 6: [M-04] Iterations over all tiers in recordMintBestAvailableTier can render system unusable

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

`JBTiered721DelegateStore.recordMintBestAvailableTier` potentially iterates over all tiers to find the one with the highest contribution floor that is lower than `_amount`. When there are many tiers, this loop can always run out of gas, which will cause some transactions (the ones that have a high `_leftoverAmount` within `_processPayment`) to always revert. The (implicit) limit for the number of tiers is 2^16 - 1, so it is possible that this happens in practice.

### Proof Of Concept

Let's say that 1,000 tiers are registered for a project. Small payments without a leftover amount or a small amount will be succesfully processed by `_processPayment`, because `_mintBestAvailableTier` is either not called or it is called with a small amount, meaning that `recordMintBestAvailableTier` will exit the loop early (when it is called with a small amount). However, if a payment with a large leftover amount (let's say greater than the highest contribution floor) is processed, it is necessary to iterate over all tiers, which will use too much gas and cause the processing to revert.

### Recommended Mitigation Steps

Use a binary search (which requires some architectural changes) for determining the best available tier. Then, the gas usage grows logarithmically (instead of linear with the current design) with the number of tiers, meaning that it would only be \~16 times higher for 65535 tiers as for 2 tiers.


**[drgorillamd (Juicebox DAO) commented on duplicate issue #226](https://github

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 7: [M-07] processFees() may fail due to exceed gas limit

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

_Submitted by oyc&#95;109, also found by 0x52, IllIllI, and pashov_

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/abstract/JBPayoutRedemptionPaymentTerminal.sol#L594>

### Impact

The function `processFees()` in `JBPayoutRedemptionPaymentTerminal.sol` may fail due to unbounded loop over `_heldFeesOf[_projectId]`

`_heldFeesOf[_projectId]` can get very large due to the function `_takeFeeFrom()` where it pushes fees that should be paid to a specific beneficiary onto the array

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/abstract/JBPayoutRedemptionPaymentTerminal.sol#L1199>

`_heldFeesOf[_projectId]` could get large and cause a DOS condition where no fees can be distributed due to exceed of gas limit

### Proof of Concept

        for (uint256 _i = 0; _i < _heldFeeLength; ) {
          // Get the fee amount.
          uint256 _amount = _feeAmount(
            _heldFees[_i].amount,
            _heldFees[_i].fee,
            _heldFees[_i].feeDiscount
          );

**[mejango (Juicebox) acknowledged](https://github.com/code-423n4/2022-07-juicebox-findings/issues/8)** 


***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-juicebox)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

