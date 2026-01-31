---
id: PAT-FROM-TO
title: From To Security Patterns
category: validation
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - from
  - to
  - address

finding_count: 6
last_updated: 2026-01-31
---
# from=to Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 6 | 0 | 0 | 0 |

**Common Sources**: Code4rena, Halborn, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for from=to vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Transfering funds to yourself increases your balance

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L182><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L187><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L189-L192><br>

Using temporary variables to update balances is a dangerous construction that has led to several hacks in the past. Here, we can see that `_toBalance` can overwrite `_fromBalance`:

```solidity
File: LBToken.sol
176:     function _transfer(
177:         address _from,
178:         address _to,
179:         uint256 _id,
180:         uint256 _amount
181:     ) internal virtual {
182:         uint256 _fromBalance = _balances[_id][_from];
...
187:         uint256 _toBalance = _balances[_id][_to];
188: 
189:         unchecked {
190:             _balances[_id][_from] = _fromBalance - _amount;
191:             _balances[_id][_to] = _toBalance + _amount; //@audit : if _from == _to : rekt
192:         }
..
196:     }
```

Furthermore, the `safeTransferFrom` function has the `checkApproval` modifier which passes without any limit if `_owner == _spender` :

```solidity
File: LBToken.sol
32:     modifier checkApproval(address _from, address _spender) {
33:         if (!_isApprovedForAll(_from, _spender)) revert LBToken__SpenderNotApproved(_from, _spender);
34:         _;
35:     }
...
131:     function safeTransferFrom(
...
1

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 2: LACK OF EXTERNAL CALLS VALIDATION

**Source**: Halborn
**Protocol**: Account Abstraction Schnorr Signatures SDK
**Impact**: HIGH

**Details**:

##### Description

Non-validated external calls occur when a function invokes an external contract without verifying the return value or handling potential errors.

Several external calls were detected without proper validation.

### Impact

This can lead to reentrancy attacks or unexpected side effects if the external call fails or returns an unexpected result, directly causing a potential impact in the availability or integrity of the environment.

##### Proof of Concept

Listed below, there are some examples of unvalidated calls that may fail or cause an unconsistent or unexpected behavior of the application execution flow.

* `examples/account-address/account_address.ts`

```
async function getAddressAlchemyAASDK(combinedAddresses: Address[], salt: string) {
  const rpcUrl = process.env.ALCHEMY_RPC_URL
  const transport = http(rpcUrl)
  const multiSigSmartAccount = await createMultiSigSmartAccount({
    transport,
    chain: CHAIN,
    combinedAddress: combinedAddresses,
    salt: saltToHex(salt),
    entryPoint: getEntryPoint(CHAIN),
  })

  return multiSigSmartAccount.address
}


```

* `src/helpers/create2.ts`

```
export async function getAccountImplementationAddress(factoryAddress: string, ethersSignerOrProvider: Signer | Provider): Promise<string> {
  const smartAccountFactory = new ethers.Contract(factoryAddress, MultiSigSmartAccountFactory_abi, ethersSignerOrProvider)
  const accountImplementation = await smartAccountFactory.accountImplementation()
  return accoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/influx-technologies/account-abstraction-schnorr-signatures-sdk)

---

### Example 3: swapOut allows overwrite of token balance

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**Critical Risk**

## Context
- **StableSwapFacet.sol**: Lines 266-281
- **SwapUtils.sol**: Lines 740-781, Lines 417-473

## Description
The `StableSwapFacet` has the function `swapExactOut()` where a user could supply the same `assetIn` address as `assetOut`, which means the indexes for `tokenIndexFrom` and `tokenIndexTo` in the function `swapOut()` are the same.

In the function `swapOut()`, a temporary array is used to store balances. When updating these balances, first `self.balances[tokenIndexFrom]` is updated and then `self.balances[tokenIndexTo]` is updated afterward. 

However, when `tokenIndexFrom == tokenIndexTo`, the second update overwrites the first update, causing token balances to be arbitrarily lowered. This also skews the exchange rates, allowing for swaps where value can be extracted.

**Note:** The protection against this problem is located in the function `getY()`. However, this function is not called from `swapOut()`.

**Note:** The same issue exists in `swapInternalOut()`, which is called from `swapFromLocalAssetIfNeededForExactOut()` via `_swapAssetOut()`. However, via this route, it is not possible to specify arbitrary token indexes. Therefore, there isnt an immediate risk here.

### Code Snippets
```solidity
contract StableSwapFacet is BaseConnextFacet {
    ...
    function swapExactOut(..., address assetIn, address assetOut, ...) ... {
        return s.swapStorages[canonicalId].swapOut(
            getSwapTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: `AllocationVesting` contract can be exploited for infinite points via self-transfer

**Source**: Cyfrin
**Protocol**: Bima
**Impact**: HIGH

**Details**:

**Description:** The `AllocationVesting` contract gives points on vesting schedules to team members, investors, influencers and anyone else entitled to a token allocation.

`AllocationVesting::transferPoints` allows users to transfer points however this function does not correctly [handle](https://github.com/Bima-Labs/bima-v1-core/blob/09461f0d22556e810295b12a6d7bc5c0efec4627/contracts/dao/AllocationVesting.sol#L129-L133) self-transfer meaning users can exploit it by transferring points to themselves, giving themselves infinite points:
```solidity
// update storage - deduct points from `from` using memory cache
allocations[from].points = uint24(fromAllocation.points - points);

// we don't use fromAllocation as it's been modified with _claim()
allocations[from].claimed = allocations[from].claimed - claimedAdjustment;

// @audit doesn't correctly handle self-transfer since the memory
// cache of `toAllocation.points` will still contain the original
// value of `fromAllocation.points`, so this can be exploited by
// self-transfer to get infinite points
//
// update storage - add points to `to` using memory cache
allocations[to].points = toAllocation.points + uint24(points);
```

**Impact:** Anyone entitled to an allocation can give themselves infinite points and hence receive more tokens than they should receive.

**Proof of Concept:** Add the following PoC contract to `test/foundry/dao/AllocationInvestingTest.t.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2024-09-27-cyfrin-bima-v2.0.md)

---

### Example 5: [H-01] Duplication of Balance

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

It is possible to duplicate currently held `ink` or `art` within a Cauldron, thereby breaking the contract's accounting system and minting units out of thin air.

The `stir` function of the `Cauldron`, which can be invoked via a `Ladle` operation, caches balances in memory before decrementing and incrementing. As a result, if a transfer to self is performed, the assignment `balances[to] = balancesTo` will contain the added-to balance instead of the neutral balance.

This allows one to duplicate any number of `ink` or `art` units at will, thereby severely affecting the protocol's integrity. A similar attack was exploited in the third bZx hack resulting in a roughly 8 million loss.

Recommend that a `require` check should be imposed prohibiting the `from` and `to` variables to be equivalent.

**[albertocuestacanada (Yield) confirmed](https://github.com/code-423n4/2021-05-yield-findings/issues/16#issuecomment-852044133):**
 > It is a good finding and a scary one. It will be fixed. Duplicated with #7.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-yield)

---

### Example 6: [H-03] transferNotionalFrom doesnt check from != to

**Source**: Code4rena
**Protocol**: Swivel
**Impact**: HIGH

**Details**:

## Handle

gpersoon


## Vulnerability details

## Impact
The function transferNotionalFrom of VaultTracker.sol uses temporary variables to store the balances.
If the "from" and "to" address are the same then the balance of "from" is overwritten by the balance of "to".
This means the balance of "from" and "to" are increased and no balances are decreased, effectively printing money.

Note: transferNotionalFrom can be called via transferVaultNotional by everyone.

## Proof of Concept
https://github.com/Swivel-Finance/gost/blob/v2/test/vaulttracker/VaultTracker.sol#L144-L196

 function transferNotionalFrom(address f, address t, uint256 a) external onlyAdmin(admin) returns (bool) {
    Vault memory from = vaults[f];
    Vault memory to = vaults[t];
    ...
    vaults[f] = from;
    ...
    vaults[t] = to;    // if f==t then this will overwrite vaults[f] 


https://github.com/Swivel-Finance/gost/blob/v2/test/marketplace/MarketPlace.sol#L234-L238
function transferVaultNotional(address u, uint256 m, address t, uint256 a) public returns (bool) {
    require(VaultTracker(markets[u][m].vaultAddr).transferNotionalFrom(msg.sender, t, a), 'vault transfer failed');
   
## Tools Used

## Recommended Mitigation Steps
Add something like the following:
   require (f != t,"Same");

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-swivel)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

