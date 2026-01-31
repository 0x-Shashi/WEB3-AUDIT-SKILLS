---
id: PAT-NONCE
title: Nonce Security Patterns
category: cryptography
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - nonce
  - replay
  - unique

finding_count: 4
last_updated: 2026-01-31
---
# Nonce Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 1 | 0 |

**Common Sources**: Code4rena, Cyfrin, Sherlock

---

## Detection Checklist

- [ ] Check for nonce vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-04] EIP712MetaTransaction.executeMetaTransaction() failed txs are open to replay attacks

**Source**: Code4rena
**Protocol**: Rolla
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/EIP712MetaTransaction.sol#L86


## Vulnerability details

Any transactions that fail based on some conditions that may change in the future are not safe to be executed again later (e.g. transactions that are based on others actions, or time-dependent etc).

In the current implementation, once the low-level call is failed, the whole tx will be reverted and so that `_nonces[metaAction.from]` will remain unchanged.

As a result, the same tx can be replayed by anyone, using the same signature.

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/EIP712MetaTransaction.sol#L86

```solidity
    function executeMetaTransaction(
        MetaAction memory metaAction,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external payable returns (bytes memory) {
        require(
            _verify(metaAction.from, metaAction, r, s, v),
            "signer and signature don't match"
        );

        uint256 currentNonce = _nonces[metaAction.from];

        // intentionally allow this to overflow to save gas,
        // and it's impossible for someone to do 2 ^ 256 - 1 meta txs
        unchecked {
            _nonces[metaAction.from] = currentNonce + 1;
        }

        // Append the metaAction.from at the end so that it can be extracted later
        // from the calling c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-rolla)

---

### Example 2: [H-04] Project funds can be drained by reusing signatures, in some cases

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by 0xA5DF, also found by Bahurum, bin2chen, byndooa, cryptphi, hansfriese, horsefacts, kaden, Lambda, neumo, panprog, rokinot, scaraven, and sseefried_

[Project.sol#L386-L490](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Project.sol#L386-L490)<br>
[Project.sol#L330-L359](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Project.sol#L330-L359)<br>
[Tasks.sol#L153-L164](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/libraries/Tasks.sol#L153-L164)<br>

This attack path is the results of signatures reusing in 2 functions - `changeOrder()` and `setComplete()`, and a missing modifier at `Tasks.unApprove()` library function.

### Impact

#### Draining the project from funds

Current or previous subcontractor of a task can drain the project out of its funds by running `setComplete()` multiple times.

This can be exploited in 3 scenarios:

*   The price of a task was changed to a price higher than available funds (i.e. `totalLent - _totalAllocated`, and therefore gets unapproved), and than changed back to the original price (or any price that's not higher than available funds)
*   The subcontractor for a task was changed via `changeOrder` and then changed back to the original subcontractor
    *   e.g. - Bob was the original SC, it was changed to Alice, and then back to Bob
*   Similar to the case above, but even if t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 3: Nonstandard usage of nonce

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The protocol implemented two withdraw functions `withdrawDeposit()` and `withdraw()`.
While the function `withdrawDeposit()` is designed to be used by the depositor themselves, the function `withdraw()` is designed to be used by anyone who has a signature from the depositor.
The function `withdraw()` has a parameter `nonce` but the usage of this param is not aligned with the general meaning of nonce.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];//@audit-info non aligned with common understanding of nonce
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 4: M-9: Nonces not used in signed data

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/160-M 

## Found by 
IllIllI

## Summary
Nonces are not used in the signature checks

## Vulnerability Detail
A nonce can prevent an old value from being used when a new value exists. Without one, two transactions submitted in one order, can appear in a block in a different order

## Impact
If a user is attacked, then tries to change the recipient address to a more secure address, initially chooses an insecure compromised one, but immediately notices the problem, then re-submits as a different, uncompromised address, a malicious miner can change the order of the transactions, so the insecure one is the one that ends up taking effect, letting the attacker transfer the funds

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L67-L71

## Tool used

Manual Review

## Recommendation
Include a nonce in what is signed

## Harpie Team
Fixed by changing nonce system to an incremental system. Fix [here](https://github.com/Harpieio/contracts/pull/4/commits/ee6f5cdf52fa5604d4693331189edff6558c9b8a).

## Lead Senior Watson
Not an issue AFAIK, miners can't reorder txs unless they are signed with the same nonce. There would have to be some serious mis-use of this function by the recipient address, i.e. they would have to ask the server to sign for two different addresses and then broadcast the txs with the same nonce for this call. The proposed fix

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

