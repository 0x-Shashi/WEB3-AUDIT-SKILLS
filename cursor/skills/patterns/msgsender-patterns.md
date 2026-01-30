# msgSender Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 0 | 0 |

**Common Sources**: Codehawks, Spearbit, Pashov Audit Group, Code4rena

---

## Detection Checklist

- [ ] Check for msgsender vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Incorrect set up and logic of `referralInfoMap` in `SystemConfig::updateReferrerInfo` function

**Source**: Codehawks
**Protocol**: Tadle
**Impact**: HIGH

**Details**:

## Summary
- The `referralInfo` contains 3 members: `referrer`, `referrerRate` and `authorityRate`.
- Here referrer is the person which has referred the other person.
- The referralInfoMap contains a mapping from an address to `ReferralInfo`, where it is expected to return the 3 members mentioned above for a person who is referred by the `referrer`, but the `referralInfoMap` sets the referrer address to all the 3 members which is incorrect.
- As well as anyone can call the function to update the mapping for any address and set arbitrary value for whole mapping members as well as the address for which the mapping is mapped to `referralInfo`

## Vulnerability Details
- The vulnerability is present in the `updateReferrerInfo` function where it allows the caller to set up any arbitrary values for the `referrer`, `referrerRate` and `authorityRate`, as well as the address for which mapping is mapped from is also set to as `referrer`.
- As a result of which anyone can maliciously set values for anyone, but where it is expected that the referrer should only be able to set value for the person to whom he is referring.
- When a user calls the `updateReferrerInfo` function, it sets the mapping as `referralInfoMap[referrer]`, and sets up all the values as passed.

- The referral bonus is allocated during the call to `createTaker` via `_updateReferralBonus` function, where it uses the values as:
```
referralInfoMap[msg.sender], where msg.sender is the one to whom referrer has referred to


*[Content truncated...]*

---

### Example 2: The castApprovalBySig and castDisapprovalBySig functions can revert

**Source**: Spearbit
**Protocol**: Llama
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
LlamaCore.sol#L683-L685

## Description
The `castApprovalBySig` and `castDisapprovalBySig` functions are used to cast an approve or disapprove via an off-chain signature. Within the `_preCastAssertions`, a check is performed against the strategy using `msg.sender` instead of `policyholder`. The strategy (e.g., `AbsoluteStrategy`) uses that argument to check if the cast sender is a policyholder.

```solidity
isApproval
? actionInfo.strategy.isApprovalEnabled(actionInfo, msg.sender)
: actionInfo.strategy.isDisapprovalEnabled(actionInfo, msg.sender);
```

While this works for normal cast, using the ones with signatures will fail as the sender can be anyone who calls the method with the signature signed off-chain.

## Recommendation
Consider sending the policyholder instead of `msg.sender`.

## Llama
Fixed in commit `4bb184` and PR `285`.

## Spearbit
Resolved.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Llama-Spearbit-Security-Review.pdf)

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

### Example 4: [M-05] The protocol uses `_msgSender()` extensively, but not everywhere

**Source**: Pashov Audit Group
**Protocol**: Florence Finance
**Impact**: MEDIUM

**Details**:

**Impact:**
Low, because protocol will still function normally, but an expectedly desired types of transactions won't work

**Likelihood:**
High, because it is certain that he issue will occur as code is

**Description**

The code is using OpenZeppelin's `Context` contract which is intended to allow meta-transactions. It works by using doing a call to `_msgSender()` instead of querying `msg.sender` directly, because the method allows those special transactions. The problem is that the `onlyDelegate` and `onlyFundApprover` modifiers in `LoanVault` use `msg.sender` directly instead of `_msgSender()`, which breaks this intent and will not allow meta-transactions at all in the methods that have those modifiers, which are one of the important ones in the `LoanVault` contract.

**Recommendations**

Change the code in the `onlyDelegate` and `onlyFundApprover` modifiers to use `_msgSender()` instead of `msg.sender`.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-04-01-Florence Finance.md)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

