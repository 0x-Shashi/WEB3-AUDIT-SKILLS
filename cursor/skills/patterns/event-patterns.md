---
id: PAT-EVENT
title: Event Security Patterns
category: best-practices
severity: low
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - events
  - logging
  - indexing

finding_count: 6
last_updated: 2026-01-31
---
# Event Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 2 | 1 |

**Common Sources**: Cyfrin, Code4rena, Hans, Sherlock

---

## Detection Checklist

- [ ] Check for event vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Centralization risk

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

### Example 2: [M-16] `ApprovalAll` event is missing parameters

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L392](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/HolographERC721.sol#L392)<br>

`beforeApprovalAll()` / `afterApprovalAll()` can only pass "to" and "approved", missing "owner", if contract listening to this event,but does not know who approve it, so can not react to this event.<br>
Basically, this event cannot be used.

### Proof of Concept

      function setApprovalForAll(address to, bool approved) external {
    ....

        if (_isEventRegistered(HolographERC721Event.beforeApprovalAll)) {
          require(SourceERC721().beforeApprovalAll(to, approved)); /***** only to/approved ,need owner
        }  

        _operatorApprovals[msg.sender][to] = approved;

        if (_isEventRegistered(HolographERC721Event.afterApprovalAll)) {
          require(SourceERC721().afterApprovalAll(to, approved)); /***** only to/approved ,need owner
        }
      }

### Recommended Mitigation Steps

Add parameter: owner

    interface HolographedERC721 {
    ...

    - function beforeApprovalAll(address _to, bool _approved) external returns (bool success);
    + function beforeApprovalAll(address owner, address _to, bool _approved) external returns (bool success);

    - function afterApprovalAll(address _to, bool _approved) external returns (bool success);
    + function afterApprovalAll(address owner, address _to, bool _approved) external returns (bool success);

<!---->

      function setApprovalForAll

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 3: M-3: Lack of events for critical arithmetic parameters

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/33 

## Found by 
zimu

## Summary
Function `BondBaseSDA.setDefaults` sets critical arithmetic parameters for bond market. But it has no event emitted, it is difficult to track these critical changes off-chain.

## Vulnerability Detail
In `bases/BondBaseSDA`, critical parameters are set and changed in function `BondBaseSDA.setDefaults` for bond market.
![image](https://user-images.githubusercontent.com/112361239/201988699-b740b31b-e6d1-4bd8-b3da-2fb9bc7c68bd.png)

However, no event is emitted, and it is difficult to track these critical changes off-chain.  Both Users and Issuers would possibly be unware of  these changes.

## Impact
Both Users and Issuers would possibly be unware of  critical changes on bond market.

## Code Snippet
https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L348-L356

## Tool used
Manual Review

## Recommendation
Add an event in `BondBaseSDA.setDefaults` to report critical arithmetic changes.

## Discussion

**Evert0x**

Message from sponsor

----

Agree. We have updated `setDefaults` to emit an event with the newly set values.



**xiaoming9090**

Fixed in https://github.com/Bond-Protocol/bonds/commit/94e38f33b69b0184762c8be1c7bfd0716d97fed2

---

### Example 4: Wrong values or confusing words in event messages

**Source**: Hans
**Protocol**: Meta
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:**

- At [mUSD.sol#L146](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/mUSD.sol#L146), `postRebaseTokenAmount` should be calculated after decreasing `totalMUSDCirculation`.
- At [IDO.sol#L103](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L103), the event message is confusing. I recommend changing the message to `"IDO: Multisig account can not be this contract"`.

**Meta Team:**
Fixed.
(commit 007c1b9183cdb65a500928173608ebff0a5197ef)

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 5: [G-10] Missing events

**Source**: Code4rena
**Protocol**: Visor
**Impact**: GAS

**Details**:

_Submitted by cmichel_

The following events are not used:
- `IInstanceRegistry.InstanceRemoved`

Unused code can hint at programming or architectural errors.  Recommend using it or removing it.

**[xyz-ctrl (Visor) acknowledged but disputed severity](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-862607014):**

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-873480513):**
> Agree with sponsor, it doesnt present a security issue its a non-critical issue.

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-889191547):**
> patch [link](https://github.com/VisorFinance/visor-core/commit/cc22d6e450e16aaa9eb3af1ee4d9e6ac8afe43da#diff-b094db7ce2f99cbcbde7ec178a6754bac666e2192f076807acbd70d49ddd0559)

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 6: Unnecessary event emissions

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: LOW

**Details**:

`PriorityPool::setPoolStatusClosed` does not check if pool status is already `CLOSED` and emits `SetPoolStatus` event. Avoid event emission if the pool status is already closed. Avoid this. The same applies to the function `setPoolStatus` as well.

**Client:**
Fixed in this [PR](https://github.com/stakedotlink/contracts/pull/32).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

