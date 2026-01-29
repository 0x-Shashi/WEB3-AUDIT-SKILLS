# Auditing and Logging Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 1 | 2 | 0 |

**Common Sources**: Cyfrin, Quantstamp

---

## Detection Checklist

- [ ] Check for auditing and logging vulnerabilities in all external functions
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

### Example 2: Reserved assets could be extracted from the Vault

**Source**: Cyfrin
**Protocol**: Accountable
**Impact**: LOW

**Details**:

**Description:** Some strategy functions can release assets without checking if those assets are part of `reservedLiquidity`. `AccountableFixedTerm._loan.drawableFunds` is not verified to be in sync with the queue `reservedLiquidity`. Hence the borrower can inadvertently borrow more funds than they should.

**Impact:** The vault can become insolvent by releasing funds needed to honor a withdrawal.

**Proof of Concept:** Violated in `FixedTerm.acceptLoanLocked(), FixedTerm.borrow(), FixedTerm.pay(), FixedTerm.acceptLoanDynamic(), FixedTerm.claimInterest()`: https://prover.certora.com/output/52567/edb399a43d1849a9b22f027e66b17924/?anonymousKey=3dcf62dfa004381083966b3639b6a485fa2e9501

```solidity
// Reserved liquidity must not exceed total assets
invariant reservedLiquidityBacked(env e)
    ghostReservedLiquidity256 <= ghostTotalAssets256
```

**Recommended Mitigation:** When `reservedLiquidity` is increased in the withdrawal queue, this needs to be synced to the FixedTerm starategy.

**Accountable:** Fixed in commit [`979c0e`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/979c0ebe4bd5860fe9b2e446f9fac2ae3919b39c).

Issue was addressed to satisfy the invariant and prevent future upgrades that might allow redemptions in a FixedTerm loan, but as of right now there's no possible way to increase `reservedLiquidity` such that it is out-of-sync with`drawableFunds`.

Borrowing after the loan is in a `Repaid` state cannot happen due to `_requireLoanOngoing` so a

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-16-cyfrin-accountable-v2.0.md)

---

### Example 3: Missing Validation for Zero `success_percentage` in DAO Creation

**Source**: Quantstamp
**Protocol**: XDAO
**Impact**: LOW

**Details**:

**Update**
The team addressed in: `a429b0c9ce78be9294a27934e1a184261b88917a`, `2255f30c7f9559ce225b407c26f6d816325d78f3`with the following explanation:

> Second commit (2255f30c7f9559ce225b407c26f6d816325d78f3) contains constants.fc update.

**File(s) affected:**`contracts/factory.fc`, `contracts/master.fc`

**Description:** In both the `factory`’s `op::create_master` and the `master`’s `op::change_success_percentage`, the code checks that `success_percentage` does not exceed 100%, but it does not enforce a minimum above zero.

Generally, we should not expect a proposal to pass with zero votes.

**Recommendation:** Add a validation such as `throw_if(error::value_too_low, success_percentage == 0)` in both `op::create_master` and `op::change_success_percentage` to ensure `success_percentage >= 1`.

**Reference**: [View Original Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
