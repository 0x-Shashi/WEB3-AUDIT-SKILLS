---
id: PAT-REVERT-BY-SENDING-DUST
title: Revert By Sending Dust Security Patterns
category: error-handling
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - revert
  - error
  - exception

finding_count: 7
last_updated: 2026-01-31
---
# Revert By Sending Dust Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 5 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for revert by sending dust vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: An attacker can freeze all incoming deposits and brick the oracle members' reporting system with only 1 wei

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

**Context:** SharesManager.1.sol#L195-L206

**Description:** An attacker can brick or lock all deposited user funds and also prevent oracle members from reaching a quorum when there are earnings to be distributed as rewards. Consider the following scenario:

1. The attacker forcefully sends 1 wei to the River contract using, e.g., `selfdestruct`. The attacker must ensure this transaction occurs before any other users deposit their funds in the contract. The attacker can observe the mempool and front-run the initial user deposit. Now, `b = _assetBalance() > 0` is at least 1 wei.
   
2. An allowed user tries to deposit funds into the River protocol. The call eventually ends up in `_mintShares(o, x)` and in the first line, `oldTotalAssetBalance = _assetBalance() - x`. Here, `_assetBalance()` represents the updated River balance after accounting for the user deposit `x`. So, `_assetBalance()` is now `b + x + ...` and `oldTotalAssetBalance = b + ...` where the `...` includes the beacon balance sum, deposited amounts for validators in the queue, etc. (which is probably 0 by this point). Therefore, `oldTotalAssetBalance > 0` means that the following if block is skipped:

   ```javascript
   if (oldTotalAssetBalance == 0) {
       _mintRawShares(_owner, _underlyingAssetValue);
       return _underlyingAssetValue;
   }
   ```

   It goes directly to the else block for the first allowed user deposit:

   ```javascript
   else {
       uint256 sharesToMint = 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 2: A malicious user could DOS a vesting schedule by sending only 1 wei ofTLCto the vesting escrow address

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context:
- `ERC20VestableVotesUpgradeable.1.sol#L132-L134`
- `ERC20VestableVotesUpgradeable.1.sol#L137-L139`
- `ERC20VestableVotesUpgradeable.1.sol#L86-L97`
- `ERC20VestableVotesUpgradeable.1.sol#L353`

## Description:
An external user who owns some TLC tokens could DOS the vesting schedule of any user by sending just 1 wei of TLC to the escrow address related to the vesting schedule. By doing that:
- The creator of the vesting schedule will not be able to revoke the vesting schedule.
- The beneficiary of the vesting schedule will not be able to release any vested tokens until the end of the vesting schedule.
- Any external contracts or dApps will not be able to call `computeVestingReleasableAmount`.

In practice, all the functions that internally call `_computeVestingReleasableAmount` will revert because of an underflow error when called before the vesting schedule ends. The underflow error is thrown because, when called before the schedule ends, `_computeVestingReleasableAmount` will enter the `if (_time < _vestingSchedule.end)` branch and will try to compute:

```solidity
uint256 releasedAmount = _computeVestedAmount(_vestingSchedule, _vestingSchedule.end) - balanceOf(_escrow);
```

In this case, `_computeVestedAmount(_vestingSchedule, _vestingSchedule.end)` will always be lower than `balanceOf(_escrow)` and the contract will revert with an underflow error. When the vesting period ends, the contract will not enter the `if (_time < _vestingSch

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective2-Spearbit-Security-Review.pdf)

---

### Example 3: [M-01] `PirexGmx.initiateMigration` can be blocked

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

`PirexGmx.initiateMigration` can be blocked so contract will not be able to migrate his funds to another contract using gmx.

### Proof of Concept

PirexGmx was designed with the thought that the current contract can be changed with another during migration.

`PirexGmx.initiateMigration` is the first point in this long process.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/PirexGmx.sol#L921-L935>

```solidity
    function initiateMigration(address newContract)
        external
        whenPaused
        onlyOwner
    {
        if (newContract == address(0)) revert ZeroAddress();


        // Notify the reward router that the current/old contract is going to perform
        // full account transfer to the specified new contract
        gmxRewardRouterV2.signalTransfer(newContract);


        migratedTo = newContract;


        emit InitiateMigration(newContract);
    }
```

As you can see `gmxRewardRouterV2.signalTransfer(newContract);` is called to start migration.

This is the code of signalTransfer function
<https://arbiscan.io/address/0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1#code#F1#L282>

```solidity
    function signalTransfer(address _receiver) external nonReentrant {
        require(IERC20(gmxVester).balanceOf(msg.sender) == 0, "RewardRouter: sender has vested tokens");
        require(IERC20(glpVester).balanceOf(msg.sender) == 0, "RewardRouter: sender has vested tokens");

        _validateReceiver(_receiver);
        pendingReceivers[msg.send

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 4: [M-05] repay function can be DOSed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L531


## Vulnerability details

## Impact
In `repay()` users can repay their debt.
```
function repay(address user, uint amount) public {
        uint debt = debts[user];
        require(debt >= amount, "Insufficient debt");
        debts[user] -= amount;
        totalDebt -= amount;
        dbr.onRepay(user, amount);
        dola.transferFrom(msg.sender, address(this), amount);
        emit Repay(user, msg.sender, amount);
    }
```

There is a `require` condition, that checks if the amount provided, is greater than the debt of the user. If it is, then the function reverts. This is where the vulnerability arises.

`repay` function can be frontrun by an attacker. Say an attacker pay a small amount of debt for the victim user, by frontrunning his repay transaction. Now when the victim's transaction gets executed, the `require` condition will fail, as the amount of debt is less than the amount of DOLA provided. Hence the attacker can repeat the process to DOS the victim from calling the repay function.


## Proof of Concept

1. Victim calls repay() function to pay his debt of 500 DOLA , by providing the amount as 500
2. Now attacker saw this transaction on mempool
3. Attacker frontruns the transaction, by calling repay() with amount provided as 1 DOLA
4. Attacker's transaction get's executed first due to frontrunning, which reduces the debt of the victim user to 499 DOLA
5. Now when the vi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 5: [M-13] Market::forceReplenish can be DoSed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L562


## Vulnerability details

## Impact
If a user wants to completely forceReplenish a borrower with deficit, the borrower or any other malicious party can front run this with a dust amount to prevent the replenish.

## Proof of Concept
```javascript
    function testForceReplenishFrontRun() public {
        gibWeth(user, wethTestAmount);
        gibDBR(user, wethTestAmount / 14);
        uint initialReplenisherDola = DOLA.balanceOf(replenisher);

        vm.startPrank(user);
        deposit(wethTestAmount);
        uint borrowAmount = getMaxBorrowAmount(wethTestAmount);
        market.borrow(borrowAmount);
        uint initialUserDebt = market.debts(user);
        uint initialMarketDola = DOLA.balanceOf(address(market));
        vm.stopPrank();

        vm.warp(block.timestamp + 5 days);
        uint deficitBefore = dbr.deficitOf(user);
        vm.startPrank(replenisher);

        market.forceReplenish(user,1); // front run DoS

        vm.expectRevert("Amount > deficit");
        market.forceReplenish(user, deficitBefore); // fails due to amount being larger than deficit
        
        assertEq(DOLA.balanceOf(replenisher), initialReplenisherDola, "DOLA balance of replenisher changed");
        assertEq(DOLA.balanceOf(address(market)), initialMarketDola, "DOLA balance of market changed");
        assertEq(DOLA.balanceOf(replenisher) - initialReplenisherDola, initialMarketDola - DOLA

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 6: M-9: [M] Incorrect Validation in `Pool.sol#transferLPs` lead to a DOS attack

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/116 

## Found by 
oxcm

## Summary

The code in the transferLPs function has an incorrect validation check, where it requires `allowances_` to be strictly equal to `lenderLpBalance`, instead of just `allowances_` being greater than `transferAmount`.

## Vulnerability Detail

In the `transferLPs()` function, `transferAmount` is being compared to `allowances_[owner_][newOwner_][index]` and `lenderLpBalance`. If the values are not strictly equal, the function will revert with a `NoAllowance` error. 

Due to the requirement of `transferLPs()` that `allowances_` must equal `lenderLpBalance`, the user can only enter `lpsAmountToApprove_` as the current `lenderLpBalance` when using `approveLpOwnership()`.

This results in `transferLPs()` reverting with `NoAllowance` if `lenderLpBalance` undergoes any change, allowing attackers to design a DOS attack.

However, this validation is not necessary as it should only require `allowances_` to be greater than `transferAmount`.

## Impact

An attacker could exploit this vulnerability by transferring a small amount of LP tokens to the owner before the transfer to the new owner is initiated. This would cause the `allowances_` value to be less than `lenderLpBalance`, causing the transfer to revert and the tokens to remain in the original owner's account.

## Code Snippet

Relevant code snippet from transferLPs function:
 
https://github.com/sherlock-audit/2023-01-ajna/blob/ma

*[Content truncated...]*

---

### Example 7: M-4: Dust amounts can cause payments to fail, leading to default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/218 

## Found by 
kiki\_dev, HollaDieWaldfee, IllIllI, ak1

## Summary

Dust amounts can cause payments to fail, leading to default


## Vulnerability Detail

In order for a loan to close, the exact right number of wei of the debt token must be sent to match the remaining loan amount. If more is sent, the balance underflows, reverting the transaction.


## Impact

An attacker can send dust amounts right before a loan is due, front-running any payments also destined for the final block before default. If the attacker's transaction goes in first, the borrower will be unable to pay back the loan before default, and will lose thier remaining collateral. This may be the whole loan amount.


## Code Snippet

If the repayment amount isn't exactly the remaining loan amount, and instead is more (due to the dust payment), the subtraction marked below will underflow, reverting the payment:
```solidity
// File: src/Cooler.sol : Cooler.repay()   #1

108        function repay (uint256 loanID, uint256 repaid) external {
109            Loan storage loan = loans[loanID];
110    
111            if (block.timestamp > loan.expiry) 
112                revert Default();
113            
114            uint256 decollateralized = loan.collateral * repaid / loan.amount;
115    
116           if (repaid == loan.amount) delete loans[loanID];
117           else {
118 @>             loan.amount -= repaid;
119                loan.coll

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

