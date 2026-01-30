# Dust Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for dust vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Dust might be trapped in WlsETH when burning one's balance.

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
*WLSETH.1.sol#L140*

## Description
It is not possible to burn the exact amount of minted/deposited lsETH back because the _value provided to burn is in ETH. 

Assume we've called `mint(r,v)` with our address `r`, then to get the `v` lsETH back to our address, we need to find an `x` where:

\[ v = \frac{b \cdot x \cdot S}{B} \]

and call `burn(r, x)` (Here `S` represents the total share of lsETH and `B` the total underlying value.). 

It's not always possible to find the exact `x`, so there will always be an amount locked in this contract:

\[ v \neq \frac{b \cdot x \cdot S}{B} \]

These dust amounts can accumulate from different users and turn into a significant number. To get the full amount back, the user needs to mint more wlsETH tokens so that we can find an exact solution to:

\[ v = \frac{b \cdot x \cdot S}{B} \]

The extra amount to get the locked-up fees back can be engineered. The same problem exists for `transfer` and `transferFrom`. 

Also note, if you have minted `x` amount of shares, the `balanceOf` would tell you that you own:

\[ b = \frac{b \cdot x \cdot B}{S \cdot wlsETH} \]

Internally, wlsETH keeps track of the shares `x`. So users think they can only burn `b` amount, plug that in for the _value, and in this case, the number of shares burnt would be:

\[
\frac{b \cdot x \cdot B}{S \cdot C \cdot B\%}
\]

which has even more rounding errors. wlsETH could internally track the underlying but 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 2: [M-18] DoS: Attacker may significantly increase the cost of withdrawExcessRewards() by creating a significant number of excess receipts

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-factorydao/blob/db415804c06143d8af6880bc4cda7222e5463c0e/contracts/PermissionlessBasicPoolFactory.sol#L245


## Vulnerability details

## Impact

An attacker may cause a DoS attack on `withdrawExcessRewards()` by creating a excessive number of `receipts` with minimal value. Each of these receipts will need to be withdrawn before the owner can call `withdrawExcessRewards()`. 

The impact is the owner would have to pay an unbounded amount of gas to `withdraw()` all the accounts and receive their excess funds.

## Proof of Concept

`withdrawExcessRewards()` has the requirement that `totalDepositsWei` for the pool is zero before the owner may call this function as seen on line 245.

```solidity
        require(pool.totalDepositsWei == 0, 'Cannot withdraw until all deposits are withdrawn');
```

`pool.totalDepositsWei` is added to each time a user calls `deposit()`. It is increased by the amount the user deposits. There are no restrictions on the amount that may be deposited as a result a user may add 1 wei (or the smallest unit on any currency) which has negligible value.

The owner can force withdraw these accounts by calling `withdraw()` so long as `block.timestamp > pool.endTime`. They would be required to do this for each account that was created.

This could be a significant amount of gas costs, especially if the gas price has increased since the attacker originally made the deposits.

## Recommended Mitigation Steps

C

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 3: M-4: Dust amounts can cause payments to fail, leading to default

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

### Example 4: [M-08] Rebases can be frontrun with very little token downtime even when warmUpPeriod  0

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52, also found by elprofesor_

Rebases can be frontrun with very little token downtime even when `warmUpPeriod > 0`.

### Proof of Concept

<https://github.com/code-423n4/2022-06-yieldy/blob/524f3b83522125fb7d4677fa7a7e5ba5a2c0fe67/src/contracts/Staking.sol#L415-L417>

<https://github.com/code-423n4/2022-06-yieldy/blob/524f3b83522125fb7d4677fa7a7e5ba5a2c0fe67/src/contracts/Staking.sol#L703>

A user can call stake the block before epoch.endTime <= block.timestamp, allowing the user to bypass the forced rebase called in L416 of the the stake function. If warmUpPeriod > 0 then the user will receive a "warmUpInfo" with the value of their deposit. The very next block, the user can then call instantUnstakeCurve.

<https://github.com/code-423n4/2022-06-yieldy/blob/524f3b83522125fb7d4677fa7a7e5ba5a2c0fe67/src/contracts/Staking.sol#L600-L627>

This will call rebase again in L633 and this time epoch.endTime <= block.timestamp will be true and it will trigger an actual rebase, distributing the pending rewards. \_retrieveBalanceFromUser (L617) will then allows the user to unstake all the funds locked in warm up. The issue is that when unstaking it uses userWarmInfo.credits meaning that any rebalance rewards are kept. This allows the user to get in, collect the rebase, then immediately get out.

### Recommended Mitigation Steps

Being able to unstake tokens even when in the warm up period is a useful feature but tokens unstaked during that period should not be allowed to a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 5: M-2: Rounding error when call function `dodoMultiswap()` can lead to revert of transaction or fund of user

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/45 

## Found by 
TrungOre

## Summary
The calculation of the proportion when do the split swap in function `_multiSwap` doesn't care about the rounding error 

## Vulnerability Detail
The amount of `midToken` will be transfered to the each adapter can be calculated by formula `curAmount = curTotalAmount * weight / totalWeight`
```solidity=
if (assetFrom[i - 1] == address(this)) {
    uint256 curAmount = curTotalAmount * curPoolInfo.weight / curTotalWeight;


    if (curPoolInfo.poolEdition == 1) {
        //For using transferFrom pool (like dodoV1, Curve), pool call transferFrom function to get tokens from adapter
        IERC20(midToken[i]).transfer(curPoolInfo.adapter, curAmount);
    } else {
        //For using transfer pool (like dodoV2), pool determine swapAmount through balanceOf(Token) - reserve
        IERC20(midToken[i]).transfer(curPoolInfo.pool, curAmount);
    }
}
```
It will lead to some scenarios when `curTotalAmount * curPoolInfo.weight` is not divisible by `curTotalWeight`, there will be some token left after the swap.

For some tx, if user set a `minReturnAmount` strictly, it may incur the reversion. 
For some token with small decimal and high value, it can make a big loss for the sender. 

## Impact
* Revert the transaction because not enough amount of `toToken`
* Sender can lose a small amount of tokens 

## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

