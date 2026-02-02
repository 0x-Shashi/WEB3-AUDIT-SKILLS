---
id: PAT-PRE-POST-BALANCE
title: Pre Post Balance Security Patterns
category: validation
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - pre-condition
  - balance
  - check

finding_count: 7
last_updated: 2026-01-31
---
# Pre/Post Balance Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for pre/post balance vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: `StrategyUtils::_executeDynamicTradeExactIn` does not wrap steth

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/99 

## Found by 
0x52, lemonmon

## Summary

`StrategyUtils::_executeDynamicTradeExactIn` will return bought steth value instead of wrapped steth. Also, steth is not wrapped as it is supposed to be.

## Vulnerability Detail

In the `StrategyUtils::_executeDynamicTradeExactIn`, if `params.tradeUnwrapped` is true, and `buyToken` is `WRAPPED_STETH`, the `buyToken` will be updated to be `WRAPPED_STETH.stETH()`, which is basically `STHETH` (not wrapped). (line 62 in StrategyUtils). So, it buys `stETH` in the trade, and the `amountBought` will be the amount of `stETH` bought. But the `amountBought` was expected to be the `WRAPPED_STETH` amount, as the buyToken given as `WRAPPED_STETH`. The `WRAPPED_STETH` and `STETH` are not 1 to 1, so an user can get more amountBought or less amountBought depending on the market than what is actually bought in `WRAPPED_STETH`.

Later in the same function (line 80-90), if `params.tradeUnwrapped` is true and `buyToken` is `WRAPPED_STETH` and the `amountBought` is bigger than zero, it will wrap the bought stETH to `WARPPED_STETH` and update the `amountBought` to the `WRAPPED_STETH` value. However, this code will be never reached, because if the first two conditions are met, the buyToken would be updated to the `stETH` in the above (line 62).

For example, 100 Wrapped steth will give 108 steth. So, If I choose trade unwrapped to be true, I will get 108 steth, which will be 100 

*[Content truncated...]*

---

### Example 2: H-1: `TradingUtils._executeTrade()` doesn't check `preTradeBalance` properly.

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/110 

## Found by 
0x52, lemonmon, hansfriese

## Summary
`TradingUtils._executeTrade()` doesn't check `preTradeBalance` properly.

## Vulnerability Detail
`TradingUtils._executeTrade()` doesn't check `preTradeBalance` properly.

```solidity
function _executeTrade(
    address target,
    uint256 msgValue,
    bytes memory params,
    address spender,
    Trade memory trade
) private {
    uint256 preTradeBalance;

    if (trade.sellToken == address(Deployments.WETH) && spender == Deployments.ETH_ADDRESS) {
        preTradeBalance = address(this).balance;
        // Curve doesn't support Deployments.WETH (spender == address(0))
        uint256 withdrawAmount = _isExactIn(trade) ? trade.amount : trade.limit;
        Deployments.WETH.withdraw(withdrawAmount);
    } else if (trade.sellToken == Deployments.ETH_ADDRESS && spender != Deployments.ETH_ADDRESS) {
        preTradeBalance = IERC20(address(Deployments.WETH)).balanceOf(address(this));
        // UniswapV3 doesn't support ETH (spender != address(0))
        uint256 depositAmount = _isExactIn(trade) ? trade.amount : trade.limit;
        Deployments.WETH.deposit{value: depositAmount }();
    }

    (bool success, bytes memory returnData) = target.call{value: msgValue}(params);
    if (!success) revert TradeExecution(returnData);

    if (trade.buyToken == address(Deployments.WETH)) {
        if (address(this).balance > preTradeBalance) {
            //

*[Content truncated...]*

---

### Example 3: Processing of end balances

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Medium Risk Vulnerability Report

## Severity
Medium Risk

## Context
- **Files Involved**: 
  - SwapperV2.sol (Lines 22-60)
  - Executor.sol (Lines 41-57)
  - Swapper.sol (Lines 22-38)

## Description
The contract **SwapperV2** contains the following construction (twice) to prevent the use of any already existing start balance:

- It gets a start balance.
- It performs an action.
- If the end balance is greater than the start balance, it uses the difference; otherwise (which includes the case where the start balance is equal to the end balance), it uses the end balance.

Thus, if the else clause is reached, it will use the end balance and ignore any start balance. If the action hasnt changed the balances, then start balance equals end balance, and this amount is used. When the action has lowered the balances, then the end balance is also used. 

This defeats the purpose of the code.

**Note**: Normally, there shouldnt be any tokens in the LiFi Diamond contract, so the risk is limited. The **Swapper.sol** contract has similar code.

### Code Snippets
```solidity
contract SwapperV2 is ILiFi {
    modifier noLeftovers(LibSwap.SwapData[] calldata _swapData, address payable _receiver) {
        ...
        uint256[] memory initialBalances = _fetchBalances(_swapData);
        ... // all kinds of actions
        newBalance = LibAsset.getOwnBalance(curAsset);
        curBalance = newBalance > initialBalances[i] ? newBalance - initialBalances[i] : newBalance;
        ...
    }



*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 4: [H-01] Duplication of Balance

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

### Example 5: [H-06] fee loss in AutoPxGmx and AutoPxGlp and reward loss in AutoPxGlp by calling `PirexRewards.claim(pxGmx/pxGpl, AutoPx*)` directly which transfers rewards to  AutoPx* pool without compound logic get executed and fee calculation logic and pxGmx wouldn't be executed for those rewards

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGlp.sol#L197-L296>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L230-L313>

### Impact

Function `compound()` in `AutoPxGmx` and `AutoPxGlp` contracts is for compounding `pxGLP` (and additionally `pxGMX`) rewards. it works by calling `PirexGmx.claim(px*, this)` to collect the rewards of the vault and then swap the received amount (to calculate the reward, contract save the balance of a contract in that reward token before and after the call to the `claim()` and by subtracting them finds the received reward amount) and deposit them in `PirexGmx` again for compounding and in doing so it calculates fee based on what it received and in `AutoPxGlp` case it calculates `pxGMX` rewards too based on the extra amount contract receives during the execution of `claim()`. But attacker can call `PirexGmx.claim(px*, PirexGlp)` directly and make `PirexGmx` contract to transfer (`gmxBaseReward` and `pxGmx`) rewards to `AutoPxGlp` and in this case the logics of fee calculation and reward calculation in `compound()` function won't get executed and contract won't get it's fee from rewards and users won't get their `pxGmx` reward. So this bug would cause fee loss in `AutoPxGmx` and `AutoPxGlp` for contract and `pxGmx`'s reward loss for users in `AutoPxGlp`.

### Proof of Concept

The bug in `AutoPxGmx`

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 6: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 7: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

**Source**: Pashov Audit Group
**Protocol**: RWf(x)_2025-08-20
**Impact**: MEDIUM

**Details**:

_Resolved_

## Severity

**Impact:** Medium  

**Likelihood:** Medium  

## Description

The `Market.mint()` function mints both fToken and xToken [based on the current collateral ratio](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/blob/main/contracts/f(x)/math/FxLowVolatilityMath.sol#L293-L307).  
In the original Aladdin implementation, this function could be called only once. However, RegnumFx [removed this restriction](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/compare/bbb461cba879349c24c02d87872e93ec0a1a1975...f6e865df2dd46d67a49391d94e54b26e6a8af43c#diff-2c8d19ba3d13b72d110c2a9536e5e9915118ad919b38848357200e91afb683faL252), allowing it to be called multiple times.

When the system enters stability mode, the collateral ratio has fallen below the defined safe threshold. This indicates that additional base tokens need to be deposited to restore the ratio.

Allowing `mint()` during stability mode worsens the problem: each new mint increases the number of fTokens in circulation, which in turn raises the amount of base tokens required to bring the system back to a healthy state. As a result, recovery becomes more difficult, and the system may remain undercollateralized for longer.

The severity chosen for this issue is medium, because only whitelisted managers can use the function, and they are trusted entities that are not interested in making stablecoin depeg.

## Recommendations

Restrict `mint()` from being called when the system is in stabili

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/RWf(x)-security-review_2025-08-20.md)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

