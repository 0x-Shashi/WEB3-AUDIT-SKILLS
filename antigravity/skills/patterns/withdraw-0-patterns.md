# Withdraw 0 Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 0 | 0 |

**Common Sources**: Codehawks, Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for withdraw 0 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Token withdrawal fails until someone manually approves spending

**Source**: Codehawks
**Protocol**: Tadle
**Impact**: HIGH

**Details**:

## Summary

The protocol uses a contract called TokenManager to control a capital pool that stores tokens.

When a user wants to withdraw, the TokenManager needs spender allowance on the capital pool, but this is not checked for, so the withdrawal fails.

## Vulnerability Details

We simulate a user creating an offer, closing it and then trying to withdraw. The withdrawal fails because of zero allowance for the TokenManager as a spender of the capital pool.

```Solidity
function test_token_withdrawal_fails() public {
    // Data for creating an offer, not relevant.
    uint256 points = 1000;
    uint256 amountToken = 1000000 * 1e18;
    uint256 collateralRate = 12000;
    uint256 eachTradeTax = 300;

    vm.startPrank(user);
    preMarktes.createOffer(
        CreateOfferParams(
            marketPlace,
            address(mockUSDCToken),
            points,
            amountToken,
            collateralRate,
            eachTradeTax,
            OfferType.Ask,
            OfferSettleType.Turbo
        )
    );

    // Close the offer.
    address offerAddr = GenerateAddress.generateOfferAddress(0);
    address stockAddr = GenerateAddress.generateStockAddress(0);

    preMarktes.closeOffer(stockAddr, offerAddr);

    tokenManager.withdraw(address(mockUSDCToken), TokenBalanceType.MakerRefund);
    vm.stopPrank();
}
```

> ```Solidity
> ├─ [8858] UpgradeableProxy::withdraw(MockERC20Token: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], 4)
> │   ├─ [8339] TokenManager::withdraw(M

*[Content truncated...]*

---

### Example 2: [H-02] denial of service

**Source**: Code4rena
**Protocol**: Hubble
**Impact**: HIGH

**Details**:

_Submitted by danb, also found by cmichel, csanuragjain, hyh, kirk-baird, leastwood, Meta0xNull, minhquanym, Omik, robee, Ruhum, and throttle_

<https://github.com/code-423n4/2022-02-hubble/blob/main/contracts/VUSD.sol#L53><br>

processWithdrawals can process limited amount in each call.<br>
An attacker can push to withdrawals enormous amount of withdrawals with amount = 0.<br>
In order to stop the dos attack and process the withdrawal, the governance needs to spend as much gas as the attacker.<br>
If the governance doesn't have enough money to pay for the gas, the withdrawals can't be processed.

### Proof of Concept

Alice wants to attack vusd, she spends 1 millions dollars for gas to push as many withdrawals of amount = 0 as she can.<br>
If the governance wants to process the deposits after Alices empty deposits, they also need to spend at least 1 million dollars for gas in order to process Alice's withdrawals first.<br>
But the governance doesn't have 1 million dollars so the funds will be locked.

### Recommended Mitigation Steps

Set a minimum amount of withdrawal. e.g. 1 dollar

        function withdraw(uint amount) external {
            require(amount >= 10 ** 6);
            burn(amount);
            withdrawals.push(Withdrawal(msg.sender, amount));
        }

**[atvanguard (Hubble) confirmed, but disagreed with High severity and commented](https://github.com/code-423n4/2022-02-hubble-findings/issues/119#issuecomment-1049473996):**
 > Confirming this is an issue. W

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-hubble)

---

### Example 3: M-3: `_withdrawFromPlugin()` will revert when `_withdrawalValues[i] == 0`

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/013-M 

## Found by 
ctf\_sec, hansfriese, WATCHPUG

## Summary

## Vulnerability Detail

When `_withdrawalValues[i] == 0` in `rebalancePlugins()`, it means NOT to rebalance this plugin.

However, the current implementation still tries to withdraw 0 from the plugin.

This will revert in AaveV2Plugin as Aave V2's `validateWithdraw()` does not allow `0` withdrawals:

https://github.com/aave/protocol-v2/blob/554a2ed7ca4b3565e2ceaea0c454e5a70b3a2b41/contracts/protocol/libraries/logic/ValidationLogic.sol#L60-L70

```solidity
  function validateWithdraw(
    address reserveAddress,
    uint256 amount,
    uint256 userBalance,
    mapping(address => DataTypes.ReserveData) storage reservesData,
    DataTypes.UserConfigurationMap storage userConfig,
    mapping(uint256 => address) storage reserves,
    uint256 reservesCount,
    address oracle
  ) external view {
    require(amount != 0, Errors.VL_INVALID_AMOUNT);
```

`removePlugin()` will also always `_withdrawFromPlugin()` even if the plugin's balance is 0, as it will also tries to withdraw 0 in that case (balance is 0).

## Impact

For AaveV2Plugin (and any future plugins that dont allow withdraw 0):

1. In every rebalance call, it must at least withdraw 1 wei from the plugin for the rebalance to work.
2. The plugin can not be removed or rebalanced when there is no balance in it. 

If such a plugin can not deposit for some reason (paused by gov, AaveV2Plu

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

