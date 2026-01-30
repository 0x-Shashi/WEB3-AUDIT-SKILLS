# Codehawks - Audit Findings

## Overview

**Total Findings**: 1,234 (2.44% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 199 | 383 | 458 | 194 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Oracle | 4 |
| Cross Chain | 2 |
| Liquidation | 2 |
| Sandwich Attack | 2 |
| Slippage | 1 |
| Whitelist/Blacklist Match | 1 |
| Withdraw 0 | 1 |
| Validation | 1 |
| msgSender | 1 |
| Access Control | 1 |

---

## Notable Findings

### 1. Any attempt to liquidate a user will fail, because StabilityPool does not hold crvUSD during operational lifecycle

**Protocol**: Core Contracts | **Impact**: HIGH

## Description

In `StabilityPool::liquidateBorrower` the function checks for `crvUSDToken.balanceOf(address(this))` but since the contract during is lifecycle never receives `crvUSD` any attempt to liquidate a borrower will fail with `InsufficientBalance()`.



## Vulnerable Code

`StabilityPool::liquidateBorrower`:

```Solidity
function liquidateBorrower(address userAddress) external onlyManagerOrOwner nonReentrant whenNotPaused {
        _update();
        uint256 userDebt = lendingPool.getUserDebt(userAddress);
        uint256 scaledUserDebt = WadRayMath.rayMul(userDebt, lendingPool.getNor...

---

### 2. Reward manipulation vulnerability in StabilityPool

**Protocol**: Core Contracts | **Impact**: HIGH

## Summary

The `StabilityPool` contract's reward distribution has a vulnerability where users can steal all accumulated RAAC rewards through a single deposit/withdrawal transaction. The issue occurs because the reward calculation uses instant deposit ratios rather than time-weighted positions, allowing theft from legitimate long-term depositors.

## Vulnerability Details

The vulnerability exists in the `calculateRaacRewards()` function of the `StabilityPool` contract. The current implementation calculates rewards using the following formula:

```Solidity
rewards = (totalRewards * userDeposit...

---

### 3. Incorrect `AutoDeleverageFactor`.

**Protocol**: Part 2 | **Impact**: HIGH

## Summary
The calculation of `AutoDeleverageFactor` is incorrect.

## Vulnerability Details
https://github.com/Cyfrin/2025-01-zaros-part-2/blob/main/src/market-making/leaves/Market.sol#L174
```solidity
    function getAutoDeleverageFactor(
        ...
    )   ...
    {   ...
        UD60x18 unscaledDeleverageFactor = Math.min(marketDebtRatio, autoDeleverageEndThresholdX18).sub(
            autoDeleverageStartThresholdX18
        ).div(autoDeleverageEndThresholdX18.sub(autoDeleverageStartThresholdX18));

        // finally, raise to the power scale
174:    autoDeleverageFactorX18 = unscaledDel...

---

### 4. Successful transactions are not stored, causing a replay attack on ``redeemDepositsAndInternalBalances``

**Protocol**: Beanstalk: The Finale | **Impact**: HIGH

## Summary

in `redeemDepositsAndInternalBalances` there is no validation about the parameters that have been used which should be stored and should not be reused.

As a result, parameters that have already been used can be reused.

## Vulnerability Details

Look at this:

```solidity
function redeemDepositsAndInternalBalances(
        address owner,
        address reciever,
        AccountDepositData[] calldata deposits,
        AccountInternalBalance[] calldata internalBalances,
        uint256 ownerRoots,
        bytes32[] calldata proof,
        uint256 deadline,
        bytes calldata si...

---

### 5. Owner of a bad ShortRecord can front-run flagShort calls AND liquidateSecondary and prevent liquidation

**Protocol**: DittoETH | **Impact**: HIGH

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47">https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101</a>

<a data-meta="codehawks-gith...

---

### 6. A user can steal an already transfered and bridged reSDL lock because of approval

**Protocol**: stake.link | **Impact**: HIGH

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281</a>


## Summary
The reSDL token approval is not ...

---

### 7. Scaled Allowance Mismatch Enables Over-Approval Exploit

**Protocol**: Core Contracts | **Impact**: HIGH

## Summary

The `transferFrom` function in RToken calculates a scaled transfer amount before checking the user’s allowance. This discrepancy allows spenders to exceed the user’s intended approval, resulting in unauthorized transfers of more tokens than permitted.

## Vulnerability Details

The RToken contract uses a liquidity index to scale down transfer amounts before calling `super.transferFrom`. This design breaks the standard ERC20 allowance, which expects `approve(spender, X)` to limit the spender to exactly `X` tokens.&#x20;

In RToken, a higher liquidity index reduces the amount checked...

---

### 8. Incorrect set up and logic of `referralInfoMap` in `SystemConfig::updateReferrerInfo` function

**Protocol**: Tadle | **Impact**: HIGH

## Summary
- The `referralInfo` contains 3 members: `referrer`, `referrerRate` and `authorityRate`.
- Here referrer is the person which has referred the other person.
- The referralInfoMap contains a mapping from an address to `ReferralInfo`, where it is expected to return the 3 members mentioned above for a person who is referred by the `referrer`, but the `referralInfoMap` sets the referrer address to all the 3 members which is incorrect.
- As well as anyone can call the function to update the mapping for any address and set arbitrary value for whole mapping members as well as the address fo...

---

### 9. Fee on transfer tokens will cause users to lose funds

**Protocol**: Beedle - Oracle free perpetual lending | **Impact**: HIGH

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Staking.sol#L46">https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Staking.sol#L46</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Staking.sol#L38">https://github.com/Cyfrin/2023-07-beedle/blob/658e046bda8b010a5b82d2d85e824f3823602d27/src/Staking.sol#L38</a>


## Summary

Some ERC20 tokens, such as USDT, al...

---

### 10. Incompatibility with Multisig Wallets in `TempleGold::send` Function

**Protocol**: TempleGold | **Impact**: HIGH

## Summary:

The `send` function in `TempleGold` smart contract is designed to facilitate cross-chain token transfers using LayerZero. However, it contains a restrictive condition that disallows transfers if the sender's address does not match the recipient's address. This creates a significant issue for users utilizing multisig wallets, as these wallets often have different addresses across different chains, preventing them from transferring their funds cross-chain.

## Vulnerability Detail:

The vulnerability lies in the address validation check: `if (msg.sender != _to) { revert ITempleGold....

---

### 11. `L2ContractMigrationFacet.addMigratedDepositsToAccount()` doesn't update some global balances during the migration.

**Protocol**: Beanstalk: The Finale | **Impact**: HIGH

## Github link

<https://github.com/Cyfrin/2024-05-beanstalk-the-finale/blob/9c7b9fd521ad7cbe65cc788df181887c0eb39c6d/protocol/contracts/beanstalk/silo/L2ContractMigrationFacet.sol#L194>

## Summary

While migrating deposits to L2, `addMigratedDepositsToAccount()` doesn't increase the global `deposited` and `depositedBdv` balances.

## Vulnerability Details

Users can redeem their deposits and internal balances on L2 using `redeemDepositsAndInternalBalances()`.

And `redeemDepositsAndInternalBalances()` calls [addMigratedDepositsToAccount()](https://github.com/Cyfrin/2024-05-beanstalk-the-fina...

---

### 12. User can revert processWithdraw

**Protocol**: SteadeFi | **Impact**: HIGH

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-10-SteadeFi/blob/0f909e2f0917cb9ad02986f631d622376510abec/contracts/strategy/gmx/GMXWithdraw.sol#L197">https://github.com/Cyfrin/2023-10-SteadeFi/blob/0f909e2f0917cb9ad02986f631d622376510abec/contracts/strategy/gmx/GMXWithdraw.sol#L197</a>


## Summary

When a user wants to withdraw his tokens after depositing, the LP tokens are first sent to GMX. GMX then sends back the deposited tokens. Before the user receives them, their Vault Shares are burned in processWithdraw:

```solidity
File: GMXWithd...

---

### 13. Borrowers can retain debt even after being liquidated.

**Protocol**: Core Contracts | **Impact**: HIGH

## Summary

StabilityPool's liquidation fails to ensure complete debt clearance after liquidation. When the StabilityPool liquidates a borrower, their debt can remain non-zero, creating "zombie debt" in the system.

The problem surfaces in the interaction between StabilityPool and LendingPool during liquidation. When the StabilityPool executes `liquidateBorrower()`, it successfully transfers collateral but fails to ensure the borrower's debt is completely cleared. This creates a scenario where a borrower's position shows as liquidated but still carries outstanding debt, while we expects that a...

---

### 14. Gauge reward system can be gamed with repeatedly  stake/withdraw

**Protocol**: Core Contracts | **Impact**: HIGH

## Summary

The RAAC Gauge system implements a reward distribution mechanism where users can stake tokens and earn rewards based on their stake amount and `veToken` balance (includes a boost multiplier feature that affects reward calculations). Users staking and withdrawing repeatedly a large amount of tokens can game the system and maximize the rewards.

## Vulnerability Details

The current implementation allows users to manipulate their reward earnings by:

* temporarily staking large amounts of tokens
* claiming or accruing rewards based on the inflated stake
* quickly withdrawing the stak...

---

### 15. Rate of decay not measured in veRAACToken::increase which allows users to unfairly boost voting power by calling this function

**Protocol**: Core Contracts | **Impact**: HIGH

## Summary

The veRAACToken::increase function contains a critical vulnerability in the calculation of voting power (bias) when users increase their locked token amount. The issue arises because the function does not account for the decay of the user's existing voting power over time. Instead, it calculates the new bias based on the original locked amount, ignoring the fact that the user's voting power has decreased due to decay.

This flaw allows users to exploit the system by:

Initially locking a small amount of tokens.

Waiting for their voting power to decay partially.

Increasing their l...

---


## Statistics

- Total findings from Codehawks: 1,234
- Last updated: 2026-01-29

