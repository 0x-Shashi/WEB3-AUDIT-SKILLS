# Cooldown Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for cooldown vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: The vault manager has unchecked power to create arbitrage using setSwapFees

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Vulnerability Report

## Severity
**High Risk**

## Context
- AeraVaultV1.sol: Lines 663-679
- BasePool.sol: Lines 58-59

## Description
A previously known issue was that a malicious vault manager could arbitrage the vault like in the below scenario:

1. Set the swap fees to a high value by calling `setSwapFee` (10% is the maximum).
2. Wait for the market price to move against the spot price.
3. In the same transaction, reduce the swap fees to ~0 (0.0001% is the minimum) and arbitrage the vault.

The proposed fix was to limit the percentage change of the swap fee to a maximum of `MAXIMUM_SWAP_FEE_PERCENT_CHANGE` each time. However, because there is no restriction on how many times the `setSwapFee` function can be called in a block or transaction, a malicious manager can still call it multiple times in the same transaction and eventually set the swap fee to the value they want.

## Recommendation
Enforce a cooldown period of reasonable length between two consecutive `setSwapFee` function calls.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] The `redeem` related functions are likely to be blocked

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L615>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L685>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L712>

### Impact

The following `redeem` related functions are likely to be blocked, users will not be able to retrieve their funds.

    function _redeemPxGlp(
        address token,
        uint256 amount,
        uint256 minOut,
        address receiver
    );
    function redeemPxGlpETH(
        uint256 amount,
        uint256 minOut,
        address receiver
    );
    function redeemPxGlp(
        address token,
        uint256 amount,
        uint256 minOut,
        address receiver
    );

### Proof of Concept

The `GlpManager` contract of GMX has a `cooldownDuration` limit on redeem/unstake (`\_removeLiquidity()`). While there is at least one deposit/stake (`\_addLiquidity()`) operation in the past `cooldownDuration` time, redemption would fail. Obviously this limitation is user-based,  and `PirexGmx` contract is one such user.

<https://github.com/gmx-io/gmx-contracts/blob/c3618b0d6fc1b88819393dc7e6c785e32e78c72b/contracts/core/GlpManager.sol#L234>

    Current setting of `cooldownDuration` is 15 minutes, the max value is 2 days.

<https://arbiscan.io/address/0x321f653eed006ad1c29d174e17d96351bde22649#readC

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: [M-03] users still forced to follow previously set cooldownDuration even when cooldown is off (set to zero) before unstaking

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

The `StakedUSDeV2` contract can enforces coolDown periods for users before they are able to unstake/ take out their funds from the silo contract if coolDown is on. Based on the presence of the modifiers `ensureCooldownOff` and `ensureCooldownOn`, it is known that the coolDown state of the `StakedUSDeV2` contract can be toggled on or off.
In a scenario where coolDown is on (always turned on by default) and Alice and Bob deposits, two days after Alice wants to withdraw/redeem. Alice is forced to wait for 90 days before completing withdrawal/getting her tokens from the silo contract because Alice must call  coolDownAsset()/coolDownShares() fcns respectively. Bob decides to wait an extra day.

On the third day, Bob decides to withdraw/redeem. Contract admin also toggles the coolDown off (sets cooldownDuration to 0), meaning there is no longer a coolDown period and all withdrawals should be sent to the users immediately. Bob now calls calls the redeem()/withdraw() fcn to withdraw instantly to his address instead of the silo address since there is no coolDown.

Alice sees Bob has gotten his tokens but Alice cant use the redeem()/withdraw() because her `StakedUSDeV2` were already burned and her underlying assets were sent to the silo contract for storage. Alice cannot sucessfully call `unstake()` because her `userCooldown.cooldownEnd`  value set to \~ 90 days. Now Alice has to unfairly wait out the 90 days even though coolDowns have been turned off and everyone else has unrestricted

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
