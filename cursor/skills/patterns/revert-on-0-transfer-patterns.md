---
id: PAT-REVERT-ON-0-TRANSFER
title: Revert On 0 Transfer Security Patterns
category: token
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - transfer
  - safe-transfer
  - return-value

finding_count: 5
last_updated: 2026-01-31
---
# Revert On 0 Transfer Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 5 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for revert on 0 transfer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-1: `Cooler.roll()` wouldn't work as expected when `newCollateral = 0`.

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/320 

## Found by 
hansfriese, cccz, Allarious, csanuragjain



## Summary
`Cooler.roll()` is used to increase the loan duration by transferring the additional collateral.

But there will be some problems when `newCollateral = 0`.

## Vulnerability Detail
```solidity
    function roll (uint256 loanID) external {
        Loan storage loan = loans[loanID];
        Request memory req = loan.request;

        if (block.timestamp > loan.expiry) 
            revert Default();

        if (!loan.rollable)
            revert NotRollable();

        uint256 newCollateral = collateralFor(loan.amount, req.loanToCollateral) - loan.collateral;
        uint256 newDebt = interestFor(loan.amount, req.interest, req.duration);

        loan.amount += newDebt;
        loan.expiry += req.duration;
        loan.collateral += newCollateral;
        
        collateral.transferFrom(msg.sender, address(this), newCollateral); //@audit 0 amount
    }
```

In `roll()`, it transfers the `newCollateral` amount of collateral to the contract.

After the borrower repaid most of the debts, `loan.amount` might be very small and `newCollateral` for the original interest might be 0 because of the rounding issue.

Then as we can see from this [one](https://github.com/d-xo/weird-erc20#revert-on-zero-value-transfers), some tokens might revert for 0 amount and `roll()` wouldn't work as expected.

## Impact
There will be 2 impacts.

1. When the 

*[Content truncated...]*

---

### Example 2: [M-01] Zero amount token transfers may cause a denial of service during liquidations

**Source**: Code4rena
**Protocol**: Particle Protocol
**Impact**: MEDIUM

**Details**:

Some ERC20 implementations revert on zero value transfers. Since liquidation rewards are based on a fraction of the available position's premiums, this may cause an accidental denial of service that prevents the successful execution of liquidations.

### Impact

Liquidations in the LAMM protocol are incentivized by a reward that is calculated as a fraction of the premiums available in the position.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L348-L354>

```solidity
348:         // calculate liquidation reward
349:         liquidateCache.liquidationRewardFrom =
350:             ((closeCache.tokenFromPremium) * LIQUIDATION_REWARD_FACTOR) /
351:             uint128(Base.BASIS_POINT);
352:         liquidateCache.liquidationRewardTo =
353:             ((closeCache.tokenToPremium) * LIQUIDATION_REWARD_FACTOR) /
354:             uint128(Base.BASIS_POINT);
```

These amounts are later transferred to the caller, the liquidator, at the end of the `liquidatePosition()` function.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L376-L378>

```solidity
376:         // reward liquidator
377:         TransferHelper.safeTransfer(closeCache.tokenFrom, msg.sender, liquidateCache.liquidationRewardFrom);
378:         TransferHelper.safeTransfer(closeCache.tokenTo, msg.sender, liquidateCache.liquidationReward

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-particle)

---

### Example 3: [M-13] Transaction revert if the baseToken does not support 0 value transfer when charging changeFee

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L423
https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L651


## Vulnerability details

## Impact

Transaction revert if the baseToken does not support 0 value transfer when charging changeFee

## Proof of Concept

When call change via the PrivatePool.sol, the caller needs to the pay the change fee,

```solidity
	// calculate the fee amount
	(feeAmount, protocolFeeAmount) = changeFeeQuote(inputWeightSum);
}

// ~~~ Interactions ~~~ //

if (baseToken != address(0)) {
	// transfer the fee amount of base tokens from the caller
	ERC20(baseToken).safeTransferFrom(
		msg.sender,
		address(this),
		feeAmount
	);
```

calling changeFeeQuote(inputWeightSum)

```solidity
function changeFeeQuote(
	uint256 inputAmount
) public view returns (uint256 feeAmount, uint256 protocolFeeAmount) {
	// multiply the changeFee to get the fee per NFT (4 decimals of accuracy)
	uint256 exponent = baseToken == address(0)
		? 18 - 4
		: ERC20(baseToken).decimals() - 4;
	uint256 feePerNft = changeFee * 10 ** exponent;

	feeAmount = (inputAmount * feePerNft) / 1e18;
	protocolFeeAmount =
		(feeAmount * Factory(factory).protocolFeeRate()) /
		10_000;
}
```

if the feeAmount is 0,

the code below woud revert if the ERC20 token does not support 0 value transfer

```solidity
ERC20(baseToken).safeTransferFrom(
	msg.sender,
	ad

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 4: [M-29] `ConvexStakingWrapper` deposits and withdraws will frequently be disabled if a token that doesn't allow zero value transfers will be added as a reward one

**Source**: Code4rena
**Protocol**: Concur Finance
**Impact**: MEDIUM

**Details**:

_Submitted by hyh_

If deposits and withdraws are done frequently enough, the reward update operation they invoke will deal mostly with the case when there is nothing to add yet, i.e. `reward.remaining` match the reward token balance.

If reward token doesn't allow for zero value transfers, the reward update function will fail on an empty incremental reward transfer, which is now done unconditionally, reverting the caller deposit/withdrawal functionality

### Proof of Concept

When ConvexStakingWrapper isn't paused, every deposit and withdraw update current rewards via `_checkpoint` function before proceeding:

[ConvexStakingWrapper.sol#L233](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L233)<br>

[ConvexStakingWrapper.sol#L260](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L260)<br>

`_checkpoint` calls `_calcRewardIntegral` for each of the reward tokens of the pid:

[ConvexStakingWrapper.sol#L220](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L220)<br>

`_calcRewardIntegral` updates the incremental reward for the token, running the logic even if reward is zero, which is frequently the case:

[ConvexStakingWrapper.sol#L182](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L182)<br>

If the reward token doesn't allow zero value transfers, this transfer will fail, reverting the corresponding deposit or wit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-concur)

---

### Example 5: M-6: Tokens that revert of zero value transfers can cause reverts on liquidation

**Source**: Sherlock
**Protocol**: Teller Lender Groups Update Audit
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-11-teller-finance-update-judging/issues/51 

## Found by 
hash
### Summary

Tokens that revert of zero value transfers can cause reverts on liquidation

### Root Cause

In the [readme the team has mentioned](https://github.com/sherlock-audit/2024-11-teller-finance-update/tree/main?tab=readme-ov-file#q-if-you-are-integrating-tokens-are-you-allowing-only-whitelisted-tokens-to-work-with-the-codebase-or-any-complying-with-the-standard-are-they-assumed-to-have-certain-properties-eg-be-non-reentrant-are-there-any-types-of-weird-tokens-you-want-to-integrate) that they would like to know if any wierd token breaks their contract pools

In multiple places token amount which can become zero is transferred without checking the value is zero. This will cause these transactions to revert
https://github.com/sherlock-audit/2024-11-teller-finance-update/blob/0c8535728f97d37a4052d2a25909d28db886a422/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/LenderCommitmentGroup/LenderCommitmentGroup_Smart.sol#L699-L727
```solidity
            IERC20(principalToken).safeTransferFrom(
                msg.sender,
                address(this),
                amountDue + tokensToTakeFromSender - liquidationProtocolFee
            ); 
             
            address protocolFeeRecipient = ITellerV2(address(TELLER_V2)).getProtocolFeeRecipient();


              IERC20(principalToken).safeT

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

