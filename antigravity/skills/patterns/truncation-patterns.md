# Truncation Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for truncation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-1: Precision is lost in depositAuction and withdrawAuction user amount due calculations

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/201 

## Found by 
CRYP70, yixxas, hyh

## Summary

Formulas for `usdcAmount`, `portion.crab`, `portion.eth` used in depositAuction() and withdrawAuction() for queued distributions perform division first, which lead to truncation and fund loss in the numerical corner cases.

## Vulnerability Detail

depositAuction() and withdrawAuction() use the same approach for USDC and crab amount calculation. Let's focus on withdrawAuction(), there it is `usdcAmount = (((withdraw.amount * 1e18) / _p.crabToWithdraw) * usdcReceived) / 1e18`.

When `_p.crabToWithdraw` is big compared to `withdraw.amount`, the `((withdraw.amount * 1e18) / _p.crabToWithdraw)` can become zero as result of integer division.

As an example there can be an ordinary user and a whale situation, for the user it can be `withdraw.amount = 900`, while `_p.crabToWithdraw = 1000e18`, `usdcReceived = 2e18`, then `usdcAmount = (((withdraw.amount * 1e18) / _p.crabToWithdraw) * usdcReceived) / 1e18 = 0`, while it should be `usdcAmount = (withdraw.amount * usdcReceived) / _p.crabToWithdraw = (900 * 2e18) / 1000e18 = 1`.

## Impact

When truncation occurs the corresponding depositor or withdrawer will experience the loss as less funds to be distributed to them.

Setting the severity to medium as this have material impact in a numerical corner cases only.

## Code Snippet

withdrawAuction() use `usdcAmount = (((withdraw.amount * 1e18) / _p.crabToWithdraw) * us

*[Content truncated...]*

---

### Example 2: [M-21] Truncation in casting can lead to a founder receiving all the base tokens

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L71-L126><br>
<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L88>

The initialize function of the `Token` contract receives an array of `FounderParams`, which contains the ownership percent of each founder as a `uint256`. The initialize function checks that the sum of the percents is not more than 100, but the value that is added to the sum of the percent is truncated to fit in `uint8`. This leads to an error because the value that is used for assigning the base tokens is the original, not truncated, `uint256` value.

This can lead to wrong assignment of the base tokens, and can also lead to a situation where not all the users will get the correct share of base tokens (if any).

### Proof of Concept

To verify this bug I created a foundry test. You can add it to the test folder and run it with `forge test --match-test testFounderGettingAllBaseTokensBug`.

This test deploys a token implementation and an `ERC1967` proxy that points to it, and initializes the proxy using an array of 2 founders, each having 256 ownership percent. The value which is added to the `totalOwnership` variable is a `uint8`, and when truncating 256 to fit in a `uint8` it will turn to 0, so this check will pass.

After the call to initialize, the test asserts that all the base token ids belongs to the first founder, w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 3: M-9: Bad debt may persist even after complete liquidation in Velo Vault due to truncation

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/174 

## Found by 
0x52

## Summary

When liquidating a user, if all their collateral is taken but it is not valuable enough to repay the entire loan they would be left with remaining debt. This is what is known as bad debt because there is no collateral left to take and the user has no obligation to pay it back. When this occurs, the vault will forgive the user's debts, clearing the bad debt. The problem is that the valuations are calculated in two different ways which can lead to truncation issue that completely liquidates a user but doesn't clear their bad debt.

## Vulnerability Detail

            uint256 totalUserCollateral = totalCollateralValue(_collateralAddress, _loanHolder);
            uint256 proposedLiquidationAmount;
            { //scope block for liquidationAmount due to stack too deep
                uint256 liquidationAmount = viewLiquidatableAmount(totalUserCollateral, 1 ether, isoUSDBorrowed, liquidatableMargin);
                require(liquidationAmount > 0 , "Loan not liquidatable");
                proposedLiquidationAmount = _calculateProposedReturnedCapital(_collateralAddress, _loanNFTs, _partialPercentage);
                require(proposedLiquidationAmount <= liquidationAmount, "excessive liquidation suggested");
            }
            uint256 isoUSDreturning = proposedLiquidationAmount*LIQUIDATION_RETURN/LOAN_SCALE;
            if(proposedLiquidationAmount >= totalUserColl

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
