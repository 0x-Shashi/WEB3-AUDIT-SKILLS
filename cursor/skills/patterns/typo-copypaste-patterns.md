# Typo / CopyPaste Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 4 | 1 | 0 |

**Common Sources**: Code4rena, Sherlock, Halborn

---

## Detection Checklist

- [ ] Check for typo / copypaste vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Use of tokenB’s price instead of tokenA in determining account health will lead to protocol mis-accounting and insolvency

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

_Submitted by 0xRajeev, also found by WatchPug_.

#### Impact

In `_supplyCreditUni()`, the last argument of `_convertTokenValues()` on `L674 being _priceB` instead of `_priceA` in the calculation of `supplyB` is a typo (should be `_priceA`) and therefore miscalculates `supplyB`, `creditB`, `creditUni` and therefore `totalAccountSupply` in function `accountHealth()` which affects the health of account/protocol determination that is used across all borrows/withdrawals/transfers/liquidations in the protocol. This miscalculation significantly affects all calculations in protocol and could therefore cause protocol insolvency.

#### Proof of Concept

- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L674>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L340>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L398-L401>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L532>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L544>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L119>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c482

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-wildcredit)

---

### Example 2: M-8: Wrong `CHANGE_COLLATERAL_DELAY` in CollateralBook

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/191 

## Found by 
GimelSec, CodingNameKiki, ctf\_sec, Jeiwan, yixxas, 0xjayne, rvierdiiev

## Summary

Admins can bypass time delay due to the wrong value of `CHANGE_COLLATERAL_DELAY`.

## Vulnerability Detail

The comment shows that the `CHANGE_COLLATERAL_DELAY` should be 2 days, but it's only 200 which means 3 minutes and 20 seconds.

## Impact

Admin can bypass the 2 days time delay and only need to wait less than 5 minutes to call `changeCollateralType`.

## Code Snippet

https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/CollateralBook.sol#L23
https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/CollateralBook.sol#L130

## Tool used

Manual Review

## Recommendation

```solidity
uint256 public constant CHANGE_COLLATERAL_DELAY = 2 days; //2 days
```

## Discussion

**kree-dotcom**

Sponsor confirmed, will fix. Duplicate of issue #231

---

### Example 3: M-4: Wrong constants for time delay

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/231 

## Found by 
GimelSec, neumo, 0x4non, hansfriese, rvierdiiev, wagmi, jonatascm



## Summary
This protocol uses several constants for time dealy and some of them are incorrect.

## Vulnerability Detail
In `isoUSDToken.sol`, `ISOUSD_TIME_DELAY` should be `3 days` instead of 3 seconds.

```solidity
    uint256 constant ISOUSD_TIME_DELAY = 3; // days;
```

In `CollateralBook.sol`, `CHANGE_COLLATERAL_DELAY` should be `2 days` instead of 200 seconds.

```solidity
    uint256 public constant CHANGE_COLLATERAL_DELAY = 200; //2 days
```

## Impact
Admin settings would be updated within a short period of delay so that users wouldn't react properly.

## Code Snippet
https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/isoUSDToken.sol#L10
https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/CollateralBook.sol#L23

## Tool used
Manual Review

## Recommendation
2 constants should be modified as mentioned above.

## Discussion

**kree-dotcom**

Sponsor confirmed, will fix.

**kree-dotcom**

Fixed https://github.com/kree-dotcom/isomorph/commit/4fc80e6178204691a365f656908c278d5faf4f88 , woops then forgot a semicolon, this was added here https://github.com/kree-dotcom/isomorph/commit/9bad2748dd3f3e7905dc8013383aef0cf98b1bea

isoToken was not altered in this commit but is correct. I made a copying error when setting up the Audit repo original

*[Content truncated...]*

---

### Example 4: [M-07] AaveYield: Misspelled external function name making functions fail

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: MEDIUM

**Details**:

_Submitted by 0xngndev_

#### Impact

In `AaveYield.sol` the functions:

*   `liquidityToken`
*   `_withdrawETH`
*   `_depositETH`

Make a conditional call to `IWETHGateway(wethGateway).getAWETHAddress()`

This function does not exist in the `wethGateway` contract, causing these function to fail with the error `"Fallback not allowed"`.

The function they should be calling is `getWethAddress()` without the "A".

Small yet dangerous typo.

##### Mitigation Steps

Simply modify:

`IWETHGateway(wethGateway).getAWETHAddress()`

to:

`IWETHGateway(wethGateway).getWETHAddress()`

In the functions mentioned above.

**[ritik99 (Sublime) confirmed](https://github.com/code-423n4/2021-12-sublime-findings/issues/42#issuecomment-1001348407):**
 > We were using an older version of the contracts that had [this definition](https://etherscan.io/address/dcd33426ba191383f1c9b431a342498fdac73488#code#F1#L158), will be updated accordingly

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

### Example 5: Typos in Interfaces

**Source**: Halborn
**Protocol**: Ecosystem - Merge Marketplace b14g
**Impact**: LOW

**Details**:

##### Description

Two typographical errors were found in the interfaces used by the project. While they may not be introduced by the team, they have been listed for the sake of completeness:

  

* In `IEarn.sol`:

```
// Amount of CORE the user recieves
...
// Amount of CORE the protocol recieves
```

`recieves` should be `recieves`.

  

* In `IBitcoinStake.sol`:

```
function accuredRewardPerBTCMap(address, uint256) external view returns (uint256);
```

`accuredRewardPerBTCMap()` should be `accruedRewardPerBTCMap()`.

##### BVSS

[AO:A/AC:L/AX:L/C:N/I:N/A:N/D:N/Y:N/R:N/S:U (0.0)](/bvss?q=AO:A/AC:L/AX:L/C:N/I:N/A:N/D:N/Y:N/R:N/S:U)

##### Recommendation

To maintain clarity and trustworthiness, it is essential to rectify any typographical errors present within the contracts. Correcting such errors minimizes the likelihood of confusion and reinforces confidence in the accuracy and integrity of the documentation.

##### Remediation

**SOLVED:** The **B14G team** fixed this finding in commit `3545f22` by correcting the typographical errors.

##### Remediation Hash

<https://github.com/b14glabs/contracts/commit/3545f2231423f454252911e7fac123a5c7fb4b46>

**Reference**: [View Original Finding](https://www.halborn.com/audits/coredao/ecosystem-Merge-Marketplace-b14g)

---

### Example 6: [M-01] Function `restructureCapTable()` in `Equity.sol` not functioning as expected

**Source**: Code4rena
**Protocol**: Frankencoin
**Impact**: MEDIUM

**Details**:

Incorrect typo in function `restructureCapTable()` leading to only burning tokens of first address of `addressToWipe` array argument.

### Proof of Concept

Here, in L313, addressToWipe\[0] only takes first address of the array. While ignoring the rest and also since first address's tokens are burned it will fail `addressesToWipe` array has more than one addresses.

        function restructureCapTable(address[] calldata helpers, address[] calldata addressesToWipe) public {
            require(zchf.equity() < MINIMUM_EQUITY);
            checkQualified(msg.sender, helpers);
            for (uint256 i = 0; i<addressesToWipe.length; i++){
                address current = addressesToWipe[0];
                _burn(current, balanceOf(current));
            }
        }


### Recommended Mitigation Steps

Change `address current = addressesToWipe[0];` ==> `  address current = addressesToWipe[i]; `

**[luziusmeisser (Frankencoin) confirmed](https://github.com/code-423n4/2023-04-frankencoin-findings/issues/941#issuecomment-1528893633)**

***

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-frankencoin)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

