---
id: PAT-1-64-RULE
title: 1 64 Rule Security Patterns
category: evm
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - 1-64-rule
  - gas
  - call

finding_count: 6
last_updated: 2026-01-31
---
# 1/64 Rule Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 2 | 0 |

**Common Sources**: TrailOfBits, Shieldify, MixBytes, Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for 1/64 rule vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-08] Gas limit check is inaccurate, leading to an operator being able to fail a job intentionally

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L316](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L316)<br>

There's a check at line 316 that verifies that there's enough gas left to execute the `HolographBridge.bridgeInRequest()` with the `gasLimit` set by the user, however the actual amount of gas left during the call is less than that (mainly due to the `1/64` rule, see below).<br>
An attacker can use that gap to fail the job while still having the `executeJob()` function complete.

### Impact

The owner of the bridged token would loose access to the token since the job failed.

### Proof of Concept

Besides using a few units of gas between the check and the actual call, there's also a rule that only 63/64 of the remaining gas would be dedicated to an (external) function call. Since there are 2 external function calls done (`nonRevertingBridgeCall()` and the actual call to the bridge) `~2/64` of the gas isn't sent to the bridge call and can be used after the bridge call runs out of gas.

The following PoC shows that if the amount of gas left before the call is at least 1 million then the execution can continue after the bridge call fails:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ContractTest is Test {
    event FailedOperatorJob(bytes32 jobHash);
    uint256 private _inboundMessageCounter;
    mapping(bytes32 => bool) private _failedJobs;
    constr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: Withdrawal queue can be forcibly activated to hinder bridge operation

**Source**: TrailOfBits
**Protocol**: Immutable Smart Contracts
**Impact**: MEDIUM

**Details**:

## Target: RootERC20PredicateFlowRate.sol

## Description

The withdrawal queue can be forcibly activated to impede the proper operation of the bridge.

The `RootERC20PredicateFlowRate` contract implements a withdrawal queue to more easily detect and stop large withdrawals from passing through the bridge (e.g., bridging illegitimate funds from an exploit). A transaction can enter the withdrawal queue in four ways:

1. If a tokens flow rate has not been configured by the rate control admin.
2. If the withdrawal amount is larger than or equal to the large transfer threshold for that token.
3. If, during a predefined period, the total withdrawals of that token are larger than the defined token capacity.
4. If the rate controller manually activates the withdrawal queue by using the `activateWithdrawalQueue` function.

In cases 3 and 4 above, the withdrawal queue becomes active for all tokens, not just the individual transfers. Once the withdrawal queue is active, all withdrawals from the bridge must wait a specified time before the withdrawal can be finalized. As a result, a malicious actor could withdraw a large amount of tokens to forcibly activate the withdrawal queue and hinder the expected operation of the bridge.

## Exploit Scenario 1

Eve observes Alice initiating a transfer to bridge her tokens back to the mainnet. Eve also initiates a transfer, or a series of transfers to avoid exceeding the per-transaction limit, of sufficient tokens to exceed the expected flow rate. 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-08-immutable-securityreview.pdf)

---

### Example 3: Insecure storage of session data in local storage

**Source**: TrailOfBits
**Protocol**: WalletConnect v2.0 SDK
**Impact**: MEDIUM

**Details**:

## Target: Browser storage

## Description
HTML5 local storage is used to hold session data, including keychain values. Because there are no access controls on modifying and retrieving this data using JavaScript, data in local storage is vulnerable to XSS attacks.

**Figure 4.1:** Keychain data stored in a browsers localStorage

## Exploit Scenario
Alice discovers an XSS vulnerability in a dApp that supports WalletConnect. This vulnerability allows Alice to retrieve the dApps keychain data, allowing her to propose new transactions to the connected wallet.

## Recommendations
Short term, consider using cookies to store and send tokens. Enable cross-site request forgery (CSRF) libraries available to mitigate these attacks. Ensure that cookies are tagged with `httpOnly`, and preferably `secure`, to ensure that JavaScript cannot access them.

## References
- OWASP HTML5 Security Cheat Sheet: Local Storage

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-03-walletconnectv2-securityreview.pdf)

---

### Example 4: [L-08] No Way to Recover Locked Tokens in the Vault

**Source**: Shieldify
**Protocol**: Pudgystrategy
**Impact**: LOW

**Details**:

## Severity

Low Risk

## Description

The vault lacks a mechanism to recover arbitrary ERC-20 tokens accidentally sent to it. Over time, stray tokens may become irrecoverable. For example the vault expects ETH and later swaps `ETH`->`HEROSTR`. If a sale is settled in WETH (very common) and the marketplace transfers WETH (ERC-20) to the vault, it just sits there. The contract has no WETH unwrap and no generic ERC-20 withdrawal.

## Location of Affected Code

File: [NFTVault%20Final.sol](https://github.com/0xcaptainy/HEROSTR/blob/cafe69ed029aef74e874471b157afabfacb0d81c/NFTVault%20Final.sol)

## Impact

Locked tokens

## Recommendation

Add a simple, restricted rescue function:

```solidity
function rescueTokens(address token, uint256 amount, address to) external onlyController nonReentrant {
    require(token != HEROSTR, "cannot rescue HEROSTR");
    IERC20(token).transfer(to, amount);
}
```

## Team Response

**Status: FIXED**

While the vault's normal operation only involves ETH and OCH NFTs, we have implemented a basic token recovery function for edge cases where tokens might get accidentally sent to the vault (such as WETH from marketplace settlements).

**Implementation:**

```solidity
function rescueTokens(address token, uint256 amount, address to) external onlyController nonReentrant {
    require(token != HEROSTR, "cannot rescue HEROSTR");
    IERC20(token).transfer(to, amount);
}
```

## [I-01] Enforse Constraints for `swapThreshold` and `maxSwapAmount` in `setSwapBe

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/PudgyStrategy-Security-Review.md)

---

### Example 5: Remove unnecessary ETH handling logic for maker asset

**Source**: MixBytes
**Protocol**: Barter DAO
**Impact**: LOW

**Details**:

##### Description
In the [`callExecutor()`](https://github.com/BarterLab/argon/blob/f653d58132124854db42d2bd93d0c6b91da2c398/contracts/InchFusionBarterResolver.sol#L93-L123) function, there's logic that checks if the maker asset is ETH and skips token transfer:

```solidity
if (makerAsset.get() != address(0) && 
    makerAsset.get() != address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)
   ) {
    IERC20(makerAsset.get()).safeTransfer(address(executor), makingAmount);
}
```

This logic appears to be leftover code from UniswapX solver implementation and is not needed in the context of 1inch Fusion orders.
<br/>
##### Recommendation
We recommend removing unnecessary logic.

---

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Barter%20DAO/InchFusionBarterResolver/README.md#3-remove-unnecessary-eth-handling-logic-for-maker-asset)

---

### Example 6: M-19: Gas Manipulation by Malicious Winners in claimPrizes Function

**Source**: Sherlock
**Protocol**: PoolTogether: The Prize Layer for DeFi
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-05-pooltogether-judging/issues/163 

## Found by 
0x73696d616f, 0xSpearmint1, MiloTruck, infect3d, jo13
## Summary

A malicious winner can exploit the `claimPrizes` function in the `Claimer` contract by reverting the transaction through returning a huge data chunk. This manipulation can cause the transaction to run out of gas, preventing legitimate claims and allowing the malicious user to claim prizes without computing winners.

## Vulnerability Detail

- The `Claimer` contract allows users to claim prizes on behalf of others by calling the `claimPrizes` function.
- A malicious winner can exploit this function by returning a huge data chunk when called, causing the transaction's gas to be too high and revert.
- Although the function catches the revert, the remaining gas (63/64 of the original gas) is likely insufficient for the rest of the claims.
- The malicious winner can then replay the transaction to claim the fees from the first claimer's computation without needing to compute the winners themselves.

## Impact

- Legitimate claimers may lose gas fees due to transaction reverts caused by malicious winners.
- Malicious winners can exploit this to claim prizes without computing winners, undermining the fairness of the prize distribution.

## Recommendation

- Implement a gas limit check to ensure that sufficient gas remains for the rest of the claims after catching a revert.
- Consider adding a mechanism to penalize or blackl

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

