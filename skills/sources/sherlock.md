# Sherlock - Audit Findings

## Overview

**Total Findings**: 3,017 (5.97% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 984 | 2032 | 1 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Business Logic | 44 |
| Front-Running | 32 |
| Oracle | 28 |
| Wrong Math | 26 |
| Missing-Logic | 23 |
| Liquidation | 20 |
| DOS | 19 |
| Denial-Of-Service | 19 |
| Decimals | 19 |
| Configuration | 18 |

---

## Notable Findings

### 1. H-1: Pool managers can steal all other pools' pending deposits from `globalEscrow` via malicious `requestManager` swapping

**Protocol**: Centrifuge Protocol V3 Audit | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2025-10-centrifuge-protocol-v3-1-audit-judging/issues/641 

## Found by 
0x52, 0xRstStn, 6PottedL, Audittens, LeFy, NovaTheMachine, PowPowPow, Waydou, anonymousjoe, asui, gh0xt, skybluescar

## Summary

The request manager system allows attackers to steal all pending user deposits from `globalEscrow`. An attacker can create fraudulent deposit requests with a malicious request manager, then swap to `AsyncRequestManager` before triggering `approvedDeposits` callbacks. This causes `AsyncRequestManager.approvedDeposits()` to transfer legitimate user funds ...

---

### 2. H-3: Intent orders are guaranteed to execute, but fees from these orders are not accounted in collateral, allowing user to withdraw all collateral ignoring these pending fees.

**Protocol**: Perennial V2 Update #4 | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2025-01-perennial-v2-4-update-judging/issues/31 

## Found by 
panprog

### Summary
In normal `update`, all orders are pending and might be invalidated if invalid price is commited for the corresponding epoch (no pricefeed available or price commit timeout). However, when `Intent`s are used, these orders are guaranteed to be accepted (`invalidation = 0` for them). In particular, this feature allows to open and close orders via `Intent`s even when open order epoch is not commited yet.

The issue is that the fees for the orders are pending and not includ...

---

### 3. H-6: There is a calculation error inside the calculateCompoundedFactor() function, causing users to overpay interest.

**Protocol**: Flayer | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2024-08-flayer-judging/issues/227 

## Found by 
0x37, Sentryx, Tendency, ZeroTrust, dany.armstrong90, dimulski, kuprum, merlinboii, robertodf, stuart\_the\_minion
## Summary
There is a calculation error inside the calculateCompoundedFactor() function, causing users to overpay interest.
## Vulnerability Detail
```javascript
    function calculateProtectedInterest(uint _utilizationRate) public pure returns (uint interestRate_) {
        // If we haven't reached our kink, then we can just return the base fee
        if (_utilizationRate <= UTILIZATION_KI...

---

### 4. H-10: Interest rate is updated before updating the debt when repaying debt

**Protocol**: ZeroLend One | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2024-06-new-scope-judging/issues/413 

## Found by 
000000, 0xweebad, A2-security, JCN, Obsidian, Tendency, TessKimy, Varun\_05, almurhasan, ether\_sky, imsrybr0, lemonmon, stuart\_the\_minion, trachev
### Summary

Interest rate is updated before updating the debt when repaying debt in `BorrowLogic@executeRepay` leading to an incorrect total debt being used when calculating the new interest rates and causing suppliers to keep accruing interest based on the previous debt and even if there are no ongoing borrows anymore.

### Root Cause

[BorrowLogic](ht...

---

### 5. H-5: `LiquidationLogic@_burnCollateralTokens` does not account for liquidation fees when withdrawing collateral during liquidation leading to incorrect accounting and Pools insolvency

**Protocol**: ZeroLend One | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2024-06-new-scope-judging/issues/228 

## Found by 
000000, A2-security, Bigsam, Honour, dhank, ether\_sky, imsrybr0, lemonmon, thisvishalsingh, trachev, zarkk01
### Summary

`LiquidationLogic@_burnCollateralTokens` does not account for liquidation fees when withdrawing collateral during liquidation leading to incorrect accounting and Pools insolvency, ultimately impacting regular flows (.e.g borrows, withdrawals, redemptions, ...) in the protocol for the different actors (.i.e Pools users, Curated Vaults and their users, NFT Positions users).

### Roo...

---

### 6. H-1: Empty orders do not request from oracle and during settlement they use an invalid oracle version with `price=0` which messes up a lot of fees and funding accounting leading to loss of funds for the makers

**Protocol**: Perennial V2 Update #2 | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2024-02-perennial-v2-3-judging/issues/5 

## Found by 
panprog
## Summary

When `market.update` which doesn't change user's position is called, a new (current) global order is created, but the oracle version is not requested due to empty order. This means that during the order settlement, it will use non-existant invalid oracle version with `price = 0`. This price is then used to accumulate all the data in this invalid `Version`, meaning accounting is done using `price = 0`, which is totally incorrect. For instance, all funding and fees calculations mu...

---

### 7. H-1: Pool can be drained

**Protocol**: WOOFi Swap | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/68 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
## Summary
The pool can be drained just as it was during the incident that occurred previously.
## Vulnerability Detail
`maxNotionalSwap` and `maxGamma` and the new math formula do not prevent the pool being drainable. Same attack vector that happent previously is still applicable:
https://woo.org/blog/en/woofi-spmm-exploit-post-mortem
https://rekt.news/woo-rekt/

Flashloan 99989999999999999990000 (99_990) WOO
Sell WOO partially (in 10 pieces) ...

---

### 8. H-6: All ETH can be stolen during rebalancing for `mTOFTs` that hold native

**Protocol**: Tapioca | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2024-02-tapioca-judging/issues/69 

## Found by 
0xadrii, GiuseppeDeLaZara
## Summary
Rebalancing of ETH transfers the ETH to the destination mTOFT without calling `sgRecieve` which leaves the ETH hanging inside the `mTOFT` contract. 
This can be exploited to steal all the ETH.

## Vulnerability Detail
Rebalancing of `mTOFTs` that hold native tokens is done through the `routerETH` contract inside the `Balancer.sol` contract. 
Here is the code snippet for the `routerETH` contract:

```solidity
## Balancer.sol

if (address(this).balance < _amount) revert...

---

### 9. H-7: Different spot prices used during the comparison

**Protocol**: Notional Update #4 | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-10-notional-judging/issues/85 

## Found by 
xiaoming90
## Summary

The spot prices used during the comparison are different, which might result in the trade proceeding even if the pool is manipulated, leading to a loss of assets.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-10-notional/blob/main/leveraged-vaults/contracts/vaults/BalancerComposableAuraVault.sol#L90

```solidity
File: BalancerComposableAuraVault.sol
090:     function _checkPriceAndCalculateValue() internal view override returns (uint256) {
091:         (uint256[...

---

### 10. H-8: Incorrect approach to tracking the PnL of a DV

**Protocol**: Tokemak | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/589 

## Found by 
xiaoming90

A DV might be incorrectly marked as not sitting in a loss, thus allowing users to burn all the DV shares, locking in all the loss of the DV and the vault shareholders.

## Vulnerability Detail

Let $DV_A$ be a certain destination vault.

Assume that at $T0$, the current debt value (`currentDvDebtValue`) of $DV_A$ is 95 WETH, and the last debt value (`updatedDebtBasis`) is 100 WETH. Since the current debt value has become smaller than the last debt value, the vault is making a loss of 5 WETH ...

---

### 11. H-7: Stat calculator returns incorrect report for swETH

**Protocol**: Tokemak | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/587 

## Found by 
xiaoming90

Stat calculator returns incorrect reports for swETH, causing multiple implications that could lead to losses to the protocol,

## Vulnerability Detail

The purpose of the in-scope `SwEthEthOracle` contract is to act as a price oracle specifically for swETH (Swell ETH) per the comment in the contract below and the codebase's [README](https://github.com/sherlock-audit/2023-06-tokemak-xiaoming9090/tree/main/v2-core-audit-2023-07-14/src/oracles#lst-oracles)

https://github.com/sherlock-audit/202...

---

### 12. H-13: `BalancerPairOracle` can be manipulated using read-only reentrancy

**Protocol**: Blueberry Update | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/141 

## Found by 
cuthalion0x
## Summary

`BalancerPairOracle.getPrice` makes an external call to `BalancerVault.getPoolTokens` without checking the Balancer Vault's reentrancy guard. As a result, the oracle can be trivially manipulated to liquidate user positions prematurely.

## Vulnerability Detail

In February, the Balancer team disclosed a read-only reentrancy vulnerability in the Balancer Vault. The detailed disclosure can be found [here](https://forum.balancer.fi/t/reentrancy-vulnerability-scope-expanded/4345). ...

---

### 13. H-16: Incomplete error handling causes execution and freezing/cancelling of Deposits/Withdrawals/Orders to fail.

**Protocol**: GMX | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-02-gmx-judging/issues/119 

## Found by 
0xdeadbeef, KingNFT, hack3r-0m

## Summary

Users can define callbacks for Deposits/Withdrawals/Orders execution and cancellations.
GMX protocol attempts to manage errors during the execution of the callbacks 

A user controlled callback can return a specially crafted revert reason that will make the error handling revert.

By making the execution and cancelation revert, a malicious actor can game orders and waste keeper gas.

## Vulnerability Detail

The bug resides in `ErrorUtils`s `getRevertMessage`  tha...

---

### 14. H-13: Vault executes swaps without slippage protection

**Protocol**: Derby | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-01-derby-judging/issues/64 

## Found by 
Bauer, Bobface, Jeiwan, Met, Nyx, Ruhum, cergyk, hyh, immeas, nobody2018, tives

## Summary
The vault executes swaps without slippage protection. That will cause a loss of funds because of sandwich attacks.

## Vulnerability Detail
Both in `Vault.claimTokens()` and `MainVault.withdrawRewards()` swaps are executed through the Swaps library. It calculates the slippage parameters itself which doesn't work. Slippage calculations (min out) have to be calculated *outside* of the swap transaction. Otherwise, it u...

---

### 15. H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

**Protocol**: Blueberry | **Impact**: HIGH

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/109 

## Found by 
berndartmueller, carrot, minhtrng, 0Kage, Jeiwan, chaduke, koxuan, Ruhum, cergyk, rbserver, stent, saian, XKET, GimelSec

## Summary
Soft vault shares are issued against interest bearing tokens issued by `Compound` protocol in exchange for underlying deposits. However, `withdrawLend` function caps the withdrawable amount to initial underlying deposited by user (`pos.underlyingAmount`). Capping underlying amount to initial underlying deposited would mean that a user can burn all his vault shares in `wi...

---


## Statistics

- Total findings from Sherlock: 3,017
- Last updated: 2026-01-29
