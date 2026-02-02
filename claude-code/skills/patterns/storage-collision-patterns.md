---
id: PAT-STORAGE-COLLISION
title: Storage Collision Security Patterns
category: storage
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - storage
  - collision
  - layout

finding_count: 3
last_updated: 2026-01-31
---
# Storage Collision Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 0 | 1 | 0 |

**Common Sources**: Cyfrin, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for storage collision vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Important Balancer fields can be overwritten by EndTime

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

**Context:**  
ManagedPool.sol#L75-L77, ManagedPool.sol#L84-L86, LegacyBasePool.sol, WordCodec.sol

**Description:**  
Balancers ManagedPool uses 32-bit values for `startTime` and `endTime`, but it does not verify if those values exist within that range. Values are stored in a 32-byte `_miscData` slot in BasePool via the `insertUint32()` function. Nevertheless, this function does not strip any excess bits, resulting in other fields stored in `_miscData` being overwritten. In the version that Aera Vault uses, only the "restrict LP" field can be overwritten, and by carefully crafting the value of `endTime`, the "restrict LP" boolean can be switched off, allowing anyone to use `joinPool`. 

The Manager could cause this behavior via the `updateWeightsGradually()` function, while the Owner could do it via `enableTradingWithWeights()`.  
**Note:** This issue has been reported to Balancer by the Spearbit team.

```solidity
contract ManagedPool is BaseWeightedPool, ReentrancyGuard { // f14de92ac443d6daf1f3a42025b1ecdb8918f22e
    // [ 64 bits | 119 bits | 1 bit | 32 bits | 32 bits | 7 bits | 1 bit ]
    // [ reserved | unused | restrict LP | end time | start time | total tokens | swap flag ]
    // |MSB
    function _startGradualWeightChange(uint256 startTime, uint256 endTime, ... ) ... {
        ...
        _setMiscData(
            _getMiscData().insertUint32(startTime, _START_TIME_OFFSET).insertUint32(endTime,
            _END_TIME_OFFSET), !
        )

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] Permanent DOS in `liquidity_lockbox` for under $10

**Source**: Code4rena
**Protocol**: Olas
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-12-autonolas/blob/main/lockbox-solana/solidity/liquidity_lockbox.sol#L54> <br><https://github.com/code-423n4/2023-12-autonolas/blob/main/lockbox-solana/solidity/liquidity_lockbox.sol#L181-L184>

The `liquidity_lockbox` contract in the `lockbox-solana` project is vulnerable to permanent DOS due to its storage limitations. The contract uses a Program Derived Address (PDA) as a data account, which is created with a maximum size limit of 10 KB.

Every time the `deposit()` function is called, a new element is added to `positionAccounts`, `mapPositionAccountPdaAta`, and `mapPositionAccountLiquidity`, which decreases the available storage by `64 + 32 + 32 = 128` bits. This means that the contract will run out of space after at most `80000 / 128 = 625` deposits.

Once the storage limit is reached, no further deposits can be made, effectively causing a permanent DoS condition. This could be exploited by an attacker to block the contract's functionality at a very small cost.

### Proof of Concept

An attacker can cause a permanent DoS of the contract by calling `deposit()` with the minimum position size only 625 times. This will fill up the storage limit of the PDA, preventing any further deposits from being made.

Since neither the contract nor seemingly Orca's pool contracts impose a limitation on the minimum position size, this can be achieved at a very low cost of `625 * dust * transaction fees`:

<img width="400" alt="no min deposit in SOL/OLAS 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-autonolas)

---

### Example 3: Upgradeable contracts which are inherited from should use ERC7201 namespaced storage layouts or storage gaps to prevent storage collision

**Source**: Cyfrin
**Protocol**: Strata
**Impact**: LOW

**Details**:

**Description:** The protocol has upgradeable contracts which other contracts inherit from. These contracts should either use:
* [ERC7201](https://eips.ethereum.org/EIPS/eip-7201) namespaced storage layouts - [example](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol#L60-L72)
* storage gaps (though this is an [older and no longer preferred](https://blog.openzeppelin.com/introducing-openzeppelin-contracts-5.0#Namespaced) method)

The ideal mitigation is that all upgradeable contracts use ERC7201 namespaced storage layouts.

Without using one of the above two techniques storage collision can occur during upgrades.

**Strata:** Fixed in commit [98068bd](https://github.com/Strata-Money/contracts/commit/98068bd9d9d435b37ce8f855f45b61d37aa274db).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-06-11-cyfrin-strata-v2.1.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

