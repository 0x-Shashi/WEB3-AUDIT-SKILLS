---
id: PAT-OPTIMISM
title: Optimism Security Patterns
category: layer2
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - optimism
  - l2
  - rollup

finding_count: 4
last_updated: 2026-01-31
---
# Optimism Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for optimism vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Permitting Multiple Drip Calls Per Block

**Source**: Spearbit
**Protocol**: Optimism Drippie
**Impact**: MEDIUM

**Details**:

## Risk Assessment

**Severity:** Medium Risk  
**Context:** Drippie.sol#L266  

## Description
The inline comments correctly note that reentrancy is possible and permitted when `state.config.interval` is 0. We are currently unaware of use cases where this is desirable. Reentrancy is one risk, and flashbot bundles are a similar risk where the drip may be called multiple times by the same actor in a single block. A malicious actor may abuse this ability, especially if the interval is misconfigured as 0 due to JavaScript type coercion.

A reentrant call or flashbot bundle may be used to frontrun an owner attempting to archive a drip or withdraw assets.

## Recommendation
We recommend limiting drip calls to 1 per block. Document the transaction order dependence (frontrunning) risk for owners wishing to archive a drip. Reasonable drip intervals can be employed to prevent this attack.

If it is important to permit multiple calls to the same drip in a single block, we recommend making the behavior opt-in rather than default if no `state.config.interval` is specified.

```solidity
+function create(string memory _name, DripConfig memory _config, bool allowMultiplePerBlock) external
onlyOwner { , !
-function create(string memory _name, DripConfig memory _config) external onlyOwner {
    // Make sure this drip doesn 't already exist. We *must* guarantee that no other function
    // will ever set the status of a drip back to NONE after it 's been created. This is why
    // archival is

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/OptimismDrippie-Spearbit-Security-Review.pdf)

---

### Example 2: Underpaying Optimism l2gas may lead to loss of funds

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity: Medium Risk

### Context
- **File:** OptimismBridgeFacet.sol
- **Lines:** 97-113

### Description
The `OptimismBridgeFacet` uses Optimisms bridge with user-provided `l2Gas`.

```solidity
function _startBridge(
    LiFiData calldata _lifiData,
    BridgeData calldata _bridgeData,
    uint256 _amount,
    bool _hasSourceSwap
) private {
    ...
    if (LibAsset.isNativeAsset(_bridgeData.assetId)) {
        bridge.depositETHTo{ value: _amount }(_bridgeData.receiver, _bridgeData.l2Gas, "");
    } else {
        ...
        bridge.depositERC20To(
            _bridgeData.assetId,
            _bridgeData.assetIdOnL2,
            _bridgeData.receiver,
            _amount,
            _bridgeData.l2Gas,
            ""
        );
    }
}
```

Optimisms standard token bridge makes the cross-chain deposit by sending a cross-chain message to `L2Bridge`.

- **File:** L1StandardBridge.sol
- **Lines:** 114-123

```solidity
// Construct calldata for finalizeDeposit call
bytes memory message = abi.encodeWithSelector(
    IL2ERC20Bridge.finalizeDeposit.selector,
    address(0),
    Lib_PredeployAddresses.OVM_ETH,
    _from,
    _to,
    msg.value,
    _data
);

// Send calldata into L2
// slither-disable-next-line reentrancy-events
sendCrossDomainMessage(l2TokenBridge, _l2Gas, message);
```

If the `l2Gas` is underpaid, `finalizeDeposit` will fail and user funds will be lost.

### Recommendation
Given the potential risks of losing users funds, it is recommend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 3: M-13: Withdrawal transactions can get stuck if output root is reproposed

**Source**: Sherlock
**Protocol**: Optimism
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-optimism-judging/issues/53 

## Found by 
Allarious, Barichek, HE1M, cmichel, unforgiven

## Summary
Withdrawal transactions may never be executed if the L2 output root for the block, for which the withdrawal was proven, is challenged and reproposed.

## Vulnerability Detail

Withdrawal transactions can be reproven in the case that the output root for their previously proven output index has been updated.
This can happen if the L2 output root was removed by the challenger.
However, to circumvent malicious users from reproving messages all the time and resetting the withdrawal countdown, reproving can only be done on the same L2 block number (and if the output root changed).

If the challenger deletes the block with the withdrawal transaction and the proposer proposes a different block that does _not_ have the withdrawal transaction, the withdrawal transaction can never be finalized - even if a future block includes the legitimate withdrawal transaction again, as reproving it is bound to the old `provenWithdrawals[withdrawalHash].l2OutputIndex`.

## Impact
Legitimate withdrawal transactions will never be finalized if the proposed block was challenged and replaced with a different one not having the withdrawal transaction. As this call fails on the "lowest level", the `OptimismPortal`, these transactions also cannot be replayed or be issued refunds. In case the withdrawal transaction was a token bridge transfer,

*[Content truncated...]*

**Reference**: [View Original Finding](https://app.sherlock.xyz/audits/contests/38)

---

### Example 4: [M-19] `CLOCK_MODE()` will not work properly for Arbitrum or Optimism due to `block.number`

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Proof of Concept

According to [Arbitrum Docs](https://developer.offchainlabs.com/time), `block.number` returns the most recently synced L1 block number. Once per minute, the block number in the `Sequencer` is synced to the actual L1 block number. Using `block.number` as a clock can lead to inaccurate timing.

It also presents an issue for [Optimism](https://community.optimism.io/docs/developers/build/differences/#block-numbers-and-timestamps) because each transaction is it's own block.

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L152>

### Recommended Mitigation Steps

Use `block.timestamp` rather than `block.number`

### Assessed type

Timing

**[LybraFinance commented](https://github.com/code-423n4/2023-06-lybra-findings/issues/114#issuecomment-1639775144):**
 > The governance contract only exists on the Ethereum mainnet.

**[LybraFinance acknowledged](https://github.com/code-423n4/2023-06-lybra-findings/issues/114#issuecomment-1656708522)**

***

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

