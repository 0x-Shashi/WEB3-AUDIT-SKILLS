# Arbitrum Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 1 | 0 |

**Common Sources**: Sherlock, Quantstamp, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for arbitrum vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Underpaying Optimism l2gas may lead to loss of funds

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
The `OptimismBridgeFacet` uses Optimism’s bridge with user-provided `l2Gas`.

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

Optimism’s standard token bridge makes the cross-chain deposit by sending a cross-chain message to `L2Bridge`.

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
Given the potential risks of losing users’ funds, it is recommend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: M-4: No check for active Arbitrum Sequencer in WSTETH Oracle

**Source**: Sherlock
**Protocol**: Sentiment Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sentiment-judging/issues/3 

## Found by 
pashov, obront

## Summary

Chainlink recommends that all Optimistic L2 oracles consult the Sequencer Uptime Feed to ensure that the sequencer is live before trusting the data returned by the oracle. This check is implemented in ArbiChainlinkOracle.sol, but is skipped in WSTETHOracle.sol.

## Vulnerability Detail

If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 optimistic rollup contract. You can review Chainlink docs on [L2 Sequencer Uptime Feeds](https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds/) for more details on this.

As a result, users may be able to use the protocol while oracle feeds are stale. This could cause many problems, but as a simple example:
- A user has an account with 100 tokens, valued at 1 ETH each, and no borrows
- The Arbitrum sequencer goes down temporarily
- While it's down, the price of the token falls to 0.5 ETH each
- The current value of the user's account is 50 ETH, so they should be able to borrow a maximum of 200 ETH to keep account healthy (`(200 + 50) / 200 = 1.2`)
- Because of the stale price, the protocol lets them borrow 400 ETH (`(400 + 100) / 400 = 1.2`)

## Impact

If the Arbitrum sequencer goes down, the protocol will allow users to continue to operate at the previous (stale) rates.

## 

*[Content truncated...]*

---

### Example 3: [M-19] `CLOCK_MODE()` will not work properly for Arbitrum or Optimism due to `block.number`

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

### Example 4: M-13: Missing checks for whether Arbitrum Sequencer is active

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/142 

## Found by 
0xepley, Bauchibred, Bauer, Brenzee, J4de, ctf\_sec, deadrxsezzz, tallo, tsvetanovv
## Summary

Missing checks for whether Arbitrum Sequencer is active

## Vulnerability Detail

the onchain deployment context is changed, in prev contest the protocol only attemps to deploy the code to ethereum while in the current contest

the protocol intends to deploy to arbtrium as well!

Chainlink recommends that users using price oracles, check whether the Arbitrum sequencer is active

https://docs.chain.link/data-feeds#l2-sequencer-uptime-feeds

If the sequencer goes down, the index oracles may have stale prices, since L2-submitted transactions (i.e. by the aggregating oracles) will not be processed.

## Impact

Stale prices, e.g. if USDC were to de-peg while the sequencer is offline, stale price is used and can result in false liquidation or over-borrowing.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L76-L98

## Tool used

Manual Review

## Recommendation

Use sequencer oracle to determine whether the sequencer is offline or not, and don't allow orders to be executed while the sequencer is offline.

---

### Example 5: Mismatched `msg_value` Validation and Refund Logic in `op::create_master` Causes Underfunded Transactions

**Source**: Quantstamp
**Protocol**: XDAO
**Impact**: LOW

**Details**:

**Update**
The team fixed the issue as recommended. Addressed in: `3be95dd540da57f9f2a1e20dd8f514e6158e9029`.

**File(s) affected:**`contracts/factory.fc`

**Description:** In the `factory`’s `op::create_master`, the initial check requires `msg_value > service_fee + BASE_FEE * (6 + mint_messages_count)`, but the refund calculation deducts `service_fee + BASE_FEE * (8 + mint_messages_count)`. This discrepancy allows transactions that pass validation to fail later or refund less than expected, leading to user confusion and potential loss of funds.

**Exploit Scenario:**

1.   A user provides `msg_value` that meets the `(6 + mint_messages_count)` requirement but falls short of `(8 + mint_messages_count)`.
2.   Deployment proceeds past the initial check but later attempts to refund, leading to a revert or incorrect refund amount.
3.   The deployment unexpectedly fails or the user loses more TON than anticipated.

**Recommendation:** Align the validation threshold with the actual outgoing costs by updating the check to account for all `BASE_FEE` deductions (including minting flow and message sends). For example, require `msg_value > service_fee + BASE_FEE * (8 + mint_messages_count)`.

**Reference**: [View Original Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
