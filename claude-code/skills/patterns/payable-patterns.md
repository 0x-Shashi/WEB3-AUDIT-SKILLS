# Payable Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 4 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for payable vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Cross-chain messaging via Multichain protocol will fail

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Assessment

## Severity: 
**High Risk**

## Context: 
`BaseMultichain.sol#L39-L47`

## Description: 
Multichain v6 is supported by Connext for cross-chain messaging. The `_sendMessage` function of `BaseMultichain.sol` relies on Multichain's anyCall for cross-chain messaging.

Per the Anycall V6 documentation, a gas fee for transaction execution needs to be paid either on the source or destination chain when an anyCall is called. However, the anyCall is called without consideration of the gas fee within the connectors, and thus the anyCall will always fail. Since Multichain's hub and spoke connectors are unable to send messages, cross-chain messaging using Multichain within Connext will not work.

```solidity
function _sendMessage(address _amb, bytes memory _data) internal {
    Multichain(_amb).anyCall(
        _amb, // Same address on every chain, using AMB as it is immutable
        _data,
        address(0), // fallback address on origin chain
        MIRROR_CHAIN_ID,
        0; // fee paid on origin chain
    );
}
```

Additionally, for the payment of the execution gas fee, a project can choose to implement either of the following methods:
- Pay on the source chain by depositing the gas fee to the caller contracts.
- Pay on the destination chain by depositing the gas fee to Multichain's anyCall contract at the destination chain.

If Connext decides to pay the gas fee on the source chain, they would need to deposit some ETH to the connector contracts. However, 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 2: Messages destined for ZkSync cannot be processed

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
ZkSyncHubConnector.sol#L49-L72

## Description
For ZkSync chain, L2 to L1 communication is free, but L1 to L2 communication requires a certain amount of ETH to be supplied to cover the base cost of the transaction (including the `_l2Value`) + layer 2 operator tip.

The `sendMessage` function of `ZkSyncHubConnector.sol` relies on the `IZkSync(AMB).requestL2Transaction` function to send messages from L1 to L2. However, the `requestL2Transaction` call will always fail because no ETH is supplied to the transaction (`msg.value` is zero).

As a result, ZkSync's hub connector on Ethereum cannot forward the latest aggregated Merkle root to ZkSync's spoke connector on the ZkSync chain. Thus, any message destined for the ZkSync chain cannot be processed since incoming messages cannot be proven without the latest aggregated Merkle root.

```solidity
function _sendMessage(bytes memory _data) internal override {
    // Should always be dispatching the aggregate root
    require(_data.length == 32, "!length");
    
    // Get the calldata
    bytes memory _calldata = abi.encodeWithSelector(Connector.processMessage.selector, _data);
    
    // Dispatch message
    // [v2-docs.zksync.io/dev/developer-guides/Bridging/l1-l2.html#structure](https://v2-docs.zksync.io/dev/developer-guides/Bridging/l1-l2.html#structure)
    // calling L2 smart contract from L1 Example contract
    // note: msg.value must be passed in and can be retrieved from the AMB view functi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 3: Executor reverts on receiving native tokens from BridgeFacet

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- **File:** Executor.sol 
- **Line:** BridgeFacet.sol#L696, AssetLogic.sol#L127-L151

## Description
When doing an external call in `execute()`, the `BridgeFacet` provides liquidity into the `Executor` contract before calling `Executor.execute`. The `BridgeFacet` transfers a native token when an `address(wrapper)` is provided. However, the `Executor` does not have a fallback or receive function. Hence, the transaction will revert when the `BridgeFacet` tries to send the native token to the `Executor` contract.

```solidity
function _handleExecuteTransaction(
    ...
    AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
    (bool success, bytes memory returnData) = s.executor.execute(...);
    ...
}
```

```solidity
function transferAssetFromContract(...) {
    ...
    if (_assetId == address(s.wrapper)) {
        // If dealing with wrapped assets, make sure they are properly unwrapped
        // before sending from contract
        s.wrapper.withdraw(_amount);
        Address.sendValue(payable(_to), _amount);
    } else {
        ...
    }
}
```

## Recommendation
It is recommended to add a receive function in the `Executor` contract:

```solidity
receive() payable external {
    require(msg.sender == connext);
}
```

Alternatively, unwrap the native asset and send it along with the call to the executor.

- **Connext:** Ether sent along with the call. Solved in PR 1532.
- **Spearbit:** Verified.
- **Connext:** Alter

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: _handleExecuteTransaction() doesn’t handle native assets correctly

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

**Severity:** High Risk  
**Context:** BridgeFacet.sol#L644-L718, Executor.sol#L142-L243  

**Description:**  
The function `_handleExecuteTransaction()` sends any native tokens to the executor contract first, and then calls `s.executor.execute()`. This means that within that function, `msg.value` will always be 0. As a result, the associated logic that uses `msg.value` doesn’t work as expected, leading to incorrect handling of native assets.

**Note:**  
Also see issue "Executor reverts on receiving native tokens from BridgeFacet".

```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction(...) {
        ...
        AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
        (bool success, bytes memory returnData) = s.executor.execute(...); // no native tokens sent
    }
}
```

```solidity
contract Executor is IExecutor {
    function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
        ...
        if (isNative && msg.value != _args.amount) { // msg.value is always 0
            ...
        }
    }
}
```

**Recommendation:**  
Change the code of `execute()` to handle previously sent native assets. Alternatively, send the native assets along with the call to `execute()`.

**Connext:** Solved in PR 1532.  
**Spearbit:** Verified.  
**Connext:** Alternate approach: removed native asset handling. Implemented in PR 31.  
**Spearbit:** Verified

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 5: WormholeFacet doesn’t send native token

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`WormholeFacet.sol#L36-L103`

## Description
The functions of `WormholeFacet` allow sending the native token; however, they don’t actually send it across the bridge, causing the native token to stay stuck in the LiFi Diamond and get lost for the sender.

```solidity
contract WormholeFacet is ILiFi, ReentrancyGuard, Swapper {
    function startBridgeTokensViaWormhole(... ) ... payable ... { // is payable
        LibAsset.depositAsset(_wormholeData.token, _wormholeData.amount); // allows native token
        _startBridge(_wormholeData);
        ...
    }

    function _startBridge(WormholeData memory _wormholeData) private {
        ...
        LibAsset.maxApproveERC20(...); // geared towards ERC20, also works when `msg.value `is set
        IWormholeRouter(_wormholeData.wormholeRouter).transferTokens(...); // no { value : .... }
    }
}
```

## Recommendation
Remove the `payable` keyword and/or check `msg.value == 0`. Alternatively, support sending the native token. This can be done via `wrapAndTransferETH()` of the wormhole bridge.

**Note:** also see issue "Consider using wrapped native token"

## LiFi
Fixed with PR #76.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 6: [H-01] SpeedBumpPriceGate: Excess ether did not return to the user

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: HIGH

**Details**:

_Submitted by cccz, also found by 0x52, 0xYamiDancho, csanuragjain, GimelSec, gzeon, hickuphh3, horsefacts, hyh, IllIllI, kenzo, leastwood, PPrieditis, reassor, unforgiven, WatchPug, and danb_

The `passThruGate` function of the `SpeedBumpPriceGate` contract is used to charge NFT purchase fees.
Since the price of NFT will change due to the previous purchase, users are likely to send more ether than the actual purchase price in order to ensure that they can purchase NFT. However, the passThruGate function did not return the excess ether, which would cause asset loss to the user.
Consider the following scenario:

1.  An NFT is sold for 0.15 eth
2.  User A believes that the value of the NFT is acceptable within 0.3 eth, considering that someone may buy the NFT before him, so user A transfers 0.3 eth to buy the NFT
3.  When user A's transaction is executed, the price of the NFT is 0.15 eth, but since the contract does not return excess eth, user A actually spends 0.3 eth.

### Proof of Concept

<https://github.com/code-423n4/2022-05-factorydao/blob/e22a562c01c533b8765229387894cc0cb9bed116/contracts/SpeedBumpPriceGate.sol#L65-L82>


### Recommended Mitigation Steps

    -   function passThruGate(uint index, address) override external payable {
    +  function passThruGate(uint index, address payer) override external payable {
            uint price = getCost(index);
            require(msg.value >= price, 'Please send more ETH');

            // bump up the price
            Gate 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 7: M-5: The ````Stream```` contract is designed to receive ETH but not implement function for withdrawal

**Source**: Sherlock
**Protocol**: NounsDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-nounsdao-judging/issues/47 

## Found by 
KingNFT, rvierdiiev

## Summary
The ````Stream```` contract instances can receive ETH but can not withdraw, ETH occasionally sent by users will be stuck in those contracts.

## Vulnerability Detail
Shown as the test case, it can receive ETH normally.
```solidity
contract StreamReceiveETHTest is StreamTest {
    function setUp() public override {
        super.setUp();
    }

    function test_receiveETH() public {
        s = Stream(
            factory.createStream(
                payer, recipient, STREAM_AMOUNT, address(token), startTime, stopTime
            )
        );

        vm.deal(payer, 10 ether);
        vm.prank(payer);
        (bool success, ) = address(s).call{value: 1 ether}("");
        assertEq(success, true);
        assertEq(address(s).balance, 1 ether);
    }
}
```

Result
```solidity
Running 1 test for test/Stream.t.sol:StreamReceiveETHTest
[PASS] test_receiveETH() (gas: 167691)
Test result: ok. 1 passed; 0 failed; finished in 1.25ms
```

## Impact
See Summary

## Code Snippet
https://github.com/Vectorized/solady/blob/db4857b4a1e17ad035668b588b41a1c90139b99d/src/utils/LibClone.sol#L193-L204

## Tool used

Manual Review

## Recommendation
Add a ````rescueETH()```` function which is similar with the existing ````rescueERC20()````

## Discussion

**eladmallel**

Fix PR: https://github.com/nounsDAO/streamer/pull/10

---

### Example 8: [M-01] It is not possible to execute actions that require ETH (or other protocol token)

**Source**: Code4rena
**Protocol**: Llama
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-llama/blob/main/src/LlamaCore.sol#L334> <br><https://github.com/code-423n4/2023-06-llama/blob/main/src/LlamaExecutor.sol#L29>

Actions can have value attached to them. That means when action is being executed, a certain amount of ETH (or other protocol token) need to be sent by the caller with the contract call. This is why `LlamaCore.executeAction` is payable.

```solidity
  function executeAction(ActionInfo calldata actionInfo) external payable {
```

However, when LlamaCore executes the action it doesn't pass value to the downstream call to LlamaExecutor

```solidity
    // Execute action.
    (bool success, bytes memory result) =
      executor.execute(actionInfo.target, actionInfo.value, action.isScript, actionInfo.data);
```

LlamaExecutor's `execute` is not payable even though it does try to pass value to the downstream call

```solidity
  function execute(address target, uint256 value, bool isScript, bytes calldata data)
    external
    returns (bool success, bytes memory result)
  {
    if (msg.sender != LLAMA_CORE) revert OnlyLlamaCore();
    (success, result) = isScript ? target.delegatecall(data) : target.call{value: value}(data);
  }
```

This will of course revert because LlamaExecutor is not expected to have any ETH balance.

### Proof of Concept

To reproduce the issue based on the existing tests we can do the following changes:

```diff
diff --git a/test/LlamaCore.t.sol b/test/LlamaCore.t.sol
index 8135c93..6964846 1006

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-llama)

---

### Example 9: M-1: Buypunk function of Cryptopunks in ERC721Pool is used incorrectly

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/163 

## Found by 
Chinmay

## Summary

The buyPunk function here seems to be for transferring NFT from sender to pool, but the original contract has a payable function that uses msg.value checks 

## Vulnerability Detail

This seems to be a weird implementation for transferring the NFT. Furthermore, the function is payable but the interface by AJNA doesn't mark it as payable. 

This function checks for the msg.value in the original Cryptopunks contract. Calling it from the ERC721Pool will always revert because the msg.value is not being sent with the call at L#577. Thus, a cryptopunk NFT will never be able to be used as the collateral in this NFT pool. 

## Impact

## Code Snippet

https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577

## Tool used

Manual Review

## Recommendation

Update the interface with the payable keyword and send msg.value along with the buyPunk call so that it passes checks at the target contract

## Discussion

**grandizzy**

we're not going to support non standard NFT anymore, just wrapped versions

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

