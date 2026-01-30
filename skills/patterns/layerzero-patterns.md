# LayerZero Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Trust Security, Code4rena, SigmaPrime

---

## Detection Checklist

- [ ] Check for layerzero vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03]  LayerZeroModule miscalculates gas, risking loss of assets

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[LayerZeroModule.sol#L431-L445](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/module/LayerZeroModule.sol#L431-L445)<br>

Holograph gets its cross chain messaging primitives through Layer Zero. To get pricing estimate, it uses the DstConfig price struct exposed in LZ's [RelayerV2](https://github.com/LayerZero-Labs/LayerZero/blob/main/contracts/RelayerV2.sol#L133).

The issue is that the important baseGas and gasPerByte configuration parameters, which are used to calculate a custom amount of gas for the destination LZ message, use the values that come from the *source* chain. This is in contrast to LZ which handles DstConfigs in a mapping keyed by chainID.  The encoded gas amount is described [here](https://layerzero.gitbook.io/docs/guides/advanced/relayer-adapter-parameters).

### Impact

The impact is that when those fields are different between chains, one of two things may happen:

1.  Less severe - we waste excess gas, which is refunded to the lzReceive() caller (Layer Zero)
2.  More severe - we underprice the delivery cost, causing lzReceive() to revert and the NFT stuck in limbo forever.

The code does not handle a failed lzReceive (differently to a failed executeJob). Therefore, no failure event is emitted and the NFT is screwed.

### Recommended Mitigation Steps

Firstly, make sure to use the target gas costs.<br>
Secondly, re-engineer lzReceive to be fault-proof, i.e. save some gas to emit result event.

**[gze

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: H-6: All ETH can be stolen during rebalancing for `mTOFTs` that hold native

**Source**: Sherlock
**Protocol**: Tapioca
**Impact**: HIGH

**Details**:

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

if (address(this).balance < _amount) revert ExceedsBalance();
        uint256 valueAmount = msg.value + _amount;
        routerETH.swapETH{value: valueAmount}(
            _dstChainId,
            payable(this),
            abi.encodePacked(connectedOFTs[_oft][_dstChainId].dstOft),
            _amount,
            _computeMinAmount(_amount, _slippage)
        );
```

The expected behaviour is ETH being received on the destination chain whereby `sgReceive` is called and ETH is deposited inside the `TOFTVault`.

```solidity
## mTOFT.sol

    function sgReceive(uint16, bytes memory, uint256, address, uint256 amountLD, bytes memory) external payable {
        if (msg.sender != _stargateRouter) revert mTOFT_NotAuthorized();

        if (erc20 == address(0)) {
            vault.depositNative{value: amountLD}();
        } else {
            IERC20(erc20).safeTransfer(address(vault), amountLD);
        }
    }
```

By taking a closer loo

*[Content truncated...]*

---

### Example 3: H-2: Malicious user can use an excessively large _toAddress in OFTCore#sendFrom to break layerZero communication

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/270 

## Found by 
0x52

## Summary

By default layerZero implements a blocking behavior, that is, that each message must be processed and succeed in the order that it was sent. In order to circumvent this behavior the receiver must implement their own try-catch pattern. If the try-catch pattern in the receiving app ever fails then it will revert to its blocking behavior. The _toAddress input to OFTCore#sendFrom is calldata of any arbitrary length. An attacker can abuse this and submit a send request with an excessively large _toAddress to break communication between network with different gas limits.

## Vulnerability Detail

    function sendFrom(address _from, uint16 _dstChainId, bytes calldata _toAddress, uint _amount, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) public payable virtual override {
        _send(_from, _dstChainId, _toAddress, _amount, _refundAddress, _zroPaymentAddress, _adapterParams);
    }

The _toAddress input to OFTCore#sendFrom is a bytes calldata of any arbitrary size. This can be used as follows to break communication between chains that have different block gas limits.

Example:
Let's say that an attacker wishes to permanently block the channel Arbitrum -> Optimism. Arbitrum has a massive gas block limit, much higher than Optimism's 20M block gas limit. The attacker would call sendFrom on the Arbitrum chain with the Optimism chain as 

*[Content truncated...]*

---

### Example 4: TRST-H-3 All LayerZero requests will fail, making the contracts are unfunctional

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: HIGH

**Details**:

**Description:**
When sending messages using the LayerZero architecture, native tokens must be supplied to 
cover the cost of delivering the message at the receiving chain. However, none of the Mozaic 
contracts account for it. The controller calls the bridge's `requestSnapshot()`, `requestSettle()`, 
`requestExecute()` without passing value. Vault calls `reportSnapshot()`, `reportSettle()` similarly. 
StargatePlugin calls the StargateRouter's swap() which also requires value. As a result, the 
contracts are completely unfunctional.

**Recommended Mitigation:**
Pass value in each of the functions above. Perform more meticulous testing with LayerZero 
endpoints. Contracts should support receiving base tokens with the `receive()` fallback, to pay 
for fees.

**Team response:**
Fixed

**Mitigation Review:**
The Controller and Vault now pass appropriate value in native tokens for messaging. The 
contracts can be topped-up with the `receive()` method.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 5: [H-06] Attacker can block LayerZero channel

**Source**: Code4rena
**Protocol**: Velodrome Finance
**Impact**: HIGH

**Details**:

_Submitted by Ruhum_

According to the LayerZero docs, the default behavior is that when a transaction on the destination application fails, the channel between the src and dst app is blocked. Before any new transactions can be executed, the failed transaction has to be retried until it succeeds.

See <https://layerzero.gitbook.io/docs/faq/messaging-properties#message-ordering> & <https://layerzero.gitbook.io/docs/guides/advanced/nonblockinglzapp>

So an attacker is able to initiate a transaction they know will fail to block the channel between FTM and Optimism. The RedemptionSender & Receiver won't be usable anymore.

### Proof of Concept

The RedemptionReceiver contract doesn't implement the non-blocking approach as seen here:<br>
<https://github.com/code-423n4/2022-05-velodrome/blob/main/contracts/contracts/redeem/RedemptionReceiver.sol#L72-L105>

An example implementation of the non-blocking approach by LayerZero:<br>
<https://github.com/LayerZero-Labs/solidity-examples/blob/main/contracts/lzApp/NonblockingLzApp.sol>

### Recommended Mitigation Steps

Use the non-blocking approach as described [here](https://layerzero.gitbook.io/docs/guides/advanced/nonblockinglzapp).

**[pooltypes (Velodrome) disagreed with severity](https://github.com/code-423n4/2022-05-velodrome-findings/issues/83)**

**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-05-velodrome-findings/issues/83#issuecomment-1169373375):**
 > @pooltypes Can anyone send a message or would

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-velodrome)

---

### Example 6: TRST-M-11 No slippage protection for cross-chain swaps in StargatePlugin

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
The StargatePlugin calls StargateRouter's swap() function to do a cross-chain swap.
```solidity 
            // Swaps
            IStargateRouter(_router).swap(_dstChainId, _srcPoolId, _dstPoolId, 
                  payable(address(this)), _amountLD, 0, IStargateRouter.lzTxObj(0, 0, "0x"), abi.encodePacked(_to), bytes(""));
``` 
It will pass 0 as the minimum amount of tokens to receive. This pattern is vulnerable to 
sandwich attacks, where the fee or conversion rate is pumped to make the user receive hardly 
any tokens. In Layer Zero, the equilibrium fee can be manipulated to force such losses.

**Recommended mitigation:**
Calculate accepted slippage off-chain, and pass it to the `_swapRemote()` function for 
validation.

**Team response:**
Fixed.

**Mitigation review:**
Affected function has been removed

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 7: Check on Stargate Router Address Could Revert

**Source**: SigmaPrime
**Protocol**: Sushi
**Impact**: MEDIUM

**Details**:

## Description

The development team pointed out that, if the call by Stargate to `sgReceive()` were to revert, the tokens transferred from Stargate would be left in the SushiXSwap contract on the destination chain, where they could be transferred away freely by any user.

One possible condition under which this transaction could revert is if the Stargate router is redeployed, perhaps as part of an upgrade. The `require` on line [80] would then cause the transaction to revert, resulting in a loss of funds. It is difficult to estimate the likelihood of this issue as it is outside the scope of this review to investigate Stargates likelihood of redeploying their router. However, whatever their stated policy, there could still be a redeployment and so a risk remains that could result in a loss of user funds.

## Recommendations

One possible solution is to remove the `require` on line [80]. This is discussed in more detail in SXS-13. Alternatively, monitor Stargate carefully for any chance that any of their router addresses could change and redeploy this contract if that occurs.

**Reference**: [View Original Finding](https://github.com/sigp/public-audits/blob/master/sushi/sushi-swap-stable-pool/review.pdf)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

