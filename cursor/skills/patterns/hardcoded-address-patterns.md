# Hardcoded Address Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for hardcoded address vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Hardcode bridge addresses via immutable

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Severity: High Risk

**Context:** 
- OmniBridgeFacet.sol#L34-L106
- AxelarFacet.sol#L18-L23

**Description:**  
Most bridge facets call bridge contracts where the bridge address has been supplied as a parameter. This is inherently unsafe because any address could be called. Luckily, the called function signature is hardcoded, which reduces risk. However, it is still possible to call an unexpected function due to the potential collisions of function signatures. Users might be tricked into signing a transaction for the LiFi protocol that calls unexpected contracts. 

One exception is the AxelarFacet which sets the bridge addresses in `initAxelar()`, however this is relatively expensive as it requires an SLOAD to retrieve the bridge addresses. 

*Note: also see "Facets approve arbitrary addresses for ERC20 tokens".*

```solidity
function startBridgeTokensViaOmniBridge(..., BridgeData calldata _bridgeData) ... {
    ...
    _startBridge(_lifiData, _bridgeData, _bridgeData.amount, false);
}

function _startBridge(..., BridgeData calldata _bridgeData, ...) ... {
    IOmniBridge bridge = IOmniBridge(_bridgeData.bridge);
    if (LibAsset.isNativeAsset(_bridgeData.assetId)) {
        bridge.wrapAndRelayTokens{ ... }(...);
    } else {
        ...
        bridge.relayTokens(...);
    }
    ...
}

contract AxelarFacet {
    function initAxelar(address _gateway, address _gasReceiver) external {
        ...
        s.gateway = IAxelarGateway(_gateway);
        s.gasReceiver = IAxelarGa

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: Hardcode or whitelist the Axelar destinationAddress

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
AxelarFacet.sol#L30-L89

## Description
The functions `executeCallViaAxelar()` and `executeCallWithTokenViaAxelar()` call a `destinationAddress` on the `destinationChain`. This `destinationAddress` needs to have specific Axelar functions (`_execute()` and `_executeWithTokento()`) to be able to receive the calls. This is implemented in the Executor. If these functions don’t exist at the `destinationAddress`, the transferred tokens will be lost.

```solidity
/// @param destinationAddress the address of the LiFi contract on the destinationChain
function executeCallViaAxelar(..., string memory destinationAddress, ...) ... {
    ...
    s.gateway.callContract(destinationChain, destinationAddress, payload);
}
```

**Note:** The comment "the address of the LiFi contract" isn’t clear; it could either be the LiFi Diamond or the Executor.

## Recommendation
Hardcode or whitelist the `destinationAddress`. Doublecheck the `@param` comment for `destinationAddress` (for both functions).

## LiFi
We acknowledge the risk and recommend all users utilize our API in order to pass correct data and enter invalid contract addresses at their own risk.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 3: [M-05] `SWAP_ROUTER` in `AutoPxGmx.sol` is hardcoded and not compatible on Avalanche

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L18>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L96>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L268>

### Impact

I want to quote from the doc:

```solidity
- Does it use a side-chain? Yes
- If yes, is the sidechain evm-compatible? Yes, Avalanche
```

This shows that the projects is intended to support Avalanche side-chain.

`SWAP_ROUTER` in the AutoPxGmx.sol is hardcoded as:

```solidity
IV3SwapRouter public constant SWAP_ROUTER =
	IV3SwapRouter(0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45);
```

But this address is the Uniswap V3 router address in arbitrium, but it is a EOA address in Avalanche,

<https://snowtrace.io/address/0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45>

Then the AutoPxGmx.sol is not working in Avalanche.

```solidity
gmxAmountOut = SWAP_ROUTER.exactInputSingle(
	IV3SwapRouter.ExactInputSingleParams({
		tokenIn: address(gmxBaseReward),
		tokenOut: address(gmx),
		fee: fee,
		recipient: address(this),
		amountIn: gmxBaseRewardAmountIn,
		amountOutMinimum: amountOutMinimum,
		sqrtPriceLimitX96: sqrtPriceLimitX96
	})
);
```

### Proof of Concept

The code below reverts because the EOA address on Avalanche does not have exactInputSingle method in compound method.

```solidity
g

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 4: M-6: Hardcoded divider address in RollerUtils is incorrect and will brick autoroller

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/19 

## Found by 
0x52

## Summary

RollerUtils uses a hard-coded constant for the Divider. This address is incorrect and will cause a revert when trying to call AutoRoller#cooldown. If the adapter is combineRestricted then LPs could potentially be unable to withdraw or eject.

## Vulnerability Detail

    address internal constant DIVIDER = 0x09B10E45A912BcD4E80a8A3119f0cfCcad1e1f12;

RollerUtils uses a hardcoded constant DIVIDER to store the Divider address. There are two issues with this. The most pertinent issue is that the current address used is not the correct mainnet address. The second is that if the divider is upgraded, changing the address of the RollerUtils may be forgotten.

        (, uint48 prevIssuance, , , , , uint256 iscale, uint256 mscale, ) = DividerLike(DIVIDER).series(adapter, prevMaturity);

With an incorrect address the divider#series call will revert causing RollerUtils#getNewTargetedRate to revert, which is called in AutoRoller#cooldown. The result is that the AutoRoller cycle can never be completed. LP will be forced to either withdraw or eject to remove their liquidity. Withdraw only works to a certain point because the AutoRoller tries to keep the target ratio. After which the eject would be the only way for LPs to withdraw. During eject the AutoRoller attempts to combine the PT and YT. If the adapter is also combineRestricted then there is no longer any way for the LPs to with

*[Content truncated...]*

---

### Example 5: M-4: Hardcoded divider address in RollerUtils is incorrect and will brick autoroller

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/19 

## Found by 
0x52

## Summary

RollerUtils uses a hard-coded constant for the Divider. This address is incorrect and will cause a revert when trying to call AutoRoller#cooldown. If the adapter is combineRestricted then LPs could potentially be unable to withdraw or eject.

## Vulnerability Detail

    address internal constant DIVIDER = 0x09B10E45A912BcD4E80a8A3119f0cfCcad1e1f12;

RollerUtils uses a hardcoded constant DIVIDER to store the Divider address. There are two issues with this. The most pertinent issue is that the current address used is not the correct mainnet address. The second is that if the divider is upgraded, changing the address of the RollerUtils may be forgotten.

        (, uint48 prevIssuance, , , , , uint256 iscale, uint256 mscale, ) = DividerLike(DIVIDER).series(adapter, prevMaturity);

With an incorrect address the divider#series call will revert causing RollerUtils#getNewTargetedRate to revert, which is called in AutoRoller#cooldown. The result is that the AutoRoller cycle can never be completed. LP will be forced to either withdraw or eject to remove their liquidity. Withdraw only works to a certain point because the AutoRoller tries to keep the target ratio. After which the eject would be the only way for LPs to withdraw. During eject the AutoRoller attempts to combine the PT and YT. If the adapter is also combineRestricted then there is no longer any way for the LPs to with

*[Content truncated...]*

---

### Example 6: M-21: Deployments.sol uses the wrong address for UNIV2 router which causes all Uniswap V2 calls to fail

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/32 

## Found by 
0x52

## Summary

Deployments.sol accidentally uses the Uniswap V3 router address for UNIV2_ROUTER which causes all Uniswap V2 calls to fail

## Vulnerability Detail

    IUniV2Router2 internal constant UNIV2_ROUTER = IUniV2Router2(0xE592427A0AEce92De3Edee1F18E0157C05861564);

The constant UNIV2_ROUTER contains the address for the Uniswap V3 router, which doesn't contain the "swapExactTokensForTokens" or "swapTokensForExactTokens" methods. As a result, all calls made to Uniswap V2 will revert.

## Impact

Uniswap V2 is totally unusable

## Code Snippet

[Deployments.sol#L25](https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/global/Deployments.sol#L25)

## Tool used

Manual Review

## Recommendation

Change UNIV2_ROUTER to the address of the V2 router:

    IUniV2Router2 internal constant UNIV2_ROUTER = IUniV2Router2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

## Discussion

**jeffywu**

@weitianjie2000 I believe this has been fixed subsequently

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
