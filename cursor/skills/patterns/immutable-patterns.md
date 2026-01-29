# Immutable Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for immutable vulnerabilities in all external functions
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

### Example 2: [M-09] Avoidable misconfiguration could lead to INVEscrow contract not minting xINV tokens

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L281-L283


## Vulnerability details

## Impact
If a user creates a market with the **INVEscrow** implementation as **escrowImplementation** and false as **callOnDepositCallback**, the deposits made by users in the escrow (through the market) would not mint **xINV** tokens for them. As **callOnDepositCallback** is an immutable variable set in the constructor, this mistake would make the market a failure and the user should deploy a new one (even worse, if the error is detected after any user has deposited funds, some sort of migration of funds should be needed).

## Proof of Concept
Both **escrowImplementation** and **callOnDepositCallback** are immutable:
```javascript
...
address public immutable escrowImplementation;
...
bool immutable callOnDepositCallback;
...
```
and its value is set at creation:
```javascript
constructor (
        address _gov,
        address _lender,
        address _pauseGuardian,
        address _escrowImplementation,
        IDolaBorrowingRights _dbr,
        IERC20 _collateral,
        IOracle _oracle,
        uint _collateralFactorBps,
        uint _replenishmentIncentiveBps,
        uint _liquidationIncentiveBps,
        bool _callOnDepositCallback
    ) {
	...
	escrowImplementation = _escrowImplementation;
	...
	callOnDepositCallback = _callOnDepositCallback;
	...
 }
```
When the user deposits collateral, if **callOnDepositCallback** is true, there is a ca

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 3: M-6: Hardcoded divider address in RollerUtils is incorrect and will brick autoroller

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

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
