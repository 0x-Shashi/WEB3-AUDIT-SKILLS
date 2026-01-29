# Token Existence Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 0 | 0 |

**Common Sources**: Code4rena

---

## Detection Checklist

- [ ] Check for token existence vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-06] OperateProxy.callFunction() should check if the callee is a contract

**Source**: Code4rena
**Protocol**: Rolla
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/OperateProxy.sol#L10-L19


## Vulnerability details

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/Controller.sol#L550-L558

```solidity
    /// @notice Allows a sender/signer to make external calls to any other contract.
    /// @dev A separate OperateProxy contract is used to make the external calls so
    /// that the Controller, which holds funds and has special privileges in the Quant
    /// Protocol, is never the `msg.sender` in any of those external calls.
    /// @param _callee The address of the contract to be called.
    /// @param _data The calldata to be sent to the contract.
    function _call(address _callee, bytes memory _data) internal {
        IOperateProxy(operateProxy).callFunction(_callee, _data);
    }
```

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/OperateProxy.sol#L10-L19

```solidity
    function callFunction(address callee, bytes memory data) external override {
        require(
            callee != address(0),
            "OperateProxy: cannot make function calls to the zero address"
        );

        (bool success, bytes memory returnData) = address(callee).call(data);
        require(success, "OperateProxy: low-level call failed");
        emit FunctionCallExecut

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-rolla)

---

### Example 2: [M-17] The tokenURI method does not check if the NFT has been minted and returns data for the contract that may be a fake NFT

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161
https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePoolMetadata.sol#L17


## Vulnerability details

## Impact

- By invoking the [Factory.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161) method for a maliciously provided NFT id, the returned data may deceive potential users, as the method will return data for a non-existent NFT id that appears to be a genuine PrivatePool. This can lead to a poor user experience or financial loss for users.
- Violation of the [ERC721-Metadata part](https://eips.ethereum.org/EIPS/eip-721) standard

## Proof of Concept

- The [Factory.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161) and [PrivatePoolMetadata.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePoolMetadata.sol#L17) methods lack any requirements stating that the provided NFT id must be created. We can also see that in the standard implementation by [OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/cf86fd9962701396457e50ab0d6cc78aa29a5ebc/contracts/token/ERC721/ERC721.sol#L94), this check is present:
- [Throws if `_tokenId` is not a valid NFT](https://eips.ethereum.org/EIPS/ei

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 3: [M-03] Put option sellers can prevent exercise by specifying zero amounts, or non-existant tokens

**Source**: Code4rena
**Protocol**: Putty
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI, also found by 0xNineDec, exd0tpy, and zzzitron_

Put option buyers pay an option premium to the seller for the privilege of being able to 'put' assets to the seller and get the strike price for it rather than the current market price. If they're unable to perform the 'put', they've paid the premium for nothing, and essentially have had funds stolen from them.

### Proof of Concept

If the put option seller includes in `order.erc20Assets`, an amount of zero for any of the assets, or specifies an asset that doesn't currently have any code at its address, the put buyer will be unable to exercise the option, and will have paid the premium for nothing:

```solidity
File: contracts/src/PuttyV2.sol   #1

453               // transfer assets from exerciser to putty
454               _transferERC20sIn(order.erc20Assets, msg.sender);
```

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L453-L454>

The function reverts if any amount is equal to zero, or the asset doesn't exist:

```solidity
File: contracts/src/PuttyV2.sol   #2

593       function _transferERC20sIn(ERC20Asset[] memory assets, address from) internal {
594           for (uint256 i = 0; i < assets.length; i++) {
595               address token = assets[i].token;
596               uint256 tokenAmount = assets[i].tokenAmount;
597   
598               require(token.code.length > 0, "ERC20: Token is not contract");
599               requ

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-putty)

---

### Example 4: [M-25] Vault can be created for not-yet-existing ERC20 tokens, which allows attackers to set traps to steal NFTs from Borrowers

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

There is a subtle difference between the implementation of solmate’s SafeTransferLib and OZ’s SafeERC20: OZ’s SafeERC20 checks if the token is a contract or not, solmate’s SafeTransferLib does not.<br>
See: <https://github.com/Rari-Capital/solmate/blob/main/src/utils/SafeTransferLib.sol#L9><br>
Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.<br>
As a result, when the token’s address has no code, the transaction will just succeed with no error.<br>
This attack vector was made well-known by the qBridge hack back in Jan 2022.

In AstariaRouter, Vault, PublicVault, VaultImplementation, ClearingHouse, TransferProxy, and WithdrawProxy, the `safetransfer` and `safetransferfrom` don't check the existence of code at the token address. This is a known issue while using solmate’s libraries.

Hence this can lead to miscalculation of funds and also loss of funds , because if safetransfer() and safetransferfrom() are called on a token address that doesn’t have contract in it, it will always return success. Due to this protocol will think that funds has been transferred and successful , and records will be accordingly calculated, but in reality funds were never transferred.

So this will lead to miscalculation and loss of funds.

### Attack scenario (example):

It’s becoming popular for protocols to deploy their token across multiple networks and when they do so, a common practice is to deploy the token cont

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
