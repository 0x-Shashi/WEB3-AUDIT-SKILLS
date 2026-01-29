# EIP-712 Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Codehawks, Spearbit

---

## Detection Checklist

- [ ] Check for eip-712 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Untyped data signing

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by Lambda, also found by 0x1f8b, 0x52, horsefacts, vlad&#95;bochok, and wastewa_

[Community.sol#L175](https://github.com/code-423n4/2022-08-rigor/blob/e35f5f61be9ff4b8dc5153e313419ac42964d1fd/contracts/Community.sol#L175)<br>
[Community.sol#L213](https://github.com/code-423n4/2022-08-rigor/blob/e35f5f61be9ff4b8dc5153e313419ac42964d1fd/contracts/Community.sol#L213)<br>
[Community.sol#L530](https://github.com/code-423n4/2022-08-rigor/blob/e35f5f61be9ff4b8dc5153e313419ac42964d1fd/contracts/Community.sol#L530)<br>
[Disputes.sol#L91](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Disputes.sol#L91)<br>
[Project.sol#L142](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L142)<br>
[Project.sol#L167](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L167)<br>
[Project.sol#L235](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L235)<br>
[Project.sol#L286](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L286)<br>
[Project.sol#L346](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L346)<br>
[Project.sol#L402](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 2: The digest inSeaDrop.mintSigned is not calculated correctly according to EIP-712

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
SeaDrop.sol#L308

## Description
The `mintParams` in the calculation of the digest in `mintSigned` is of struct type, so we would need to calculate and use its `hashStruct`, not the actual variable on its own.

## Recommendation
According to EIP-712, the correct digest would be:

```solidity
// Include this typehash at the top of the contract
bytes32 internal constant _MINT_PARAMS_TYPEHASH = keccak256(
    "MintParams("
    "uint256 mintPrice,"
    "uint256 maxTotalMintableByWallet,"
    "uint256 startTime,"
    "uint256 endTime,"
    "uint256 dropStageIndex,"
    "uint256 maxTokenSupplyForStage,"
    "uint256 feeBps,"
    "bool restrictFeeRecipients"
    ")"
);
```

...

```solidity
// hashStruct for mintParams
bytes32 mintParamsHashStruct = keccak256(
    abi.encode(
        _MINT_PARAMS_TYPEHASH,
        mintParams.mintPrice,
        mintParams.maxTotalMintableByWallet,
        mintParams.startTime,
        mintParams.endTime,
        mintParams.dropStageIndex,
        mintParams.maxTokenSupplyForStage,
        mintParams.feeBps,
        mintParams.restrictFeeRecipients
    )
);
```

```solidity
bytes32 digest = keccak256(
    abi.encodePacked(
        // EIP-191: `0x19 ` as set prefix, `0x01 ` as version byte
        bytes2(0x1901),
        _domainSeparator(),
        keccak256(
            abi.encode(
                _SIGNED_MINT_TYPEHASH,
                nftContract,
                minter,
                feeRecipient,
             

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 3: The `digest` calculation in `deployProxyAndDistributeBySignature` does not follow EIP-712 specification

**Source**: Codehawks
**Protocol**: Sparkn
**Impact**: MEDIUM

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159">https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159</a>


## Summary

The calculation of the `digest` done in [`ProxyFactory.deployProxyAndDistributeBySignature()`](https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159) does not follow the [EIP-712 specification](https://eips.ethereum.org/EIPS/eip-712). It is missing the function's corresponding `typeHash`, as well as the `hashStruct` calculation of the `data` signature parameter, which are both defined in the EIP.

Not following the EIP specification will end up in unexpected integration failures with EIP712-compliant wallets or tooling that perform the encoding in the appropriate way.  

## Vulnerability Details

In [`ProxyFactory.deployProxyAndDistributeBySignature()`](https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159), the `digest` is calculated as follows:

```solidity
bytes32 digest = _hashTypedDataV4(
    keccak256(
        abi.encode(contestId, data)
    )
);
```
The [EIP-712 specification](https://eips.ethereum.org/EIPS/eip-712#specification) defines the encoding of a message as:

```
"\x19\x01" ‖ domainSeparator ‖ hashStruct(message)
```
In the current impl

*[Content truncated...]*

---

### Example 4: [M-11] Protocol does not implement EIP712 correctly on multiple occasions

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L151-L151> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L373-L375> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L384-L386> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L232-L238> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L636>

Being not EIP712 compliant can lead to issues with integrators and possibly DOS.

### Problem 1

The implementation of the hook hash ([here](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L151C56-L151C56)) is done incorrectly. `hook.extraData` is of type `bytes` which according to EIP712 it is referred to as a `dynamic type`. Dynamic types must be first hashed with `keccak256` to become one 32-byte word before being encoded and hashed together with the typeHash and the other values.

### Mitigation to Problem 1:

```diff
function _deriveHookHash(Hook memory hook) internal view returns (bytes32) {
  // Derive and return the hook as specified by EIP-712.
    return
        keccak256(
-           abi.encode(_HOOK_TYPEHASH, hook.target, hook.itemIndex, hook.extraData)
+           abi.encode(_HOOK_TYPEHAS

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 5: [M-07] EIP-712 typehash is incorrect for several functions in `MetaTxLib`

**Source**: Code4rena
**Protocol**: Lens Protocol
**Impact**: MEDIUM

**Details**:

In `LensHub.sol`, the second parameter of `setProfileMetadataURIWithSig()` is declared as `metadataURI`:

[LensHub.sol#L119-L123](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/LensHub.sol#L119-L123)

```solidity
    function setProfileMetadataURIWithSig(
        uint256 profileId,
        string calldata metadataURI,
        Types.EIP712Signature calldata signature
    ) external override whenNotPaused onlyProfileOwnerOrDelegatedExecutor(signature.signer, profileId) {
```

However, its [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typehash stores the parameter as `metadata` instead:

[Typehash.sol#L33](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/libraries/constants/Typehash.sol#L33)

```solidity
bytes32 constant SET_PROFILE_METADATA_URI = keccak256('SetProfileMetadataURI(uint256 profileId,string metadata,uint256 nonce,uint256 deadline)');
```

The `PostParams` struct (which is used for [`postWithSig()`](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/LensHub.sol#L235-L244)) has `address[] actionModules` and `bytes[] actionModulesInitDatas` as its third and fourth fields:

[Types.sol#L178-L185](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/libraries/constants/Types.sol#L178-L185)

```solidity
    struct PostParams {
        uint256 profileId;
        string contentURI;
        address[] actionModules;
        bytes[] actionModulesInitDatas;
        address referenceModule;
        bytes referenceModuleInit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-lens)

---

### Example 6: M-1: Incorrect encoding of bytes for EIP712 digest in `TitleGraph` causes signatures generated by common EIP712 tools to be unusable

**Source**: Sherlock
**Protocol**: TITLES Publishing Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-04-titles-judging/issues/74 

## Found by 
0x73696d616f, T1MOH, ZanyBonzy, ast3ros, fugazzi, mt030d
## Summary

The signature in `﻿TitleGraph.acknowledgeEdge()` and ﻿`TitleGraph.unacknowledgeEdge()` is generated based on a digest computed from ﻿`edgeId` and ﻿`data`. However, the ﻿`data` bytes argument is not correctly encoded according to the EIP712 specification. Consequently, a signature generated using common EIP712 tools would not pass validation in ﻿`TitleGraph.checkSignature()`.

## Vulnerability Detail
According to [EIP712](https://eips.ethereum.org/EIPS/eip-712#definition-of-encodedata):
> The dynamic values bytes and string are encoded as a keccak256 hash of their contents.

```solidity
    modifier checkSignature(bytes32 edgeId, bytes calldata data, bytes calldata signature) {
        bytes32 digest = _hashTypedData(keccak256(abi.encode(ACK_TYPEHASH, edgeId, data)));
        ...
    }
```
However, the `checkSignature()` modifier in the `TitlesGraph` contract reconstructs the digest by encoding the ﻿data bytes argument without first applying keccak256 hashing.
As a result, a signature generated using common EIP712 tools (e.g. using the `signTypedData` function from `ethers.js`) would not pass validation in ﻿`TitleGraph.checkSignature()`.

### POC
1. EIP712 signature computed by using ethers.js
```js
// main.js
const { ethers } = require("ethers");

async function main() {
    const pk = "0xac0974bec39a17e36ba4a6b4d238ff9

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
