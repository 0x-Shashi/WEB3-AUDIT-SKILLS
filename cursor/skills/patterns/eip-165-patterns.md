# EIP-165 Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 2 | 3 | 0 |

**Common Sources**: Code4rena, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for eip-165 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-15] `HolographERC721.safeTransferFrom` not compliant with EIP-721

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L366](https://github.com/code-423n4/2022-10-holograph/blob/24bc4d8dfeb6e4328d2c6291d20553b1d3eff00b/src/enforcer/HolographERC721.sol#L366)<br>

According to EIP-721, we have the following for `safeTransferFrom`:

```solidity
///  (...) When transfer is complete, this function
///  checks if `_to` is a smart contract (code size > 0). If so, it calls
///  `onERC721Received` on `_to` and throws if the return value is not
///  `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
```

According to the specification, the function must therefore always call `onERC721Received`, not only when it has determined via ERC-165 that the contract provides this function. Note that in the EIP, the provided interface for `ERC721TokenReceiver` does not mention ERC-165. For the token itself, we have: `interface ERC721 /* is ERC165 */ {`<br>
However, for the receiver, the provided interface there is just: `interface ERC721TokenReceiver {`<br>
This leads to failed transfers when they should not fail, because many receivers will just implement the `onERC721Received` function (which is sufficient according to the EIP), and not `supportsInterface` for ERC-165 support.

### Proof Of Concept

Let's say a receiver just implements the `IERC721Receiver` from OpenZeppelin: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/IERC721Receiver.sol><br>
Like the provided interface in the EIP itself, this interface does not derive from

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: [M-03] LSP8 and LSP9's `ERC-165` interface ID differs from their specification

**Source**: Code4rena
**Protocol**: LUKSO
**Impact**: MEDIUM

**Details**:

According to [LSP7's specification](https://github.com/lukso-network/LIPs/blob/main/LSPs/LSP-7-DigitalAsset.md#specification), the [ERC-165](https://eips.ethereum.org/EIPS/eip-165) interface ID for LSP7 token contracts should be `0x5fcaac27`:

> ERC165 interface id: `0x5fcaac27`

However, `_INTERFACEID_LSP7` has a different value in the code:

[LSP7Constants.sol#L4-L5](https://github.com/code-423n4/2023-06-lukso/blob/main/contracts/LSP7DigitalAsset/LSP7Constants.sol#L4-L5)

```solidity
// --- ERC165 interface ids
bytes4 constant _INTERFACEID_LSP7 = 0xda1f85e4;
```

Similarly, LSP8's interface ID should be `0x49399145` according to [LSP8's specification](https://github.com/lukso-network/LIPs/blob/main/LSPs/LSP-8-IdentifiableDigitalAsset.md#specification):

> ERC165 interface id: `0x49399145`

However, `_INTERFACEID_LSP8` has a different value in the code:

[LSP8Constants.sol#L4-L5](https://github.com/code-423n4/2023-06-lukso/blob/main/contracts/LSP8IdentifiableDigitalAsset/LSP8Constants.sol#L4-L5)

```solidity
// --- ERC165 interface ids
bytes4 constant _INTERFACEID_LSP8 = 0x622e7a01;
```

These constants are used in `supportsInterface()` for the `LSP7DigitalAsset` and `LSP8IdentifiableDigitalAsset` contracts.

### Impact

Protocols that check for LSP7/LSP8 compatibility using the `ERC-165` interface IDs declared in the specification will receive incorrect return values when calling `supportsInterface()`.

### Recommended Mitigation

Ensure that the interface ID declared in th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lukso)

---

### Example 3: [01] Allowing DSSes that do not implement `ERC165.supportsInterface` function to be registered is problematic

**Source**: Code4rena
**Protocol**: Karak
**Impact**: LOW

**Details**:

### Description
https://github.com/code-423n4/2024-07-karak?tab=readme-ov-file#eip-compliance-checklist states that `DSS contract should comply with ERC-165`. Therefore, the protocol requires that each DSS is ERC-165 compliant.

According to https://eips.ethereum.org/EIPS/eip-165#how-a-contract-will-publish-the-interfaces-it-implements, `A contract that is compliant with ERC-165 shall implement the following interface`:

```solidity
interface ERC165 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceID The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    ///  uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceID` and
    ///  `interfaceID` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}
```

Thus, each DSS needs to implement the `ERC165.supportsInterface` function to comply with ERC-165. However, calling the following `Core.registerDSS` function does not check if the DSS implements the `ERC165.supportsInterface` function or not so a DSS that does not implement the `ERC165.supportsInterface` function and hence is not ERC-165 compliant can also be registered.

https://github.com/code-423n4/2024-07-karak/blob/53eb78ebda718d752023db4faff4ab1567327db4/src/Core.sol#L262-L267
```solidity
    function registerDSS(uint256 maxSlashablePercentageWad) external {
        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-07-karak)

---

### Example 4: [12] `supportsInterface` Implementation Non-Compliant with ERC-165

**Source**: Code4rena
**Protocol**: Kinetiq
**Impact**: LOW

**Details**:

**Contract Name:** `DefaultAdapter.sol`

**Function Name:** `supportsInterface`

**Description:**
The `supportsInterface` function does not return `true` for the ERC-165 interface ID (`0x01ffc9a7`), violating the standard and potentially causing compatibility issues.

**Mitigation:**
Update the function:
```

function supportsInterface(bytes4 interfaceId) external view returns (bool) {
    return interfaceId == type(IOracleAdapter).interfaceId || interfaceId == type(IERC165).interfaceId;
}
```

**Reference**: [View Original Finding](https://code4rena.com/reports/2025-04-kinetiq)

---

### Example 5: [L-03] Missing `IERC165` support in `supportsInterface()`

**Source**: Pashov Audit Group
**Protocol**: Hyperhyper_2025-03-30
**Impact**: LOW

**Details**:

The `supportsInterface` function in the `ERC721WithURIBuilderUpgradeable` contract overrides the IERC165 interface but fails to provide support for the necessary interface IDs(`IERC165`). This is not a good practice and may return incorrect results.

```solidity
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        return ERC721EnumerableUpgradeable.supportsInterface(interfaceId);
    }
```

To mitigate this issue, change it to:

````solidity
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        return ERC721EnumerableUpgradeable.supportsInterface(interfaceId) || super.supportsInterface(interfaceId);
    }

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Hyperhyper-security-review_2025-03-30.md)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

