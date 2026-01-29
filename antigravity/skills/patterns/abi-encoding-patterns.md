# ABI Encoding Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 0 | 0 |

**Common Sources**: Pashov Audit Group, Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for abi encoding vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-04] `CidNFT`: Broken `tokenURI` function

**Source**: Code4rena
**Protocol**: Canto Identity Protocol
**Impact**: MEDIUM

**Details**:

[`CidNFT#tokenURI`](https://github.com/code-423n4/2023-01-canto-identity/blob/dff8e74c54471f5f3b84c217848234d474477d82/src/CidNFT.sol#L133-L142) does not convert the `uint256 _id` argument to a string before interpolating it in the token URI:

```solidity
    /// @notice Get the token URI for the provided ID
    /// @param _id ID to retrieve the URI for
    /// @return tokenURI The URI of the queried token (path to a JSON file)
    function tokenURI(uint256 _id) public view override returns (string memory) {
        if (ownerOf[_id] == address(0))
            // According to ERC721, this revert for non-existing tokens is required
            revert TokenNotMinted(_id);
        return string(abi.encodePacked(baseURI, _id, ".json"));
    }

```

This means the raw bytes of the 32-byte ABI encoded integer `_id` will be interpolated into the token URI, e.g. `0x0000000000000000000000000000000000000000000000000000000000000001` for ID `#1`.

Most of the resulting UTF-8 strings will be malformed, incorrect, or invalid URIs. For example, token ID `#1` will show up as the invisible "start of heading" control character, and ID `#42` will show as the asterisk symbol `*`. URI-unsafe characters will break the token URIs altogether.

### Impact

*   `CidNFT` tokens will have invalid `tokenURI`s. Offchain tools that read the `tokenURI` view may break or display malformed data.

### Suggestion

Convert the `_id` to a string before calling `abi.encodePacked`. Latest Solmate includes a `LibStri

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-canto-identity)

---

### Example 2: [M-01] Wrong collateral refund in liquidation when `liqPrice == priceAfterImpact`

**Source**: Pashov Audit Group
**Protocol**: Ostium_2025-04-06
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

When a liquidation is triggered and the Oracle price used results in `liqPrice == priceAfterImpact` during the execution of `executeAutomationCloseOrderCallback()`, the system may incorrectly refund a portion of the user collateral - approximately equal to the `liquidationFee`.

This occurs due to a discrepancy in how `value` and `liqMarginValue` are calculated within the `getTradeValuePure()` function. Under specific conditions (`liqPrice == priceAfterImpact`), `value` can become greater than `liqMarginValue`, even though the position should be fully liquidated.

Within the new `Margin-Based Liquidations` logic, users should not receive any collateral back during liquidation. The entire collateral should be distributed between the `liquidationFee` and the `Vault` to cover losing trade.

However, do to the legacy refund logic that remains in the code:

```solidity
@>      uint256 usdcSentToVault = usdcLeftInStorage - usdcSentToTrader;
        storageT.transferUsdc(address(storageT), address(this), usdcSentToVault);
        vault.receiveAssets(usdcSentToVault, trade.trader);
@>      if (usdcSentToTrader > 0) storageT.transferUsdc(address(storageT), trade.trader, usdcSentToTrader);
```

With combination to the incorrect calculation of `value` and `liqMarginValue`, the `usdcSentToTrader` returned from the `getTradeValue()` function may end up being roughly equal to the `liquidationFee`, resulting in an unintende

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Ostium-security-review_2025-04-06.md)

---

### Example 3: ABI decoding for bytes: memory can be corrupted by maliciously constructing the calldata

**Source**: Spearbit
**Protocol**: SEAPORT
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity: 
**Medium Risk**

## Context: 
`ConsiderationDecoder.sol#L51-L62`

## Description: 
In the code snippet below, `size` can be made `0` by maliciously crafting the calldata. In this case, the free memory is not incremented.

```solidity
assembly {
    mPtrLength := mload(0x40)
    let size := and(
        add(
            and(calldataload(cdPtrLength), OffsetOrLengthMask),
            AlmostTwoWords
        ),
        OnlyFullWordMask
    )
    calldatacopy(mPtrLength, cdPtrLength, size)
    mstore(0x40, add(mPtrLength, size))
}
```

This has two different consequences:
1. If the memory offset `mPtrLength` is immediately used, then junk values at that memory location can be interpreted as the decoded bytes type. In the case of Seaport 1.2, the likelihood of the current free memory pointing to junk value is low. So, this case has low severity.
2. The consequent memory allocation will also use the value `mPtrLength` to store data in memory. This can lead to corrupting the initial memory data. In the worst case, the next allocation can be tuned so that the first bytes data can be any arbitrary data.

### Steps to Make the Size Calculation Return 0:
1. Find a function call which has `bytes` as a (nested) parameter.
2. Modify the calldata field where the length of the above byte is stored to the new length `0xffffe0`.
3. The calculation will now return `size = 0`.

**Note:** There is an additional requirement that this `bytes` type should be

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seaport-Spearbit-Security-Review.pdf)

---

### Example 4: M-1: `abi.encodePacked` Allows Hash Collision

**Source**: Sherlock
**Protocol**: NFTPort
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-nftport-judging/issues/118 

## Found by 
keccak123, 0xheynacho

## Summary

From the solidity documentation:
https://docs.soliditylang.org/en/v0.8.17/abi-spec.html?highlight=collisions#non-standard-packed-mode
    > If you use `keccak256(abi.encodePacked(a, b))` and both `a` and `b` are dynamic types, it is easy to craft collisions in the hash value by moving parts of `a` into `b` and vice-versa. More specifically, `abi.encodePacked("a", "bc") == abi.encodePacked("ab", "c")`.

This issue exists in the Factory contract can results in hash collisions, bypassing the `signedOnly` modifier.

## Vulnerability Detail

The issue is in these lines of code:
https://github.com/sherlock-audit/2022-10-nftport/blob/main/evm-minting-master/contracts/Factory.sol#L171
https://github.com/sherlock-audit/2022-10-nftport/blob/main/evm-minting-master/contracts/Factory.sol#L195
https://github.com/sherlock-audit/2022-10-nftport/blob/main/evm-minting-master/contracts/Factory.sol#L222

As the solidity docs describe, two or more dynamic types are passed to `abi.encodePacked`. Moreover, these dynamic values are user-specified function arguments in external functions, meaning anyone can directly specify the value of these arguments when calling the function. The `signedOnly` modifier is supposed to protect functions to permit only function arguments that have been properly signed to be passed to the function logic, but because a collision can be created,

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
