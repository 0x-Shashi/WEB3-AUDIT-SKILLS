---
id: PAT-SUPPORTSINTERFACE
title: Supportsinterface Security Patterns
category: standards
severity: low
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - erc165
  - interface
  - detection

finding_count: 5
last_updated: 2026-01-31
---
# supportsInterface Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 2 | 0 |

**Common Sources**: Code4rena, MixBytes, Pashov Audit Group, Cyfrin

---

## Detection Checklist

- [ ] Check for supportsinterface vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Some real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `InfinityExchange::_transferNFTs`

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by PwnedNoMore_

Many real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `InfinityExchange::_transferNFTs`, i.e., transferring less tokens than expected.

For example, the asset token of [The Sandbox Game](https://www.sandbox.game/en/), a Top20 ERC1155 token on [Etherscan](https://etherscan.io/tokens-nft1155?sort=7d\&order=desc), supports both ERC1155 and ERC721 interfaces. Specifically, any ERC721 token transfer is regarded as an ERC1155 token transfer with only one item transferred ([token address](https://etherscan.io/token/0xa342f5d851e866e18ff98f351f2c6637f4478db5) and [implementation](https://etherscan.io/address/0x7fbf5c9af42a6d146dcc18762f515692cd5f853b#code#F2#L14)).

Assuming there is a user tries to buy two tokens of Sandbox's ASSETs with the same token id, the actual transferring is carried by `InfinityExchange::_transferNFTs` which first checks ERC721 interface supports and then ERC1155.

```solidity
  function _transferNFTs(
    address from,
    address to,
    OrderTypes.OrderItem calldata item
  ) internal {
    if (IERC165(item.collection).supportsInterface(0x80ac58cd)) {
      _transferERC721s(from, to, item);
    } else if (IERC165(item.collection).supportsInterface(0xd9b67a26)) {
      _transferERC1155s(from, to, item);
    }
  }
```

The code will go into `_transferERC721s` instead of `_transferERC1155s`, since the Sandbox's ASSETs also support ERC721 interface. Then,

```solidity
  function _transferERC721s(


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 2: [M-04] The `FERC1155.sol` don't respect the EIP2981

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: MEDIUM

**Details**:

_Submitted by 0x29A_

The [EIP-2981: NFT Royalty Standard](https://eips.ethereum.org/EIPS/eip-2981) implementation is incomplete, missing the implementation of `function supportsInterface(bytes4 interfaceID) external view returns (bool);` from the [EIP-165: Standard Interface Detection](https://eips.ethereum.org/EIPS/eip-165).

### Proof of Concept

A marketplace that implemented royalties could check if the NFT has royalties, but if they don't, add the interface of `ERC2981` on the `_registerInterface`, the marketplace can't know if this NFT has royalties.

### Recommended Mitigation Steps

Like in [solmate ERC1155.sol](https://github.com/Rari-Capital/solmate/blob/03e425421b24c4f75e4a3209b019b367847b7708/src/tokens/ERC1155.sol#L137-L146) add the `ERC2981` interfaceId on the `FERC1155` contract

```solidity
    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) public view  override returns (bool) {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == 0x2a55205a; // ERC165 Interface ID for ERC2981
    }
```

**[aklatham (Fractional) confirmed](https://github.com/code-423n4/2022-07-fractional-findings/issues/544)** 

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-07-fractional-findings/issues/544#issuecomment-1208112166):**
 > The contr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 3: [M-05] Missing `supportsInterface` Selector from `DiamondLoupeFacet`

**Source**: Pashov Audit Group
**Protocol**: Burve_2025-01-29
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

The `SimplexDiamond` contract is intended to support multiple interfaces, including `IERC165`, `IDiamondCut`, `IDiamondLoupe`, and `IERC173`. While `SimplexDiamond` correctly adds these interfaces to `ds.supportedInterfaces`, it **fails to include the `supportsInterface` function from `DiamondLoupeFacet` as a selector**. This omission **prevents the contract from properly supporting interfaces**, making it **incompatible with standard interface detection mechanisms**.

## Recommendations

Ensure `supportsInterface` is included in the `DiamondLoupeFacet` selectors:

```diff
        {
-            bytes4[] memory loupeFacetSelectors = new bytes4[](4);
+            bytes4[] memory loupeFacetSelectors = new bytes4[](5);
            loupeFacetSelectors[0] = DiamondLoupeFacet.facets.selector;
            loupeFacetSelectors[1] = DiamondLoupeFacet.facetFunctionSelectors.selector;
            loupeFacetSelectors[2] = DiamondLoupeFacet.facetAddresses.selector;
            loupeFacetSelectors[3] = DiamondLoupeFacet.facetAddress.selector;
+            loupeFacetSelectors[4] = DiamondLoupeFacet.supportsInterface.selector;
            cuts[1] = FacetCut({
                facetAddress: address(new DiamondLoupeFacet()),
                action: FacetCutAction.Add,
                functionSelectors: loupeFacetSelectors
            });
```

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Burve-security-review_2025-01-29.md)

---

### Example 4: Incorrect interface check for market maker contract

**Source**: MixBytes
**Protocol**: XPress
**Impact**: LOW

**Details**:

##### Description
This issue has been identified within the [_changeMarketMakerAddress](https://github.com/longgammalabs/hanji-contracts/blob/70b15ec4d9e7578248141604503843716a67d875/src/HanjiLOB.sol#L1088) function of the `HanjiLOB` contract.

The function changes the market maker address and checks whether the new market maker implements the `ITradeConsumer` interface by using the ERC165 `supportsInterface` function. However, the current implementation uses the `onTrade.selector` to perform this check, which is not the standard approach for ERC165 interface identification. Instead, the correct method is to use the `ITradeConsumer.interfaceId`, which represents the full interface rather than a single function.

The issue is classified as **low** severity because, while it may not cause immediate failures, it deviates from the ERC165 standard and could potentially lead to compatibility issues with other contracts that correctly implement the standard.
##### Recommendation
We recommend updating the interface check to use `ITradeConsumer.interfaceId` instead of `onTrade.selector`. This change ensures that the check is consistent with the ERC165 standard and accurately verifies that the market maker implements the entire `ITradeConsumer` interface.
```solidity!
if (!maker.supportsInterface(type(ITradeConsumer).interfaceId)) {
    revert HanjiErrors.InvalidMarketMaker();
}
```

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/XPress/OnchainCLOB/README.md#18-incorrect-interface-check-for-market-maker-contract)

---

### Example 5: Incomplete ERC20 interface support

**Source**: Cyfrin
**Protocol**: Soneium Shibuya
**Impact**: LOW

**Details**:

**Description:** The `supportsInterface()` function doesn't declare support for `IERC20` interface ID despite implementing ERC20 functionality.
This could cause issues with interface detection in some integration scenarios.

**Recommended Mitigation:** Add support for `type(IERC20).interfaceId` in the `supportsInterface` function.

**Startale:** Fixed in commit [cb5b05](https://github.com/StartaleLabs/ccip-contracts-registration/commit/cb5b05c4f09b449aa46b5e6290456f9f94cdb09f).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2024-12-23-cyfrin-soneium-shibuya-v2.0.md)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

