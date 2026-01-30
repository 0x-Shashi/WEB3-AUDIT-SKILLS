# ERC721 Security Patterns

## Overview

**Frequency**: 21 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 13 | 1 | 0 |

**Common Sources**: Code4rena, Sherlock, Codehawks, Cyfrin

---

## Detection Checklist

- [ ] Check for erc721 vulnerabilities in all external functions
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

### Example 2: Attacker can destroy user voting power by setting `ERC721Power::totalPower` and all existing NFTs `currentPower` to 0

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can destroy user voting power by setting `ERC721Power::totalPower` & all existing nfts' `currentPower` to 0 via a permission-less attack contract by exploiting a discrepancy ("<" vs "<=") in `ERC721Power` [L144](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L144) & [L172](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L172):

```solidity
function recalculateNftPower(uint256 tokenId) public override returns (uint256 newPower) {
    // @audit execution allowed to continue when
    // block.timestamp == powerCalcStartTimestamp
    if (block.timestamp < powerCalcStartTimestamp) {
        return 0;
    }
    // @audit getNftPower() returns 0 when
    // block.timestamp == powerCalcStartTimestamp
    newPower = getNftPower(tokenId);

    NftInfo storage nftInfo = nftInfos[tokenId];

    // @audit as this is the first update since power
    // calculation has just started, totalPower will be
    // subtracted by nft's max power
    totalPower -= nftInfo.lastUpdate != 0 ? nftInfo.currentPower : getMaxPowerForNft(tokenId);
    // @audit totalPower += 0 (newPower = 0 in above line)
    totalPower += newPower;

    nftInfo.lastUpdate = uint64(block.timestamp);
    // @audit will set nft's current power to 0
    nftInfo.currentPower = newPower;
}

function getNftPower(uint256 tokenId) public view ove

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 3: [M-04] `CidNFT`: Broken `tokenURI` function

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

### Example 4: [M-17] The tokenURI method does not check if the NFT has been minted and returns data for the contract that may be a fake NFT

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

### Example 5: [M-19] `HolographERC721.approve` not EIP-721 compliant

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L272](https://github.com/code-423n4/2022-10-holograph/blob/24bc4d8dfeb6e4328d2c6291d20553b1d3eff00b/src/enforcer/HolographERC721.sol#L272)<br>

According to EIP-721, we have for `approve`:

```solidity
///  Throws unless `msg.sender` is the current NFT owner, or an authorized
///  operator of the current owner.
```

An operator in the context of EIP-721 is someone who was approved via `setApprovalForAll`:

```solidity
/// @notice Enable or disable approval for a third party ("operator") to manage
///  all of `msg.sender`'s assets
/// @dev Emits the ApprovalForAll event. The contract MUST allow
///  multiple operators per owner.
/// @param _operator Address to add to the set of authorized operators
/// @param _approved True if the operator is approved, false to revoke approval
function setApprovalForAll(address _operator, bool _approved) external;
```

Besides operators, there are also approved addresses for a token (for which `approve` is used). However, approved addresses can only transfer the token, see for instance the `safeTransferFrom` description:

```solidity
/// @dev Throws unless `msg.sender` is the current owner, an authorized
///  operator, or the approved address for this NFT.
```

`HolographERC721` does not distinguish between authorized operators and approved addresses when it comes to the `approve` function. Because `_isApproved(msg.sender, tokenId)` is used there, an approved address can approve another address, which is a violation of the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 6: [M-15] `HolographERC721.safeTransferFrom` not compliant with EIP-721

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

### Example 7: H-3: CouncilMember:burn renders the contract inoperable after the first execution

**Source**: Sherlock
**Protocol**: Telcoin Platform Audit
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-01-telcoin-judging/issues/199 

## Found by 
0xAsen, 0xLogos, 0xadrii, 0xlamide, 0xmystery, 0xpep7, Aamirusmani1552, Arz, BAICE, Bauer, DenTonylifer, HonorLt, Ignite, IvanFitro, Jaraxxus, Kow, Krace, VAD37, alexbabits, almurhasan, araj, bitsurfer, dipp, fibonacci, ggg\_ttt\_hhh, gqrp, grearlake, jah, m4ttm, mstpr-brainbot, popeye, psb01, r0ck3tz, ravikiran.web3, sakshamguruji, sobieski, sonny2k, tives, ubl4nk, vvv, ydlee, zhuying, zzykxx
## Summary
The CouncilMember contract suffers from a critical vulnerability that misaligns the balances array after a successful burn, rendering the contract inoperable.

## Vulnerability Detail

The root cause of the vulnerability is that the `burn` function incorrectly manages the `balances` array, shortening it by one each time an ERC721 token is burned while the latest minted NFT still withholds its unique `tokenId` which maps to the previous value of `balances.length`.
```solidity
// File: telcoin-audit/contracts/sablier/core/CouncilMember.sol
210:    function burn(
        ...
220:        balances.pop(); // <= FOUND: balances.length decreases, while latest minted nft withold its unique tokenId
221:        _burn(tokenId);
222:    }
```

This misalignment between existing `tokenIds` and the `balances` array results in several critical impacts:

1. Holders with tokenId greater than the length of balances cannot claim.
2. Subsequent burns of tokenId greater than balances length will revert.
3. 

*[Content truncated...]*

---

### Example 8: [H-02] An attacker is able to hijack any ERC721 / ERC1155 he borrows because guard is missing validation on the address supplied to function call `setFallbackHandler()`

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: HIGH

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **Gnosis safe fallback handlers**: Safes starting with version 1.1.1 allow to specify a fallback handler. A gnosis safe fallback handler is a contract which handles all functions that is unknown to the safe, this feature is meant to provide a great flexibility for the safe user. The safe in particular says "If I see something unknown, then I just let the fallback handler deal with it."

    **Example**: If you want to take a uniswap flash loan using your gnosis safe, you'll have to create a fallback handler contract with the callback function `uniswapV2Call()`. When you decide to take a flash loan using your safe, you'll send a call to `swap()` in the uniswap contract. The uniswap contract will then reach out to your safe contract asking to call `uniswapV2Call()`, but `uniswapV2Call()` isn't actually implemented in the safe contract itself, so your safe will reach out to the fallback handler you created, set as the safe's fallback handler and ask it to handle the `uniswapV2Call()` TX coming from uniswap.

    **Setting a fallback handler**: To set a fallback handler for your safe, you'll have to call the function [`setFallbackHandler()`](https://github.com/safe-global/safe-contracts/blob/b140318af6581e499506b11128a892e3f7a52aeb/contracts/base/FallbackManager.sol#L44) which you can find it's logic in [FallbackManager.sol](https://github.com/safe-global/safe-contracts/blob/main/contracts/base/Fallba

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 9: [H-03] Approval for NFT transfers is not removed after transfer

**Source**: Code4rena
**Protocol**: Visor
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by gpersoon, and pauliax_

The `Visor.transferERC721` does not reset the approval for the NFT.

An approved delegatee can move the NFT out of the contract once.
It could be moved to a market and bought by someone else who then deposits it again to the same vault.
The first delegatee can steal the NFT and move it out of the contract a second time.

Recommend resetting the approval on transfer.

**[xyz-ctrl (Visor) confirmed](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-856953219):**
> We will be mitigating this issue for our next release and before these experimental features are introduced in platform.
> PR pending

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-889192312):**
> duplicate of above ones and fixed

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 10: [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

Many ERC721/ERC1155 tokens, including well-known games such as Axie Infinity, have a pause functionality inside the contract. This pause functionality will cause the `stopRent` call to always revert and could cause issues, especially for the `PAY` order type.

### Proof of Concept

When `stopRent` /`stopRentBatch` is called, it will eventually trigger `  _reclaimRentedItems ` and execute `reclaimRentalOrder` from the safe to send back tokens to lender.

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L353> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L293> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L183>



```solidity
    function _reclaimRentedItems(RentalOrder memory order) internal {
        // Transfer ERC721s from the renter back to lender.
        bool success = ISafe(order.rentalWallet).execTransactionFromModule(
            // Stop policy inherits the reclaimer package.
            address(this),
            // value.
            0,
            // The encoded call to the `reclaimRentalOrder` function.
            abi.encodeWithSelector(this.reclaimRentalOrder.selector, order),
            // Safe must delegate call to the stop policy so that it is the msg.sender.
            Enum.Operation.DelegateCall
        );

        // Assert that the transfer back to the len

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 11: [H-07] `_transferNFTs()` succeeds even if no transfer is performed

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by k, also found by 0x29A, 0xf15ers, 0xsanson, antonttc, hyh, PwnedNoMore, and zzzitron_

If an NFT is sold that does not specify support for the ERC-721 or ERC-1155 standard interface, the sale will still succeed. In doing so, the seller will receive funds from the buyer, but the buyer will not receive any NFT from the seller. This could happen in the following cases:

1.  A token that claims to be ERC-721/1155 compliant, but fails to implement the `supportsInterface()` function properly.
2.  An NFT that follows a standard other than ERC-721/1155 and does not implement their EIP-165 interfaces.
3.  A malicious contract that is deployed to take advantage of this behavior.

### Proof of Concept

<https://gist.github.com/kylriley/3bf0e03d79b3d62dd5a9224ca00c4cb9>

### Recommended Mitigation Steps

If neither the ERC-721 nor the ERC-1155 interface is supported the function should revert. An alternative approach would be to attempt a `transferFrom` and check the balance before and after to ensure that it succeeded.

**[nneverlander (Infinity) confirmed and resolved](https://github.com/code-423n4/2022-06-infinity-findings/issues/87#issuecomment-1162963184):**
 > Fixed in https://github.com/infinitydotxyz/exchange-contracts-v2/commit/377c77f0888fea9ca1e087de701b5384a046f760

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-06-infinity-findings/issues/87#issuecomment-1179596601):**
> If `supportsInterface` returns false for both 721 & 1155 then no 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 12: M-1: [Tomo-M3] Use safeMint instead of mint for ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/65 

## Found by 
Tomo

## Summary

Use safeMint instead of mint for ERC721

## Vulnerability Detail

The `msg.sender` will be minted as a proof of staking NFT when `_stakeToken()` is called. 

However, if `msg.sender` is a contract address that does not support ERC721, the NFT can be frozen in the contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.
> 

Ref: [https://eips.ethereum.org/EIPS/eip-721](https://eips.ethereum.org/EIPS/eip-721)

As per the documentation of ERC721.sol by Openzeppelin

Ref: [https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285)

```solidity
/**
 * @dev Mints `tokenId` and transfers it to `to`.
 *
 * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
 *
 * Requirements:
 *
 * - `tokenId` must not exist.
 * - `to` cannot be the zero address.
 *
 * Emits a {Transfer} event.
 */
function _mint(address to, uint256 tokenId) internal virtual {
```

## Impact

Users possibly lose their NFTs

## Code Snippet
https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L411
``` solidity
  _mint(msg.sender, _tokenId);
```
## Tool used

Manual Review

## Recommendation

Us

*[Content truncated...]*

---

### Example 13: [M-08] Assets in a Safe can be lost

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

The `Guard.sol` contract is enabled on Safe's and uses the [`_checkTransaction`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293) function to ensure that transactions that the Safe executes do not transfer the asset out of the Safe.

The `checkTransaction` function achieves this by isolating the function selector and checking that it is not a disallowed function selector. For instance: `safeTransferFrom`, `transferFrom`, `approve`, `enableModule`, etc.

The list does not, however, check for calls to `burn` the token, neither does it check if it is a `permit`. The sponsor has noted the following:

> The [Guard](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol) contract can only protect against the transfer of tokens that faithfully
implement the ERC721/ERC1155 spec.

But this does not acknowledge the fact that an ERC721/ERC1155 implementation can still be an honest implementation and have extra functionality. In particular, the `burn` function is a common addition to many ERC721 contracts, usually granted through inheriting `ERC721Burnable`.

For example, the following projects all have a `burn` function, and Safe's protected by `Guard.sol` that hold these NFTs will be vulnerable to loss of assets via a malicious renter:

*   [Pudgy Penguins](https://etherscan.io/address/0xbd3531da5cf5857e7cfaa92426877b022e612cf8#writeContract)
*   [Lil Pudgies

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 14: [M-09] Use safeTransferFrom instead of transferFrom for ERC721 transfers

**Source**: Code4rena
**Protocol**: Cally
**Impact**: MEDIUM

**Details**:

_Submitted by hickuphh3, also found by antonttc, berndartmueller, catchup, cccz, dipp, FSchmoede, GimelSec, hake, jah, jayjonah8, joestakey, kebabsec, Kenshin, Kumpa, MiloTruck, minhquanym, peritoflores, rfa, shenwilly, WatchPug, and ynnad_

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L199>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L295>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L344>

### Details & Impact

The `transferFrom()` method is used instead of `safeTransferFrom()`, presumably to save gas. I however argue that this isn’t recommended because:

*   [OpenZeppelin’s documentation](https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#IERC721-transferFrom-address-address-uint256-) discourages the use of `transferFrom()`, use `safeTransferFrom()` whenever possible
*   Given that any NFT can be used for the call option, there are a few NFTs (here’s an [example](https://github.com/sz-piotr/eth-card-game/blob/master/src/ethereum/contracts/ERC721Market.sol#L20-L31)) that have logic in the `onERC721Received()` function, which is only triggered in the `safeTransferFrom()` function and not in `transferFrom()`

### Recommended Mitigation Steps

Call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers. Note that the `CallyNft` contrac

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-cally)

---

### Example 15: H-1: Escrow approvals are not cleared when club is transferred allowing for abuse after transfer

**Source**: Sherlock
**Protocol**: Footium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/289 

## Found by 
0x52, BenRai, Brenzee, CMierez, J4de, MiloTruck, PokemonAuditSimulator, Quantish, cergyk, ctf\_sec, mstpr-brainbot, pengun, sashik\_eth, shaka, shogoki, toshii
## Summary

Escrow approvals remain even across club token transfers. This allows a malicious club owners to sell their club then drain everything after sale due to previous approvals.

## Vulnerability Detail

ERC20 and ERC721 token approval persist regardless of the owner of the club. The result is that approvals set by one owner can be accessed after a token has been sold or transferred. This allows the following attack:

1) User A owns clubId = 1
2) User A sets approval to themselves
3) User A sells clubId = 1 to User B
4) User A uses persistent approval to drain all players and tokens

## Impact

Malicious approvals can be used to drain club after sale

## Code Snippet

[FootiumEscrow.sol#L75-L81](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumEscrow.sol#L75-L81)

[FootiumEscrow.sol#L90-L96](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumEscrow.sol#L90-L96)

## Tool used

Manual Review

## Recommendation

Club escrow system needs to be redesigned

---

### Example 16: [M-04] Incorrect implementation of ERC721 may have bad consequences for receiver

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L467](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/HolographERC721.sol#L467)<br>

HolographERC721.sol is an enforcer contract that fully implements ERC721. In its safeTransferFromFunction there is the following code:

    if (_isContract(to)) {
      require(
        (ERC165(to).supportsInterface(ERC165.supportsInterface.selector) &&
          ERC165(to).supportsInterface(ERC721TokenReceiver.onERC721Received.selector) &&
          ERC721TokenReceiver(to).onERC721Received(address(this), from, tokenId, data) ==
          ERC721TokenReceiver.onERC721Received.selector),
        "ERC721: onERC721Received fail"
      );
    }

If the target address is a contract, the enforcer requires the target's `onERC721Received()` to succeed. However, the call deviates from the [standard](https://eips.ethereum.org/EIPS/eip-721):

    interface ERC721TokenReceiver {
        /// @notice Handle the receipt of an NFT
        /// @dev The ERC721 smart contract calls this function on the recipient
        ///  after a `transfer`. This function MAY throw to revert and reject the
        ///  transfer. Return of other than the magic value MUST result in the
        ///  transaction being reverted.
        ///  Note: the contract address is always the message sender.
        /// @param _operator The address which called `safeTransferFrom` function
        /// @param _from The address which previously owned the token

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 17: M-3: Using `ERC721.transferFrom()` instead of `safeTransferFrom()` may cause the user's NFT to be frozen in a contract that does not support ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/55 

## Found by 
saian, rvierdiiev, WATCHPUG, Tomo, Bnke0x0, Nyx

## Summary

There are certain smart contracts that do not support ERC721, using `transferFrom()` may result in the NFT being sent to such contracts.

## Vulnerability Detail

In `unstake()`, `_to` is param from user's input.

However, if `_to` is a contract address that does not support ERC721, the NFT can be frozen in that contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.

Ref: https://eips.ethereum.org/EIPS/eip-721

## Impact

The NFT may get stuck in the contract that does support ERC721.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L463-L489

## Tool used

Manual Review

## Recommendation

Consider using `safeTransferFrom()` instead of `transferFrom()`.

## Discussion

**zobront**

Fixed: https://github.com/Solidity-Guild/FrankenDAO/pull/10

---

### Example 18: [M-07] Using `transferFrom` on ERC721 tokens

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

_Submitted by shw_

In the function `awardExternalERC721` of contract `PrizePool`, when awarding external ERC721 tokens to the winners, the `transferFrom` keyword is used instead of `safeTransferFrom`. If any winner is a contract and is not aware of incoming ERC721 tokens, the sent tokens could be locked.

Recommend consider changing `transferFrom` to `safeTransferFrom` at line 602. However, it could introduce a DoS attack vector if any winner maliciously rejects the received ERC721 tokens to make the others unable to get their awards. Possible mitigations are to use a `try/catch` statement to handle error cases separately or provide a function for the pool owner to remove malicious winners manually if this happens.

**[asselstine (PoolTogether) confirmed and disagreed with severity](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-868021913):**
 > This issue poses no risk to the Prize Pool, so it's more of a `1 (Low Risk` IMO.
>
> This is just about triggering a callback on the ERC721 recipient.  We omitted it originally because we didn't want a revert on the callback to DoS the prize pool.
>
> However, to respect the interface it makes sense to implement it fully.  That being said, if it does throw we must ignore it to prevent DoS attacks.

**[dmvt (judge) commented](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-907507608):**
 > I agree with the medium risk rating provided by the warden.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-pooltogether)

---

### Example 19: [M-02] A malicious borrower can hijack any NFT with `permit()` function he rents.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **ERC-4494: Permit for ERC-721 NFTs**: ERC721-Permit is very similar to ERC20-permit (EIP-2612). ERC721 Permit adds a new `permit()` function. It allows user can sign an ERC721 approve transaction off-chain producing a signature that anyone could use and submit to the permit function. When permit is executed, it will execute the approve function. This allows for meta-transaction support of ERC721 transfers, but it also simply gets rid of the annoyance of needing two transactions: `approve` and `transferFrom`. Additionally, ERC721-Permit, just like ERC20 permit, prevents misuse and replay attacks. A replay attack is when a valid signature is used several times or in places where it's not intended to be used in.

    You can find an implementation of it here, by uniswap: <https://github.com/Uniswap/v3-periphery/blob/main/contracts/base/ERC721Permit.sol>

***

### The Vulnerability & Exploitation Steps

***

ReNFT doesn't account for ERC721 implementing the `permit()` function, allowing a malicious borrower to hijack the token by producing a signature and feeding it to the `permit()` function requesting it to approve his address to transfer the token

**Exploitation Steps**

1.  The attacker rents the NFT token in his rental safe
2.  The attacker creates a signature which he will need to feed to the `permit()` function. The signature is a signed data including info like: 1. the deadline (until when t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 20: M-7: Minting inconsistencies on FootiumPlayer and FootiumClub

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/342 

## Found by 
0xAsen, 0xHati, 0xLook, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xhacksmithh, BAHOZ, Bauchibred, Bauer, Dug, GalloDaSballo, Koolex, PTolev, Phantasmagoria, TheNaubit, Tricko, ali\_shehab, cergyk, chaithanya\_gali, ctf\_sec, cuthalion0x, deadrxsezzz, descharre, indijanc, jasonxiale, kiki\_dev, lewisbroadhurst, nzm\_, oualidpro, sashik\_eth, shame, shogoki, tsueti\_, tsvetanovv, wzrdk3lly
## Summary

The `FootiumClub.sol` contract when minting uses `_mint()` instead of `_safeMint()` which can cause to mint a club to a contract who does not support nfts. On the other hand `FootiumPlayer.sol` uses `_safeMint()`.

## Vulnerability Detail

See summary.

## Impact

`FootiumClub.sol` might mint a club NFT to a contract that cannot handle nfts.

## Code Snippet

https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumClub.sol#L65

## Tool used

Manual Review

## Recommendation

Use `_safeMint()` as in FootiumPlayer.

---

### Example 21: No Check for Transferring to Self

**Source**: Codehawks
**Protocol**: stake.link
**Impact**: LOW

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/tree/main/contracts/core/sdlPool/base/SDLPool.sol#L460-462">https://github.com/Cyfrin/2023-12-stake-link/tree/main/contracts/core/sdlPool/base/SDLPool.sol#L460-462</a>


## Summary

The `_transfer` function is responsible for transferring the ownership of a lock from one address to another. It is a critical part of the ERC721 token standard implementation, which this contract adheres to. However, there is a missing check to ensure that the `_from` address is not the same as the `_to` address. Transferring a lock where the `_from` and `_to` addresses are the same can lead to unintended consequences like the double changing of state variables.

Since the _updateRewards function logic depends on the rewards pool, this could create an exploit depending on the implementation of the rewards pool. 

By adding this check, we can ensure that locks are not transferred to the same address that already owns them, thus mitigating the described vulnerability.

## Recommendations

Add a check to the _transfer function to ensure that `_from` != `_to`.

---

## Statistics

- Total findings analyzed: 21
- Examples shown: 21
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

