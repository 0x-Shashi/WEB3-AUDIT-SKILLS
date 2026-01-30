# mint vs safeMint Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 4 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, TrailOfBits

---

## Detection Checklist

- [ ] Check for mint vs safemint vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Minter user can conﬁscate any user tokens

**Source**: TrailOfBits
**Protocol**: Curve DAO
**Impact**: HIGH

**Details**:

## Auditing and Logging
**Type:** Auditing and Logging  
**Target:** ERC20CV.vy  

**Difficulty:** Low  

## Description
ERC20CV’s minter has the unexpected right to move tokens from any users, increasing the risks associated with the minter account.

The administrator of the contract can design a special user called a minter:
```python
@public
def set_minter(_minter: address):
    assert msg.sender == self.admin  # dev: admin only
    self.minter = _minter
```
*Figure 7.1: ERC20CV.vy#L143-L146*  

This privileged user can be wielded to mint new tokens:
```python
@public
def mint(_to: address, _value: uint256):
    """
    @dev Mint an amount of the token and assigns it to an account.
    This encapsulates the modification of balances such that the
    proper events are emitted.
    @param _to The account that will receive the created tokens.
    @param _value The amount that will be created.
    """
    assert msg.sender == self.minter  # dev: minter only
    assert _to != ZERO_ADDRESS          # dev: zero address
    if block.timestamp >= self.start_epoch_time + RATE_REDUCTION_TIME:
        self._update_mining_parameters()
    _total_supply: uint256 = self.total_supply + _value
    assert _total_supply <= self._available_supply()  # dev: exceeds allowable mint amount
    self.total_supply = _total_supply
    self.balanceOf[_to] += _value
    log.Transfer(ZERO_ADDRESS, _to, _value)
```
*Figure 7.2: ERC20CRV.vy#L230-L250*  

However, it is also possible to use the minter to t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/CurveDAO.pdf)

---

### Example 2: [M-10] Putty position tokens may be minted to non ERC721 receivers

**Source**: Code4rena
**Protocol**: Putty
**Impact**: MEDIUM

**Details**:

_Submitted by horsefacts, also found by 0xc0ffEE, 0xsanson, berndartmueller, BowTiedWardens, csanuragjain, defsec, IllIllI, joestakey, Kenshin, Picodes, shenwilly, Sm4rty, unforgiven, and xiaoming90_

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L302-L308>

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2Nft.sol#L11-L18>

### Vulnerability Details

Putty uses ERC721 `safeTransfer` and `safeTransferFrom` throughout the codebase to ensure that ERC721 tokens are not transferred to non ERC721 receivers. However, the initial position mint in `fillOrder` uses `_mint` rather than `_safeMint` and does not check that the receiver accepts ERC721 token transfers:

[`PuttyV2#fillOrder`](https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L302-L308)

```solidity
        // create long/short position for maker
        _mint(order.maker, uint256(orderHash));

        // create opposite long/short position for taker
        bytes32 oppositeOrderHash = hashOppositeOrder(order);
        positionId = uint256(oppositeOrderHash);
        _mint(msg.sender, positionId);
```

[`PuttyV2Nft#_mint`](https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2Nft.sol#L11-L18)

```solidity
    function _mint(address to, uint256 id) internal override {
      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-putty)

---

### Example 3: M-1: [Tomo-M3] Use safeMint instead of mint for ERC721

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

### Example 4: [M-07] NFT of NFT collection or NFT drop collection can be locked when calling _mint or mintCountTo function to mint it to a contract that does not support ERC721 protocol

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by rbserver, also found by 0xc0ffEE, 0xsolstars, berndartmueller, Bnke0x0, brgltd, cccz, CodingNameKiki, Deivitto, Diraco, Dravee, durianSausage, erictee, ignacio, IllIllI, joestakey, KIntern&#95;NA, Lambda, LeoS, Noah3o6, oyc&#95;109, ReyAdmirado, Rohan16, Rolezn, Sm4rty, Treasure-Seeker, zeesaw, and zkhorse_

<https://github.com/code-423n4/2022-08-foundation/blob/main/contracts/NFTCollection.sol#L262-L274>

<https://github.com/code-423n4/2022-08-foundation/blob/main/contracts/NFTDropCollection.sol#L171-L187>

### Impact

When calling the following `_mint` or `mintCountTo` function for minting an NFT of a NFT collection or NFT drop collection, the OpenZeppelin's `ERC721Upgradeable` contract's [`_mint`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/token/ERC721/ERC721Upgradeable.sol#L284-L296) function is used to mint the NFT to a receiver. If such receiver is a contract that does not support the ERC721 protocol, the NFT will be locked and cannot be retrieved.

<https://github.com/code-423n4/2022-08-foundation/blob/main/contracts/NFTCollection.sol#L262-L274>

      function _mint(string calldata tokenCID) private onlyCreator returns (uint256 tokenId) {
        require(bytes(tokenCID).length != 0, "NFTCollection: tokenCID is required");
        require(!cidToMinted[tokenCID], "NFTCollection: NFT was already minted");
        unchecked {
          // Number of tokens cannot overflow 256 bits.
          tokenId = ++latestToke

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-foundation)

---

### Example 5: M-7: Minting inconsistencies on FootiumPlayer and FootiumClub

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

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

