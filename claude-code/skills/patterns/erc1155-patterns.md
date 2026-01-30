# ERC1155 Security Patterns

## Overview

**Frequency**: 17 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 15 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, ConsenSys

---

## Detection Checklist

- [ ] Check for erc1155 vulnerabilities in all external functions
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

### Example 2: Re-entrancy issue for ERC1155 ✓ Fixed

**Source**: ConsenSys
**Protocol**: Bridge Mutual
**Impact**: HIGH

**Details**:

#### Resolution



Addressed by moving `isNFTDistributed = true;` before the token transfers and only transferring tokens to the message sender.


#### Description


ERC1155 tokens have callback functions on some of the transfers, like `safeTransferFrom`, `safeBatchTransferFrom`. During these transfers, the `IERC1155ReceiverUpgradeable(to).onERC1155Received` function is called in the `to` address.


For example, `safeTransferFrom` is used in the `LiquidityMining` contract:


**code/contracts/LiquidityMining.sol:L204-L224**



```
function distributeAllNFT() external {
    require(block.timestamp > getEndLMTime(),
        "2 weeks after liquidity mining time has not expired");
    require(!isNFTDistributed, "NFT is already distributed");

    for (uint256 i = 0; i < leaderboard.length; i++) {
        address[] memory \_groupLeaders = groupsLeaders[leaderboard[i]];

        for (uint256 j = 0; j < \_groupLeaders.length; j++) {
            \_sendNFT(j, \_groupLeaders[j]);
        }
    }

    for (uint256 i = 0; i < topUsers.length; i++) {
        address \_currentAddress = topUsers[i];
        LMNFT.safeTransferFrom(address(this), \_currentAddress, 1, 1, "");
        emit NFTSent(\_currentAddress, 1);
    }

    isNFTDistributed = true;
}

```
During that transfer, the `distributeAllNFT`  function can be called again and again. So multiple transfers will be done for each user.


In addition to that, any receiver of the tokens can revert the transfer. If that happens, nobody wil

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2021/03/bridge-mutual/)

---

### Example 3: [H-01] StandardPolicyERC1155.sol returns amount == 1 instead of amount == order.amount

**Source**: Code4rena
**Protocol**: Blur Exchange
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-blur/blob/main/contracts/matchingPolicies/StandardPolicyERC1155.sol#L12-L36
https://github.com/code-423n4/2022-10-blur/blob/main/contracts/BlurExchange.sol#L154-L161


## Vulnerability details

## Impact

The ```canMatchMakerAsk``` and ```canMatchMakerBid``` functions in ```StandardPolicyERC1155.sol``` will only return 1 as the amount instead of the order.amount value. This value is then used in the ```_executeTokenTransfer``` call during the execution flow and leads to only 1 ERC1155 token being sent. A buyer matching an ERC1155 order wih amount > 1 would expect to receive amount of tokens if they pay the order's price. The seller, who might also expect more than 1 tokens to be sent, would have set the order's price to be for the amount of tokens and not just for 1 token.

The buyer would lose overspent ETH/WETH to the seller without receiving all tokens as specified in the order.

## Proof of Concept

[StandardPolicyERC1155.sol:canMatchMakerAsk](https://github.com/code-423n4/2022-10-blur/blob/main/contracts/matchingPolicies/StandardPolicyERC1155.sol#L12-L36)

```solidity
    function canMatchMakerAsk(Order calldata makerAsk, Order calldata takerBid)
        external
        pure
        override
        returns (
            bool,
            uint256,
            uint256,
            uint256,
            AssetType
        )
    {
        return (
            (makerAsk.side != takerBid.side) &&
            (makerAsk.pay

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-blur)

---

### Example 4: [H-01] Truncation in `OrderValidator` can lead to resetting the fill and selling more tokens

**Source**: Code4rena
**Protocol**: OpenSea
**Impact**: HIGH

**Details**:

[OrderValidator.sol#L228](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L228)<br>
[OrderValidator.sol#L231](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L231)<br>
[OrderValidator.sol#L237](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L237)<br>
[OrderValidator.sol#L238](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L238)<br>

A partial order's fractions (`numerator` and `denominator`) can be reset to `0` due to a truncation. This can be used to craft malicious orders:

1.  Consider user Alice, who has 100 ERC1155 tokens, who approved all of their tokens to the `marketplaceContract`.
2.  Alice places a `PARTIAL_OPEN` order with 10 ERC1155 tokens and consideration of ETH.
3.  Malory tries to fill the order in the following way:
    1.  Malory tries to fill 50% of the order, but instead of providing the fraction `1 / 2`, Bob provides `2**118 / 2**119`. This sets the `totalFilled` to `2**118` and `totalSize` to `2**119`.
    2.  Malory tries to fill 10% of the order, by providing `1 / 10`. The computation `2**118 / 2**119 + 1 / 10` is done by "cross multiplying" the denominators, leading to the acutal fraction being `numerator = (2**118 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-opensea-seaport)

---

### Example 5: [H-02] OZ ERC1155Supply vulnerability

**Source**: Code4rena
**Protocol**: Overlay Protocol
**Impact**: HIGH

**Details**:

_Submitted by pauliax, also found by hubble and defsec_

#### Impact

Overlay uses OZ contracts version 4.3.2:

```yaml
  dependencies:
    - OpenZeppelin/openzeppelin-contracts@4.3.2
```

and has a contract that inherits from ERC1155Supply:

```solidity
  contract OverlayV1OVLCollateral is ERC1155Supply
```

This version has a recently discovered vulnerability:
<https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-wmpv-c2jp-j2xg>

In your case, function unwind relies on totalSupply when calculating `\_userNotional`, `\_userDebt`, `\_userCost`, and `\_userOi`, so a malicious actor can exploit this vulnerability by first calling 'build' and then on callback 'unwind' in the same transaction before the total supply is updated.

#### Recommended Mitigation Steps

Consider updating to a patched version of 4.3.3.

**[mikeyrf (Overlay) confirmed](https://github.com/code-423n4/2021-11-overlay-findings/issues/127)**

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-overlay)

---

### Example 6: [H-02] An attacker is able to hijack any ERC721 / ERC1155 he borrows because guard is missing validation on the address supplied to function call `setFallbackHandler()`

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

### Example 7: [H-03] Migration: no check that user-supplied `proposalId` and `vault` match

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by kenzo, also found by 0x1f8b, bin2chen, codexploder, dipp, minhtrng, and smiling&#95;heretic_

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L111>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L124>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L143>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L157>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L164>

### Vulnerability Details

In Migration, when joining or leaving a migration proposal, Fractional does not check whether the user supplied `proposalId` and `vault` match the actual vault that the proposal belongs to.

This allows the user to trick the accounting.

### Impact

Loss of funds for users.

Malicious users can withdraw tokens from proposals which have not been committed yet.

### Proof of Concept

Let's say Vault A's FERC1155 token is called TOKEN.
Alice has deposited 100 TOKEN in Migration to Vault A on proposal ID 1.

Now Malaclypse creates Vault B with token ERIS as FERC1155 and mints 100 tokens to himself.
He then calls Migration's `join` with amount as 100, Vault B as `vault`, proposal ID as 1.
The function [will get](https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L111) ERIS as the token to deposit.
It [will pull](https://github.com/code-423n4/2022-07-fractiona

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 8: [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.

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

### Example 9: [H-07] `_transferNFTs()` succeeds even if no transfer is performed

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

### Example 10: [H-01] It is possible to create fake ERC1155 `NameWrapper` token for subdomain, which is not owned by `NameWrapper`

**Source**: Code4rena
**Protocol**: ENS
**Impact**: HIGH

**Details**:

[NameWrapper.sol#L820-L821](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L820-L821)<br>
[NameWrapper.sol#L524](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L524)<br>
[NameWrapper.sol#L572](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L572)<br>

Due to re-entrancy possibility in `NameWrapper._transferAndBurnFuses` (called from `setSubnodeOwner` and `setSubnodeRecord`), it is possible to do some stuff in `onERC1155Received` right after transfer but before new owner and new fuses are set. This makes it possible, for example, to unwrap the subdomain, but owner and fuses will still be set even for unwrapped domain, creating fake `ERC1155` `NameWrapper` token for domain, which is not owned by `NameWrapper`.

Fake token creation scenario:

1.  `Account1` registers and wraps `test.eth` domain
2.  `Account1` calls `NameWrapper.setSubnodeOwner` for `sub.test.eth` subdomain with `Account1` as owner (to make NameWrapper owner of subdomain)
3.  `Contract1` smart contract is created, which calls unwrap in its `onERC1155Received` function, and a function to send `sub.test.eth` ERC1155 NameWrapper token back to `Account1`
4.  `Account1` calls `NameWrapper.setSubnodeOwner` for `sub.test.eth` with `Contract1` as new owner, which unwraps domain back to `Account1` but 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-ens)

---

### Example 11: [M-08] Assets in a Safe can be lost

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

### Example 12: [H-03] An attacker can hijack any ERC1155 token he rents due to a design issue in reNFT via reentrancy exploitation

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

### Example 13: [H-13] Anyone can wipe complete state of any collateral at any point

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/ClearingHouse.sol#L114-L167><br>
<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/CollateralToken.sol#L524-L545><br>
<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/LienToken.sol#L497-L510><br>
<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/LienToken.sol#L623-L656>

The Clearing House is implemented as an ERC1155. This is used to settle up at the end of an auction. The Clearing House's token is listed as one of the Consideration Items, and when Seaport goes to transfer it, it triggers the settlement process.

This settlement process includes deleting the collateral state hash from LienToken.sol, burning all lien tokens, deleting the idToUnderlying mapping, and burning the collateral token. **These changes effectively wipe out all record of the liens, as well as removing any claim the borrower has on their underlying collateral.**

After an auction, this works as intended. The function verifies that sufficient payment has been made to meet the auction criteria, and therefore all these variables should be zeroed out.

However, the issue is that there is no check that this safeTransferFrom function is being called after an auction has completed. In the case that it is called when there is no auction, all the auction criteria will be set to

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 14: [H-02] Forced buyouts can be performed by malicious buyers

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by cccz_

In the end function of the Buyout contract, when the buyout fails, ERC1155 tokens are sent to the proposer. A malicious proposer can start a buyout using a contract that cannot receive ERC1155 tokens, and if the buyout fails, the end function fails because it cannot send ERC1155 tokens to the proposer. This prevents a new buyout from being started.

### Proof of Concept

<https://github.com/code-423n4/2022-07-fractional/blob/8f2697ae727c60c93ea47276f8fa128369abfe51/src/modules/Buyout.sol#L224-L238>

### Recommended Mitigation Steps

Consider saving the status of the proposer after a failed buyout and implementing functions to allow the proposer to withdraw the ERC1155 tokens and eth.

**[Ferret-san (Fractional) confirmed](https://github.com/code-423n4/2022-07-fractional-findings/issues/212)** 

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-07-fractional-findings/issues/212#issuecomment-1217143098):**
 > The 1155 receiver can prevent a failed buyout from ending, which prevents a new one from starting. Agree with severity.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 15: [H-02] Loss of funds in `matchOneToManyOrders()` and `takeOrders()` and `matchOrders()` because code don't check that different ids in one collection are different, so it's possible to sell one id multiple time instead of selling multiple id one time in one collection of order (lack of checks in `doTokenIdsIntersect()` especially for ERC1155 tokens)

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by unforgiven_

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L271-L312>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L59-L116>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L245-L294>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L118-L143>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L330-L364>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L934-L951>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L145-L164>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L171-L243>

### Impact

Function `matchOneToManyOrders()` and `takeOrders()` and `matchOrders()` suppose to match `sell order` to `buy order` and should perform some checks to ensure that user specified parameters in orders which are signed are not violated when order matching happens. but There i

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 16: [H-03] getRandomTokenIdFromFund yields wrong probabilities for ERC1155

**Source**: Code4rena
**Protocol**: NFTX
**Impact**: HIGH

**Details**:

## Handle

@cmichelio


## Vulnerability details


## Vulnerability Details

`NFTXVaultUpgradeable.getRandomTokenIdFromFund` does not work with ERC1155 as it does not take the deposited `quantity1155` into account. 

## Impact

Assume `tokenId0` has a count of 100, and `tokenId1` has a count of 1.
Then `getRandomId` would have a pseudo-random 1:1 chance for token 0 and 1 when in reality it should be 100:1.

This might make it easier for an attacker to redeem more valuable NFTs as the probabilities are off.

## Recommended Mitigation Steps

Take the quantities of each token into account (`quantity1155`) which probably requires a design change as it's currently hard to do without iterating over all tokens.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-nftx)

---

### Example 17: H-5: Adversary can break deposit queue and cause loss of funds

**Source**: Sherlock
**Protocol**: Y2K
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-03-Y2K-judging/issues/468 

## Found by 
0x52, 0xRobocop, Bauer, HonorLt, Respx, Ruhum, VAD37, bin2chen, immeas, joestakey, jprod15, libratus, ltyu, mstpr-brainbot, nobody2018, roguereddwarf, warRoom, yixxas

## Summary



## Vulnerability Detail

[Carousel.sol#L531-L538](https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L531-L538)

    function _mintShares(
        address to,
        uint256 id,
        uint256 amount
    ) internal {
        _mint(to, id, amount, EMPTY);
        _mintEmissions(to, id, amount);
    }

When processing deposits for the deposit queue, it _mintShares to the specified receiver which makes a _mint subcall.

[ERC1155.sol#L263-L278](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ca822213f2275a14c26167bd387ac3522da67fe9/contracts/token/ERC1155/ERC1155.sol#L263-L278)

    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal virtual {
        require(to != address(0), "ERC1155: mint to the zero address");

        address operator = _msgSender();
        uint256[] memory ids = _asSingletonArray(id);
        uint256[] memory amounts = _asSingletonArray(amount);

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        _balances[id][to] += amount;
        emit TransferSingle(operator, address(0), to, id, amount);

        _afterTokenTransfer(operator, address(0), to, ids, amounts, data);

   

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 17
- Examples shown: 17
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

