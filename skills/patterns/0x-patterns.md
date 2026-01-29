# 0x Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 3 | 0 |

**Common Sources**: Code4rena, MixBytes, Shieldify, Sherlock

---

## Detection Checklist

- [ ] Check for 0x vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

_Submitted by GreyArt, also found by 0xDjango, CertoraInc, cmichel, rayn, TomFrenchBlockchain, and WatchPug_

[Collateral.sol#L82-L91](https://github.com/code-423n4/2022-03-prepo/blob/main/contracts/core/Collateral.sol#L82-L91)<br>

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

### Proof of Concept

*   Attacker deposits 2 wei (so that it is greater than min fee) to mint 1 share
*   Attacker transfers exorbitant amount to `_strategyController` to greatly inflate the share’s price. Note that the `_strategyController` deposits its entire balance to the strategy when its `deposit()` function is called.
*   Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

```jsx
it("will cause 0 share issuance", async () => {
	// 1. first user deposits 2 wei because 1 wei will be deducted for fee
	let firstDepositAmount = ethers.BigNumber.from(2)
	await transferAndApproveForDeposit(
	    user,
	    collateral.address,
	    firstDepositAmount
	)
	
	await collateral
	    .connect(user)
	    .deposit(firstDepositAmount)
	
	// 2. do huge transfer of 1M to strategy to controller
	// to 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-prepo)

---

### Example 2: H-4: Bought/Purchased Token Can Be Sent To Attacker's Wallet Using 0x Adaptor

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/75 

## Found by 
xiaoming90

## Summary

The lack of recipient validation against the 0x order within the 0x adaptor (`ZeroExAdapter`) allows the purchased/output tokens of the trade to be sent to the attacker's wallet.

## Vulnerability Detail

#### Background

**How does the emergency vault settlement process work?**

1. Anyone can call the `settleVaultEmergency` function to trigger the emergency vault settlement as it is permissionless
2. The `_getEmergencySettlementParams` function will calculate the excess BPT tokens within the vault to be settled/sold
3. The amount of excess BPT tokens will be converted to an equivalence amount of strategy tokens to be settled
4. The strategy tokens will be settled by withdrawing staked BPT tokens from Aura Finance back to the vault for redemption.
5. The vault will then redeem the BTP tokens from Balancer to redeem its underlying assets (WETH and stETH)
6. The primary and secondary assets of the vault are WETH and stETH respectively. The secondary asset (stETH) will be traded for the primary asset (WETH) in one of the supported DEXes. In the end, only the primary assets (WETH) should remain within the vault.
7. The WETH within the vault will be sent to Notional, and Notional will mint the asset tokens (cEther) for the vault in return.
8. After completing the emergency vault settlement process, the vault will gain asset tokens (cEther) after settling/selling its 

*[Content truncated...]*

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

### Example 4: [M-04] Lender can trade claimToken in a malicious way to steal the borrower’s money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/modules/credit/SpigotedLine.sol#L106-L112
https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/utils/SpigotedLineLib.sol#L75-L85


## Vulnerability details

## Impact

Lender can trade claimToken in a malicious way to steal the borrower's money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData.

In the design of the protocol, the lender can use the function claimAndRepay(), the lender can take claimToken by spigot.claimEscrow and then trade the claimToken to the CreditTOken via ZeroEx exchange, then repay the credit. 

```
function claimAndRepay(address claimToken, bytes calldata zeroExTradeData) external
        whileBorrowing
        nonReentrant
        returns (uint256) { 

...
// Line 106 - Line 112
uint256 newTokens = claimToken == credit.token ?
          spigot.claimEscrow(claimToken) :  // same asset. dont trade
          _claimAndTrade(                   // trade revenue token for debt obligation
              claimToken,
              credit.token,
              zeroExTradeData
          );
...
// Line 128 - Line 130 
 credits[id] = _repay(credit, id, repaid);

        emit RevenuePayment(claimToken, repaid);

...

}

```

```
function _claimAndTrade(
      address claimToken,
      address targetToken,
      bytes calldata zeroExTradeData
    )
        internal
        returns (uint256)
    {
        (uint256 tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 5: [L-03] Merkle Root Is Mutable Mid-Airdrop

**Source**: Shieldify
**Protocol**: Spellborne S2Airdrop
**Impact**: LOW

**Details**:

## Severity

Low Risk

## Description

The owner can change `merkleRoot` at any time. Already-registered users remain unaffected (state stored), but future registrations switch to the new root, which can change eligibility without warning.

## Location of Affected Code

File: [src/S2Airdrop.sol#L160-L163](https://github.com/SlothFi/s2-airdrop/blob/fa331efe0bc68794537d6df645241f61be14be7b/src/S2Airdrop.sol#L160-L163)

```solidity
function setMerkleRoot(bytes32 root) public onlyOwner {
    merkleRoot = root;
    emit MerkleRootSet(root);
}
```

## Impact

Trust/governance risk: operator can exclude/replace users mid-campaign; users and integrators cannot assume a stable eligibility set after launch.

## Recommendation

Freeze the root after a start time, or gate changes behind a timelock/multisig and communicate immutability guarantees. Optionally add a phase ID and store it to make root changes explicit on-chain.

## Team Response

Acknowledged.

## [I-01] Hardcoded Token Address Limits Deployment To A Specific Chain

## Severity

Informational Risk

## Description

The contract uses a hardcoded token address `0x133879524DDb38582cf0b93D10aDB789601Ff397` as a constant, which corresponds to the BORNE ERC-20 token on [Avalanche mainnet](https://avascan.info/blockchain/c/token/0x133879524DDb38582cf0b93D10aDB789601Ff397). This implementation prevents the contract from being deployed on other blockchain networks where the BORNE token exists at different addresses.

For example, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Spellborne-S2Airdrop-Security-Review.md)

---

### Example 6: Remove unnecessary ETH handling logic for maker asset

**Source**: MixBytes
**Protocol**: Barter DAO
**Impact**: LOW

**Details**:

##### Description
In the [`callExecutor()`](https://github.com/BarterLab/argon/blob/f653d58132124854db42d2bd93d0c6b91da2c398/contracts/InchFusionBarterResolver.sol#L93-L123) function, there's logic that checks if the maker asset is ETH and skips token transfer:

```solidity
if (makerAsset.get() != address(0) && 
    makerAsset.get() != address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)
   ) {
    IERC20(makerAsset.get()).safeTransfer(address(executor), makingAmount);
}
```

This logic appears to be leftover code from UniswapX solver implementation and is not needed in the context of 1inch Fusion orders.
<br/>
##### Recommendation
We recommend removing unnecessary logic.

---

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Barter%20DAO/InchFusionBarterResolver/README.md#3-remove-unnecessary-eth-handling-logic-for-maker-asset)

---

### Example 7: Redundant `afterInitialize()` Function

**Source**: MixBytes
**Protocol**: Algebra Finance
**Impact**: LOW

**Details**:

##### Description
The `LimitOrderManager.afterInitialize` function exposed to plugins duplicates the exact same initialization that `LimitOrderManager.place()` already performs for any uninitialized pool. Since `place()` calls `_initialize()` when `initialized[pool] == false`, there is no scenario in which a pool remains uninitialized by the time a limit order is placed. Keeping `afterInitialize` merely expands the public API surface and increases maintenance complexity without providing any real benefit.
<br/>
##### Recommendation
We recommend removing the `afterInitialize` endpoint and relying exclusively on the in-place initialization logic within `place()`.

> **Client's Commentary:**
> Commit: https://github.com/cryptoalgebra/plugins-monorepo/commit/f8103fde4248decd05975e5523174e5d199c9574

---

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Algebra%20Finance/Limit%20Order%20Plugin/README.md#11-redundant-afterinitialize-function)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
