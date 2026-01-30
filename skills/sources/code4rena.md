# Code4rena - Audit Findings

## Overview

**Total Findings**: 12,292 (24.33% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1637 | 3828 | 4279 | 2548 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Business Logic | 102 |
| Wrong Math | 55 |
| Front-Running | 47 |
| Fee On Transfer | 40 |
| Reentrancy | 35 |
| Validation | 31 |
| DOS | 25 |
| Oracle | 22 |
| Don't update state | 20 |
| Access Control | 19 |

---

## Notable Findings

### 1. [H-01] Chained signature with checkpoint usage disabled can bypass all checkpointer validation

**Protocol**: Sequence | **Impact**: HIGH

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/auth/BaseSig.sol# L88>

### Finding description and impact

Consider a scenario where (1) the wallet is behind the checkpointer and (2) a chained signature is used; however, bit 6 (`0x40` - the checkpointer usage flag) is zero. As a result, when `BaseSig.recover` is called the below if-block on `BaseSig.sol:88-106` will be skipped:
```

    if (signatureFlag & 0x40 == 0x40 && _checkpointer == address(0)) {
      // Override the checkpointer
      // not ideal, but we don't have much room i...

---

### 2. [H-03] `ExecuteRequest`’s are not properly removed from the context queue

**Protocol**: Initia | **Impact**: HIGH

The `minievm` cosmos precompile allows a Solidity contract to dispatch a Cosmos SDK message, which is executed after the EVM call is successfully executed.

This is done by calling the cosmos precompile with the `execute_cosmos` or `execute_cosmos_with_options` function selector and passing the encoded message. This will wrap the message with `ExecuteRequest` and append it to the messages slice in the context with the key `types.CONTEXT_KEY_EXECUTE_REQUESTS`.

[`minievm:x/evm/precompiles/cosmos/contract.go# L287-L294`](https://github.com/initia-labs/minievm/blob/744563dc6a642f054b4543db008df22...

---

### 3. [H-03] User can bypass `MAX_EXPIRATION` when extend expiration

**Protocol**: Initia | **Impact**: HIGH

<https://github.com/code-423n4/2025-01-initia-move/blob/a96f5136c4808f6968564a4592fe2d6ac243a233/usernames-module/sources/name_service.move# L483>

### Finding Description and Impact

In the `extend_expiration` function, the validation for the duration is incorrect, allowing the user to bypass `MAX_EXPIRATION`:
```

 let expiration_date = metadata::get_expiration_date(token);
        let new_expiration_date = if (expiration_date > timestamp) {
            expiration_date + duration
        } else {
            timestamp + duration
        };

        assert!(
=>            new_expiration_date ...

---

### 4. [H-01] Invalid `DISPUTED_L2_BLOCK_NUMBER` is passed to VM

**Protocol**: Optimism | **Impact**: HIGH

The span of the game tree at split depth is far larger than the length between the starting block and the claimed block. When `starting block + trace index + 1 > claimed block`, honest party should continue to commit to the root of the claimed block. However, the `DISPUTED_L2_BLOCK_NUMBER` passed to the VM is always `starting block + trace index + 1`, which means the op-program (at inter-block perspective) will not stop until it reaches the l2 safe head (corresponding to parenthash), and if the claimed block is earlier than the safe head, it can be challenged and will be considered invalid.

#...

---

### 5. [H-01] Most users won't be able to claim their share of Uniswap fees

**Protocol**: Vultisig | **Impact**: HIGH

Users should be able to claim Uniswap fees for their current liquidity position regardless of their pending vestings, or cliff. But most users won't be able to claim those Uniswap fees.

It is also possible that they won't be able to claim their vesting if they accumulate sufficient unclaimed Uniswap fees.

### Vulnerability Details

The root issue is that the `claim()` function collects ALL the owed tokens at once, including the ones from the burnt liquidity, but also the fees corresponding to ALL positions:

```solidity
    (uint128 amountCollected0, uint128 amountCollected1) = pool.collect(...

---

### 6. [H-02] Division before multiplication could lead to users losing 50% in `WithdrawalQueue`

**Protocol**: Gondi | **Impact**: HIGH

In the `_getAvailable()` function, the calculation performs division before multiplication, which could result in precision loss. The consequence is that users may not be able to withdraw the amount they should receive, leaving some funds locked in the `WithdrawalQueue`.

```solidity
// @audit division before multiplication
function _getAvailable(uint256 _tokenId) private view returns (uint256) {
    return getShares[_tokenId] * _getWithdrawablePerShare() - getWithdrawn[_tokenId]; 
}

/// @notice Get the amount that can be withdrawn per share.
function _getWithdrawablePerShare() private view r...

---

### 7. [H-04] Since you can reroll with a different fighterType than the NFT you own, you can reroll bypassing maxRerollsAllowed and reroll attributes based on a different fighterType

**Protocol**: AI Arena | **Impact**: HIGH

Can reroll attributes based on a different fighterType, and can bypass maxRerollsAllowed.

### Proof of Concept

`maxRerollsAllowed` can be set differently depending on the `fighterType`. Precisely, it increases as the generation of fighterType increases.

```solidity
function incrementGeneration(uint8 fighterType) external returns (uint8) {
    require(msg.sender == _ownerAddress);
@>  generation[fighterType] += 1;
@>  maxRerollsAllowed[fighterType] += 1;
    return generation[fighterType];
}
```

The `reRoll` function does not verify if the `fighterType` given as a parameter is actually the ...

---

### 8. [H-01] The 51% majority can hijack the party's precious tokens through an arbitrary call proposal if the `AddPartyCardsAuthority` contract is added as an authority in the party.

**Protocol**: Party Protocol | **Impact**: HIGH

### Pre-requisite knowledge & an overview of the features in question

1. **The [**`AddPartyCardsAuthority`**](https://github.com/code-423n4/2023-10-party/blob/main/contracts/authorities/AddPartyCardsAuthority.sol) contract:** The `AddPartyCardsAuthority` contract is a contract designed to be integrated into a Party and it has only one purpose - to mint new party governance NFT tokens for party members.
    - The party has to add this contract as an authority before it can start minting new party governance NFT tokens for users.
    - The `AddPartyCardsAuthority` contract is deployed on the ma...

---

### 9. [H-16] Attacker can block LayerZero channel due to variable gas cost of saving payload

**Protocol**: Tapioca DAO | **Impact**: HIGH

<https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/usd0/BaseUSDO.sol#L399> 

<https://github.com/Tapioca-DAO/tapiocaz-audit/blob/master/contracts/tOFT/BaseTOFT.sol#L442> 

<https://github.com/Tapioca-DAO/tap-token-audit/blob/main/contracts/tokens/BaseTapOFT.sol#L52>

This is an issue that affects `BaseUSDO`, `BaseTOFT`, and `BaseTapOFT` or all the contracts which are sending and receiving LayerZero messages.
The consequence of this is that anyone can with low cost and high frequency keep on blocking the pathway between any two chains, making the whole system unusable.

###...

---

### 10. [H-01] The call to `MsgValueSimulator` with non zero `msg.value` will call to sender itself which will bypass the `onlySelf` check

**Protocol**: zkSync | **Impact**: HIGH

First, I need to clarify, there may be more serious ways to exploit this issue. Due to the lack of time and documents, I cannot complete further exploit. The current exploit has only achieved the impact in the title. I will expand the possibility of further exploit in the poc chapter.

The call to MsgValueSimulator with non zero msg.value will call to sender itself with the msg.data. It means that if you can make a contract or a custom account call to specified address with non zero msg.value (that's very common in withdrawal functions and smart contract wallets), you can make the contract/acc...

---

### 11. [H-09] Attacker can steal 99% of total balance from any reward token in any Staking contract

**Protocol**: Popcorn | **Impact**: HIGH

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L108-L110>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L483-L503> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L296-L315>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L351-L360> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L377-L378>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L390...

---

### 12. [H-02] Stealing fund by applying reentrancy attack on removeCollateral, startLiquidationAuction, and purchaseLiquidationAuctionNFT

**Protocol**: Backed Protocol | **Impact**: HIGH

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L444


## Vulnerability details

## Impact

By applying reentrancy attack involving the functions `removeCollateral`, `startLiquidationAuction`, and `purchaseLiquidationAuctionNFT`, an Attacker can steal large amount of fund.

## Proof of Concept

 - Bob (a malicious user) deploys a contract to apply the attack. This contract is called `BobContract`. Please note that all the following transactions are going to be done in one transaction.
 - BobContract takes a flash loan o...

---

### 13. [H-03] First depositor can break minting of shares

**Protocol**: Caviar | **Impact**: HIGH

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

### Proof of Concept

In `Pair.add()`, the amount of LP token minted is calculated as

```solidity
function addQuote(uint256 baseTokenAmount, uint256 fractionalTokenAmount) public view returns (uint256) {
    uint256 lpTokenSupply = lpToken.totalSup...

---

### 14. [H-01] Reentrancy in buy function for ERC777 tokens allows buying funds with considerable discount

**Protocol**: Caviar | **Impact**: HIGH

<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L95><br>
<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L137><br>
<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L172><br>
<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L203>

Current implementation of functions `add`, `remove`, `buy` and `sell` first transfer fractional tokens, and then base tokens.

If this base toke...

---

### 15. [H-11] Not enough margin pulled or burned from user when adding to a position

**Protocol**: Tigris Trade | **Impact**: HIGH

When adding to a position, the amount of margin pulled from the user is not as much as it should be, which leaks value from the protocol, lowering the collateralization ratio of `tigAsset`.

### Proof of Concept

In `Trading.addToPosition` the `_handleDeposit` function is called like this:

```js
_handleDeposit(
    _trade.tigAsset,
    _marginAsset,
    _addMargin - _fee,
    _stableVault,
    _permitData,
    _trader
);
```

The third parameter with the value of `_addMargin - _fee` is the amount pulled (or burned in the case of using `tigAsset`) from the user. The `_fee` value is calculated ...

---


## Statistics

- Total findings from Code4rena: 12,292
- Last updated: 2026-01-29

