# OtterSec - Audit Findings

## Overview

**Total Findings**: 2,273 (4.50% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 430 | 346 | 1497 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|

---

## Notable Findings

### 1. Denial Of Slashing

**Protocol**: Ethos EVM | **Impact**: HIGH

## Vulnerability Report: verifyDoubleSigning

`verifyDoubleSigning` is vulnerable to gas griefing attacks, allowing a malicious operator to evade slashing. This vulnerability stems from the linear complexity \( O(N) \) of `verifyDoubleSigning`, where \( N \) denotes the length of the delegators array (`delegatedValidators`). The complexity arises from the loop that iterates over the delegated validators to check for evidence of double-signing. The malicious operator may repeatedly invoke `updateDelegation` with the same operator and consumer chain, thereby increasing the length of the delegato...

---

### 2. Inconsistencies Due to Zero Share Amount Value

**Protocol**: Walrus Contracts | **Impact**: HIGH

## Withdrawal Request Issue in Staking Pool

`staking_inner::request_withdraw_stake` does not explicitly prevent a withdrawal request with a `share_amount` of zero. This oversight may allow a malicious user to manipulate the staking pools share-to-asset ratio by withdrawing a small principal or leaving it.

Furthermore, there is a possibility of a denial-of-service attack when `share_amount` is zero in `exchange_rate::convert_to_wal_amount`, due to division by zero when the function performs a division by `share_amount` to compute the WAL equivalent. Specifically, this affects epoch advanceme...

---

### 3. Missing Activation Epoch Check in Join

**Protocol**: Walrus Contracts | **Impact**: HIGH

## Vulnerability in StakedWal Joining Protocol

When joining a `StakedWal`, it must have the same `node_id`, `activation_epoch`, and `state`. However, for a `StakedWal` in the withdrawal state, only the `withdraw_epoch` is checked, while the activation epoch check is missing. Since the share amount is calculated based on the activation epoch, this omission results in incorrect reward calculations, allowing an attacker to gain additional benefits.

## Source Code Reference

```rust
public fun join(sw: &mut StakedWal, other: StakedWal) {
    assert!(sw.node_id == other.node_id, EMetadataMismatch...

---

### 4. Violation of Protocol Integrity via Emission Removal

**Protocol**: Exponent Generic Standard | **Impact**: HIGH

## Vulnerability Report

## Summary
The vulnerability concerns the potential for an emission to be removed from SyMeta in a way that breaks the integrity of the system. 

## Details
The **Position** structure tracks the state of a users position, including their amount and a list of rewards, which are tied to emissions. Each **Reward** in **Position** corresponds to an **Emission** on SyMeta, tracked by its *mint* and *last_seen_share_index*, which is saved in **Reward**. 

The `Position::ensure_trackers` function ensures that the position has a corresponding reward entry for every emission t...

---

### 5. Bypassing of NFT Collection Integrity Checks

**Protocol**: Claynosaurz | **Impact**: HIGH

## Staking Action Vulnerability

The `staking_action::stake` function fails to properly verify the collection associated with the staked NFT. Currently, the function checks whether the `collection.key` field in `nft_metadata` matches a predefined collection address (`CLAYNO_COLLECTION_ADDRESS`). However, this validation is insufficient, as it only checks the key field of the collection structure but overlooks the `verified` field. The `verified` field ensures that the collection has been officially validated by the authority responsible for the collection.

## Code Snippet

```rust
/// Stakes ...

---

### 6. Incorrect ETH Fee Handling

**Protocol**: Mayan EVM | **Impact**: HIGH

## SwiftSource Refund Order Vulnerability

In `SwiftSource::refundOrder`, the function handles refunds in two scenarios: 
- Native Cryptocurrency (ETH) when `tokenIn == address(0)`
- ERC20 tokens for all other addresses.

The vulnerability arises because native ETH is transferred via `payEth` instead of passing it as `msg.value` when interacting with the `FeeManager`. If native ETH is sent utilizing a direct transfer (`payEth`), the receiving contract may not recognize it, resulting in incorrect accounting.

> _src/swift/SwiftSource.sol solidity_

```solidity
function refundOrder(bytes memory ...

---

### 7. Improper Length Check and Encoding Flaw

**Protocol**: Mayan EVM | **Impact**: HIGH

## Issues in postBatch Function within SwiftDest

There are two significant issues in the `postBatch` function within `SwiftDest`. 

## Issue 1: Incorrect Length Check

Firstly, the length check comparing the length of `unlockMsg` against the `UNLOCK_MSG_SIZE` constant is incorrect, as it reverts if they are equal. This implies that a valid unlock message will have a length different from `UNLOCK_MSG_SIZE`, which is counterintuitive since a valid message should match a predefined size. As a result, valid unlock messages will be rejected.

```solidity
// src/swift/SwiftDest.sol
function postBat...

---

### 8. Preventing Minting via Front-Running Payload

**Protocol**: Lombard | **Impact**: HIGH

## validate_and_store_payload in Consortium

`validate_and_store_payload` in Consortium validates and records the usage of a payload. However, since it is public, anyone may call it. This creates a potential front-running attack, where a malicious actor may interfere with the expected execution of a valid transaction. 

Thus, if a user submits a valid transaction that calls `validate_and_store_payload(payload, proof)` to validate the payload, the attacker may front-run this with a similar call to `validate_and_store_payload`, which executes before the users call.

```rust
>_ move/consortium/s...

---

### 9. Improper Handling of Empty Items In Circular Buffer

**Protocol**: Code Inc. | **Impact**: HIGH

## CircularBuffer::contains

The `CircularBuffer::contains` method checks whether a specific item exists within the buffer. However, it does not ignore empty items when checking for a given item. 

In the context of this `CircularBuffer`, empty items are represented as arrays filled with default values (`[0; M]`). These empty slots may skew the behavior of `contains` if they are not properly handled. Without ignoring empty items, the search may incorrectly match these slots and return a false positive. This is especially problematic when an item (such as `[0; M]`) is used to represent an empty...

---

### 10. Bypassing Funds Repayment via Double Upscaling

**Protocol**: Thala Swap + Math V2 | **Impact**: HIGH

## Vulnerability Report: Double Upscaling in pay_flashloan

## Description

The vulnerability arises from double upscaling during the repayment process in `pay_flashloan` when handling meta-stable pools. Specifically, `pay_flashloan` upscales `balance_after_flashloan` twice. When handling meta-stable pools, the funds are multiplied by their value derived from an oracle. As a result, the post-repayment invariant computation utilizes an incorrectly scaled value.

## Code Snippet

> _ thalaswap_v2/sources/pool.move rust

```rust
public fun pay_flashloan(assets: vector<FungibleAsset>, loan: Flashl...

---

### 11. Inheritance Conflict in Decimals Method

**Protocol**: Plume Network | **Impact**: HIGH

## Vulnerability in Solidity's Inheritance Hierarchy

The vulnerability lies in how Soliditys inheritance hierarchy and the `super` keyword determine which parent implementation is prioritized when overriding a function. 

Here, `YieldToken` inherits both `YieldDistributionToken` and `ERC4626`, both of which implement the `decimals` function.

```solidity
// smart-wallets/src/token/YieldToken.sol
contract YieldToken is YieldDistributionToken, ERC4626, WalletUtils, IYieldToken, IComponentToken {
    [...]
    /// @inheritdoc ERC20
    function decimals() public view override(YieldDistributionT...

---

### 12. Inconsistent Function Override Logic

**Protocol**: Plume Network | **Impact**: HIGH

## Vulnerability Overview

The vulnerability concerns inconsistencies that arise when certain functions in the ERC4626 implementation define custom logic without overriding the dependent functions in the base ERC4626 contract to reflect this custom logic. 

## YieldToken Custom Logic

`YieldToken` redefines `convertToShares` and `convertToAssets` with custom logic that differs from the inherited ERC4626 contracts expectations. These methods directly impact proportionality calculations between assets and shares.

```solidity
// smart-wallets/src/token/YieldToken.sol
function convertToShares(
 ...

---

### 13. Yield Distribution Share Inflation

**Protocol**: Plume Network | **Impact**: HIGH

## Issue Overview

The issue concerns how `receiveYield` in `YieldToken` interacts with the contracts accounting, specifically the mechanism used to track user share values relative to the underlying assets. In the current implementation, when `receiveYield` is called, it increases both the `yieldPerTokenStored` and the total `currencyToken` held by the `YieldToken` contract.

## Code Snippet

```solidity
> _ smart-wallets/src/token/YieldToken.sol solidity
function receiveYield(IAssetToken assetToken, IERC20 currencyToken, uint256 currencyTokenAmount) external {
    [...]
    _depositYield(cu...

---

### 14. Improper Mint Limit Reset

**Protocol**: Lombard Finance | **Impact**: HIGH

In `treasury::mint_and_transfer`, the line `left = limit;` modifies the local variable `left`. However, `get_cap_mut(treasury, ctx.sender())` returns a mutable reference to the `MinterCap` object associated with the sender. This implies `left` is a mutable reference, which refers to the actual value in the `MinterCap` structure. Thus, currently, the function is only re-assigning the `left` variable with a reference to the `limit` field of the structure rather than updating the `left` field. 

So, to properly update the value of `left` within the `MinterCap` structure, it needs to be de-referen...

---

### 15. Sequence Misalignment in Allocations Array

**Protocol**: Kamino KVault | **Impact**: HIGH

## Sequence Mismatch Issue

There is a sequence mismatch between the `vault_allocation_strategy` and `invested.allocations` arrays in `amounts_invested`. 

`vault_allocation_strategy` represents the vaults target allocation strategy and contains all allocations, including active and inactive ones (inactive entries have `Pubkey::default` as the reserve key). `invested.allocations`, on the other hand, reflects the current state of investments in the vault.

## Code Snippet

```rust
pub fn amounts_invested<'info, T>(
    vault: &VaultState,
    mut reserves_iter: impl Iterator<Item = T>,
    slo...

---


## Statistics

- Total findings from OtterSec: 2,273
- Last updated: 2026-01-29

