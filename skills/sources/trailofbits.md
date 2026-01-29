# TrailOfBits - Audit Findings

## Overview

**Total Findings**: 2,094 (4.14% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 402 | 388 | 1304 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Business Logic | 2 |
| 1/64 Rule | 2 |
| DOS | 2 |
| Reentrancy | 2 |
| Denial-Of-Service | 1 |
| Chain Reorganization Attack | 1 |
| External Contract | 1 |
| Oracle | 1 |
| Initialization | 1 |
| Front-Running | 1 |

---

## Notable Findings

### 1. Users can gain tokens during round-trip swaps

**Protocol**: Bunni v2 | **Impact**: HIGH

## Diﬃculty: Low

## Type: Data Validation

### Description

The swap functionality of the BunniSwapMath library is not accurately implemented, allowing users to gain tokens during round-trip swaps (i.e., swapping token0 for token1 and then swapping the same amount of token1 for token0).

The `computeSwap` function in the BunniSwapMath library allows users to swap tokens on a valid pool state. Given an `amountSpecified` and the swap direction, the function calculates the input tokens exchanged for the output tokens. In a zeroForOne swap, the user exchanges token0 for token1, and the pool state...

---

### 2. Users can gain free tokens through the BunniSwap swap functionality

**Protocol**: Bunni v2 | **Impact**: HIGH

## Diﬃculty: Low

## Type: Data Validation

## Description
During token swaps, users can receive a nonzero amount of output tokens even when they provide zero input tokens, allowing them to acquire free tokens without contributing any input tokens for the swap.

The `computeSwap` function in the BunniSwapMath library executes swap operations based on a user-specified token amount specified as one of the inputs to the function. As shown in figure 15.1, depending on whether the `amountSpecified` is negative or positive, the swap is configured to be an ExactIn or ExactOut swap.

```solidity
// in...

---

### 3. Missing debt validation in group burn function

**Protocol**: Radius Technology EVMAuth | **Impact**: HIGH

## Denial of Service: _burnGroupBalances Function

**Diﬃculty:** Medium  
**Type:** Denial of Service  

## Description
The `_burnGroupBalances` function fails to validate that the burn operation completes successfully when expired tokens are present, potentially creating inconsistencies between ERC1155 balance tracking and group array tracking. The function skips over expired token groups during burning but does not verify that the burn was completed successfully.

The `_burnGroupBalances` function iterates through the account’s token groups in FIFO order to burn the requested amount. However...

---

### 4. Roles manager can never be updated

**Protocol**: Atlendis Labs Loan Products | **Impact**: HIGH

## Security Assessment of Atlendis Labs Protocol

## Difficulty
**High**

## Type
**Timing**

## Target
**Managed.sol**

## Description
The Atlendis Labs protocol uses role-based access control to manage permissions and privileges. The manager of the roles is responsible for granting and revoking roles; if necessary, the role manager can be transferred to another address by governance via the `updateRolesManager` function. However, the `updateRolesManager` function will always revert:

```solidity
modifier onlyGovernance() {
    if (!rolesManager.isGovernance(msg.sender)) revert ONLY_GOVERNANC...

---

### 5. Minter user can conﬁscate any user tokens

**Protocol**: Curve DAO | **Impact**: HIGH

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
def mint(_to: address,...

---

### 6. Lack of reserve updates when collecting fees allows anyone to drain the Vault

**Protocol**: Balancer v3 | **Impact**: HIGH

## Diﬃculty: Low

## Type: Data Validation

## Description

The lack of reserve updates when fees are collected allows anyone to drain the Vault. The accumulated fees for each of the pools are counted as part of the token reserves of the Vault and can be collected by calling the `collectAggregateFees` function. This function is permissionless, allowing anyone to call it, and it withdraws the fees to the `ProtocolFeeController` contract.

```solidity
function collectAggregateFees(address pool) public onlyVaultDelegateCall
nonReentrant withRegisteredPool(pool) {
    IERC20[] memory poolTokens = ...

---

### 7. Lack of a two-step process for ownership transfer

**Protocol**: Beanstalk | **Impact**: HIGH

## Beanstalk Security Assessment

**Difficulty:** Low  
**Type:** Data Validation  
**Target:** `protocol/contracts/farm/facets/OwnershipFacet.sol`  

## Description
The `transferOwnership()` function is used to change the owner of the Beanstalk protocol. This function calls the `setContractOwner()` function, which immediately sets the contract’s new owner. Transferring ownership in one function call is error-prone and could result in irrevocable mistakes.

```solidity
function transferOwnership(address _newOwner) external override {
    LibDiamond.enforceIsContractOwner();
    LibDiamond.setC...

---

### 8. Staker contract balance invariant can be broken using SELFDESTRUCT

**Protocol**: Upgrade | **Impact**: HIGH

## VeChain DPoS Contract Balance Invariant

**Difficulty:** N/A  
**Type:** Configuration

## Description

VeChain DPoS uses a Staker contract to handle validations and delegations. One of the system's invariants requires that the total amount of staked VET matches the Staker contract balance. 

Even though the contract prevents VET from being received via normal transfers, an attacker can still send VET to the contract via `SELFDESTRUCT`. This can break two assumptions: the first one is that the amount of VET transferred to the contract is always an integer, and the second is that all VET in ...

---

### 9. Missing debt validation in group transfer function

**Protocol**: Radius Technology EVMAuth | **Impact**: HIGH

## Difficulty: Medium

## Type: Data Validation

## Description

The `_transferGroups` function fails to complete group transfers when expired tokens are present, creating an inconsistency between the ERC1155 balance tracking and the group array tracking. The function skips over expired token groups during transfer but does not verify that the transfer was completed successfully.

The `_transferGroups` function iterates through the sender’s token groups in the FIFO order to transfer the requested amount. However, it skips over expired token groups without accounting for them in the transfer ca...

---

### 10. Expired token groups not synchronized with ERC1155 balance tracking

**Protocol**: Radius Technology EVMAuth | **Impact**: HIGH

## Diﬃculty: Low

## Type: Data Validation

## Description
The *pruneGroups* function removes expired token groups from the custom group tracking system but fails to update the underlying ERC1155 balance tracking. This creates a data inconsistency where expired tokens can still be transferred despite being removed from the expiration tracking system. 

The contract maintains two separate balance tracking systems: the standard ERC1155 *balances* mapping and a custom *group* array system for expiration management. When tokens expire, the *pruneGroups* function correctly removes expired groups fr...

---

### 11. Incorrect account assignment in token burning logic

**Protocol**: Radius Technology EVMAuth | **Impact**: HIGH

## Diﬃculty: Low

## Type: Data Validation

### Description
The token burning logic incorrectly assigns the wrong account address when burning tokens. When tokens are being burned, the code incorrectly assigns `address _account = to` instead of using the `from` address, causing the contract to attempt burning tokens from the zero address.

The `_update` function is responsible for handling token minting, burning, and transferring operations. When burning tokens, the logic should burn tokens from the `from` address (the token holder), but the current implementation incorrectly sets `_account = ...

---

### 12. Insufficient fee validation leading to user contract state lock

**Protocol**: EVAA Finance | **Impact**: HIGH

## High Difficulty Data Validation Issue

## Description

The liquidation fee validation logic contains a flaw that allows attackers to permanently lock user funds by triggering incomplete liquidation processes. The current implementation validates only that `msg_value` is enough to cover `enough_fee` without accounting for the additional `TON_reserve_amount` required for successful transaction completion.

```solidity
if ((min_collateral_amount > max_allowed_liquidation) | (msg_value < enough_fee)) {
    [...]
    ;; Refund asset
    immediate_asset_refund(
        [...]
    );
    ;; Note th...

---

### 13. Wallet can be embedded in iframe, enabling clickjacking attacks

**Protocol**: Gemini Smart Wallet | **Impact**: HIGH

## Diﬃculty: High

## Type: Data Validation

### Description
The wallet SDK allows the wallet UI to be embedded in an iframe instead of opening in a popup window. This creates a clickjacking vulnerability where a malicious dapp can overlay the wallet interface with hidden elements or misleading UI, tricking users into signing transactions or messages without their knowledge. Any dapp could make a user sign a malicious message, thinking they are signing a safe message.

### Exploit Scenario
A malicious dapp embeds the wallet in an iframe and overlays it with transparent elements or misleading U...

---

### 14. API keys exposure in client-side code enables API abuse

**Protocol**: Gemini Smart Wallet | **Impact**: HIGH

## Security Analysis Report

## Difficulty: Low

## Type: Data Validation

## Description
The API keys are exposed in client-side code, allowing malicious users to extract and abuse them. The API keys are used to create a Pimlico client for bundling transactions and to get on-chain information using Alchemy. However, the API key is currently being sent to the client browser, where it can be accessed through browser developer tools. This enables unauthorized users to make API calls using Gemini’s API key, potentially exhausting the API quota or incurring unexpected costs.

```javascript
// Crea...

---

### 15. Arbitrary messages can be executed via vault notiﬁcation messages

**Protocol**: Swap Coffee TON DEX | **Impact**: HIGH

## Vulnerability Report

## Difficulty: Medium

## Type: Data Validation

## Description
The vault contract allows arbitrary messages to be sent to arbitrary recipients through its notification system, which can be exploited to bypass critical security checks. Similar to **TOB-SWAPCOFFEE-1**, the vault sends notification messages that can contain any payload, allowing attackers to craft malicious operations that appear to come from the vault. This vulnerability can be exploited to send malicious messages, such as a swap operation or a liquidity deposit, without transferring any tokens to the v...

---


## Statistics

- Total findings from TrailOfBits: 2,094
- Last updated: 2026-01-29
