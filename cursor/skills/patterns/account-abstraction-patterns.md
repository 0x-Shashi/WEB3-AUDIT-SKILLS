---
id: PAT-ACCOUNT-ABSTRACTION
title: Account Abstraction Security Patterns
category: erc4337
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - erc4337
  - aa
  - bundler

finding_count: 6
last_updated: 2026-01-31
---
# Account Abstraction Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 4 | 1 | 0 |

**Common Sources**: Code4rena, Quantstamp

---

## Detection Checklist

- [ ] Check for account abstraction vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-02] Non-compliance with EIP-4337

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: MEDIUM

**Details**:

[contracts/smart-contract-wallet/BaseSmartAccount.sol#L60-L68](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/BaseSmartAccount.sol#L60-L68)<br>
[contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L319-L329](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L319-L329)<br>
[contracts/smart-contract-wallet/BaseSmartAccount.sol#L60-L68](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/BaseSmartAccount.sol#L60-L68)

Some parts of the codebase are not compliant with the EIP-4337 from the [EIP-4337 specifications](https://eips.ethereum.org/EIPS/eip-4337#specification), at multiple degrees of severity.

### Proof of Concept

**Sender existence**

```text
Create the account if it does not yet exist, using the initcode provided in the UserOperation. If the account does not exist, and the initcode is empty, or does not deploy a contract at the sender address, the call must fail.
```

If we take a look at the [`_createSenderIfNeeded()`]() function, we can see that it's not properly implemented:

```solidity
function _createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) internal {
	if (initCode.length != 0) {
		address sender = opInfo.mUserOp.sender;
    	if (sender.code.length != 0) revert FailedOp(opIndex, address(0), "AA10 sender already constructed");

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-biconomy)

---

### Example 2: [H-05] Paymaster ETH can be drained with malicious sender

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: HIGH

**Details**:

[contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L97-L111](https://github.com/code-423n4/2023-01-biconomy/blob/53c8c3823175aeb26dee5529eeefa81240a406ba/scw-contracts/contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L97-L111)

Paymaster's signature can be replayed to drain their deposits.

### Proof of Concept

Scenario :

*   user A is happy with biconomy and behaves well biconomy gives some sponsored tx using verifyingPaymaster -- let's say paymaster's signature as sig X
*   user A becomes not happy with biconomy for some reason and A wants to attack biconomy
*   user A delegate calls to Upgrader and upgrade it's sender contract to MaliciousAccount.sol
*   MaliciousAccount.sol does not check any nonce and everything else is same to SmartAccount(but they can also add some other details to amplify the attack, but let's just stick it this way)
*   user A uses sig X(the one that used before) to initiate the same tx over and over
*   user A earnes nearly nothing but paymaster will get their deposits drained

files : Upgrader.sol, MaliciousAccount.sol, test file <br><https://gist.github.com/leekt/d8fb59f448e10aeceafbd2306aceaab2>

### Tools Used

hardhat test, verified with livingrock

### Recommended Mitigation Steps

Since `validatePaymasterUserOp` function is not limited to view function in erc4337 spec, add simple boolean data for mapping if hash is used or not

    mapping(bytes32 => 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-biconomy)

---

### Example 3: [M-03] Cross-Chain Signature Replay Attack

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: MEDIUM

**Details**:

User operations can be replayed on smart accounts accross different chains. This can lead to user's losing funds or any unexpected behaviour that transaction replay attacks usually lead to.

### Proof of Concept

As specified by the [EIP4337](https://eips.ethereum.org/EIPS/eip-4337) standard `to prevent replay attacks ... the signature should depend on chainid`. In [VerifyingSingletonPaymaster.sol#getHash](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L77-L90) the chainId is missing which means that the same UserOperation can be replayed on a different chain for the same smart contract account if the `verifyingSigner` is the same (and most likely this will be the case).

### Recommended Mitigation Steps

Add the chainId in the calculation of the UserOperation hash in [VerifyingSingletonPaymaster.sol#getHash](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L77-L90)

        function getHash(UserOperation calldata userOp)
        public view returns (bytes32) { // @audit change to view
            //can't use userOp.hash(), since it contains also the paymasterAndData itself.
            return keccak256(abi.encode(
                    userOp.getSender(),
                    userOp.nonce,
                    keccak256(userOp.initCode),
         

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-biconomy)

---

### Example 4: [M-01] Griefing attacks on `handleOps` and `multiSend` logic

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: MEDIUM

**Details**:

[contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L68](https://github.com/code-423n4/2023-01-biconomy/blob/5df2e8f8c0fd3393b9ecdad9ef356955f07fbbdd/scw-contracts/contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L68)<br>
[contracts/smart-contract-wallet/libs/MultiSend.sol#L26](https://github.com/code-423n4/2023-01-biconomy/blob/5df2e8f8c0fd3393b9ecdad9ef356955f07fbbdd/scw-contracts/contracts/smart-contract-wallet/libs/MultiSend.sol#L26)

The `handleOps` function executes an array of `UserOperation`. If at least one user operation fails the whole transaction will revert. That means the error on one user ops will fully reverts the other executed ops.

The `multiSend` function reverts if at least one of the transactions fails, so it is also vulnerable to such type of attacks.

### Attack scenario

Relayer offchain verify the batch of `UserOperation`s, convinced that they will receive fees, then send the `handleOps` transaction to the mempool. An attacker front-run the relayers transaction with another `handleOps` transaction that executes only one `UserOperation`, the last user operation from the relayers `handleOps` operations. An attacker will receive the funds for one `UserOperation`. Original relayers transaction will consume gas for the execution of all except one, user ops, but reverts at the end.

### Impact

Griefing attacks on the gas used for `handleOps` and `multiSend` function calls.

Please note, that while an attacker have no direct incentive t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-biconomy)

---

### Example 5: [M-05] DoS of user operations and loss of user transaction fee due to insufficient gas value submission by malicious bundler

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: MEDIUM

**Details**:

[contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L68-L86](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L68-L86)<br>
[contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L168-L190](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/aa-4337/core/EntryPoint.sol#L168-L190)

An attacker (e.g. a malicious bundler) could submit a bundle of high gas usage user operations with insufficient gas value, causing the bundle to fail even when the users calculated the gas limits correctly. This will result in a DoS for the user and the user/paymaster still have to pay for the execution, potentially draining their funds. This attack is possible as user operations are included by bundlers from the UserOperation mempool into the Ethereum block (see post on ERC-4337 <https://medium.com/infinitism/erc-4337-account-abstraction-without-ethereum-protocol-changes-d75c9d94dc4a>).

Reference for this issue: <https://github.com/eth-infinitism/account-abstraction/commit/4fef857019dc2efbc415ac9fc549b222b07131ef>

### Proof of Concept

In innerHandleOp(), a call was made to handle the operation with the specified mUserOp.callGasLimit. However, a malicious bundler could call the innerHandleOp() via handleOps() with a gas value that is insufficient for the transactions, resulting in the call to fail.

The remaining gas amount (e.g. gasLeft()) at this po

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-biconomy)

---

### Example 6: Missing Validation for Zero `success_percentage` in DAO Creation

**Source**: Quantstamp
**Protocol**: XDAO
**Impact**: LOW

**Details**:

**Update**
The team addressed in: `a429b0c9ce78be9294a27934e1a184261b88917a`, `2255f30c7f9559ce225b407c26f6d816325d78f3`with the following explanation:

> Second commit (2255f30c7f9559ce225b407c26f6d816325d78f3) contains constants.fc update.

**File(s) affected:**`contracts/factory.fc`, `contracts/master.fc`

**Description:** In both the `factory`s `op::create_master` and the `master`s `op::change_success_percentage`, the code checks that `success_percentage` does not exceed 100%, but it does not enforce a minimum above zero.

Generally, we should not expect a proposal to pass with zero votes.

**Recommendation:** Add a validation such as `throw_if(error::value_too_low, success_percentage == 0)` in both `op::create_master` and `op::change_success_percentage` to ensure `success_percentage >= 1`.

**Reference**: [View Original Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

