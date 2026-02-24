---
id: PAT-MISC
title: Misc Security Patterns
category: general
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - security
  - vulnerability
related_patterns:
  - vulnerability
finding_count_source: 6
finding_count_note: "Count reflects a single constituent tag. Consolidated file covers multiple miscellaneous patterns. See STATISTICS.md."
last_updated: 2026-02-24
---
# Miscellaneous Security Patterns (Consolidated)

> **Collection of additional vulnerability patterns including timing, events, and code quality.**

---

## Quick Summary

| Category | Key Issues |
|----------|------------|
| Timing | block.timestamp manipulation, deadline issues |
| Events | Missing events, incorrect event data |
| Code Quality | Typos, copy-paste errors, dead code |
| Account Abstraction | ERC-4337 specific vulnerabilities |
| Business Logic | Protocol-specific logic flaws |

---

## Key Patterns

### Timestamp Manipulation
```solidity
// LOW RISK: Miners can manipulate by ~15 seconds
if (block.timestamp >= unlockTime) { ... }

// HIGHER RISK: Short time windows vulnerable
if (block.timestamp < auctionEnd && block.timestamp > auctionEnd - 30) {
    // Miner could manipulate to extend/shorten by ~15s
}
```

### Event Emission
```solidity
// WRONG: No event for critical state change
function setPrice(uint _price) external onlyOwner {
    price = _price;  // No way to track off-chain!
}

// CORRECT: Emit event
event PriceUpdated(uint oldPrice, uint newPrice);

function setPrice(uint _price) external onlyOwner {
    emit PriceUpdated(price, _price);
    price = _price;
}
```

### Pre/Post Balance Check
```solidity
// For accurate accounting with any token type
function deposit(address token, uint amount) external {
    uint balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    uint received = IERC20(token).balanceOf(address(this)) - balanceBefore;
    // Use 'received' not 'amount' for accounting
}
```

---

## Included Pattern Files

- account-abstraction-patterns.md, business-logic-patterns.md
- timing-patterns.md, block-period-patterns.md
- event-patterns.md, auditing-and-logging-patterns.md
- code-quality-patterns.md, coding-bug-patterns.md, typo-copypaste-patterns.md
- documentation-patterns.md, don-t-update-state-patterns.md
- mapping-patterns.md, payable-patterns.md, refund-ether-patterns.md
- pre-post-balance-patterns.md, sense-patterns.md
- supportsinterface-patterns.md, eip-165-patterns.md
- protocol-specific-patterns.md, vulnerability-patterns.md, vulnerability-taxonomy.md
- severity-scoring.md, invariant-testing.md

---

## Full Pattern Details

---
## account-abstraction-patterns.md
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


---
## business-logic-patterns.md
# Business Logic Security Patterns

## Overview

**Frequency**: 234 occurrences (0.46% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 100 | 127 | 7 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, Pashov Audit Group, Trust Security

---

## Detection Checklist

- [ ] Check for business logic vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-09] Attacker can steal 99% of total balance from any reward token in any Staking contract

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L108-L110>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L483-L503> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L296-L315>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L351-L360> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L377-L378>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L390-L399>

### Impact

Attacker can steal 99% of the balance of a reward token of any Staking contract in the blockchain. An attacker can do this by modifying the reward speed of the target reward token.

So an attacker gets access to `changeRewardSpeed`, he will need to deploy a vault using the target Staking contract as its Staking contract. Since the Staking contract is now attached to the attacker's created vault, he can now successfully `changeRewardSpeed`. Now with `changeRewardSpeed`, attacker can set the `rewardSpeed` to any absurdly large amount that allows them to drain 99% of the balance (dust usually remains due to rounding issues) after some seconds (12 seconds in the PoC.)

### Proof of Concept

This attack is made possible by the following issues:

1.  Any user can deploy a Vault that uses any existing Staking contract - <https://github.com/code-423n4/2023-01-popcorn/blob/mai

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 2: [H-01] Too many rewards are distributed when a draw is closed

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L178-L184><br>
<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L154-L157><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/PrizePool.sol#L366><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/abstract/TieredLiquidityDistributor.sol#L374>

A relayer completes a prize pool draw by calling `rngComplete` in `RngRelayAuction.sol`. This method closes the prize pool draw with the relayed random number and distributes the rewards to the RNG auction recipient and the RNG relay auction recipient. These rewards are calculated based on a fraction of the prize pool reserve rather than an actual value.

However, the current reward calculation mistakenly includes an extra `reserveForOpenDraw` amount just after the draw has been closed. Therefore the fraction over which the rewards are being calculated includes tokens that have not been added to the reserve and will actually only be added to the reserve when the next draw is finalised. As a result, the reward recipients are rewarded too many tokens.

### Proof of Concept

Before deciding whether or not to relay an auction result, a bot can call `computeRewards` to calculate how many rewards they'll be getting based on

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-pooltogether)

---

### Example 3: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`WithdrawProxy.sol#L172-L175`

## Description
Anytime there is a withdrawal pending (i.e., someone holds WithdrawProxy shares), shares may be redeemed as long as `totalAssets() > 0` and `s.finalAuctionEnd == 0`. Under normal operating conditions, `totalAssets()` becomes greater than 0 when the `PublicVault` calls `transferWithdrawReserve`. 

`totalAssets()` can also be increased to a non-zero value by anyone transferring WETH to the contract. If this occurs and a user attempts to redeem, they will receive a smaller share than they are owed.

### Exploit Scenario
- Depositor redeems from `PublicVault` and receives WithdrawProxy shares.
- Malicious actor deposits a small amount of WETH into the WithdrawProxy.
- Depositor accidentally redeems, or is tricked into redeeming, from the WithdrawProxy while `totalAssets()` is smaller than it should be.
- `PublicVault` properly processes epoch and full `withdrawReserve` is sent to the WithdrawProxy.
- All remaining holders of WithdrawProxy shares receive an outsized share as the previous shares were redeemed for the incorrect value.

## Recommendation

### Option 1
Consider being explicit in opening the WithdrawProxy for redemptions (`redeem/withdraw`) by requiring `s.withdrawReserveReceived` to be a non-zero value:

```solidity
if (s.finalAuctionEnd != 0) {
    // Updated condition
    if (s.finalAuctionEnd != 0 || s.withdrawReserveReceived == 0) {
        // if finalAuctionEnd is 0, no auctions were

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: Refactor _paymentAH()

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: 
**High Risk**

## Context: 
**LienToken.sol#L571**

## Description: 
The `_paymentAH()` function has several vulnerabilities:

- The `stack` parameter is defined as a memory parameter, so any updates made to `stack` do not reflect back in the corresponding storage variable.
- There is no need to update `stack[position]` as it is deleted later.
- The function `decreaseEpochLienCount()` is always passed `0`, as `stack[position]` has already been deleted. Furthermore, `decreaseEpochLienCount()` expects `epoch`, but `end` is passed instead.
- The if/else block can be merged. The function `updateAfterLiquidationPayment()` expects `msg.sender` to be `LIEN_TOKEN`, which should work as expected.

## Recommendation:
Apply the following diff:

```solidity
function _paymentAH(
    LienStorage storage s,
    uint256 collateralId,
    - AuctionStack[] memory stack,
    + AuctionStack[] storage stack,
    uint256 position,
    uint256 payment,
    address payer
) internal returns (uint256) {
    uint256 lienId = stack[position].lienId;
    uint256 end = stack[position].end;
    uint256 owing = stack[position].amountOwed;

    //checks the lien exists
    address owner = ownerOf(lienId);
    address payee = _getPayee(s, lienId);

    - if (owing > payment.safeCastTo88()) {
    -     stack[position].amountOwed -= payment.safeCastTo88();
    - } else {
    + if (owing < payment.safeCastTo88()) {
        payment = owing;
    }

    s.TRANSFER_PROXY.tokenT

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: Incorrect auction end validation in liquidatorNFTClaim()

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`CollateralToken.sol#L119`

## Description
The function `liquidatorNFTClaim()` includes a check to determine if a Seaport auction has ended:

```solidity
if (block.timestamp < params.endTime) {
    // auction hasn't ended yet
    revert InvalidCollateralState(InvalidCollateralStates.AUCTION_ACTIVE);
}
```

In this scenario, `params` is completely controlled by users. To bypass this check, the caller can set `params.endTime` to a value less than `block.timestamp`. 

A possible exploit scenario occurs when `AstariaRouter.liquidate()` is called to list the underlying asset on Seaport, which also sets the liquidator address. Consequently, anyone can call `liquidatorNFTClaim()` to transfer the underlying asset to the liquidator by setting `params.endTime < block.timestamp`.

## Recommendation
The parameter passed to `liquidatorNFTClaim()` should be validated against the parameters created for the Seaport auction. To achieve this:

- Update the `collateralIdToAuction` mapping, which currently maps `collateralId` to a boolean value indicating an active auction, to instead map from `collateralId` to the Seaport order hash.
- All usages of `collateralIdToAuction` should be updated. For instance, `isValidOrder()` and `isValidOrderIncludingExtraData()` should be modified as follows:

```solidity
return
    s.collateralIdToAuction[uint256(zoneHash)] == orderHash
        ? ZoneInterface.isValidOrder.selector
        : bytes4(0xffffffff);
```

- The `liqu

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 6: VaultImplementation.buyoutLien can be DoSed by calls to LienToken.buyoutLien

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
- LienToken.sol#L102
- LienToken.sol#L121
- VaultImplementation.sol#L305

### Description
Anyone can call into `LienToken.buyoutLien` and provide params of the type `LienActionBuyout`:  
`params.incoming` is not used, so for example, vault signatures or strategy validation is skipped. There are a few checks for `params.encumber`.

Let's define the following variables:

| Parameter | Value |
|-----------|-------|
| i         | params.position |
| kj        | params.encumber.stack[j].point.position |
| tj        | params.encumber.stack[j].point.last |
| ej        | params.encumber.stack[j].point.end |
| e0       | itnow+D0 |
| i         | lj params.encumber.stack[j].point.lienId |
| l0       | ih(N0 i,V0 i,S0 i,c0 i, (A0max i,r0 i,D0 i,P0 i,L0 i)) where h is the keccak256 of the encoding |
| rj        | params.encumber.stack[j].lien.details.rate : old rate |
| r0       | params.encumber.lien.details.rate : new rate |
| c         | params.encumber.collateralId |

| Parameter | Value |
|-----------|-------|
| cj        | params.encumber.stack[j].lien.collateralId |
| c0       | params.encumber.lien.collateralId |
| Aj        | params.encumber.stack[j].point.amount |
| A0       | params.encumber.amount |
| Amax     | params.encumber.stack[j].lien.details.maxAmount |
| A0max    | params.encumber.lien.details.maxAmount |
| R         | params.encumber.receiver |
| Nj        | params.encumber.stack[j].lien.token |
| N0      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 7: OperatorsRegistry._getNextValidatorsFromActiveOperators can DOS Alluvial staking if there's anoperator with funded==stopped and funded == min(limit, keys)

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
OperatorsRegistry.1.sol#L403-L454

## Description
This issue is also related to `OperatorsRegistry._getNextValidatorsFromActiveOperators` which should not consider stopped when picking a validator.

Consider a scenario where we have:

### Operators
- **Op at index 0**
  - Name: `op1`
  - Active: `true`
  - Limit: `10`
  - Funded: `10`
  - Stopped: `10`
  - Keys: `10`

- **Op at index 1**
  - Name: `op2`
  - Active: `true`
  - Limit: `10`
  - Funded: `0`
  - Stopped: `0`
  - Keys: `10`

In this case:
- Op1 got all 10 keys funded and exited. Because it has `keys=10` and `limit=10`, it means that it has no more keys to get funded again.
- Op2 instead has still 10 approved keys to be funded.

Because of how the selection of the picked validator works:

```solidity
uint256 selectedOperatorIndex = 0;
for (uint256 idx = 1; idx < operators.length;) {
    if (
        operators[idx].funded - operators[idx].stopped <
        operators[selectedOperatorIndex].funded - operators[selectedOperatorIndex].stopped
    ) {
        selectedOperatorIndex = idx;
    }
    unchecked {
        ++idx;
    }
}
```

When the function finds an operator with `funded == stopped`, it will pick that operator because `0 < operators[selectedOperatorIndex].funded - operators[selectedOperatorIndex].stopped`.

After the loop ends, `selectedOperatorIndex` will be the index of an operator that has no more validators to be funded (for this scenario). Because of this, the follo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 8: [H-01] Borrowers may earn auction proceeds without filling the debt shortfall

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

The proceeds from the collateral auctions will not be used to fill the debt shortfall, but be transferred directly to the borrower.

### Proof of Concept

Assume N is an allowed NFT, B is a borrower, the vault V is `_vaultInfo[B][N]`:

1.  B add two NFTs (N-1 and N-2) as collaterals to vault V.
2.  B [increaseDebt()](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L138) of vault V.
3.  The vault V becomes liquidatable.
4.  Someone calls [startLiquidationAuction()](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L297) to liquidate collateral N-1.
5.  No one buys N-1 because the price of N is falling.
6.  After [liquidationAuctionMinSpacing - 2days](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L41), someone calls [startLiquidationAuction()](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L297) to liquidate collateral N-2.
7.  Someone calls [purchaseLiquidationAuctionNFT](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L264) to purchase N-1. Partial of the debt is filled, while the remaining (shortfall) is burnt:

```solidity
if (isLastCollateral && remaining != 0) {
    /// there will be debt left with no NFTs, set it to 0
    _reduceDebtWithoutBurn(auction.nftOwner, auction.auctionAssetContract

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 9: Missing mirrorConnector check on Optimism hub connector

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`OptimismHubConnector.sol#L69-L121`

## Description
The `processMessageFromRoot()` function calls `_processMessage()` to process messages for the "fast" path. However, `_processMessage()` can also be invoked by the AMB in the slow path. 

The second call to `_processMessage()` is unnecessary and could lead to double processing of the message. This issue is mitigated somewhat by the `processed[]` mapping, which prevents double processing. However, the second call (from the AMB directly to `_processMessage()`) does not properly verify the origin of the message, potentially allowing for the insertion of fraudulent messages.

```solidity
function processMessageFromRoot(...) {
    ...
    _processMessage(abi.encode(_data));
    ...
}

function _processMessage(bytes memory _data) internal override {
    // sanity check root length
    require(_data.length == 32, "!length");
    // get root from data
    bytes32 root = bytes32(_data);
    if (!processed[root]) {
        // set root to processed
        processed[root] = true;
        // update the root on the root manager
        IRootManager(ROOT_MANAGER).aggregate(MIRROR_DOMAIN, root);
    } // otherwise root was already sent to root manager
}
```

## Recommendation
Remove the second path.

## Connext
Solved in PR 2447.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 10: swapInternal() shouldn't use msg.sender

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- BridgeFacet.sol#L337-L369
- BridgeFacet.sol#L659-L750
- AssetLogic.sol#L150-L182
- AssetLogic.sol#L229-L262
- SwapUtils.sol#L798-L826

## Description
As reported by the Connext team, the internal stable swap checks if `msg.sender` has sufficient funds in `onexecute()`. This `msg.sender` is the relayer which normally wouldn't have these funds, so the swaps would fail. The local funds should come from the Connext diamond itself.

### BridgeFacet.sol
```solidity
function execute(ExecuteArgs calldata _args) external nonReentrant whenNotPaused returns (bytes32) {
    ...
    (uint256 amountOut, address asset, address local) = _handleExecuteLiquidity(...);
    ...
}
```

### AssetLogic.sol
```solidity
function swapFromLocalAssetIfNeeded(...) ... {
    ...
    return _swapAsset(...);
}
```

### SwapUtils.sol
```solidity
function swapInternal(...) ... {
    IERC20 tokenFrom = self.pooledTokens[tokenIndexFrom];
    require(dx <= tokenFrom.balanceOf(msg.sender), "more than you own"); // msg.sender is the relayer
    ...
}
```

## Recommendation
Don't use the balance of `msg.sender`.

## Connext
Solved in PR 2120.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 11: [H-08] function withdrawETH from GiantMevAndFeesPool can steal most of eth because of idleETH is reduced before burning token

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantPoolBase.sol#L57-L60
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L176-L178
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L76-L90


## Vulnerability details

## Impact

The contract GiantMevAndFeesPool override the function totalRewardsReceived:
```
return address(this).balance + totalClaimed - idleETH;
```
The function totalRewardsReceived is used as the current rewards balance to caculate the unprocessed rewards in the function `SyndicateRewardsProcessor._updateAccumulatedETHPerLP`
```
uint256 received = totalRewardsReceived();
uint256 unprocessed = received - totalETHSeen;
```
But it will decrease the `idleETH` first and then burn the lpTokenETH in the function `GiantMevAndFeesPool.withdrawETH`. The lpTokenETH burn option will trigger `GiantMevAndFeesPool.beforeTokenTransfer` which will call _updateAccumulatedETHPerLP and send the accumulated rewards to the msg sender. Because of the diminution of the idleETH, the `accumulatedETHPerLPShare` is added out of thin air. So the attacker can steal more eth from the GiantMevAndFeesPool.

## Proof of Concept
I wrote a test file for proof, but there is another bug/vulnerability which will make the `GiantMevAndFeesPool.withdrawETH` function break down. I submitted it as the other finding named "Gian

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 12: [H-05] Borrower can craft a borrow that cannot be liquidated, even by arbiter. 

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L516-L538


## Vulnerability details

## Description

LineOfCredit manages an array of open credit line identifiers called `ids`. Many interactions with the Line operate on ids\[0\], which is presumed to be the oldest borrow which has non zero principal. For example, borrowers must first deposit and repay to ids\[0\] before other credit lines.

The list is managed by several functions:

1.  CreditListLib.removePosition - deletes parameter id in the ids array
2.  CreditListLib.stepQ - rotates all ids members one to the left, with the leftmost becoming the last element
3.  _sortIntoQ - most complex function, finds the smallest index which can swap identifiers with the parameter id, which satisfies the conditions:
    1.  target index is not empty
    2.  there is no principal owed for the target index's credit

The idea I had is that if we could corrupt the ids array so that ids\[0\] would be zero, but after it there would be some other active borrows, it would be a very severe situation. The whileBorrowing() modifier assumes if the first element has no principal, borrower is not borrowing.

```
modifier whileBorrowing() {
    if(count == 0 || credits[ids[0]].principal == 0) { revert NotBorrowing(); }
    _;
}
```

It turns out there is a simple sequence of calls which allows borrowing while ids\[0\] is deleted, and does not re-ar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 13: [H-04] Borrower can close a credit without repaying debt

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

A borrower can close a credit without repaying the debt to the lender. The lender will be left with a bad debt and the borrower will keep the borrowed amount and the collateral.

### Proof of Concept

The `close` function of `LineOfCredit` doesn't check whether a credit exists or not. As a result, the `count` variable is decreased in the internal `_close` function when the `close` function is called with an non-existent credit ID:
[LineOfCredit.sol#L388](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L388):

```solidity
function close(bytes32 id) external payable override returns (bool) {
    Credit memory credit = credits[id];
    address b = borrower; // gas savings
    if(msg.sender != credit.lender && msg.sender != b) {
      revert CallerAccessDenied();
    }

    // ensure all money owed is accounted for. Accrue facility fee since prinicpal was paid off
    credit = _accrue(credit, id);
    uint256 facilityFee = credit.interestAccrued;
    if(facilityFee > 0) {
      // only allow repaying interest since they are skipping repayment queue.
      // If principal still owed, _close() MUST fail
      LineLib.receiveTokenOrETH(credit.token, b, facilityFee);

      credit = _repay(credit, id, facilityFee);
    }

    _close(credit, id); // deleted; no need to save to storage

    return true;
}
```

[LineOfCredit.sol#L483](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8da

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 14: [H-03] addCredit / increaseCredit cannot be called by lender first when token is ETH

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

<https://github.com/debtdao/Line-of-Credit/blob/f32cb3eeb08663f2456bf6e2fba21e964da3e8ae/contracts/modules/credit/LineOfCredit.sol#L234>

<https://github.com/debtdao/Line-of-Credit/blob/f32cb3eeb08663f2456bf6e2fba21e964da3e8ae/contracts/modules/credit/LineOfCredit.sol#L270>

### Impact

The functions `addCredit` and `increaseCredit` both ahve a `mutualConsent` or `mutualConsentById` modifier. Furthermore, these functions are `payable` and the lender needs to send the corresponding ETH with each call. However, if we look at the mutual consent modifier works, we can have a problem:

```solidity
modifier mutualConsent(address _signerOne, address _signerTwo) {
      if(_mutualConsent(_signerOne, _signerTwo))  {
        // Run whatever code needed 2/2 consent
        _;
      }
}

function _mutualConsent(address _signerOne, address _signerTwo) internal returns(bool) {
        if(msg.sender != _signerOne && msg.sender != _signerTwo) { revert Unauthorized(); }

        address nonCaller = _getNonCaller(_signerOne, _signerTwo);

        // The consent hash is defined by the hash of the transaction call data and sender of msg,
        // which uniquely identifies the function, arguments, and sender.
        bytes32 expectedHash = keccak256(abi.encodePacked(msg.data, nonCaller));

        if (!mutualConsents[expectedHash]) {
            bytes32 newHash = keccak256(abi.encodePacked(msg.data, msg.sender));

            mutualConsents[newHash] = true;

            emit MutualConsentRegist

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 15: [H-02] Non-existing revenue contract can be passed to claimRevenue to send all tokens to treasury

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

Neither `SpigotLib.claimRevenue` nor `SpigotLib._claimRevenue` check that the provided `revenueContract` was registered before. If this is not the case, `SpigotLib._claimRevenue` assumes that this is a revenue contract with push payments (because `self.settings[revenueContract].claimFunction` is 0) and just returns the difference since the last call to `claimRevenue`:

```solidity
       if(self.settings[revenueContract].claimFunction == bytes4(0)) {
            // push payments

            // claimed = total balance - already accounted for balance
            claimed = existingBalance - self.escrowed[token]; //@audit Rebasing tokens
            // underflow revert ensures we have more tokens than we started with and actually claimed revenue
        }
```

`SpigotLib.claimRevenue` will then read `self.settings[revenueContract].ownerSplit`, which is 0 for non-registered revenue contracts:

```solidity
uint256 escrowedAmount = claimed * self.settings[revenueContract].ownerSplit / 100;
```

Therefore, the whole `claimed` amount is sent to the treasury.

This becomes very problematic for revenue tokens that use push payments. An attacker (in practice the borrower) can just regularly call `claimRevenue` with this token and a non-existing revenue contract. All of the tokens that were sent to the spigot since the last call will be sent to the treasury and none to the escrow, i.e. a borrower can ensure that no revenue will be available for the lender, no matter what the configured s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 16: reimburseLiquidityFees send tokens twice

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## High Risk Report

## Severity 
High Risk

## Context 
- **Files**: 
  - BridgeFacet.sol (Lines 644-675)
  - SponsorVault.sol (Lines 197-226)
  - ITokenExchange.sol (Lines 18-24)

## Description 
The function `reimburseLiquidityFees()` is called from the `BridgeFacet`, making the `msg.sender` within this function to be the `BridgeFacet`. 

When using token exchanges via `swapExactIn()`, tokens are sent to `msg.sender`, which is the `BridgeFacet`. Then, tokens are sent again to `msg.sender` via `safeTransfer()`, which is also the `BridgeFacet`. Therefore, tokens end up being sent to the `BridgeFacet` twice.

**Note:** The check `...balanceOf(...) != starting + sponsored` should fail too.

**Note:** The fix in C4 seems to introduce this issue: `code4rena-246`.

### Code Snippet
```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction(...) ... {
        ...
        uint256 starting = IERC20(_asset).balanceOf(address(this));
        ...
        (bool success, bytes memory data) = address(s.sponsorVault).call(
            abi.encodeWithSelector(s.sponsorVault.reimburseLiquidityFees.selector, _asset, _args.amount, _args.params.to)
        );
        if (success) {
            uint256 sponsored = abi.decode(data, (uint256));
            // Validate correct amounts are transferred
            if (IERC20(_asset).balanceOf(address(this)) != starting + sponsored) { // this should fail now
                revert BridgeFacet__handleExecuteTransaction

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 17: SponsorVault sponsors full transfer amount in reimburseLiquidityFees()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

**Severity**: High Risk  
**Context**: BridgeFacet.sol#L660-L663  
**Description**: The `BridgeFacet` passes `args.amount` as `_liquidityFee` when calling `reimburseLiquidityFees`. Instead of sponsoring `liquidityFee`, the sponsor vault would sponsor the full transfer amount to the receiver. 

**Note**: Luckily, the amount in `reimburseLiquidityFees` is capped by `relayerFeeCap`.  
```solidity
function _handleExecuteTransaction(...) ... {
    ...
    (bool success, bytes memory data) = address(s.sponsorVault).call(
        abi.encodeWithSelector(s.sponsorVault.reimburseLiquidityFees.selector, _asset, _args.amount, _args.params.to), 
        ! 
    );
}
```

**Recommendation**: Pass `args.amount * (s.LIQUIDITY_FEE_DENOMINATOR - s.LIQUIDITY_FEE_NUMERATOR) / s.LIQUIDITY_FEE_DENOMINATOR` instead.  
**Connext**: Solved in PR 1551.  
**Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 18: Executor reverts on receiving native tokens from BridgeFacet

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- **File:** Executor.sol 
- **Line:** BridgeFacet.sol#L696, AssetLogic.sol#L127-L151

## Description
When doing an external call in `execute()`, the `BridgeFacet` provides liquidity into the `Executor` contract before calling `Executor.execute`. The `BridgeFacet` transfers a native token when an `address(wrapper)` is provided. However, the `Executor` does not have a fallback or receive function. Hence, the transaction will revert when the `BridgeFacet` tries to send the native token to the `Executor` contract.

```solidity
function _handleExecuteTransaction(
    ...
    AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
    (bool success, bytes memory returnData) = s.executor.execute(...);
    ...
}
```

```solidity
function transferAssetFromContract(...) {
    ...
    if (_assetId == address(s.wrapper)) {
        // If dealing with wrapped assets, make sure they are properly unwrapped
        // before sending from contract
        s.wrapper.withdraw(_amount);
        Address.sendValue(payable(_to), _amount);
    } else {
        ...
    }
}
```

## Recommendation
It is recommended to add a receive function in the `Executor` contract:

```solidity
receive() payable external {
    require(msg.sender == connext);
}
```

Alternatively, unwrap the native asset and send it along with the call to the executor.

- **Connext:** Ether sent along with the call. Solved in PR 1532.
- **Spearbit:** Verified.
- **Connext:** Alter

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 19: Executor andAssetLogic deals with the native tokens inconsistently that breaks execute()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
- `Executor.sol#L142`
- `AssetLogic.sol#L127-L151`
- `BridgeFacet.sol#L644-L718`

### Description
When dealing with an external callee, the `BridgeFacet` will transfer liquidity to the `Executor` before calling `Executor.execute`.

In order to send the native token:
- The `Executor` checks for `_args.assetId == address(0)`.
- `AssetLogic.transferAssetFromContract()` disallows `address(0)`.

**Note:** Also see the issue: "Executor reverts on receiving native tokens from BridgeFacet."

```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction() ... {
        ...
        AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount); // _asset may not be 0, !
        (bool success, bytes memory returnData) = s.executor.execute(
            IExecutor.ExecutorArgs(
                ...
                _asset, // assetId parameter from ExecutorArgs // must be 0 for Native asset
                ...
            )
        );
        ...
    }
}
```

```solidity
library AssetLogic {
    function transferAssetFromContract(address _assetId, ...) {
        ...
        // No native assets should ever be stored on this contract
        if (_assetId == address(0)) revert AssetLogic__transferAssetFromContract_notNative();
        if (_assetId == address(s.wrapper)) {
            // If dealing with wrapped assets, make sure they are properly unwrapped before sending from contract
       

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 20: _handleExecuteTransaction() doesnt handle native assets correctly

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

**Severity:** High Risk  
**Context:** BridgeFacet.sol#L644-L718, Executor.sol#L142-L243  

**Description:**  
The function `_handleExecuteTransaction()` sends any native tokens to the executor contract first, and then calls `s.executor.execute()`. This means that within that function, `msg.value` will always be 0. As a result, the associated logic that uses `msg.value` doesnt work as expected, leading to incorrect handling of native assets.

**Note:**  
Also see issue "Executor reverts on receiving native tokens from BridgeFacet".

```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction(...) {
        ...
        AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
        (bool success, bytes memory returnData) = s.executor.execute(...); // no native tokens sent
    }
}
```

```solidity
contract Executor is IExecutor {
    function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
        ...
        if (isNative && msg.value != _args.amount) { // msg.value is always 0
            ...
        }
    }
}
```

**Recommendation:**  
Change the code of `execute()` to handle previously sent native assets. Alternatively, send the native assets along with the call to `execute()`.

**Connext:** Solved in PR 1532.  
**Spearbit:** Verified.  
**Connext:** Alternate approach: removed native asset handling. Implemented in PR 31.  
**Spearbit:** Verified

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 21: Upon failing to back unbacked debt _reconcileProcessPortal() will leave the converted asset in the contract

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
`NomadFacet.sol#L225-L242`

## Description
When routers front liquidity for the protocols users, they are later reconciled once the bridge has optimistically verified transfers from the source chain. Upon being reconciled, the `_reconcileProcessPortal()` attempts to first pay back Aave debt before distributing the rest back to the router. However, `_reconcileProcessPortal()` will not convert the adopted asset back to the local asset in the case where the call to the Aave pool fails.

Instead, the function will set `amountIn = 0` and continue to distribute the local asset to the router.

```solidity
if (success) {
    emit AavePortalRepayment(_transferId, adopted, backUnbackedAmount, portalFee);
} else {
    // Reset values
    s.portalDebt[_transferId] += backUnbackedAmount;
    s.portalFeeDebt[_transferId] += portalFee;
    // Decrease the allowance
    SafeERC20.safeDecreaseAllowance(IERC20(adopted), s.aavePool, totalRepayAmount);
    // Update the amount repaid to 0, so the amount is credited to the router
    amountIn = 0;
    emit AavePortalRepaymentDebt(_transferId, adopted, s.portalDebt[_transferId],
                                 s.portalFeeDebt[_transferId]);
}
```

## Recommendation
It might be useful to convert the adopted asset amount back to the local asset such that subsequent swaps do not fail due to an insufficient amount of local asset. Alternatively, if the attempt to back unbacked debt fails, cons

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 22: Deriving price with balanceOf is dangerous

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`ConnextPriceOracle.sol#L109-L135`

## Description
The function `getPriceFromDex` derives the price by querying the balance of AMMs pools.

```solidity
function getPriceFromDex(address _tokenAddress) public view returns (uint256) {
    PriceInfo storage priceInfo = priceRecords[_tokenAddress];
    ...
    uint256 rawTokenAmount = IERC20Extended(priceInfo.token).balanceOf(priceInfo.lpToken);
    ...
    uint256 rawBaseTokenAmount = IERC20Extended(priceInfo.baseToken).balanceOf(priceInfo.lpToken);
    ...
}
```

Deriving the price with `balanceOf` is dangerous as `balanceOf` may be gamed. Consider Uniswap V2 as an example; exploiters can first send tokens into the pool and pump the price, then absorb the tokens that were previously donated by calling `mint`.

## Recommendation
Consider querying DEXs state through function calls such as Uniswap V2s `getReserves()` which returns the correct state of the pool.

## References
- **Connext**: Solved in PR 1649.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 23: MatchingEngineForAave is using the wrong totalSupply in updateBorrowers

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Risk Assessment

## Severity
**Critical Risk**

## Context
`MatchingEngineForAave.sol#L376-L385`

## Description
The `_poolTokenAddress` is referencing `AToken`, so the `totalStaked` would be the total supply of the `AToken`. In this case, the `totalStaked` should reference the total supply of the `DebtToken`; otherwise, the user would be rewarded for a wrong amount of reward.

## Recommendation
Use the correct token address to query `scaledTotalSupply` as follows:

```solidity
address variableDebtTokenAddress = lendingPool
    .getReserveData(IAToken(_poolTokenAddress).UNDERLYING_ASSET_ADDRESS())
    .variableDebtTokenAddress;

uint256 totalStaked = IScaledBalanceToken(variableDebtTokenAddress).scaledTotalSupply();
```

## Spearbit
Fixed; recommendation was implemented in the PR #554.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 24: Order of calls to removeValidators can affect the resulting validator keys set

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
OperatorsRegistry.1.sol#L310

## Description
If two entities A and B (which can be either the admin or the operator O with the index I) send a call to `removeValidators` with 2 different sets of parameters:

- T1: (I, R1)
- T2: (I, R2)

Then, depending on the order of transactions, the resulting set of validators for this operator might be different. Since either party might not know a priori if any other transaction is going to be included on the blockchain after they submit their transaction, they don't have a 100 percent guarantee that their intended set of validator keys are going to be removed.

This also opens an opportunity for either party to DoS the other party's transaction by frontrunning it with a call to remove enough validator keys to trigger the `InvalidIndexOutOfBounds` error:

```solidity
OperatorsRegistry.1.sol#L324-L326:
if (keyIndex >= operator.keys) {
    revert InvalidIndexOutOfBounds();
}
```

## Recommendation
We can send a snapshot block parameter to `removeValidators` and compare it to a stored field for the operator to ensure there have not been any changes to the validator key set since that snapshot block. Alluvial has introduced such a mechanism for `setOperatorLimits` in `030b52feb5af2dd2ad23da0d512c5b0e55eb8259`. A similar technique can be used here.

## Alluvial's Perspective
Alluvial: *Don't think this is really an issue.*  
On a regular basis, the admin would not remove the keys but would request the Node O

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 25: TRST-H-1 Incorrect implementation of getProfitSharingE18() greatly reduces Lender's yield

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
`ProfitSharingModel.getProfitSharingE18()` calculates the share of profit that Lender gets 
based on the APR of the position. According to the formula, the higher the APR, the lower 
the share of profit the Lender gets, but due to the wrong implementation of the 
`getProfitSharingE18()` function, if the APR is smaller than **MAX_ANNUALIZED_YEILD**, the 
base share of 25% is returned, actually 25% should be returned when the APR is larger than 
**MAX_ANNUALIZED_YEILD**.
Considering an APR of 5%, Lender's share of the profit should be 77%, while 
getProfitSharingE18() returns 25%, which greatly reduces Lender's share of the profit.

**Recommended Mitigation:**
Modify `getProfitSharingE18()` as follows 
```solidity
            - if (_annualizedYieldE18 < MAX_ANNUALIZED_YEILD) {
            + if (_annualizedYieldE18 >= MAX_ANNUALIZED_YEILD) { 
            return 0.25e18;
            }
```

**Team response:**
Fixed

**Mitigation Review:**
The team has fixed it as recommended to make the logic correct

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

## Statistics

- Total findings analyzed: 234
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## timing-patterns.md
# Timing Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 8 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for timing vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-34: liquidationAccountant can be claimed at any time

**Source**: Sherlock
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-astaria-judging/issues/46 

## Found by 
obront

## Summary

New liquidations are sent to the `liquidationAccountant` with a `finalAuctionTimestamp` value, but the actual value that is passed in is simply the duration of an auction. The `claim()` function uses this value in a require check, so this error will allow it to be called before the auction is complete.

## Vulnerability Detail

When a lien is liquidated, `AstariaRouter.sol:liquidate()` is called. If the lien is set to end in a future epoch, we call `handleNewLiquidation()` on the `liquidationAccountant`.

One of the values passed in this call is the `finalAuctionTimestamp`, which updates the `finalAuctionEnd` variable in the `liquidationAccountant`. This value is then used to protect the `claim()` function from being called too early.

However, when the router calls `handleLiquidationAccountant()`, it passes the duration of an auction rather than the final timestamp:

```solidity
LiquidationAccountant(accountant).handleNewLiquidation(
  lien.amount,
  COLLATERAL_TOKEN.auctionWindow() + 1 days
);
```
As a result, `finalAuctionEnd` will be set to 259200 (3 days). 

When `claim()` is called, it requires the final auction to have ended for the function to be called:

```solidity
require(
  block.timestamp > finalAuctionEnd || finalAuctionEnd == uint256(0),
  "final auction has not ended"
);
```
Because of the error above, `block.timestamp` will always be greater than `fi

*[Content truncated...]*

---

### Example 2: [M-06] `L1::xRenzoBridge` and `L2::xRenzoBridge` uses the `block.timestamp` as dependency, which can cause issues

**Source**: Code4rena
**Protocol**: Renzo
**Impact**: MEDIUM

**Details**:

In `L1::xRenzoBridge` the `block.timestamp` from L1 is encoded and sent to L2. When the message is delivered from L1 to L2  with `xRenzoBridge::_updatePrice()`, the function checks the `block.timestamp` like this:

```solidity
    if (_timestamp > block.timestamp) {
            revert InvalidTimestamp(_timestamp);
        }
```

This check is done to not allow future timestamps for updating the price But the timestamps between two chains L1 and L2 are different for chain like Arbitrum as there's a possibility that the sequencer fails to post batches on the parent chain (for example, Ethereum) for a period of time.

According to the [Arbitrum docs](<https://docs.arbitrum.io/build-decentralized-apps/arbitrum-vs-ethereum/block-numbers-and-time#block-timestamps-arbitrum-vs-ethereum>):

> **Timestamp boundaries of the sequencer**
>
> As mentioned, block timestamps are usually set based on the sequencer's clock. Because there's a possibility that the sequencer fails to post batches on the parent chain (for example, Ethereum) for a period of time, it should have the ability to slightly adjust the timestamp of the block to account for those delays and prevent any potential reorganisations of the chain. To limit the degree to which the sequencer can adjust timestamps, some boundaries are set, currently to 24 hours earlier than the current time, and 1 hour in the future.

So the issue is that timestamp validation for `_updatePrice()` won't be effective and can reject validation both l2

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-04-renzo)

---

### Example 3: The off-chain mechanism must be ensured to work in a correct order strictly

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `PriorityPool` contract relies on the distribution oracle for accounting and the accounting calculation is done off-chain.

According to the communication with the protocol team, the correct workflow for queued deposits can be described as below:
- Whenever there is a new room for deposit in the staking pool, the function `depositQueuedTokens` is called.
- The `PriorityPool` contract is paused by calling `pauseForUpdate()`.
- Accounting calculations happen off-chain using the function `getAccountData()` and `getDepositsSinceLastUpdate()`(`depositsSinceLastUpdate`) variable to compose the latest Merkle tree.
- The distribution oracle calls the function `updateDistribution()` and this will resume the `PriorityPool`.

The only purpose of pausing the queue contract is to prevent unqueue until the accounting status are updated.
Through an analysis we found that the off-chain mechanism MUST follow the order very strictly or else user funds can be stolen.
While we acknowledge that the protocol team will ensure it, we decided to keep this finding as a medium risk because we can not verify the off-chain mechanism.

**Impact:** If the off-chain mechanism occurs in a wrong order by any chance, user funds can be stolen.
Given the likelihood is low, we evaluate the impact to be Medium.

**Proof of Concept:** The below test case shows the attack scenario.
```javascript
  it('Cyfrin: off-chain mechanism in an incorrect order can lead to user funds 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 4: [M-16] Due to inappropriately short `votingPeriod`  and `votingDelay`, it is nearly impossible for the governance to function correctly.

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Proof of Concept

When making proposals with the [`Governor`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/Governor.sol#L299-L308) contract OZ uses `votingPeriod`.

```jsx
        uint256 snapshot = currentTimepoint + votingDelay();
        uint256 duration = votingPeriod();

        _proposals[proposalId] = ProposalCore({
            proposer: proposer,
            voteStart: SafeCast.toUint48(snapshot),//@audit votingDelay() for when the voting starts
            voteDuration: SafeCast.toUint32(duration),//@audit votingPeriod() for the duration
            executed: false,
            canceled: false
        });
```

But currently, Lybra has implemented the wrong amounts for bolt [`votingPeriod`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L143-L145) and [`votingDelay`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L147-L149), which means proposals from the governance will be nearly impossible to be voted on.

```jsx
    function votingPeriod() public pure override returns (uint256){
         return 3;//@audit this should be time in blocks 
    }

     function votingDelay() public pure override returns (uint256){
         return 1;//@audit this should be time in blocks 
    }
```

### HH PoC

<https://gist.github.com/0x3b33/dfd5a29d5fa50a00a149080280569d12>

### Tools Used

Manual Review

### Recommended Mitigation S

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 5: [M-15] Lack of timelock on `rigidRedemption`, enables to steal yield from other users

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

The withdraw function of the `LybraEUSDVaultBase` vaults, uses a time softlock to prevent users from hopping in and out of the protocol; to gain access to the yield generated by other users and then leave right away (by charging a small percentage from the withdrawn amount).

The same measure isn't applied to `rigidRedemptions`, which enable a user to withdraw most of the underlying assets at any time after deposit. This enables a user to deposit into the pool right before a rebase is about to happen, get access to the yield generated by other users and leave by calling `rigidRedemption` and withdraw on the tokens left by `rigidRedemption` (the amount charged on the leftovers assets, can be outbalanced by the yield).

Therefore, a malicious user to get access to yield that they didn't generate, effectively stealing it from others. The amount that the user will get access to will vary based on the deposited amounts.

### Proof of Concept

This issue involves 3 functions:

- `withdraw(address onBehalfOf, uint256 amount)` from the `LybraEUSDVaultBase` [contract](https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L98), which internally calls `checkWithdrawal(address user, uint256 amount)` to check that 3 days has passed after deposit and charges the user otherways:

    ```
    withdrawal = block.timestamp - 3 days >= depositedTime[user] ? amount : (amount * 999) / 1000;
    ```

- `rigidRede

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 6: [M-01] Malicious actor can win an auction unfavorably to the protocol by block stuffing

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L158-L202><br><https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L467-L470><br><https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L213>

When the protocol bad debt is auctioned off with 10% incentive at the beginning, a user who gives the best bid wins. The auction ends when at least one account placed a bid, and the current block number is bigger than `nextBidderBlockLimit`:

```jsx
function closeAuction(address comptroller) external nonReentrant {
        Auction storage auction = auctions[comptroller];

        require(_isStarted(auction), "no on-going auction");
        require(
            block.number > auction.highestBidBlock + nextBidderBlockLimit && auction.highestBidder != address(0),
            "waiting for next bidder. cannot close auction"
        );
```

`nextBidderBlockLimit` is set to 10 in the initializer, which means that other users have only 30 seconds to place a better bid. This is a serious problem because stuffing a whole block with dummy transactions is very cheap on Binance Smart Chain. According to <https://www.cryptoneur.xyz/en/gas-fees-calculator>, 15M gas - whole block - costs `$`14\~`$`15 on BSC. This makes a malicious user occasionally cheaply prohibit other users to overbid them, winning the auction at the least favorable price for the protocol. Because BSC is a centralized blockch

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-venus)

---

### Example 7: [M-01] Insufficient input validation

**Source**: Pashov Audit Group
**Protocol**: Gtrade
**Impact**: MEDIUM

**Details**:

**Severity**

**Impact:**
High, as it can lead to stuck funds

**Likelihood:**
Low, as it requires a bad user error

**Description**

In `GNSStakingV6_4_1::createUnlockSchedule` we have the `UnlockScheduleInput calldata _input` parameter, where most of the fields in the struct are properly validated to be in range of valid values. The issue is that the `start` field of the `UnlockScheduleInput` is not sufficiently validated, as it can be too further away in the future - for example 50 years in the future, due to a user error when choosing the timestamp. This would result in (almost) permanent lock of the `GNS` funds sent to the method.

**Recommendations**

Add a validation that the `start` field is not too further away in the future, for example it should be max 1 year in the future.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-08-01-gTrade.md)

---

### Example 8: [M-19] `CLOCK_MODE()` will not work properly for Arbitrum or Optimism due to `block.number`

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Proof of Concept

According to [Arbitrum Docs](https://developer.offchainlabs.com/time), `block.number` returns the most recently synced L1 block number. Once per minute, the block number in the `Sequencer` is synced to the actual L1 block number. Using `block.number` as a clock can lead to inaccurate timing.

It also presents an issue for [Optimism](https://community.optimism.io/docs/developers/build/differences/#block-numbers-and-timestamps) because each transaction is it's own block.

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L152>

### Recommended Mitigation Steps

Use `block.timestamp` rather than `block.number`

### Assessed type

Timing

**[LybraFinance commented](https://github.com/code-423n4/2023-06-lybra-findings/issues/114#issuecomment-1639775144):**
 > The governance contract only exists on the Ethereum mainnet.

**[LybraFinance acknowledged](https://github.com/code-423n4/2023-06-lybra-findings/issues/114#issuecomment-1656708522)**

***

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 9: M-6: Auction date will drift irreversibly forward over time leading to loss of yield for bond holders

**Source**: Sherlock
**Protocol**: Plaza Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/446 

## Found by 
0x52

### Summary

During the creation of the auction, lastDistribution is set to block.timestamp. Delays are compounding and will lead to loss of yield over time as the subsequent distribution will be delayed.

[Pool.sol#L530-L571](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L530-L571)

        function startAuction() external whenNotPaused() {
            // Check if distribution period has passed
    @>      require(lastDistribution + distributionPeriod < block.timestamp, DistributionPeriodNotPassed());

            // Check if auction period hasn't passed
            require(lastDistribution + distributionPeriod + auctionPeriod >= block.timestamp, AuctionPeriodPassed());

            ... SNIP

            // Update last distribution time
    @>      lastDistribution = block.timestamp;
        }

Above we see that lastDistribution is used to determine if the auction can be started. Additionally, lastDistribution is set to block.timestamp which means that any delay between lastDistribution + distributionPeriod and block.timestamp will cause loss of yield in the subsequent quarter.

According to sherlock rules a loss of 0.01% qualifies as medium impact. The distribution period is 1 quarter or 90 days which is 7 776 000 seconds. This means that a delay of 777.6 seconds (13 minutes) will break this threshold. Given that the start of the

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## block-period-patterns.md
# Block Period Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 2 | 1 | 0 |

**Common Sources**: Quantstamp, Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for block period vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-02] `BLOCK_PERIOD` is incorrect

**Source**: Code4rena
**Protocol**: zkSync
**Impact**: MEDIUM

**Details**:

[Config.sol#L47](https://github.com/code-423n4/2022-10-zksync/blob/456078b53a6d09636b84522ac8f3e8049e4e3af5/ethereum/contracts/zksync/Config.sol#L47)<br>

The `BLOCK_PERIOD` is set to 13 seconds in `Config.sol`.

```sol
uint256 constant BLOCK_PERIOD = 13 seconds;
```

Since moving to Proof-of-Stake (PoS) after the Merge, block times on ethereum are fixed at 12 seconds per block (slots).
<https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/#:~:text=Whereas%20under%20proof%2Dof%2Dwork,block%20proposer%20in%20every%20slot>.

### Impact

This results in incorrect calculation of `PRIORITY_EXPIRATION` which is used to determine when a transaction in the Priority Queue should be considered expired.

```sol
uint256 constant PRIORITY_EXPIRATION_PERIOD = 3 days;
/// @dev Expiration delta for priority request to be satisfied (in ETH blocks)
uint256 constant PRIORITY_EXPIRATION = PRIORITY_EXPIRATION_PERIOD/BLOCK_PERIOD;
```

The time difference can be calulated

```python
>>> 3*24*60*60 / 13    # 3 days / 13 sec block period
19938.46153846154
>>> 3*24*60*60 / 12    # 3 days / 12 sec block period
21600.0
>>> 21600 - 19938      # difference in blocks
1662
>>> 1662 * 12 / (60 * 60) # difference in hours
5.54
```

By using block time of 13 seconds, a transaction in the Priority Queue incorrectly expires 5.5 hours earlier than is expected.

5.5 hours is a significant amount of time difference so I believe this issue to be Medium severity.

### Recommended Mitigation Steps

Change

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-zksync)

---

### Example 2: M-2: `optionTokens` can be expired even though the epoch is not over

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/63 

## Found by 
BenRai, qandisa
## Summary

When deploying an `optionToken` the parameter `expiry` is rounded down to the nearest day at 0000 UTC but since the end of an epoch is calculated by the `epochDuration` and the exact time the epoch has stared and the `optionToken` was created this can lead to an epoch still being active but the corresponding `optionToken` to be already expired. 

## Vulnerability Detail

When starting a new epoch, the variable `epochStart` is set to the current time (`block.timestamp`) and the end of the epoch is calculated by adding the `epochDuration` to the `epochStart` variable. 

The `optionToken` of the new epoch is deployed with the parameter `expire` calculated based on the current time stamp, the `timeUntilEligible` and the `eligibleDuration`. (`uint48(block.timestamp) + timeUntilEligible + eligibleDuration`). The final expiration date of the optionToken is rounded down to the nearest day at 0000 UTC before the token is deployed.

Since the `epochDuration` can be as close as 1 second to the sum of `timeUntilEligible + eligibleDuration` this can lead to an epoch still being active but its `optionToken` to be already expired.

Example:

epochDuration = 7 days
timeUntilEligible = 0
eligibleDuration = 7 days + 12 hours


New epoch is launched on the 01.01.2024 at 11:45 am.

=>
epochStart = block.timestamp  = 01.01.2024 at 11:45 am
epochEnd = epochStart + epochDuration =

*[Content truncated...]*

---

### Example 3: Mismatched `msg_value` Validation and Refund Logic in `op::create_master` Causes Underfunded Transactions

**Source**: Quantstamp
**Protocol**: XDAO
**Impact**: LOW

**Details**:

**Update**
The team fixed the issue as recommended. Addressed in: `3be95dd540da57f9f2a1e20dd8f514e6158e9029`.

**File(s) affected:**`contracts/factory.fc`

**Description:** In the `factory`s `op::create_master`, the initial check requires `msg_value > service_fee + BASE_FEE * (6 + mint_messages_count)`, but the refund calculation deducts `service_fee + BASE_FEE * (8 + mint_messages_count)`. This discrepancy allows transactions that pass validation to fail later or refund less than expected, leading to user confusion and potential loss of funds.

**Exploit Scenario:**

1.   A user provides `msg_value` that meets the `(6 + mint_messages_count)` requirement but falls short of `(8 + mint_messages_count)`.
2.   Deployment proceeds past the initial check but later attempts to refund, leading to a revert or incorrect refund amount.
3.   The deployment unexpectedly fails or the user loses more TON than anticipated.

**Recommendation:** Align the validation threshold with the actual outgoing costs by updating the check to account for all `BASE_FEE` deductions (including minting flow and message sends). For example, require `msg_value > service_fee + BASE_FEE * (8 + mint_messages_count)`.

**Reference**: [View Original Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## event-patterns.md
# Event Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 2 | 1 |

**Common Sources**: Cyfrin, Code4rena, Hans, Sherlock

---

## Detection Checklist

- [ ] Check for event vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Centralization risk

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol has an owner with privileged rights to perform admin tasks that can affect users.
Especially, the owner can change the fee settings and reward handler address.

1. Validation is missing for admin fee setter functions.

```solidity
FeeData.sol
31:     function setFeeValue(uint256 feeValue) external onlyOwner {
32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");
33:         _feeValue = feeValue;
34:     }

43:
44:     function setFixedFee(uint256 fixedFee) external onlyOwner {//@audit-issue validate min/max
45:         _fixedFee = fixedFee;
46:     }
```

2. Important changes initiated by admin should be logged via events.

```solidity
File: helpers/FeeData.sol

31:     function setFeeValue(uint256 feeValue) external onlyOwner {

36:     function setMaxHops(uint256 maxHops) external onlyOwner {

40:     function setMaxSwaps(uint256 maxSwaps) external onlyOwner {

44:     function setFixedFee(uint256 fixedFee) external onlyOwner {

48:     function setFeeToken(address feeTokenAddress) public onlyOwner {

53:     function setFeeTokens(address[] memory feeTokenAddresses) public onlyOwner {

60:     function clearFeeTokens() public onlyOwner {

```

```solidity
File: helpers/TransferHelper.sol

86:     function setRewardHandler(address rewardAddress) external onlyOwner {

92:     function setRewardsActive(bool _rewardsActive) external onlyOwner {

```

**Impact:** While the protocol owner is rega

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 2: [M-16] `ApprovalAll` event is missing parameters

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L392](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/HolographERC721.sol#L392)<br>

`beforeApprovalAll()` / `afterApprovalAll()` can only pass "to" and "approved", missing "owner", if contract listening to this event,but does not know who approve it, so can not react to this event.<br>
Basically, this event cannot be used.

### Proof of Concept

      function setApprovalForAll(address to, bool approved) external {
    ....

        if (_isEventRegistered(HolographERC721Event.beforeApprovalAll)) {
          require(SourceERC721().beforeApprovalAll(to, approved)); /***** only to/approved ,need owner
        }  

        _operatorApprovals[msg.sender][to] = approved;

        if (_isEventRegistered(HolographERC721Event.afterApprovalAll)) {
          require(SourceERC721().afterApprovalAll(to, approved)); /***** only to/approved ,need owner
        }
      }

### Recommended Mitigation Steps

Add parameter: owner

    interface HolographedERC721 {
    ...

    - function beforeApprovalAll(address _to, bool _approved) external returns (bool success);
    + function beforeApprovalAll(address owner, address _to, bool _approved) external returns (bool success);

    - function afterApprovalAll(address _to, bool _approved) external returns (bool success);
    + function afterApprovalAll(address owner, address _to, bool _approved) external returns (bool success);

<!---->

      function setApprovalForAll

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 3: M-3: Lack of events for critical arithmetic parameters

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/33 

## Found by 
zimu

## Summary
Function `BondBaseSDA.setDefaults` sets critical arithmetic parameters for bond market. But it has no event emitted, it is difficult to track these critical changes off-chain.

## Vulnerability Detail
In `bases/BondBaseSDA`, critical parameters are set and changed in function `BondBaseSDA.setDefaults` for bond market.
![image](https://user-images.githubusercontent.com/112361239/201988699-b740b31b-e6d1-4bd8-b3da-2fb9bc7c68bd.png)

However, no event is emitted, and it is difficult to track these critical changes off-chain.  Both Users and Issuers would possibly be unware of  these changes.

## Impact
Both Users and Issuers would possibly be unware of  critical changes on bond market.

## Code Snippet
https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L348-L356

## Tool used
Manual Review

## Recommendation
Add an event in `BondBaseSDA.setDefaults` to report critical arithmetic changes.

## Discussion

**Evert0x**

Message from sponsor

----

Agree. We have updated `setDefaults` to emit an event with the newly set values.



**xiaoming9090**

Fixed in https://github.com/Bond-Protocol/bonds/commit/94e38f33b69b0184762c8be1c7bfd0716d97fed2

---

### Example 4: Wrong values or confusing words in event messages

**Source**: Hans
**Protocol**: Meta
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:**

- At [mUSD.sol#L146](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/mUSD.sol#L146), `postRebaseTokenAmount` should be calculated after decreasing `totalMUSDCirculation`.
- At [IDO.sol#L103](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L103), the event message is confusing. I recommend changing the message to `"IDO: Multisig account can not be this contract"`.

**Meta Team:**
Fixed.
(commit 007c1b9183cdb65a500928173608ebff0a5197ef)

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 5: [G-10] Missing events

**Source**: Code4rena
**Protocol**: Visor
**Impact**: GAS

**Details**:

_Submitted by cmichel_

The following events are not used:
- `IInstanceRegistry.InstanceRemoved`

Unused code can hint at programming or architectural errors.  Recommend using it or removing it.

**[xyz-ctrl (Visor) acknowledged but disputed severity](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-862607014):**

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-873480513):**
> Agree with sponsor, it doesnt present a security issue its a non-critical issue.

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-889191547):**
> patch [link](https://github.com/VisorFinance/visor-core/commit/cc22d6e450e16aaa9eb3af1ee4d9e6ac8afe43da#diff-b094db7ce2f99cbcbde7ec178a6754bac666e2192f076807acbd70d49ddd0559)

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 6: Unnecessary event emissions

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: LOW

**Details**:

`PriorityPool::setPoolStatusClosed` does not check if pool status is already `CLOSED` and emits `SetPoolStatus` event. Avoid event emission if the pool status is already closed. Avoid this. The same applies to the function `setPoolStatus` as well.

**Client:**
Fixed in this [PR](https://github.com/stakedotlink/contracts/pull/32).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## auditing-and-logging-patterns.md
# Auditing and Logging Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 1 | 2 | 0 |

**Common Sources**: Cyfrin, Quantstamp

---

## Detection Checklist

- [ ] Check for auditing and logging vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Centralization risk

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol has an owner with privileged rights to perform admin tasks that can affect users.
Especially, the owner can change the fee settings and reward handler address.

1. Validation is missing for admin fee setter functions.

```solidity
FeeData.sol
31:     function setFeeValue(uint256 feeValue) external onlyOwner {
32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");
33:         _feeValue = feeValue;
34:     }

43:
44:     function setFixedFee(uint256 fixedFee) external onlyOwner {//@audit-issue validate min/max
45:         _fixedFee = fixedFee;
46:     }
```

2. Important changes initiated by admin should be logged via events.

```solidity
File: helpers/FeeData.sol

31:     function setFeeValue(uint256 feeValue) external onlyOwner {

36:     function setMaxHops(uint256 maxHops) external onlyOwner {

40:     function setMaxSwaps(uint256 maxSwaps) external onlyOwner {

44:     function setFixedFee(uint256 fixedFee) external onlyOwner {

48:     function setFeeToken(address feeTokenAddress) public onlyOwner {

53:     function setFeeTokens(address[] memory feeTokenAddresses) public onlyOwner {

60:     function clearFeeTokens() public onlyOwner {

```

```solidity
File: helpers/TransferHelper.sol

86:     function setRewardHandler(address rewardAddress) external onlyOwner {

92:     function setRewardsActive(bool _rewardsActive) external onlyOwner {

```

**Impact:** While the protocol owner is rega

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 2: Reserved assets could be extracted from the Vault

**Source**: Cyfrin
**Protocol**: Accountable
**Impact**: LOW

**Details**:

**Description:** Some strategy functions can release assets without checking if those assets are part of `reservedLiquidity`. `AccountableFixedTerm._loan.drawableFunds` is not verified to be in sync with the queue `reservedLiquidity`. Hence the borrower can inadvertently borrow more funds than they should.

**Impact:** The vault can become insolvent by releasing funds needed to honor a withdrawal.

**Proof of Concept:** Violated in `FixedTerm.acceptLoanLocked(), FixedTerm.borrow(), FixedTerm.pay(), FixedTerm.acceptLoanDynamic(), FixedTerm.claimInterest()`: https://prover.certora.com/output/52567/edb399a43d1849a9b22f027e66b17924/?anonymousKey=3dcf62dfa004381083966b3639b6a485fa2e9501

```solidity
// Reserved liquidity must not exceed total assets
invariant reservedLiquidityBacked(env e)
    ghostReservedLiquidity256 <= ghostTotalAssets256
```

**Recommended Mitigation:** When `reservedLiquidity` is increased in the withdrawal queue, this needs to be synced to the FixedTerm starategy.

**Accountable:** Fixed in commit [`979c0e`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/979c0ebe4bd5860fe9b2e446f9fac2ae3919b39c).

Issue was addressed to satisfy the invariant and prevent future upgrades that might allow redemptions in a FixedTerm loan, but as of right now there's no possible way to increase `reservedLiquidity` such that it is out-of-sync with`drawableFunds`.

Borrowing after the loan is in a `Repaid` state cannot happen due to `_requireLoanOngoing` so a

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-16-cyfrin-accountable-v2.0.md)

---

### Example 3: Missing Validation for Zero `success_percentage` in DAO Creation

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

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## code-quality-patterns.md
# Code Quality Security Patterns

## Overview

**Frequency**: 10 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 0 | 8 | 1 |

**Common Sources**: Cyfrin, Cantina, MixBytes, Hans, Code4rena

---

## Detection Checklist

- [ ] Check for code quality vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Debug code in `getPriceByExternal`

**Source**: MixBytes
**Protocol**: Divergence Protocol
**Impact**: HIGH

**Details**:

##### Description
The last instruction of the `getPriceByExternal` function will always return the same price (30_000e18). 
https://github.com/DivergenceProtocol/diver-contracts/blob/e5286f94a7ccb9d6279fae51ea66a8833672628a/src/core/Oracle.sol#L43
It leads to the incorrect settles of battles. An attacker can use this code issue for getting profit from bets. 
##### Recommendation
We recommend removing the `return (30_000e18, 0)` instruction from the function.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Divergence%20Protocol/README.md#1-debug-code-in-getpricebyexternal)

---

### Example 2: Unnecessary logical operation

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** In the function `SwapExchange::calculateMultiSwap()` there is a logical operation that is not necessary in the for loop.

```solidity
SwapExchange.sol
161:         for (uint256 i = 0; i < swapIdCount; i++) {
162:             swapId = multiClaimInput.swapIds[i];
163:             SwapUtils.Swap memory swap = swaps[swapId];
164:             if (swap.tokenB != matchToken) revert Errors.NonMatchingToken();
165:             if (swap.amountB < matchAmount) revert Errors.NonMatchingAmount();
166:             if (matchAmount < swap.amountB) {
167:                 if (!swap.isPartial) revert Errors.NotPartialSwap();
168:                 matchAmount = MathUtils._mulDiv(swap.amountA, matchAmount, swap.amountB);
169:                 complete = complete && false;//@audit-issue INFO unnecessary operation, just set complete=false
170:             }
171:             else {
172:                 matchAmount = swap.amountA;
173:             }
174:             matchToken = swap.tokenA;
175:         }
```

**Protocol:** Fixed in commit [a079c11](https://github.com/SwapExchangeio/Contracts/commit/a079c11cc3bc044c61493040dab1f94de4a0f14a).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 3: Not proper variable naming

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The contract `FeeData` has a internal variable `_feeValue` that is used to calculate the fee.
Across the usage of this variable, it is used as a numerator while calculating the fee percentage.
We recommend renaming this variable to `feeNumerator` to avoid confusion.

```solidity
FeeUtils.sol
16:     function _calculateFees(uint256 amountA, uint256 amountB, uint8 feeType,  uint256 hops, uint256 feeValue, uint256 feeDenominator, uint256 fixedFee)
17:     internal pure returns (uint256) {
18:         if (feeType == Constants.FEE_TYPE_TOKEN_B) {
19:             return MathUtils._mulDiv(amountB, feeValue, feeDenominator) * hops;
20:         }
21:         if (feeType == Constants.FEE_TYPE_TOKEN_A) {
22:             return MathUtils._mulDiv(amountA, feeValue, feeDenominator) * hops;
23:         }
24:         if (feeType == Constants.FEE_TYPE_ETH_FIXED) {
25:             return fixedFee * hops;
26:         }
27:         revert Errors.UnknownFeeType(feeType);
28:     }
```

**Protocol:** Fixed in commit [f6154c9](https://github.com/SwapExchangeio/Contracts/commit/f6154c99edabe7b62d956935a94567c88ee89b3d).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 4: Functions not used internally could be marked external

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** Using proper visibility modifiers is a good practice to prevent unintended access to functions.
Furthermore, marking functions as `external` instead of `public` can save gas.

```solidity
File: DepositVault.sol

37:     function deposit(uint256 amount, address tokenAddress) public payable

59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public

81:     function withdrawDeposit(uint256 depositIndex) public
```

**Recommended Mitigation:** Consider change the visibility modifier to `external` for the functions that are not used internally.

**Client:**
Fixed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 5: Unnecessary parameter amount in withdraw function

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The function `withdraw()` has a parameter `amount` but we don't understand the necessity of this parameter.
At line L67, the amount is required to be the same to the whole deposit amount. This means the user does not have a flexibility to choose the withdraw amount, after all it means the parameter was not necessary at all.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");//@audit-info only full withdrawal is allowed
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depositToWithdraw.tokenAddress);
75:             token.safeTransfer(recipient, amount);
76:      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 6: Nonstandard usage of nonce

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The protocol implemented two withdraw functions `withdrawDeposit()` and `withdraw()`.
While the function `withdrawDeposit()` is designed to be used by the depositor themselves, the function `withdraw()` is designed to be used by anyone who has a signature from the depositor.
The function `withdraw()` has a parameter `nonce` but the usage of this param is not aligned with the general meaning of nonce.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];//@audit-info non aligned with common understanding of nonce
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 7: The deposit function is not following CEI pattern

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);//@audit-issue against CEI pattern
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L47, we can see that the token transfer happens before updating the accounting state of the protocol against the CEI pattern.
Because the protocol intends to support all ERC20 tokens, the tokens with hooks (e.g. ERC777) can be exploited for reentrancy.
Although we can n

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 8: Use modifier instead of repeating the same code block

**Source**: Hans
**Protocol**: Meta
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:**

There are numerous places where the same code block is repeated. These can be replaced with a modifier.

- [IDO.sol#L92](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L92), [IDO.sol#L129](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L129), [IDO.sol#L134](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L134)

- [IDO.sol#L160](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L160), [IDO.sol#L173](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L173), [IDO.sol#L181](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L181)

- [ESMeta.sol#L35](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/ESMeta.sol#L35), [ESMeta.sol#L50](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/ESMeta.sol#L50)

**Meta Team:**

Fixed. Either refactored the code or used modifiers.

(commit : 007c1b9183cdb65a500928173608ebff0a5197ef)

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 9: Interface recommendations 

**Source**: Cantina
**Protocol**: Olas
**Impact**: LOW

**Details**:

## Context
(No context files were provided by the reviewer)

## Description/Recommendation
- **IMech.sol#L15-L21:** `maxDeliveryRate` and `paymentType` can be defined as `view`. This will guarantee that when those interface endpoints are used, `staticcall` is made instead of a regular call.
- **IStaking.sol:** `IStaking.sol` does not seem to be used and perhaps can be removed.

## Valory
Fixed on PR 94.

## Cantina Managed
Fix verified.

**Reference**: [View Original Finding](https://cdn.cantina.xyz/reports/cantina_valory_january2025.pdf)

---

### Example 10: [G-10] Missing events

**Source**: Code4rena
**Protocol**: Visor
**Impact**: GAS

**Details**:

_Submitted by cmichel_

The following events are not used:
- `IInstanceRegistry.InstanceRemoved`

Unused code can hint at programming or architectural errors.  Recommend using it or removing it.

**[xyz-ctrl (Visor) acknowledged but disputed severity](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-862607014):**

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-873480513):**
> Agree with sponsor, it doesnt present a security issue its a non-critical issue.

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-889191547):**
> patch [link](https://github.com/VisorFinance/visor-core/commit/cc22d6e450e16aaa9eb3af1ee4d9e6ac8afe43da#diff-b094db7ce2f99cbcbde7ec178a6754bac666e2192f076807acbd70d49ddd0559)

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

## Statistics

- Total findings analyzed: 10
- Examples shown: 10
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## coding-bug-patterns.md
# Coding-Bug Security Patterns

## Overview

**Frequency**: 20 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 11 | 8 | 1 | 0 |

**Common Sources**: Sherlock, Cyfrin, Hans

---

## Detection Checklist

- [ ] Check for coding-bug vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/109 

## Found by 
berndartmueller, carrot, minhtrng, 0Kage, Jeiwan, chaduke, koxuan, Ruhum, cergyk, rbserver, stent, saian, XKET, GimelSec

## Summary
Soft vault shares are issued against interest bearing tokens issued by `Compound` protocol in exchange for underlying deposits. However, `withdrawLend` function caps the withdrawable amount to initial underlying deposited by user (`pos.underlyingAmount`). Capping underlying amount to initial underlying deposited would mean that a user can burn all his vault shares in `withdrawLend` function and only receive original underlying deposited.

Interest accrued component received from Soft vault (that rightfully belongs to the user) is no longer retrievable because the underlying vault shares are already burnt. Loss to the users is permanent as such interest amount sits permanently locked in Blueberry bank.

## Vulnerability Detail

[`withdrawLend` function in `BlueBerryBank`](https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/BlueBerryBank.sol#L669) allows users to withdraw underlying amount from `Hard` or `Soft` vaults. `Soft` vault shares are backed by interest bearing `cTokens` issued by Compound Protocol

User can request underlying by specifying `shareAmount`. When user tries to send the maximum `shareAmount` to withdraw all the lent amount, notice that the amount withdrawable is limited to the `pos.underlyingAmount` (original depos

*[Content truncated...]*

---

### Example 2: Wrong validation in `DefaultUndelegationPolicy.onUndelegate()`

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `onUndelegate()`, it checks if the operator owner still holds at least `minimumSelfDelegationFraction` of total supply.

```solidity
   function onUndelegate(address delegator, uint amount) external {
       // limitation only applies to the operator, others can always undelegate
       if (delegator != owner) { return; }

       uint actualAmount = amount < balanceOf(owner) ? amount : balanceOf(owner); //@audit amount:DATA, balanceOf:Operator
       uint balanceAfter = balanceOf(owner) - actualAmount;
       uint totalSupplyAfter = totalSupply() - actualAmount;
       require(1 ether * balanceAfter >= totalSupplyAfter * streamrConfig.minimumSelfDelegationFraction(), "error_selfDelegationTooLow");
   }
```

But `amount` means the DATA token amount and `balanceOf(owner)` indicates the `Operator` token balance and it's impossible to compare them directly.

**Impact:** The operator owner wouldn't be able to undelegate because `onUndelegate()` works unexpectedly.

**Recommended Mitigation:** `onUndelegate()` should compare amounts after converting to the same token.

**Client:** Fixed in commit [9b8c65e](https://github.com/streamr-dev/network-contracts/commit/9b8c65ea31b6bf15fe4ec913a975782f27c0c9a0).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 3: H-1: attackers will keep stealing the `rewards` from Convex SPELL

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/101 

## Found by 
Bauer, Ch\_301
## Summary
On [WConvexPools.burn()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235) transfer [CRV + CVX + the extra rewards](https://docs.convexfinance.com/convexfinance/general-information/why-convex/convex-for-liquidity-providers) to Convex SPELL 


## Vulnerability Detail
But [ConvexSpell.openPositionFarm()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L67-L138) only refund CVX to the user.
So the rest rewards will stay in the SPELL intel if someone (could be an attacker) invokes `_doRefund()` within `closePositionFarm()` with the same address tokens 

## Impact
- Convex SPELL steals the user rewards 
- the protocol will lose some fees 
- attackers will keep stealing the rewards from Convex SPELL

## Code Snippet
`WConvexPools.burn()` transfer CRV + CVX + the extra rewards
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235
```solidity
        // Transfer LP Tokens
        IERC20Upgradeable(lpToken).safeTransfer(msg.sender, amount);

        // Transfer Reward Tokens
        (rewardTokens, rewards) = pendingRewards(id, amount);

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                

*[Content truncated...]*

---

### Example 4: H-6: ShortLongSpell#_withdraw checks slippage limit but never applies it making it useless

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/126 

## Found by 
0x52, Ch\_301
## Summary

Slippage limits protect the protocol in the event that a malicious user wants to extract value via swaps, this is an important protection in the event that a user finds a way to trick collateral requirements. Currently the sell slippage is checked but never applied so it is useless.

## Vulnerability Detail

See summary.

## Impact

Slippage limit protections are ineffective for ShortLongSpell

## Code Snippet

[ShortLongSpell.sol#L160-L20](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Review

## Recommendation

Apply sell slippage after it is checked



## Discussion

**securitygrid**

Escalate for 10 USDC
This is not a valid M/H. The toAmont and expectedAmount in the off-chain parameter [MegaSwapSellData](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/libraries/Paraswap/Utils.sol#L30-L42) structure are the real slippage protection parameters. Just like ExactInputParams/ExactOutputParams of uniswapV3 pool.

**sherlock-admin**

 > Escalate for 10 USDC
> This is not a valid M/H. The toAmont and expectedAmount in the off-chain parameter [MegaSwapSellData](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/libraries/Paraswap/Utils.sol#L30-L42) structure are the real slippage protection par

*[Content truncated...]*

---

### Example 5: H-9: BlueBerryBank#withdrawLend will cause underlying token accounting error if soft/hard vault has withdraw fee

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/33 

## Found by 
y1cunhui, rvierdiiev, csanuragjain, Ruhum, evan, 0x52

## Summary

Soft/hard vaults can have a withdraw fee. This takes a certain percentage from the user when they withdraw. The way that the token accounting works in BlueBerryBank#withdrawLend, it will only remove the amount returned by the hard/soft vault from pos.underlying amount. If there is a withdraw fee, underlying amount will not be decrease properly and the user will be left with phantom collateral that they can still use.

## Vulnerability Detail

        // Cut withdraw fee if it is in withdrawVaultFee Window (2 months)
        if (
            block.timestamp <
            config.withdrawVaultFeeWindowStartTime() +
                config.withdrawVaultFeeWindow()
        ) {
            uint256 fee = (withdrawAmount * config.withdrawVaultFee()) /
                DENOMINATOR;
            uToken.safeTransfer(config.treasury(), fee);
            withdrawAmount -= fee;
        }

Both SoftVault and HardVault implement a withdraw fee. Here we see that withdrawAmount (the return value) is decreased by the fee amount.

        uint256 wAmount;
        if (address(ISoftVault(bank.softVault).uToken()) == token) {
            ISoftVault(bank.softVault).approve(
                bank.softVault,
                type(uint256).max
            );
            wAmount = ISoftVault(bank.softVault).withdraw(shareAmount);
        } else {
    

*[Content truncated...]*

---

### Example 6: Some constants wouldn't work as expected.

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`Constants.sol#L5`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/lib/Constants.sol#L5)

**Description:**
Two constants `KEEPER_RATE` and `MAX_KEEPER_RATE` are declared like the below.

```solidity
uint256 constant KEEPER_RATE = 0.01e18; //1%
uint256 constant MAX_KEEPER_RATE = 0.05e18; //5%
```

But when we use the `KEEPER_RATE` in `liquidation()/superLiquidation()`, we divide the rate by 100 again.

```solidity
if (provider == msg.sender) {
glp.transfer(msg.sender, reducedGLP);
} else {
reward2keeper = (reducedGLP * rates.getKR()) / 110 / Constants.PINT; //@audit divide by 100 again
glp.transfer(provider, reducedGLP - reward2keeper);
glp.transfer(msg.sender, reward2keeper);
}
```

So the default keeper rate will be 0.01% instead of 1% during the liquidation.

**Impact**
The reward rate for the keepers wouldn't work as expected. Because it will just affect the reward rate for keepers without losing funds, I evaluate the severity to Medium.

**Recommendation:**
Modify the constants or reward calculation formula accordingly.

**Meta Team:**

The keepr rewards and number libraries are consistenly used. And necessary changes have been made in the commit 007c1b9183cdb65a500928173608ebff0a5197ef

```
Constants.sol

library Constants {
// Base constants
uint256 constant PINT = 1e18;
uint256 constant HUNDRED_PERCENT = 100e18; //100

// Collateral constants
uint256 constant BAD_COLLATERAL_LIMIT = 150e

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 7: H-2: ShortLongSpell#openPosition uses the wrong balanceOf when determining how much collateral to put

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/31 

## Found by 
0x52
## Summary

The _doPutCollateral subcall in ShortLongSpell#openPosition uses the balance of the uToken rather than the vault resulting in the vault tokens being left in the contract which will be stolen.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L144-L150

        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );

When putting the collateral the contract is putting vault but it uses the balance of the uToken instead of the balance of the vault.

## Impact

Vault tokens will be left in contract and stolen

## Code Snippet

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L111-L151

## Tool used

Manual Review

## Recommendation

Use the balanceOf vault rather than vault.uToken



## Discussion

**sleepriverfish**

Escalate for 10 USDC

In #Blueberry Update, despite the successful escalation of the issue, no reward was granted for the heightened severity and impact of the vulnerability. However, in #Blueberry Update2, a reward was offered specifically for the detection and reporting of a similar vulnerability.
https://github.com/sherlock-audit/2023-04-bluebe

*[Content truncated...]*

---

### Example 8: M-2: price is calculated wrongly in BoundedStepwiseExponentialPriceAdapter

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/39 

## Found by 
0x007, 0x52, Brenzee, auditsea, dany.armstrong90
## Summary
The BoundedStepwiseExponentialPriceAdapter contract is trying to implement price change as `scalingFactor * (e^x - 1)` but the code implements `scalingFactor * e^x - 1`. Since there are no brackets, multiplication would be executed before subtraction. And this has been confirmed with one of the team members.

## Vulnerability Detail
The [getPrice code](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/integration/auction-price/BoundedStepwiseExponentialPriceAdapter.sol#L40-L73) has been simplified as the following when boundary/edge cases are ignored

```solidity
(
    uint256 initialPrice,
    uint256 scalingFactor,
    uint256 timeCoefficient,
    uint256 bucketSize,
    bool isDecreasing,
    uint256 maxPrice,
    uint256 minPrice
) = getDecodedData(_priceAdapterConfigData);

uint256 timeBucket = _timeElapsed / bucketSize;

int256 expArgument = int256(timeCoefficient * timeBucket);

uint256 expExpression = uint256(FixedPointMathLib.expWad(expArgument));

uint256 priceChange = scalingFactor * expExpression - WAD;
```

When timeBucket is 0, we want priceChange to be 0, so that the returned price would be the initial price. Since `e^0 = 1`, we need to subtract 1 (in WAD) from the `expExpression`. 

However, with the incorrect implementation, the returned price would be different than real

*[Content truncated...]*

---

### Example 9: M-3: Cancellation refunds should return tokens to order creator, not recipient

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/61 

## Found by 
0x007, ArmedGoose, Kodyvim, ctf\_sec, dirk\_y, james\_wu, osmanozdemir1, shtesesamoubiq
## Summary
When an order is cancelled, the refund is sent to `order.recipient` instead of the order creator because it is the order creator (requestor) pay the payment token for buy order or pay the dShares for sell order

As is the standard in many L1/L2 bridges, cancelled deposits should be returned to the order creator instead of the recipient. In Dinari's current implementation, a refund acts as a transfer with a middle-man.

## Vulnerability Detail
Simply, the `_cancelOrderAccounting()` function returns the refund to the `order.recipient`:

```solidity
    function _cancelOrderAccounting(OrderRequest calldata orderRequest, bytes32 orderId, OrderState memory orderState)
        internal
        virtual
        override
    {
        ...

        uint256 refund = orderState.remainingOrder + feeState.remainingPercentageFees;

        ...

        if (refund + feeState.feesEarned == orderRequest.quantityIn) {
            _closeOrder(orderId, orderRequest.paymentToken, 0);
            // Refund full payment
            refund = orderRequest.quantityIn;
        } else {
            // Otherwise close order and transfer fees
            _closeOrder(orderId, orderRequest.paymentToken, feeState.feesEarned);
        }


        // Return escrow
        IERC20(orderRequest.paymentToken).safeTransfer(orderRe

*[Content truncated...]*

---

### Example 10: M-8: asking for the wrong address for `balanceOf()`

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/116 

## Found by 
Ch\_301
## Summary

## Vulnerability Detail
ShortLongSpell.[openPosition()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L143-L150) pass to `_doPutCollateral()` wrong value of `balanceOf()`
```solidity
        // 5. Put collateral - strategy token
        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );
```
the balance should be of `address(vault)`

## Impact
- `openPosition()` will never work

## Code Snippet

## Tool used

Manual Review

## Recommendation
```diff
        // 5. Put collateral - strategy token
        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
-            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
-                address(this)
+                IERC20Upgradeable(vault).balanceOf(address(this))
            )
        );
```



## Discussion

**Ch-301**

Escalate for 10 USDC

This is a simple finding when you know that `SoftVault` is transferring all `uToken` to Compound to generate yield 

Also of wonder the judge set this as invalid but he submitted both this and #114  in the next contest **Blueberry Update 2**

**sherlock-admin**

 > Escalate for 10 USDC
> 
> This 

*[Content truncated...]*

---

### Example 11: M-6: M-03 wrong token address on `ShortLongSpell.sol`

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/114 

## Found by 
Ch\_301
## Summary

## Vulnerability Detail
[ShortLongSpell.openPosition()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#LL111C4-L151C6) send `uToken` to SoftVault then deposit it into the Compound protocol to earn a passive yield. In return, SPELL receives share tokes of SoftVault  `address(strategy.vault)`  

`WERC20.sol` should receive `address(strategy.vault)` token, but the logic of `ShortLongSpell.sol` subcall (WERC20.sol) `wrapper.burn()` and pass the `uToken` address (please check the Code Snippet part) instead of `strategy.vault` address

## Impact
Short/Long Spell will never work

## Code Snippet
1- https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L128-L141
```solidity
            address burnToken = address(ISoftVault(strategy.vault).uToken());
            if (collSize > 0) {
                if (posCollToken != address(wrapper))
                    revert Errors.INCORRECT_COLTOKEN(posCollToken);
                bank.takeCollateral(collSize);
                wrapper.burn(burnToken, collSize);
                _doRefund(burnToken);
            }
```
2- https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L229-L234
```solidity
        // 1. Take out collateral
        bank.takeCollateral(par

*[Content truncated...]*

---

### Example 12: M-3: The protocol  will not be able to add liquidity on the curve with another token with a balance.

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/47 

## Found by 
Bauer, nobody2018
## Summary
The `CurveSpell` protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.

## Vulnerability Detail
The  `openPositionFarm()` function enables user to open a leveraged position in a yield farming strategy by borrowing funds and using them to add liquidity to a Curve pool, while also taking into account certain risk management parameters such as maximum LTV and position size. When add liquidity on curve ,the protocol use the borrowed token and the collateral token, it checks the number of tokens in the pool and creates an array of the supplied token amounts to be passed to the add_liquidity function. Then the curve will transfer the tokens from the protocol and mint lp tokens to the protocol. However, the protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.
```solidity
 // 3. Add liquidity on curve
        _ensureApprove(param.borrowToken, pool, borrowBalance);
        if (tokens.length == 2) {
            uint256[2] memory suppliedAmts;
            for (uint256 i = 0; i < 2; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_

*[Content truncated...]*

---

### Example 13: M-2: AuraSpell openPositionFarm does not join pool

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/46 

## Found by 
Ch\_301, cducrest-brainbot, cuthalion0x, nobody2018
## Summary

The function to open a position for the AuraSpell does not join the pool due to wrong conditional check.

## Vulnerability Detail

The function deposits collateral into the bank, borrow tokens, and attempts to join the pool:

```solidity
    function openPositionFarm(
        OpenPosParam calldata param
    )
        external
        existingStrategy(param.strategyId)
        existingCollateral(param.strategyId, param.collToken)
    {
        ...
        // 1. Deposit isolated collaterals on Blueberry Money Market
        _doLend(param.collToken, param.collAmount);

        // 2. Borrow specific amounts
        uint256 borrowBalance = _doBorrow(
            param.borrowToken,
            param.borrowAmount
        );

        // 3. Add liquidity on Balancer, get BPT
        {
            IBalancerVault vault = wAuraPools.getVault(lpToken);
            _ensureApprove(param.borrowToken, address(vault), borrowBalance);

            (address[] memory tokens, uint256[] memory balances, ) = wAuraPools
                .getPoolTokens(lpToken);
            uint[] memory maxAmountsIn = new uint[](2);
            maxAmountsIn[0] = IERC20(tokens[0]).balanceOf(address(this));
            maxAmountsIn[1] = IERC20(tokens[1]).balanceOf(address(this));

            uint totalLPSupply = IBalancerPool(lpToken).totalSupply();
            // 

*[Content truncated...]*

---

### Example 14: H-12: Pending CRV rewards are not accounted for and can cause unfair liquidations

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/136 

## Found by 
0x52
## Summary

pendingRewards are factored into the health of a position so that the position collateral is fairly assessed. However WCurveGauge#pendingRewards doesn't return the proper reward tokens/amounts meaning that positions aren't valued correctly and users can be unfairly liquidated.

## Vulnerability Detail

[BlueBerryBank.sol#L408-L413](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L408-L413)

            (address[] memory tokens, uint256[] memory rewards) = IERC20Wrapper(
                pos.collToken
            ).pendingRewards(pos.collId, pos.collateralSize);
            for (uint256 i; i < tokens.length; i++) {
                rewardsValue += oracle.getTokenValue(tokens[i], rewards[i]);
            }

When BlueBerryBank is valuing a position it also values the pending rewards since they also have value. 

[WCurveGauge.sol#L106-L114](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WCurveGauge.sol#L106-L114)

    function pendingRewards(
        uint256 tokenId,
        uint256 amount
    )
        public
        view
        override
        returns (address[] memory tokens, uint256[] memory rewards)
    {}

Above we see that WCurveGauge#pendingRewards returns empty arrays when called. This means that pending rewards are not factored in correctly and users can be 

*[Content truncated...]*

---

### Example 15: H-10: Balance check for swapToken in ShortLongSpell#_deposit is incorrect and will result in nonfunctional contract

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/133 

## Found by 
0x52, Ch\_301, sinarette
## Summary

The balance checks on ShortLongSpell#_withdraw are incorrect and will make contract basically nonfunctional 

## Vulnerability Detail

swapToken is always vault.uToken. borrowToken is always required to be vault.uToken which means that swapToken == borrowToken. This means that the token borrowed is always required to be swapped. 

[ShortLongSpell.sol#L83-L89](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L83-L89)

        uint256 strTokenAmt = _doBorrow(param.borrowToken, param.borrowAmount);

        // 3. Swap borrowed token to strategy token
        IERC20Upgradeable swapToken = ISoftVault(strategy.vault).uToken();
        // swapData.fromAmount = strTokenAmt;
        PSwapLib.megaSwap(augustusSwapper, tokenTransferProxy, swapData);
        strTokenAmt = swapToken.balanceOf(address(this)) - strTokenAmt; <- @audit-issue will always revert on swap

Because swapToken == borrowToken if there is ever a swap then the swapToken balance will decrease. This causes L89 to always revert when a swap happens, making the contract completely non-functional

## Impact

ShortLongSpell is nonfunctional

## Code Snippet

[ShortLongSpell.sol#L160-L202](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Revi

*[Content truncated...]*

---

### Example 16: H-8: UserData for balancer pool exits is malformed and will permanently trap users

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/129 

## Found by 
0x52, cuthalion0x
## Summary

UserData for balancer pool exits is malformed and will result in all withdrawal attempts failing, trapping the user permanently. 

## Vulnerability Detail

[AuraSpell.sol#L184-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L184-L189)

    wAuraPools.getVault(lpToken).exitPool(
        IBalancerPool(lpToken).getPoolId(),
        address(this),
        address(this),
        IBalancerVault.ExitPoolRequest(tokens, minAmountsOut, "", false)
    );

We see above that UserData is encoded as "". This is problematic as it doesn't contain the proper data for exiting the pool, causing all exit request to fail and trap the user permanently.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F9#L50

    function exactBptInForTokenOut(bytes memory self) internal pure returns (uint256 bptAmountIn, uint256 tokenIndex) {
        (, bptAmountIn, tokenIndex) = abi.decode(self, (WeightedPool.ExitKind, uint256, uint256));
    }

UserData is decoded into the data shown above when using ExitKind = 0. Since the exit uses "" as the user data this will be decoded as 0 a.k.a [EXACT_BPT_IN_FOR_ONE_TOKEN_OUT](https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L50). This is problematic because the token index and bptAmountIn should also be encoded in user data f

*[Content truncated...]*

---

### Example 17: H-7: WAuraPools will irreversibly break if reward tokens are added to pool after deposit

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/127 

## Found by 
0x52, Ch\_301
## Summary

WAuraPools will irreversibly break if reward tokens are added to pool after deposit due to an OOB error on accExtPerShare.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength(); <- @audit-issue rewardTokenCount pulled fresh
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);

            @audit-issue attempts to pull from array which will be too small if tokens are added
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

accExtPerShare stores the current rewardPerToken when the position is fir

*[Content truncated...]*

---

### Example 18: H-2: AuraSpell#openPositionFarm uses incorrect join type for balancer

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/120 

## Found by 
0x52, cuthalion0x
## Summary

The JoinPoolRequest uses "" for userData meaning that it will decode into 0. This is problematic because join requests of type 0 are "init" type joins and will revert for pools that are already initialized. 

## Vulnerability Detail

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L49

    enum JoinKind { INIT, EXACT_TOKENS_IN_FOR_BPT_OUT, TOKEN_IN_FOR_EXACT_BPT_OUT }

We see above that enum JoinKind is INIT for 0 values.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L290

            return _joinExactTokensInForBPTOut(balances, normalizedWeights, userData);
        } else if (kind == JoinKind.TOKEN_IN_FOR_EXACT_BPT_OUT) {
            return _joinTokenInForExactBPTOut(balances, normalizedWeights, userData);
        } else {
            _revert(Errors.UNHANDLED_JOIN_KIND);
        }

Here user data is decoded into join type and since it is "" it will decode to type 0 which will result in a revert.

## Impact

Users will be unable to open any farm position on AuraSpell

## Code Snippet

[AuraSpell.sol#L63-L147](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L63-L147)

## Tool used

Manual Review

## Recommendation

Uses JoinKind = 1 for user data

---

### Example 19: Unnecessary parameter amount in withdraw function

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The function `withdraw()` has a parameter `amount` but we don't understand the necessity of this parameter.
At line L67, the amount is required to be the same to the whole deposit amount. This means the user does not have a flexibility to choose the withdraw amount, after all it means the parameter was not necessary at all.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");//@audit-info only full withdrawal is allowed
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depositToWithdraw.tokenAddress);
75:             token.safeTransfer(recipient, amount);
76:      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 20: M-2: ShortLongSpell#openPosition attempts to burn wrong token

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/30 

## Found by 
0x52
## Summary

ShortLongSpell#openPosition attempts to burn vault.uToken when it should be using vault instead. The result is that ShortLongSpell#openPosition will be completely nonfunctional when the user is adding to their position

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L133-L140

            address burnToken = address(ISoftVault(strategy.vault).uToken());
            if (collSize > 0) {
                if (posCollToken != address(wrapper))
                    revert Errors.INCORRECT_COLTOKEN(posCollToken);
                bank.takeCollateral(collSize);
                wrapper.burn(burnToken, collSize);
                _doRefund(burnToken);
            }

We see above that the contract attempts to withdraw vault.uToken from the wrapper.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L145-L150

        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );

This is in direct conflict with the collateral that is actually deposited which is vault. This will cause the function to always revert when adding to an existing position.

## Impact

ShortLongSpell#openPosition will be completely nonfunctional when the user is

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 20
- Examples shown: 20
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## typo-copypaste-patterns.md
# Typo / CopyPaste Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 4 | 1 | 0 |

**Common Sources**: Code4rena, Sherlock, Halborn

---

## Detection Checklist

- [ ] Check for typo / copypaste vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Use of tokenBs price instead of tokenA in determining account health will lead to protocol mis-accounting and insolvency

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

_Submitted by 0xRajeev, also found by WatchPug_.

#### Impact

In `_supplyCreditUni()`, the last argument of `_convertTokenValues()` on `L674 being _priceB` instead of `_priceA` in the calculation of `supplyB` is a typo (should be `_priceA`) and therefore miscalculates `supplyB`, `creditB`, `creditUni` and therefore `totalAccountSupply` in function `accountHealth()` which affects the health of account/protocol determination that is used across all borrows/withdrawals/transfers/liquidations in the protocol. This miscalculation significantly affects all calculations in protocol and could therefore cause protocol insolvency.

#### Proof of Concept

- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L674>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L340>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L398-L401>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L532>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L544>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c48235289a25b2134bb16530185483e8c85507f8/contracts/LendingPair.sol#L119>
- <https://github.com/code-423n4/2021-09-wildcredit/blob/c482

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-wildcredit)

---

### Example 2: M-8: Wrong `CHANGE_COLLATERAL_DELAY` in CollateralBook

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/191 

## Found by 
GimelSec, CodingNameKiki, ctf\_sec, Jeiwan, yixxas, 0xjayne, rvierdiiev

## Summary

Admins can bypass time delay due to the wrong value of `CHANGE_COLLATERAL_DELAY`.

## Vulnerability Detail

The comment shows that the `CHANGE_COLLATERAL_DELAY` should be 2 days, but it's only 200 which means 3 minutes and 20 seconds.

## Impact

Admin can bypass the 2 days time delay and only need to wait less than 5 minutes to call `changeCollateralType`.

## Code Snippet

https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/CollateralBook.sol#L23
https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/CollateralBook.sol#L130

## Tool used

Manual Review

## Recommendation

```solidity
uint256 public constant CHANGE_COLLATERAL_DELAY = 2 days; //2 days
```

## Discussion

**kree-dotcom**

Sponsor confirmed, will fix. Duplicate of issue #231

---

### Example 3: M-4: Wrong constants for time delay

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/231 

## Found by 
GimelSec, neumo, 0x4non, hansfriese, rvierdiiev, wagmi, jonatascm



## Summary
This protocol uses several constants for time dealy and some of them are incorrect.

## Vulnerability Detail
In `isoUSDToken.sol`, `ISOUSD_TIME_DELAY` should be `3 days` instead of 3 seconds.

```solidity
    uint256 constant ISOUSD_TIME_DELAY = 3; // days;
```

In `CollateralBook.sol`, `CHANGE_COLLATERAL_DELAY` should be `2 days` instead of 200 seconds.

```solidity
    uint256 public constant CHANGE_COLLATERAL_DELAY = 200; //2 days
```

## Impact
Admin settings would be updated within a short period of delay so that users wouldn't react properly.

## Code Snippet
https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/isoUSDToken.sol#L10
https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/CollateralBook.sol#L23

## Tool used
Manual Review

## Recommendation
2 constants should be modified as mentioned above.

## Discussion

**kree-dotcom**

Sponsor confirmed, will fix.

**kree-dotcom**

Fixed https://github.com/kree-dotcom/isomorph/commit/4fc80e6178204691a365f656908c278d5faf4f88 , woops then forgot a semicolon, this was added here https://github.com/kree-dotcom/isomorph/commit/9bad2748dd3f3e7905dc8013383aef0cf98b1bea

isoToken was not altered in this commit but is correct. I made a copying error when setting up the Audit repo original

*[Content truncated...]*

---

### Example 4: [M-07] AaveYield: Misspelled external function name making functions fail

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: MEDIUM

**Details**:

_Submitted by 0xngndev_

#### Impact

In `AaveYield.sol` the functions:

*   `liquidityToken`
*   `_withdrawETH`
*   `_depositETH`

Make a conditional call to `IWETHGateway(wethGateway).getAWETHAddress()`

This function does not exist in the `wethGateway` contract, causing these function to fail with the error `"Fallback not allowed"`.

The function they should be calling is `getWethAddress()` without the "A".

Small yet dangerous typo.

##### Mitigation Steps

Simply modify:

`IWETHGateway(wethGateway).getAWETHAddress()`

to:

`IWETHGateway(wethGateway).getWETHAddress()`

In the functions mentioned above.

**[ritik99 (Sublime) confirmed](https://github.com/code-423n4/2021-12-sublime-findings/issues/42#issuecomment-1001348407):**
 > We were using an older version of the contracts that had [this definition](https://etherscan.io/address/dcd33426ba191383f1c9b431a342498fdac73488#code#F1#L158), will be updated accordingly

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

### Example 5: Typos in Interfaces

**Source**: Halborn
**Protocol**: Ecosystem - Merge Marketplace b14g
**Impact**: LOW

**Details**:

##### Description

Two typographical errors were found in the interfaces used by the project. While they may not be introduced by the team, they have been listed for the sake of completeness:

  

* In `IEarn.sol`:

```
// Amount of CORE the user recieves
...
// Amount of CORE the protocol recieves
```

`recieves` should be `recieves`.

  

* In `IBitcoinStake.sol`:

```
function accuredRewardPerBTCMap(address, uint256) external view returns (uint256);
```

`accuredRewardPerBTCMap()` should be `accruedRewardPerBTCMap()`.

##### BVSS

[AO:A/AC:L/AX:L/C:N/I:N/A:N/D:N/Y:N/R:N/S:U (0.0)](/bvss?q=AO:A/AC:L/AX:L/C:N/I:N/A:N/D:N/Y:N/R:N/S:U)

##### Recommendation

To maintain clarity and trustworthiness, it is essential to rectify any typographical errors present within the contracts. Correcting such errors minimizes the likelihood of confusion and reinforces confidence in the accuracy and integrity of the documentation.

##### Remediation

**SOLVED:** The **B14G team** fixed this finding in commit `3545f22` by correcting the typographical errors.

##### Remediation Hash

<https://github.com/b14glabs/contracts/commit/3545f2231423f454252911e7fac123a5c7fb4b46>

**Reference**: [View Original Finding](https://www.halborn.com/audits/coredao/ecosystem-Merge-Marketplace-b14g)

---

### Example 6: [M-01] Function `restructureCapTable()` in `Equity.sol` not functioning as expected

**Source**: Code4rena
**Protocol**: Frankencoin
**Impact**: MEDIUM

**Details**:

Incorrect typo in function `restructureCapTable()` leading to only burning tokens of first address of `addressToWipe` array argument.

### Proof of Concept

Here, in L313, addressToWipe\[0] only takes first address of the array. While ignoring the rest and also since first address's tokens are burned it will fail `addressesToWipe` array has more than one addresses.

        function restructureCapTable(address[] calldata helpers, address[] calldata addressesToWipe) public {
            require(zchf.equity() < MINIMUM_EQUITY);
            checkQualified(msg.sender, helpers);
            for (uint256 i = 0; i<addressesToWipe.length; i++){
                address current = addressesToWipe[0];
                _burn(current, balanceOf(current));
            }
        }


### Recommended Mitigation Steps

Change `address current = addressesToWipe[0];` ==> `  address current = addressesToWipe[i]; `

**[luziusmeisser (Frankencoin) confirmed](https://github.com/code-423n4/2023-04-frankencoin-findings/issues/941#issuecomment-1528893633)**

***

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-frankencoin)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## documentation-patterns.md
# Documentation Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 1 | 3 | 0 |

**Common Sources**: Cyfrin, Code4rena

---

## Detection Checklist

- [ ] Check for documentation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [QA-02] Interface Documentation References Wrong Token Standard

**Source**: Code4rena
**Protocol**: THORWallet
**Impact**: LOW

**Details**:

### Finding description and impact

The `IERC677Receiver` interface documentation incorrectly references `ERC1363` instead of `ERC677`. This mismatch between the interface name and its documentation could lead to integration issues and developer confusion.

The interface is named `IERC677Receiver` but its documentation comments reference `ERC1363`s `transferAndCall` functionality. While both standards have similar purposes, they have different implementations and requirements. This inconsistency could cause:

* Integration errors if developers implement the wrong standard based on the documentation
* Confusion during code review and maintenance
* Potential compatibility issues with other contracts expecting specific standard implementations
  The impact is low, as this is primarily a documentation issue and does not affect the actual functionality of the code.

### Proof of Concept

The interface in [IERC677Receiver.sol](https://github.com/code-423n4/2025-02-thorwallet/blob/98d7e936518ebd80e2029d782ffe763a3732a792/contracts/interfaces/IERC677Receiver.sol# L5-L6):
```

/**
 * @title IERC1363Receiver
 * @dev Interface for any contract that wants to support `transferAndCall` or `transferFromAndCall` from ERC-1363 token contracts.
 */
interface IERC677Receiver {
    function onTokenTransfer(address sender, uint value, bytes calldata data) external;
}
```

The interface is used in `MergeTgt.sol` for handling token transfers, but its implementing ERC677 functionality despite the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2025-02-thorwallet)

---

### Example 2: Use call instead of transfer

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** In both of the withdraw functions, `transfer()` is used for native ETH withdrawal.
The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

**Impact:** The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:
- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.

Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.

**Recommended Mitigation:** Use call() instead of transfer().

**Protocol:**
Agree, transfer was causing issues with smart contract wallets.

**Cyfrin:** Verified in commit [7726ae7](https://github.com/HyperGood/woosh-contracts/commit/7726ae72118cfdf91ceb9129e36662f69f4d42de).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 3: Exit fees implementation is inconsistent with documentation

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** Inline comments of `StakePet` contract indicate that exit fee is charged as % of the collateral.

```
The contract also has an early exit fee, which is a percentage of the collateral taken if a participant chooses to exit early.
```

However, implementation shows that exit fee is charged as a [percent of yield](https://github.com/Ranama/StakePet/blob/9ba301823b5062d657baa3462224da498dc4bb46/src/StakePet.sol#L559)

```
uint256 earlyExitFee = (uint256(yieldToWithdraw) * EARLY_EXIT_FEE) / BASIS_POINT
```

**Recommended Mitigation:** Consider correcting code documentation to reflect actual implementation

**Client:** Fixed in [54a4dcb](https://github.com/Ranama/StakePet/commit/54a4dcbb696da3138dc0fdd8e7032d664d32b7da)

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 4: Closedown condition is inconsistent with the stated documentation of majority agreement

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** [Documentation](https://hackmd.io/CPINxScvSE2vo-t8mwY_Og#Risks) states the following:

_"Closing the Contract: If the majority of the pets agree, they can vote to close the contract. Once closed, the remaining funds will be divided among the surviving pets. This is the most beneficial scenario for you, as youll earn the base rewards, early withdrawal rewards, and rewards from dead pets."_

Inline comments for the [`StakePet::closedown`](https://github.com/Ranama/StakePet/blob/9ba301823b5062d657baa3462224da498dc4bb46/src/StakePet.sol#L398C2-L398C2) function state the following"

```
    /// @notice Close down the contract if majority wants it, after closedown everyone can withdraw without getting a yield cut and no pet can die.
    function closedown(uint256[] memory _idsOfMajorityThatWantsClosedown) external {
...
}
```

In both cases, condition for closedown is for `majority of pets` to agree for a closedown. However, the check used for `closedown` is that the total collateral of pets wanting a closedown should be atleast 50% of the total collateral. This would mean that a single or few pet owners with large collateral deposits can trigger a closedown even if its not something that a majority of pet owners agree to.

Having 50% of value agreement and having majority agreement could be 2 different things.

**Impact:** The current model can be hijacked by whales who can trigger closedown of contract whenever they wish to. This could create 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## don-t-update-state-patterns.md
# Don't update state Security Patterns

## Overview

**Frequency**: 47 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 26 | 21 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for don't update state vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: OrderNFT theft due to controlling future and past tokens of same order index

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- `OrderBook.sol#L410`
- `OrderNFT.sol#L285`

## Description
The order queue is implemented as a ring buffer. To retrieve an order (`Orderbook.getOrder`), the index in the queue is computed as `orderIndex % _MAX_ORDER`. The owner of an `OrderNFT` also uses this function.

```solidity
function _getOrder(OrderKey calldata orderKey) internal view returns (Order storage) {
    return _getQueue(orderKey.isBid, orderKey.priceIndex).orders[orderKey.orderIndex & _MAX_ORDER_M];
}
```

`CloberOrderBook(market).getOrder(decodeId(tokenId)).owner`

As a result, the current owner of the NFT of `orderIndex` also owns all NFTs with `orderIndex + k * _MAX_ORDER`.

An attacker can set approvals of future token IDs to themselves. These approvals are not cleared on `OrderNFT.onMint`. When a victim mints this future token ID, the attacker can steal the NFT and cancel the NFT to claim their tokens.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../../../contracts/interfaces/CloberMarketSwapCallbackReceiver.sol";
import "../../../../contracts/mocks/MockQuoteToken.sol";
import "../../../../contracts/mocks/MockBaseToken.sol";
import "../../../../contracts/mocks/MockOrderBook.sol";
import "../../../../contracts/markets/VolatileMarket.sol";
import "../../../../contracts/OrderNFT.sol";
import "../utils/MockingFactoryTest.sol";
import "./Constants.sol";

contract ExploitsTest is Test, CloberMarketSw

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: makePayment doesn't properly update stack, so most payments don't pay off debt

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
LienToken.sol#615-635

## Description
As we loop through individual payments in `_makePayment`, each is called with:

```solidity
(newStack, spent) = _payment(
    s,
    stack,
    uint8(i),
    totalCapitalAvailable,
    address(msg.sender)
);
```

This call returns the updated stack as `newStack` but then uses the function argument `stack` again in the next iteration of the loop. The `newStack` value is unused until the final iterate, when it is passed along to `_updateCollateralStateHash()`. This means that the new state hash will be the original state with only the final loan repaid, even though all other loans have actually had payments made against them.

## Recommendation
```solidity
uint256 n = stack.length;
newStack = stack;
for (uint256 i; i < n; ) {
    (newStack, spent) = _payment(
        s,
        - stack,
        newStack,
        uint8(i),
        totalCapitalAvailable,
        address(msg.sender)
    );
```

This fixes the issue above, but the solution must also take into account the fix for the loop within `_payment` outlined here in Issue 134. If you follow the suggestion in that issue, then this function should return an extra value (`elementRemoved`) and use that to dictate whether the loop iterates forward, or remains at the same index for the next run.

The final result should look like:

```solidity
function _makePayment(
    LienStorage storage s,
    Stack[] calldata stack,
    uint256 totalCapitalAvailable
) inte

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 3: LienToken payee not reset on transfer

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity: High Risk

### Context
`LienToken.sol#L303-L313`

### Description
The `payee` and `ownerOf` functionalities are detached, meaning that owners may set a `payee`, and the owner may transfer the `LienToken` to a new owner without affecting the `payee`. The `payee` does not reset upon transfer.

### Exploit Scenario
- Owner of a `LienToken` sets themselves as `payee`.
- Owner of `LienToken` sells the lien to a new owner.
- New owner does not update `payee`.
- Payments go to the address set by the old owner.

### Recommendation
Reset `payee` on transfer.

```solidity
function transferFrom(
    address from,
    address to,
    uint256 id
) public override(ERC721, IERC721) {
    LienStorage storage s = _loadLienStorageSlot();
    if (s.lienMeta[id].atLiquidation) {
        revert InvalidState(InvalidStates.COLLATERAL_AUCTION);
    }
    + delete s.lienMeta[id].payee;
    + emit PayeeChanged(id, address(0));
    super.transferFrom(from, to, id);
}
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: stateHash isn't updated by buyoutLien function

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Issue Report

## Severity
**High Risk**

## Context
LienToken.sol#L102-187

## Description
We never update the collateral state hash anywhere in the `buyoutLien` function. As a result, once all checks are passed, payment will be transferred from the buyer to the seller, but the seller will retain ownership of the lien in the system's state.

## Recommendation
We should save the return value of the `_replaceStackAtPositionWithNewLien` function call and use it to call:
```solidity
s.collateralStateHash[collateralId] = keccak256(abi.encode(newUpdatedStack));
```

## Spearbit
Confirmed, the following commit fixes this issue.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: Anyone can take a valid commitment combined with a self-registered private vault to steal funds from any vault without owning any collateral

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- `VaultImplementation.sol#L279`
- `VaultImplementation.sol#L227`

## Description
The issue stems from the following check in `VaultImplementation._validateCommitment(params, receiver)`:

```solidity
if (
    msg.sender != holder &&
    receiver != holder &&
    receiver != operator &&
    !ROUTER().isValidVault(receiver) // <-- the problematic condition
) {
    ...
}
```

In this `if` block, if `receiver` is a valid vault, the body of the `if` is skipped. A valid vault is one that has been registered in `AstariaRouter` using `newVault` or `newPublicVault`. So for example, any supplied private vault as a receiver would be allowed here and the call to `_validateCommitment` will continue without reverting, at least in this `if` block.

If we backtrack function calls to `_validateCommitment`, we arrive at three exposed endpoints:
- `commitToLiens`
- `buyoutLien`
- `commitToLien`

A call to `commitToLiens` will end up having the receiver be the `AstariaRouter`. A call to `buyoutLien` will set the receiver as the `recipient()` for the vault, which is either the vault itself for public vaults or the owner for private vaults. So, we are only left with `commitToLien`, where the caller can set the value for the receiver directly.

A call to `commitToLien` will initiate a series of function calls, and so the `receiver` is only supplied to `_validateCommitment` to check whether it is allowed to be used, and finally when transferring (`safeTransfer`

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 6: Oracle.removeMember could, in the same epoch, allow members to vote multiple times and other members to not vote at all

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Oracle Vulnerability Report

**Severity:** High Risk  
**Context:** Oracle.1.sol#L213-L222  

## Description

The current implementation of `removeMember` is introducing an exploit that allows an oracle member to vote multiple times in the same epoch, while preventing another oracle that has never voted from casting a vote during the same epoch.

Due to the implementation of `OracleMembers.deleteItem`, the last item of the array is swapped with the item that is being deleted, and then the last element is popped.

### Example Scenario

1. At T0, add member `m0` to the list of members: `members[0] = m0`.
2. At T1, add member `m1` to the list of members: `members[1] = m1`.
3. At T3, `m0` calls `reportBeacon(...)`. This action triggers a call to `ReportsPositions.register(uint256(0));` which registers that the member at index 0 has voted.
4. At T4, the oracle admin calls `removeMember(m0)`. This operation swaps `m0`s address from the last position of the array with the position of the member being deleted. After this, it pops the last position of the array. The state changes from:
   - `members[0] = m0; members[1] = m1`
   - to `members[0] = m1;`.

At this point, the oracle member `m1` will not be able to vote during this epoch because when he/she calls `reportBeacon(...)`, the function will check:

```solidity
if (ReportsPositions.get(uint256(memberIndex))) {
    revert AlreadyReported(_epochId, msg.sender);
}
```

This is because `int256 memberIndex = OracleMembers.indexOf(

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 7: [H-04] Unstaking does not update the mapping sETHUserClaimForKnot

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L245


## Vulnerability details

## Impact

If a user stakes some sETH, and after some time decides to unstake some amount of sETH, later s/he will not be qualified or be less qualified to claim ETH on the remaining staked sETH.

## Proof of Concept

Suppose Alice stakes 5 sETH by calling `stake(...)`.
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L203
So, we will have:
 -  `sETHUserClaimForKnot[BLS][Alice] = (5 * 10^18 * accumulatedETHPerFreeFloatingShare) / PRECISION`
 - `sETHStakedBalanceForKnot[BLS][Alice] = 5 * 10^18`
 - `sETHTotalStakeForKnot[BLS] += 5 * 10^18`

Later, Alice decides to unstake 3 sETH by calling `unstake(...)`.
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L245

So, all ETH owed to Alice will be paid:
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L257

Then, we will have:
 -  `sETHUserClaimForKnot[BLS][Alice] = (5 * 10^18 * accumulatedETHPerFreeFloatingShare) / PRECISION`
 - `sETHStakedBalanceForKnot[BLS][Alice] = 2 * 10^18`
 - `sETHTotalStakeForKnot[BLS] -= 3 * 10^18`

It is clear that the mapping `sETHStakedBalanceForKnot` is decreased as expected, but the mapping

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 8: [H-19] withdrawETH() in GiantPoolBase dont call _distributeETHRewardsToUserForToken() or _onWithdraw() which would make users to lose their remaining rewards 

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L50-L64
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L180-L193


## Vulnerability details

## Impact
Function `_distributeETHRewardsToUserForToken()` is used to distribute remaining reward of user and it's called in `_onWithdraw()` of `GiantMevAndFeesPool`. but function `withdrawETH()` in `GiantPoolBase` don't call either of them and burn user giant LP token balance so if user withdraw his funds and has some remaining ETH rewards he would lose those rewards because his balance set to zero.

## Proof of Concept
This is `withdrawETH()` code in `GiantPoolBase`:
```
    /// @notice Allow a user to chose to burn their LP tokens for ETH only if the requested amount is idle and available from the contract
    /// @param _amount of LP tokens user is burning in exchange for same amount of ETH
    function withdrawETH(uint256 _amount) external nonReentrant {
        require(_amount >= MIN_STAKING_AMOUNT, "Invalid amount");
        require(lpTokenETH.balanceOf(msg.sender) >= _amount, "Invalid balance");
        require(idleETH >= _amount, "Come back later or withdraw less ETH");

        idleETH -= _amount;

        lpTokenETH.burn(msg.sender, _amount);
        (bool success,) = msg.sender.call{value: _amount}("");
        require(succe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 9: [H-15] User loses remaining rewards in GiantMevAndFeesPool when new deposits happen because _onDepositETH() set claimed[][] to max without transferring user remaining rewards

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L195-L204
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L33-L48


## Vulnerability details

## Impact
When `depositETH()` is called in giant pool it calls `_onDepositETH()` which calls `_setClaimedToMax()` to make sure new ETH stakers are not entitled to ETH earned by but this can cause users to lose their remaining rewards when they deposits. code should first transfer user remaining rewards when deposit happens.

## Proof of Concept
This is `depositETH()` code in `GiantPoolBase`:
```
    /// @notice Add ETH to the ETH LP pool at a rate of 1:1. LPs can always pull out at same rate.
    function depositETH(uint256 _amount) public payable {
        require(msg.value >= MIN_STAKING_AMOUNT, "Minimum not supplied");
        require(msg.value == _amount, "Value equal to amount");

        // The ETH capital has not yet been deployed to a liquid staking network
        idleETH += msg.value;

        // Mint giant LP at ratio of 1:1
        lpTokenETH.mint(msg.sender, msg.value);

        // If anything extra needs to be done
        _onDepositETH();

        emit ETHDeposited(msg.sender, msg.value);
    }
```
As you can see it increase user `lpTokenETH` balance and then calls `_onDepositETH()`. This is `_onDepositETH()` and `_setCla

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 10: [H-14] Fund lose in function bringUnusedETHBackIntoGiantPool() of GiantSavETHVaultPool ETH gets back to giant pool but the value of idleETH dont increase

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L133-L157
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L24-L25


## Vulnerability details

## Impact
Variable `idleETH` in giant pools is storing total amount of ETH sat idle ready for either withdrawal or depositing into a liquid staking network and whenever a deposit or withdraw happens contract adjust the value of `idleETH` of contract, but in function `bringUnusedETHBackIntoGiantPool()` which brings unused ETH from savETH vault to giant pool the value of `idleETH` don't get increased which would cause those ETH balance to not be accessible for future staking or withdrawing.

## Proof of Concept
This is `bringUnusedETHBackIntoGiantPool()` code in `GiantSavETHVaultPool()`:
```
    /// @notice Any ETH that has not been utilized by a savETH vault can be brought back into the giant pool
    /// @param _savETHVaults List of savETH vaults where ETH is staked
    /// @param _lpTokens List of LP tokens that the giant pool holds which represents ETH in a savETH vault
    /// @param _amounts Amounts of LP within the giant pool being burnt
    function bringUnusedETHBackIntoGiantPool(
        address[] calldata _savETHVaults,
        LPToken[][] calldata _lpTokens,
        uint256[][] calldata _amounts
    ) external {
        uint2

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 11: [H-12] Sender transferring GiantMevAndFeesPool tokens can afterward experience pool DOS and orphaning of future rewards

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L170-L173


## Vulnerability details

## Impact
When a user transfers away GiantMevAndFeesPool tokens, the pool's claimed[] computed is left unchanged and still corresponds to what they had claimed with their old (higher) number of tokens. (See GiantMevAndFeesPool afterTokenTransfer() - no adjustment is made to claimed[] on the from side.) As a result, their claimed[] may be higher than the max amount they could possibly have claimed for their new (smaller) number of tokens. The erroneous claimed value can cause an integer overflow when the claimed[] value is subtracted, leading to inability for this user to access some functions of the GiantMevAndFeesPool - including such things as being able to transfer their tokens (overflow is triggered in a callback attempting to pay out their rewards). These overflows will occur in SyndicateRewardsProcessor's _previewAccumulatedETH() and _distributeETHRewardsToUserForToken(), the latter of which is called in a number of places. When rewards are later accumulated in the pool, the user will not be able to claim certain rewards owed to them because of the incorrect (high) claimed[] value. The excess rewards will be orphaned in the pool.

## Proof of Concept
This patch demonstrates both DOS and orphaned rewards due to the claimed[] error described above. Note that the patch include

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 12: [H-10] GiantMevAndFeesPool.bringUnusedETHBackIntoGiantPool function loses the addition of the idleETH which allows attackers to steal most of eth from the Giant Pool

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126-L138
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L176-L178


## Vulnerability details

## Impact
The contract GiantMevAndFeesPool override the function totalRewardsReceived:
```
return address(this).balance + totalClaimed - idleETH;
```
The function totalRewardsReceived is used as the current rewards balance to caculate the unprocessed rewards in the function `SyndicateRewardsProcessor._updateAccumulatedETHPerLP`
```
uint256 received = totalRewardsReceived();
uint256 unprocessed = received - totalETHSeen;
```

The idleETH will be decreased in the function `batchDepositETHForStaking` for sending eth to the staking pool. But the idleETH wont be increased in the function `bringUnusedETHBackIntoGiantPool` which is used to burn lp tokens in the staking pool, and the staking pool will send the eth back to the giant pool. And then because of the diminution of the idleETH, the `accumulatedETHPerLPShare` is added out of thin air. So the attacker can steal more eth from the GiantMevAndFeesPool.

## Proof of Concept
test:
test/foundry/TakeFromGiantPools.t.sol
```
pragma solidity ^0.8.13;

// SPDX-License-Identifier: MIT

import "forge-std/console.sol";
import {GiantPoolTests} from "./GiantPools.t.sol";
import { LPToken } from "../../contracts/liquid-staking/LPToken.sol";

contract TakeFromGiantP

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 13: [H-09] Incorrect accounting in SyndicateRewardsProcessor results in any LP token holder being able to steal other LP tokens holders ETH from the fees and MEV vault

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L63
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/StakingFundsVault.sol#L88


## Vulnerability details

## Impact
The SyndicateRewardsProcessor's internal `_distributeETHRewardsToUserForToken()` function is called from external `claimRewards()` function in the `StakingFundsVault` contract. This function is called by LP Token holders to claim their accumulated rewards based on their LP Token holdings and already claimed rewards.
The accumulated rewards `due` are calculated as `((accumulatedETHPerLPShare * balance) / PRECISION)` reduced by the previous claimed amount stored in `claimed[_user][_token]`. When the ETH is sent to the `_user` the stored value should be increased by the `due` amount. However in the current code base the `claimed[_user][_token]` is set equal to the calculated `due`.

```solidity
function _distributeETHRewardsToUserForToken(
        address _user,
        address _token,
        uint256 _balance,
        address _recipient
    ) internal {
        require(_recipient != address(0), "Zero address");
        uint256 balance = _balance;
        if (balance > 0) {
            // Calculate how much ETH rewards the address is owed / due 
            uint256 due = ((accumulatedETHPerLPShare * balance) / PRECISION) - claime

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 14: [H-06] BringUnusedETHBackIntoGiantPool can cause stuck ether funds in Giant Pool

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126-L138
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantSavETHVaultPool.sol#L137-L158


## Vulnerability details

## Impact
withdrawUnusedETHToGiantPool will withdraw any eth from the vault if staking has not commenced(knot status is INITIALS_REGISTERED), the eth will be drawn successful to the giant pool. However, idleETH variable is not updated. idleETH  is the available ETH for withdrawing and depositing eth for staking. Since there is no other places that updates idleETH other than depositing eth for staking and withdrawing eth, the eth withdrawn from the vault will be stuck forever. 

## Proof of Concept
place poc in GiantPools.t.sol with `import { MockStakingFundsVault } from "../../contracts/testing/liquid-staking/MockStakingFundsVault.sol";`


```solidity
    function testStuckFundsInGiantMEV() public {

        stakingFundsVault = MockStakingFundsVault(payable(manager.stakingFundsVault()));
        address nodeRunner = accountOne; vm.deal(nodeRunner, 4 ether);
        //address feesAndMevUser = accountTwo; vm.deal(feesAndMevUser, 4 ether);
        //address savETHUser = accountThree; vm.deal(savETHUser, 24 ether);
        address victim = accountFour; vm.deal(victim, 1 ether);


        registerSingleBLSPubKey(nodeRunner, blsPubKeyOne, accountFour);

        emit log_address(address(giantFeesAndMevPoo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 15: [H-01] Making a payment to the protocol with `_dontMint` parameter will result in lost fund for user.

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

User will have their funds lost if they tries to pay the protocol with `_dontMint = False`. A payment made with this parameter set should increase the `creditsOf[]` balance of user.

In `_processPayment()`, `creditsOf[_data.beneficiary]` is updated at the end if there are leftover funds. However, If `metadata` is provided and `_dontMint == true`, it immediately returns.
[JBTiered721Delegate.sol#L524-L590](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721Delegate.sol#L524-L590)

```solidity
  function _processPayment(JBDidPayData calldata _data) internal override {
    // Keep a reference to the amount of credits the beneficiary already has.
    uint256 _credits = creditsOf[_data.beneficiary];
    ...
    if (
      _data.metadata.length > 36 &&
      bytes4(_data.metadata[32:36]) == type(IJB721Delegate).interfaceId
    ) {
      ...
      // Don't mint if not desired.
      if (_dontMint) return;
      ...
    }
    ...
    // If there are funds leftover, mint the best available with it.
    if (_leftoverAmount != 0) {
      _leftoverAmount = _mintBestAvailableTier(
        _leftoverAmount,
        _data.beneficiary,
        _expectMintFromExtraFunds
      );

      if (_leftoverAmount != 0) {
        // Make sure there are no leftover funds after minting if not expected.
        if (_dontOverspend) revert OVERSPENDING();

        // Increment the leftover amount.
        creditsOf[_data.beneficiary] = _lefto

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 16: [H-02] unstake should update exchange rates first

**Source**: Code4rena
**Protocol**: Covalent
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `unstake` function does not immediately update the exchange rates. It first computes the `validatorSharesRemove = tokensToShares(amount, v.exchangeRate)` **with the old exchange rate**.

Only afterwards, it updates the exchange rates (if the validator is not disabled):

```solidity
// @audit shares are computed here with old rate
uint128 validatorSharesRemove = tokensToShares(amount, v.exchangeRate);
require(validatorSharesRemove > 0, "Unstake amount is too small");

if (v.disabledEpoch == 0) {
    // @audit rates are updated here
    updateGlobalExchangeRate();
    updateValidator(v);
    // ...
}
```

## Impact
More shares for the amount are burned than required and users will lose rewards in the end.

## POC
Demonstrating that users will lose rewards:

1. Assume someone staked `1000 amount` and received `1000 shares`, and `v.exchangeRate = 1.0`. (This user is the single staker)
2. Several epochs pass, interest accrues, and `1000 tokens` accrue for the validator, `tokensGivenToValidator = 1000`. User should be entitled to 1000 in principal + 1000 in rewards = 2000 tokens.
3. But user calls `unstake(1000)`, which sets `validatorSharesRemove = tokensToShares(amount, v.exchangeRate) = 1000 / 1.0 = 1000`. **Afterwards**, the exchange rate is updated: `v.exchangeRate += tokensGivenToValidator / totalShares = 1.0 + 1.0 = 2.0`. The staker is updated with `s.shares -= validatorSharesRemove = 0` and `s.staked -= amount = 0`. And the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-covalent)

---

### Example 17: H-9: `moveQuoteToken()` can cause bucket to go bankrupt but it is not reflected in the accounting

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/83 

## Found by 
yixxas

## Summary
Both `removeQuoteToken()` and `moveQuoteToken()` can be used to completely remove all quote tokens from a bucket. When this happens, if at the same time `bucketCollateral == 0 && lpsRemaining != 0`, then the bucket should be declared bankrupt. This update is done in `removeQuoteToken()` but not in `moveQuoteToken()`.

## Vulnerability Detail
`removeQuoteToken()` has the following check to update bankruptcy time when collateral and quote token remaining is 0, but lps is more than 0. `moveQuoteToken()` is however missing this check. Both this functions has the same effects on the `fromBucket` and the only difference is that `removeQuoteToken()` returns the token to `msg.sender` but `moveQuoteToken()` moves the token to another bucket.

```solidity
if (removeParams.bucketCollateral == 0 && unscaledRemaining == 0 && lpsRemaining != 0) {
	emit BucketBankruptcy(params_.index, lpsRemaining);
	bucket.lps            = 0;
	bucket.bankruptcyTime = block.timestamp;
} else {
	bucket.lps = lpsRemaining;
}
```

## Impact
A future depositor to the bucket will get less lps than expected due to depositing in a bucket that is supposedly bankrupt, hence the lps they get will be diluted with the existing ones in the bucket.

## Code Snippet
https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/libraries/external/LenderActions.sol#L359-L365

## Tool used

Manual Review

## Re

*[Content truncated...]*

---

### Example 18: H-1: RewardsManager doesn't delete old bucket snapshot info on unstaking

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/183 

## Found by 
hyh

## Summary

RewardsManager's unstake() use `delete stakes[tokenId_]` to clear old stake state, but `snapshot` is the nested mapping in the `StakeInfo` structure and will not be reset this way as delete operation do not traverse through nested mappings as it lacks key set information.

## Vulnerability Detail

`stakes[tokenId_]` gets written on staking and `mapping(uint256 => BucketState) snapshot` is written for the *current* list of buckets. This means if this list persists and there were no bucket changes it's ok as new values will be overwritten on next stake.

But, if Bob the staker has changed his composition of buckets and his second stake takes place over another set, possibly intersecting with the first one, old part will persist. If then Bob's `positionIndexes = positionManager.getPositionIndexes(tokenId_)` changed after the second stake, say as a result of PositionManager's moveLiquidity(), and indices from the first set were added there, their snapshot values from the first stake will be reused.

## Impact

If Bob knows this it will be straightforward for him to exploit the mechanics, obtaining extra rewards (interest earned will be counted from the first stake time for old positions) at the expense of other stakers.

## Code Snippet

RewardsManager's unstake() deletes `stakes[tokenId_]`:

https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/RewardsManage

*[Content truncated...]*

---

### Example 19: H-5: removeCollateral miss bankrupcy logic and can make future LPs sharing losses with the current ones

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/133 

## Found by 
hyh, Jeiwan, yixxas

## Summary

LenderActions' removeCollateral() do not checks for bucket solvency after it has removed a collateral from there. This can lead to losses for future depositors of the bucket.

## Vulnerability Detail

Bankrupcy check logic now exist in all asset removing functions. That prevent a situation when a bucket defaults, but next LP deposit makes in solvent again and next LP shared losses with the old ones this way without having such intent.

For example, mergeOrRemoveCollateral() calls _removeMaxCollateral() that do check affected bucket for bankrupcy. removeCollateral() do not check for that despite insolvency situation for a bucket can occur after collateral was removed.

## Impact

When bucket defaults, but no bankrupcy is checked and no such flag is set, the next LP depositors have to bail out previous, i.e. have to share their losses.

That's a loss for next LPs by unconditional transfer from them to the previous ones.

As removeCollateral() is a part of base functionality that to be used frequently and bucket defaults can routinely happen, so there is no low probability prerequisites, and given the loss for future bucket depositors, setting the severity to be high.

## Code Snippet

There is no bucket bankrupcy logic in removeCollateral(), i.e. when there is no quote tokens in the bucket, `lpAmount_ < bucketLPs`, but `bucketCollateral <= collateralAmount_`

*[Content truncated...]*

---

### Example 20: TransitionLoanManager.add does not account for accrued interest since last call

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`pool-v2::TransitionLoanManager.sol#L74`

## Description
The `TransitionLoanManager.add` advances the domain start but the accrued interest since the last domain start is not accounted for. It therefore wrongly tracks the `_accountedInterest` variable. If `add` is called several times, the accounting will be wrong.

## Recommendation
Consider tracking the accrued interest or ensure that the `MigrationHelper.addLoansToLM` is called only once in the final migration script, adding all loans at the same time.

```solidity
function add(address loan_) external override nonReentrant {
    ...
    uint256 domainStart_ = domainStart;
    + uint256 accruedInterest;
    if (domainStart_ == 0 || domainStart_ != block.timestamp) {
        + accruedInterest = getAccruedInterest();
        domainStart = _uint48(block.timestamp);
    }
    ...
    + _updateIssuanceParams(issuanceRate += newRate_, accountedInterest + accruedInterest);
}
```

This mimics `LoanManager._advanceGlobal` as long as there are no late payments, but that's also the case for `TransitionLoanManager` as one of the preconditions for the migration is that loans have at least 5 days for any payment to be due.

## Discussion
**Maple:** In theory yes, but realistically we'll add all loans atomically. Even in the largest pool, we have around 30 active loans, which is feasible to do in one transaction. This is not an issue since all loans are added atomically, but we can add this functionali

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 21: Order owner isn't zeroed after burning

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `OrderBook.sol#L821-L823`
- `OrderNFT.sol#L78-L82`
- `OrderNFT.sol#L189`

## Description
The order's owner is not zeroed out when the NFT is burnt. As a result, while the `onBurn()` method records the NFT to have been transferred to the zero address, `ownerOf()` still returns the current order's owner. This allows for unexpected behaviour, like being able to call `approve()` and `safeTransferFrom()` functions on non-existent tokens.

A malicious actor could sell such resurrected NFTs on secondary exchanges for profit even though they have no monetary value. Such NFTs will revert on cancellation or claim attempts since `openOrderAmount` is zero.

### Code Example
```solidity
function testNFTMovementAfterBurn() public {
    _createOrderBook(0, 0);
    address attacker2 = address(0x1337);
    // Step 1: make 2 orders to avoid bal sub overflow when moving burnt NFT in step 3
    uint256 orderIndex1 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    CloberOrderBook.OrderKey memory orderKey = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Constants.PRICE_INDEX,
        orderIndex: orderIndex1
    });
    uint256 tokenId = orderToken.encodeId(orderKey);
    // Step 2: burn 1 NFT by cancelling one of the orders
    vm.startPrank(Constants.MAKER);
    orderBook.cancel(Constants.MAKER, _toArray(orderKey));
    // verify ownership is still mak

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 22: diamondCut() allows re-execution of old updates

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
**File:** LibDiamond.sol  
**Lines:** 112-115

## Description
When `diamondCut()` is executed, `ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))]` is not reset to zero. This means the contract owner can rerun the old updates again without any delay by executing the `diamondCut()` function.

Assume the following:
- `diamondCut()` function is executed to update the facet selector with version_2.
- A bug is found in version_2 and it is rolled back.
- The Owner can still execute the `diamondCut()` function, which will again update the facet selector to version 2 since `ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))]` is still valid.

## Recommendation
Reset `ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))]` to zero as shown below:

```solidity
function diamondCut(
    IDiamondCut.FacetCut[] memory _diamondCut,
    address _init,
    bytes memory _calldata
) internal {
    ...
    if (ds.facetAddresses.length != 0) {
        uint256 time = ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))];
        require(time != 0 && time <= block.timestamp, "LibDiamond: delay not elapsed");
    }
    ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))] = 0;
    ...
}
```

## Context
**Fix in PR:** 2222.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 23: _domainSeparatorV4() not updated after name /symbol change

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `BridgeToken.sol#L58-L63`
- `OZERC20.sol#L382-L388`
- `OZERC20.sol#L348-L369`
- `draft-EIP712.sol`
- `EIP712.sol#L69-L75`
- `EIP712.sol#L100-L102`

## Description
The `BridgeToken` allows updating the name and symbol of a token. However, the `_CACHED_DOMAIN_SEPARATOR` (of EIP712) isn't updated. This means that `permit()`, which uses `_hashTypedDataV4()` and `_CACHED_DOMAIN_SEPARATOR`, still uses the old value. On the other hand, `DOMAIN_SEPARATOR()` is updated. Both, and especially their combination, can give unexpected results.

### BridgeToken.sol
```solidity
function setDetails(string calldata _newName, string calldata _newSymbol) external override onlyOwner {
    // careful with naming convention change here
    token.name = _newName;
    token.symbol = _newSymbol;
    emit UpdateDetails(_newName, _newSymbol);
}
```

### OZERC20.sol
```solidity
function DOMAIN_SEPARATOR() external view override returns (bytes32) {
    // See {EIP712._buildDomainSeparator}
    return keccak256(
        abi.encode(_TYPE_HASH, keccak256(abi.encode(token.name)), _HASHED_VERSION, block.chainid, address(this))
    );
}

function permit(...) ... {
    ...
    bytes32 _hash = _hashTypedDataV4(_structHash);
    ...
}
```

### draft-EIP712.sol
```solidity
import "./EIP712.sol";
```

### EIP712.sol
```solidity
function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
    return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 24: [M-21] EIP1559 rewards received by syndicate during the period when it has no registered knots can be lost

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L218-L220><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L154-L157><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L597-L607><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L610-L627><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L174-L197>

When the `deRegisterKnotFromSyndicate` function is called by the DAO, the `_deRegisterKnot` function is eventually called to execute `numberOfRegisteredKnots -= 1`. It is possible that `numberOfRegisteredKnots` is reduced to 0. During the period when the syndicate has no registered knots, the EIP1559 rewards that are received by the syndicate remain in the syndicate since functions like `updateAccruedETHPerShares` do not include any logics for handling such rewards received by the syndicate. Later, when a new knot is registered and mints the derivatives, the node runner can call the `claimRewardsAsNodeRunner` function to receive half ot these rewards received by the syndicate during the period when it has no registered knots. Yet, because such rewards are received by the syndicate before the new knot mints the derivatives, the node runner should not be entitled to these rewards. Moreover, due to the issue mentioned in my other f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 25: [M-15] GiantMevAndFeesPool.previewAccumulatedETH function: accumulated variable is not updated correctly in for loop leading to result that is too low

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L82
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L91


## Vulnerability details

## Impact
The `GiantMevAndFeesPool.previewAccumulatedETH` function ([https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L82](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L82)) allows to view the ETH that is accumulated by an address.  

However the formula is not correct.  

In each iteration of the foor loop, `accumulated` is assigned a new value ([https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L91](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L91)) when actually the value should be updated like this:  
```solidity
accumulated += StakingFundsVault(payable(_stakingFundsVaults[i])).batchPreviewAccumulatedETH(
        address(this),
        _lpTokens[i]
    );
```

Obviously the `accumulated` value must be calculated for all stakingFundVaults not only for one st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 47
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## mapping-patterns.md
# Mapping Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for mapping vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-22: Memorializing an NFT position on the same bucket of a previously memorialized NFT locks redemption

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/13 

## Found by 
MalfurionWhitehat

## Summary

Memorializing a position as an NFT on the same bucket of an existing memorialized position will not allow any of the owners to directly redeem it back later.

## Vulnerability Detail

This issue happens because, after a position is memorialized on the `PositionManager`, this contract will centralize LP positions from different users, but these will be mapped to the same address from the point of view of Ajna pools (different users will be mapped as the same `lender` from the point of view of a `Pool`). 

If more than one user has memorialized a position to the same bucket index, when attempting to `PositionManager.redeemPositions`, the call to [`pool.transferLPs`](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/PositionManager.sol#L311) will revert with [`NoAllowance`](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/libraries/external/LenderActions.sol#L538), as `LenderActions` does not allow a transfer with value lower than the total `lenderLpBalance`.

Because of that, any of the users' that share a bucket `redeemPositions` calls will fail.

## Impact

Although users that share a bucket with memorialized positions are not able to direct redeem their positions, they can eventually get their LPs back with a specific set of actions.

By first calling `PositionManager.moveLiquidity` to a bucket _without any other LP

*[Content truncated...]*

---

### Example 2: H-7: WAuraPools will irreversibly break if reward tokens are added to pool after deposit

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/127 

## Found by 
0x52, Ch\_301
## Summary

WAuraPools will irreversibly break if reward tokens are added to pool after deposit due to an OOB error on accExtPerShare.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength(); <- @audit-issue rewardTokenCount pulled fresh
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);

            @audit-issue attempts to pull from array which will be too small if tokens are added
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

accExtPerShare stores the current rewardPerToken when the position is fir

*[Content truncated...]*

---

### Example 3: [M-02] The stake fees are not tracked on chain

**Source**: Pashov Audit Group
**Protocol**: Smoothly
**Impact**: MEDIUM

**Details**:

**Severity**

**Impact:**
High, as it can result in wrong accounting of ETH held by `SmoothlyPool`

**Likelihood:**
Low, as it requires off-chain code to be wrong

**Description**

Every validator who joins the `SmoothlyPool` should register by paying a `STAKE_FEE` (with the size of 0.065 ETH) to the contract. The pool does not track how much of a stake fee balance a validator has, which is problematic for the following reasons:

1. The pool has no guarantee that it holds at least `numValidators * STAKE_FEE` ETH in its balance - the ETH might have been mistakenly distributed as rewards or claimed as fees from operators
2. It is possible for a validator to deposit more than `STAKE_FEE` if he calls `SmoothlyPool::addStake` multiple times
3. The slashing/punishment mechanism can't be enforced on chain

**Recommendations**

Add a mapping to track validators' stake fee balances in `SmoothlyPool`.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-08-01-Smoothly.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## payable-patterns.md
# Payable Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 4 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for payable vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Cross-chain messaging via Multichain protocol will fail

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Assessment

## Severity: 
**High Risk**

## Context: 
`BaseMultichain.sol#L39-L47`

## Description: 
Multichain v6 is supported by Connext for cross-chain messaging. The `_sendMessage` function of `BaseMultichain.sol` relies on Multichain's anyCall for cross-chain messaging.

Per the Anycall V6 documentation, a gas fee for transaction execution needs to be paid either on the source or destination chain when an anyCall is called. However, the anyCall is called without consideration of the gas fee within the connectors, and thus the anyCall will always fail. Since Multichain's hub and spoke connectors are unable to send messages, cross-chain messaging using Multichain within Connext will not work.

```solidity
function _sendMessage(address _amb, bytes memory _data) internal {
    Multichain(_amb).anyCall(
        _amb, // Same address on every chain, using AMB as it is immutable
        _data,
        address(0), // fallback address on origin chain
        MIRROR_CHAIN_ID,
        0; // fee paid on origin chain
    );
}
```

Additionally, for the payment of the execution gas fee, a project can choose to implement either of the following methods:
- Pay on the source chain by depositing the gas fee to the caller contracts.
- Pay on the destination chain by depositing the gas fee to Multichain's anyCall contract at the destination chain.

If Connext decides to pay the gas fee on the source chain, they would need to deposit some ETH to the connector contracts. However, 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 2: Messages destined for ZkSync cannot be processed

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
ZkSyncHubConnector.sol#L49-L72

## Description
For ZkSync chain, L2 to L1 communication is free, but L1 to L2 communication requires a certain amount of ETH to be supplied to cover the base cost of the transaction (including the `_l2Value`) + layer 2 operator tip.

The `sendMessage` function of `ZkSyncHubConnector.sol` relies on the `IZkSync(AMB).requestL2Transaction` function to send messages from L1 to L2. However, the `requestL2Transaction` call will always fail because no ETH is supplied to the transaction (`msg.value` is zero).

As a result, ZkSync's hub connector on Ethereum cannot forward the latest aggregated Merkle root to ZkSync's spoke connector on the ZkSync chain. Thus, any message destined for the ZkSync chain cannot be processed since incoming messages cannot be proven without the latest aggregated Merkle root.

```solidity
function _sendMessage(bytes memory _data) internal override {
    // Should always be dispatching the aggregate root
    require(_data.length == 32, "!length");
    
    // Get the calldata
    bytes memory _calldata = abi.encodeWithSelector(Connector.processMessage.selector, _data);
    
    // Dispatch message
    // [v2-docs.zksync.io/dev/developer-guides/Bridging/l1-l2.html#structure](https://v2-docs.zksync.io/dev/developer-guides/Bridging/l1-l2.html#structure)
    // calling L2 smart contract from L1 Example contract
    // note: msg.value must be passed in and can be retrieved from the AMB view functi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 3: Executor reverts on receiving native tokens from BridgeFacet

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- **File:** Executor.sol 
- **Line:** BridgeFacet.sol#L696, AssetLogic.sol#L127-L151

## Description
When doing an external call in `execute()`, the `BridgeFacet` provides liquidity into the `Executor` contract before calling `Executor.execute`. The `BridgeFacet` transfers a native token when an `address(wrapper)` is provided. However, the `Executor` does not have a fallback or receive function. Hence, the transaction will revert when the `BridgeFacet` tries to send the native token to the `Executor` contract.

```solidity
function _handleExecuteTransaction(
    ...
    AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
    (bool success, bytes memory returnData) = s.executor.execute(...);
    ...
}
```

```solidity
function transferAssetFromContract(...) {
    ...
    if (_assetId == address(s.wrapper)) {
        // If dealing with wrapped assets, make sure they are properly unwrapped
        // before sending from contract
        s.wrapper.withdraw(_amount);
        Address.sendValue(payable(_to), _amount);
    } else {
        ...
    }
}
```

## Recommendation
It is recommended to add a receive function in the `Executor` contract:

```solidity
receive() payable external {
    require(msg.sender == connext);
}
```

Alternatively, unwrap the native asset and send it along with the call to the executor.

- **Connext:** Ether sent along with the call. Solved in PR 1532.
- **Spearbit:** Verified.
- **Connext:** Alter

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: _handleExecuteTransaction() doesnt handle native assets correctly

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

**Severity:** High Risk  
**Context:** BridgeFacet.sol#L644-L718, Executor.sol#L142-L243  

**Description:**  
The function `_handleExecuteTransaction()` sends any native tokens to the executor contract first, and then calls `s.executor.execute()`. This means that within that function, `msg.value` will always be 0. As a result, the associated logic that uses `msg.value` doesnt work as expected, leading to incorrect handling of native assets.

**Note:**  
Also see issue "Executor reverts on receiving native tokens from BridgeFacet".

```solidity
contract BridgeFacet is BaseConnextFacet {
    function _handleExecuteTransaction(...) {
        ...
        AssetLogic.transferAssetFromContract(_asset, address(s.executor), _amount);
        (bool success, bytes memory returnData) = s.executor.execute(...); // no native tokens sent
    }
}
```

```solidity
contract Executor is IExecutor {
    function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
        ...
        if (isNative && msg.value != _args.amount) { // msg.value is always 0
            ...
        }
    }
}
```

**Recommendation:**  
Change the code of `execute()` to handle previously sent native assets. Alternatively, send the native assets along with the call to `execute()`.

**Connext:** Solved in PR 1532.  
**Spearbit:** Verified.  
**Connext:** Alternate approach: removed native asset handling. Implemented in PR 31.  
**Spearbit:** Verified

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 5: WormholeFacet doesnt send native token

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`WormholeFacet.sol#L36-L103`

## Description
The functions of `WormholeFacet` allow sending the native token; however, they dont actually send it across the bridge, causing the native token to stay stuck in the LiFi Diamond and get lost for the sender.

```solidity
contract WormholeFacet is ILiFi, ReentrancyGuard, Swapper {
    function startBridgeTokensViaWormhole(... ) ... payable ... { // is payable
        LibAsset.depositAsset(_wormholeData.token, _wormholeData.amount); // allows native token
        _startBridge(_wormholeData);
        ...
    }

    function _startBridge(WormholeData memory _wormholeData) private {
        ...
        LibAsset.maxApproveERC20(...); // geared towards ERC20, also works when `msg.value `is set
        IWormholeRouter(_wormholeData.wormholeRouter).transferTokens(...); // no { value : .... }
    }
}
```

## Recommendation
Remove the `payable` keyword and/or check `msg.value == 0`. Alternatively, support sending the native token. This can be done via `wrapAndTransferETH()` of the wormhole bridge.

**Note:** also see issue "Consider using wrapped native token"

## LiFi
Fixed with PR #76.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 6: [H-01] SpeedBumpPriceGate: Excess ether did not return to the user

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: HIGH

**Details**:

_Submitted by cccz, also found by 0x52, 0xYamiDancho, csanuragjain, GimelSec, gzeon, hickuphh3, horsefacts, hyh, IllIllI, kenzo, leastwood, PPrieditis, reassor, unforgiven, WatchPug, and danb_

The `passThruGate` function of the `SpeedBumpPriceGate` contract is used to charge NFT purchase fees.
Since the price of NFT will change due to the previous purchase, users are likely to send more ether than the actual purchase price in order to ensure that they can purchase NFT. However, the passThruGate function did not return the excess ether, which would cause asset loss to the user.
Consider the following scenario:

1.  An NFT is sold for 0.15 eth
2.  User A believes that the value of the NFT is acceptable within 0.3 eth, considering that someone may buy the NFT before him, so user A transfers 0.3 eth to buy the NFT
3.  When user A's transaction is executed, the price of the NFT is 0.15 eth, but since the contract does not return excess eth, user A actually spends 0.3 eth.

### Proof of Concept

<https://github.com/code-423n4/2022-05-factorydao/blob/e22a562c01c533b8765229387894cc0cb9bed116/contracts/SpeedBumpPriceGate.sol#L65-L82>


### Recommended Mitigation Steps

    -   function passThruGate(uint index, address) override external payable {
    +  function passThruGate(uint index, address payer) override external payable {
            uint price = getCost(index);
            require(msg.value >= price, 'Please send more ETH');

            // bump up the price
            Gate 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 7: M-5: The ````Stream```` contract is designed to receive ETH but not implement function for withdrawal

**Source**: Sherlock
**Protocol**: NounsDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-nounsdao-judging/issues/47 

## Found by 
KingNFT, rvierdiiev

## Summary
The ````Stream```` contract instances can receive ETH but can not withdraw, ETH occasionally sent by users will be stuck in those contracts.

## Vulnerability Detail
Shown as the test case, it can receive ETH normally.
```solidity
contract StreamReceiveETHTest is StreamTest {
    function setUp() public override {
        super.setUp();
    }

    function test_receiveETH() public {
        s = Stream(
            factory.createStream(
                payer, recipient, STREAM_AMOUNT, address(token), startTime, stopTime
            )
        );

        vm.deal(payer, 10 ether);
        vm.prank(payer);
        (bool success, ) = address(s).call{value: 1 ether}("");
        assertEq(success, true);
        assertEq(address(s).balance, 1 ether);
    }
}
```

Result
```solidity
Running 1 test for test/Stream.t.sol:StreamReceiveETHTest
[PASS] test_receiveETH() (gas: 167691)
Test result: ok. 1 passed; 0 failed; finished in 1.25ms
```

## Impact
See Summary

## Code Snippet
https://github.com/Vectorized/solady/blob/db4857b4a1e17ad035668b588b41a1c90139b99d/src/utils/LibClone.sol#L193-L204

## Tool used

Manual Review

## Recommendation
Add a ````rescueETH()```` function which is similar with the existing ````rescueERC20()````

## Discussion

**eladmallel**

Fix PR: https://github.com/nounsDAO/streamer/pull/10

---

### Example 8: [M-01] It is not possible to execute actions that require ETH (or other protocol token)

**Source**: Code4rena
**Protocol**: Llama
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-llama/blob/main/src/LlamaCore.sol#L334> <br><https://github.com/code-423n4/2023-06-llama/blob/main/src/LlamaExecutor.sol#L29>

Actions can have value attached to them. That means when action is being executed, a certain amount of ETH (or other protocol token) need to be sent by the caller with the contract call. This is why `LlamaCore.executeAction` is payable.

```solidity
  function executeAction(ActionInfo calldata actionInfo) external payable {
```

However, when LlamaCore executes the action it doesn't pass value to the downstream call to LlamaExecutor

```solidity
    // Execute action.
    (bool success, bytes memory result) =
      executor.execute(actionInfo.target, actionInfo.value, action.isScript, actionInfo.data);
```

LlamaExecutor's `execute` is not payable even though it does try to pass value to the downstream call

```solidity
  function execute(address target, uint256 value, bool isScript, bytes calldata data)
    external
    returns (bool success, bytes memory result)
  {
    if (msg.sender != LLAMA_CORE) revert OnlyLlamaCore();
    (success, result) = isScript ? target.delegatecall(data) : target.call{value: value}(data);
  }
```

This will of course revert because LlamaExecutor is not expected to have any ETH balance.

### Proof of Concept

To reproduce the issue based on the existing tests we can do the following changes:

```diff
diff --git a/test/LlamaCore.t.sol b/test/LlamaCore.t.sol
index 8135c93..6964846 1006

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-llama)

---

### Example 9: M-1: Buypunk function of Cryptopunks in ERC721Pool is used incorrectly

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/163 

## Found by 
Chinmay

## Summary

The buyPunk function here seems to be for transferring NFT from sender to pool, but the original contract has a payable function that uses msg.value checks 

## Vulnerability Detail

This seems to be a weird implementation for transferring the NFT. Furthermore, the function is payable but the interface by AJNA doesn't mark it as payable. 

This function checks for the msg.value in the original Cryptopunks contract. Calling it from the ERC721Pool will always revert because the msg.value is not being sent with the call at L#577. Thus, a cryptopunk NFT will never be able to be used as the collateral in this NFT pool. 

## Impact

## Code Snippet

https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577

## Tool used

Manual Review

## Recommendation

Update the interface with the payable keyword and send msg.value along with the buyPunk call so that it passes checks at the target contract

## Discussion

**grandizzy**

we're not going to support non standard NFT anymore, just wrapped versions

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## refund-ether-patterns.md
# Refund Ether Security Patterns

## Overview

**Frequency**: 12 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for refund ether vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-22] ETH sent when calling executeAsSmartWallet function can be lost

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L202-L215
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/smart-wallet/OwnableSmartWallet.sol#L52-L64


## Vulnerability details

## Impact
Calling the `executeAsSmartWallet` function by the DAO further calls the `OwnableSmartWallet.execute` function. Since the `executeAsSmartWallet` function is `payable`, an ETH amount can be sent when calling it. However, since the sent ETH amount is not forwarded to the smart wallet contract, such sent amount can become locked in the `LiquidStakingManager` contract. For example, when the DAO attempts to call the `executeAsSmartWallet` function for sending some ETH to the smart wallet so the smart wallet can use it when calling its `execute` function, if the smart wallet's ETH balance is also higher than this sent ETH amount, calling the `executeAsSmartWallet` function would not revert, and the sent ETH amount is locked in the `LiquidStakingManager` contract while such amount is deducted from the smart wallet's ETH balance for being sent to the target address. Besides that this is against the intention of the DAO, the DAO loses the sent ETH amount that becomes locked in the `LiquidStakingManager` contract, and the node runner loses the amount that is unexpectedly deducted from the corresponding smart wallet's ETH balance.

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liqu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 2: [M-08] Mistakenly sent eth could be locked

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

If ERC20 and eth are transferred at same time, the mistakenly sent eth will be locked.

There are several functions that could be affected and cause user fund lock:

*   `addCollateral()`
*   `addCredit()`
*   `increaseCredit()`
*   `depositAndClose()`
*   `depositAndRepay()`
*   `close()`

### Proof of Concept

In `receiveTokenOrETH()`, different logic is used to handle ERC20 and eth transfer. However, in the ERC20 if block, mistakenly sent eth will be ignored. This part of eth will be locked in the contract.

```solidity
// Line-of-Credit/contracts/utils/LineLib.sol
    function receiveTokenOrETH(
      address token,
      address sender,
      uint256 amount
    )
      external
      returns (bool)
    {
        if(token == address(0)) { revert TransferFailed(); }
        if(token != Denominations.ETH) { // ERC20
            IERC20(token).safeTransferFrom(sender, address(this), amount);
        } else { // ETH
            if(msg.value < amount) { revert TransferFailed(); }
        }
        return true;
    }
```

### Recommended Mitigation Steps

In the ERC20 part, add check for `msg.value` to ensure no eth is sent:

```solidity
        if(token != Denominations.ETH) { // ERC20
            if (msg.value > 0) { revert TransferFailed(); }
            IERC20(token).safeTransferFrom(sender, address(this), amount);
        } else { // ETH
```

**[kibagateaux (Debt DAO) confirmed](https://github.com/code-423n4/2022-11-debtdao-findings/issues/355#issuecomment-1405077581)**





*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 3: [M-08] `_payoutEth()` calculates `balance` with an offset, always leaving dust `ETH` in the contract

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[PA1D.sol#L391](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/PA1D.sol#L391)<br>
[PA1D.sol#L395](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/PA1D.sol#L395)<br>

Payout recipients can call `getEthPayout()` to transfer the ETH balance of the contract to all payout recipients.<br>
This function makes an internal call to `_payoutEth`, which sends the payment to the recipients based on their associated `bp`.

The issue is that the `balance` used in the `transfer` calls is not the contract ETH balance, but the balance minus a `gasCost`.

This means `getEthPayout()` calls will leave dust in the contract.

### Impact

If the dust is small enough, a subsequent call to `getEthPayout` is likely to revert because of [this check](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/PA1D.sol#L390).<br>
And `enforcer/PA1D` does not have any other ETH withdrawal function. While `enforcer/PA1D` is meant to be used via delegate calls from a NFT collection contract, if the NFT contract does not have any withdrawal function either, this dust mentioned above is effectively lost.

### Proof of Concept

Let us take the example of a payout recipient trying to retrieve their share of the balance, equal to `40_000` For simplicity, assume one payout address, owned by Alice:

*   Alice calls `getEthPayout()`, w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: [H-01] SpeedBumpPriceGate: Excess ether did not return to the user

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: HIGH

**Details**:

_Submitted by cccz, also found by 0x52, 0xYamiDancho, csanuragjain, GimelSec, gzeon, hickuphh3, horsefacts, hyh, IllIllI, kenzo, leastwood, PPrieditis, reassor, unforgiven, WatchPug, and danb_

The `passThruGate` function of the `SpeedBumpPriceGate` contract is used to charge NFT purchase fees.
Since the price of NFT will change due to the previous purchase, users are likely to send more ether than the actual purchase price in order to ensure that they can purchase NFT. However, the passThruGate function did not return the excess ether, which would cause asset loss to the user.
Consider the following scenario:

1.  An NFT is sold for 0.15 eth
2.  User A believes that the value of the NFT is acceptable within 0.3 eth, considering that someone may buy the NFT before him, so user A transfers 0.3 eth to buy the NFT
3.  When user A's transaction is executed, the price of the NFT is 0.15 eth, but since the contract does not return excess eth, user A actually spends 0.3 eth.

### Proof of Concept

<https://github.com/code-423n4/2022-05-factorydao/blob/e22a562c01c533b8765229387894cc0cb9bed116/contracts/SpeedBumpPriceGate.sol#L65-L82>


### Recommended Mitigation Steps

    -   function passThruGate(uint index, address) override external payable {
    +  function passThruGate(uint index, address payer) override external payable {
            uint price = getCost(index);
            require(msg.value >= price, 'Please send more ETH');

            // bump up the price
            Gate 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 5: [M-05] It is possible that operator loses sent ETH after calling `HolographOperator` contract's `executeJob` function

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

ETH can be sent when calling the `HolographOperator` contract's `executeJob` function, which can execute the following code.

```solidity
File: contracts\HolographOperator.sol
419:     try
420:       HolographOperatorInterface(address(this)).nonRevertingBridgeCall{value: msg.value}(
421:         msg.sender,
422:         bridgeInRequestPayload
423:       )
424:     {
425:       /// @dev do nothing
426:     } catch {
427:       _failedJobs[hash] = true;
428:       emit FailedOperatorJob(hash);
429:     }
```

Executing the `try ... {...} catch {...}` code mentioned above will execute `HolographOperatorInterface(address(this)).nonRevertingBridgeCall{value: msg.value}(...)`. Calling the `nonRevertingBridgeCall` function can possibly execute `revert(0, 0)` if the external call to the bridge contract is not successful. When this occurs, the code in the `catch` block of the `try ... {...} catch {...}` code mentioned above will run, which does not make calling the `executeJob` function revert. As a result, even though the job is not successfully executed, the sent ETH is locked in the `HolographOperator` contract since there is no other way to transfer such sent ETH out from this contract. In this situation, the operator that calls the `executeJob` function will lose the sent ETH.

<https://github.com/code-423n4/2022-10-holograph/blob/main/contracts/HolographOperator.sol#L301-L439>

```solidity
  function executeJob(bytes calldata bridgeInRequestPayload) external payable {
    
    .

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 6: M-4: Native funds can be lost by submit() as msg.value isn't synchronized with amount

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/76 

## Found by 
hyh

## Summary

When used with native funds FeeBuyback#submit() doesn't check for the `amount` argument to correspond to `msg.value` actually linked to the call. 

## Vulnerability Detail

This can lead either to bloating or to underpaying of the actual fee depending on the mechanics that will be used to call submit(). I.e. as two values can differ, and only one can be correct, the difference is a fund loss either to the `owner` (when the fee is overpaid) or to `recipient` (when the fee is underpaid vs correct formula).

## Impact

Net impact is a fund loss proportional to the difference of the `amount` and `msg.value`. This can be either incomplete setup (native funds case isn't fully covered in a calling script) or an operational mistake (it is covered correctly, but a wrong value was occasionally left from a testing, and so on) situation.

Setting the severity to be medium as this is conditional on the actual usage of submit().

## Code Snippet

submit() uses `msg.value`, which can differ from `amount`:

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L35-L82

```solidity
  /**
   * @notice submits wallet transactions
   * @dev a secondary swap may occur
   * @dev staking contract updates may be made
   * @dev function can be paused
   * @param wallet address of the primary transaction
   * @param walletData bytes wallet data for prim

*[Content truncated...]*

---

### Example 7: Calls to PausableZone 'sexecuteMatchAdvancedOrders and executeMatchOrders would revert if unused native tokens would need to be returned

**Source**: Spearbit
**Protocol**: SEAPORT
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- PausableZone.sol#L34
- PausableZone.sol#L149
- PausableZone.sol#L188
- OrderCombiner.sol#L704-L707

## Description
In match (advanced) orders, one can provide native tokens as offer and consideration items. So, a PausableZone would need to provide msg.value to call the corresponding Seaport endpoints. There are a few scenarios where not all the msg.value native tokens amount provided to the Seaport marketplace will be used:

1. Rounding errors in calculating the current amount of offer or consideration items. The zone can prevent sending extra native tokens to Seaport by pre-calculating these values and making sure to have its transaction to be included in the specific block that these values were calculated for (this is important when the start and end amount of an item are not equal).
2. The zone (un)intentionally sends more native tokens than are necessary to Seaport.
3. The (advanced) orders sent for matching in Seaport include order type of CONTRACT offerer order and the offerer contract provides a different amount for at least one item that would eventually make the whole transaction not use the full amount of msg.value provided to it.

In all these cases, since PausableZone does not have a receive or fallback endpoint to accept native tokens, when Seaport tries to send back the unused native token amount, the transaction may revert.

### PausableZone not accepting native tokens:
```bash
$ export CODE=$(jq -r '.deployedBytecode' ar

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seaport-Spearbit-Security-Review.pdf)

---

### Example 8: H-3: `TradingUtils::_executeTrade` will leak ETH to WETH

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/98 

## Found by 
lemonmon

## Summary

If sellToken is ETH, and using Uniswap for the dex, and it is exact out trade, too much is deposited to the WETH and does not withdraw the excess amount. It will give wrong `amountSold` value as well as accounting error.

## Vulnerability Detail

`trade.sellToken` is ETH and using Uniswap as dex, WETH should be used instead of ETH as Uniswap does not support ETH. There for TradingUtils wraps the ETH to WETH before trading.

If the trade would be exact out, the amount `trade.limit` will be deposited to WETH instead of the `trade.amount`. However, because it is exact out, not all ETH deposited will be traded. In the current implementation, there is no logic to recover the excess deposit.

As the `TradingUtils::_executeInternal`, which uses the `TradingUtils::_executeTrade` will calculate the `amountSold` based on the balance of ETH, it will return the `trade.limit` as the `amountSold`, thus resulting in accounting error.

Note: in the current implementation, the trade using Uniswap with ETH as sellToken would not even work, because the WETH is not properly approved (issue 2). This issue assumes that the issue is resolved. 

## Impact

`amountSold` will reflect not the amount really sold, rather the `trade.limit`. It is unclear whether the excess amount of ETH, which is deposited for WETH can be recovered.

## Code Snippet

https://github.com/sherlock-audit/2022-09-n

*[Content truncated...]*

---

### Example 9: [M-03] Giant pools cannot receive ETH from vaults

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L137><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126>

Both giant pools are affected:

1.  GiantSavETHVaultPool
2.  bringUnusedETHBackIntoGiantPool

The giant pools have a `bringUnusedETHBackIntoGiantPool` function that calls the vaults to send back any unused ETH.
Currently, any call to this function will revert.<br>
Unused ETH will not be sent to the giant pools and will stay in the vaults.

This causes an insolvency issue when many users want to withdraw ETH and there is not enough liquidity inside the giant pools.

### Proof of Concept

`bringUnusedETHBackIntoGiantPool` calls the vaults to receive ETH:<br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L137>

        function bringUnusedETHBackIntoGiantPool(
            address[] calldata _savETHVaults,
            LPToken[][] calldata _lpTokens,
            uint256[][] calldata _amounts
        ) external {
            uint256 numOfVaults = _savETHVaults.length;
            require(numOfVaults > 0, "Empty arrays");
            require(numOfVaults == _lpTokens.length, "Inconsistent arrays");
            require(numOfVaults == _amounts.length, "Inconsistent arrays");
          

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 10: [M-03] Borrower/Lender excessive ETH not refunded and permanently locked in protocol

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L292>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L315>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L223>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L265>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/LineLib.sol#L71>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L388>

### Impact

The protocol does not refund overpayment of ETH. Excessive ETH is not included in the protocols accounting. As a result, the funds are permanently locked in the protocol **(Loss of funds)**.

There are multiple scenarios where excessive ETH could be sent by Borrowers and Lenders to the protocol.

The vulnerability effects at least five different scenarios and locks both the lender and borrowers ETH in LineOfCredit if overpaid. **There is no way to transfer the locked ETH back to the users**, as the withdraw methods are dependent on accounting (which is not updated with locked ETH).

This vulnerability impacts EscrowedLine, LineOfCredit, SpigotedLine and SecuredLine.


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 11: [M-02] If L1GraphTokenGateways outboundTransfer is called by a contract, the entire msg.value is blackholed, whether the ticket got redeemed or not

**Source**: Code4rena
**Protocol**: The Graph
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/gateway/L1GraphTokenGateway.sol#L236


## Vulnerability details

The outboundTransfer function in L1GraphTokenGateway is used to transfer user's Graph tokens to L2. To do that it eventually calls the standard Arbitrum Inbox's createRetryableTicket. The issue is that it passes caller's address in the `submissionRefundAddress` and `valueRefundAddress`. This behaves fine if caller is an EOA, but if it's called by a contract it will lead to loss of the submissionRefund (ETH passed to outboundTransfer() minus the total submission fee), or in the event of failed L2 ticket creation, the whole submission fee. The reason it's fine for EOA is because of the fact that ETH and Arbitrum addresses are congruent. However, the calling contract probably does not exist on L2 and even in the rare case it does, it might not have a function to move out the refund.

The docs don't suggest contracts should not use the TokenGateway, and it is fair to assume it will be used in this way. Multisigs are inherently contracts, which is one of the valid use cases. Since likelihood is high and impact is medium (loss of submission fee), I believe it to be a HIGH severity find.

## Impact

If L1GraphTokenGateway's outboundTransfer is called by a contract, the entire msg.value is blackholed, whether the ticket got redeemed or not.

## Proof of Concept

Alice has a multisig wallet. She sends 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-thegraph)

---

### Example 12: [M-17] WeVE (FTM) may be lost forever if redemption process is failed

**Source**: Code4rena
**Protocol**: Velodrome Finance
**Impact**: MEDIUM

**Details**:

_Submitted by Chom_

[RedemptionSender.sol#L28-L51](https://github.com/code-423n4/2022-05-velodrome/blob/7fda97c570b758bbfa7dd6724a336c43d4041740/contracts/contracts/redeem/RedemptionSender.sol#L28-L51)<br>
[RedemptionReceiver.sol#L72-L105](https://github.com/code-423n4/2022-05-velodrome/blob/7fda97c570b758bbfa7dd6724a336c43d4041740/contracts/contracts/redeem/RedemptionReceiver.sol#L72-L105)<br>

WeVE (FTM) may be lost forever if redemption process is failed.

Redemption process is likely to be failed if

*   (redeemedWEVE += amountWEVE) > eligibleWEVE
*   Not enough USDC or VELO in the contract

The case that redeem more than eligible can't be fixed because eligibleWEVE is hardcoded on contract initialization.

This mean that if there are any mistake for example LayerZero slow down and user try to repeatedly redeem their WeVE, user will lose their WeVE token forever due to contract always reverted in the destination chain due to the reason that user has redeemed more than eligible.

### Proof of Concept

1.  User redeem WeVE in fantom chain using redeemWEVE function in RedemptionSender contract.
2.  LayerZero slow but user think it is failed. (But it is just slow)
3.  User repeat process 1 again
4.  LayerZero call lzReceive in RedemptionReceiver contract on Optimism chain for the first time it's success. USDC + VELO is redeemed as intended.
5.  LayerZero call lzReceive in RedemptionReceiver contract on Optimism chain again due to repeated transaction in step 3. But this time

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-velodrome)

---

## Statistics

- Total findings analyzed: 12
- Examples shown: 12
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## pre-post-balance-patterns.md
# Pre/Post Balance Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for pre/post balance vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: `StrategyUtils::_executeDynamicTradeExactIn` does not wrap steth

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/99 

## Found by 
0x52, lemonmon

## Summary

`StrategyUtils::_executeDynamicTradeExactIn` will return bought steth value instead of wrapped steth. Also, steth is not wrapped as it is supposed to be.

## Vulnerability Detail

In the `StrategyUtils::_executeDynamicTradeExactIn`, if `params.tradeUnwrapped` is true, and `buyToken` is `WRAPPED_STETH`, the `buyToken` will be updated to be `WRAPPED_STETH.stETH()`, which is basically `STHETH` (not wrapped). (line 62 in StrategyUtils). So, it buys `stETH` in the trade, and the `amountBought` will be the amount of `stETH` bought. But the `amountBought` was expected to be the `WRAPPED_STETH` amount, as the buyToken given as `WRAPPED_STETH`. The `WRAPPED_STETH` and `STETH` are not 1 to 1, so an user can get more amountBought or less amountBought depending on the market than what is actually bought in `WRAPPED_STETH`.

Later in the same function (line 80-90), if `params.tradeUnwrapped` is true and `buyToken` is `WRAPPED_STETH` and the `amountBought` is bigger than zero, it will wrap the bought stETH to `WARPPED_STETH` and update the `amountBought` to the `WRAPPED_STETH` value. However, this code will be never reached, because if the first two conditions are met, the buyToken would be updated to the `stETH` in the above (line 62).

For example, 100 Wrapped steth will give 108 steth. So, If I choose trade unwrapped to be true, I will get 108 steth, which will be 100 

*[Content truncated...]*

---

### Example 2: H-1: `TradingUtils._executeTrade()` doesn't check `preTradeBalance` properly.

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/110 

## Found by 
0x52, lemonmon, hansfriese

## Summary
`TradingUtils._executeTrade()` doesn't check `preTradeBalance` properly.

## Vulnerability Detail
`TradingUtils._executeTrade()` doesn't check `preTradeBalance` properly.

```solidity
function _executeTrade(
    address target,
    uint256 msgValue,
    bytes memory params,
    address spender,
    Trade memory trade
) private {
    uint256 preTradeBalance;

    if (trade.sellToken == address(Deployments.WETH) && spender == Deployments.ETH_ADDRESS) {
        preTradeBalance = address(this).balance;
        // Curve doesn't support Deployments.WETH (spender == address(0))
        uint256 withdrawAmount = _isExactIn(trade) ? trade.amount : trade.limit;
        Deployments.WETH.withdraw(withdrawAmount);
    } else if (trade.sellToken == Deployments.ETH_ADDRESS && spender != Deployments.ETH_ADDRESS) {
        preTradeBalance = IERC20(address(Deployments.WETH)).balanceOf(address(this));
        // UniswapV3 doesn't support ETH (spender != address(0))
        uint256 depositAmount = _isExactIn(trade) ? trade.amount : trade.limit;
        Deployments.WETH.deposit{value: depositAmount }();
    }

    (bool success, bytes memory returnData) = target.call{value: msgValue}(params);
    if (!success) revert TradeExecution(returnData);

    if (trade.buyToken == address(Deployments.WETH)) {
        if (address(this).balance > preTradeBalance) {
            //

*[Content truncated...]*

---

### Example 3: Processing of end balances

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Medium Risk Vulnerability Report

## Severity
Medium Risk

## Context
- **Files Involved**: 
  - SwapperV2.sol (Lines 22-60)
  - Executor.sol (Lines 41-57)
  - Swapper.sol (Lines 22-38)

## Description
The contract **SwapperV2** contains the following construction (twice) to prevent the use of any already existing start balance:

- It gets a start balance.
- It performs an action.
- If the end balance is greater than the start balance, it uses the difference; otherwise (which includes the case where the start balance is equal to the end balance), it uses the end balance.

Thus, if the else clause is reached, it will use the end balance and ignore any start balance. If the action hasnt changed the balances, then start balance equals end balance, and this amount is used. When the action has lowered the balances, then the end balance is also used. 

This defeats the purpose of the code.

**Note**: Normally, there shouldnt be any tokens in the LiFi Diamond contract, so the risk is limited. The **Swapper.sol** contract has similar code.

### Code Snippets
```solidity
contract SwapperV2 is ILiFi {
    modifier noLeftovers(LibSwap.SwapData[] calldata _swapData, address payable _receiver) {
        ...
        uint256[] memory initialBalances = _fetchBalances(_swapData);
        ... // all kinds of actions
        newBalance = LibAsset.getOwnBalance(curAsset);
        curBalance = newBalance > initialBalances[i] ? newBalance - initialBalances[i] : newBalance;
        ...
    }



*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 4: [H-01] Duplication of Balance

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

It is possible to duplicate currently held `ink` or `art` within a Cauldron, thereby breaking the contract's accounting system and minting units out of thin air.

The `stir` function of the `Cauldron`, which can be invoked via a `Ladle` operation, caches balances in memory before decrementing and incrementing. As a result, if a transfer to self is performed, the assignment `balances[to] = balancesTo` will contain the added-to balance instead of the neutral balance.

This allows one to duplicate any number of `ink` or `art` units at will, thereby severely affecting the protocol's integrity. A similar attack was exploited in the third bZx hack resulting in a roughly 8 million loss.

Recommend that a `require` check should be imposed prohibiting the `from` and `to` variables to be equivalent.

**[albertocuestacanada (Yield) confirmed](https://github.com/code-423n4/2021-05-yield-findings/issues/16#issuecomment-852044133):**
 > It is a good finding and a scary one. It will be fixed. Duplicated with #7.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-yield)

---

### Example 5: [H-06] fee loss in AutoPxGmx and AutoPxGlp and reward loss in AutoPxGlp by calling `PirexRewards.claim(pxGmx/pxGpl, AutoPx*)` directly which transfers rewards to  AutoPx* pool without compound logic get executed and fee calculation logic and pxGmx wouldn't be executed for those rewards

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGlp.sol#L197-L296>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L230-L313>

### Impact

Function `compound()` in `AutoPxGmx` and `AutoPxGlp` contracts is for compounding `pxGLP` (and additionally `pxGMX`) rewards. it works by calling `PirexGmx.claim(px*, this)` to collect the rewards of the vault and then swap the received amount (to calculate the reward, contract save the balance of a contract in that reward token before and after the call to the `claim()` and by subtracting them finds the received reward amount) and deposit them in `PirexGmx` again for compounding and in doing so it calculates fee based on what it received and in `AutoPxGlp` case it calculates `pxGMX` rewards too based on the extra amount contract receives during the execution of `claim()`. But attacker can call `PirexGmx.claim(px*, PirexGlp)` directly and make `PirexGmx` contract to transfer (`gmxBaseReward` and `pxGmx`) rewards to `AutoPxGlp` and in this case the logics of fee calculation and reward calculation in `compound()` function won't get executed and contract won't get it's fee from rewards and users won't get their `pxGmx` reward. So this bug would cause fee loss in `AutoPxGmx` and `AutoPxGlp` for contract and `pxGmx`'s reward loss for users in `AutoPxGlp`.

### Proof of Concept

The bug in `AutoPxGmx`

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 6: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 7: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

**Source**: Pashov Audit Group
**Protocol**: RWf(x)_2025-08-20
**Impact**: MEDIUM

**Details**:

_Resolved_

## Severity

**Impact:** Medium  

**Likelihood:** Medium  

## Description

The `Market.mint()` function mints both fToken and xToken [based on the current collateral ratio](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/blob/main/contracts/f(x)/math/FxLowVolatilityMath.sol#L293-L307).  
In the original Aladdin implementation, this function could be called only once. However, RegnumFx [removed this restriction](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/compare/bbb461cba879349c24c02d87872e93ec0a1a1975...f6e865df2dd46d67a49391d94e54b26e6a8af43c#diff-2c8d19ba3d13b72d110c2a9536e5e9915118ad919b38848357200e91afb683faL252), allowing it to be called multiple times.

When the system enters stability mode, the collateral ratio has fallen below the defined safe threshold. This indicates that additional base tokens need to be deposited to restore the ratio.

Allowing `mint()` during stability mode worsens the problem: each new mint increases the number of fTokens in circulation, which in turn raises the amount of base tokens required to bring the system back to a healthy state. As a result, recovery becomes more difficult, and the system may remain undercollateralized for longer.

The severity chosen for this issue is medium, because only whitelisted managers can use the function, and they are trusted entities that are not interested in making stablecoin depeg.

## Recommendations

Restrict `mint()` from being called when the system is in stabili

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/RWf(x)-security-review_2025-08-20.md)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## sense-patterns.md
# Sense Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 0 | 1 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for sense vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: AutoRoller#eject can be used to steal all the yield from vault's YTs

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/22 

## Found by 
0x52

## Summary

AutoRoller#eject collects all the current yield of the YTs, combines the users share of the PTs and YTs then sends the user the entire target balance of the contract. The problem is that combine claims the yield for ALL YTs, which sends the AutoRoller target assets. Since it sends the user the entire target balance of the contract it accidentally sends the user the yield from all the pool's YTs. 

## Vulnerability Detail

    function eject(
        uint256 shares,
        address receiver,
        address owner
    ) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {

        ...

        //@audit call of interest
        (excessBal, isExcessPTs) = _exitAndCombine(shares);

        _burn(owner, shares); // Burn after percent ownership is determined in _exitAndCombine.

        if (isExcessPTs) {
            pt.transfer(receiver, excessBal);
        } else {
            yt.transfer(receiver, excessBal);
        }

        //@audit entire asset (adapter.target) balance transferred to caller, which includes collected YT yield and combined
        asset.transfer(receiver, assets = asset.balanceOf(address(this)));

        emit Ejected(msg.sender, receiver, owner, assets, shares,
            isExcessPTs ? excessBal : 0,
            isExcessPTs ? 0 : excessBal
        );
    }

    function _exitAndCombine(uint256 shares) internal returns (uint256, bool) {

*[Content truncated...]*

---

### Example 2: H-4: Adversary can brick AutoRoller by creating another AutoRoller on the same adapter

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/20 

## Found by 
0x52

## Summary

onSponsorWindowOpened attempts to make a new series at the desired maturity. Each adapter can only have one of each maturity. If the maturity requested already exists then onSponsorWindowOpened will revert, making it impossible to roll the AutoRoller. An adversary can take advantage of this to brick an AutoRoller by creating a second AutoRoller on the same adapter that will create a target maturity before the first AutoRoller. Since the maturity now exists, the first AutoRoller will always revert when trying to Roll.  

## Vulnerability Detail

    uint256 _maturity = utils.getFutureMaturity(targetDuration);

    function getFutureMaturity(uint256 monthsForward) public view returns (uint256) {
        (uint256 year, uint256 month, ) = DateTime.timestampToDate(DateTime.addMonths(block.timestamp, monthsForward));
        return DateTime.timestampFromDateTime(year, month, 1 /* top of the month */, 0, 0, 0);
    }

Inside AutoRoller#onSponsorWindowOpened the maturity is calculated using RollerUtils#getFutureMaturity. This returns the timestamp the requested months ahead, truncated down to the first of the month. It passes this calculated maturity as the maturity to sponsor a new series.

    (ERC20 _pt, YTLike _yt) = periphery.sponsorSeries(address(adapter), _maturity, true);

https://etherscan.io/address/0xFff11417a58781D3C72083CB45EF54d79Cd02437#code#F1#L90

    function s

*[Content truncated...]*

---

### Example 3: [L-04] Frontrunnable Initialization

**Source**: Pashov Audit Group
**Protocol**: Enclave_2025-10-25
**Impact**: LOW

**Details**:

_Acknowledged_

The `initialize` instruction creates the global `fund_pool` PDA (`seed = b"fund_pool"`) and sets `initial_admin` to an arbitrary public key supplied by the caller. There is no access control restricting who may invoke this first-use initializer. An attacker can front-run deployment, initialize the pool, and seize control over all admin- and signer-gated operations for the lifetime of the program (until redeploy).

**Recommendations**

Implement a robust access control mechanism that ensures only a trusted entity, such as the program's deployer or a predefined address, can call the `initialize` function. This restriction can be enforced by verifying the caller's identity or using a specific signature during initialization.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Enclave-security-review_2025-10-25.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## supportsinterface-patterns.md
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


---
## eip-165-patterns.md
# EIP-165 Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 2 | 3 | 0 |

**Common Sources**: Code4rena, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for eip-165 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-15] `HolographERC721.safeTransferFrom` not compliant with EIP-721

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

### Example 2: [M-03] LSP8 and LSP9's `ERC-165` interface ID differs from their specification

**Source**: Code4rena
**Protocol**: LUKSO
**Impact**: MEDIUM

**Details**:

According to [LSP7's specification](https://github.com/lukso-network/LIPs/blob/main/LSPs/LSP-7-DigitalAsset.md#specification), the [ERC-165](https://eips.ethereum.org/EIPS/eip-165) interface ID for LSP7 token contracts should be `0x5fcaac27`:

> ERC165 interface id: `0x5fcaac27`

However, `_INTERFACEID_LSP7` has a different value in the code:

[LSP7Constants.sol#L4-L5](https://github.com/code-423n4/2023-06-lukso/blob/main/contracts/LSP7DigitalAsset/LSP7Constants.sol#L4-L5)

```solidity
// --- ERC165 interface ids
bytes4 constant _INTERFACEID_LSP7 = 0xda1f85e4;
```

Similarly, LSP8's interface ID should be `0x49399145` according to [LSP8's specification](https://github.com/lukso-network/LIPs/blob/main/LSPs/LSP-8-IdentifiableDigitalAsset.md#specification):

> ERC165 interface id: `0x49399145`

However, `_INTERFACEID_LSP8` has a different value in the code:

[LSP8Constants.sol#L4-L5](https://github.com/code-423n4/2023-06-lukso/blob/main/contracts/LSP8IdentifiableDigitalAsset/LSP8Constants.sol#L4-L5)

```solidity
// --- ERC165 interface ids
bytes4 constant _INTERFACEID_LSP8 = 0x622e7a01;
```

These constants are used in `supportsInterface()` for the `LSP7DigitalAsset` and `LSP8IdentifiableDigitalAsset` contracts.

### Impact

Protocols that check for LSP7/LSP8 compatibility using the `ERC-165` interface IDs declared in the specification will receive incorrect return values when calling `supportsInterface()`.

### Recommended Mitigation

Ensure that the interface ID declared in th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lukso)

---

### Example 3: [01] Allowing DSSes that do not implement `ERC165.supportsInterface` function to be registered is problematic

**Source**: Code4rena
**Protocol**: Karak
**Impact**: LOW

**Details**:

### Description
https://github.com/code-423n4/2024-07-karak?tab=readme-ov-file#eip-compliance-checklist states that `DSS contract should comply with ERC-165`. Therefore, the protocol requires that each DSS is ERC-165 compliant.

According to https://eips.ethereum.org/EIPS/eip-165#how-a-contract-will-publish-the-interfaces-it-implements, `A contract that is compliant with ERC-165 shall implement the following interface`:

```solidity
interface ERC165 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceID The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    ///  uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceID` and
    ///  `interfaceID` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}
```

Thus, each DSS needs to implement the `ERC165.supportsInterface` function to comply with ERC-165. However, calling the following `Core.registerDSS` function does not check if the DSS implements the `ERC165.supportsInterface` function or not so a DSS that does not implement the `ERC165.supportsInterface` function and hence is not ERC-165 compliant can also be registered.

https://github.com/code-423n4/2024-07-karak/blob/53eb78ebda718d752023db4faff4ab1567327db4/src/Core.sol#L262-L267
```solidity
    function registerDSS(uint256 maxSlashablePercentageWad) external {
        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-07-karak)

---

### Example 4: [12] `supportsInterface` Implementation Non-Compliant with ERC-165

**Source**: Code4rena
**Protocol**: Kinetiq
**Impact**: LOW

**Details**:

**Contract Name:** `DefaultAdapter.sol`

**Function Name:** `supportsInterface`

**Description:**
The `supportsInterface` function does not return `true` for the ERC-165 interface ID (`0x01ffc9a7`), violating the standard and potentially causing compatibility issues.

**Mitigation:**
Update the function:
```

function supportsInterface(bytes4 interfaceId) external view returns (bool) {
    return interfaceId == type(IOracleAdapter).interfaceId || interfaceId == type(IERC165).interfaceId;
}
```

**Reference**: [View Original Finding](https://code4rena.com/reports/2025-04-kinetiq)

---

### Example 5: [L-03] Missing `IERC165` support in `supportsInterface()`

**Source**: Pashov Audit Group
**Protocol**: Hyperhyper_2025-03-30
**Impact**: LOW

**Details**:

The `supportsInterface` function in the `ERC721WithURIBuilderUpgradeable` contract overrides the IERC165 interface but fails to provide support for the necessary interface IDs(`IERC165`). This is not a good practice and may return incorrect results.

```solidity
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        return ERC721EnumerableUpgradeable.supportsInterface(interfaceId);
    }
```

To mitigate this issue, change it to:

````solidity
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        return ERC721EnumerableUpgradeable.supportsInterface(interfaceId) || super.supportsInterface(interfaceId);
    }

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Hyperhyper-security-review_2025-03-30.md)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## protocol-specific-patterns.md
# Protocol-Specific Audit Patterns

> **AI Skill**: This file contains protocol-specific vulnerability patterns and audit focus areas based on 50+ real audit reports from production protocols.

## Protocol Categories

| Category | Example Protocols | Key Risks |
|----------|------------------|-----------|
| [Perpetuals/Derivatives](#1-perpetuals--derivatives) | GMX, Synthetix, MUX | Oracle manipulation, liquidation, funding |
| [AMMs/DEXs](#2-amms--dexs) | MIMSwap, Smardex, Poolshark | Price manipulation, LP attacks, MEV |
| [Lending](#3-lending-protocols) | Dolomite, K33Loans, Impermax | Bad debt, interest accrual, collateral |
| [Bridges](#4-bridge-protocols) | Bridges Exchange, USDT0 | Message validation, replay, signatures |
| [Stablecoins](#5-stablecoin-protocols) | Ethena, M0, AbracadabraMoney | Depeg, redemption, collateral |
| [Vaults/Yield](#6-vault--yield-protocols) | BeefyFinance, Umami, Reliquary | Share manipulation, donation, harvest |
| [NFT/GameFi](#7-nft--gamefi-protocols) | YugaLabs, Animecoin, NFTR | Mint manipulation, metadata, randomness |
| [Governance](#8-governance-protocols) | GMX Governance, Ethereal | Vote manipulation, timelock, delegation |

---

## 1. Perpetuals & Derivatives

**Example Protocols**: GMX (365 findings over 11 months), Synthetix, MUX, PariFi

### Critical Focus Areas

#### 1.1 Oracle & Price Feeds
```
Check for:
- Price staleness handling
- Chainlink sequencer uptime checks (L2)
- Price deviation thresholds
- Multi-oracle fallback mechanisms
- Block timestamp vs oracle timestamp
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: No sequencer check on L2
function getPrice() external view returns (uint256) {
    (, int256 price,,,) = priceFeed.latestRoundData();
    return uint256(price);  // What if sequencer is down?
}

// SECURE: L2 sequencer check
function getPrice() external view returns (uint256) {
    // Check sequencer uptime first (Arbitrum, Optimism)
    (, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
    require(answer == 0, "Sequencer down");
    require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period not passed");
    
    // Then get price
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
    return uint256(price);
}
```

#### 1.2 Position Management
```
Check for:
- Maximum position size limits
- Leverage calculation accuracy
- Position update atomicity
- Fee calculation precision
- PnL calculation edge cases
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: PnL calculation can overflow
function calculatePnL(Position memory pos, uint256 currentPrice) returns (int256) {
    int256 priceDelta = int256(currentPrice) - int256(pos.entryPrice);
    return priceDelta * int256(pos.size);  // Can overflow for large positions!
}

// SECURE: Use safe math
function calculatePnL(Position memory pos, uint256 currentPrice) returns (int256) {
    int256 priceDelta = int256(currentPrice) - int256(pos.entryPrice);
    return (priceDelta * int256(pos.size)) / int256(pos.entryPrice);
}
```

#### 1.3 Liquidation Mechanics
```
Check for:
- Liquidation threshold accuracy
- Partial vs full liquidation logic
- Liquidator incentives
- Bad debt handling
- Cascade liquidation scenarios
```

#### 1.4 Funding Rate
```
Check for:
- Funding rate calculation frequency
- Rate limits/caps
- Payment direction logic
- Accumulator precision
```

### Audit Prompt for Perpetuals
```
Analyze this perpetual/derivatives protocol for:
1. Oracle manipulation via flash loans or price lag
2. Position size limits and leverage caps
3. Liquidation race conditions and threshold manipulation
4. Funding rate edge cases (overflow, frequency attacks)
5. Fee bypass or manipulation vectors
6. Cross-margin vs isolated margin edge cases
```

---

## 2. AMMs & DEXs

**Example Protocols**: MIMSwap, Smardex, Poolshark, GammaStrategies

### Critical Focus Areas

#### 2.1 Liquidity Pool Security
```
Check for:
- First depositor attack (share inflation)
- Donation attacks
- LP token manipulation
- Imbalanced pool exploitation
- Minimum liquidity requirements
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: First depositor attack
function deposit(uint256 amount) returns (uint256 shares) {
    if (totalSupply == 0) {
        shares = amount;  // First depositor sets price
    } else {
        shares = amount * totalSupply / totalAssets;
    }
    _mint(msg.sender, shares);
}

// SECURE: Burn initial shares
function deposit(uint256 amount) returns (uint256 shares) {
    if (totalSupply == 0) {
        shares = amount - MINIMUM_LIQUIDITY;
        _mint(address(0), MINIMUM_LIQUIDITY);  // Burn initial shares
    } else {
        shares = amount * totalSupply / totalAssets;
    }
    _mint(msg.sender, shares);
}
```

#### 2.2 Swap Security
```
Check for:
- Slippage protection implementation
- Fee calculation accuracy
- Token balance tracking (before/after)
- Reentrancy in swap callbacks
- k-value invariant maintenance
```

#### 2.3 Concentrated Liquidity (Uniswap V3 style)
```
Check for:
- Tick boundary handling
- Price range edge cases
- Position NFT security
- Fee accrual accuracy
- Out-of-range position handling
```

### Audit Prompt for AMMs
```
Review this AMM/DEX for:
1. First depositor/donation attack vectors
2. Swap path manipulation and routing attacks
3. Fee bypass or extraction opportunities
4. k-value invariant violations
5. MEV/sandwich attack resistance
6. Token compatibility (rebasing, fee-on-transfer)
```

---

## 3. Lending Protocols

**Example Protocols**: Dolomite, K33Loans, Impermax, MagnifyCash

### Critical Focus Areas

#### 3.1 Interest Rate Model
```
Check for:
- Utilization rate calculation
- Interest accrual frequency
- Rate manipulation via flash loans
- Compound interest precision
```

#### 3.2 Collateral Management
```
Check for:
- Collateral factor accuracy
- Cross-collateralization logic
- Collateral withdrawal checks
- Price-based vs value-based calculations
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: Check collateral after withdrawal
function withdraw(uint256 amount) external {
    collateral[msg.sender] -= amount;  // State change
    require(isHealthy(msg.sender), "Unhealthy");  // Check after
    token.transfer(msg.sender, amount);  // External call
}

// SECURE: Check before state change
function withdraw(uint256 amount) external {
    require(wouldBeHealthy(msg.sender, amount), "Would be unhealthy");
    collateral[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
}
```

#### 3.3 Liquidation
```
Check for:
- Liquidation bonus calculation
- Partial liquidation support
- Bad debt socialization
- Liquidator whitelist (if any)
- Grace period handling
```

#### 3.4 Isolation Mode
```
Check for:
- Isolation tier enforcement
- Debt ceiling per asset
- Cross-borrowing restrictions
```

### Audit Prompt for Lending
```
Analyze this lending protocol for:
1. Interest rate manipulation via utilization
2. Oracle-based price manipulation for collateral
3. Liquidation threshold gaming
4. Flash loan attack vectors (borrow/repay same block)
5. Bad debt accumulation scenarios
6. Share/debt accounting precision issues
```

---

## 4. Bridge Protocols

**Example Protocols**: Bridges Exchange, USDT0, L2 bridges

### Critical Focus Areas

#### 4.1 Message Validation
```
Check for:
- Source chain verification
- Message hash uniqueness
- Nonce management
- Expiry handling
- Replay protection
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: No chain ID in message
function processMessage(bytes32 messageHash, bytes memory signature) external {
    require(!processed[messageHash], "Already processed");
    processed[messageHash] = true;
    // Replay possible on other chains with same contract address!
}

// SECURE: Include chain ID
function processMessage(
    uint256 sourceChainId,
    bytes32 messageHash,
    bytes memory signature
) external {
    bytes32 fullHash = keccak256(abi.encode(sourceChainId, block.chainid, messageHash));
    require(!processed[fullHash], "Already processed");
    processed[fullHash] = true;
}
```

#### 4.2 Signature Verification
```
Check for:
- EIP-712 compliance
- ecrecover return value check
- Signature malleability
- Multi-sig threshold validation
```

#### 4.3 Token Handling
```
Check for:
- Lock/mint vs burn/unlock consistency
- Token address mapping correctness
- Decimal handling across chains
- Native token handling
```

### Audit Prompt for Bridges
```
Review this bridge for:
1. Cross-chain replay attacks
2. Message validation completeness
3. Signature verification security
4. Relayer manipulation vectors
5. Token supply consistency across chains
6. Finality assumptions per chain
```

---

## 5. Stablecoin Protocols

**Example Protocols**: Ethena, M0, AbracadabraMoney

### Critical Focus Areas

#### 5.1 Peg Maintenance
```
Check for:
- Redemption mechanism security
- Minting rate limits
- Collateralization ratio checks
- Emergency pause functionality
```

#### 5.2 Yield Distribution
```
Check for:
- Yield source security
- Distribution frequency
- Rebase mechanics (if applicable)
- Yield manipulation vectors
```

#### 5.3 Collateral Management
```
Check for:
- Accepted collateral types
- Collateral ratio enforcement
- Liquidation of under-collateralized positions
- Depeg scenario handling
```

### Audit Prompt for Stablecoins
```
Analyze this stablecoin protocol for:
1. Depeg scenario handling and recovery
2. Collateral value manipulation
3. Redemption/minting arbitrage
4. Yield source sustainability and security
5. Governance attack on parameters
6. Emergency mechanism effectiveness
```

---

## 6. Vault & Yield Protocols

**Example Protocols**: BeefyFinance, Umami, Reliquary, KeyFinance

### Critical Focus Areas

#### 6.1 Share Calculation
```
Check for:
- Share inflation attacks
- Rounding direction (favor protocol)
- Deposit/withdraw atomicity
- Fee on deposit/withdraw
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: Rounding favors user
function withdraw(uint256 shares) returns (uint256 assets) {
    assets = shares * totalAssets / totalShares;  // Can round up
    totalShares -= shares;
    token.transfer(msg.sender, assets);  // More assets than owed
}

// SECURE: Round down for user withdrawals
function withdraw(uint256 shares) returns (uint256 assets) {
    assets = shares.mulDivDown(totalAssets, totalShares);  // Round down
    totalShares -= shares;
    token.transfer(msg.sender, assets);
}
```

#### 6.2 Strategy Security
```
Check for:
- Strategy migration safety
- Harvest timing attacks
- Emergency withdrawal
- Strategy composability risks
```

#### 6.3 Reward Distribution
```
Check for:
- Reward token handling
- Distribution frequency
- Reward manipulation via deposits
- Vesting schedule enforcement
```

### Audit Prompt for Vaults
```
Review this vault/yield protocol for:
1. Share price manipulation via donation
2. Harvest sandwich attacks
3. Strategy migration fund safety
4. Reward dilution attacks
5. Emergency withdrawal functionality
6. Composability risks with underlying protocols
```

---

## 7. NFT & GameFi Protocols

**Example Protocols**: YugaLabs, Animecoin, NFTR, UltiBets

### Critical Focus Areas

#### 7.1 Minting Security
```
Check for:
- Mint limit enforcement
- Whitelist verification
- Price manipulation
- Randomness source for traits
```

#### 7.2 Metadata Security
```
Check for:
- URI manipulation
- Reveal mechanism security
- On-chain vs off-chain data
```

#### 7.3 Game Mechanics
```
Check for:
- Random number generation
- Reward distribution fairness
- Anti-cheat mechanisms
- Economy inflation controls
```

### Audit Prompt for NFT/GameFi
```
Analyze this NFT/GameFi protocol for:
1. Mint function access control and limits
2. Randomness manipulation for rare items
3. Game economy exploits
4. Metadata tampering vectors
5. Transfer restriction bypass
6. Marketplace integration security
```

---

## 8. Governance Protocols

**Example Protocols**: GMX Governance, Ethereal, DAO frameworks

### Critical Focus Areas

#### 8.1 Voting Mechanism
```
Check for:
- Vote counting accuracy
- Snapshot timing
- Flash loan voting attacks
- Vote delegation security
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: No snapshot, flash loan voting
function vote(uint256 proposalId, bool support) external {
    uint256 votes = token.balanceOf(msg.sender);  // Current balance!
    // Attacker flash loans tokens, votes, returns
}

// SECURE: Snapshot-based voting
function vote(uint256 proposalId, bool support) external {
    uint256 snapshotBlock = proposals[proposalId].snapshotBlock;
    uint256 votes = token.getPastVotes(msg.sender, snapshotBlock);
}
```

#### 8.2 Proposal Execution
```
Check for:
- Timelock enforcement
- Guardian/veto power
- Execution success verification
- Reentrancy in execution
```

#### 8.3 Parameter Changes
```
Check for:
- Rate limits on changes
- Sanity bounds on parameters
- Multi-step change requirements
```

### Audit Prompt for Governance
```
Review this governance protocol for:
1. Flash loan voting attacks
2. Proposal execution security
3. Timelock bypass vectors
4. Parameter change bounds
5. Vote delegation manipulation
6. Guardian/emergency power abuse
```

---

## Cross-Protocol Patterns

### Common Findings Across All Protocols

| Finding | Frequency | Severity |
|---------|-----------|----------|
| Missing access control | Very High | High-Critical |
| Incorrect rounding | High | Medium-High |
| Missing events | High | Low-Info |
| Unchecked return values | Medium | Medium |
| Timestamp dependence | Medium | Low-Medium |
| Gas griefing | Medium | Low-Medium |

### Universal Audit Checklist

```
For ANY protocol, always check:
 Access control on all state-changing functions
 Reentrancy protection on external calls
 Return value checks on token transfers
 Slippage/deadline protection on swaps
 Oracle staleness checks
 Proper event emission
 Pausability for emergencies
 Upgrade mechanism security (if upgradeable)
 Admin key management
 Input validation and bounds checking
```

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - General patterns
- [defi-vulnerabilities.md](defi-vulnerabilities.md) - DeFi patterns
- [bridge-security.md](bridge-security.md) - Bridge security
- [l2-security.md](l2-security.md) - L2 patterns


---
## vulnerability-patterns.md
# Vulnerability Patterns - AI Reference

> **For AI Assistants:** Use these patterns to detect vulnerabilities in smart contract code.

---

## How to Use These Patterns

1. **Match the pattern** against the code
2. **Check for negative patterns** (if present, it's likely a false positive)
3. **Report with severity, description, and recommendation**

---

## Solidity Patterns

###  CRITICAL Severity

#### Reentrancy with ETH Transfer
```
ID: reentrancy-eth
Category: reentrancy
Pattern: External call with value before state update

Look for:
- .call{value: ...}(...) followed by balance/state update
- Any external call before state changes

Example vulnerable code:
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // External call
    require(success);
    balances[msg.sender] -= amount;  // State update AFTER call - vulnerable!
}
```

Recommendation: Use checks-effects-interactions pattern or ReentrancyGuard
```

#### Delegatecall to Untrusted Target
```
ID: delegatecall-to-untrusted
Category: access-control
Pattern: .delegatecall() with user-controlled data

Look for:
- .delegatecall(msg.data) or .delegatecall(_data)
- delegatecall where target address is user-provided

Example vulnerable code:
```solidity
function execute(address target, bytes calldata data) external {
    target.delegatecall(data);  // Attacker controls target!
}
```

Recommendation: Never delegatecall to untrusted addresses
```

#### Unprotected Selfdestruct
```
ID: selfdestruct-arbitrary
Category: access-control
Pattern: selfdestruct without access control

Look for:
- selfdestruct(address) without onlyOwner or require(owner)
- Missing authorization checks

Negative pattern (safe if present):
- onlyOwner modifier
- require(msg.sender == owner)

Recommendation: Add access control or remove selfdestruct
```

#### Arbitrary ETH Send
```
ID: arbitrary-send-eth
Category: access-control
Pattern: ETH sent to user-controlled address without validation

Look for:
- .call{value:}() or .transfer() or .send() to arbitrary address
- Missing validation on recipient

Recommendation: Validate recipient addresses and implement access control
```

---

###  HIGH Severity

#### tx.origin Authentication
```
ID: tx-origin-auth
Category: access-control
Pattern: Using tx.origin for authentication

Look for:
- require(tx.origin == ...)
- if(tx.origin == ...)

Example vulnerable code:
```solidity
function withdraw() external {
    require(tx.origin == owner);  // Phishable!
}
```

Recommendation: Use msg.sender instead of tx.origin
```

#### Unchecked External Call
```
ID: unchecked-call
Category: unchecked-return
Pattern: External call without return value check

Look for:
- .call{...}(...); without (bool success, ) =
- Missing require(success)

Negative pattern (safe if present):
- (bool success, ) = ...
- require(success)

Example vulnerable code:
```solidity
function withdraw() external {
    payable(msg.sender).call{value: balance}("");  // Return not checked!
}
```

Recommendation: Check the return value and handle failures
```

#### Unsafe ERC20 Transfer
```
ID: unsafe-erc20-transfer
Category: unchecked-return
Pattern: ERC20 transfer without SafeERC20

Look for:
- IERC20(...).transfer(...); without require()
- Not using SafeERC20 library

Negative pattern (safe if present):
- SafeERC20
- safeTransfer
- require(token.transfer(...))

Recommendation: Use SafeERC20 from OpenZeppelin
```

#### Block Timestamp Dependence
```
ID: block-timestamp-manipulation
Category: timestamp
Pattern: Precise timestamp comparisons for critical logic

Look for:
- block.timestamp < deadline (with tight deadlines)
- Critical logic depending on exact timestamp

Example vulnerable code:
```solidity
function claim() external {
    require(block.timestamp == auctionEnd);  // Miners can manipulate!
}
```

Recommendation: Avoid precise timestamp comparisons, use ranges
```

#### Unchecked Arithmetic
```
ID: integer-overflow-unchecked
Category: arithmetic
Pattern: unchecked block with arithmetic operations

Look for:
- unchecked { ... + ... }
- unchecked { ... - ... }
- unchecked { ... * ... }

Example:
```solidity
unchecked {
    balance -= amount;  // Can underflow!
}
```

Recommendation: Ensure operations cannot overflow/underflow
```

#### Missing Zero Address Check
```
ID: missing-zero-check
Category: validation
Pattern: Critical address assignment without zero check

Look for:
- owner = _owner; without require(_owner != address(0))
- token = _token; without validation

Negative pattern (safe if present):
- require(address != address(0))
- != address(0) check

Recommendation: Add require(address != address(0))
```

---

###  MEDIUM Severity

#### Reentrancy (No ETH)
```
ID: reentrancy-no-eth
Category: reentrancy
Pattern: External call before state update (no ETH transfer)

Look for:
- .call(...) followed by state changes
- External function call before state update

Recommendation: Use checks-effects-interactions pattern
```

#### Front-Running Vulnerability
```
ID: front-running-vulnerable
Category: front-running
Pattern: Public swap/trade functions without protection

Look for:
- function swap(...) external
- function buy(...) public
- Auction/trading functions without slippage protection

Recommendation: Implement slippage protection or commit-reveal
```

#### Oracle Price Manipulation
```
ID: oracle-manipulation
Category: oracle
Pattern: Single-block price queries

Look for:
- getReserves()
- getAmountOut()
- getPrice()
- latestRoundData() without staleness check

Example vulnerable code:
```solidity
function getPrice() external view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // Spot price - manipulable!
}
```

Recommendation: Use TWAP oracles or Chainlink with proper validation
```

#### Flash Loan Callback
```
ID: flashloan-callback
Category: flash-loan
Pattern: Flash loan callback implementation

Look for:
- executeOperation()
- onFlashLoan()
- flashLoanCallback()
- uniswapV2Call() / uniswapV3Call()

Check:
- Is caller validated?
- Can it be called by anyone?

Recommendation: Validate caller is the expected pool/lender
```

#### Centralization Risk
```
ID: centralization-risk
Category: centralization
Pattern: Admin-controlled critical functions

Look for:
- onlyOwner
- onlyAdmin
- hasRole(ADMIN_ROLE, ...)

Recommendation: Consider timelocks, multisig, or DAO governance
```

#### ERC20 Approve Race Condition
```
ID: approve-race-condition
Category: race-condition
Pattern: Standard approve() without increaseAllowance pattern

Look for:
- function approve(address, uint256)
- Missing increaseAllowance/decreaseAllowance

Recommendation: Use increaseAllowance/decreaseAllowance pattern
```

---

###  LOW Severity

#### Missing Event Emission
```
ID: missing-event-emission
Category: best-practice
Pattern: State-changing function without event

Look for:
- function setXxx() without emit

Recommendation: Emit events for important state changes
```

#### Variable Shadowing
```
ID: public-variable-shadowing
Category: code-quality
Pattern: Function parameter shadows state variable

Recommendation: Use different names for parameters and state variables
```

#### Floating Pragma
```
ID: floating-pragma
Category: best-practice
Pattern: pragma solidity ^x.x.x

Look for:
- pragma solidity ^

Recommendation: Lock pragma version (e.g., pragma solidity 0.8.20)
```

#### Outdated Solidity
```
ID: outdated-solidity
Category: best-practice
Pattern: Solidity version < 0.8.x

Look for:
- pragma solidity 0.7.x or earlier

Recommendation: Upgrade to Solidity 0.8.x or later
```

---

###  GAS Optimization

#### Storage Read in Loop
```
ID: gas-storage-loop
Pattern: Reading storage variables inside loops

Look for:
- for(...) { ... array.length ... }
- for(...) { ... storageVar ... }

Recommendation: Cache storage values in memory before loops
```

#### Long Revert Strings
```
ID: gas-string-error
Pattern: require() with strings > 32 characters

Recommendation: Use custom errors or shorter messages
```

---

## Rust/Solana Patterns

###  CRITICAL

#### Missing Signer Check
```
ID: missing-signer-check
Category: access-control
Pattern: AccountInfo used without is_signer verification

Look for:
- AccountInfo without .is_signer check
- Missing Signer constraint in account validation

Recommendation: Add require!(account.is_signer)
```

#### Arbitrary CPI
```
ID: arbitrary-cpi
Category: access-control
Pattern: Cross-program invocation without program validation

Look for:
- invoke() or invoke_signed() without program_id validation
- User-controlled program in CPI

Recommendation: Validate program ID before CPI calls
```

###  HIGH

#### Missing Owner Check
```
ID: missing-owner-check
Category: access-control
Pattern: Account without ownership verification

Look for:
- Account<'info, X> without owner constraint

Recommendation: Add owner constraint in account validation
```

#### Missing PDA Validation
```
ID: pda-validation
Category: validation
Pattern: PDA without proper seed/bump validation

Look for:
- find_program_address without storing bump
- create_program_address without validation

Recommendation: Store and validate bump seeds
```

---

## Move Patterns

###  CRITICAL

#### Missing Capability Check
```
ID: missing-capability-check
Category: access-control
Pattern: Entry function without permission check

Look for:
- public entry fun without assert! for capabilities

Recommendation: Add capability check with assert!
```

###  MEDIUM

#### Resource Leak
```
ID: resource-leak
Category: resource-safety
Pattern: Resource extracted but not properly handled

Look for:
- move_from<X>(...) without move_to or drop

Recommendation: Ensure all extracted resources are moved or dropped
```

---

## Pattern Matching Tips for AI

1. **Context matters**: A pattern match in a test file is less critical
2. **Check negative patterns**: If safe pattern exists, likely false positive
3. **Follow the flow**: Trace variable assignments to understand context
4. **Consider modifiers**: Check if function has security modifiers
5. **Look for mitigations**: ReentrancyGuard, SafeERC20, etc.

## Confidence Scoring

When reporting findings:
- **HIGH confidence**: Clear pattern match with vulnerable context
- **MEDIUM confidence**: Pattern match but context unclear
- **LOW confidence**: Pattern match but mitigations may exist


---
## vulnerability-taxonomy.md
# Vulnerability Taxonomy - AI Reference

> **For AI Assistants:** Use this taxonomy to classify vulnerabilities accurately.

---

## Primary Categories

### 1. Access Control
```
Category: access-control
Description: Issues related to authorization and permission management

Subcategories:
- missing-authorization: No auth check on sensitive function
- incorrect-modifier: Wrong modifier or incomplete check
- unprotected-function: Public function should be restricted
- privilege-escalation: User gains unauthorized privileges

CWE IDs: CWE-284, CWE-285, CWE-862
Impact: unauthorized-access, funds-theft, protocol-takeover

Keywords to detect: onlyOwner missing, no auth, anyone can call
```

### 2. Reentrancy
```
Category: reentrancy
Description: Recursive calls before state updates

Subcategories:
- single-function: Same function re-entered
- cross-function: Different function in same contract
- cross-contract: Re-entry through external contract
- read-only: View function returns stale data during attack

CWE IDs: CWE-841
Impact: funds-theft, state-corruption

Keywords to detect: external call, callback, state update after call
```

### 3. Arithmetic
```
Category: arithmetic
Description: Integer overflow, underflow, and precision issues

Subcategories:
- overflow: Value exceeds maximum
- underflow: Value goes below minimum
- precision-loss: Significant digits lost in division
- division-by-zero: Unhandled zero divisor
- rounding-error: Incorrect rounding direction

CWE IDs: CWE-190, CWE-191, CWE-369
Impact: funds-theft, incorrect-calculation, dos

Keywords to detect: unchecked, multiply, divide, overflow, underflow
```

### 4. Oracle & Price Manipulation
```
Category: oracle
Description: Issues with external data feeds and price calculations

Subcategories:
- spot-price: Using easily manipulable spot price
- stale-data: Using outdated oracle data
- incorrect-decimals: Decimal mismatch in calculations
- missing-validation: Not validating oracle response

CWE IDs: CWE-20
Impact: funds-theft, unfair-arbitrage

Keywords to detect: getReserves, getPrice, latestRoundData, oracle
```

### 5. Flash Loan Attacks
```
Category: flash-loan
Description: Vulnerabilities exploitable through flash loans

Subcategories:
- price-manipulation: Flash loan to manipulate price
- governance-attack: Flash loan for voting power
- reentrancy: Flash loan combined with reentrancy

CWE IDs: (none specific)
Impact: funds-theft, protocol-manipulation

Keywords to detect: flash loan, single transaction, arbitrage
```

### 6. Front-Running & MEV
```
Category: front-running
Description: Transaction ordering vulnerabilities

Subcategories:
- sandwich-attack: Transactions before and after victim
- displacement: Attacker replaces victim transaction
- insertion: Attacker inserts transaction before victim
- suppression: Attacker blocks victim transaction

CWE IDs: CWE-362
Impact: value-extraction, unfair-execution

Keywords to detect: slippage, deadline, mempool, MEV
```

### 7. Signature & Cryptography
```
Category: signature
Description: Issues with signatures and cryptographic operations

Subcategories:
- replay-attack: Signature can be reused
- malleability: Signature can be modified
- missing-validation: Signature not properly verified
- weak-randomness: Predictable random values

CWE IDs: CWE-347, CWE-330
Impact: unauthorized-access, double-spend

Keywords to detect: signature, sign, recover, ecrecover, nonce
```

### 8. Data Validation
```
Category: data-validation
Description: Missing or incorrect input validation

Subcategories:
- missing-zero-check: No zero address/value check
- array-bounds: Array index out of bounds
- type-confusion: Incorrect type handling
- encoding: Incorrect abi encoding/decoding

CWE IDs: CWE-20, CWE-129
Impact: state-corruption, dos, funds-loss

Keywords to detect: require, validate, check, input
```

### 9. Denial of Service
```
Category: denial-of-service
Description: Attacks preventing normal operation

Subcategories:
- gas-exhaustion: Out of gas in unbounded operation
- unbounded-loop: Loop without gas limit consideration
- block-stuffing: Filling blocks to prevent transactions
- griefing: Causing loss to others without profit

CWE IDs: CWE-400, CWE-770
Impact: protocol-halt, funds-lock

Keywords to detect: loop, iterate, gas limit, revert, fail
```

### 10. Business Logic
```
Category: logic
Description: Flaws in protocol logic and invariants

Subcategories:
- incorrect-state-machine: Invalid state transitions
- broken-invariant: Protocol invariant violated
- wrong-assumption: Incorrect assumption about behavior
- edge-case: Unhandled edge case

CWE IDs: CWE-840
Impact: funds-theft, protocol-manipulation

Keywords to detect: invariant, state, logic, edge case
```

### 11. Upgradeability
```
Category: upgradeability
Description: Issues with proxy patterns and upgrades

Subcategories:
- storage-collision: Storage slot conflicts
- initialization: Uninitialized or re-initializable
- selfdestruct: Implementation can self-destruct
- function-clashing: Function selector collision

CWE IDs: (none specific)
Impact: protocol-takeover, funds-theft, brick

Keywords to detect: proxy, upgrade, initialize, implementation
```

### 12. Gas Optimization
```
Category: gas
Description: Inefficient gas usage patterns

Subcategories:
- storage-access: Expensive storage operations
- loop-optimization: Inefficient loop patterns
- memory-vs-calldata: Wrong data location
- packing: Suboptimal storage packing

CWE IDs: (none specific)
Impact: increased-cost

Keywords to detect: gas, storage, memory, calldata, optimize
```

### 13. Centralization Risks
```
Category: centralization
Description: Single points of failure and trust assumptions

Subcategories:
- admin-key: Single admin can rug
- single-oracle: Dependence on one oracle
- pause-mechanism: Centralized pause control
- upgrade-control: Centralized upgrade authority

CWE IDs: (none specific)
Impact: rug-pull, censorship, protocol-halt

Keywords to detect: owner, admin, pause, upgrade, trusted
```

### 14. Composability
```
Category: composability
Description: Issues from protocol interactions

Subcategories:
- reentrancy: Re-entry from composed protocols
- callback-handling: Improper callback handling
- token-compatibility: Incompatible token behaviors
- hook-safety: Unsafe hook implementations

CWE IDs: (none specific)
Impact: funds-theft, unexpected-behavior

Keywords to detect: callback, hook, external protocol, integration
```

---

## SWC Registry Mapping

| SWC ID | Category | Name |
|--------|----------|------|
| SWC-100 | access-control | Function Default Visibility |
| SWC-101 | arithmetic | Integer Overflow and Underflow |
| SWC-102 | upgradeability | Outdated Compiler Version |
| SWC-103 | gas | Floating Pragma |
| SWC-104 | arithmetic | Unchecked Call Return Value |
| SWC-105 | access-control | Unprotected Ether Withdrawal |
| SWC-106 | access-control | Unprotected SELFDESTRUCT |
| SWC-107 | reentrancy | Reentrancy |
| SWC-108 | data-validation | State Variable Default Visibility |
| SWC-109 | access-control | Uninitialized Storage Pointer |
| SWC-110 | denial-of-service | Assert Violation |
| SWC-111 | logic | Use of Deprecated Functions |
| SWC-112 | access-control | Delegatecall to Untrusted Callee |
| SWC-113 | denial-of-service | DoS with Failed Call |
| SWC-114 | front-running | Transaction Order Dependence |
| SWC-115 | access-control | Authorization through tx.origin |
| SWC-116 | logic | Block values as proxy for time |
| SWC-117 | signature | Signature Malleability |
| SWC-118 | upgradeability | Incorrect Constructor Name |
| SWC-119 | upgradeability | Shadowing State Variables |
| SWC-120 | signature | Weak Sources of Randomness |
| SWC-121 | data-validation | Missing Signature Replay Protection |
| SWC-122 | access-control | Lack of Proper Signature Verification |
| SWC-123 | logic | Requirement Violation |
| SWC-124 | data-validation | Write to Arbitrary Storage Location |
| SWC-125 | denial-of-service | Incorrect Inheritance Order |
| SWC-126 | denial-of-service | Insufficient Gas Griefing |
| SWC-127 | access-control | Arbitrary Jump |
| SWC-128 | denial-of-service | DoS With Block Gas Limit |
| SWC-129 | data-validation | Typographical Error |
| SWC-130 | access-control | Right-To-Left-Override |
| SWC-131 | data-validation | Presence of unused variables |
| SWC-132 | logic | Unexpected Ether balance |
| SWC-133 | signature | Hash Collisions |
| SWC-134 | logic | Hardcoded gas amount |
| SWC-135 | arithmetic | Code With No Effects |
| SWC-136 | access-control | Unencrypted Private Data |

---

## Attack Vectors

### External Call
```
Vector: external-call
Techniques:
- Reentrancy attack
- Callback exploitation
- Return value manipulation
```

### Flash Loan
```
Vector: flash-loan
Techniques:
- Price manipulation
- Governance attack
- Collateral manipulation
```

### Front-Running
```
Vector: front-running
Techniques:
- Sandwich attack
- Displacement
- Time-bandit attack
```

### Economic
```
Vector: economic
Techniques:
- Arbitrage exploitation
- Liquidation manipulation
- Token inflation attack
```

### Governance
```
Vector: governance
Techniques:
- Vote buying
- Flash loan voting
- Proposal griefing
```

### Oracle
```
Vector: oracle
Techniques:
- Spot price manipulation
- TWAP manipulation
- Oracle front-running
```

---

## Impact Types

| Impact | Description |
|--------|-------------|
| funds-theft | Direct loss of user/protocol funds |
| protocol-takeover | Attacker gains control of protocol |
| state-corruption | Invalid protocol state |
| dos | Protocol becomes unusable |
| funds-lock | Funds stuck, cannot withdraw |
| unauthorized-access | Access to restricted functions |
| value-extraction | MEV/arbitrage extraction |
| rug-pull | Admin drains funds |
| censorship | Transactions can be blocked |
| increased-cost | Higher than necessary gas costs |

---

## Classification Workflow for AI

1. **Identify category** from keywords and code patterns
2. **Determine subcategory** for specificity
3. **Map to SWC ID** if applicable
4. **Identify attack vector** - how would this be exploited?
5. **Assess impact** - what's the worst case?
6. **Check CWE mapping** for compliance reporting
7. **Generate tags** for searchability


---
## severity-scoring.md
# Severity Scoring Guide - AI Reference

> **For AI Assistants:** Use this guide to assign accurate severity scores to vulnerabilities.

---

## Severity Levels

| Level | Score Range | Color | Description |
|-------|-------------|-------|-------------|
| CRITICAL | 9.0 - 10.0 |  | Direct, unconditional fund loss |
| HIGH | 7.0 - 8.9 |  | Significant damage possible |
| MEDIUM | 4.0 - 6.9 |  | Limited impact or conditional |
| LOW | 2.0 - 3.9 |  | Minor issues, best practices |
| INFO | 0.1 - 1.9 |  | Suggestions, no security impact |
| GAS | 0.0 - 0.5 |  | Gas optimization only |

---

## Quick Severity Decision Tree

```
Is there direct fund loss possible?
 YES  Is it unconditional (anyone can exploit)?
         YES  CRITICAL
         NO (needs conditions)  HIGH

 NO  Is there indirect fund loss or protocol damage?
         YES  Is the attack practical?
                 YES  HIGH
                 NO (theoretical)  MEDIUM
        
         NO  Does it affect protocol operation?
                 YES  MEDIUM
                 NO  Is it a code quality issue?
                         YES  LOW
                         NO  INFO/GAS
```

---

## Impact Weights

When calculating severity, weight these factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Funds at Risk** | 3.0x | Can attacker steal/lock funds? |
| **Access Control** | 2.5x | Can attacker bypass authorization? |
| **Governance** | 2.0x | Can attacker manipulate governance? |
| **Data Integrity** | 2.0x | Can attacker corrupt state? |
| **Availability** | 1.5x | Can attacker DoS the protocol? |
| **Gas Efficiency** | 0.5x | Is there gas waste? |

---

## Category Base Severities

| Category | Typical Severity | Reason |
|----------|------------------|--------|
| reentrancy | CRITICAL/HIGH | Usually leads to fund theft |
| access-control | CRITICAL/HIGH | Unauthorized actions possible |
| arithmetic | HIGH/MEDIUM | Depends on affected values |
| oracle | HIGH/MEDIUM | Price manipulation risk |
| flash-loan | HIGH | Usually requires conditions |
| front-running | MEDIUM | Attack cost vs profit |
| signature | HIGH/MEDIUM | Depends on what's signed |
| data-validation | MEDIUM | Depends on impact |
| denial-of-service | MEDIUM | Funds usually safe |
| logic | Varies | Depends on business impact |
| upgradeability | CRITICAL/HIGH | Protocol takeover risk |
| centralization | MEDIUM | Trust assumption issue |
| gas | LOW/GAS | No security impact |
| best-practice | LOW/INFO | Code quality |

---

## Likelihood Modifiers

Adjust severity based on how easily exploited:

| Likelihood | Modifier | Examples |
|------------|----------|----------|
| Always exploitable | 1.0x | Anyone can call, no conditions |
| Requires specific conditions | 0.7x | Needs specific market state |
| Requires privileged access | 0.5x | Needs admin key (but admin is trusted) |
| Theoretical only | 0.3x | Requires extreme conditions |
| Unlikely in practice | 0.2x | Economic incentives prevent it |

---

## Context Modifiers

Adjust based on protocol context:

### Protocol Type
| Type | Modifier | Reason |
|------|----------|--------|
| Bridge | 1.5x | Cross-chain = higher risk |
| Oracle | 1.3x | Data integrity critical |
| DeFi (Lending/AMM) | 1.2x | Funds directly at risk |
| DAO | 1.1x | Governance attacks possible |
| NFT | 0.9x | Usually lower value at risk |
| General | 1.0x | Default |

### TVL (Total Value Locked)
| Range | Modifier |
|-------|----------|
| >$100M | 1.3x |
| $10M-$100M | 1.1x |
| <$10M | 0.9x |

### Audit Status
| Status | Modifier |
|--------|----------|
| Unaudited | 1.3x |
| Previously audited | 0.9x |
| Multiple audits | 0.8x |

---

## Severity Examples

### CRITICAL Examples
```
 Reentrancy allowing drain of all pool funds
 Missing access control on withdraw function
 Unprotected selfdestruct
 Arbitrary delegatecall to user-controlled address
 Storage collision in proxy allowing takeover
```

### HIGH Examples
```
 tx.origin authentication (phishing possible)
 Unchecked ERC20 transfer return value
 Missing zero address check on token address
 Oracle manipulation via flash loan
 First depositor vault inflation attack
```

### MEDIUM Examples
```
 Centralization risk (single admin key)
 Front-running on swap without slippage protection
 Block timestamp used for deadline
 Missing event emission on critical function
 Approve race condition (standard ERC20 approve)
```

### LOW Examples
```
 Floating pragma
 Outdated Solidity version (0.7.x)
 Variable shadowing
 Magic numbers without constants
 Missing NatSpec comments
```

### INFO/GAS Examples
```
 Storage read in loop (gas optimization)
 Long revert strings
 Public function could be external
 Unused imports
 Code style suggestions
```

---

## Severity Adjustment Keywords

**Increase severity if description contains:**
- "steal", "drain"  +20%
- "arbitrary"  +20%
- "bypass"  +15%
- "lock", "freeze"  +10%
- "anyone can"  +30%

**Decrease severity if description contains:**
- "requires admin"  -40%
- "requires owner"  -40%
- "edge case"  -30%
- "theoretical"  -50%
- "unlikely"  -60%

---

## Comparison Scoring

When prioritizing findings, compare:

```
Priority Score = Severity  Likelihood  Impact  Context

Where:
- Severity: 0-10 base score
- Likelihood: 0.2-1.0 multiplier  
- Impact: 0.5-3.0 based on funds/access affected
- Context: 0.8-1.5 based on protocol type/TVL
```

### Priority Ordering
1. CRITICAL with high likelihood  Fix immediately
2. HIGH with high likelihood  Fix before deployment
3. CRITICAL with low likelihood  Fix before deployment
4. HIGH with low likelihood  Fix recommended
5. MEDIUM  Acknowledge and consider
6. LOW  Best practice improvements
7. INFO/GAS  Optional optimizations

---

## Reporting Format

When reporting findings, include:

```markdown
## [SEVERITY] Title

**Severity:** CRITICAL | HIGH | MEDIUM | LOW | INFO
**Category:** reentrancy | access-control | ...
**Likelihood:** High | Medium | Low

**Score Breakdown:**
- Base: X/10 (from category)
- Impact: +/- Y (funds/access affected)
- Likelihood: Z (exploitability)
- Context: W (protocol type)
- **Final: X.X/10**

**Impact:**
What happens if exploited?

**Description:**
Technical details of the vulnerability.

**Recommendation:**
How to fix it.
```

---

## AI Guidelines

1. **Start with category default** severity
2. **Adjust for impact** - what's actually at risk?
3. **Adjust for likelihood** - how practical is the attack?
4. **Consider context** - protocol type, TVL, audit status
5. **Document reasoning** - explain severity choice
6. **Be consistent** - same issue = same severity across audits
7. **When in doubt** - err on higher severity, let team triage


---
## invariant-testing.md
# Invariant Test Generator - AI Reference

> **For AI Assistants:** Use these templates to generate Foundry invariant/fuzz tests for smart contracts.

---

## Overview

Invariant testing is a powerful technique where the fuzzer tries to break 
protocol invariants through random sequences of actions.

**Key concepts:**
- **Invariant**: A property that must ALWAYS be true
- **Actor/Handler**: Contract that fuzzer calls to interact with protocol
- **Target**: The contracts being tested
- **Ghost Variables**: Tracking variables that mirror expected state

---

## Basic Invariant Test Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

// Import your contracts
import {YourProtocol} from "../src/YourProtocol.sol";
import {YourToken} from "../src/YourToken.sol";

contract YourProtocolInvariantTest is StdInvariant, Test {
    YourProtocol public protocol;
    YourToken public token;
    Handler public handler;
    
    function setUp() public {
        // Deploy contracts
        token = new YourToken();
        protocol = new YourProtocol(address(token));
        
        // Deploy handler
        handler = new Handler(protocol, token);
        
        // Target the handler for fuzzing
        targetContract(address(handler));
        
        // Optional: Exclude specific functions
        // bytes4[] memory selectors = new bytes4[](1);
        // selectors[0] = Handler.skipMe.selector;
        // targetSelector(FuzzSelector({
        //     addr: address(handler),
        //     selectors: selectors
        // }));
    }
    
    // INVARIANT 1: Total supply should never exceed max
    function invariant_maxSupply() public view {
        assertLe(token.totalSupply(), token.MAX_SUPPLY());
    }
    
    // INVARIANT 2: Protocol balance should match accounting
    function invariant_balanceAccounting() public view {
        assertEq(
            token.balanceOf(address(protocol)),
            protocol.totalDeposited()
        );
    }
    
    // INVARIANT 3: Sum of all user balances equals total
    function invariant_userBalances() public view {
        uint256 sum = handler.ghost_depositSum();
        assertEq(sum, protocol.totalDeposited());
    }
    
    // Call summary for debugging
    function invariant_callSummary() public view {
        console2.log("Deposit calls:", handler.ghost_depositCount());
        console2.log("Withdraw calls:", handler.ghost_withdrawCount());
        console2.log("Total deposited:", handler.ghost_depositSum());
    }
}
```

---

## Handler Contract Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {YourProtocol} from "../src/YourProtocol.sol";
import {YourToken} from "../src/YourToken.sol";

contract Handler is Test {
    YourProtocol public protocol;
    YourToken public token;
    
    // Ghost variables for tracking
    uint256 public ghost_depositSum;
    uint256 public ghost_withdrawSum;
    uint256 public ghost_depositCount;
    uint256 public ghost_withdrawCount;
    
    // Actor tracking
    address[] public actors;
    address internal currentActor;
    
    // Bounded values
    uint256 constant MAX_DEPOSIT = 1_000_000e18;
    
    modifier useActor(uint256 actorIndexSeed) {
        currentActor = actors[bound(actorIndexSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }
    
    constructor(YourProtocol _protocol, YourToken _token) {
        protocol = _protocol;
        token = _token;
        
        // Create actors
        for (uint256 i = 0; i < 10; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            
            // Fund actors
            deal(address(token), actor, 1_000_000e18);
            
            // Approve protocol
            vm.prank(actor);
            token.approve(address(protocol), type(uint256).max);
        }
    }
    
    // HANDLER FUNCTION: Deposit
    function deposit(uint256 amount, uint256 actorSeed) public useActor(actorSeed) {
        amount = bound(amount, 1, MAX_DEPOSIT);
        
        uint256 balance = token.balanceOf(currentActor);
        if (balance < amount) return;  // Skip if insufficient
        
        protocol.deposit(amount);
        
        // Update ghost variables
        ghost_depositSum += amount;
        ghost_depositCount++;
    }
    
    // HANDLER FUNCTION: Withdraw
    function withdraw(uint256 amount, uint256 actorSeed) public useActor(actorSeed) {
        uint256 deposited = protocol.balanceOf(currentActor);
        if (deposited == 0) return;  // Skip if nothing to withdraw
        
        amount = bound(amount, 1, deposited);
        
        protocol.withdraw(amount);
        
        // Update ghost variables
        ghost_withdrawSum += amount;
        ghost_withdrawCount++;
    }
    
    // HANDLER FUNCTION: Transfer (if applicable)
    function transfer(
        uint256 amount, 
        uint256 fromSeed, 
        uint256 toSeed
    ) public {
        address from = actors[bound(fromSeed, 0, actors.length - 1)];
        address to = actors[bound(toSeed, 0, actors.length - 1)];
        
        if (from == to) return;
        
        uint256 balance = protocol.balanceOf(from);
        if (balance == 0) return;
        
        amount = bound(amount, 1, balance);
        
        vm.prank(from);
        protocol.transfer(to, amount);
    }
}
```

---

## Common Invariants by Protocol Type

### Vault/Staking Invariants

```solidity
// Total shares * price per share >= total assets (no loss)
function invariant_noLoss() public view {
    if (vault.totalSupply() == 0) return;
    
    uint256 expectedAssets = vault.totalSupply() * vault.pricePerShare() / 1e18;
    assertGe(vault.totalAssets(), expectedAssets * 99 / 100); // 1% tolerance for rounding
}

// Sum of all shares equals total supply
function invariant_shareAccounting() public view {
    uint256 sumShares;
    for (uint i = 0; i < handler.actorCount(); i++) {
        sumShares += vault.balanceOf(handler.actors(i));
    }
    assertEq(sumShares, vault.totalSupply());
}

// No shares without assets (except initial state)
function invariant_noEmptyVault() public view {
    if (vault.totalSupply() > 0) {
        assertGt(vault.totalAssets(), 0);
    }
}

// First depositor attack prevention
function invariant_noInflation() public view {
    if (vault.totalSupply() > 0 && vault.totalAssets() > 0) {
        // Price per share shouldn't be astronomical
        assertLe(vault.pricePerShare(), 1e36);
    }
}
```

### Lending Protocol Invariants

```solidity
// Collateral ratio must be maintained
function invariant_collateralization() public view {
    for (uint i = 0; i < handler.actorCount(); i++) {
        address user = handler.actors(i);
        uint256 debt = lending.getBorrowBalance(user);
        uint256 collateral = lending.getCollateralValue(user);
        
        if (debt > 0) {
            assertGe(
                collateral * 100 / debt,
                lending.minCollateralRatio()
            );
        }
    }
}

// Total borrows <= Total liquidity supplied
function invariant_liquidity() public view {
    assertLe(lending.totalBorrows(), lending.totalSupply());
}

// Interest accrual is monotonic
function invariant_interestAccrual() public view {
    assertGe(lending.borrowIndex(), handler.ghost_lastBorrowIndex());
}

// Bad debt tracking
function invariant_noBadDebt() public view {
    assertEq(lending.badDebt(), 0);
}
```

### AMM/DEX Invariants

```solidity
// Constant product (x * y = k)
function invariant_constantProduct() public view {
    uint256 reserve0 = amm.reserve0();
    uint256 reserve1 = amm.reserve1();
    
    // K should only increase (from fees)
    assertGe(reserve0 * reserve1, handler.ghost_initialK());
}

// LP tokens redeemable for fair share
function invariant_lpRedemption() public view {
    uint256 totalSupply = amm.totalSupply();
    if (totalSupply == 0) return;
    
    uint256 reserve0 = amm.reserve0();
    uint256 reserve1 = amm.reserve1();
    
    // Any LP holder should get proportional reserves
    for (uint i = 0; i < handler.actorCount(); i++) {
        address user = handler.actors(i);
        uint256 lpBalance = amm.balanceOf(user);
        
        uint256 expectedToken0 = reserve0 * lpBalance / totalSupply;
        uint256 expectedToken1 = reserve1 * lpBalance / totalSupply;
        
        // Verify they'd get at least this much
        (uint256 out0, uint256 out1) = amm.getRedeemableAmounts(lpBalance);
        assertGe(out0, expectedToken0 * 99 / 100);
        assertGe(out1, expectedToken1 * 99 / 100);
    }
}

// No free tokens
function invariant_noFreeTokens() public view {
    assertEq(
        token0.balanceOf(address(amm)),
        amm.reserve0()
    );
    assertEq(
        token1.balanceOf(address(amm)),
        amm.reserve1()
    );
}
```

### ERC20 Token Invariants

```solidity
// Sum of balances equals total supply
function invariant_balanceSum() public view {
    uint256 sum;
    for (uint i = 0; i < handler.actorCount(); i++) {
        sum += token.balanceOf(handler.actors(i));
    }
    sum += token.balanceOf(address(handler));  // Handler balance
    
    assertEq(sum, token.totalSupply());
}

// Total supply never exceeds max
function invariant_maxSupply() public view {
    assertLe(token.totalSupply(), token.MAX_SUPPLY());
}

// Zero address has zero balance
function invariant_zeroAddress() public view {
    assertEq(token.balanceOf(address(0)), 0);
}
```

### NFT/ERC721 Invariants

```solidity
// Owner count matches balance
function invariant_ownerBalance() public view {
    for (uint i = 0; i < handler.actorCount(); i++) {
        address user = handler.actors(i);
        uint256 balance = nft.balanceOf(user);
        uint256 counted = 0;
        
        for (uint j = 0; j < nft.totalSupply(); j++) {
            if (nft.ownerOf(j) == user) counted++;
        }
        
        assertEq(balance, counted);
    }
}

// Every token has valid owner
function invariant_validOwners() public view {
    for (uint i = 0; i < nft.totalSupply(); i++) {
        address owner = nft.ownerOf(i);
        assertTrue(owner != address(0));
    }
}
```

---

## Ghost Variable Patterns

```solidity
contract Handler is Test {
    // Track deposits/withdrawals
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    
    // Track per-user
    mapping(address => uint256) public ghost_userDeposits;
    mapping(address => uint256) public ghost_userWithdrawals;
    
    // Track call counts
    uint256 public ghost_depositCalls;
    uint256 public ghost_withdrawCalls;
    uint256 public ghost_failedCalls;
    
    // Track state snapshots
    uint256 public ghost_lastTotalSupply;
    uint256 public ghost_lastPrice;
    
    // Track bounds
    uint256 public ghost_minDeposit = type(uint256).max;
    uint256 public ghost_maxDeposit = 0;
    
    function deposit(uint256 amount) public {
        // ... do deposit ...
        
        // Update ghosts
        ghost_totalDeposited += amount;
        ghost_userDeposits[currentActor] += amount;
        ghost_depositCalls++;
        
        if (amount < ghost_minDeposit) ghost_minDeposit = amount;
        if (amount > ghost_maxDeposit) ghost_maxDeposit = amount;
        
        ghost_lastTotalSupply = token.totalSupply();
    }
}
```

---

## Foundry Configuration

```toml
# foundry.toml
[invariant]
runs = 256
depth = 15
fail_on_revert = false
call_override = false
dictionary_weight = 80
include_storage = true
include_push_bytes = true
shrink_run_limit = 5000
```

---

## Command Line

```bash
# Run all invariant tests
forge test --match-contract Invariant

# Run specific invariant
forge test --match-test invariant_balanceAccounting

# With verbosity for debugging
forge test --match-contract Invariant -vvvv

# With specific seed for reproduction
forge test --match-contract Invariant --fuzz-seed 12345
```

---

## AI Generation Guide

When generating invariant tests:

1. **Identify protocol type** (Vault, Lending, AMM, etc.)
2. **List core invariants**:
   - Accounting invariants (sums, balances)
   - Security invariants (access, bounds)
   - Economic invariants (ratios, prices)
3. **Create handler with bounded actions**
4. **Add ghost variables for tracking**
5. **Write invariant assertions**

### Template Prompt for AI
```
Generate Foundry invariant tests for a [PROTOCOL_TYPE] with:
- Main contract: [CONTRACT_NAME]
- Key functions: [deposit, withdraw, swap, etc.]
- Critical invariants: [describe what must always be true]
- Token: [ERC20/ERC721/native]
```


