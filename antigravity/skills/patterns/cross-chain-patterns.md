---
id: PAT-CROSS-CHAIN
title: Cross Chain Security Patterns
category: cross-chain
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - cross-chain
  - messaging
  - relayer

finding_count: 8
last_updated: 2026-01-31
---
# Cross Chain Security Patterns

## Overview

**Frequency**: 8 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 4 | 0 | 0 |

**Common Sources**: Sherlock, Codehawks, Code4rena, Halborn

---

## Detection Checklist

- [ ] Check for cross chain vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: A user can steal an already transfered and bridged reSDL lock because of approval

**Source**: Codehawks
**Protocol**: stake.link
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281</a>


## Summary
The reSDL token approval is not deleted when the lock is bridged to an other chain

## Vulnerability Details
When a reSDL token is bridged to an other chain, the `handleOutgoingRESDL()` function is called to make the state changes into the `sdlPool` contract. The function executes the following:

```
    function handleOutgoingRESDL(
        address _sender,
        uint256 _lockId,
        address _sdlReceiver
    )
        external
        onlyCCIPController
        onlyLockOwner(_lockId, _sender)
        updateRewards(_sender)
        updateRewards(ccipController)
        returns (Lock memory)
    {
        Lock memory lock = locks[_lockId];

        delete locks[_lockId].amount;
        delete lockOwners[_lockId];
        balances[_sender] -= 1;

        uint256 totalAmount = lock.amount + lock.boostAmount;
        effectiveBalances[_sender] -= totalAmount;
        effectiveBalances[ccipController] += totalAmount;


*[Content truncated...]*

---

### Example 2: Incompatibility with Multisig Wallets in `TempleGold::send` Function

**Source**: Codehawks
**Protocol**: TempleGold
**Impact**: HIGH

**Details**:

## Summary:

The `send` function in `TempleGold` smart contract is designed to facilitate cross-chain token transfers using LayerZero. However, it contains a restrictive condition that disallows transfers if the sender's address does not match the recipient's address. This creates a significant issue for users utilizing multisig wallets, as these wallets often have different addresses across different chains, preventing them from transferring their funds cross-chain.

## Vulnerability Detail:

The vulnerability lies in the address validation check: `if (msg.sender != _to) { revert ITempleGold.NonTransferrable(msg.sender, _to); }`. This condition ensures that the sender and the recipient addresses are identical, which is not the case for multisig wallets operating across different chains such as Ethereum and Arbitrum.

## Code Snippet:

```javascript
function send(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable virtual override(IOFT, OFTCore) returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt) {
        if (_sendParam.composeMsg.length > 0) { revert CannotCompose(); }
        /// cast bytes32 to address
        address _to = _sendParam.to.bytes32ToAddress();
        /// @dev user can cross-chain transfer to self
@>      if (msg.sender != _to) { revert ITempleGold.NonTransferrable(msg.sender, _to); }

        // @dev Applies the token transfers regarding this send() operatio

*[Content truncated...]*

---

### Example 3: H-1: Users will lock raffle prizes on the `WinnablesPrizeManager` contract by calling `WinnablesTicketManager::propagateRaffleWinner` with wrong CCIP inputs

**Source**: Sherlock
**Protocol**: Winnables Raffles
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-08-winnables-raffles-judging/issues/50 

## Found by 
0rpse, 0x0bserver, 0x73696d616f, 0xAadi, 0xbrivan, 0xrex, CatchEmAll, DrasticWatermelon, Feder, Galturok, IMAFVCKINSTARRRRRR, KungFuPanda, Oblivionis, Offensive021, Oxsadeeq, PNS, PTolev, Paradox, Penaldo, PeterSR, S3v3ru5, SadBase, SovaSlava, Trooper, Waydou, akiro, araj, dany.armstrong90, dimulski, dinkras\_, durov, dy, gajiknownnothing, iamnmt, irresponsible, jennifer37, joshuajee, matejdb, neko\_nyaa, ogKapten, philmnds, rsam\_eth, sakshamguruji, shaflow01, shikhar, tofunmi, turvec, utsav
### Summary

The [`WinnablesTicketManager::propagateRaffleWinner`](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L334) function is vulnerable to misuse, where incorrect CCIP inputs can lead to assets being permanently locked in the `WinnablesPrizeManager` contract. The function does not have input validation for the `address prizeManager` and `uint64 chainSelector` parameters. If called with incorrect values, it will fail to send the message to `WinnablesPrizeManager`, resulting in the assets not being unlocked.


### Root Cause

The root cause of the issue lies in the design of the `propagateRaffleWinner` function:
1. The function is responsible for sending a message to WinnablesPrizeManager to unlock the raffle assets.
2. The function is marked as external, so anyone can call it.
3. The function receives `addr

*[Content truncated...]*

---

### Example 4: [M-14] Cross-chain replay attacks are possible with deployLPToken

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LPTokenFactory.sol#L27-L48


## Vulnerability details

### Impact
Mistakes made on one chain can be re-applied to a new chain

There is nochain.idin the data

If a user does `deployLPToken`using the wrong network, an attacker can replay the action on the correct chain, and steal the funds a-la the wintermute gnosis safe attack, where the attacker can create the same address that the user tried to, and steal the funds from there


https://mirror.xyz/0xbuidlerdao.eth/lOE5VN-BHI0olGOXe27F0auviIuoSlnou_9t3XRJseY


### Proof of Concept

```js
contracts/liquid-staking/LPTokenFactory.sol:
  26      /// @param _tokenName Name of the LP token to be deployed
  27:     function deployLPToken(
  28:         address _deployer,
  29:         address _transferHookProcessor,
  30:         string calldata _tokenSymbol,
  31:         string calldata _tokenName
  32:     ) external returns (address) {
  33:         require(address(_deployer) != address(0), "Zero address");
  34:         require(bytes(_tokenSymbol).length != 0, "Symbol cannot be zero");
  35:         require(bytes(_tokenName).length != 0, "Name cannot be zero");
  36: 
  37:         address newInstance = Clones.clone(lpTokenImplementation);
  38:         ILPTokenInit(newInstance).init(
  39:             _deployer,
  40:             _transferHookProcessor,
  41:             _tokenSymbol,
  42:             _tokenName
  43:     

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 5: Unhandled Exceptions in CCIP Message Processing Can Lead to Cross-Chain Communication Failure

**Source**: Halborn
**Protocol**: Contracts V1
**Impact**: MEDIUM

**Details**:

##### Description

The `CCIPAdapter` contract in the LucidLabs protocol uses Chainlink's Cross-Chain Interoperability Protocol (CCIP) to facilitate cross-chain communication. However, the implementation fails to handle exceptions gracefully in the receiving contracts, specifically in `VotingControllerUpgradeable` and `AssetController`.

```
function _ccipReceive(Client.Any2EVMMessage memory any2EvmMessage) internal override {
    _registerMessage(bytes32ToAddress(_originSender), _callData, chainId);
}
```

  

This function calls `registerMessage()` on `VotingControllerUpgradeable` and `AssetController`, which can revert due to various reasons:

```
function castCrossChainVote(...) external {
    //E @AUDIT can revert because of state(proposalId) , timepoint is not the good
    if ((adapter != msg.sender) || (state(proposalId) != ProposalState.Active) || (proposalSnapshot(proposalId) != timepoint) || (chainTokens[chainId] != sourceToken))
        revert Governor_WrongParams();
// ...
    _countVote(proposalId, voter, support, votes, voteData, chainId);
// ...
}

function _countVote(
        uint256 proposalId,
        address account,
        uint8 support,
        uint256 totalWeight,
        bytes memory voteData, //E when called from LucidGovernor{Timelock} it is not implemented => _countVoteNominal is called
        uint256 chainId 
    ) internal virtual {
        
        if (totalWeight == 0) revert GovernorCrossCountingFractionalUpgradeable_NoWeight();

        if (_p

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/lucid-labs/contracts-v1)

---

### Example 6: [M-03] Cross-Chain Signature Replay Attack

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

### Example 7: H-30: In the Liquidation Type 1 process, Ether refunds are being sent to an incorrect recipient address

**Source**: Sherlock
**Protocol**: Autonomint Colored Dollar V1
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-11-autonomint-judging/issues/998 

## Found by 
0x23r0, 0xAristos, Audinarey, AuditorPraise, Aymen0909, DenTonylifer, Flashloan44, John44, LZ\_security, Ocean\_Sky, RampageAudit, nuthan2x, santiellena, super\_jack, t.aksoy, theweb3mechanic, valuevalk, volodya, wellbyt3

### Summary

In the Liquidation Type 1 process, Ether refunds are being sent to an incorrect [recipient address](https://github.com/sherlock-audit/2024-11-autonomint-bluenights004/blob/main/Blockchain/Blockchian/contracts/Core_logic/borrowLiquidation.sol#L303). Specifically, refunds should be directed to the admin user, who acts as the liquidation operator and is the legitimate recipient. However, the current implementation mistakenly sends the refund to the borrowers address.

```Solidity
File: borrowLiquidation.sol
302:         if (liqAmountToGetFromOtherChain == 0) {
303:             (bool sent, ) = payable(user).call{value: msg.value}(""); //@note wrong address 
304:             require(sent, "Failed to send Ether");
305:         }
```

### Root Cause

When liqAmountToGetFromOtherChain is zero or cross-chain operations are unnecessary, the Ether refund is incorrectly sent to the borrowers address instead of the admins address. This misdirection can result in the admin losing funds that should rightfully be refunded to them.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

Her

*[Content truncated...]*

---

### Example 8: M-2: Cross-chain replay attacks are possible with `changeRecipientAddress()`

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/004-M 

## Found by 
minhquanym, JohnSmith, IllIllI

## Summary
Mistakes made on one chain can be re-applied to a new chain

## Vulnerability Detail
There is no `chain.id` in the signed data

## Impact
If a user does a `changeRecipientAddress()` using the wrong network, an attacker can replay the action on the correct chain, and steal the funds a-la the wintermute gnosis safe attack, where the attacker can create the same address that the user tried to, and steal the funds from there

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L60-L73

## Tool used

Manual Review

## Recommendation
Include the `chain.id` in what's hashed

## Harpie Team
Added chainId to signature and signature validation. Fix [here](https://github.com/Harpieio/contracts/pull/4/commits/de24a50349ec014163180ba60b5305098f42eb14).

## Lead Senior Watson
This is true assuming the contract address is the same across other chains. Confirmed fix.

---

## Statistics

- Total findings analyzed: 8
- Examples shown: 8
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

