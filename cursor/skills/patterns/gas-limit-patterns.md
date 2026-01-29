# Gas Limit Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 6 | 11 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Check for gas limit vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-08] Gas limit check is inaccurate, leading to an operator being able to fail a job intentionally

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L316](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L316)<br>

There's a check at line 316 that verifies that there's enough gas left to execute the `HolographBridge.bridgeInRequest()` with the `gasLimit` set by the user, however the actual amount of gas left during the call is less than that (mainly due to the `1/64` rule, see below).<br>
An attacker can use that gap to fail the job while still having the `executeJob()` function complete.

### Impact

The owner of the bridged token would loose access to the token since the job failed.

### Proof of Concept

Besides using a few units of gas between the check and the actual call, there's also a rule that only 63/64 of the remaining gas would be dedicated to an (external) function call. Since there are 2 external function calls done (`nonRevertingBridgeCall()` and the actual call to the bridge) `~2/64` of the gas isn't sent to the bridge call and can be used after the bridge call runs out of gas.

The following PoC shows that if the amount of gas left before the call is at least 1 million then the execution can continue after the bridge call fails:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ContractTest is Test {
    event FailedOperatorJob(bytes32 jobHash);
    uint256 private _inboundMessageCounter;
    mapping(bytes32 => bool) private _failedJobs;
    constr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: [H-01] An attacker can lock operator out of the pod by setting gas limit that's higher than the block gas limit of dest chain

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L415](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L415)<br>

When a beaming job is executed, there's a requirement that the gas left would be at least as the `gasLimit` set by the user.
Given that there's no limit on the `gasLimit` the user can set, a user can set the `gasLimit` to amount that's higher than the block gas limit on the dest chain, causing the operator to fail to execute the job.

### Impact

Operators would be locked out of the pod, unable to execute any more jobs and not being able to get back the bond they paid.

The attacker would have to pay a value equivalent to the gas fee if that amount was realistic (i.e. `gasPrice` &ast; `gasLimit` in dest chain native token), but this can be a relative low amount for Polygon and Avalanche chain (for Polygon that's 20M gas limit and `200 Gwei gas = 4 Matic`, for Avalanche the block gas limit seems to be 8M and the price `~30 nAVAX = 0.24 AVAX`). Plus, the operator isn't going to receive that amount.

### Proof of Concept

The following test demonstrates this scenario:

```diff
diff --git a/test/06_cross-chain_minting_tests_l1_l2.ts b/test/06_cross-chain_minting_tests_l1_l2.ts
index 1f2b959..a1a23b7 100644
--- a/test/06_cross-chain_minting_tests_l1_l2.ts
+++ b/test/06_cross-chain_minting_tests_l1_l2.ts
@@ -276,6 +276,7 @@ describe('Testing cross-chain minting (L1 & L2)', async function () {
             gasLimit: TES

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 3: [H-03]  LayerZeroModule miscalculates gas, risking loss of assets

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[LayerZeroModule.sol#L431-L445](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/module/LayerZeroModule.sol#L431-L445)<br>

Holograph gets its cross chain messaging primitives through Layer Zero. To get pricing estimate, it uses the DstConfig price struct exposed in LZ's [RelayerV2](https://github.com/LayerZero-Labs/LayerZero/blob/main/contracts/RelayerV2.sol#L133).

The issue is that the important baseGas and gasPerByte configuration parameters, which are used to calculate a custom amount of gas for the destination LZ message, use the values that come from the *source* chain. This is in contrast to LZ which handles DstConfigs in a mapping keyed by chainID.  The encoded gas amount is described [here](https://layerzero.gitbook.io/docs/guides/advanced/relayer-adapter-parameters).

### Impact

The impact is that when those fields are different between chains, one of two things may happen:

1.  Less severe - we waste excess gas, which is refunded to the lzReceive() caller (Layer Zero)
2.  More severe - we underprice the delivery cost, causing lzReceive() to revert and the NFT stuck in limbo forever.

The code does not handle a failed lzReceive (differently to a failed executeJob). Therefore, no failure event is emitted and the NFT is screwed.

### Recommended Mitigation Steps

Firstly, make sure to use the target gas costs.<br>
Secondly, re-engineer lzReceive to be fault-proof, i.e. save some gas to emit result event.

**[gze

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: H-3: Bull can prevent `settleContract()`

**Source**: Sherlock
**Protocol**: Bull v Bear
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bullvbear-judging/issues/111 

## Found by 
Bahurum, KingNFT, ak1, ElKu, WATCHPUG

## Summary

The bull can intentionally cause out-of-gas and revert the transaction and prevent `settleContract()`.

## Vulnerability Detail

As `IERC721(order.collection).safeTransferFrom()` is used in `settleContract()` which will call `IERC721Receiver(to).onERC721Received()` when the `to` address is an contract. 

This gives the bull a chance to intentionally prevent the transaction from happening by consuming a lot of gas and revert the whole transaction.

## Impact

The bear (victim) can not `settleContract()` therefore cannot exercise their put option rights. The bull (attacker) always wins.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L374-L411


## Tool used

Manual Review

## Recommendation

```diff
function settleContract(Order calldata order, uint tokenId) public nonReentrant {
    bytes32 orderHash = hashOrder(order);

    // ContractId
    uint contractId = uint(orderHash);

    address bear = bears[contractId];

    // Check that only the bear can settle the contract
    require(msg.sender == bear, "ONLY_BEAR");

    // Check that the contract is not expired
    require(block.timestamp < order.expiry, "EXPIRED_CONTRACT");

    // Check that the contract is not already settled
    require(!settledContracts[contractId], "SETTLED_CONTRACT");

    address bull = bulls[c

*[Content truncated...]*

---

### Example 5: TRST-M-10 MozBridge underestimates gas for sending of Moz messages

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
The bridge calculates LayerZero fees for sending Mozaic messages using the function below:
```solidity
        function quoteLayerZeroFee(uint16 _chainId, uint16 _msgType, LzTxObj memory _lzTxParams) public view returns (uint256 _nativeFee, uint256 _zroFee) { 
             bytes memory payload = "";
        if (_msgType == TYPE_REPORT_SNAPSHOT) {
                payload = abi.encode(TYPE_REPORT_SNAPSHOT);
        }
        else if (_msgType == TYPE_REQUEST_SNAPSHOT) {
                     payload = abi.encode(TYPE_REQUEST_SNAPSHOT);
        }
        else if (_msgType == TYPE_SWAP_REMOTE) {
                        payload = abi.encode(TYPE_SWAP_REMOTE);
        }
        else if (_msgType == TYPE_STAKE_ASSETS) {
                          payload = abi.encode(TYPE_STAKE_ASSETS);
        }   
        else if (_msgType == TYPE_UNSTAKE_ASSETS) {
                                 payload = abi.encode(TYPE_UNSTAKE_ASSETS);
        }
        else if (_msgType == TYPE_REPORT_SETTLE) {
                                 payload = abi.encode(TYPE_REPORT_SETTLE);
        }
        else if (_msgType == TYPE_REQUEST_SETTLE) {
                            payload = abi.encode(TYPE_REQUEST_SETTLE);
        }
        else {
                         revert("MozBridge: unsupported function type");
        }
        
                     bytes memory _adapterParams = _txParamBuilder(_chainId, _msgType, _lzTxParams);
              return layerZeroEndpoint.estimateFees(_chainId, addr

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 6: [H-03] DoS: `claimForAllWindows()` May Be Made Unusable By An Attacker

**Source**: Code4rena
**Protocol**: Joyn
**Impact**: HIGH

**Details**:

_Submitted by kirk-baird, also found by hyh and Ruhum_

When the value of `currentWindow` is raised sufficiently high `Splitter.claimForAllWindows()` will not be able to be called due to the block gas limit.

`currentWindow` can only ever be incremented and thus will always increase. This value will naturally increase as royalties are paid into the contract.

Furthermore, an attacker can continually increment `currentWindow` by calling `incrementWindow()`. An attacker can impersonate a `IRoyaltyVault` and send 1 WEI worth of WETH to pass the required checks.

### Proof of Concept

Excerpt from `Splitter.claimForAllWindows()` demonstrating the for loop over `currentWindow` that will grow indefinitely.

            for (uint256 i = 0; i < currentWindow; i++) {
                if (!isClaimed(msg.sender, i)) {
                    setClaimed(msg.sender, i);

                    amount += scaleAmountByPercentage(
                        balanceForWindow[i],
                        percentageAllocation
                    );
                }
            }

`Splitter.incrementWindow()` may be called by an attacker increasing `currentWindow`.

        function incrementWindow(uint256 royaltyAmount) public returns (bool) {
            uint256 wethBalance;

            require(
                IRoyaltyVault(msg.sender).supportsInterface(IID_IROYALTY),
                "Royalty Vault not supported"
            );
            require(
                IRoyaltyVault(msg.sender).getSplitter(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-joyn)

---

### Example 7: M-14: BondAggregator.liveMarketsBy eventually will revert because of block gas limit

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/10 

## Found by 
rvierdiiev

## Summary
BondAggregator.liveMarketsBy eventually will revert because of block gas limit
## Vulnerability Detail
https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondAggregator.sol#L259-L280
```solidity
    function liveMarketsBy(address owner_) external view returns (uint256[] memory) {
        uint256 count;
        IBondAuctioneer auctioneer;
        for (uint256 i; i < marketCounter; ++i) {
            auctioneer = marketsToAuctioneers[i];
            if (auctioneer.isLive(i) && auctioneer.ownerOf(i) == owner_) {
                ++count;
            }
        }


        uint256[] memory ids = new uint256[](count);
        count = 0;
        for (uint256 i; i < marketCounter; ++i) {
            auctioneer = marketsToAuctioneers[i];
            if (auctioneer.isLive(i) && auctioneer.ownerOf(i) == owner_) {
                ids[count] = i;
                ++count;
            }
        }


        return ids;
    }
```
BondAggregator.liveMarketsBy function is looping through all markets and does at least `marketCounter` amount of external calls(when all markets are not live) and at most 4 * `marketCounter` external calls(when all markets are live and owner matches. This  all consumes a lot of gas, even that is called from view function. And each new market increases loop size.

That means that after some time `marketsToAuctioneers` mapping will be big enough that 

*[Content truncated...]*

---

### Example 8: [M-08] OOG error in `clearLoop()`

**Source**: Pashov Audit Group
**Protocol**: Primodium_2024-10-02
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

Function `ResetClearLoopSubsystem.clearLoop()` calls `PointsMap.clear(empire)` to clear all utilities associated with an empire. The issue is that this function loops through all players of the empire and clears their data and if the player's count is very big then the execution can encounter OOG.

```solidity
  function clear(EEmpire empire) internal {
    bytes32[] memory players = keys(empire);
    for (uint256 i = 0; i < players.length; i++) {
      Value_PointsMap.deleteRecord(empire, players[i]);
      Meta_PointsMap.deleteRecord(empire, players[i]);
    }
    Keys_PointsMap.deleteRecord(empire);
    Empire.setPointsIssued(empire, 0);
  }
```

## Recommendations

Add restriction to the number of players or avoid looping through all of them in one transaction.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Primodium-security-review_2024-10-02.md)

---

### Example 9: [M-03] Risk of DoS when stoping large rental orders due to block gas limit

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

When an order is created on Opensea the `Create::validateOrder()` policy method is used to ensure the order is configured correctly. Currently there is no maximum limit to the number of `offers` in the input `ZoneParameters`, which allows orders to contain an arbitrary amount of ERC-721 and ERC-1155 items to a rental order.

If a large enough rental order is successfully created, there is a risk that it won't be able to be stopped by calling the `Stop::stopRent()` due to the amount of gas required exceeding the block gas limit. This would prevent the escrow from settling the order and leave the order permantanly in a rental state. This also means any ERC-721 and ERC-1155 tokens in the order would not be able to be reclaimed.

This situation arises under the following conditions:

*   The call to stop a rental order uses more gas than the call to create a rental order
*   The call to create the rental order is successful
*   The call to stop a rental order uses more gas than the block gas limit

### Proof of Concept

Below I have written 2 proof of concepts to show the above conditions are possible. Each of these can be added to `StopRent.t.sol` to run.

<Details>

```solidity
    // Update the `setup` in AccountCreator to 2000+ tokens on deployToken
    function testFuzz_StopRent_PayOrder_More_Expensive_To_Stop_Than_Start(uint numOf721, uint numof1155) public {
        numOf721 = bound(numOf721, 400, erc721s.length);
        numof1155 = bound(numof1155, 400, erc1155s.length);

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 10: Arithemetic underflow leading to unexpected revert and loss of funds in Receiver contract.

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- **Files:** `Receiver.sol#L254`, `Receiver.sol#L282`

## Description
The Receiver contract is designed to gracefully return the funds to users. It reserves the gas for recovering gas before doing swaps via `executor.swapAndCompleteBridgeTokens`. The logic of reserving gas for recovering funds is implemented at `Receiver.sol#L236-L258`.

```solidity
contract Receiver is ILiFi, ReentrancyGuard, TransferrableOwnership {
    // ...
    if (reserveRecoverGas && gasleft() < _recoverGas) {
        // case 1a: not enough gas left to execute calls
        receiver.call{ value: amount }("");
        // ...
    }
    // case 1b: enough gas left to execute calls
    try
        executor.swapAndCompleteBridgeTokens{
            value: amount,
            gas: gasleft() - _recoverGas
        }(_transactionId, _swapData, assetId, receiver) 
    {} catch {
        receiver.call{ value: amount }("");
    }
    // ...
}
```

The `gasleft()` function returns the remaining gas of a call. It is continuously decreasing. The second query of `gasleft()` is smaller than the first query. Hence, if the attacker tries to relay the transaction with a carefully crafted gas where `gasleft() >= _recoverGas` at the first query and `gasleft() - _recoverGas` reverts, this results in the token loss in the Receiver contract.

## Recommendation
Recommend to cache the `gasleft()`:
```solidity
if (LibAsset.isNativeAsset(assetId)) {
    // case 1: native asset
    + uint256 cach

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 11: Controller Can Indefinitely Lock Users’ Tokens

**Source**: SigmaPrime
**Protocol**: Status
**Impact**: MEDIUM

**Details**:

## Description

The `release()` function is affected by a denial of service (DoS) vulnerability, which allows the controller (or an attacker who owns the controller account) to permanently prevent users from withdrawing their deposited tokens.

This vulnerability relates to the way the external call on line [143] is executed. A malicious controller can create an attack contract, which implements a false assert (as shown in DOSAttack Contract) that consumes all the gas of the called transaction, causing the global transaction to fail. To execute this attack, the controller would migrate the `UsernameRegistrar` contract to the malicious contract, preventing all users from withdrawing their tokens.

**Note:** In practice, gas allowance of the CALL opcode varies and is dependent on the total transaction gas allowance. For transactions with > 3.5M gas, the residue gas after the call is sufficient to complete the `release()` function. See the test: `test_attack_dos_all_users` that accompanies this report for a demonstration.

## Recommendations

This type of vulnerability can be prevented by specifying a gas stipend to the external call, which prevents the external call from consuming the entire gas of the transaction. Such a solution will limit the functionality of `dropUsername(bytes32)` to the stipend gas specified in the call. An example of the correct syntax is:

```solidity
1 ! newOwner.call.gas(gasAmount)(
2 abi.encodeWithSignature(
3 "dropUsername(bytes32)",
4 _label
5 )
6 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/sigp/public-audits/blob/master/reports/status/review.pdf)

---

### Example 12: H-2: Malicious user can use an excessively large _toAddress in OFTCore#sendFrom to break layerZero communication

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/270 

## Found by 
0x52

## Summary

By default layerZero implements a blocking behavior, that is, that each message must be processed and succeed in the order that it was sent. In order to circumvent this behavior the receiver must implement their own try-catch pattern. If the try-catch pattern in the receiving app ever fails then it will revert to its blocking behavior. The _toAddress input to OFTCore#sendFrom is calldata of any arbitrary length. An attacker can abuse this and submit a send request with an excessively large _toAddress to break communication between network with different gas limits.

## Vulnerability Detail

    function sendFrom(address _from, uint16 _dstChainId, bytes calldata _toAddress, uint _amount, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) public payable virtual override {
        _send(_from, _dstChainId, _toAddress, _amount, _refundAddress, _zroPaymentAddress, _adapterParams);
    }

The _toAddress input to OFTCore#sendFrom is a bytes calldata of any arbitrary size. This can be used as follows to break communication between chains that have different block gas limits.

Example:
Let's say that an attacker wishes to permanently block the channel Arbitrum -> Optimism. Arbitrum has a massive gas block limit, much higher than Optimism's 20M block gas limit. The attacker would call sendFrom on the Arbitrum chain with the Optimism chain as 

*[Content truncated...]*

---

### Example 13: M-5: Users buying too many tickets will DoS them and the protocol if they are the winner due to OOG

**Source**: Sherlock
**Protocol**: Winnables Raffles
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-08-winnables-raffles-judging/issues/398 

## Found by 
0x73696d616f, Oblivionis, S3v3ru5, TessKimy, kuprum, neko\_nyaa
### Summary

`WinnablesTicket` stores `nft` ownership by setting the first minted nft id ownership to the user minting and all the next minted nfts remain as `0`. This means it always costs the same to mint, but the `ownerOf()` function becomes much more expensive, to the point where it may cause OOG errors. In this case, the user is able to buy tickets via [WinnablesTicketManager::buyTickets()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L182), the draw is made in [WinnablesTicketManager::drawWinner()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L310) and the chainlink request is fulfilled with the winner in [WinnablesTicketManager::fulfillRandomWords()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L350). However, in [WinnablesTicketManager::propagateWinner()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L334), it reverts due to OOG when calling [WinnablesTicket::ownerOf()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicket.sol#L97-L99).



*[Content truncated...]*

---

### Example 14: M-8: Settlement of batch auction can exceed the gas limit

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/237 

## Found by 
0xR360, Kose, MrjoryStewartBaxter, flacko, shaka
## Summary

Settlement of batch auction can exceed the gas limit, making it impossible to settle the auction.

## Vulnerability Detail

When a batch auction (EMPAM) is settled, to calculate the lot marginal price, the contract [iterates over all bids](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L611-L651) until the capacity is reached or a bid below the minimum price is found. 

As some of the operations performed in the loop are gas-intensive, the contract may run out of gas if the number of bids is too high.

Note that additionally, there is [another loop](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L772-L781) in the `_settle` function that iterates over all the remaining bids to delete them from the queue. While this loop consumes much less gas per iteration and would require the number of bids to be much higher to run out of gas, it adds to the problem.

## Impact

Settlement of batch auction will revert, causing sellers and bidders to lose their funds.

## Code Snippet

https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L611-L651

## Proof of concept

Change the minimum bid percent to 0.1% in the `EmpaModuleTest` contract in `EMPAModuleTest.sol`.

```d

*[Content truncated...]*

---

### Example 15: Low/high MaxGas values could make match/unmatch supplier/borrower functions always “fail” or revert

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Severity
**Medium Risk**

## Context
- PositionsManagerForAaveGettersSetters.sol#L47-L50
- PositionsManagerForAaveLogic.sol#L34

## Description
The `maxGas` variable is used to determine how much gas the `matchSuppliers`, `unmatchSuppliers`, `matchBorrowers`, and `unmatchBorrowers` functions can consume while trying to match/unmatch suppliers/borrowers and also updating their position if matched.

- `maxGas = 0` will make the process skip the loop entirely.
- A low `maxGas` will make the loop run at least one time, but the smaller the `maxGas`, the higher the possibility that not all available suppliers/borrowers are matched/unmatched.
- A very high `maxGas` could cause the loop to consume all the block gas, leading to a transaction revert.

*Note:* `maxGas` can be overridden by the user when calling the `supply` or `borrow` functions.

## Recommendation
Conduct thorough testing to determine a safe minimum and maximum value for `maxGas`.

## Morpho
These parameters will be decided by governance in the future. We will implement a time-lock of seven days to ensure everyone can review the relevance of these parameters. Additionally, the governance has no incentives to implement incorrect parameters that could harm Morpho and its users.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 16: A malicious user can grief a `StakePet` contract by creating massive number of pets

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `StakePet::create` function facilitates the minting of a pet NFT by depositing collateral. However, its lack of a minimum deposit requirement for minting exposes it to potential abuse. A malicious user can exploit this by minting an excessive number of NFTs. Notably, this behaviour can strain functions like `StakePetManager::buryAllDeadPets`, which in turn calls `StakePetManager::getDeadNonBuriedPets`. This latter function iterates through all pet IDs to identify pets that are dead but not yet buried.

**Impact:** When a function processes an extensive and potentially unlimited list of pet IDs, there's a risk of it consuming all available gas. Consequently, it can fail, throwing an out-of-gas exception, which negatively affects users trying to interact with the contract.

**Recommended Mitigation:** To deter such griefing attacks, it's advisable to introduce a minimum deposit requirement for the creation of a new pet. Setting this threshold ensures that the mass-minting strategy becomes cost-prohibitive for attackers.

**Client:** Fixed in commit [a692abc](https://github.com/Ranama/StakePet/commit/a692abc038fdd8992916f93d213a38c30e3a9764).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 17: [L-04] Frontrunnable Initialization

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

### Example 18: M-1: Determining how many votes to buy may run OOG.

**Source**: Sherlock
**Protocol**: Ethos Reputation Market Fix Review Contest
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-12-ethos-update-judging/issues/43 

## Found by 
bughuntoor

### Summary
The current way buying votes works is that a user sends a certain `msg.value` and a minimum and maximum amount they wish to buy, and the contract loops through the values to find the maximum amount the user can actually buy.

```solidity
    (, , , uint256 total) = _calculateBuy(markets[profileId], isPositive, minVotesToBuy);
    if (total > msg.value) revert InsufficientFunds();

    (
      uint256 purchaseCostBeforeFees,
      uint256 protocolFee,
      uint256 donation,
      uint256 totalCostIncludingFees
    ) = _calculateBuy(markets[profileId], isPositive, maxVotesToBuy);
    uint256 currentVotesToBuy = maxVotesToBuy;
    // if the cost is greater than the maximum votes to buy,
    // decrement vote count and recalculate until we identify the max number of votes they can afford
    while (totalCostIncludingFees > msg.value) {
      currentVotesToBuy--;
      (purchaseCostBeforeFees, protocolFee, donation, totalCostIncludingFees) = _calculateBuy(
        markets[profileId],
        isPositive,
        currentVotesToBuy
      );
    }
```

The problem is that this way is highly gas inefficient. And even though protocol is to be deployed on Base where gas costs are low, it would still be possible to reach significant gas costs.

Looping to check a certain buy's gas costs, costs around ~33k gas (PoC attached below). Considering

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
