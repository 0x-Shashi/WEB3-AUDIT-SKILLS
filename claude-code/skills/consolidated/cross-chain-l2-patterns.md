# Cross-Chain & L2 Security Patterns (Consolidated)

> **Bridging and L2 introduce unique attack vectors. Cross-chain replay = double withdrawal.**

---

## Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Message Replay | Same message executed on multiple chains | Critical |
| Sequencer Down | L2 sequencer offline breaks oracles | High |
| Bridge Double-Spend | Withdraw same funds twice | Critical |
| Reorg Risk | L2 reorgs can reverse finality | High |
| L1 → L2 Delay | Messages take time to finalize | Medium |
| Gas Price Differences | L2 gas much cheaper than L1 | Medium |

---

## Detection Strategy

### Cross-Chain Replay
```solidity
// VULNERABLE: No chain ID in message
bytes32 messageHash = keccak256(abi.encode(to, amount, nonce));

// SAFE: Include chain ID
bytes32 messageHash = keccak256(abi.encode(
    to, 
    amount, 
    nonce, 
    block.chainid,  // Prevent cross-chain replay
    address(this)   // Prevent cross-contract replay
));
```

### L2 Sequencer Check (Chainlink)
```solidity
// For Arbitrum/Optimism, check sequencer status
address constant SEQUENCER_FEED = 0x...;

function getPrice() external view returns (uint) {
    // Check sequencer is up
    (, int answer, uint startedAt,,) = sequencerFeed.latestRoundData();
    bool isSequencerUp = answer == 0;
    require(isSequencerUp, "Sequencer down");
    
    // Check grace period after sequencer restart
    uint timeSinceUp = block.timestamp - startedAt;
    require(timeSinceUp > GRACE_PERIOD, "Grace period");
    
    // Now safe to get price
    return getPriceFromOracle();
}
```

### Bridge Security Checklist
- [ ] Messages include source chain ID
- [ ] Messages include source contract address
- [ ] Nonce prevents replay on same chain
- [ ] Waiting period for L2 → L1 messages
- [ ] Sequencer uptime check for L2 oracles
- [ ] Grace period after sequencer restart

---

## L2 Specific Considerations

| Chain | Block Time | Finality | Special Considerations |
|-------|------------|----------|------------------------|
| Arbitrum | ~0.25s | ~1 week to L1 | Sequencer can censor |
| Optimism | ~2s | ~1 week to L1 | Sequencer can censor |
| zkSync | ~1s | Minutes to L1 | Different gas model |
| Polygon | ~2s | Minutes | Reorg risk |

---

## Included Pattern Files

- cross-chain-patterns.md, bridge-patterns.md, bridge-security.md
- l2-sequencer-patterns.md, l2-security.md
- arbitrum-patterns.md, optimism-patterns.md, layerzero-patterns.md
- 51-attack-patterns.md, chain-reorganization-attack-patterns.md

---

## Full Pattern Details

---
## cross-chain-patterns.md
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

There is noÂ chain.idÂ in the data

If a user does `deployLPToken`Â using the wrong network, an attacker can replay the action on the correct chain, and steal the funds a-la the wintermute gnosis safe attack, where the attacker can create the same address that the user tried to, and steal the funds from there


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

In the Liquidation Type 1 process, Ether refunds are being sent to an incorrect [recipient address](https://github.com/sherlock-audit/2024-11-autonomint-bluenights004/blob/main/Blockchain/Blockchian/contracts/Core_logic/borrowLiquidation.sol#L303). Specifically, refunds should be directed to the admin user, who acts as the liquidation operator and is the legitimate recipient. However, the current implementation mistakenly sends the refund to the borrowerâ€™s address.

```Solidity
File: borrowLiquidation.sol
302:         if (liqAmountToGetFromOtherChain == 0) {
303:             (bool sent, ) = payable(user).call{value: msg.value}(""); //@note wrong address 
304:             require(sent, "Failed to send Ether");
305:         }
```

### Root Cause

When liqAmountToGetFromOtherChain is zero or cross-chain operations are unnecessary, the Ether refund is incorrectly sent to the borrowerâ€™s address instead of the adminâ€™s address. This misdirection can result in the admin losing funds that should rightfully be refunded to them.

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


---
## bridge-patterns.md
# Bridge Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 2 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for bridge vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Tokens are left in the protocol when the swap at the destination chain fails

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
- AmarokFacet.sol#L55-L94
- StargateFacet.sol#L149-L187
- NXTPFacet.sol#L86-L117
- Executor.sol#L125-L221
- XChainExecFacet.sol#L17-L51

## Description
LiFi protocol finds the best bridge route for users. In some cases, it helps users do a swap at the destination chain. With the help of the bridge protocols, the LiFi protocol assists users in triggering `swapAndComplete-BridgeTokensVia{Services}` or `CompleteBridgeTokensVia{Services}` at the destination chain to perform the swap.

Some bridge services will send the tokens directly to the receiver address when the execution fails. For example, Stargate, Amarok, and NXTP conduct the external call in a try-catch clause and send the tokens directly to the receiver when it fails. The tokens will remain in the LiFi protocol in this scenario. If the receiver is the Executor contract, users can freely pull the tokens. 

**Note:** Exploiters can pull the tokens from the LiFi protocol. Please refer to the issue **"Remaining tokens can be swept from the LiFi Diamond or the Executor," Issue #82**. Exploiters can take a more aggressive strategy and force the victim's swap to revert. A possible exploit scenario:

- A victim wants to swap 10K optimismâ€™s BTC into Ethereum mainnet USDC.
- Since DEXs on the mainnet have the best liquidity, the LiFi protocol helps users swap on the mainnet.
- The transaction on the source chain (optimism) succeeds, and the bridge services try to call `Co

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] Large Validator Sets/Rapid Validator Set Updates May Freeze the Bridge or Relayers

**Source**: Code4rena
**Protocol**: Althea Gravity Bridge
**Impact**: HIGH

**Details**:

_Submitted by nascent_

In a similar vein to "Freeze The Bridge Via Large ERC20 Names/Symbols/Denoms", a sufficiently large validator set or sufficiently rapid validator update, could cause both the `eth_oracle_main_loop` and `relayer_main_loop` to fall into a state of perpetual errors. In `find_latest_valset`, [we call](https://github.com/althea-net/cosmos-gravity-bridge/blob/92d0e12cea813305e6472851beeb80bd2eaf858d/orchestrator/relayer/src/find_latest_valset.rs#L33-L40):

```rust
let mut all_valset_events = web3
    .check_for_events(
        end_search.clone(),
        Some(current_block.clone()),
        vec![gravity_contract_address],
        vec![VALSET_UPDATED_EVENT_SIG],
    )
    .await?;
```

Which if the validator set is sufficiently large, or sufficiently rapidly updated, continuoussly return an error if the logs in a 5000 (see: `const BLOCKS_TO_SEARCH: u128 = 5_000u128;`) block range are in excess of 10mb. Cosmos hub says they will be pushing the number of validators up to 300 (currently 125). At 300, each log would produce 19328 bytes of data (4\*32+64\*300). Given this, there must be below 517 updates per 5000 block range otherwise the node will fall out of sync.

This will freeze the bridge by disallowing attestations to take place.

This requires a patch to reenable the bridge.

#### Recommendation

Handle the error more concretely and check if you got a byte limit error. If you did, chunk the search size into 2 and try again. Repeat as necessary, and combine

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-08-gravitybridge)

---

### Example 3: [H-03] Freeze The Bridge Via Large ERC20 Names/Symbols/Denoms

**Source**: Code4rena
**Protocol**: Althea Gravity Bridge
**Impact**: HIGH

**Details**:

_Submitted by nascent_

Ethereum Oracles watch for events on the `Gravity.sol` contract on the Ethereum blockchain. This is performed in the [`check_for_events`](https://github.com/althea-net/cosmos-gravity-bridge/blob/92d0e12cea813305e6472851beeb80bd2eaf858d/orchestrator/orchestrator/src/ethereum_event_watcher.rs#L23) function, and run in the [`eth_oracle_main_loop`](https://github.com/althea-net/cosmos-gravity-bridge/blob/92d0e12cea813305e6472851beeb80bd2eaf858d/orchestrator/orchestrator/src/main_loop.rs#L94).

In this function, there is [the following code snippet](https://github.com/althea-net/cosmos-gravity-bridge/blob/92d0e12cea813305e6472851beeb80bd2eaf858d/orchestrator/orchestrator/src/ethereum_event_watcher.rs#L66-L73):

```rust
let erc20_deployed = web3
    .check_for_events(
        starting_block.clone(),
        Some(latest_block.clone()),
        vec![gravity_contract_address],
        vec![ERC20_DEPLOYED_EVENT_SIG],
    )
    .await;
```

This snippet leverages the `web30` library to check for events from the `starting_block` to the `latest_block`. Inside the `web30` library this nets out to calling:

```rust
pub async fn eth_get_logs(&self, new_filter: NewFilter) -> Result<Vec<Log>, Web3Error> {
    self.jsonrpc_client
        .request_method(
            "eth_getLogs",
            vec![new_filter],
            self.timeout,
            Some(10_000_000),
        )
        .await
}
```

The `10_000_000` specifies the maximum size of the return in bytes and retu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-08-gravitybridge)

---

### Example 4: [H-02] Freeze Bridge via Non-UTF8 Token Name/Symbol/Denom

**Source**: Code4rena
**Protocol**: Althea Gravity Bridge
**Impact**: HIGH

**Details**:

_Submitted by nascent_

Manual insertion of non-utf8 characters in a token name will break parsing of logs and will always result in the oracle getting in a loop of failing and early returning an error. The fix is non-trivial and likely requires significant redesign.

### Proof of Concept
Note the `c0` in the last argument of the call data (invalid UTF8).

It can be triggered with:

```solidity
data memory bytes = hex"f7955637000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000461746f6d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046e616d6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000673796d626fc00000000000000000000000000000000000000000000000000000";
gravity.call(data);
```

The log output is as follows:
```solidity
    ERC20DeployedEvent("atom", "name", â®utf8 decode failedâ¯: 0x73796d626fc0, 18, 2)
```

Which hits [this code path](https://github.com/althea-net/cosmos-gravity-bridge/blob/92d0e12cea813305e6472851beeb80bd2eaf858d/orchestrator/gravity_utils/src/types/ethereum_events.rs#L431-L438):

```rust
    let symbol = String::from_utf8(input.data[index_start..index_end

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-08-gravitybridge)

---

### Example 5: Funds can be locked during the recovery stage

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Low Risk**

## Context
`AmarokFacet.sol#L133`

## Description
The recovery address is intended to receive funds if the execution fails on the destination domain. This approach ensures that funds are never lost due to failed calls. However, in the `AmarokFacet`, it is hardcoded as `msg.sender`. Several unexpected behaviors can be observed with this implementation:

- If the `msg.sender` is a smart contract, it might not be available on the destination chain.
- If the `msg.sender` is a smart contract deployed on another chain, the contract may not have a function to withdraw the native token.

As a result of this implementation, funds can be locked when an execution fails.

```solidity
contract AmarokFacet is ILiFi, SwapperV2, ReentrancyGuard {
...
IConnextHandler.XCallArgs memory xcallArgs = IConnextHandler.XCallArgs({
    params: IConnextHandler.CallParams({
        to: _bridgeData.receiver,
        callData: _bridgeData.callData,
        originDomain: _bridgeData.srcChainDomain,
        destinationDomain: _bridgeData.dstChainDomain,
        agent: _bridgeData.receiver,
        recovery: msg.sender,
        forceSlow: false,
        receiveLocal: false,
        callback: address(0),
        callbackFee: 0,
        relayerFee: 0,
        slippageTol: _bridgeData.slippageTol
    }),
    transactingAssetId: _bridgeData.assetId,
    amount: _amount
});
...
}
```

## Recommendation
Consider taking the recovery parameter as an argument.

## LiFi
Fi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 6: Users are forced to accept any slippage on the destination chain

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
BridgeFacet.sol#L28

## Description
The documentation mentioned that there is a cancel function on the destination domain that allows users to send the funds back to the origin domain, accepting the loss incurred by slippage from the origin pool. However, this feature is not found in the current codebase. If the high slippage rate persists continuously on the destination domain, the users will be forced to accept the high slippage rate. Otherwise, their funds will be stuck in Connext.

## Recommendation
Implement the cancel function on the destination domain to allow users to send funds back to the origin domain if they choose not to accept the high slippage rate on the destination domain.

## Connext
Solved in PR 2456.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 7: RootManager.propagate does not operate in a fail-safe manner

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
RootManager.sol#L147-L173

## Description
A bridge failure on one of the supported chains will cause the entire messaging network to break down.

When the `RootManager.propagate` function is called, it will loop through the hub connector of all six chains (Arbitrum, Gnosis, Multichain, Optimism, Polygon, ZKSync) and attempt to send over the latest aggregated root by making a function call to the respective chain's AMB contract. There is a tight dependency between the chain's AMB and hub connector.

The problem is that if one of the function calls to the chain's AMB contract reverts (e.g. one of the bridges is paused), the entire `RootManager.propagate` function will revert, and the messaging network will stop working until someone figures out the problem and manually removes the problematic hub connector.

As Connext grows, the number of chains supported will increase, and the risk of this issue occurring will also increase.

## Recommendation
The `RootManager.propagate` function should operate in a fail-safe manner (e.g. using try-catch or `address.call`). Chain's AMB contracts are considered external third-party and beyond Connext's control. Thus, the `RootManager.propagate` function should not assume that function calls to these third-party bridge contracts will always succeed and will not revert.

- **Connext:** Solved in PR 2430.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## bridge-security.md
# Bridge Security Patterns - AI Reference

> **For AI Assistants:** Bridges are high-value targets. Apply these patterns when auditing cross-chain protocols.

---

## Bridge Architecture Types

| Type | Description | Risk Level |
|------|-------------|------------|
| **Lock & Mint** | Lock on source, mint on destination | High - custodial |
| **Burn & Mint** | Burn on source, mint on destination | Medium - coordination |
| **Liquidity Pool** | Swap against pools on both chains | High - liquidity attacks |
| **Atomic Swap** | Trustless exchange using HTLCs | Low - no custody |
| **Canonical** | Official L1<->L2 bridge | Lower - protocol secured |

---

## Critical Bridge Vulnerabilities

### 1. Message Validation Failures
```
Severity: CRITICAL
Category: access-control

Description:
The most common bridge vulnerability - not properly validating 
that a message came from the expected source.

Attack: Attacker sends fake message to destination chain claiming 
they deposited on source chain.

Vulnerable patterns:
```solidity
// VULNERABLE: No sender validation
function receiveMessage(bytes calldata proof) external {
    (address user, uint256 amount) = decode(proof);
    _mint(user, amount);  // Mints without verifying source!
}

// VULNERABLE: Wrong validation
function receiveMessage(bytes calldata data) external {
    require(msg.sender == trustedRelayer);  // Relayer can be compromised!
    _processMessage(data);
}
```

Correct pattern:
```solidity
function receiveMessage(bytes calldata data, bytes32[] calldata proof) external {
    // Verify Merkle proof against source chain state
    bytes32 messageHash = keccak256(data);
    require(
        MerkleProof.verify(proof, sourceChainRoot, messageHash),
        "Invalid proof"
    );
    
    // Verify message not already processed
    require(!processedMessages[messageHash], "Already processed");
    processedMessages[messageHash] = true;
    
    _processMessage(data);
}
```

Key checks:
- [ ] Cryptographic proof of source chain state
- [ ] Message not already processed (replay protection)
- [ ] Correct source chain ID
- [ ] Correct source contract address
```

### 2. Message Replay Attacks
```
Severity: CRITICAL
Category: reentrancy

Description:
Same message processed multiple times, minting tokens repeatedly.

Attack vectors:
- Same message on same chain (missing processed flag)
- Same message on different chain (missing chain ID)
- Same message with different nonces

Vulnerable pattern:
```solidity
function processMessage(bytes calldata data) external {
    // No replay protection!
    (address to, uint256 amount) = abi.decode(data, (address, uint256));
    token.mint(to, amount);
}
```

Correct pattern:
```solidity
mapping(bytes32 => bool) public processedMessages;

function processMessage(bytes calldata data) external {
    bytes32 messageId = keccak256(abi.encodePacked(
        sourceChainId,
        block.chainid,  // Destination chain
        messageNonce,
        data
    ));
    
    require(!processedMessages[messageId], "Already processed");
    processedMessages[messageId] = true;
    
    _execute(data);
}
```
```

### 3. Signature Verification Issues
```
Severity: CRITICAL
Category: signature

Description:
Multi-sig or validator signature verification flaws.

Common issues:
- Signature malleability
- Missing signer uniqueness check
- Threshold bypass
- Reused nonces

Vulnerable patterns:
```solidity
// VULNERABLE: Signature malleability
function verify(bytes32 hash, bytes[] calldata sigs) external {
    for (uint i = 0; i < sigs.length; i++) {
        address signer = ecrecover(hash, sigs[i]);
        require(isValidator[signer], "Invalid signer");
    }
    require(sigs.length >= threshold, "Not enough sigs");
}
// Attack: Same signature with different s value counts twice!

// VULNERABLE: No uniqueness check
function verify(bytes32 hash, bytes[] calldata sigs) external {
    uint validSigs = 0;
    for (uint i = 0; i < sigs.length; i++) {
        address signer = recoverSigner(hash, sigs[i]);
        if (isValidator[signer]) validSigs++;
    }
    require(validSigs >= threshold);
}
// Attack: Submit same valid signature multiple times!
```

Correct pattern:
```solidity
function verify(bytes32 hash, bytes[] calldata sigs) external {
    require(sigs.length >= threshold, "Not enough signatures");
    
    address lastSigner = address(0);
    for (uint i = 0; i < sigs.length; i++) {
        address signer = ECDSA.recover(hash, sigs[i]);  // Handles malleability
        
        require(signer > lastSigner, "Signers not unique/ordered");
        require(isValidator[signer], "Not a validator");
        
        lastSigner = signer;
    }
}
```
```

### 4. Deposit/Withdrawal Mismatch
```
Severity: CRITICAL
Category: accounting

Description:
Mismatch between deposited amount on source and minted amount 
on destination.

Attack vectors:
- Fee-on-transfer tokens
- Rebasing tokens
- Decimal mismatch between chains
- Rounding errors

Vulnerable pattern:
```solidity
// SOURCE CHAIN
function deposit(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    emit Deposit(token, msg.sender, amount);  // Logs requested amount
}

// DESTINATION CHAIN
function mint(address token, address to, uint256 amount) external {
    wrappedToken[token].mint(to, amount);  // Mints logged amount
}
// Attack: Use fee-on-transfer token, deposit 100, only 98 arrives,
// but 100 is minted on destination!
```

Correct pattern:
```solidity
function deposit(address token, uint256 amount) external {
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 actualAmount = IERC20(token).balanceOf(address(this)) - balanceBefore;
    
    emit Deposit(token, msg.sender, actualAmount);  // Log actual amount
}
```
```

### 5. Oracle/Relayer Manipulation
```
Severity: HIGH
Category: oracle

Description:
Compromised or malicious relayers/oracles can forge messages.

Risk factors:
- Single relayer (centralization)
- Insufficient validator set
- No fraud proofs
- Oracle manipulation

Mitigation:
- Multiple independent relayers
- Fraud proof mechanisms
- Optimistic verification with challenge period
- On-chain state verification
```

---

## Bridge-Specific Patterns

### Lock & Mint Bridges

#### Locked Token Accounting
```
Severity: HIGH
Category: accounting

Check for:
- Total locked on source >= total minted on destination
- Proper handling of token transfers
- No way to unlock without burning wrapped

Invariant:
sourceChain.lockedBalance >= destinationChain.wrappedTotalSupply
```

#### Unlock Authorization
```
Severity: CRITICAL
Category: access-control

Check for:
- Only burn proof can trigger unlock
- Proper burn verification
- No double-unlock possibility
```

### Liquidity Pool Bridges

#### Pool Imbalance Attacks
```
Severity: HIGH
Category: economic

Description:
Attacker drains pool on one side by manipulating the other.

Check for:
- Maximum single-swap limits
- Rebalancing mechanisms
- Flash loan resistance

Vulnerable pattern:
```solidity
function swap(uint256 amount) external {
    require(poolBalance >= amount);  // No per-tx limit!
    poolBalance -= amount;
    token.transfer(msg.sender, amount);
}
```
```

#### LP Token Value Manipulation
```
Severity: HIGH  
Category: oracle

Check for:
- First depositor attack (vault inflation)
- Flash loan manipulation of LP value
- Proper share calculation
```

---

## Cross-Chain Message Patterns

### 1. Asynchronous Execution
```
Severity: MEDIUM
Category: timing

Description:
Cross-chain messages are asynchronous - state may change between 
send and receive.

Check for:
- State assumptions at receive time
- Revert handling (funds stuck?)
- Timeout mechanisms

Example issue:
```solidity
// Source: User has 100 tokens, initiates bridge
// ... time passes ...
// Destination: Tries to deposit to protocol that now has different rates
// User gets less than expected, no recourse
```

Mitigation:
- Slippage protection in destination logic
- Minimum output amounts
- Refund mechanisms for failed executions
```

### 2. Message Ordering
```
Severity: MEDIUM
Category: logic

Description:
Messages may arrive out of order or some may fail.

Check for:
- Dependency on message order
- Handling of failed predecessor messages
- Nonce gaps

Example:
```solidity
// Message 1: Create position
// Message 2: Add collateral
// If Message 1 fails but Message 2 succeeds, collateral is lost
```
```

### 3. Gas Estimation
```
Severity: MEDIUM
Category: denial-of-service

Description:
Insufficient gas for destination execution causes failures.

Check for:
- Gas estimation for complex destination logic
- Handling of out-of-gas on destination
- Refund mechanisms
```

---

## Bridge Security Checklist

### Message Security
- [ ] Cryptographic proof of source message
- [ ] Replay protection (nonce/hash tracking)
- [ ] Chain ID validation (source and destination)
- [ ] Source contract address validation
- [ ] Message expiration handling

### Signature Security
- [ ] Signature malleability protection (use ECDSA library)
- [ ] Signer uniqueness verification
- [ ] Threshold enforcement
- [ ] Nonce management for signers
- [ ] Key rotation mechanism

### Token Security
- [ ] Fee-on-transfer token handling
- [ ] Rebasing token handling
- [ ] Decimal normalization across chains
- [ ] Token address mapping validation
- [ ] Wrapped token supply invariant

### Access Control
- [ ] Admin key security (multisig, timelock)
- [ ] Pause mechanism
- [ ] Upgrade controls
- [ ] Emergency withdrawal

### Economic Security
- [ ] Per-transaction limits
- [ ] Daily/periodic limits
- [ ] Flash loan resistance
- [ ] Pool balance monitoring
- [ ] Oracle manipulation resistance

### Operational Security
- [ ] Relayer redundancy
- [ ] Monitoring and alerting
- [ ] Incident response plan
- [ ] Recovery mechanisms

---

## Famous Bridge Hacks Reference

| Bridge | Loss | Root Cause |
|--------|------|------------|
| Ronin | $624M | Compromised validator keys (5/9 threshold) |
| Wormhole | $326M | Signature verification bypass |
| Nomad | $190M | Faulty message validation (any message accepted) |
| Harmony | $100M | Compromised multisig (2/5) |
| BNB Bridge | $586M | Merkle proof verification flaw |
| Multichain | $130M | Compromised MPC keys |

### Key Lessons

1. **Ronin**: 5 of 9 validators compromised â†’ Use higher thresholds, distributed validators
2. **Wormhole**: Guardian signature check bypassed â†’ Rigorous signature verification
3. **Nomad**: acceptableRoot allowed any message â†’ Never trust unverified messages
4. **Harmony**: 2 of 5 multisig â†’ Use higher M/N ratios
5. **BNB**: Proof verification bug â†’ Formal verification of proof logic

---

## AI Application Guide

When auditing bridges:

1. **Identify bridge type** (Lock/Mint, Pool, etc.)
2. **Map the message flow** from source to destination
3. **Verify message validation** - the #1 issue
4. **Check replay protection** - must be airtight
5. **Analyze signature scheme** if using validators
6. **Test token handling** for edge cases
7. **Assess centralization** in relayers/validators
8. **Review economic attacks** for pool-based bridges
9. **Check admin controls** - pausable, upgradeable?

### Priority Areas
```
1. Message validation (CRITICAL)
2. Replay protection (CRITICAL)
3. Signature verification (CRITICAL if applicable)
4. Token accounting (HIGH)
5. Access control (HIGH)
6. Economic attacks (MEDIUM-HIGH)
7. Operational security (MEDIUM)
```


---
## l2-sequencer-patterns.md
# L2 Sequencer Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 6 | 0 | 0 |

**Common Sources**: Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for l2 sequencer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Missing L2 sequencer uptime check in `OracleAdapter`

**Source**: Cyfrin
**Protocol**: Yieldfi
**Impact**: MEDIUM

**Details**:

**Description:** On L2, the `YToken` exchange rate is provided by custom Chainlink oracles. The exchange rate is queried in [`OracleAdapter::fetchExchangeRate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/OracleAdapter.sol#L52-L77):

```solidity
function fetchExchangeRate(address token) external view override returns (uint256) {
    address oracle = oracles[token];
    require(oracle != address(0), "Oracle not set");

    (, /* uint80 roundId */ int256 answer, , /* uint256 startedAt */ uint256 updatedAt /* uint80 answeredInRound */, ) = IOracle(oracle).latestRoundData();

    require(answer > 0, "Invalid price");
    require(updatedAt > 0, "Round not complete");
    require(block.timestamp - updatedAt < staleThreshold, "Stale price");

    // Get decimals and normalize to 1e18 (PINT)
    uint8 decimals = IOracle(oracle).decimals();

    if (decimals < 18) {
        return uint256(answer) * (10 ** (18 - decimals));
    } else if (decimals > 18) {
        return uint256(answer) / (10 ** (decimals - 18));
    } else {
        return uint256(answer);
    }
}
```

However, this protocol is intended to be deployed on L2 networks such as Arbitrum and Optimism, where it's important to verify that the [sequencer is up](https://docs.chain.link/data-feeds/l2-sequencer-feeds). Without this check, if the sequencer goes down, the latest round data may appear fresh, when in fact it is stale, for advanced users submitting transactions

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### Example 2: M-4: No check for active Arbitrum Sequencer in WSTETH Oracle

**Source**: Sherlock
**Protocol**: Sentiment Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sentiment-judging/issues/3 

## Found by 
pashov, obront

## Summary

Chainlink recommends that all Optimistic L2 oracles consult the Sequencer Uptime Feed to ensure that the sequencer is live before trusting the data returned by the oracle. This check is implemented in ArbiChainlinkOracle.sol, but is skipped in WSTETHOracle.sol.

## Vulnerability Detail

If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 optimistic rollup contract. You can review Chainlink docs on [L2 Sequencer Uptime Feeds](https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds/) for more details on this.

As a result, users may be able to use the protocol while oracle feeds are stale. This could cause many problems, but as a simple example:
- A user has an account with 100 tokens, valued at 1 ETH each, and no borrows
- The Arbitrum sequencer goes down temporarily
- While it's down, the price of the token falls to 0.5 ETH each
- The current value of the user's account is 50 ETH, so they should be able to borrow a maximum of 200 ETH to keep account healthy (`(200 + 50) / 200 = 1.2`)
- Because of the stale price, the protocol lets them borrow 400 ETH (`(400 + 100) / 400 = 1.2`)

## Impact

If the Arbitrum sequencer goes down, the protocol will allow users to continue to operate at the previous (stale) rates.

## 

*[Content truncated...]*

---

### Example 3: M-3: _validateAndGetPrice() doesn't check If Arbitrum sequencer is down in Chainlink feeds

**Source**: Sherlock
**Protocol**: Bond Protocol Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-bond-judging/issues/1 

## Found by 
Avci

## Summary
When utilizing Chainlink in L2 chains like Arbitrum, it's important to ensure that the prices provided are not falsely perceived as fresh, even when the sequencer is down. This vulnerability could potentially be exploited by malicious actors to gain an unfair advantage.

## Vulnerability Detail
There is no check: 
```soldity
solidity function _validateAndGetPrice(AggregatorV2V3Interface feed_, uint48 updateThreshold_)
        internal
        view
        returns (uint256)
    {
        // Get latest round data from feed
        (uint80 roundId, int256 priceInt, , uint256 updatedAt, uint80 answeredInRound) = feed_
            .latestRoundData();
        // @audit check if Arbitrum L2 sequencer is down in Chainlink feeds: medium
        // Validate chainlink price feed data
        // 1. Answer should be greater than zero
        // 2. Updated at timestamp should be within the update threshold
        // 3. Answered in round ID should be the same as the round ID
        if (
            priceInt <= 0 ||
            updatedAt < block.timestamp - uint256(updateThreshold_) ||
            answeredInRound != roundId
        ) revert BondOracle_BadFeed(address(feed_));
        return uint256(priceInt);
    }
```
## Impact
could potentially be exploited by malicious actors to gain an unfair advantage.
## Code Snippet
https://github.com/sherlock-audit/2023-02-bond-0xdanial/blob/0d6f

*[Content truncated...]*

---

### Example 4: M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/82 

## Found by 
ctf\_sec, qandisa
## Summary

Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

## Vulnerability Detail

In the current implementation, if the option token expires, the user is not able to [exerise the option at strike price](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L336)

```solidity
    // Validate that option token is not expired
        if (uint48(block.timestamp) >= expiry) revert Teller_OptionExpired(expiry);
```

if the option token expires, the user lose rewards from OTLM as well when [claim the reward](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/liquidity-mining/OTLM.sol#L496)

```solidity
    function _claimRewards() internal returns (uint256) {
        // Claims all outstanding rewards for the user across epochs
        // If there are unclaimed rewards from epochs where the option token has expired, the rewards are lost

        // Get the last epoch claimed by the user
        uint48 userLastEpoch = lastEpochClaimed[msg.sender];

```

and

```solidity
    // If the option token has expired, then the rewards are zero
        if (uint256(optionToken.expiry()) < block.timestamp) return 0;
```

And in the onchain context, the protocol intends to deploy the contract in arbitr

*[Content truncated...]*

---

### Example 5: M-3: No check for sequencer uptime can lead to dutch auctions executing at bad prices

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/40 

## Found by 
0x52
## Summary

When purchasing from dutch auctions on L2s there is no considering of sequencer uptime. When the sequencer is down, all transactions must originate from the L1. The issue with this is that these transactions use an aliased address. Since the set token contracts don't implement any way for these aliased addressed to interact with the protocol, no transactions can be processed during this time even with force L1 inclusion. If the sequencer goes offline during the the auction period then the auction will continue to decrease in price while the sequencer is offline. Once the sequencer comes back online, users will be able to buy tokens from these auctions at prices much lower than market price.

## Vulnerability Detail

See summary.

## Impact

Auction will sell/buy assets at prices much lower/higher than market price leading to large losses for the set token

## Code Snippet

[AuctionRebalanceModuleV1.sol#L772-L836](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L772-L836)

## Tool used

Manual Review

## Recommendation

Check sequencer uptime and invalidate the auction if the sequencer was ever down during the auction period



## Discussion

**pblivin0x**

What exactly is the remediation here? To check an external uptime feed https://docs.chain.link/data-feeds/l2-sequencer-feeds ?

Not sur

*[Content truncated...]*

---

### Example 6: M-13: Missing checks for whether Arbitrum Sequencer is active

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/142 

## Found by 
0xepley, Bauchibred, Bauer, Brenzee, J4de, ctf\_sec, deadrxsezzz, tallo, tsvetanovv
## Summary

Missing checks for whether Arbitrum Sequencer is active

## Vulnerability Detail

the onchain deployment context is changed, in prev contest the protocol only attemps to deploy the code to ethereum while in the current contest

the protocol intends to deploy to arbtrium as well!

Chainlink recommends that users using price oracles, check whether the Arbitrum sequencer is active

https://docs.chain.link/data-feeds#l2-sequencer-uptime-feeds

If the sequencer goes down, the index oracles may have stale prices, since L2-submitted transactions (i.e. by the aggregating oracles) will not be processed.

## Impact

Stale prices, e.g. if USDC were to de-peg while the sequencer is offline, stale price is used and can result in false liquidation or over-borrowing.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L76-L98

## Tool used

Manual Review

## Recommendation

Use sequencer oracle to determine whether the sequencer is offline or not, and don't allow orders to be executed while the sequencer is offline.

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## l2-security.md
# L2 Security Patterns - AI Reference

> **For AI Assistants:** Layer 2 networks have unique vulnerabilities. Apply these patterns when auditing L2 deployments.

---

## Overview

| L2 Network | Type | Key Concerns |
|------------|------|--------------|
| Arbitrum | Optimistic Rollup | Sequencer, delayed inbox, retryable tickets |
| Optimism | Optimistic Rollup | Cross-domain messaging, gas price oracle |
| zkSync | ZK Rollup | Account abstraction, bytecode differences |
| Base | Optimistic Rollup | Similar to Optimism (OP Stack) |
| Polygon zkEVM | ZK Rollup | EVM equivalence gaps |
| StarkNet | Validity Rollup | Cairo language, different model |
| Scroll | ZK Rollup | EVM compatibility |

---

## Universal L2 Vulnerabilities

### 1. Sequencer Dependence
```
Severity: MEDIUM-HIGH
Category: centralization

Description:
L2s rely on sequencers to order transactions. Sequencer downtime 
or malicious behavior can affect protocol operation.

Check for:
- Does protocol assume continuous sequencer operation?
- Is there a fallback for sequencer downtime?
- Can sequencer censor specific transactions?

Vulnerable pattern:
```solidity
// Protocol relies on timely execution
function auction() external {
    require(block.timestamp < deadline);  // Sequencer can delay
}
```

Mitigation:
- Allow for sequencer downtime in time-sensitive logic
- Implement forced inclusion via L1 (where available)
- Add grace periods for time-sensitive operations
```

### 2. L1 to L2 Message Replay
```
Severity: HIGH
Category: cross-chain

Description:
Messages from L1 to L2 may be replayed if not properly validated.

Check for:
- Unique message identifiers
- Nonce tracking for cross-layer messages
- Proper sender validation

Vulnerable pattern:
```solidity
function receiveMessage(bytes calldata data) external {
    // No replay protection!
    _processMessage(data);
}
```

Mitigation:
- Use message nonces
- Track processed message hashes
- Validate message origin chain
```

### 3. Block.number Differences
```
Severity: MEDIUM
Category: logic

Description:
block.number on L2 may not match L1 and behaves differently.
Some L2s have faster block times, others have L1 block number.

Check for:
- Logic assuming specific block times
- Block-based randomness
- Block-based locks/delays

Vulnerable pattern:
```solidity
// Assumes ~12s blocks like L1
uint256 public constant BLOCKS_PER_DAY = 7200;

function canWithdraw() external view returns (bool) {
    return block.number > depositBlock + BLOCKS_PER_DAY;
}
```

Mitigation:
- Use block.timestamp instead of block.number for time
- Query actual block time if needed
- Document block time assumptions
```

### 4. Gas Price Oracle Manipulation
```
Severity: MEDIUM
Category: oracle

Description:
L2 gas prices can vary significantly and may be manipulable.

Check for:
- Reliance on tx.gasprice for logic
- Gas price assumptions for MEV protection
- Refund calculations based on gas price

Vulnerable pattern:
```solidity
function submit() external {
    require(tx.gasprice <= maxGasPrice);  // L2 gas is different
}
```
```

---

## Arbitrum-Specific Patterns

### 1. ArbSys Precompile
```
Severity: INFO
Category: l2-specific

Description:
Arbitrum has ArbSys precompile at 0x64 for L2-specific operations.

Key functions:
- arbBlockNumber(): L2 block number
- arbBlockHash(): L2 block hash
- sendTxToL1(): Send message to L1
- wasMyCallersAddressAliased(): Check address aliasing

Check for:
- Using block.number when arbBlockNumber is needed
- Proper use of address aliasing
```

### 2. Address Aliasing
```
Severity: HIGH
Category: access-control

Description:
When L1 contracts call L2, the address is "aliased" by adding 
0x1111000000000000000000000000000000001111.

Check for:
- L1->L2 calls expecting msg.sender to be L1 contract address
- Access control based on L1 sender

Vulnerable pattern:
```solidity
// On L2
function executeFromL1() external {
    // msg.sender is ALIASED, not the actual L1 address!
    require(msg.sender == l1Contract);  // WRONG
}
```

Mitigation:
```solidity
function undoL1ToL2Alias(address l2Address) internal pure returns (address l1Address) {
    uint160 offset = uint160(0x1111000000000000000000000000000000001111);
    l1Address = address(uint160(l2Address) - offset);
}
```
```

### 3. Retryable Tickets
```
Severity: MEDIUM
Category: cross-chain

Description:
Arbitrum retryable tickets can be auto-redeemed or manually redeemed.
Failed auto-redemption needs manual retry or ticket expires.

Check for:
- Assumption that L1->L2 messages always succeed
- Handling of failed retryable tickets
- Ticket expiration (7 days default)

Mitigation:
- Handle failed ticket scenarios
- Provide mechanism to retry failed tickets
- Monitor ticket status
```

### 4. Delayed Inbox
```
Severity: MEDIUM
Category: timing

Description:
Users can force-include transactions via L1 delayed inbox,
bypassing sequencer (after ~24h delay).

Check for:
- Assumption that sequencer ordering is final
- Time-sensitive operations that could be bypassed

Security consideration:
- Malicious sequencer can be bypassed
- ~24h delay for force inclusion
```

---

## Optimism / Base (OP Stack) Patterns

### 1. Cross Domain Messenger
```
Severity: HIGH
Category: cross-chain

Description:
CrossDomainMessenger is the official way to send L1<->L2 messages.

Check for:
- Proper use of CrossDomainMessenger
- Validation of xDomainMessageSender()
- Handling of failed messages

Vulnerable pattern:
```solidity
function receiveFromL1(uint256 amount) external {
    // Anyone can call!
    _mint(msg.sender, amount);
}
```

Correct pattern:
```solidity
function receiveFromL1(uint256 amount) external {
    require(
        msg.sender == address(crossDomainMessenger),
        "Not messenger"
    );
    require(
        crossDomainMessenger.xDomainMessageSender() == l1Bridge,
        "Wrong sender"
    );
    _mint(address(this), amount);
}
```
```

### 2. L1Block Predeploy
```
Severity: INFO
Category: l2-specific

Description:
Optimism has L1Block predeploy at 0x4200000000000000000000000000000000000015
providing L1 block info.

Available data:
- number: L1 block number
- timestamp: L1 block timestamp
- basefee: L1 base fee
- hash: L1 block hash
- sequenceNumber: L2 sequence number

Check for:
- Confusion between L1 and L2 block numbers
- Using wrong block reference for timing
```

### 3. Gas Price Oracle
```
Severity: MEDIUM
Category: oracle

Description:
OP Stack has gas price oracle at 0x420000000000000000000000000000000000000F.

Check for:
- Reliance on L2 gas price for security
- L1 data fee calculations

Note:
- L2 execution gas is separate from L1 data gas
- Total fee = L2 execution + L1 data fee
```

### 4. Deposit Transactions
```
Severity: MEDIUM
Category: cross-chain

Description:
Deposits from L1 to L2 are guaranteed to execute (different from Arbitrum).

Check for:
- L1 deposit failures (reverts) lose funds
- msg.value handling in deposit receivers

Mitigation:
- Test deposit receivers thoroughly
- Handle all edge cases in receiver
```

---

## zkSync-Specific Patterns

### 1. Native Account Abstraction
```
Severity: MEDIUM
Category: account-abstraction

Description:
zkSync has native account abstraction. EOAs work differently.

Check for:
- Assumptions about msg.sender being EOA
- ecrecover usage (works but different internally)
- Paymaster interactions

Considerations:
- Accounts can have custom validation logic
- Paymasters can pay for user gas
```

### 2. Bytecode Differences
```
Severity: HIGH
Category: l2-specific

Description:
zkSync compiles to zkEVM bytecode which has differences.

Check for:
- contract.code.length may differ
- extcodesize behavior
- CREATE2 address calculation is different

Vulnerable pattern:
```solidity
function isContract(address account) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(account) }
    return size > 0;  // May not work as expected on zkSync
}
```
```

### 3. System Contracts
```
Severity: INFO
Category: l2-specific

Description:
zkSync has system contracts for L2 functionality.

Key contracts:
- ContractDeployer: Deploy contracts
- NonceHolder: Nonce management
- L1Messenger: L1 communication
- MsgValueSimulator: Handle msg.value

Check for:
- Direct interaction with system contracts
- Assumptions about standard EVM behavior
```

### 4. L1->L2 Priority Queue
```
Severity: MEDIUM
Category: cross-chain

Description:
L1->L2 transactions go through priority queue with processing delay.

Check for:
- Timing assumptions for L1 deposits
- Handling of queued transactions
- Order of priority vs regular transactions
```

---

## Polygon zkEVM Patterns

### 1. EVM Equivalence Gaps
```
Severity: MEDIUM
Category: l2-specific

Description:
Polygon zkEVM aims for EVM equivalence but has some gaps.

Check for:
- Unsupported opcodes (check docs)
- Gas cost differences
- Precompile differences
```

### 2. Bridge Security
```
Severity: HIGH
Category: cross-chain

Description:
Polygon zkEVM uses ZK proofs for bridge security.

Check for:
- Proper use of bridge contracts
- Message validation on destination
- Handling of bridge delays
```

---

## Cross-L2 Considerations

### 1. Chain ID Validation
```
Severity: HIGH
Category: signature

Description:
When contracts deploy across multiple L2s, ensure chain ID validation.

Check for:
- Signatures include chain ID (EIP-712)
- Replay protection across chains
- Contract addresses may differ across L2s

Vulnerable pattern:
```solidity
function executeWithSig(bytes calldata sig, bytes calldata data) external {
    address signer = recover(keccak256(data), sig);  // No chain ID!
}
```
```

### 2. Bridge Token Standards
```
Severity: MEDIUM
Category: composability

Description:
Different L2s have different canonical bridge token implementations.

Check for:
- Token address differences across L2s
- Bridge token vs native token differences
- Wrapped token behaviors
```

### 3. Finality Differences
```
Severity: MEDIUM
Category: timing

Description:
Different L2s have different finality guarantees.

| L2 | Soft Finality | Hard Finality |
|----|---------------|---------------|
| Arbitrum | ~1 min | ~7 days (challenge) |
| Optimism | ~1 min | ~7 days (challenge) |
| zkSync | ~1 min | ~1 hour (proof) |
| Polygon zkEVM | ~1 min | ~30 min (proof) |

Check for:
- Assumptions about finality in cross-chain logic
- Withdrawal delay handling
```

---

## L2 Audit Checklist

### General
- [ ] Check block.number assumptions
- [ ] Verify block.timestamp behavior
- [ ] Review gas price/cost assumptions
- [ ] Test sequencer downtime scenarios
- [ ] Verify chain ID in signatures

### Cross-Chain
- [ ] Validate message sender properly
- [ ] Handle message replay protection
- [ ] Consider message failure scenarios
- [ ] Verify address aliasing (Arbitrum)
- [ ] Test bridge deposit/withdrawal flows

### Network-Specific
- [ ] Check for unsupported opcodes
- [ ] Verify precompile availability
- [ ] Test account abstraction interactions (zkSync)
- [ ] Review system contract usage
- [ ] Verify CREATE2 address calculations
```

---

## AI Application Guide

When auditing L2 contracts:

1. **Identify the target L2** from chain ID or deployment context
2. **Apply universal L2 patterns** first
3. **Apply network-specific patterns** for the target L2
4. **Check cross-chain messaging** if protocol bridges
5. **Verify assumptions** about block times, gas, finality
6. **Test edge cases** for sequencer downtime/failures


---
## arbitrum-patterns.md
# Arbitrum Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 1 | 0 |

**Common Sources**: Sherlock, Quantstamp, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for arbitrum vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Underpaying Optimism l2gas may lead to loss of funds

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity: Medium Risk

### Context
- **File:** OptimismBridgeFacet.sol
- **Lines:** 97-113

### Description
The `OptimismBridgeFacet` uses Optimismâ€™s bridge with user-provided `l2Gas`.

```solidity
function _startBridge(
    LiFiData calldata _lifiData,
    BridgeData calldata _bridgeData,
    uint256 _amount,
    bool _hasSourceSwap
) private {
    ...
    if (LibAsset.isNativeAsset(_bridgeData.assetId)) {
        bridge.depositETHTo{ value: _amount }(_bridgeData.receiver, _bridgeData.l2Gas, "");
    } else {
        ...
        bridge.depositERC20To(
            _bridgeData.assetId,
            _bridgeData.assetIdOnL2,
            _bridgeData.receiver,
            _amount,
            _bridgeData.l2Gas,
            ""
        );
    }
}
```

Optimismâ€™s standard token bridge makes the cross-chain deposit by sending a cross-chain message to `L2Bridge`.

- **File:** L1StandardBridge.sol
- **Lines:** 114-123

```solidity
// Construct calldata for finalizeDeposit call
bytes memory message = abi.encodeWithSelector(
    IL2ERC20Bridge.finalizeDeposit.selector,
    address(0),
    Lib_PredeployAddresses.OVM_ETH,
    _from,
    _to,
    msg.value,
    _data
);

// Send calldata into L2
// slither-disable-next-line reentrancy-events
sendCrossDomainMessage(l2TokenBridge, _l2Gas, message);
```

If the `l2Gas` is underpaid, `finalizeDeposit` will fail and user funds will be lost.

### Recommendation
Given the potential risks of losing usersâ€™ funds, it is recommend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: M-4: No check for active Arbitrum Sequencer in WSTETH Oracle

**Source**: Sherlock
**Protocol**: Sentiment Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sentiment-judging/issues/3 

## Found by 
pashov, obront

## Summary

Chainlink recommends that all Optimistic L2 oracles consult the Sequencer Uptime Feed to ensure that the sequencer is live before trusting the data returned by the oracle. This check is implemented in ArbiChainlinkOracle.sol, but is skipped in WSTETHOracle.sol.

## Vulnerability Detail

If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 optimistic rollup contract. You can review Chainlink docs on [L2 Sequencer Uptime Feeds](https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds/) for more details on this.

As a result, users may be able to use the protocol while oracle feeds are stale. This could cause many problems, but as a simple example:
- A user has an account with 100 tokens, valued at 1 ETH each, and no borrows
- The Arbitrum sequencer goes down temporarily
- While it's down, the price of the token falls to 0.5 ETH each
- The current value of the user's account is 50 ETH, so they should be able to borrow a maximum of 200 ETH to keep account healthy (`(200 + 50) / 200 = 1.2`)
- Because of the stale price, the protocol lets them borrow 400 ETH (`(400 + 100) / 400 = 1.2`)

## Impact

If the Arbitrum sequencer goes down, the protocol will allow users to continue to operate at the previous (stale) rates.

## 

*[Content truncated...]*

---

### Example 3: [M-19] `CLOCK_MODE()` will not work properly for Arbitrum or Optimism due to `block.number`

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

### Example 4: M-13: Missing checks for whether Arbitrum Sequencer is active

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/142 

## Found by 
0xepley, Bauchibred, Bauer, Brenzee, J4de, ctf\_sec, deadrxsezzz, tallo, tsvetanovv
## Summary

Missing checks for whether Arbitrum Sequencer is active

## Vulnerability Detail

the onchain deployment context is changed, in prev contest the protocol only attemps to deploy the code to ethereum while in the current contest

the protocol intends to deploy to arbtrium as well!

Chainlink recommends that users using price oracles, check whether the Arbitrum sequencer is active

https://docs.chain.link/data-feeds#l2-sequencer-uptime-feeds

If the sequencer goes down, the index oracles may have stale prices, since L2-submitted transactions (i.e. by the aggregating oracles) will not be processed.

## Impact

Stale prices, e.g. if USDC were to de-peg while the sequencer is offline, stale price is used and can result in false liquidation or over-borrowing.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L76-L98

## Tool used

Manual Review

## Recommendation

Use sequencer oracle to determine whether the sequencer is offline or not, and don't allow orders to be executed while the sequencer is offline.

---

### Example 5: Mismatched `msg_value` Validation and Refund Logic in `op::create_master` Causes Underfunded Transactions

**Source**: Quantstamp
**Protocol**: XDAO
**Impact**: LOW

**Details**:

**Update**
The team fixed the issue as recommended. Addressed in: `3be95dd540da57f9f2a1e20dd8f514e6158e9029`.

**File(s) affected:**`contracts/factory.fc`

**Description:** In the `factory`â€™s `op::create_master`, the initial check requires `msg_value > service_fee + BASE_FEE * (6 + mint_messages_count)`, but the refund calculation deducts `service_fee + BASE_FEE * (8 + mint_messages_count)`. This discrepancy allows transactions that pass validation to fail later or refund less than expected, leading to user confusion and potential loss of funds.

**Exploit Scenario:**

1.   A user provides `msg_value` that meets the `(6 + mint_messages_count)` requirement but falls short of `(8 + mint_messages_count)`.
2.   Deployment proceeds past the initial check but later attempts to refund, leading to a revert or incorrect refund amount.
3.   The deployment unexpectedly fails or the user loses more TON than anticipated.

**Recommendation:** Align the validation threshold with the actual outgoing costs by updating the check to account for all `BASE_FEE` deductions (including minting flow and message sends). For example, require `msg_value > service_fee + BASE_FEE * (8 + mint_messages_count)`.

**Reference**: [View Original Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## optimism-patterns.md
# Optimism Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for optimism vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Permitting Multiple Drip Calls Per Block

**Source**: Spearbit
**Protocol**: Optimism Drippie
**Impact**: MEDIUM

**Details**:

## Risk Assessment

**Severity:** Medium Risk  
**Context:** Drippie.sol#L266  

## Description
The inline comments correctly note that reentrancy is possible and permitted when `state.config.interval` is 0. We are currently unaware of use cases where this is desirable. Reentrancy is one risk, and flashbot bundles are a similar risk where the drip may be called multiple times by the same actor in a single block. A malicious actor may abuse this ability, especially if the interval is misconfigured as 0 due to JavaScript type coercion.

A reentrant call or flashbot bundle may be used to frontrun an owner attempting to archive a drip or withdraw assets.

## Recommendation
We recommend limiting drip calls to 1 per block. Document the transaction order dependence (frontrunning) risk for owners wishing to archive a drip. Reasonable drip intervals can be employed to prevent this attack.

If it is important to permit multiple calls to the same drip in a single block, we recommend making the behavior opt-in rather than default if no `state.config.interval` is specified.

```solidity
+function create(string memory _name, DripConfig memory _config, bool allowMultiplePerBlock) external
onlyOwner { , !
-function create(string memory _name, DripConfig memory _config) external onlyOwner {
    // Make sure this drip doesn 't already exist. We *must* guarantee that no other function
    // will ever set the status of a drip back to NONE after it 's been created. This is why
    // archival is

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/OptimismDrippie-Spearbit-Security-Review.pdf)

---

### Example 2: Underpaying Optimism l2gas may lead to loss of funds

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity: Medium Risk

### Context
- **File:** OptimismBridgeFacet.sol
- **Lines:** 97-113

### Description
The `OptimismBridgeFacet` uses Optimismâ€™s bridge with user-provided `l2Gas`.

```solidity
function _startBridge(
    LiFiData calldata _lifiData,
    BridgeData calldata _bridgeData,
    uint256 _amount,
    bool _hasSourceSwap
) private {
    ...
    if (LibAsset.isNativeAsset(_bridgeData.assetId)) {
        bridge.depositETHTo{ value: _amount }(_bridgeData.receiver, _bridgeData.l2Gas, "");
    } else {
        ...
        bridge.depositERC20To(
            _bridgeData.assetId,
            _bridgeData.assetIdOnL2,
            _bridgeData.receiver,
            _amount,
            _bridgeData.l2Gas,
            ""
        );
    }
}
```

Optimismâ€™s standard token bridge makes the cross-chain deposit by sending a cross-chain message to `L2Bridge`.

- **File:** L1StandardBridge.sol
- **Lines:** 114-123

```solidity
// Construct calldata for finalizeDeposit call
bytes memory message = abi.encodeWithSelector(
    IL2ERC20Bridge.finalizeDeposit.selector,
    address(0),
    Lib_PredeployAddresses.OVM_ETH,
    _from,
    _to,
    msg.value,
    _data
);

// Send calldata into L2
// slither-disable-next-line reentrancy-events
sendCrossDomainMessage(l2TokenBridge, _l2Gas, message);
```

If the `l2Gas` is underpaid, `finalizeDeposit` will fail and user funds will be lost.

### Recommendation
Given the potential risks of losing usersâ€™ funds, it is recommend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 3: M-13: Withdrawal transactions can get stuck if output root is reproposed

**Source**: Sherlock
**Protocol**: Optimism
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-optimism-judging/issues/53 

## Found by 
Allarious, Barichek, HE1M, cmichel, unforgiven

## Summary
Withdrawal transactions may never be executed if the L2 output root for the block, for which the withdrawal was proven, is challenged and reproposed.

## Vulnerability Detail

Withdrawal transactions can be reproven in the case that the output root for their previously proven output index has been updated.
This can happen if the L2 output root was removed by the challenger.
However, to circumvent malicious users from reproving messages all the time and resetting the withdrawal countdown, reproving can only be done on the same L2 block number (and if the output root changed).

If the challenger deletes the block with the withdrawal transaction and the proposer proposes a different block that does _not_ have the withdrawal transaction, the withdrawal transaction can never be finalized - even if a future block includes the legitimate withdrawal transaction again, as reproving it is bound to the old `provenWithdrawals[withdrawalHash].l2OutputIndex`.

## Impact
Legitimate withdrawal transactions will never be finalized if the proposed block was challenged and replaced with a different one not having the withdrawal transaction. As this call fails on the "lowest level", the `OptimismPortal`, these transactions also cannot be replayed or be issued refunds. In case the withdrawal transaction was a token bridge transfer,

*[Content truncated...]*

**Reference**: [View Original Finding](https://app.sherlock.xyz/audits/contests/38)

---

### Example 4: [M-19] `CLOCK_MODE()` will not work properly for Arbitrum or Optimism due to `block.number`

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

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## layerzero-patterns.md
# LayerZero Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Trust Security, Code4rena, SigmaPrime

---

## Detection Checklist

- [ ] Check for layerzero vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03]  LayerZeroModule miscalculates gas, risking loss of assets

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

### Example 2: H-6: All ETH can be stolen during rebalancing for `mTOFTs` that hold native

**Source**: Sherlock
**Protocol**: Tapioca
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-02-tapioca-judging/issues/69 

## Found by 
0xadrii, GiuseppeDeLaZara
## Summary
Rebalancing of ETH transfers the ETH to the destination mTOFT without calling `sgRecieve` which leaves the ETH hanging inside the `mTOFT` contract. 
This can be exploited to steal all the ETH.

## Vulnerability Detail
Rebalancing of `mTOFTs` that hold native tokens is done through the `routerETH` contract inside the `Balancer.sol` contract. 
Here is the code snippet for the `routerETH` contract:

```solidity
## Balancer.sol

if (address(this).balance < _amount) revert ExceedsBalance();
        uint256 valueAmount = msg.value + _amount;
        routerETH.swapETH{value: valueAmount}(
            _dstChainId,
            payable(this),
            abi.encodePacked(connectedOFTs[_oft][_dstChainId].dstOft),
            _amount,
            _computeMinAmount(_amount, _slippage)
        );
```

The expected behaviour is ETH being received on the destination chain whereby `sgReceive` is called and ETH is deposited inside the `TOFTVault`.

```solidity
## mTOFT.sol

    function sgReceive(uint16, bytes memory, uint256, address, uint256 amountLD, bytes memory) external payable {
        if (msg.sender != _stargateRouter) revert mTOFT_NotAuthorized();

        if (erc20 == address(0)) {
            vault.depositNative{value: amountLD}();
        } else {
            IERC20(erc20).safeTransfer(address(vault), amountLD);
        }
    }
```

By taking a closer loo

*[Content truncated...]*

---

### Example 3: H-2: Malicious user can use an excessively large _toAddress in OFTCore#sendFrom to break layerZero communication

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

### Example 4: TRST-H-3 All LayerZero requests will fail, making the contracts are unfunctional

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: HIGH

**Details**:

**Description:**
When sending messages using the LayerZero architecture, native tokens must be supplied to 
cover the cost of delivering the message at the receiving chain. However, none of the Mozaic 
contracts account for it. The controller calls the bridge's `requestSnapshot()`, `requestSettle()`, 
`requestExecute()` without passing value. Vault calls `reportSnapshot()`, `reportSettle()` similarly. 
StargatePlugin calls the StargateRouter's swap() which also requires value. As a result, the 
contracts are completely unfunctional.

**Recommended Mitigation:**
Pass value in each of the functions above. Perform more meticulous testing with LayerZero 
endpoints. Contracts should support receiving base tokens with the `receive()` fallback, to pay 
for fees.

**Team response:**
Fixed

**Mitigation Review:**
The Controller and Vault now pass appropriate value in native tokens for messaging. The 
contracts can be topped-up with the `receive()` method.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 5: [H-06] Attacker can block LayerZero channel

**Source**: Code4rena
**Protocol**: Velodrome Finance
**Impact**: HIGH

**Details**:

_Submitted by Ruhum_

According to the LayerZero docs, the default behavior is that when a transaction on the destination application fails, the channel between the src and dst app is blocked. Before any new transactions can be executed, the failed transaction has to be retried until it succeeds.

See <https://layerzero.gitbook.io/docs/faq/messaging-properties#message-ordering> & <https://layerzero.gitbook.io/docs/guides/advanced/nonblockinglzapp>

So an attacker is able to initiate a transaction they know will fail to block the channel between FTM and Optimism. The RedemptionSender & Receiver won't be usable anymore.

### Proof of Concept

The RedemptionReceiver contract doesn't implement the non-blocking approach as seen here:<br>
<https://github.com/code-423n4/2022-05-velodrome/blob/main/contracts/contracts/redeem/RedemptionReceiver.sol#L72-L105>

An example implementation of the non-blocking approach by LayerZero:<br>
<https://github.com/LayerZero-Labs/solidity-examples/blob/main/contracts/lzApp/NonblockingLzApp.sol>

### Recommended Mitigation Steps

Use the non-blocking approach as described [here](https://layerzero.gitbook.io/docs/guides/advanced/nonblockinglzapp).

**[pooltypes (Velodrome) disagreed with severity](https://github.com/code-423n4/2022-05-velodrome-findings/issues/83)**

**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-05-velodrome-findings/issues/83#issuecomment-1169373375):**
 > @pooltypes Can anyone send a message or would

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-velodrome)

---

### Example 6: TRST-M-11 No slippage protection for cross-chain swaps in StargatePlugin

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
The StargatePlugin calls StargateRouter's swap() function to do a cross-chain swap.
```solidity 
            // Swaps
            IStargateRouter(_router).swap(_dstChainId, _srcPoolId, _dstPoolId, 
                  payable(address(this)), _amountLD, 0, IStargateRouter.lzTxObj(0, 0, "0x"), abi.encodePacked(_to), bytes(""));
``` 
It will pass 0 as the minimum amount of tokens to receive. This pattern is vulnerable to 
sandwich attacks, where the fee or conversion rate is pumped to make the user receive hardly 
any tokens. In Layer Zero, the equilibrium fee can be manipulated to force such losses.

**Recommended mitigation:**
Calculate accepted slippage off-chain, and pass it to the `_swapRemote()` function for 
validation.

**Team response:**
Fixed.

**Mitigation review:**
Affected function has been removed

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 7: Check on Stargate Router Address Could Revert

**Source**: SigmaPrime
**Protocol**: Sushi
**Impact**: MEDIUM

**Details**:

## Description

The development team pointed out that, if the call by Stargate to `sgReceive()` were to revert, the tokens transferred from Stargate would be left in the SushiXSwap contract on the destination chain, where they could be transferred away freely by any user.

One possible condition under which this transaction could revert is if the Stargate router is redeployed, perhaps as part of an upgrade. The `require` on line [80] would then cause the transaction to revert, resulting in a loss of funds. It is difficult to estimate the likelihood of this issue as it is outside the scope of this review to investigate Stargateâ€™s likelihood of redeploying their router. However, whatever their stated policy, there could still be a redeployment and so a risk remains that could result in a loss of user funds.

## Recommendations

One possible solution is to remove the `require` on line [80]. This is discussed in more detail in SXS-13. Alternatively, monitor Stargate carefully for any chance that any of their router addresses could change and redeploy this contract if that occurs.

**Reference**: [View Original Finding](https://github.com/sigp/public-audits/blob/master/sushi/sushi-swap-stable-pool/review.pdf)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## 51-attack-patterns.md
# 51% Attack Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 1 | 0 |

**Common Sources**: Code4rena, MixBytes

---

## Detection Checklist

- [ ] Check for 51% attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] The 51% majority can hijack the party's precious tokens through an arbitrary call proposal if the `AddPartyCardsAuthority` contract is added as an authority in the party.

**Source**: Code4rena
**Protocol**: Party Protocol
**Impact**: HIGH

**Details**:

### Pre-requisite knowledge & an overview of the features in question

1. **The [**`AddPartyCardsAuthority`**](https://github.com/code-423n4/2023-10-party/blob/main/contracts/authorities/AddPartyCardsAuthority.sol) contract:** The `AddPartyCardsAuthority` contract is a contract designed to be integrated into a Party and it has only one purpose - to mint new party governance NFT tokens for party members.
    - The party has to add this contract as an authority before it can start minting new party governance NFT tokens for users.
    - The `AddPartyCardsAuthority` contract is deployed on the mainnet on address `0xC534bb3640A66fAF5EAE8699FeCE511e1c331cAD`

2. **The 51% Majority attack:** The PartyDAO team has put a lot of safeguards on a type of proposal called `ArbitraryCallsProposal` to prevent the 51% majority of the party to steal the precious NFT tokens of the party through this type of proposal. For a precious NFT token to be transferred out of the party to any other entity through this proposal, the proposal needs to be unanimously voted (100% of party members have voted on that proposal).

### Overview of the vulnerability

There is no check on the [`ArbitraryCallsProposal`](https://github.com/code-423n4/2023-10-party/blob/main/contracts/proposals/ArbitraryCallsProposal.sol) contract that prevents the calling of the [`AddPartyCardsAuthority`](https://github.com/code-423n4/2023-10-party/blob/main/contracts/authorities/AddPartyCardsAuthority.sol) contract. This allows the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-party)

---

### Example 2: [H-06]  A majority attack can steal precious NFT from the party by crafting and chaining two proposals

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Trust, also found by ladboy233 and Lambda_

<https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/proposals/ProposalExecutionEngine.sol#L116>

<https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/proposals/FractionalizeProposal.sol#L54-L62>

### Description

The PartyGovernance system has many defenses in place to protect against a majority holder stealing the NFT. Majority cannot exfiltrate the ETH gained from selling precious NFT via any proposal, and it's impossible to sell NFT for any asset except ETH. If the party were to be compensated via an ERC20 token, majority could pass an ArbitraryCallsProposal to transfer these tokens to an attacker wallet. Unfortunately, FractionalizeProposal is vulnerable to this attack. Attackers could pass two proposals and wait for them to be ready for execution. Firstly, a FractionalizeProposal to fractionalize the NFT and mint totalVotingPower amount of ERC20 tokens of the created vault. Secondly, an ArbitraryCallsProposal to transfer the entire ERC20 token supply to an attacker address. At this point, attacker can call `vault.redeem()` to burn the outstanding token supply and receive the NFT back.

### Impact

A 51% majority could steal the precious NFT from the party and leave it empty.

### Proof of Concept

The only non-trivial component of this attack is that the created vault, whose tokens we wish to transfer out, has an

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 3: [M-11] Loss of Veto Power can Lead to 51% Attack

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: MEDIUM

**Details**:

_Submitted by TomJ, also found by 0xSky, ayeslick, Chom, pedr02b2, PwnPatrol, yixxas, and zkhorse_

[Governor.sol#L76](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/governance/governor/Governor.sol#L76)<br>
[Governor.sol#L596-L602](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/governance/governor/Governor.sol#L596-L602)<br>

The veto power is important functionality for current Nouns DAO logic in order to protect their treasury from malicious proposals.
However there is lack of zero address check and lack of 2 step address changing process for vetoer address.<br>
This might lead to DAO owner losing their veto power unintentionally and open to 51% attack which can drain their entire treasury.

<https://dialectic.ch/editorial/nouns-governance-attack><br>
<https://dialectic.ch/editorial/nouns-governance-attack-2>

### Proof of Concept

Lack of 0-address check for vetoer address at initialize() of Governor.sol<br>
Also I recommend to make changing address process of vetoer at updateVetoer() into 2-step process to avoid accidently setting
vetoer to arbitrary address and end up lossing veto power unintentionally.

    Governor.sol:
    57:    function initialize(
             ...
    76:        settings.vetoer = _vetoer;

<!---->

    596:    function updateVetoer(address _newVetoer) external onlyOwner {
    597:        if (_newVetoer == address(0)) revert ADDRESS_ZERO();

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 4: Remove unnecessary ETH handling logic for maker asset

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

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## chain-reorganization-attack-patterns.md
# Chain Reorganization Attack Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 13 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, ConsenSys, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Check for chain reorganization attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Block Reorg Can Allow For Double Spending

**Source**: AuditOne
**Protocol**: Aurorafastbridge
**Impact**: HIGH

**Details**:

**Description**: 

Block reorg, also known as blockchain reorganization, is a situation where a competing chain replaces the main blockchain. This can happen when multiple miners find valid blocks at the same time, and the network has to decide which block to include in the blockchain. In some cases, the network may choose to include a block that is not in the main blockchain, resulting in a reorganization of the chain.

**Recommendations:**

To mitigate the risk of block reorgs, the Fast Bridge project may need to implement additional measures, such as waiting for multiple confirmations before proceeding with token transfers or implementing a fallback mechanism in case of a block reorg.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/AuditOne/2023-05-09-Aurorafastbridge.md)

---

### Example 2: [M-09] Create methods are suspicious of the reorg attack

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

The createVaultBooster() function deploys a new VaultBooster contract using the `create`, where the address derivation depends only on the VaultBoosterFactory nonce.

Re-orgs can happen in all EVM chains and as confirmed the contracts will be deployed on most EVM compatible L2s including Arbitrum, etc. It is also planned to be deployed on ZKSync in future. In ethereum, where this is deployed, Re-orgs has already been happened. For more info, [check here](https://decrypt.co/101390/ethereum-beacon-chain-blockchain-reorg).

This issue will increase as some of the chains like Arbitrum and Polygon are suspicious of the reorg attacks.

Polygon re-org reference: [click here](https://protos.com/polygon-hit-by-157-block-reorg-despite-hard-fork-to-reduce-reorgs/). This one happened this year in February, 2023.

Polygon blocks forked: [check here](https://polygonscan.com/blocks_forked)

The issue would happen when users rely on the address derivation in advance or try to deploy the position clone with the same address on different EVM chains, any funds sent to the `new` contract could potentially be withdrawn by anyone else. All in all, it could lead to the theft of user funds.

```Solidity
File: src/VaultBoosterFactory.sol

    function createVaultBooster(PrizePool _prizePool, address _vault, address _owner) external returns (VaultBooster) {
>>        VaultBooster booster = new VaultBooster(_prizePool, _vault, _owner);

        emit CreatedVaultBooster(booster, _prizePool, _vault, _own

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-pooltogether)

---

### Example 3: [M-01] Identifying publications using its ID makes the protocol vulnerable to blockchain re-orgs

**Source**: Code4rena
**Protocol**: Lens Protocol
**Impact**: MEDIUM

**Details**:

In the protocol, publications are uniquely identified through the publisher's profile ID and the publication's ID. For example, when a user calls `act()`, the publication being acted on is determined by `publicationActedProfileId` and `publicationActedId`:

[ActionLib.sol#L23-L26](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/libraries/ActionLib.sol#L23-L26)

```solidity
        Types.Publication storage _actedOnPublication = StorageLib.getPublication(
            publicationActionParams.publicationActedProfileId,
            publicationActionParams.publicationActedId
        );
```

However, as publication IDs are not based on the publication's data, this could cause users to act on the wrong publication in the event a blockchain re-org occurs.

For example:

*   Assume the following transactions occur in separate blocks:
    *   Block 1: Alice calls `post()` to create a post; its publication ID is 20.
    *   Block 2: Bob is interested in the post, he calls `act()` with `publicationActedId = 20` to act on the post.
    *   Block 3: Alice calls `comment()` separately, which creates another publication; its publication ID is 21.
*   A blockchain re-org occurs; block 1 is dropped in place of block 3:
    *   Alice's comment now has the publication ID 20 instead of 21.
*   Bob's call to `act()` in block 2 is applied on top of the re-orged blockchain:
    *   This causes him to act on the comment instead of the post he intended to, as it now has the publication 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-lens)

---

### Example 4: [M-04] Many `create` methods are suspicious of the reorg attack

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

### Proof of Concept

There are many instances of this; but to understand things better, take the example of the `createTalosV3Strategy` method.

The `createTalosV3Strategy` function deploys a new `TalosStrategyStaked` contract using the `create` method, where the address derivation depends only on the arguments passed.

At the same time, some of the chains like Arbitrum and Polygon are suspicious of the reorg attack.

```solidity
File: TalosStrategyStaked.sol

  function createTalosV3Strategy(
        IUniswapV3Pool pool,
        ITalosOptimizer optimizer,
        BoostAggregator boostAggregator,
        address strategyManager,
        FlywheelCoreInstant flywheel,
        address owner
    ) public returns (TalosBaseStrategy) {
        return new TalosStrategyStaked( // @audit-issue Reorg Attack
                pool,
                optimizer,
                boostAggregator,
                strategyManager,
                flywheel,
                owner
            );
    }

```

[Link to Code](https://github.com/code-423n4/2023-05-maia/blob/main/src/talos/TalosStrategyStaked.sol#L28)

Even more, the reorg can be a couple of minutes long. So, it is quite enough to create the `TalosStrategyStaked` and transfer funds to that address using the `deposit` method; especially when someone uses a script and not doing it by hand.

Optimistic rollups (Optimism/Arbitrum) are also suspect to reorgs. If someone finds a fraud, the blocks will be reverted, even though the user receives

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 5: TRST-M-3 Attacker could abuse victim's vote to pass their own proposal

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
Proposals are created using `submitProposal()`:
```solidity
        function submitProposal(uint8 _actionType, bytes memory _payload)  public onlyCouncil {
             uint256 proposalId = proposalCount;
                 proposals[proposalId] = Proposal(msg.sender,_actionType, 
                    _payload, 0, false);
                proposalCount += 1;
         emit ProposalSubmitted(proposalId, msg.sender);
        }
```
After submission, council members approve them by calling `confirmTransaction()`:

```solidity
        function confirmTransaction(uint256 _proposalId) public onlyCouncil 
            notConfirmed(_proposalId) {
             confirmations[_proposalId][msg.sender] = true;
             proposals[_proposalId].confirmation += 1;
        emit Confirmation(_proposalId, msg.sender);
        }
```
Notably, the **_proposalId** passed to `confirmTransaction()` is simply the **proposalCount** at time 
of submission. This design allows the following scenario to occur:
1. User A submits proposal P1
2. User B is interested in the proposal and confirms it
3. Attacker submits proposal P2
4. A blockchain re-org occurs. Submission of P1 is dropped in place of P2.
5. User B's confirmation is applied on top of the re-orged blockchain. Attacker gets their 
vote.
We've seen very large re-orgs in top blockchains such as Polygon, so this threat remains a 
possibility to be aware of.

**Recommended Mitigation:**
Calculate **proposalId** as a hash of the proposal p

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 6: in3-server - should enforce safe settings for minBlockHeight Â Won't Fix

**Source**: ConsenSys
**Protocol**: Slock.it Incubed3
**Impact**: MEDIUM

**Details**:

#### Resolution



The default block is changed to 10 and `minBlockHeight` is added to the registry
(as part of the properties) in [8c72633e](https://git.slock.it/in3/ts/in3-server/commit/8c72633e53651bb4dc2b0d6627ce6c238dd3e2e8), but allow the user to define a `minBlockHeight` lower than this number. The client is responsible to review the settings depending on how secure they want their nodes to be.


Client response:



> 
> We have discussed this, but decided to keep it flexible. This means:
> 
> 
> 1. We have put the minBlockHeight into the registry (as part of the properties). Because these properties indicate the limit and capabilities of the node and give the client a chance to filter out nodes if they donâ€™t match the requirements. So each client is able to filter out node who are not willing to take the risk and sign for example latest-6. Of course these nodes will most likely only store a low deposit ( you can not have a signature of a young block and a high deposit), but if you need a high security the nodes with a deposit will propably wait at least 10 or more blocks. In order to protect the owner of a node of using insecure settings, we will use our wizard to check the deposit and minBlockHeights and warn or educate the user. The reason why this flexibility is important, is because there use cases where dapps will not accept the let user wait 10 blocks before confirming a transaction. If the dapp developer needs a signature of a younger block, he will need to liv

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2019/09/slock.it-incubed3/)

---

### Example 7: Polygon chain reorgs will change mystery box tiers which can be gamed by validators

**Source**: Cyfrin
**Protocol**: Mode Earnm
**Impact**: HIGH

**Details**:

**Description:** [`REQUEST_CONFIRMATIONS = 3`](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L26) is too small for polygon, as [chain re-orgs frequently have block-depth greater than 3](https://polygonscan.com/blocks_forked?p=1).

**Impact:** Chain re-orgs re-order blocks and transactions changing randomness results. Someone who originally won a rare box could have that result changed into a common box and vice versa due to changing randomness result during the re-org.

This can also be [exploited by validators](https://docs.chain.link/vrf/v2/security/#choose-a-safe-block-confirmation-time-which-will-vary-between-blockchains) who can intentionally rewrite the chain's history to force a randomness request into a different block, changing the randomness result. This allows validators to get a fresh random value which may be to their advantage if they are minting mystery boxes by moving the txn around to get a better randomness result to mint a rarer box.

**Recommended Mitigation:** `REQUEST_CONFIRMATIONS = 30` appears very safe for polygon as it is very rare for chain re-orgs to have block-depth greater than this. If this happens occasionally it isn't a big deal, but if it happens all the time ("3" ensures this) that is not good and potentially exploitable by validators.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-20-cyfrin-mode-earnm.md)

---

### Example 8: [C-01] Polygon chain reorgs will often change game results

**Source**: Pashov Audit Group
**Protocol**: Nft Loots
**Impact**: HIGH

**Details**:

**Impact:**
High, as an already winning user will lose its reward

**Likelihood:**
High, as reorgs with > 3 depth happen often on Polygon

**Description**

The `REQUEST_CONFIRMATION` constant in `VRFv2Consumer` is set to 3. This value is used to tell the Chainlink VRF service how much blocks do you want to wait at a minimum before receiving randomness. The reason this value was added is because of chain reorganizations - when this event happens, blocks and transactions get reorganized and they change. This is a serious problem in this application as it is expected to be launched on Polygon (mentioned in `README.md`), but as we can see [here](https://polygonscan.com/blocks_forked) there are more than 5 block reorganizations a day with depth that is more than 3 blocks. In [this article](https://protos.com/polygon-hit-by-157-block-reorg-despite-hard-fork-to-reduce-reorgs/) we can even see a recent event where there was a 156 block depth chain reorg on Polygon. This means that it is possible that often the winner of a lootbox game to be changed since when your transaction for requesting randomness from VRF is moved to a different block then the randomness will change as well.

**Recommendations**

Use a larger `REQUEST_CONFIRMATIONS` value - I would suggest around 60 to be safe. For the past 7 days the deepest chain reorganization had a depth of < 30 blocks. While 60 might not fit your use case for the game, I think anything below 25-30 is potentially dangerous to the project's u

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-06-01-NFT Loots.md)

---

### Example 9: [H-02] Miners Can Re-Roll the VRF Output to Game the Protocol

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

_Submitted by leastwood_.

#### Impact

Miners are able to rewrite a chain's history if they dislike the VRF output used by the protocol. Consider the following example:

*   A miner or well-funded user is participating in the PoolTogether protocol.
*   A VRF request is made and fulfilled in the same block.
*   The protocol participant does not benefit from the VRF output and therefore wants to increase their chances of winning by including the output in another block, producing an entirely new VRF output. This is done by re-orging the chain, i.e. following a new canonical chain where the VRF output has not been included in a block.
*   This attack can be continued as long as the attacker controls 51% of the network. The miner itself could control a much smaller proportion of the network and still be able to mine a few blocks in succession, although this is of low probability but entirely possible.
*   A well-funded user could also pay miners to re-org the chain on their behalf in the form of MEV to achieve the same benefit.

The PoolTogether team is aware of this issue but is yet to mitigate this attack vector fully.

#### Proof of Concept

- <https://docs.chain.link/docs/vrf-security-considerations/#choose-a-safe-block-confirmation-time-which-will-vary-between-blockchains>
- <https://github.com/pooltogether/pooltogether-rng-contracts/blob/master/contracts/RNGChainlink.sol>
- <https://github.com/pooltogether/v4-core/blob/master/contracts/DrawBeacon.sol#L311-L324>
- <https://

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-pooltogether)

---

### Example 10: Malicious clients can use forks or reorgs to convict honest nodes Â Won't Fix

**Source**: ConsenSys
**Protocol**: Slock.it Incubed3
**Impact**: HIGH

**Details**:

#### Resolution



Default value for past signed blocks is changed to 10 blocks. Slockit plans to use their off-chain channels to notify clients for planned forks. They also looking into using fork oracles in the future releases to detect planned hardforks to mitigate risks.


#### Description


In case of reorgs it is possible to have more than 6 blocks in a node that gets replaced by a new longer chain. Also for forks, such as upcoming [Istanbul fork](https://blog.infura.io/were-ready-for-the-istanbul-fork-e39afc2b1412), itâ€™s common to have some nodes taking some time to update and they will be in the wrong chain for the time being. In both cases, in3-nodes are prone to sign blocks that are considered invalid in the main chain.
Malicious nodes can catch these instances and convict the honest users in the main chain to get 50% of their deposits.


#### Recommendation


No perfect solution comes to mind at this time. One possible mitigation method for forks could be to disable the network on the time of the fork but this is most certainly going to be a threat to the system itself.

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2019/09/slock.it-incubed3/)

---

### Example 11: [M-01] QuestFactory is suspicious of the reorg attack

**Source**: Code4rena
**Protocol**: RabbitHole
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/QuestFactory.sol#L75
https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/QuestFactory.sol#L108


## Vulnerability details

## Description

The `createQuest` function deploys a quest contract using the `create`, where the address derivation depends only on the `QuestFactory` nonce. 

At the same time, some of the chains (Polygon, Optimism, Arbitrum) to which the `QuestFactory` will be deployed are suspicious of the reorg attack.

- https://polygonscan.com/blocks_forked

![](https://i.imgur.com/N8tDUVX.png)

Here you may be convinced that the Polygon has in practice subject to reorgs. Even more, the reorg on the picture is 1.5 minutes long. So, it is quite enough to create the quest and transfer funds to that address, especially when someone uses a script, and not doing it by hand.

Optimistic rollups (Optimism/Arbitrum) are also suspect to reorgs since if someone finds a fraud the blocks will be reverted, even though the user receives a confirmation and already created a quest.

## Attack scenario

Imagine that Alice deploys a quest, and then sends funds to it. Bob sees that the network block reorg happens and calls `createQuest`. Thus, it creates `quest` with an address to which Alice sends funds. Then Alices' transactions are executed and Alice transfers funds to Bob's controlled quest. 

## Impact

If use

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-rabbithole)

---

### Example 12: [M-14] Re-org attack in factory

**Source**: Code4rena
**Protocol**: Frankencoin
**Impact**: MEDIUM

**Details**:

The `createClone` function deploys a clone contract using the create, where the address derivation depends only on the `PositionFactory` nonce.

Re-orgs can happen in all EVM chains. In ethereum, where currently Frankencoin is deployed, it is not "super common" but it still happens, being the last one less than a year ago:

<https://decrypt.co/101390/ethereum-beacon-chain-blockchain-reorg>

The issue increases the changes of happening because frankencoin is thinking about deploying also in L2's/ rollups, proof:

<https://discord.com/channels/810916927919620096/1095308824354758696/1096693817450692658>

where re-orgs have been much more active:

<https://protos.com/polygon-hit-by-157-block-reorg-despite-hard-fork-to-reduce-reorgs/>

being the last one, less than a year ago.

The issue would happen when users rely on the address derivation in advance or try to deploy the position clone with the same address on different EVM chains, any funds sent to the new clone could potentially be withdrawn by anyone else. All in all, it could lead to the theft of user funds.

As you can see in a previous report, the issue should be marked and judged as a medium:

<https://code4rena.com/reports/2023-01-rabbithole/#m-01-questfactory-is-suspicious-of-the-reorg-attack>

### Proof of Concept

Imagine that Alice deploys a position clone, and then sends funds to it. Bob sees that the network block reorg happens and calls `clonePosition`. Thus, it creates a position clone with an address to which Al

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-frankencoin)

---

### Example 13: M-2: useLoan doesn't allow liqudator to specifiy maximum price

**Source**: Sherlock
**Protocol**: Kairos Loan
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-kairos-judging/issues/25 

## Found by 
0x52

## Summary

useLoan doesn't allow the liquidator to specify a max price they are will to pay for the collateral they are liquidating. On the surface this doesn't seem like an issue because the price is always decreasing due to the dutch auction. However this can be problematic if the chain the contracts are deployed suffers a reorg attack. This can place the transaction earlier than anticipated and therefore charge the user more than they meant to pay. On Ethereum this is unlikely but this is meant to be deployed on any compatible EVM chain many of which are frequently reorganized.

## Vulnerability Detail

See summary.

## Impact

Liquidator can be charged more than intended

## Code Snippet

https://github.com/sherlock-audit/2023-02-kairos/blob/main/kairos-contracts/src/AuctionFacet.sol#L59-L73

## Tool used

Manual Review

## Recommendation

Allow liquidator to specify a max acceptable price to pay



## Discussion

**npasquie**

fixed here https://github.com/kairos-loan/kairos-contracts/pull/50

---

### Example 14: Block depth used does not offer guarantees against reorgs under edge cases

**Source**: Spearbit
**Protocol**: Redacted Dinero Infrastructure
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

**Context:** cdk-dinero-keeper/src/functions/update-validator-stats/index.ts#L226

**Description:** 
The Ethereum chain finalizes roughly every 2 epochs (64 slots); at this point, the network offers extreme guarantees for the finalized blocks. The current value of `CONFIRMATION_BLOCKS=30` would be historically safe but offers no guarantees in edge/attack cases against reorgs and non-finality incidents.

**Recommendation:** 
There is a notion of finalized blocks that could be used instead. The data would be older but would represent the finalized state of the network. Note that in the case of a non-finality incident on the network, the value will be stuck in the past unless the network is healthy again. This may even be an advantage as you will not perform actions on data that might change or spend funds that should not have been.

**Redacted:** Fixed in PR 56.

**Spearbit:** 
The recommendation was followed and a fix was applied in PR 56 at commit `3772bdd8`.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Redacted-Dinero-Infrastructure-Security-Review.pdf)

---

### Example 15: [M-01] No check for sequencer uptime can lead to dutch auctions failing or executing at bad prices

**Source**: Code4rena
**Protocol**: Ethereum Credit Guild
**Impact**: MEDIUM

**Details**:

The `AuctionHouse` contract implements a Dutch auction mechanism to recover debt from collateral. However, there is no check for sequencer uptime, which could lead to auctions failing or executing at unfavorable prices.

The current deployment parameters allow auctions to succeed without a loss to the protocol for a duration of 10m 50s. If there's no bid on the auction after this period, the protocol has no other option but to take a loss or forgive the loan. This could have serious consequences in the event of a network outage, as any loss results in the slashing of all users with weight on the term.

Network outages and large reorgs happen with relative frequency. For instance, Arbitrum suffered an hour-long outage just two weeks ago ([source](https://github.com/ArbitrumFoundation/docs/blob/50ee88b406e6e5f3866b32d147d05a6adb0ab50e/postmortems/15\_Dec\_2023.md)).

### Proof of Concept

Consider the following scenario:

1. A loan is called and an auction is initiated.
2. The network experiences an outage, causing the sequencer to go offline.
3. The auction fails to receive any bids within the 10m 50s window due to the outage.
4. The protocol is forced to take a loss (if there's still a bid after the `midPoint` and before the auction ends) or forgive the loan, both leading to the complete slashing of all users with weight on the term.

### Recommended Mitigation Steps

To mitigate this issue, consider integrating an external uptime feed such as [Chainlink's L2 Sequencer Feeds]

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-ethereumcreditguild)

---

### Example 16: Risk of double-spend attacks due to use of single-node Clique consensus without ï¬nality API

**Source**: TrailOfBits
**Protocol**: Scroll, l2geth
**Impact**: MEDIUM

**Details**:

## Diï¬ƒculty: Medium

## Type: Denial of Service

## Description
l2geth uses the proof-of-authority Clique consensus protocol, defined by EIP-255. This consensus type is not designed for single-node networks, and an attacker-controlled sequencer node may produce multiple conflicting forks of the chain to facilitate double-spend attacks.

The severity of this finding is compounded by the fact that there is no API for an end user to determine whether their transaction has been finalized by L1, forcing L2 users to use ineffective block/time delays to determine finality.

Clique consensus was originally designed as a replacement for proof-of-work consensus for Ethereum testnets. It uses the same fork choice rule as Ethereumâ€™s proof-of-work consensus; the fork with the highest â€œdifficultyâ€ should be considered the canonical fork.

Clique consensus does not use proof-of-work and cannot update block difficulty using the traditional calculation; instead, block difficulty may be one of two values:
- â€œ1â€ if the block was mined by the designated signer for the block height
- â€œ2â€ if the block was mined by a non-designated signer for the block height

This means that in a network with only one authorized signer, all of the blocks and forks produced by the sequencer will have the same difficulty value, making it impossible for syncing nodes to determine which fork is canonical at the given block height.

In a normal proof-of-work network, one of the proposed blocks will have a higher diffic

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-08-scrollL2geth-initial-securityreview.pdf)

---

### Example 17: [M-08] An attacker can front-run `deployVault` to deploy at the same address

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

Vaults are created from the factory via `CREATE1`. An attacker can front-run `deployVault` to deploy at the same address, but with different config. If the deployed chain reorg, a different vault might also be deployed at the same address.

### Proof of Concept

<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/VaultFactory.sol#L67-L78>

1.  Bob setup a bot to monitor the `mempool` when PT deploys a new vault.
2.  Bob's bot saw a deployment by PT at `0x1234` and fires a tx to deposit immediately.
3.  Alice front-runs PT's deployment by deploying a malicious vault at `0x1234`.
4.  Bob's transaction ended up deposited into Alice's malicious vault.

### Recommended Mitigation Steps

Use `CREATE2` and the vault config as salt.

### Assessed type

MEV

**[asselstine (PoolTogether) disputed and commented](https://github.com/code-423n4/2023-07-pooltogether-findings/issues/416#issuecomment-1644728305):**
 > The Vault address is a derivative of the (sender address, nonce).  I don't see how this scenario is possible?

**[Picodes (judge) commented](https://github.com/code-423n4/2023-07-pooltogether-findings/issues/416#issuecomment-1666992892):**
 > @asselstine - exactly. Here, it only depends on the nonce of the factory; so in case of reorg, someone could "override" a vault deployment and all following transactions would still be executed.

**[PoolTogether mitigated](https://github.com/code-423n4/2023-08-pooltogether-mitigation#individu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 18: M-4: Loss of bond amounts on re-org attacks

**Source**: Sherlock
**Protocol**: Optimism Fault Proofs
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-optimism-2024-judging/issues/201 

The protocol has acknowledged this issue.

## Found by 
MiloTruck, Trust
## Summary

The `move()` function lacks proper identification of the target of the move, leading to successful re-org attacks which can take the honest participant's funds.

## Vulnerability Detail

Participants in the game can call `attack()`, `defend()` or `move()`, each accepting a `parentIndex` which corresponds to the claim being challenged, and a `_claim` commitment. 

When participants claim, they have a particular claim in mind which they wish to challenge, and then pass on that claim's index. However, between the moment they sent the TX and the moment that TX is executed, a block reorg can take place. When it occurs, the challenge corresponding to that ID may change to another challenge, which may be valid or invalid in a different way. Regardless, the participant's commitment to that `move()` will be wrong, and they stand to lose their bond amount.

Chain reorgs are very prevalent in Ethereum mainnet, where the contract is deployed. You can check [this](https://etherscan.io/blocks_forked) index of reorged blocks on etherscan. It is **incorrect** to assume the attacker will wait until it achieved finality, because there's no warnings or documentation available for them to identify this as a threat. Therefore, it remains a very valid concern with reasonable hypotheticals.

Note that in high depths, the bond amoun

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


