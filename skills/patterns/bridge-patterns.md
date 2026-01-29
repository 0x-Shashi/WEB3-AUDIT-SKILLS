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

- A victim wants to swap 10K optimism’s BTC into Ethereum mainnet USDC.
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
    ERC20DeployedEvent("atom", "name", ❮utf8 decode failed❯: 0x73796d626fc0, 18, 2)
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
