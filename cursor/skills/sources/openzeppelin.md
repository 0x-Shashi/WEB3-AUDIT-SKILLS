# OpenZeppelin - Audit Findings

## Overview

**Total Findings**: 3,237 (6.41% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 436 | 851 | 1950 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Wrong Math | 4 |
| Overflow/Underflow | 2 |
| Weird ERC20 | 2 |
| Front-Running | 2 |
| Fund Lock | 1 |
| Rounding | 1 |
| Reentrancy | 1 |
| ERC777 | 1 |
| DOS | 1 |

---

## Notable Findings

### 1. Integer Underflow in _getTargetOutput Due to Improper Type Casting

**Protocol**: OpenZeppelin Uniswap Hooks v1.1.0 RC 1 Audit | **Impact**: HIGH

In the `AntiSandwichHook` contract, an integer underflow may occur due to the improper casting of a negative `int128` value to `uint128` in the [`_getTargetOutput`](https://github.com/OpenZeppelin/uniswap-hooks/blob/087974776fb7285ec844ca090eab860bd8430a11/src/general/AntiSandwichHook.sol#L196) function:

```
int128 target =
    (params.amountSpecified < 0 == params.zeroForOne) ? targetDelta.amount1() : targetDelta.amount0();
targetOutput = uint256(uint128(target));

```

To understand the issue, consider the following example:

```
SwapParams({
    zeroForOne: true,
    amountSpecified: 10_...

---

### 2. Limit Orders Can Be Incorrectly Filled

**Protocol**: OpenZeppelin Uniswap Hooks v1.1.0 RC 1 Audit | **Impact**: HIGH

The `LimitOrderHook` [contract](https://github.com/OpenZeppelin/uniswap-hooks/blob/087974776fb7285ec844ca090eab860bd8430a11/src/general/LimitOrderHook.sol) [uses](https://github.com/OpenZeppelin/uniswap-hooks/blob/087974776fb7285ec844ca090eab860bd8430a11/src/general/LimitOrderHook.sol#L198) the `_getCrossedTicks` [function](https://github.com/OpenZeppelin/uniswap-hooks/blob/087974776fb7285ec844ca090eab860bd8430a11/src/general/LimitOrderHook.sol#L613) to determine which ticks were crossed during a swap by comparing the current pool tick with the previously stored tick. It then [processes](https...

---

### 3. Inner Variable Shadowing Causes Incorrect Return in mloadPotentiallyPaddedValue

**Protocol**: EVM Emulator and Semi-abstracted Nonces Update Audit | **Impact**: HIGH

The helper function [`mloadPotentiallyPaddedValue`](https://github.com/matter-labs/era-contracts/blob/cc1619cfb03cc19adb21a2071c89415cab1479e8/system-contracts/evm-emulator/EvmEmulatorFunctions.template.yul#L1052) is intended to read a 32-byte word from memory and zero out any bytes that lie beyond a specified memory boundary. However, due to improper use of a `let` declaration inside an `if` block, the adjusted value is not actually returned.

```
function mloadPotentiallyPaddedValue(index, memoryBound) -> value {
    value := mload(index)

    if lt(memoryBound, add(index, 32)) {
        me...

---

### 4. Wrong Scaling for Amount of Gas Tokens

**Protocol**: Across Protocol Diff Audit -Arbitrum CustomGasToken & ExclusivityPeriod | **Impact**: HIGH

The `Arbitrum_CustomGasToken_Adapter` [contract](https://github.com/across-protocol/contracts/blob/f56146a01ca9c62e6206a2c23c55dbe01a25a912/contracts/chain-adapters/Arbitrum_CustomGasToken_Adapter.sol#L130) is an adapter meant to handle cases where the destination chain uses a custom token to charge gas fees. Such a token might have non-standard decimals so proper scaling must be performed in order to correctly calculate the amounts.

The `_pullCustomGas` [function](https://github.com/across-protocol/contracts/blob/f56146a01ca9c62e6206a2c23c55dbe01a25a912/contracts/chain-adapters/Arbitrum_Cust...

---

### 5. Overflow in quantize Function Can Cause a DoS

**Protocol**: Forta Firewall Incremental Audit | **Impact**: HIGH

The [`quantize` function](https://github.com/forta-network/forta-firewall-contracts/blob/09feff1d712011470d49d54f2462e3204c11afaf/src/Quantization.sol#L20-L24) contains a vulnerability caused by an intermediate overflow during sequential operations in the return statement:

```
return ((n >> offset) << offset) + (2 ** offset) - 1;

```

When `offset = 256` (calculated as `8 * Math.log256(n)` for sufficiently large `n`), the operation `2 ** offset` results in an overflow since `2^256` exceeds the maximum value of a `uint256`. This overflow affects the intermediate result of the addition:

```
...

---

### 6. Wrong Token Output Calculation in Oracle Price

**Protocol**: Anvil Audit | **Impact**: HIGH

Token prices in terms of USD are retrieved from the [Pyth oracle](https://github.com/AmperaFoundation/sol-contracts/blob/4c4423791b3427153937881fc5287a81283ee141/contracts/PythPriceOracle.sol#L156). It returns the [`PythStructs.Price`](https://github.com/pyth-network/pyth-sdk-solidity/blob/main/PythStructs.sol#L13-L22) struct that includes an integer value `price` along with an `exponent` value to scale the `price` by.


In order to calculate an output amount of tokens per unit input (input price), the `PythPriceOracle` contract [performs the following calculation](https://github.com/AmperaFou...

---

### 7. Attacker Can Downscale All Protocol Shares by 18 Decimals

**Protocol**: Restakefi Audit | **Impact**: HIGH

The [`deposit` function](https://github.com/DigitalMOB2/refi-protocol/blob/dc842fd071f225c9d1ff9ad4677b986970125cf9/contracts/Controller.sol#L105) of the `Controller` contract enables users to deposit underlying assets into the protocol, which are subsequently deposited into EigenLayer by the `StrategyManager`. In return, the Controller [mints protocol token shares](https://github.com/DigitalMOB2/refi-protocol/blob/dc842fd071f225c9d1ff9ad4677b986970125cf9/contracts/Controller.sol#L127) for the user, maintaining a 1:1 ratio between the underlying deposited token and the underlying token balance...

---

### 8. Incorrect Batch Hashes Due to Memory Corruption

**Protocol**: Scroll Phase 1 Audit | **Impact**: HIGH

When committing a new batch, the `ScrollChain` contract calls the [`_commitChunk`](https://github.com/scroll-tech/scroll/blob/3bc8a3f5c6ac816ddffadca41024331dcf4d3064/contracts/src/L1/rollup/ScrollChain.sol#L394) function to compute a hash for each chunk in the batch. This hash includes the block contexts, as well as L1 and L2 transaction hashes that are part of this chunk. The `_commitChunk` function does this by getting the free memory pointer, storing everything it needs contiguously starting there, and then getting the free memory pointer again to [compute the keccak256 hash of this sectio...

---

### 9. ETH withdrawal within allowed limit could fail

**Protocol**: zkSync  L1 Diff Audit (February 2023) | **Impact**: HIGH

The protocol enforces an ETH withdraw limit (currently 10% of the total balance) within each 1-day window as a safety mechanism. This is done through the[`_verifyWithdrawalLimit`function in`Mailbox.sol`](https://github.com/matter-labs/zksync-2-contracts/blob/3f345ce52bc378c4b5d710c80d817db170775049/ethereum/contracts/zksync/facets/Mailbox.sol#L204). However, this function has a logic flaw that could cause an ETH withdrawal within the limit to fail.


When withdrawal validations occur within the same 1-day window, the function checks the limit in[line 215 of Mailbox](https://github.com/matt...

---

### 10. Unbound RLP Length Encoding

**Protocol**: zkSync Bootloader Audit Report | **Impact**: HIGH

The[`RLPEncoder`library](https://github.com/matter-labs/system-contracts/blob/4ad1f26ae205d5a973216d141833e0ac37d72ec8/contracts/libraries/RLPEncoder.sol)allows the encoding of bytes and list-type values. These dynamic types need to be prefixed to indicate the type and length of the data. The type is indicated through an offset:


* `0x80`for bytes
* `0xc0`for a list


The length encoding depends on the length itself:


1. Length < 56: The length is added onto the offset.
	* Bytes 1st byte range:`[0x80, 0xb7]`
	* List 1st byte range:`[0xc0, 0xf7]`
2. Length  56: The length of the data ...

---

### 11. Duplicate Request Rewards

**Protocol**: UMA DVM 2.0 Audit | **Impact**: HIGH

In the`VotingV2`contract the[`_updateAccountSlashingTrackers`](https://github.com/UMAprotocol/protocol/blob/7938617bf79854811959eb605237edf6bdccbc90/packages/core/contracts/oracle/implementation/VotingV2.sol#L831)function contains an optimization that marks unresolved requests in a prior round (rolled votes) as deleted via an entry in the`deletedRequests`map. The intention is to reduce gas consumption as the function will be called for every staker in the system. The logic on[line 860](https://github.com/UMAprotocol/protocol/blob/7938617bf79854811959eb605237edf6bdccbc90/packages/core/con...

---

### 12. [H01] Incorrect Uniswap price use discourages liquidations

**Protocol**: Beta Finance Audit | **Impact**: HIGH

When the protocol considers that a position does not have enough collateral, decided by [the assets `liquidationLTV`](https://github.com/beta-finance/beta-private/blob/9e73eaf40e5118125d6925b29e4fb9ad8bf8e113/contracts/BetaConfig.sol#L9), anyone can call the [`BetaBank` `liquidate` function](https://github.com/beta-finance/beta-private/blob/9e73eaf40e5118125d6925b29e4fb9ad8bf8e113/contracts/BetaBank.sol#L360) to liquidate the position in question. The caller can pay off up to 50% of the positions debt, and in return gets paid from the collateral of the position.


The process of liquidation ...

---

### 13. [C01][Fixed] An attacker can steal all the collateral assets

**Protocol**: Opyn Gamma Protocol Audit | **Impact**: HIGH

The [`Controller` contract](https://github.com/opynfinance/GammaProtocol/blob/d151621b33134789b29dc78eb89dad2b557b25b9/contracts/Controller.sol#L27) allows users to interact with the majority of the platform, being able to open a vault, deposit collateral assets, minting oTokens, or redeem their oTokens. All of these actions start by calling the [`operate` function](https://github.com/opynfinance/GammaProtocol/blob/d151621b33134789b29dc78eb89dad2b557b25b9/contracts/Controller.sol#L331) which then calls the [`_runActions` function](https://github.com/opynfinance/GammaProtocol/blob/d151621b33134...

---

### 14. [P4-C02] Calculation error in the BigNumber addition

**Protocol**: Eco Contracts Audit | **Impact**: HIGH

###### Critical


The `BigNumber` library has an [`innerAdd`](https://github.com/BeamNetwork/currency/blob/de81d9bad4195e03f07aedd2a6817f0cb04a8c8d/contracts/VDF/BigNumber.sol#L252) [function](https://github.com/BeamNetwork/currency/blob/de81d9bad4195e03f07aedd2a6817f0cb04a8c8d/contracts/VDF/BigNumber.sol#L252) that adds two numbers, starting from their least significant 256-bit words.


This function needs to take the carry into account, when the addition of two words overflows. To do this, in [L283](https://github.com/BeamNetwork/currency/blob/de81d9bad4195e03f07aedd2a6817f0cb04a8c8d/contrac...

---

### 15. [P1-C02] Storage collision on Policed contract

**Protocol**: Eco Contracts Audit | **Impact**: HIGH

###### Critical


Component: [`policy`](https://github.com/BeamNetwork/currency/tree/af3428020545e3f3ae2f3567b94e1fbc5e5bdb4c/contracts/policy)


[`Policy`](https://github.com/BeamNetwork/policed-contracts/blob/f9299f43e2bf3629bee2f82bf637918ac9221d62/contracts/Policy.sol) [contracts](https://github.com/BeamNetwork/policed-contracts/blob/f9299f43e2bf3629bee2f82bf637918ac9221d62/contracts/Policy.sol) have the power to enforce actions over [`Policed`](https://github.com/BeamNetwork/policed-contracts/blob/f9299f43e2bf3629bee2f82bf637918ac9221d62/contracts/Policed.sol) [contracts](https://github.c...

---


## Statistics

- Total findings from OpenZeppelin: 3,237
- Last updated: 2026-01-29

