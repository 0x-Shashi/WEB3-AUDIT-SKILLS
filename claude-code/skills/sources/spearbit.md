# Spearbit - Audit Findings

## Overview

**Total Findings**: 2,224 (4.40% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 395 | 626 | 1203 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Business Logic | 72 |
| Validation | 72 |
| Don't update state | 18 |
| Wrong Math | 13 |
| Admin | 12 |
| Access Control | 11 |
| Front-Running | 10 |
| Fund Lock | 10 |
| DOS | 8 |
| Approve | 6 |

---

## Notable Findings

### 1. Protocol fees are double-counted as registry balance and pool reserve

**Protocol**: Primitive | **Impact**: HIGH

## Severity: Critical Risk

## Context
Portfolio.sol#L489-L507

## Description
When swapping, the registry is credited a `protocolFee`. However, this fee is always reinvested in the pool, meaning the `virtualX` or `virtualY` pool reserves per liquidity increase by `protocolFee / liquidity`. The protocol fee is now double-counted as the registrys user balance and the pool reserve, while the global reserves are only increased by the protocol fee once in `_increaseReserves(_state.tokenInput, iteration.input)`. A protocol fee breaks the invariant that the global reserve should be greater than the...

---

### 2. Overpayment of one side of LP Pair onJoinPool due to sandwich or user error

**Protocol**: Cron Finance | **Impact**: HIGH

## Vulnerability Report

## Severity
**High Risk**

## Context
`CronV1Pool.sol#L2048-L2051`

## Description
Only one of the two incoming tokens is used to determine the amount of pool tokens minted (`amountLP`) on join:

```solidity
amountLP = Math.min(
    _token0InU112.mul(supplyLP).divDown(_token0ReserveU112),
    _token1InU112.mul(supplyLP).divDown(_token1ReserveU112)
);
```

In the event the price moves between the time a minter sends their transaction and when it is included in a block, they may overpay for one of `_token0InU112` or `_token1InU112`. This can occur due to user error, or d...

---

### 3. OrderNFT theft due to ambiguous tokenId encoding/decoding scheme

**Protocol**: CLOBER | **Impact**: HIGH

## Severity: Critical Risk

## Context
- OrderNFT.sol#L249-L274 
- OrderNFT.sol#L70-L74 
- OrderNFT.sol#L82-L89 

## Description
The `encodeId()` function uniquely encodes `OrderKey` to a `uint256` number. However, the `decodeId()` function ambiguously can decode many `tokenId`s to the exact same `OrderKey`. This can be problematic due to the fact that the contract uses `tokenId`s to store approvals. The ambiguity arises from converting `uint8` value to `bool` `isBid` value.

```solidity
function decodeId(uint256 id) public pure returns (CloberOrderBook.OrderKey memory) {
    uint8 isBid;
    ...

---

### 4. OrderNFT theft due to controlling future and past tokens of same order index

**Protocol**: CLOBER | **Impact**: HIGH

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

As a result, the cu...

---

### 5. makePayment doesn't properly update stack, so most payments don't pay off debt

**Protocol**: Astaria | **Impact**: HIGH

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

This call returns the updated stack as `newStack` but then uses the function argument `stack` again in the next iteration of the loop. The `newStack` value is unused until the final iterate, when it is passed along to `_updateCollateralStateHash()`. This means that the new state hash will be the original state wi...

---

### 6. Too generic calls in GenericBridgeFacet allow stealing of tokens

**Protocol**: LI.FI | **Impact**: HIGH

## Security Report

## Severity
**High Risk**

## Context
- `GenericBridgeFacet.sol#L69-L120`
- `LibSwap.sol#L30-L68`

## Description
With the contract `GenericBridgeFacet`, the functions `swapAndStartBridgeTokensGeneric()` (via `LibSwap.swap()`) and `_startBridge()` allow arbitrary function calls, which enable anyone to call `transferFrom()` and steal tokens from users who have provided a large allowance to the LiFi protocol. This vulnerability has been exploited in the past.

### Additional Risks
- Ability to call the LiFi Diamond itself via functions that dont have `nonReentrant`.
- Potent...

---

### 7. Tokens can get stuck in Executor contract if the destination doesnt claim them all

**Protocol**: Connext | **Impact**: HIGH

## Vulnerability Report

## Severity
**High Risk**

## Context
**Executor.sol#L142-L243**

## Description
The function `execute()` increases allowance and then calls the recipient (`_args.to`). When the recipient does not use all tokens, these could remain stuck inside the Executor contract. 

**Notes:**
- The executor can have excess tokens, see: kovan executor.
- See issue: "Malicious call data can DOS execute or steal unclaimed tokens in the Executor contract".

```solidity
function execute(...) ... {
    ...
    if (!isNative && hasValue) {
        SafeERC20.safeIncreaseAllowance(IERC20(_a...

---

### 8. Lack of transferId Verification Allows an Attacker to Front-Run Bridge Transfers

**Protocol**: Connext | **Impact**: HIGH

## Severity: Critical Risk  

## Context  
- `NomadFacet.sol#L99-L149`  
- `BridgeRouter.sol#L176-L199`  
- `BridgeRouter.sol#L347-L381`  

## Description  
The `onReceive()` function does not verify the integrity of `transferId` against all other parameters. Although the `onlyBridgeRouter` modifier checks that the call originates from another BridgeRouter (assuming a correct configuration of the whitelist) to the `onReceive()` function, it does not check that the call originates from another Connext Diamond.

This allows anyone to send arbitrary data to `BridgeRouter.sendToHook()`, which is l...

---

### 9. Clones with malicious extradata are also considered valid clones

**Protocol**: Sudoswap | **Impact**: HIGH

## Severity: Critical Risk

## Context
- **LSSVMPairCloner.sol:** lines 121 
- **LSSVMPair.sol:** lines 687-695 
- **LSSVMRoute.sol:** lines 574-594 
- **LSSVMPairFactory.sol:** lines 223-257 
- **LSSVMPairCloner.sol:** lines 206

## Description
Spearbit discovered that the functions verifying if a contract is a pair do so by only checking the first 54 bytes (i.e., the Proxy code). An attacker could deploy a contract that starts with the first 54 bytes of proxy code but have a malicious payload, and these functions will still verify it as a legitimate clone. We have found this to be a critical...

---

### 10. An attacker can freeze all incoming deposits and brick the oracle members' reporting system with only 1 wei

**Protocol**: Liquid Collective | **Impact**: HIGH

## Severity: Critical Risk

**Context:** SharesManager.1.sol#L195-L206

**Description:** An attacker can brick or lock all deposited user funds and also prevent oracle members from reaching a quorum when there are earnings to be distributed as rewards. Consider the following scenario:

1. The attacker forcefully sends 1 wei to the River contract using, e.g., `selfdestruct`. The attacker must ensure this transaction occurs before any other users deposit their funds in the contract. The attacker can observe the mempool and front-run the initial user deposit. Now, `b = _assetBalance() > 0` is at ...

---

### 11. The Protocol owner can drain users' currency tokens

**Protocol**: LOOKSRARE | **Impact**: HIGH

## Severity: Critical Risk

## Context:
- LooksRareProtocol.sol#L138
- LooksRareProtocol.sol#L391-L398
- ITransferSelectorNFT.sol#L14-L17
- TransferSelectorNFT.sol#L41
- TransferSelectorNFT.sol#L89-L98

## Description:
The Protocol owner can drain users' currency tokens that have been approved to the protocol. Makers who want to bid on NFTs would need to approve their currency token to be spent by the protocol. The owner should not be able to access these funds for free.

The owner can drain the funds as follows:

1. Calls `addTransferManagerForAssetType` and assigns the currency token as the ...

---

### 12. Loss of Long-Term Swap Proceeds Likely in Pools With Decimal or Price Imbalances

**Protocol**: Cron Finance | **Impact**: HIGH

## Severity: High Risk

## Context
`VirtualOrders.sol#L166`

## Description
This TWAMM implementation tracks the proceeds of long-term swaps efficiently via accumulated values called "scaled proceeds" for each token. In every order block interval (OBI), the scaled proceeds for e.g. the sale of token 0 are incremented by:

```
(quantity of token 1 purchased during the OBI) * 264 = (sales rate of token 0 during the OBI)
```

Then the proceeds of any specific long-term swap can be computed as the product of the difference between the scaled proceeds at the current block (or the expiration block o...

---

### 13. Rounding up of taker fees of constituent orders may exceed collected fee

**Protocol**: CLOBER | **Impact**: HIGH

## Severity: High Risk

## Context
- OrderBook.sol#L463 
- OrderBook.sol#L478-L482 
- OrderBook.sol#L604 

## Description
If multiple orders are taken, the taker fee calculated is rounded up once, but that of each taken maker order could be rounded up as well, leading to more fees accounted for than actually taken.

### Example:
- takerFee = 100011 (10.0011%)
- 2 maker orders of amounts 400000 and 377000
- total amount = 400000 + 377000 = 777000
- Taker fee taken = 777000 * 100011 / 1000000 = 77708.547  77709 

Maker fees would be:
- 377000 * 100011 / 1000000 = 37704.147  37705
- 400000 * 10...

---

### 14. Wrong minimum net fee check

**Protocol**: CLOBER | **Impact**: HIGH

## Severity: High Risk

## Context
- MarketFactory.sol#L79
- MarketFactory.sol#L111

## Description
A minimum net fee was introduced that all markets should comply by such that the protocol earns fees. The protocol fees are computed as `takerFee + makerFee`, but the market factory computes the wrong check. Fee pairs that should be accepted are currently not accepted, and, even worse, fee pairs that should be rejected are currently accepted. Market creators can avoid collecting protocol fees this way.

## Recommendation
Implement a `takerFee + makerFee >= minNetFee` check instead:
```solidity
r...

---

### 15. Missing owner check on from when transferring tokens

**Protocol**: CLOBER | **Impact**: HIGH

## Security Report

## Severity: High Risk

### Context
`OrderNFT.sol#L207`

### Description
The `OrderNFT.transferFrom`/`safeTransferFrom` methods use the internal `_transfer` function. While they check approvals on `msg.sender` through `_isApprovedOrOwner(msg.sender, tokenId)`, it is never checked that the specified `from` parameter is actually the owner of the NFT. 

An attacker can decrease other users' NFT balances, making them unable to cancel or claim their NFTs and locking users' funds. The attacker transfers their own NFT passing the victim as `from` by calling `transferFrom(from=vict...

---


## Statistics

- Total findings from Spearbit: 2,224
- Last updated: 2026-01-29

