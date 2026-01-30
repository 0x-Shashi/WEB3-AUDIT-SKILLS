# Validation Security Patterns

## Overview

**Frequency**: 127 occurrences (0.25% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 52 | 75 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock, Cyfrin, MixBytes

---

## Detection Checklist

- [ ] Check for validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: OrderNFT theft due to ambiguous tokenId encoding/decoding scheme

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

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
    uint16 priceIndex;
    uint232 orderIndex;
    assembly {
        orderIndex := id
        priceIndex := shr(232, id)
        isBid := shr(248, id)
    }
    return CloberOrderBook.OrderKey({
        isBid: isBid == 1, 
        priceIndex: priceIndex, 
        orderIndex: orderIndex
    });
}
```

(Note that the attack is possible only for ASK limit orders.)

## Proof of Concept

1. **Step 1**: Attacker creates an ASK limit order and receives NFT.
    ```solidity
    uint16 priceIndex = 100;
    uint256 orderIndex = orderBook.limitOrder{value: Constants.CLAIM_BOUNTY * 1 gwei}({
        user: attacker,
        priceIndex: priceIndex,
        rawAmount: 0,
        baseAmount: 10**18,
        options: _buildLimitOrderOptions(Constants.ASK, Constants.POST_ONLY),
        data: new bytes(0)
    });
    ```

2. **Step 2**: Given the `OrderKey` which represents the created limit order, an attack

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: Lack of transferId Verification Allows an Attacker to Front-Run Bridge Transfers

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: Critical Risk  

## Context  
- `NomadFacet.sol#L99-L149`  
- `BridgeRouter.sol#L176-L199`  
- `BridgeRouter.sol#L347-L381`  

## Description  
The `onReceive()` function does not verify the integrity of `transferId` against all other parameters. Although the `onlyBridgeRouter` modifier checks that the call originates from another BridgeRouter (assuming a correct configuration of the whitelist) to the `onReceive()` function, it does not check that the call originates from another Connext Diamond.

This allows anyone to send arbitrary data to `BridgeRouter.sendToHook()`, which is later interpreted as the `transferId` on Connext’s `NomadFacet.sol` contract. This can be abused by a front-running attack as described in the following scenario:

- **Alice** is a bridge user and makes an honest call to transfer funds over to the destination chain.  
- **Bob** does not make a transfer but instead calls the `sendToHook()` function with the same `_extraData` but passes an `_amount` of `1 wei`.  
- Both Alice and Bob have their tokens debited on the source chain and must wait for the Nomad protocol to optimistically verify incoming `TransferToHook` messages.  
- Once the messages have been replicated onto the destination chain, Bob processes the message before Alice, causing `onReceive()` to be called on the same `transferId`.  
- However, because `_amount` is not verified against the `transferId`, Alice receives significantly fewer tokens, and the `s.reconciledTransfers` m

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: [H-01] Last NFT from the supply can't be minted

**Source**: Pashov Audit Group
**Protocol**: Museumofmahomes
**Impact**: HIGH

**Details**:

**Severity**

**Impact:**
Medium, as only one NFT won't be available for minting, but this is value loss to the protocol

**Likelihood:**
High, as it's impossible to mint the last NFT

**Description**

Currently both the `mint` and `mintPhysical` methods have the following check:

```solidity
if (nextId + amount >= MAX_SUPPLY) revert ExceedsMaxSupply();
```

This is incorrect, as even when the `nextId` is `MAX_SUPPLY - 1` then an `amount` of 1 should be allowed but with the current check the code will revert. This is due to the `equal` sign in the check, which shouldn't be there. Here is a Proof of Concept unit test demonstrating the issue (add it to `MuseumOfMahomes.t.sol`):

```solidity
    function testNotAllNFTsCanBeMinted() public {
        museum.setPrice(PRICE);
        uint256 allButOneNFTSupply = 3089;

        // mint all but one from the NFT `MAX_SUPPLY` (3090)
        museum.mint{value: allButOneNFTSupply * PRICE}(address(this), allButOneNFTSupply);
        require(allButOneNFTSupply == museum.balanceOf(address(this)), "Mint did not work");

        // try to mint the last NFT from the supply, but it doesn't work
        vm.expectRevert(MuseumOfMahomes.ExceedsMaxSupply.selector);
        museum.mint{value: PRICE}(address(this), 1);
    }
```

**Recommendations**

Do the following change in both `mint` and `mintPhysical`:

```diff
- if (nextId + amount >= MAX_SUPPLY) revert ExceedsMaxSupply();
+ if (nextId + amount > MAX_SUPPLY) revert ExceedsMaxSupply();
```

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-09-01-MuseumOfMahomes.md)

---

### Example 4: Wrong minimum net fee check

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- MarketFactory.sol#L79
- MarketFactory.sol#L111

## Description
A minimum net fee was introduced that all markets should comply by such that the protocol earns fees. The protocol fees are computed as `takerFee + makerFee`, but the market factory computes the wrong check. Fee pairs that should be accepted are currently not accepted, and, even worse, fee pairs that should be rejected are currently accepted. Market creators can avoid collecting protocol fees this way.

## Recommendation
Implement a `takerFee + makerFee >= minNetFee` check instead:
```solidity
require(int256(uint256(takerFee)) + makerFee >= minNetFee, Errors.INVALID_FEE);
```

## Clober
Fixed in PR 307, PR 308, and PR 311.

## Spearbit
Fixed. Condition has been inverted for the use of custom errors.
```solidity
if (marketHost != owner && int256(uint256(takerFee)) + makerFee < int256(uint256(minNetFee))) {
    revert Errors.CloberError(Errors.INVALID_FEE);
}
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 5: Missing owner check on from when transferring tokens

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Security Report

## Severity: High Risk

### Context
`OrderNFT.sol#L207`

### Description
The `OrderNFT.transferFrom`/`safeTransferFrom` methods use the internal `_transfer` function. While they check approvals on `msg.sender` through `_isApprovedOrOwner(msg.sender, tokenId)`, it is never checked that the specified `from` parameter is actually the owner of the NFT. 

An attacker can decrease other users' NFT balances, making them unable to cancel or claim their NFTs and locking users' funds. The attacker transfers their own NFT passing the victim as `from` by calling `transferFrom(from=victim, to=attackerAccount, tokenId=attackerTokenId)`. This passes the `_isApprovedOrOwner` check but reduces `from`'s balance.

### Recommendation
Add the following check to `_transfer`:

```solidity
require(ownerOf(tokenId) == from, Errors.ACCESS);
```

### Clober
Fixed PR 310.

### Spearbit
Verified. Ownership check added.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 6: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

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

### Example 7: The lower bound for liquidationInitialAsk for new lines needs to be stricter

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `LienToken.sol#L376-L381`
- `AstariaRouter.sol#L516`

## Description
`params.lien.details.liquidationInitialAsk` (`Lnew`) is only compared to `params.amount` (`Anew`) whereas in `_appendStack` `newStack[j].lien.details.liquidationInitialAsk` (`Lj`) is compared to `potentialDebt`. 

`potentialDebt` is the aggregated sum of all potential owed amounts at the end of each position/lien. 

So in `_appendStack` we have:

```
onew + on + ... + oj  ≤ Lj
```

Where `oj` is `getOwed(newStack[j], newStack[j].point.end)`, which is the amount for the stack slot plus the potential interest at the end of its term. 

So it would make sense to enforce a stricter inequality for `Lnew`:

```
(1 + r(tend − tnow) / 10^18) Anew = onew ≤ Lnew
```

The big issue regarding the current lower bound is when the borrower only takes one lien and for this lien `liquidationInitialAsk == amount` (or they are close). Then at any point during the lien term (maybe very close to the end), the borrower can atomically self-liquidate and settle the Seaport auction in one transaction. This way the borrower can skip paying any interest (they would need to pay OpenSea fees and potentially royalty fees) and plus they would receive liquidation fees.

## Recommendation
Make sure the following stricter lower bound is used instead:

```
(1 + r(tend − tnow) / 10^18) Anew = onew ≤ Lnew
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 8: c.lienRequest.strategy.vault is not checked to be a registered vault when commitToLiens is called

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
AstariaRouter.sol#L680-L683

## Description
From when `commitToLiens` is called till when we end up calling `IVaultImplementation(c.lienRequest.strategy.vault).commitToLien( ... )` and after the value of `c.lienRequest.strategy.vault` is not checked whether it is a registered vault within the system (by checking `s.vaults`). The caller can set this value to any address they would desire and potentially perform some unwanted actions.

For example, the user could spoof all the values in commitments so that the later dependent contracts' checks are skipped and lastly we end up transferring funds:

```solidity
s.TRANSFER_PROXY.tokenTransferFrom(
    address(s.WETH),
    address(this), // <--- AstariaRouter
    address(msg.sender),
    totalBorrowed
);
```

Note that since all checks are skipped, the caller can also indirectly set `totalBorrowed` to any value they would desire. And so, if `AstariaRouter` would hold any WETH at any point in time, anyone can craft a payload to `commitToLiens` to drain its WETH balance.

## Recommendation
Check that the value of `s.vaults[c.lienRequest.strategy.vault]` is not `address(0)` before calling `c.lienRequest.strategy.vault`'s `commitToLien` endpoint.

## Astaria
Solved in PR 197.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 9: Can create lien for collateral while at auction by passing spoofed data

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
**File:** LienToken.sol  
**Lines:** 368-372

## Description
In the `createLien` function, we check that the collateral isn't currently at auction before giving a lien with the following check:

```solidity
if (
    s.collateralStateHash[params.collateralId] == bytes32("ACTIVE_AUCTION")
) {
    revert InvalidState(InvalidStates.COLLATERAL_AUCTION);
}
```

However, `collateralId` is passed in multiple places in the `params`: both in `params` directly and in `params.encumber.lien`. 

The `params.encumber.lien.collateralId` is used everywhere else, and is the final value that is used. But the check is performed on `params.collateralId`.

As a result, we can set the following:
- `params.encumber.lien.collateralId`: collateral that is at auction.
- `params.collateralId`: collateral not at auction.

This will allow us to pass this validation while using the collateral at auction for the lien.

## Recommendation
The check should be updated to use `params.encumber.lien.collateralId` instead:

```solidity
if (
    s.collateralStateHash[params.encumber.lien.collateralId] == bytes32("ACTIVE_AUCTION")
) {
    revert InvalidState(InvalidStates.COLLATERAL_AUCTION);
}
```

Additionally, we can remove `collateralId` entirely from the encumber call, as it's inside lien. The fix is to update to use `lien.collateralId` everywhere instead of `encumber.collateralId`.

## Team Consensus
**Astaria:** We can remove `collateralId` entirel

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 10: Refactor _paymentAH()

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

### Example 11: Incorrect auction end validation in liquidatorNFTClaim()

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

### Example 12: Phony signatures can be used to forge any strategy

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**Critical Risk**

## Context
`VaultImplementation.sol#L249`

## Description
In `in_validateCommitment()`, we check that the merkle root of the strategy has been signed by the strategist or delegate. After the signer is recovered, the following check is performed to validate the signature:

```plaintext
recovered != owner() && recovered != s.delegate && recovered != address(0)
```

This check seems to be miswritten, so that any time `recovered == address(0)`, the check passes. Whenever `ecrecover` is used to check the signed data, it returns `address(0)` in the situation that a phony signature is submitted. 

See this example for how this can be done. The result is that any borrower can pass in any merkle root they'd like, sign it in a way that causes `address(0)` to return from `ecrecover`, and have their commitment validated.

## Recommendation
Modify the check to:

```plaintext
if (
- recovered != owner() && recovered != s.delegate && recovered != address(0)
+ (recovered != owner() && recovered != s.delegate) || recovered == address(0)
) {
    revert IVaultImplementation.InvalidRequest(
        InvalidRequestReason.INVALID_SIGNATURE
    );
}
```

## Acknowledgements
- **Astaria**: Fixed in PR 209.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 13: validateStack allows any stack to be used with collateral with no liens

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
LienToken.sol#L225-232

## Description
The `validateStack` modifier is used to confirm that a stack entered by a user matches the `stateHash` in storage. However, the function reverts under the following conditions:

```solidity
if (stateHash != bytes32(0) && keccak256(abi.encode(stack)) != stateHash) {
    revert InvalidState(InvalidStates.INVALID_HASH);
}
```

The result is that any collateral with `stateHash == bytes32(0)` (which is all collateral without any liens taken against it yet) will accept any provided stack as valid. This can be used in a number of harmful ways. Examples of vulnerable endpoints are:

- **createLien**: If we create the first lien but pass a stack with other liens, those liens will automatically be included in the stack going forward, which means that the collateral holder will owe money they didn't receive.
  
- **makePayment**: If we make a payment on behalf of a collateral with no liens, but include a stack with many liens (all owed to me), the result will be that the collateral will be left with the remaining liens continuing to be owed.
  
- **buyoutLien**: Anyone can call `buyoutLien(...)` and provide parameters that are spoofed but satisfy some constraints so that the call would not revert. This is currently possible due to the issue in this context. As a consequence, the caller can:
    - _mint any unminted liens which can DoS the system.
    - _burn lienIds that they don't have the right to remove.
  

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 14: _hasFundableKeys marks operators that have no more fundable validators as fundable.

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
Operators.sol#L151-L152

## Description
Since `operator.keys >= operator.limit` (based on the checks when `operator.keys` has been set), we can simplify `_hasFundableKeys`'s return expression to:

```
operator.active && operator.limit > (operator.funded - operator.stopped)
```

Also based on the assumption that a non-zero `operator.limit` should always be greater than or equal to `operator.funded`, if true:

```
operator.limit >= operator.funded
```

This means an active operator that has at least one stopped validator would pass the test:

```
_hasFundableKeys(operator) == true
```

For example:
```
(stop, funded, limit, keys) = (s, F, L, K) // where s > 0
```

Even operators that have their funded equal to their limit:
```
(stop, funded, limit, keys) = (s, F, F, K) // where s > 0
```

Although they are maxed out for further funding. For these cases, `_hasFundableKeys` returns true. So based on these findings, it would make sense to have this function return:

```
operator.active && (operator.limit > operator.funded)
```

Unless some other changes are applied to `OperatorRegistry.1.sol`, especially its `_getNextValidatorsFromActiveOperators` function.

Also, note that `funded`, `limit`, and `keys` are not only counters for the operator's struct but also they define ranges in `ValidatorKeys` for the operator (based on the way that they have been used in `OperatorRegistry.1.sol`). This is one of the main differences between these three fields

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 15: OperatorsRegistry._getNextValidatorsFromActiveOperators can DOS Alluvial staking if there's anoperator with funded==stopped and funded == min(limit, keys)

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

### Example 16: Add _mirrorConnector to_sendMessage ofBaseMultichain

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## High Risk Report

## Severity: High Risk

### Context
BaseMultichain.sol#L39-L47

### Description
The function `_sendMessage()` of `BaseMultichain` sends the message to the address of the `_amb`. This doesn't seem right as the first parameter is the target contract to interact with according to multichain cross-chain. This should probably be the `_mirrorConnector`.

```solidity
function _sendMessage(address _amb, bytes memory _data) internal {
    Multichain(_amb).anyCall(
        _amb, // Same address on every chain, using AMB as it is immutable
        ...
    );
}
```

### Recommendation
Doublecheck the conclusion and change the code to:

```solidity
- function _sendMessage(address _amb, bytes memory _data) ... {
+ function _sendMessage(address _amb, address _mirrorConnector, bytes memory _data) ... {
    Multichain(_amb).anyCall(
        - _amb,
        + _mirrorConnector
        ...
    );
}
```

### Connext
Solved in PR 2386.

### Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 17: PolygonSpokeConnector orPolygonHubConnector can get compromised and DoSed if an address(0) is passed to their constructor for _mirrorConnector

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `FxBaseChildTunnel.sol#L38-L41`
- `FxBaseRootTunnel.sol#L58-L61`
- `Connector.sol#L119-L121`
- `PolygonSpokeConnector.sol#L78-L82`
- `PolygonHubConnector.sol#L51-L55`

## Description
`PolygonSpokeConnector` (`PolygonHubConnector`) inherits from `SpokeConnector` (`HubConnector`) and `FxBaseChildTunnel` (`FxBaseRootTunnel`). When `PolygonSpokeConnector` (`PolygonHubConnector`) gets deployed and its constructor is called, if `_mirrorConnector` == `address(0)` then setting the `mirrorConnector` storage variable is skipped:

```solidity
// File: Connector.sol#L118-L121
if (_mirrorConnector != address(0)) {
    _setMirrorConnector(_mirrorConnector);
}
```

Now since the `setFxRootTunnel` (`setFxChildTunnel`) is an unprotected endpoint that is not overridden by `PolygonSpokeConnector` (`PolygonHubConnector`), anyone can call it and assign their own `fxRootTunnel` (`fxChildTunnel`) address (note, `fxRootTunnel` (`fxChildTunnel`) is supposed to correspond to `mirrorConnector` on the destination domain).

Note that the `require` statement in `setFxRootTunnel` (`setFxChildTunnel`) only allows `fxRootTunnel` (`fxChildTunnel`) to be set once (non-zero address value) so afterward even the owner cannot update this value. If at some later time the owner tries to call `setMirrorConnector` to assign the `mirrorConnector`, since `_setMirrorConnector` is overridden by `PolygonSpokeConnector` (`PolygonHubConnector`), the following will try to execute:

```soli

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 18: swapInternal() shouldn't use msg.sender

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

### Example 19: [H-02] Non-existing revenue contract can be passed to claimRevenue to send all tokens to treasury

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

### Example 20: Anyone can repay the portalDebt with different tokens

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- **File**: `PortalFacet.sol`
- **Lines**: 80-113, 115-167

## Description
Routers can provide liquidity in the protocol to improve the UX of cross-chain transfers. Liquidity is sent to users under the router’s consent before the cross-chain message is settled on the optimistic message protocol, i.e., Nomad. The router can also borrow liquidity from AAVE if the router does not have enough of it. It is the router’s responsibility to repay the debt to AAVE.

### Code Snippet
```solidity
contract PortalFacet is BaseConnextFacet {
    function repayAavePortalFor(
        address _adopted,
        uint256 _backingAmount,
        uint256 _feeAmount,
        bytes32 _transferId
    ) external payable {
        address adopted = _adopted == address(0) ? address(s.wrapper) : _adopted;
        ...
        // Transfer funds to the contract
        uint256 total = _backingAmount + _feeAmount;
        if (total == 0) revert PortalFacet__repayAavePortalFor_zeroAmount();
        (, uint256 amount) = AssetLogic.handleIncomingAsset(_adopted, total, 0);
        ...
        // repay the loan
        _backLoan(adopted, _backingAmount, _feeAmount, _transferId);
    }
}
```

The `PortalFacet` does not check whether `_adopted` is the correct token in debt. Assume that the protocol borrows ETH for the current `_transferId`; therefore, the Router should repay ETH to clear the debt. However, the Router can provide any valid tokens (e.g., DAI, USDC) to clear the

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 21: Executor andAssetLogic deals with the native tokens inconsistently that breaks execute()

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

### Example 22: swapOut allows overwrite of token balance

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**Critical Risk**

## Context
- **StableSwapFacet.sol**: Lines 266-281
- **SwapUtils.sol**: Lines 740-781, Lines 417-473

## Description
The `StableSwapFacet` has the function `swapExactOut()` where a user could supply the same `assetIn` address as `assetOut`, which means the indexes for `tokenIndexFrom` and `tokenIndexTo` in the function `swapOut()` are the same.

In the function `swapOut()`, a temporary array is used to store balances. When updating these balances, first `self.balances[tokenIndexFrom]` is updated and then `self.balances[tokenIndexTo]` is updated afterward. 

However, when `tokenIndexFrom == tokenIndexTo`, the second update overwrites the first update, causing token balances to be arbitrarily lowered. This also skews the exchange rates, allowing for swaps where value can be extracted.

**Note:** The protection against this problem is located in the function `getY()`. However, this function is not called from `swapOut()`.

**Note:** The same issue exists in `swapInternalOut()`, which is called from `swapFromLocalAssetIfNeededForExactOut()` via `_swapAssetOut()`. However, via this route, it is not possible to specify arbitrary token indexes. Therefore, there isn’t an immediate risk here.

### Code Snippets
```solidity
contract StableSwapFacet is BaseConnextFacet {
    ...
    function swapExactOut(..., address assetIn, address assetOut, ...) ... {
        return s.swapStorages[canonicalId].swapOut(
            getSwapTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 23: SwapManager fails at updating TWAP

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`SwapManagerUniV2.sol#L83-L85`

## Description
The update function returns early without updating the TWAP if the elapsed time is past the TWAP period. Meaning, once the TWAP period passes, the TWAP is stale and forever represents an old value. This could lead to a denial of service attack when claiming rewards as the wrongly calculated expected amount slippage check reverts.

## Recommendation
Fix the code:

```solidity
// ensure that at least one full period has passed since the last update
- if (timeElapsed >= PERIOD) {
+ if (timeElapsed < PERIOD) {
return;
}
```

## Morpho
Fixed in PR #550

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 24: RewardsManagerAave does not verify token addresses

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
`RewardsManagerForAave.sol#L145-L147`

## Description
Aave has 3 different types of tokens: aToken, stable debt token, and variable debt token (a/s/vToken). Aave’s incentive controller can define rewards for all of them, but Morpho never uses a stable-rate borrow token (sToken). 

The public `accrueUserUnclaimedRewards` function allows passing arbitrary token addresses for which to accrue user rewards. Current code assumes that if the token is not the variable debt token, then it must be the aToken, and uses the user’s supply balance for the reward calculation as follows:

```solidity
uint256 stakedByUser = reserve.variableDebtTokenAddress == asset
? positionsManager.borrowBalanceInOf(reserve.aTokenAddress, _user).onPool
: positionsManager.supplyBalanceInOf(reserve.aTokenAddress, _user).onPool;
```

An attacker can accrue rewards by passing in an sToken address and steal from the contract. The steps are as follows:
1. Attacker supplies a large amount of tokens for which sToken rewards are defined.
2. The aToken reward index is updated to the latest index, but the sToken index is not initialized.
3. Attacker calls `accrueUserUnclaimedRewards([sToken])`, which will compute the difference between the current Aave reward index and the user’s sToken index, then multiply it by their supply balance.
4. The user-accumulated rewards in `userUnclaimedRewards[user]` can be withdrawn by calling `PositionManager.claimRewards([sToken, ...])`.
5. Attac

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 25: Non-zero operator.limit should always be greater than or equal to operator.funded

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `OperatorsRegistry.1.sol#L241`
- `OperatorsRegistry.1.sol#L428-L430`

## Description
For the subtraction operation in `OperatorsRegistry.1.sol#L428-L430` to not underflow and revert, there should be an assumption that 

```
operators[selectedOperatorIndex].limit >= operators[selectedOperatorIndex].funded
```

Perhaps this is a general assumption, but it is not enforced when `setOperatorLimits` is called with a new set of limits.

## Recommendation
Add a check in `setOperatorLimits` to enforce that the new limits for the operators are either 0 or in the range `[limit, keys]`.

If these assumptions are not correct, what would having `0 < limit < funded` signify? Also, what would setting the limit to 0 when funded is positive signify?

## Alluvial
Implemented in SPEARBIT/3.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

## Statistics

- Total findings analyzed: 127
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

