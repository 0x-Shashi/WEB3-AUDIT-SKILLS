# Validation Security Patterns (Consolidated)

> **Missing input validation is the easiest bug to exploit and the easiest to prevent.**

---

## Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Missing Zero Check | address(0) or amount=0 not validated | Medium-High |
| Unchecked Return | External call return value ignored | High |
| Array Length Mismatch | Two arrays expected same length | High |
| Bounds Check Missing | Array index out of bounds | High |
| from == to | Self-transfer breaks logic | Medium |
| Bypass Limit | User can exceed intended limits | High |

---

## Detection Strategy

### Zero Address Check
```solidity
// VULNERABLE
function setAdmin(address _admin) external onlyOwner {
    admin = _admin;  // Can be set to address(0)!
}

// SAFE
function setAdmin(address _admin) external onlyOwner {
    require(_admin != address(0), "Zero address");
    admin = _admin;
}
```

### Array Length Validation
```solidity
// VULNERABLE
function batchTransfer(address[] calldata to, uint[] calldata amounts) external {
    for (uint i = 0; i < to.length; i++) {
        transfer(to[i], amounts[i]);  // Reverts if lengths differ
    }
}

// SAFE
function batchTransfer(address[] calldata to, uint[] calldata amounts) external {
    require(to.length == amounts.length, "Length mismatch");
    for (uint i = 0; i < to.length; i++) {
        transfer(to[i], amounts[i]);
    }
}
```

### Return Value Check
```solidity
// VULNERABLE: Ignoring return value
token.transfer(to, amount);  // Might return false!

// SAFE: Check return or use SafeERC20
require(token.transfer(to, amount), "Transfer failed");
// OR
token.safeTransfer(to, amount);
```

### Audit Checklist
- [ ] All address parameters checked for zero
- [ ] All amount parameters checked for zero (if relevant)
- [ ] Array lengths validated when multiple arrays used together
- [ ] External call return values checked
- [ ] from != to validated where relevant
- [ ] Bounds checks on all array accesses
- [ ] User input validated before use in calculations

---

## Included Pattern Files

- validation-patterns.md, data-validation-patterns.md, change-validation-patterns.md
- missing-check-patterns.md, missing-logic-patterns.md
- min-max-cap-validation-patterns.md, minout-maxin-validation-patterns.md
- from-to-patterns.md, bypass-limit-patterns.md

---

## Full Pattern Details

---
## validation-patterns.md
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

This allows anyone to send arbitrary data to `BridgeRouter.sendToHook()`, which is later interpreted as the `transferId` on Connextâ€™s `NomadFacet.sol` contract. This can be abused by a front-running attack as described in the following scenario:

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
onew + on + ... + oj  â‰¤ Lj
```

Where `oj` is `getOwed(newStack[j], newStack[j].point.end)`, which is the amount for the stack slot plus the potential interest at the end of its term. 

So it would make sense to enforce a stricter inequality for `Lnew`:

```
(1 + r(tend âˆ’ tnow) / 10^18) Anew = onew â‰¤ Lnew
```

The big issue regarding the current lower bound is when the borrower only takes one lien and for this lien `liquidationInitialAsk == amount` (or they are close). Then at any point during the lien term (maybe very close to the end), the borrower can atomically self-liquidate and settle the Seaport auction in one transaction. This way the borrower can skip paying any interest (they would need to pay OpenSea fees and potentially royalty fees) and plus they would receive liquidation fees.

## Recommendation
Make sure the following stricter lower bound is used instead:

```
(1 + r(tend âˆ’ tnow) / 10^18) Anew = onew â‰¤ Lnew
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
Routers can provide liquidity in the protocol to improve the UX of cross-chain transfers. Liquidity is sent to users under the routerâ€™s consent before the cross-chain message is settled on the optimistic message protocol, i.e., Nomad. The router can also borrow liquidity from AAVE if the router does not have enough of it. It is the routerâ€™s responsibility to repay the debt to AAVE.

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

**Note:** The same issue exists in `swapInternalOut()`, which is called from `swapFromLocalAssetIfNeededForExactOut()` via `_swapAssetOut()`. However, via this route, it is not possible to specify arbitrary token indexes. Therefore, there isnâ€™t an immediate risk here.

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
Aave has 3 different types of tokens: aToken, stable debt token, and variable debt token (a/s/vToken). Aaveâ€™s incentive controller can define rewards for all of them, but Morpho never uses a stable-rate borrow token (sToken). 

The public `accrueUserUnclaimedRewards` function allows passing arbitrary token addresses for which to accrue user rewards. Current code assumes that if the token is not the variable debt token, then it must be the aToken, and uses the userâ€™s supply balance for the reward calculation as follows:

```solidity
uint256 stakedByUser = reserve.variableDebtTokenAddress == asset
? positionsManager.borrowBalanceInOf(reserve.aTokenAddress, _user).onPool
: positionsManager.supplyBalanceInOf(reserve.aTokenAddress, _user).onPool;
```

An attacker can accrue rewards by passing in an sToken address and steal from the contract. The steps are as follows:
1. Attacker supplies a large amount of tokens for which sToken rewards are defined.
2. The aToken reward index is updated to the latest index, but the sToken index is not initialized.
3. Attacker calls `accrueUserUnclaimedRewards([sToken])`, which will compute the difference between the current Aave reward index and the userâ€™s sToken index, then multiply it by their supply balance.
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


---
## data-validation-patterns.md
# Data Validation Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Cyfrin, TrailOfBits

---

## Detection Checklist

- [ ] Check for data validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-5: Users can get around MaxLTV because of lack of strategyId validation

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/129 

## Found by 
8olidity, carrot, Jeiwan, obront, Ch\_301, cergyk, rbserver

## Summary

When a user withdraws some of their underlying token, there is a check to ensure they still meet the Max LTV requirements. However, they are able to arbitrarily enter any `strategyId` that they would like for this check, which could allow them to exceed the LTV for their real strategy while passing the approval.

## Vulnerability Detail

When a user calls `IchiVaultSpell.sol#reducePosition()`, it removes some of their underlying token from the vault, increasing the LTV of any loans they have taken.

As a result, the `_validateMaxLTV(strategyId)` function is called to ensure they remain compliant with their strategy's specified LTV:
```solidity
function _validateMaxLTV(uint256 strategyId) internal view {
    uint256 debtValue = bank.getDebtValue(bank.POSITION_ID());
    (, address collToken, uint256 collAmount, , , , , ) = bank
        .getCurrentPositionInfo();
    uint256 collPrice = bank.oracle().getPrice(collToken);
    uint256 collValue = (collPrice * collAmount) /
        10**IERC20Metadata(collToken).decimals();

    if (
        debtValue >
        (collValue * maxLTV[strategyId][collToken]) / DENOMINATOR
    ) revert EXCEED_MAX_LTV();
}
```
To summarize, this check:
- Pulls the position's total debt value
- Pulls the position's total value of underlying tokens
- Pulls the specified maxLTV for this strate

*[Content truncated...]*

---

### Example 2: Possible overflow in `_payOutFirstInQueue`

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `_payOutFirstInQueue()`, possible revert during `operatorTokenToDataInverse()`.

```solidity
uint amountOperatorTokens = moduleCall(address(exchangeRatePolicy), abi.encodeWithSelector(exchangeRatePolicy.operatorTokenToDataInverse.selector, amountDataWei));
```

If a delegator calls `undelegate()` with `type(uint256).max`, `operatorTokenToDataInverse()` will revert due to uint overflow and the queue logic will be broken forever.

```solidity
   function operatorTokenToDataInverse(uint dataWei) external view returns (uint operatorTokenWei) {
       return dataWei * this.totalSupply() / valueWithoutEarnings();
   }
```

**Impact:** The queue logic will be broken forever because `_payOutFirstInQueue()` keeps reverting.

**Recommended Mitigation:** We should cap `amountDataWei` before calling `operatorTokenToDataInverse()`.

**Client:** Fixed in commit [c62e5d9](https://github.com/streamr-dev/network-contracts/commit/c62e5d90ce8f8c084fe3917f499c967c85a3873b).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 3: Missing check of return value of transfer and transferFrom

**Source**: TrailOfBits
**Protocol**: Frax Solidity
**Impact**: HIGH

**Details**:

## Frax Solidity Security Assessment

## Difficulty: Medium

## Type: Undefined Behavior

## Target: TWAMM.sol

### Description
Some tokens, such as BAT, do not precisely follow the ERC20 specification and will return
false or fail silently instead of reverting. Because the codebase does not consistently use
OpenZeppelinâ€™s SafeERC20 library, the return values of calls to `transfer` and
`transferFrom` should be checked. However, return value checks are missing from these
calls in many areas of the code, opening the TWAMM contract (the time-weighted automated
market maker) to severe vulnerabilities.

```solidity
function provideLiquidity(uint256 lpTokenAmount) external {
    require(totalSupply() != 0, 'EC3');
    // execute virtual orders
    longTermOrders.executeVirtualOrdersUntilCurrentBlock(reserveMap);
    // the ratio between the number of underlying tokens and the number of lp tokens
    // must remain invariant after mint
    uint256 amountAIn = lpTokenAmount * reserveMap[tokenA] / totalSupply();
    uint256 amountBIn = lpTokenAmount * reserveMap[tokenB] / totalSupply();
    ERC20(tokenA).transferFrom(msg.sender, address(this), amountAIn);
    ERC20(tokenB).transferFrom(msg.sender, address(this), amountBIn);
}
```
*Figure 20.1: contracts/FPI/TWAMM.sol#L125-136*

### Exploit Scenario
Frax deploys the TWAMM contract. Pools are created with tokens that do not revert on
failure, allowing an attacker to call `provideLiquidity` and mint LP tokens for free; the
attacker does 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/FraxQ42021.pdf)

---

### Example 4: [M-01] EIP-712 signatures can be re-used in private sales

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by thankthedark, also found by Afanasyevich and cmichel_

[NFTMarketPrivateSale.sol#L123-L174](https://github.com/code-423n4/2022-02-foundation/blob/main/contracts/mixins/NFTMarketPrivateSale.sol#L123-L174)<br>

Within a NFTMarketPrivateSale contract, buyers are allowed to purchase a seller's NFT. This is done through a seller providing a buyer a EIP-712 signature. The buyer can then call `#buyFromPrivateSaleFor` providing the v, r, and s values of the signature as well as any additional details to generate the message hash. If the signature is valid, then the NFT is transferred to the buyer.

The problem with the code is that EIP-712 signatures can be re-used within a small range of time assuming that the original seller takes back ownership of the NFT. This is because the NFTMarketPrivateSale#buyFromPrivateSaleFor method has no checks to determine if the EIP-712 signature has been used before.

### Proof of Concept

Consider the following example:

1.  Joe the NFT owner sells a NFT to the malicious buyer Rachel via a private sale.
2.  Rachel through this private sale obtains the EIP-712 signature and uses it to purchase a NFT.
3.  Joe the NFT owner purchases back the NFT within two days of the original sale to Rachel.
4.  Joe the NFT owner puts the NFT back on sale.
5.  Rachel, who has the original EIP-712 signature, can re-purchase the NFT by calling `#buyFromPrivateSaleFor` again with the same parameters they provided in the original private sale purchase in st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-foundation)

---

### Example 5: M-12: Chainlink's latestRoundData  return stale or incorrect result

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94 

## Found by 
8olidity, tsvetanovv, WatchDogs, Nyx, Avci, obront, Aymen0909, SPYBOY, HonorLt, csanuragjain, koxuan, evan, rbserver, hl\_, peanuts, Chinmay

## Summary
https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/oracle/ChainlinkAdapterOracle.sol#L76

## Vulnerability Detail

## Impact
On ChainlinkAdapterOracle.sol, you are using latestRoundData, but there is no check if the return value indicates stale data. 
```solidity
function getPrice(address _token) external view override returns (uint256) {
        // remap token if possible
        address token = remappedTokens[_token];
        if (token == address(0)) token = _token;

        uint256 maxDelayTime = maxDelayTimes[token];
        if (maxDelayTime == 0) revert NO_MAX_DELAY(_token);

        // try to get token-USD price
        uint256 decimals = registry.decimals(token, USD);
        (, int256 answer, , uint256 updatedAt, ) = registry.latestRoundData(
            token,
            USD
        );
        if (updatedAt < block.timestamp - maxDelayTime)
            revert PRICE_OUTDATED(_token);

        return (answer.toUint256() * 1e18) / 10**decimals;
    }
```
This could lead to stale prices according to the Chainlink documentation:
https://docs.chain.link/data-feeds/price-feeds/historical-data
Related report:
https://github.com/code-423n4/2021-05-fairside-findings/issues/70

## Code Snippet
https://github.com/sh

*[Content truncated...]*

---

### Example 6: [M-09] There is no mechanism that prevents from minting less than `esLBR` maximum supply in `StakingRewardsV2`

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/token/esLBR.sol#L30-L32> <br><https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/token/esLBR.sol#L20> <br><https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/miner/ProtocolRewardsPool.sol#L73-L77>

### Vulnerability details

I'm assuming that esLBR is distributed as a reward in `StakingRewardsV2` - it's not clear from the docs. But `rewardsToken` is of type `IesLBR` and in order to calculate boost for rewards `esLBRBoost` contract is used, so I think that it's a reasonable assumption.

The esLBR token has a total supply of `100 000 000` and this is enforced in the `esLBR` contract:

```solidity
function mint(address user, uint256 amount) external returns (bool) {
        require(configurator.tokenMiner(msg.sender), "not authorized");
        require(totalSupply() + amount <= maxSupply, "exceeding the maximum supply quantity.");
```

However, the `StakingRewardsV2` contract which is approved to mint new esLBR tokens doesn't enforce that new tokens can always be minted.

Either due to admin mistake (it's possible to call `StakingRewardsV2::notifyRewardAmount` with arbitrarily high `_amount`, which is not validated; it's also possible to set `duration` to an arbitrarily low value, so `rewardRatio` may be very high), or by normal protocol functioni

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 7: H-8: UserData for balancer pool exits is malformed and will permanently trap users

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

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## change-validation-patterns.md
# Change Validation Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Halborn, Hans

---

## Detection Checklist

- [ ] Check for change validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-11: priceLiquidity() may not work if PriceFeed.aggregator() is updated

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/145 

## Found by 
cccz

## Summary
priceLiquidity() may not work if PriceFeed.aggregator() is updated
## Vulnerability Detail
In the constructor of the DepositReceipt_* contract, the value of minAnswer/maxAnswer in priceFeed.aggregator() is obtained and assigned to *MinPrice/*MaxPrice as the maximum/minimum price limit when calling the getOraclePrice function in priceLiquidity, and *MinPrice/*MaxPrice can not change.
```solidity
        IAccessControlledOffchainAggregator  aggregator = IAccessControlledOffchainAggregator(priceFeed.aggregator());
        //fetch the pricefeeds hard limits so we can be aware if these have been reached.
        tokenMinPrice = aggregator.minAnswer();
        tokenMaxPrice = aggregator.maxAnswer();
...
            uint256 oraclePrice = getOraclePrice(priceFeed, tokenMaxPrice, tokenMinPrice);
...
    function getOraclePrice(IAggregatorV3 _priceFeed, int192 _maxPrice, int192 _minPrice) public view returns (uint256 ) {
        (
            /*uint80 roundID*/,
            int signedPrice,
            /*uint startedAt*/,
            uint timeStamp,
            /*uint80 answeredInRound*/
        ) = _priceFeed.latestRoundData();
        //check for Chainlink oracle deviancies, force a revert if any are present. Helps prevent a LUNA like issue
        require(signedPrice > 0, "Negative Oracle Price");
        require(timeStamp >= block.timestamp - HEARTBEAT_TIME , "Stale pricefe

*[Content truncated...]*

---

### Example 2: M-2: Expired locks should not continue to earn rewards at the original high multiplier rate

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/108 

## Found by 
WATCHPUG

## Summary

Expired locks should be considered as same as the deposits with no lock.

## Vulnerability Detail

The current implementation allows the deposits with expired locks to continue to enjoy the original high multiplier rate, while they can withdraw anytime they want.

The multiplier of shares amount is essentially a higher reward rate (APR) for longer period of locks.

For example:

If the regular APR is 2%; Locking for 4 years will boost the APR to 10%.

- Alice deposited 1M $MC tokens and got 10% APR;
- 4 years later, Alice's deposit's lock was expired.

Expected result:

The new APR for Alice's deposit is 2%;

Actual result:

Alice can continue to enjoy a 10% APR while she can withdraw anytime.

## Impact

Users with expired locks will take more rewards than expected, which means fewer rewards for other users.

## Code Snippet

https://github.com/Merit-Circle/merit-liquidity-mining/blob/ce5feaae19126079d309ac8dd9a81372648437f1/contracts/TimeLockPool.sol#L116-L135

## Tool used

Manual Review

## Recommendation

Curve's Gauge system introduced a method called `kick()` which allows the expired (zeroed) veCRV users to be kicked from the rewards.

See: https://github.com/curvefi/curve-dao-contracts/blob/master/contracts/gauges/LiquidityGaugeV5.vy#L430-L446

A similar method can be added to solve this issue:

```solidity
function kick(uint256 _depositId, address _u

*[Content truncated...]*

---

### Example 3: NON-STANDARD ERC20 TOKENS WILL REVERT

**Source**: Halborn
**Protocol**: Primex Contracts
**Impact**: MEDIUM

**Details**:

##### Description

The library `TokenTransfersLibrary.sol` contains the function to perform ERC20 tokens transfers in the protocol. However, this library uses the interface of `IERC20` from OpenZeppelin which enforces the return value on transfer.

This pattern is not followed by all ERC20 tokens, as for example USDT. If attempting to transfer these tokens, the contract will revert, preventing the transaction to be executed.

Code Location
-------------

[TokenTransfersLibrary.sol#L12-L19](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L12-L19)

#### TokenTransfersLibrary.sol

```
function doTransferFromTo(address token, address from, address to, uint256 amount) public returns (uint256) {
    uint256 balanceBefore = IERC20(token).balanceOf(to);
    // The returned value is checked in the assembly code below.
    // Arbitrary `from` should be checked at a higher level. The library function cannot be called by the user.
    // slither-disable-next-line unchecked-transfer arbitrary-send-erc20
    IERC20(token).transferFrom(from, to, amount);

    bool success;

```

[TokenTransfersLibrary.sol#L46-L51](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L46-L51)

#### TokenTransfersLibrary.sol

```
function doTransferOut(address token, address to, uint256 amount) public {
    // The retur

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/primex/primex-contracts)

---

### Example 4: H-6: Outstanding loans cannot be closed or liquidated if collateral is paused

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/57 

## Found by 
0x52, HonorLt

## Summary

When a collateral is paused by governance, `collateralValid` is set to false. This causes closing and liquidating of loans to be impossible, leading to two issues. The first is that users with exist loans are unable to close their loans to recover their collateral. The second is that since debt is impossible to liquidate the protocol could end up being stuck with a lot of bad debt.

## Vulnerability Detail

    function pauseCollateralType(
        address _collateralAddress,
        bytes32 _currencyKey
        ) external collateralExists(_collateralAddress) onlyAdmin {
        require(_collateralAddress != address(0)); //this should get caught by the collateralExists check but just to be careful
        //checks two inputs to help prevent input mistakes
        require( _currencyKey == collateralProps[_collateralAddress].currencyKey, "Mismatched data");
        collateralValid[_collateralAddress] = false;
        collateralPaused[_collateralAddress] = true;
    }

When a collateral is paused `collateralValid[_collateralAddress]` is set to `false`. For `Vault_Lyra` `Vault_Synths` and `Vault_Velo` this will cause `closeLoan` and `callLiquidation` to revert. This traps existing users and prevents liquidations which will result in bad debt for the protocol

## Impact

Outstanding loans cannot be closed or liquidated, freezing user funds and causing the protocol

*[Content truncated...]*

---

### Example 5: M-11: Delisted assets can still be deposited and borrowed against by accounts that already have them

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/154-M 
## Found by 
0x52, Kumpa, devtooligan, WATCHPUG

## Summary

Delisting an asset does not prevent accounts, that already contain the asset from depositing more. It blocks the deposit function but users can sidestep but sending tokens directly to their account

## Vulnerability Detail

AccountManger.sol#deposit attempts to block deposits from assets that are not on the list of supported collateral. When calculating the health of the account, the total balance of the account address is considered. An account that already has the asset on it's assets list doesn't need to use AccountManger.sol#deposit because they can transfer the tokens directly to the account contract. This means that these account can continue to add to and use delisted assets as collateral.

## Impact

One of two scenarios depending on actions taken by the protocol. If the asset is delisted from accountManager.sol and the oracle is removed then all users with loans taken against the asset will likely be immediately liquidated, which is highly unfair to users. If the asset is just delisted from accountManager.sol then existing users that already have the asset would be able to continue using the asset to take loans. If the reason an asset is being delisted is to prevent a vulnerability then the exploit would still be able to happen due to these accounts sidestepping deposit restrictions.

## Code Snippet

[AccountManager.sol#L1

*[Content truncated...]*

---

### Example 6: Admin level vulnerabilities

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`IDO.sol#L66-69`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L66-69)

**Description:**
Numerous admin functions do not check the validity of the input parameters.

- Many setter functions that set token addresses do not validate zero address (e.g. `MetaManager::setTokens`)
- `IDO::setClaimTime` - time validation
- `MetaManager::setMaxExitCycle` - use strict inequality to prevent DOS unstaking

Also some functions are not necessary and can lead to unintentional situations.

- `IDO::setPrice` - According to the documentation, the floor price is kept as constant but the current implementation allow the owner to change the price to any value.

Although we assume the admin is trusted, these issues can lead to unexpected loss by a mistake of an admin.

**Impact**
The admin can change the protocolâ€™s behavior in unexpected ways.

**Recommendation:**
Add necessary validations to the admin functions and remove unnecessary functions.

**Meta Team:**

Fixed. In the commit :007c1b9183cdb65a500928173608ebff0a5197ef.
Actions include require statments and also to remove unnecessary functions.

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## missing-check-patterns.md
# Missing Check Security Patterns

## Overview

**Frequency**: 23 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 14 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Cyfrin, Codehawks

---

## Detection Checklist

- [ ] Check for missing check vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] A malicious user can avoid unfavorable score updates after alpha/multiplier changes, resulting in accrual of outsized rewards for the attacker at the expense of other users

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L397-L405> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L704-L756> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L623-L639> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L827-L833> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L200-L219> 

<https://github.com/code-423n4/2023-09-venus/blob/main/tests/hardhat/Prime/Prime.ts#L294-L301>

Please note: All functions/properties referred to are in the `Prime.sol` contract.

### Impact

A malicious user can accrue outsized rewards at the expense of other users after `updateAlpha()` or `updateMultipliers()` is called.

### Proof of Concept

An attacker can prevent their score from being updated and decreased after the protocol's alpha or multipliers change. This is done by manipulatively decreasing the value of `pendingScoreUpdates`, then ensuring that only other user scores are updated until `pendingScoreUpdates` reaches zero, at which point calls to `updateScores()` will revert with the error `NoScoreUpdatesRequired()`. This can be done via the attacker calling `updateScores()` to update other users' scores first and/or DoSing calls to `updateScores()` that would update the attacker's score (see the issue titled "DoS and gas griefing of Prime.updateScores()").

The core of 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-venus)

---

### Example 2: [H-03] Poor detection of disputed trees allows claiming tokens from a disputed tree

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: HIGH

**Details**:

<https://github.com/AngleProtocol/merkl-contracts/blob/1825925daef8b22d9d6c0a2bc7aab3309342e786/contracts/Distributor.sol#L200>

Users can claim rewards from a Merkle tree that's being disputed. This can potentially lead to loss of funds since a malicious trusted EOA can claim funds from a malicious tree while it's being disputed.

### Proof of Concept

The [Distribution.getMerkleRoot](https://github.com/AngleProtocol/merkl-contracts/blob/1825925daef8b22d9d6c0a2bc7aab3309342e786/contracts/Distributor.sol#L199) function is used to get the current Merkle root during claiming. The function is aware of the dispute period of the current root and returns the previous root if the current tree is still in the dispute period.

However, the function doesn't take into account the situation when:

1.  a tree was disputed (i.e. [the disputer address is set](https://github.com/AngleProtocol/merkl-contracts/blob/1825925daef8b22d9d6c0a2bc7aab3309342e786/contracts/Distributor.sol#L237));
2.  and the dispute period has finished (i.e. when `block.timestamp >= endOfDisputePeriod`).

Such situations can happen realistically when a tree is disputed closer to the end of its dispute period and/or when the governor/guardian takes longer time to resolve the dispute. In such situations, the dispute period checks in the above functions will pass, however the `disputer` address will be set, which means that the tree is being disputed and shouldn't be used in claims.

As an example exploit scenario, a mal

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 3: [H-04] If insider deposits and unlocks in quick succession, attacker can steal their NFT and their deposit funds

**Source**: ZachObront
**Protocol**: Dyad
**Impact**: HIGH

**Details**:

The dNFT contract allows the owner to mint a predefined quantity of "insider" NFTs without any deposit attached to them. These NFTs begin in a locked state, which stops them from being immediately liquidated due to their lack of deposits.

The protocol enforces that, in order for insider's to mint any DYAD, they must unlock their NFTs (so that they will be subject to liquidation, like all other users).

However, there is no safety check for the opposite case, where an insider unlocks their NFT before making a deposit. In this situation, any user could liquidate them and steal their NFT.

This is especially dangerous because if a user calls both of these functions in quick succession, they may both be in the mempool at the same time. If this is the case, a malicious attacker can create a flashbots bundle to sandwich their liquidation transaction between the unlock() and deposit() transactions, with the result that:

- The attacker will successfully liquidate and steal the insider's NFT
- The deposit transaction will deposit the insider's ETH to the stolen NFT, securing it for the attacker

**Recommendation**

I would recommend adding a check to the unlock() function to ensure this situation is avoided:

```solidity
function unlock(uint id)
external
isNftOwner(id)
{
if (!id2Locked[id]) revert NotLocked();
if (id2Shared[id] == 0) revert MustDepositFirst();
id2Locked[id] = false;
emit Unlocked(id);
}
```

Note: This requires adding a MustDepositFirst() error to IDNft.sol.

**Revi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-02-12-Dyad.md)

---

### Example 4: H-1: Can steal gOhm by calling Clearinghouse.claimDefaulted on loans not made by Clearinghouse

**Source**: Sherlock
**Protocol**: Cooler Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-08-cooler-judging/issues/28 

## Found by 
detectiveking, jkoppel, mert\_eren

`Clearinghouse.claimDefaulted` assumes that all loans passed in were originated by the Clearinghouse. However, nothing guarantees that. An attacker can wreak havoc by calling it with a mixture of Clearinghouse-originated and external loans. In particular, they can inflate the computed `totalCollateral` recovered to steal excess gOhm from defaulted loans.

## Vulnerability Detail

1. Alice creates a Cooler. 9 times, she calls `requestLoan` (not through the Clearinghouse) to request a loan of 0.000001 DAI collateralized by 2 gOhm. For each loan, she then calls `clearLoan` and loans the 0.000001 DAI to herself.
1. One week later, Bob calls `Clearinghouse.lendToCooler` and takes a loan for 3000 DAI collateralized by 1 gOHM
3. Alice defaults on the loans she made to herself and waits 7 days
4. Bob defaults on his loan
5. Alice calls `Clearinghouse.claimDefaulted`, passing in both her loans to herself and Bob's loan from the Clearinghouse. `Clearinghouse.claimDefaulted` calls `Cooler.claimDefaulted` on each, returning 18 gOhm to Alice and 1 gOhm to the Clearinghouse.
6. For each of Alice's loan, the keeper reward is incremented by the max award of 0.1 gOhm. For Bob's loan, the keeper reward is incremented by somewhere between 0 and 0.05 gOhm,  depending on how much time has elapsed since Bob's loan defaulted. 
8. The keeper reward is transferred to Alice. Al

*[Content truncated...]*

---

### Example 5: H-1: MarginTrading.sol: Missing flash loan initiator check allows attacker to open trades, close trades and steal funds

**Source**: Sherlock
**Protocol**: DODO Margin Trading
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-dodo-judging/issues/34 

## Found by 
0xHati, BAHOZ, Bauer, BowTiedOriole, CRYP70, Jiamin, Juntao, Quantish, Tendency, VAD37, alexzoid, carrotsmuggler, circlelooper, curiousapple, nobody2018, oot2k, pengun, qbs, roguereddwarf, rvierdiiev, sashik\_eth, shaka, shogoki, smiling\_heretic, theOwl
## Summary
The `MarginTrading.executeOperation` function is called when a flash loan is made (and it can only be called by the `lendingPool`).

The wrong assumption by the protocol is that the flash loan can only be initiated by the `MarginTrading` contract itself.

However this is not true. A flash loan can be initiated for any `receiverAddress`.

This is actually a known mistake that devs make and the aave docs warn about this (although admittedly the warning is not very clear):
https://docs.aave.com/developers/v/2.0/guides/flash-loans

![2023-05-11_12-43](https://github.com/sherlock-audit/2023-05-dodo-roguereddwarf/assets/118631472/1bc59eb4-407b-4b5f-a38b-9c415932caf1)

So an attacker can execute a flash loan with the `MarginTrading` contract as `receiverAddress`. Also the funds that are needed to pay back the flash loan are pulled from the `receiverAddress` and NOT from the `initiator`:

https://github.com/aave/protocol-v2/blob/30a2a19f6d28b6fb8d26fc07568ca0f2918f4070/contracts/protocol/lendingpool/LendingPool.sol#L532-L536

This means the attacker can close a position or repay a position in the `MarginTrading` contract.

By crafting a

*[Content truncated...]*

---

### Example 6: [M-02] `pause/unpause` functionalities not implemented in many pausable contracts

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/SocializingPool.sol#L21> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/Auction.sol#L14> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L17><br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/OperatorRewardsCollector.sol#L16>

The following contracts: `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` are supposed to be pausable (as they all inherit from `PausableUpgradeable`), but they don't implement the external `pause/unpause` functionalities which means it will never be possible to pause them.

### Proof of Concept

All the following contracts `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` inherit from the openzeppelin `PausableUpgradeable` extension which means that they contain internal functions `_pause` and `_unpause`.

Because those functions are internal, the contract must implement two other public/external `pause` and `unpause` functions to allow the manager to pause and unpause the contracts when necessary. None of the aforementioned contracts implement those functions, which means even if those contracts are supposed to be pausable (and have the `pause/unpause` functionalities), none of them can be paused.

### Recommended Mitigation Steps

Add public/external `pause` and `unpause` functions in the aforementioned contracts to allow them to be pausable, this can be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 7: [M-03] User can lock tokens from the TemporaryHolding for an "infinite" amount of time

**Source**: Pashov Audit Group
**Protocol**: Subsquid
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium, admin won't be able to retrieve tokens after lock time has passed

**Likelihood:** Medium, attacker needs to be a temporary holding beneficiary

## Description

`TemporaryHoldings.sol` allows the `beneficiary` address to use tSQD in the whitelisted protocol contracts for a limited amount of time

```solidity
  function execute(address to, bytes calldata data, uint256 requiredApprove) public returns (bytes memory) {
    require(_canExecute(msg.sender), "Not allowed to execute");
    require(router.networkController().isAllowedVestedTarget(to), "Target is not allowed");

    // It's not likely that following addresses will be allowed by network controller, but just in case
    require(to != address(this), "Cannot call self");
    require(to != address(tSQD), "Cannot call tSQD");

    if (requiredApprove > 0) {
      tSQD.approve(to, requiredApprove);
    }
    return to.functionCall(data);
  }
```

after `lockedUntil` amount of time has passed `admin` regains control over the funds inside

```solidity
  function _canExecute(address executor) internal view override returns (bool) {
    if (block.timestamp < lockedUntil) {
      return executor == beneficiary;
    }
    return executor == admin;
  }
```

One of the whitelisted targets is the `GatewayRegistry`. A savvy beneficiary can stake tokens from `TemporaryHolding` for a time far in the future and enjoy boosted CU, while admin cannot unstake these tokens even after `lockedUntil`

```solidity


*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Subsquid-security-review.md)

---

### Example 8: M-3: Repaying loans with small amounts of debt tokens can lead to underflowing in the `roll` function

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/263 

## Found by 
tsvetanovv, rvierdiiev, ck, zaskoh, Allarious, Trumpero, Breeje, berndartmueller, jonatascm, Deivitto

## Summary

Due to precision issues when repaying a loan with small amounts of debt tokens, the `loan.amount` can be reduced whereas the `loan.collateral` remains unchanged. This can lead to underflowing in the `roll` function.

## Vulnerability Detail

The `decollateralized` calculation in the `repay` function rounds down to zero if the `repaid` amount is small enough. This allows iteratively repaying a loan with very small amounts of debt tokens without reducing the collateral.

The consequence is that the `roll` function can revert due to underflowing the `newCollateral` calculation once the `loan.collateral` is greater than `collateralFor(loan.amount, req.loanToCollateral)` (`loan.amount` is reduced by repaying the loan)

As any ERC-20 tokens with different decimals can be used, this precision issue is amplified if the decimals of the collateral and debt tokens differ greatly.

## Impact

The `roll` function can revert due to underflowing the `newCollateral` calculation if the `repay` function is (iteratively) called with small amounts of debt tokens.

## Code Snippet

[Cooler.sol#L114](https://github.com/sherlock-audit/2023-01-cooler/blob/main/src/Cooler.sol#L114)

```solidity
function repay (uint256 loanID, uint256 repaid) external {
    Loan storage loan = loans[loanID];

    if

*[Content truncated...]*

---

### Example 9: [M-02] Soft Restricted Staker Role can withdraw stUSDe for USDe

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

A requirement is stated that a user with the `SOFT_RESTRICTED_STAKER_ROLE` is not allowed to withdraw `USDe` for `stUSDe`.

The code does not satisfy that condition, when a holder has the `SOFT_RESTRICTED_STAKER_ROLE`, they can exchange their `stUSDe` for `USDe` using `StakedUSDeV2`.

### Description

The Ethena readme has the following decription of legal requirements for the Soft Restricted Staker Role: <br><https://github.com/code-423n4/2023-10-ethena/blob/ee67d9b542642c9757a6b826c82d0cae60256509/README.md?plain=1#L98>

    Due to legal requirements, there's a `SOFT_RESTRICTED_STAKER_ROLE` and `FULL_RESTRICTED_STAKER_ROLE`. 
    The former is for addresses based in countries we are not allowed to provide yield to, for example USA. 
    Addresses under this category will be soft restricted. They cannot deposit USDe to get stUSDe or withdraw stUSDe for USDe. 
    However they can participate in earning yield by buying and selling stUSDe on the open market.

In summary, legal requires are that a `SOFT_RESTRICTED_STAKER_ROLE`:

*   MUST NOT deposit USDe to get stUSDe
*   MUST NOT withdraw USDe for USDe
*   MAY earn yield by trading stUSDe on the open market

As `StakedUSDeV2` is a `ERC4626`, the `stUSDe` is a share on the underlying `USDe` asset. There are two distinct entrypoints for a user to exchange their share for their claim on the underlying the asset, `withdraw` and `redeem`. Each cater for a different input (`withdraw` being by asset, `redeem` being by share), however

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

### Example 10: [M-01] LibHelpers.piecewiseLinear will revert when the value is less than the first element of the array

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/facets/Redeemer.sol#L156-L157> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibSetters.sol#L230-L240> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibHelpers.sol#L77-L80>

`LibHelpers.piecewiseLinear` reverts when the value is less than the first element of the array. This method is used in Redeemer contract and if the collateral ratio is below the first element of xRedemptionCurve, the redepmtion will revert.

### Proof of Concept

In `Redeemer._quoteRedemptionCurve`, a penalty factor is applied when the protocol is under-collateralized using `LibHelpers.piecewiseLinear`.

Redeemer.sol#L156-L157

```solidity
        uint64[] memory xRedemptionCurveMem = ts.xRedemptionCurve;
        penaltyFactor = uint64(LibHelpers.piecewiseLinear(collatRatio, xRedemptionCurveMem, yRedemptionCurveMem));
```

`xRedemptionCurveMem` is strictly increasing and upper bounded by `BASE_9`, and there's no more limitations.

LibSetters.sol

```solidity
230        (action == ActionType.Redeem && (xFee[n - 1] > BASE_9 || yFee[n - 1] < 0 || yFee[n - 1] > int256(BASE_9)))
           
233        for (uint256 i = 0; i < n - 1; ++i) {
234            if (
           
240                (action == ActionType.Redeem && (xFe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 11: [H-01] Missing user input validation can lead to stuck funds

**Source**: Pashov Audit Group
**Protocol**: Baton Launchpad
**Impact**: HIGH

**Details**:

**Severity**

**Impact:**
High, as all mint fees can be stuck forever

**Likelihood:**
Medium, as users can easily misconfigure inputs

**Description**

There are multiple insufficiencies in the input validation of the arguments of the `initialize` method in `Nft`:

1. The sum of the `supply` of all `categories_` can be less than the `maxMintSupply_` - this would lead to the mint never completing, which results in all of the ETH in the `Nft` contract coming from mints so far being stuck in it forever
2. The `duration` of the `vestingParams_` should have a lower and upper bound as for example a too big of a duration can mean vesting can never complete or a division rounding error
3. The `mintEndTimestamp` of `refundParams_` should not be too further away in the future otherwise refund & vesting mechanisms would never work, and if it is too close then the mint mechanism won't work.

**Recommendations**

Add a validation that the sum of all categories' supply is more than or equal to the `maxMintSupply`. Also add sensible upper and lower bounds for both `duration` for the vesting mechanism and `mintEndTimestamp` for the refund mechanism.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-07-01-Baton Launchpad.md)

---

### Example 12: [H-01] Attacker can call sweepRewardToken() when `bribesProcessor==0` and reward funds will be lost because there is no check in sweepRewardToken() and _handleRewardTransfer() and _sendTokenToBribesProcessor()

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by unforgiven, also found by GimelSec, and zzzitron_

<https://github.com/Badger-Finance/vested-aura/blob/d504684e4f9b56660a9e6c6dfb839dcebac3c174/contracts/MyStrategy.sol#L107-L113>

<https://github.com/Badger-Finance/vested-aura/blob/d504684e4f9b56660a9e6c6dfb839dcebac3c174/contracts/MyStrategy.sol#L405-L413>

<https://github.com/Badger-Finance/vested-aura/blob/d504684e4f9b56660a9e6c6dfb839dcebac3c174/contracts/MyStrategy.sol#L421-L425>

### Impact

If the value of `bribesProcessor` was `0x0` (the default is `0x0` and `governance()`  can set to `0x0`) then attacker can call `sweepRewardToken()` make contract to send his total balance in attacker specified token to `0x0` address.

### Proof of Concept

The default value of `bribesProcessor` is `0x0` and `governance` can set the value to `0x0` at any time. Rewards are stacking in contract address and they are supposed to send to `bribesProcessor`.

This is `sweepRewardToken()` and `_handleRewardTransfer()` and `_sendTokenToBribesProcessor()` code:

      /// @dev Function to move rewards that are not protected
      /// @notice Only not protected, moves the whole amount using _handleRewardTransfer
      /// @notice because token paths are hardcoded, this function is safe to be called by anyone
      /// @notice Will not notify the BRIBES_PROCESSOR as this could be triggered outside bribes
      function sweepRewardToken(address token) public nonReentrant {
          _onlyGovernanceOrStrategist();
          _onlyNot

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-badger)

---

### Example 13: M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

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

### Example 14: M-3: Blocklisted address can be used to lock the option token minter's fund

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/81 

## Found by 
Vagner, berndartmueller, bin2chen, caventa, ctf\_sec
## Summary

Blocklisted address can be used to lock the option token minter's fund

## Vulnerability Detail

When deploy a token via the teller contract, the contract validate that [receiver address is not address(0)](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L139)

However, a malicious option token creator can save a seemingly favorable strike price and pick a blocklisted address and set the blocklisted address as receiver

https://github.com/d-xo/weird-erc20#tokens-with-blocklists

> Some tokens (e.g. USDC, USDT) have a contract level admin controlled address blocklist. If an address is blocked, then transfers to and from that address are forbidden.

> Malicious or compromised token owners can trap funds in a contract by adding the contract address to the blocklist. This could potentially be the result of regulatory action against the contract itself, against a single user of the contract (e.g. a Uniswap LP), or could also be a part of an extortion attempt against users of the blocked contract.

then user would see the favorable strike price and mint the option token using payout token for call option or use quote token for put option

However, they can never exercise their option because the transaction would revert when [transferri

*[Content truncated...]*

---

### Example 15: M-1: Funds can be stolen from the `FixedStrikeOptionTeller` contract by creating put option tokens without providing collateral

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/61 

## Found by 
berndartmueller, pks\_, techOptimizor
## Summary

Due to a rounding error when calculating the `quoteAmount` in the `create` function of the `FixedStrikeOptionTeller` contract, it is possible to create (issue) option tokens without providing the necessary collateral. A malicious receiver can exploit this to steal funds from the `FixedStrikeOptionTeller` contract.

## Vulnerability Detail

Anyone can create (issue) put option tokens with the `create` function in the `FixedStrikeOptionTeller` contract. However, by specifying a very small `amount_`, the `quoteAmount` calculation in line 283 can potentially round down to zero. This is the case if the result of the multiplication in line 283, $amount * strikePrice$ is smaller than $10^{decimals}$, where `decimals` is the number of decimals of the payout token.

For example, assume the following scenario:

| Parameter                | Description                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------ |
| Quote token              | $USDC. 6 decimals                                                                                |
| Payout token             | $GMX. 18 decimals                                                                                |
| $payoutToken_{decimals}$ | 18 decim

*[Content truncated...]*

---

### Example 16: [M-03] Contract inherits from `Pausable` but does not expose pausing/unpausing functionality

**Source**: Pashov Audit Group
**Protocol**: Parcel Payroll
**Impact**: MEDIUM

**Details**:

**Impact:**
Low, as methods do not have `whenNotPaused` modifier

**Likelihood:**
High, as it is certain that contract can't be paused at all

**Description**

The `Organizer` smart contract inherits from OpenZeppelin's `Pausable` contract, but the `_pause` and `_unpause` methods are not exposed externally to be callable and also no method actually uses the `whenNotPaused` modifier. This shows that `Pausable` was used incorrectly and is possible to give out a false sense of security when actually contract is not pausable at all.

**Recommendations**

Either remove `Pausable` from the contract or add `whenNotPaused` modifier to the methods that you want to be safer and also expose the `_pause` and `_unpause` methods externally with access control.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-02-01-Parcel Payroll.md)

---

### Example 17: Validation is missing for tokenA in `SwapExchange::calculateMultiSwap()`

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** The protocol supports claiming a chain of swaps and the function `SwapExchange::calculateMultiSwap()` is used to do some calculations including the amount of tokenA that can be received for a given amount of tokenB.
Looking at the implementation, the protocol does not validate that the tokenA of the last swap in the chain is actually the same as the tokenA of `multiClaimInput`.
Because this view function is supposed to be used by the frontend to 'preview' the result of a `MultiSwap`, this does not imply a direct security risk but can lead to unexpected results. (It is notable that the actual swap function `SwapExchange::_claimMultiSwap()` implemented a proper validation.)

```solidity
SwapExchange.sol
150:     function calculateMultiSwap(SwapUtils.MultiClaimInput calldata multiClaimInput) external view returns (SwapUtils.SwapCalculation memory) {
151:         uint256 swapIdCount = multiClaimInput.swapIds.length;
152:         if (swapIdCount == 0 || swapIdCount > _maxHops) revert Errors.InvalidMultiClaimSwapCount(_maxHops, swapIdCount);
153:         if (swapIdCount == 1) {
154:             SwapUtils.Swap memory swap = swaps[multiClaimInput.swapIds[0]];
155:             return SwapUtils._calculateSwapNetB(swap, multiClaimInput.amountB, _feeValue, _feeDenominator, _fixedFee);
156:         }
157:         uint256 matchAmount = multiClaimInput.amountB;
158:         address matchToken = multiClaimInput.tokenB;
159:         uint256 swapId;
160:    

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 18: User can create small position after exit with bid

**Source**: Codehawks
**Protocol**: DittoETH
**Impact**: MEDIUM

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L175-L180">https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L175-L180</a>


## Summary
User can create small position after exit with bid, because there is no validation after matching.
## Vulnerability Details
Shorter can partially exit from position using `ExitShortFacet.exitShort` function. This function acccepts `buyBackAmount` param which is debt amount that user wants to repay.
In order to cover debt, function [will create force bid](https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L210-L212) on behalf of user with `buyBackAmount` as needed asset.

In the beginning function checks that [position will not be too small](https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L175-L180) after this action. In case if `buyBackAmount == e.ercDebt` then this check is skipped. This is needed in order to not allow small positions as it creates risks for the system.

The problem is that such check is not enough and it should be actually done after the bid matching, when you know how many assets were purchased. This is because, matching doesn't guarantee, that there is enough amount that can be sold. As result, not whole `buyBackAmount` can be acquired.
So in case if user provides `buyBackAmount == e.ercDebt` then check is ski

*[Content truncated...]*

---

### Example 19: [M-01] Insufficient input validation

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

### Example 20: Admin level vulnerabilities

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`IDO.sol#L66-69`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L66-69)

**Description:**
Numerous admin functions do not check the validity of the input parameters.

- Many setter functions that set token addresses do not validate zero address (e.g. `MetaManager::setTokens`)
- `IDO::setClaimTime` - time validation
- `MetaManager::setMaxExitCycle` - use strict inequality to prevent DOS unstaking

Also some functions are not necessary and can lead to unintentional situations.

- `IDO::setPrice` - According to the documentation, the floor price is kept as constant but the current implementation allow the owner to change the price to any value.

Although we assume the admin is trusted, these issues can lead to unexpected loss by a mistake of an admin.

**Impact**
The admin can change the protocolâ€™s behavior in unexpected ways.

**Recommendation:**
Add necessary validations to the admin functions and remove unnecessary functions.

**Meta Team:**

Fixed. In the commit :007c1b9183cdb65a500928173608ebff0a5197ef.
Actions include require statments and also to remove unnecessary functions.

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 21: [M-14] No check for Individual mint amount surpassing 10% when the circulation reaches 10\_000\_000 in `mint()` of `LybraEUSDVaultBase` contract

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L124> <br><https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L126>

### Impact

The mint functions in `LybraEUSDVaultBase` have no checks for when the supplied amount to mint is more than 10% if circulation reaches 10,000,000, as specified in the comments explaining the logic of the function.

### Proof of Concept

Lets have a look at `mint()` code in the `LybraEUSDVaultBase` contract:

        /**
         * @notice The mint amount number of EUSD is minted to the address
         * Emits a `Mint` event.
         *
         * Requirements:
         * - `onBehalfOf` cannot be the zero address.
         * - `amount` Must be higher than 0. Individual mint amount shouldn't surpass 10% when the circulation 
              reaches 10_000_000
         */
        function mint(address onBehalfOf, uint256 amount) external {
            require(onBehalfOf != address(0), "MINT_TO_THE_ZERO_ADDRESS");
            require(amount > 0, "ZERO_MINT");
            _mintEUSD(msg.sender, onBehalfOf, amount, getAssetPrice());
        }

        function _mintEUSD(address _provider, address _onBehalfOf, uint256 _mintAmount, uint256 _assetPrice) internal virtual {
            require(poolTotalEUSDCirculation + _mintAmount <= configurator.mintVaultMaxSuppl

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 22: M-3: No check for sequencer uptime can lead to dutch auctions executing at bad prices

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

### Example 23: Missing checks for `address(0)` when assigning values to address state variables

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: LOW

**Details**:

```solidity
File: PriorityPool.sol

399:         distributionOracle = _distributionOracle;

```

**Client:**
Acknowledged.

**Cyfrin:** Acknowledged.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

## Statistics

- Total findings analyzed: 23
- Examples shown: 23
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## missing-logic-patterns.md
# Missing-Logic Security Patterns

## Overview

**Frequency**: 33 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 14 | 19 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Hans, Pashov Audit Group, Kann

---

## Detection Checklist

- [ ] Check for missing-logic vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Incorrect Accounting of currentWithheldETHinInstantWithdrawals

**Source**: Kann
**Protocol**: Mystic Finance
**Impact**: HIGH

**Details**:

## Severity

High

## Description

In the withdraw(address recipient) function, when the withdrawal amount is less than
or equal to currentWithheldETH, the function enters the instant withdrawal path. In this case, the
contract does not call plumeStaking.withdraw(), and the funds are expected to be fully covered by the
ETH already held in currentWithheldETH. However, the code still sets withdrawn = amount and then
unconditionally adds this value back to currentWithheldETH. Immediately after, it subtracts amount
from currentWithheldETH, effectively leaving the value of currentWithheldETH unchanged.

```solidity
} else {
fee = amount * INSTANT_REDEMPTION_FEE / RATIO_PRECISION;
withdrawn = amount;
}
uint256 cachedWithheldETH = currentWithheldETH;
currentWithheldETH += withdrawn; // adding the withdraw amount
withHoldEth += fee;
currentWithheldETH -= amount; // deducting the amount
```

This logic is flawed because the ETH used to fulfill the withdrawal is not newly received; it is already
present in currentWithheldETH, and should simply be subtracted, not first added and then subtracted.
The current logic makes it appear as if no ETH was withdrawn, which results in incorrect accounting
of the withheld pool. If multiple such withdrawals occur, the system will consistently over-report the
available withheld ETH, potentially leading to over-withdrawals or failed withdrawals in the future
when actual funds are not available.

## Team Response

Fixed.

**Reference**: [View Original Finding](https://github.com/Kann-Audits/Kann-Audits/blob/main/reports/md-format/private-audits-reports/Mystic Finance.md)

---

### Example 2: [H-01] All orders can be hijacked to lock rental assets forever by tipping a malicious ERC20

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: HIGH

**Details**:

The `Create` contract is responsible for creating a rental. It achieves this by acting as a Seaport `Zone`, and storing and validating orders as rentals when they are fulfilled on Seaport.

However, one thing it doesn't account for is the fact that Seaport allows for "tipping" in the form of ERC20 tokens as part of the order fulfillment process. This is done by extending the `consideration` array in the order with additional ERC20 tokens.

From the Seaport [docs](https://docs.opensea.io/reference/seaport-overview#order) (emphasis mine):

> The `consideration` contains an array of items that must be received in order to fulfill the order. It contains all of the same components as an offered item, and additionally includes a `recipient` that will receive each item. This array **may be extended by the fulfiller on order fulfillment so as to support "tipping"** (e.g. relayer or referral payments).

This other passage, while discussing a different issue, even highlights the root cause of this vulnerability (the zone does not properly allocate consideration extensions):

> As extensions to the consideration array on fulfillment (i.e. "tipping") can be arbitrarily set by the caller, fulfillments where all matched orders have already been signed for or validated can be frontrun on submission, with the frontrunner modifying any tips. Therefore, it is important that orders fulfilled in this manner either leverage "restricted" order types with a **zone that enforces appropriate allocati

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 3: H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

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

### Example 4: H-5: Users can get around MaxLTV because of lack of strategyId validation

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/129 

## Found by 
8olidity, carrot, Jeiwan, obront, Ch\_301, cergyk, rbserver

## Summary

When a user withdraws some of their underlying token, there is a check to ensure they still meet the Max LTV requirements. However, they are able to arbitrarily enter any `strategyId` that they would like for this check, which could allow them to exceed the LTV for their real strategy while passing the approval.

## Vulnerability Detail

When a user calls `IchiVaultSpell.sol#reducePosition()`, it removes some of their underlying token from the vault, increasing the LTV of any loans they have taken.

As a result, the `_validateMaxLTV(strategyId)` function is called to ensure they remain compliant with their strategy's specified LTV:
```solidity
function _validateMaxLTV(uint256 strategyId) internal view {
    uint256 debtValue = bank.getDebtValue(bank.POSITION_ID());
    (, address collToken, uint256 collAmount, , , , , ) = bank
        .getCurrentPositionInfo();
    uint256 collPrice = bank.oracle().getPrice(collToken);
    uint256 collValue = (collPrice * collAmount) /
        10**IERC20Metadata(collToken).decimals();

    if (
        debtValue >
        (collValue * maxLTV[strategyId][collToken]) / DENOMINATOR
    ) revert EXCEED_MAX_LTV();
}
```
To summarize, this check:
- Pulls the position's total debt value
- Pulls the position's total value of underlying tokens
- Pulls the specified maxLTV for this strate

*[Content truncated...]*

---

### Example 5: H-3: LP tokens are not sent back to withdrawing user

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/151 

## Found by 
rvierdiiev, minhtrng, Dug, Jeiwan, obront, chaduke, koxuan, sinarette, Ch\_301, cergyk, evan, berndartmueller, 0x52, Bauer

## Summary

When users withdraw their assets from `IchiVaultSpell.sol`, the function unwinds their position and sends them back their assets, but it never sends them back the amount they requested to withdraw, leaving the tokens stuck in the Spell contract.

## Vulnerability Detail

When a user withdraws from `IchiVaultSpell.sol`, they either call `closePosition()` or `closePositionFarm()`, both of which make an internal call to `withdrawInternal()`.

The following arguments are passed to the function:
- strategyId: an index into the `strategies` array, which specifies the Ichi vault in question
- collToken: the underlying token, which is withdrawn from Compound
- amountShareWithdraw: the number of underlying tokens to withdraw from Compound
- borrowToken: the token that was borrowed from Compound to create the position, one of the underlying tokens of the vault
- amountRepay: the amount of the borrow token to repay to Compound
- amountLpWithdraw: the amount of the LP token to withdraw, rather than trade back into borrow tokens

In order to accomplish these goals, the contract does the following...

1) Removes the LP tokens from the ERC1155 holding them for collateral.
```solidity
doTakeCollateral(strategies[strategyId].vault, lpTakeAmt);
```
2) Calculates the n

*[Content truncated...]*

---

### Example 6: H-2: Users who deposit extra funds into their Ichi farming positions will lose all their ICHI rewards

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/158 

## Found by 
carrot, rvierdiiev, minhtrng, obront, sinarette, tives, berndartmueller, 0x52

## Summary

When a user deposits extra funds into their Ichi farming position using `openPositionFarm()`, the old farming position will be closed down and a new one will be opened. Part of this process is that their ICHI rewards will be sent to the `IchiVaultSpell.sol` contract, but they will not be distributed. They will sit in the contract until the next user (or MEV bot) calls `closePositionFarm()`, at which point they will be stolen by that user.

## Vulnerability Detail

When Ichi farming positions are opened via the `IchiVaultSpell.sol` contract, `openPositionFarm()` is called. It goes through the usual deposit function, but rather than staking the LP tokens directly, it calls `wIchiFarm.mint()`. This function deposits the token into the `ichiFarm`, encodes the deposit as an ERC1155, and sends that token back to the Spell:
```solidity
function mint(uint256 pid, uint256 amount)
    external
    nonReentrant
    returns (uint256)
{
    address lpToken = ichiFarm.lpToken(pid);
    IERC20Upgradeable(lpToken).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
    if (
        IERC20Upgradeable(lpToken).allowance(
            address(this),
            address(ichiFarm)
        ) != type(uint256).max
    ) {
        // We only need to do this once per pool, as LP token's all

*[Content truncated...]*

---

### Example 7: [H-02] A malicious user can avoid unfavorable score updates after alpha/multiplier changes, resulting in accrual of outsized rewards for the attacker at the expense of other users

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L397-L405> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L704-L756> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L623-L639> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L827-L833> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L200-L219> 

<https://github.com/code-423n4/2023-09-venus/blob/main/tests/hardhat/Prime/Prime.ts#L294-L301>

Please note: All functions/properties referred to are in the `Prime.sol` contract.

### Impact

A malicious user can accrue outsized rewards at the expense of other users after `updateAlpha()` or `updateMultipliers()` is called.

### Proof of Concept

An attacker can prevent their score from being updated and decreased after the protocol's alpha or multipliers change. This is done by manipulatively decreasing the value of `pendingScoreUpdates`, then ensuring that only other user scores are updated until `pendingScoreUpdates` reaches zero, at which point calls to `updateScores()` will revert with the error `NoScoreUpdatesRequired()`. This can be done via the attacker calling `updateScores()` to update other users' scores first and/or DoSing calls to `updateScores()` that would update the attacker's score (see the issue titled "DoS and gas griefing of Prime.updateScores()").

The core of 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-venus)

---

### Example 8: tradingFunction returns wrong invariant at bounds, allowing to steal all pool reserves

**Source**: Spearbit
**Protocol**: Primitive
**Impact**: HIGH

**Details**:

## Critical Risk Report

## Severity
**Critical Risk**

## Context
`NormalStrategyLib.sol#L157-L165`

## Description
The `tradingFunction` computing the invariant value of 

\[ k = \Phi^{-1}(y/K) - \Phi^{-1}(1-x) + \sigma \tau \]

returns the wrong value at the bounds of `x` and `y`. 

- The bounds of `x` are 0 and 1e18.
- The bounds of `y` are 0 and `K`, the strike price.

If `x` or `y` is at these bounds, the corresponding term's computation is skipped and therefore implicitly set to 0, its initialization value.

```solidity
int256 invariantTermX; // Î¦Â¹(1-x)
// @audit if x is at the bounds, the term remains 0
if (self.reserveXPerWad.isBetween(lowerBoundX + 1, upperBoundX - 1)) {
    invariantTermX = Gaussian.ppf(int256(WAD - self.reserveXPerWad));
}
```

```solidity
int256 invariantTermY; // Î¦Â¹(y/K)
// @audit if y is at the bounds, the term remains 0
if (self.reserveYPerWad.isBetween(lowerBoundY + 1, upperBoundY - 1)) {
    invariantTermY = Gaussian.ppf(
        int256(self.reserveYPerWad.divWadUp(self.strikePriceWad))
    );
}
```

Note that \(\Phi^{-1} = \text{Gaussian.ppf}\) is the probit function, which is undefined at 0 and 1.0, but tends towards -infinity at 0 and +infinity at 1.0 = 1e18. (The closest values used in the Solidity approximation are `Gaussian.ppf(1) = -8710427241990476442 ~ -8.71` and `Gaussian.ppf(1e18-1) = 8710427241990476442 ~ 8.71`.)

This fact can be abused by an attacker to steal the pool reserves. For example, the y-term \(\Phi^{-1}(y/K)\) will be

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review-July.pdf)

---

### Example 9: H-1: All fund from Teller contract can be drained because a malicious receiver can call reclaim repeatedly

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/79 

## Found by 
0xcrunch, Jiamin, Juntao, Kow, Musaka, Sm4rty, Yuki, berndartmueller, bin2chen, circlelooper, ctf\_sec, kutugu, stuxy, tnquanghuy0512, tvdung94
## Summary

All fund from Teller contract can be drained because a malicious receiver can call reclaim repeatedly

## Vulnerability Detail

When [mint an option token](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L296), the user is required to transfer the [payout token for a call option](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L277) or [quote token for a put option](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L289)

if after the expiration, the receiver can call reclaim to claim the payout token if the option type is call or claim the quote token if the option type is put

however, the root cause is when reclaim the token, the corresponding option is not burnt ([code](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L395))

```solidity
       // Revert if caller is not receiver
        if (msg.sender != receiver) revert Teller_NotAuthorized();

    

*[Content truncated...]*

---

### Example 10: [M-01] `setGatewayAddress` incorrectly updates address of the gateway

**Source**: Pashov Audit Group
**Protocol**: Subsquid
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium, gateway will still has it's old address

**Likelihood:** Medium, only occurs if the user decides to set a new address for his gateway

## Description

The gateway owner can set a new address for it using `setGatewayAddress` function. Unfortunately, this function only updates `gatewayByAddress` mapping, leaving `Gateway` struct intact

```solidity
  function setGatewayAddress(bytes calldata peerId, address newAddress) public {
    (Gateway storage gateway, bytes32 peerIdHash) = _getGateway(peerId);
    _requireOperator(gateway);

    if (gateway.ownAddress != address(0)) {
>>    delete gatewayByAddress[gateway.ownAddress];
    }

    if (address(newAddress) != address(0)) {
      require(gatewayByAddress[newAddress] == bytes32(0), "Gateway address already registered");
>>     gatewayByAddress[newAddress] = peerIdHash;
    }
```

If the user tries to call `allocateComputationUnits`, the contract will expect the old gateway address in `msg.sender`

```solidity
  function allocateComputationUnits(bytes calldata peerId, uint256[] calldata workerId, uint256[] calldata cus)
    external
    whenNotPaused
  {
    require(workerId.length == cus.length, "Length mismatch");
    (Gateway storage gateway,) = _getGateway(peerId);
>>  require(gateway.ownAddress == msg.sender, "Only gateway can allocate CUs");
```

Coded POC for `GatewayRegistry.unstake.t.sol`

```solidity
  function test_SetAddress() public {
    GatewayRegistry.Gateway memory gt = gatewayRe

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Subsquid-security-review.md)

---

### Example 11: [M-02] `pause/unpause` functionalities not implemented in many pausable contracts

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/SocializingPool.sol#L21> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/Auction.sol#L14> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L17><br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/OperatorRewardsCollector.sol#L16>

The following contracts: `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` are supposed to be pausable (as they all inherit from `PausableUpgradeable`), but they don't implement the external `pause/unpause` functionalities which means it will never be possible to pause them.

### Proof of Concept

All the following contracts `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` inherit from the openzeppelin `PausableUpgradeable` extension which means that they contain internal functions `_pause` and `_unpause`.

Because those functions are internal, the contract must implement two other public/external `pause` and `unpause` functions to allow the manager to pause and unpause the contracts when necessary. None of the aforementioned contracts implement those functions, which means even if those contracts are supposed to be pausable (and have the `pause/unpause` functionalities), none of them can be paused.

### Recommended Mitigation Steps

Add public/external `pause` and `unpause` functions in the aforementioned contracts to allow them to be pausable, this can be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 12: User's funds are locked temporarily in the PriorityPool contract

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intended to utilize the deposit queue for withdrawal to minimize the stake/unstake interaction with the staking pool.
When a user wants to withdraw, they are supposed to call the function `PriorityPool::withdraw()` with the desired amount as a parameter.
```solidity
function withdraw(uint256 _amount) external {//@audit-info LSD token
    if (_amount == 0) revert InvalidAmount();
    IERC20Upgradeable(address(stakingPool)).safeTransferFrom(msg.sender, address(this), _amount);//@audit-info get LSD token from the user
    _withdraw(msg.sender, _amount);
}
```
As we can see in the implementation, the protocol pulls the `_amount` of LSD tokens from the user first and then calls `_withdraw()` where the actual withdrawal utilizing the queue is processed.
```solidity
function _withdraw(address _account, uint256 _amount) internal {
    if (poolStatus == PoolStatus.CLOSED) revert WithdrawalsDisabled();

    uint256 toWithdrawFromQueue = _amount <= totalQueued ? _amount : totalQueued;//@audit-info if the queue is not empty, we use that first
    uint256 toWithdrawFromPool = _amount - toWithdrawFromQueue;

    if (toWithdrawFromQueue != 0) {
        totalQueued -= toWithdrawFromQueue;
        depositsSinceLastUpdate += toWithdrawFromQueue;//@audit-info regard this as a deposit via the queue
    }

    if (toWithdrawFromPool != 0) {
        stakingPool.withdraw(address(this), address(this), toWithdrawFromPool);//@audit-info withdraw from

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 13: M-12: Chainlink's latestRoundData  return stale or incorrect result

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94 

## Found by 
8olidity, tsvetanovv, WatchDogs, Nyx, Avci, obront, Aymen0909, SPYBOY, HonorLt, csanuragjain, koxuan, evan, rbserver, hl\_, peanuts, Chinmay

## Summary
https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/oracle/ChainlinkAdapterOracle.sol#L76

## Vulnerability Detail

## Impact
On ChainlinkAdapterOracle.sol, you are using latestRoundData, but there is no check if the return value indicates stale data. 
```solidity
function getPrice(address _token) external view override returns (uint256) {
        // remap token if possible
        address token = remappedTokens[_token];
        if (token == address(0)) token = _token;

        uint256 maxDelayTime = maxDelayTimes[token];
        if (maxDelayTime == 0) revert NO_MAX_DELAY(_token);

        // try to get token-USD price
        uint256 decimals = registry.decimals(token, USD);
        (, int256 answer, , uint256 updatedAt, ) = registry.latestRoundData(
            token,
            USD
        );
        if (updatedAt < block.timestamp - maxDelayTime)
            revert PRICE_OUTDATED(_token);

        return (answer.toUint256() * 1e18) / 10**decimals;
    }
```
This could lead to stale prices according to the Chainlink documentation:
https://docs.chain.link/data-feeds/price-feeds/historical-data
Related report:
https://github.com/code-423n4/2021-05-fairside-findings/issues/70

## Code Snippet
https://github.com/sh

*[Content truncated...]*

---

### Example 14: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/132 

## Found by 
0x52
## Summary

The sqrtRatioLimit for UniV3 doesn't cause the swap to revert upon reaching that value. Instead it just cause the swap to partially fill. This is a [known issue](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L641) with using sqrtRatioLimit as can be seen here where the swap ends prematurely when it has been reached. This is problematic as this is meant to provide the user with slippage protection but doesn't.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L209-L223

        if (amountToSwap > 0) {
            SWAP_POOL = IUniswapV3Pool(vault.pool());
            uint160 deltaSqrt = (param.sqrtRatioLimit *
                uint160(param.sellSlippage)) / uint160(Constants.DENOMINATOR);
            SWAP_POOL.swap(
                address(this),
                // if withdraw token is Token0, then swap token1 -> token0 (false)
                !isTokenA,
                amountToSwap.toInt256(),
                isTokenA
                    ? param.sqrtRatioLimit + deltaSqrt
                    : param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
                abi.encode(address(this))
            );
        }

sqrtRatioLimit is used as slippage protection for the user but is ineffective and depending on what tokens are 

*[Content truncated...]*

---

### Example 15: H-9: BlueBerryBank#withdrawLend will cause underlying token accounting error if soft/hard vault has withdraw fee

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

### Example 16: H-4: Fail to accrue interests on multiple token positions

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/140 

## Found by 
cducrest-brainbot, rvierdiiev, Jeiwan

## Summary

In `BlueBerryBank.sol` the functions `borrow`, `repay`, `lend`, or `withdrawLend` call `poke(token)` to trigger interest accrual on concerned token, but fail to do so for other token debts of the concerned position.  This could lead to wrong calculation of position's debt and whether the position is liquidatable.

## Vulnerability Detail

Whether a position is liquidatable or not is checked at the end of the `execute` function, the execution should revert if the position is liquidatable. 

The calculation of whether a position is liquidatable takes into account all the different debt tokens within the position. However, the debt accrual has been triggered only for one of these tokens, the one concerned by the executed action. For other tokens, the value of `bank.totalDebt` will be lower than what it should be. This results in the debt value of the position being lower than what it should be and a position seen as not liquidatable while it should be liquidatable. 

## Impact

Users may be able to operate on their position leading them in a virtually liquidatable state while not reverting as interests were not applied. This will worsen the debt situation of the bank and lead to overall more liquidatable positions.

## Code Snippet

execute checking isLiquidatable without triggering interests:

https://github.com/sherlock-audit/2023-02-

*[Content truncated...]*

---

### Example 17: Borrower with bad debt gets mint reward

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`MUSDManager.sol#L249`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L249), [`MUSDManager.sol#L299`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L299 "â€Œ"), [`MintRewards.sol#L121`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/reward/MintRewards.sol#L121 "â€Œ"), [`MintRewards.sol#L92`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/reward/MintRewards.sol#L92 "â€Œ")

**Description:**

With the current implementation, it is possible that the borrowers are in bad debt. As confirmed with the protocol team, _â€œWhen user's collateral position is under 100%, only the respective amount of mUSD which is equivalent of GLP\*price which is less than is debt position is closed.â€_ ([MUSDManager.sol#L249](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L249), [MUSDManager.sol#L299](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L299 "â€Œ"))

On the other hand, by the protocolâ€™s design, anyone with positive `borrowed` is considered as a mUSD holder and can claim the mint reward. Note that the user does not need to mint additional mUSD. ([MintRewards.sol#L121](https://github.com/getmetafinance/

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 18: On restaking, funds should be unslashed back

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`MetaManager.sol#L117-L126`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/MetaManager.sol#L117-L126)

**Description:**
In `MetaManager::reStake`, `toMint` is calculated as `getReservedForVesting(caller) + getClaimable(caller)` and itâ€™s essentially the same to `unstakeRate[_user] * (time2fullRedemption[_user] - lastWithdrawTime[_user])`. The problem is that this should be â€œunslashedâ€ using the `lastSlashRate` to be fair.

For example, a user starts unstaking 100e18 esMETA with 10 days vesting period and after a day he decided to stop unstaking and restake.

In this case, the originally slashed 50e18 esMETA are not fair for him and the protocol should reimburse partial slash.

**Impact**
While this is not a genuine bug, it is more of a recommendation to enhance the protocol's completeness. However, I have classified its severity level as MEDIUM since it is evidently not an intended mechanism to ensure fairness.

**Recommendation:**
Add a new logic to reimburse the slashed amounts partially when the user restakes.

**Meta Team:**

Fixed.

```diff

function reStake() external updateReward(msg.sender) {
address caller = msg.sender;
uint256 toMint = getReservedForVesting(caller) + getClaimable(caller);
+       toMint = (toMint * 100 * Constants.PINT) / (100 - lastSlashRate[caller]);
+       toMint /= Constants.PINT;
if (toMint > 0) {
esMeta.mint(caller, toMint);
unstakeRate[caller] = 0;
time2

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 19: M-1: BalancerPairOracle#getPrice will revert due to division by zero in some cases

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/25 

## Found by 
0x52, nobody2018
## Summary

`BalancerPairOracle#getPrice` internally calls `computeFairReserves`, which returns fair reserve amounts given spot reserves, weights, and fair prices. When the parameter `resA` passed to `computeFairReserves` is smaller than `resB`, division by 0 will occur.

## Vulnerability Detail

In `BalancerPairOracle#getPrice`, resA and resB passed to `computeFairReserves` are the balance of TokenA and TokenB of the pool respectively. It is common for the balance of TokenB to be greater than the balance of TokenA.

```solidity
function computeFairReserves(
        uint256 resA,
        uint256 resB,
        uint256 wA,
        uint256 wB,
        uint256 pxA,
        uint256 pxB
    ) internal pure returns (uint256 fairResA, uint256 fairResB) {
    	...
    	//@audit r0 = 0 when resA < resB.
->      uint256 r0 = resA / resB;
        uint256 r1 = (wA * pxB) / (wB * pxA);
        // fairResA = resA * (r1 / r0) ^ wB
        // fairResB = resB * (r0 / r1) ^ wA
        if (r0 > r1) {
            uint256 ratio = r1 / r0;
            fairResA = resA * (ratio ** wB);
            fairResB = resB / (ratio ** wA);
        } else {
->          uint256 ratio = r0 / r1;		// radio = 0 when r0 = 0
->          fairResA = resA / (ratio ** wB);   	// revert divided by 0
            fairResB = resB * (ratio ** wA);
        }
    }
```

Another case is **when the decimals of tokenA is s

*[Content truncated...]*

---

### Example 20: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/29 

## Found by 
0x52, nobody2018
## Summary

When a user adds to an existing position on AuraSpell, the contract burns their current position and remints them a new one. The issues is that WAuraPool will send all reward tokens to the contract but it only sends Aura back to the user, causing all other rewards to be lost.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L256-L261

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                msg.sender,
                rewards[i]
            );
        }

Inside WAuraPools#burn reward tokens are sent to the user.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L130-L140

        IBank.Position memory pos = bank.getCurrentPositionInfo();
        if (pos.collateralSize > 0) {
            (uint256 pid, ) = wAuraPools.decodeId(pos.collId);
            if (param.farmingPoolId != pid)
                revert Errors.INCORRECT_PID(param.farmingPoolId);
            if (pos.collToken != address(wAuraPools))
                revert Errors.INCORRECT_COLTOKEN(pos.collToken);
            bank.takeCollateral(pos.collateralSize);
            wAuraPools.burn(pos.collId, pos.collateralSize);
            _doRefundRewards(AURA);
        }

We see above that t

*[Content truncated...]*

---

### Example 21: M-6: Target raises can be highly damaging for dutch auctions with multiple components

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/45 

## Found by 
0x52
## Summary

Multi-component dutch auctions are fundamentally incompatible with target raises and will lead to inefficient pricing causing loss to set token.

## Vulnerability Detail

The AuctionRebalanceModuleV1 allows targets to be increased when all component targets have been met and there is still excess quote token. When combined with multiple components, it his highly likely that these target raises will lead to inefficient pricing which will cause loss to the set token.

Consider the following a set token has the following composition that has target raises enabled:

40% USDC
30% WBTC
30% WETH

The manager wishes to rebalance the set to the following using USDC as the quote token:

20% USDC
40% WBTC
40% WETH

Assume the WETH portion of the execute within the first hour of the auction. The WBTC on the other hand doesn't execute until 12 hours in. Assume there is excess quote so the target is increased. The issue is that now because of the change in time, the WETH auction is now well above the market price. This buys the WETH for a large loss compared to the market price of WETH.

## Impact

Pricing after target raises will likely be heavily skewed from market prices for some components lead to set token losses

## Code Snippet

[AuctionRebalanceModuleV1.sol#L359-L380](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionR

*[Content truncated...]*

---

### Example 22: M-1: SetToken can't be unlocked early.

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/38 

## Found by 
0x52, Yuki, auditsea, qandisa
## Summary
SetToken can't be unlocked early

## Vulnerability Detail
The function unlock() is used to unlock the setToken after rebalancing, as how it is right now there are two ways to unlock the setToken.

- can be unlocked once the rebalance duration has elapsed
- can be unlocked early if all targets are met, there is excess or at-target quote asset, and raiseTargetPercentage is zero
```solidity
    function unlock(ISetToken _setToken) external {
        bool isRebalanceDurationElapsed = _isRebalanceDurationElapsed(_setToken);
        bool canUnlockEarly = _canUnlockEarly(_setToken);

        // Ensure that either the rebalance duration has elapsed or the conditions for early unlock are met
        require(isRebalanceDurationElapsed || canUnlockEarly, "Cannot unlock early unless all targets are met and raiseTargetPercentage is zero");

        // If unlocking early, update the state
        if (canUnlockEarly) {
            delete rebalanceInfo[_setToken].rebalanceDuration;
            emit LockedRebalanceEndedEarly(_setToken);
        }

        // Unlock the SetToken
        _setToken.unlock();
    }
```
```solidity
    function _canUnlockEarly(ISetToken _setToken) internal view returns (bool) {
        RebalanceInfo storage rebalance = rebalanceInfo[_setToken];
        return _allTargetsMet(_setToken) && _isQuoteAssetExcessOrAtTarget(_setToken) && rebal

*[Content truncated...]*

---

### Example 23: M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

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

### Example 24: M-2: Escrow record not cleared on cancellation and order fill

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/56 

## Found by 
Delvir0, bin2chen, bitsurfer, chainNue, ctf\_sec, dirk\_y, hals, volodya
## Summary
In `DirectBuyIssuer.sol`, a market buy requires the operator to take the payment token as escrow prior to filling the order. Checks are in place so that the math works out in terms of how much escrow has been taken vs the order's remaining fill amount. However, if the user cancels the order or fill the order, the escrow record is not cleared. 

The escrow record will exists as a positive amount which can lead to accounting issues.

## Vulnerability Detail
Take the following example:

- Operator broadcasts a `takeEscrow()` transaction around the same time that the user calls `requestCancel()` for the order
- Operator also broadcasts a `cancelOrder()` transaction
- If the `cancelOrder()` transaction is mined before the `takeEscrow()` transaction, then the contract will transfer out token when it should not be able to.

`takeEscrow()` simply checks that the `getOrderEscrow[orderId]` is less than or equal to the requested amount:
```solidity
        bytes32 orderId = getOrderIdFromOrderRequest(orderRequest, salt);
        uint256 escrow = getOrderEscrow[orderId];
        if (amount > escrow) revert AmountTooLarge();


        // Update escrow tracking
        getOrderEscrow[orderId] = escrow - amount;
        // Notify escrow taken
        emit EscrowTaken(orderId, orderRequest.recipient, amount);


        /

*[Content truncated...]*

---

### Example 25: M-1: In case of stock split and reverse split, the Dshare token holder will gain or loss his Dshare token value

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/29 

## Found by 
ast3ros
## Summary

Stock split and reverse split may cause the token accounting to be inaccurate.

## Vulnerability Detail

Stock split and reverse split are very common in the stock market. There are many examples here: https://companiesmarketcap.com/amazon/stock-splits/

For instance, in a 2-for-1 stock split, a shareholder receives an additional share for each share held. However, the DShare token holder still holds only one DShare token after the split. If a DShare token holder owns 100 DShare tokens before the split, he will still own 100 DShare tokens after the split. However, he should own 200 DShare tokens after the split.

Currently, users can buy 1 DShare token at the current market price of the underlying share. https://sbt.dinari.com/tokens

This means that after the stock split, a new Dshare token holder can buy a Dshare at half the price of the previous Dshare token holder. This is unfair to the previous Dshare token holder. In other words, the original Dshare token holder will lose 50% of his Dshare token value after the stock split.

The same logic applies to stock reverse split.

## Impact

The Dshare token holder will gain or loss his Dshare token value after the stock split or reverse split.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dinari/blob/50eb49260ab54e02748c2f6382fd95284d271f06/sbt-contracts/src/BridgedERC20.sol#L13

## Tool used

Manual Revie

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 33
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## min-max-cap-validation-patterns.md
# Min/Max Cap Validation Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 7 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for min/max cap validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-3: Unbounded `_unlockTime` allows the attacker to get a huge `stakedTimeBonus` and dominate the voting

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/53 

## Found by 
Trumpero, WATCHPUG, neumo, bin2chen, curiousapple, koxuan, John, hansfriese

## Summary

`stakingSettings.maxStakeBonusTime` is not enforced, allowing the attacker to gain a huge `stakedTimeBonus` by using a huge value for `_unlockTime`.

## Vulnerability Detail

There is no max `_unlockTime` check in `_stakeToken()` to enforce the `stakingSettings.maxStakeBonusTime`.

As a result, an attacker can set a huge value for `_unlockTime` and get an enormous `stakedTimeBonus`.

## Impact

The attacker can get a huge amount of votes and dominate the voting.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L389-L394

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L356-L384

## Tool used

Manual Review

## Recommendation

Change to:

```solidity
  function _stakeToken(uint _tokenId, uint _unlockTime) internal returns (uint) {
    if (_unlockTime > 0) {
      unlockTime[_tokenId] = _unlockTime;
      uint time = _unlockTime - block.timestamp;
      uint maxtime = stakingSettings.maxStakeBonusTime;
      uint maxBonus = stakingSettings.maxStakeBonusAmount;
      if (time < stakingSettings.maxStakeBonusTime){
        uint fullStakedTimeBonus = (time * maxBonus) / maxtime;
      }else{
        uint fullStakedTimeBonus = maxBonus;
      }
      stakedTimeBonus[_tokenId] = _tokenId < 10000 ? fullStakedTimeBonus : fullSta

*[Content truncated...]*

---

### Example 2: Liens cannot be bought out once we've reached the maximum number of active liens on one collateral

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
LienToken.sol#L373-375

## Description
The `buyoutLien` function is intended to transfer ownership of a lien from one user to another. In practice, it creates a new lien by calling `_createLien` and then calls `_replaceStackAtPositionWithNewLien` to update the stack.

In the `_createLien` function, there is a check to ensure we don't take out more than `maxLiens` against one piece of collateral:

```solidity
if (params.stack.length >= s.maxLiens) {
    revert InvalidState(InvalidStates.MAX_LIENS);
}
```

The result is that, when we already have `maxLiens` and we try to buy one out, this function will revert.

## Recommendation
Move this check from `_createLien` into the `_appendStack` function, which is only called when new liens are created rather than when they are bought out.

## Astaria
Fixed in PR 213.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 3: Absence of Minimum delayBlocks

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Severity
**Medium Risk**

## Context
- `RootManager.sol#L102-106`
- `SpokeConnector.sol#L218-L221`

## Description
The owner can accidentally set `delayBlocks` to `0` (or a very small delay block), which will collapse the whole fraud protection mechanism. Since there is no check for a minimum delay before setting a new delay value, even a low value will be accepted by the `setDelayBlocks` function:

```solidity
function setDelayBlocks(uint256 _delayBlocks) public onlyOwner {
    require(_delayBlocks != delayBlocks, "!delayBlocks");
    emit DelayBlocksUpdated(_delayBlocks, delayBlocks);
    delayBlocks = _delayBlocks;
}
```

## Recommendation
Introduce a variable `minDelay` that specifies the minimum possible delay allowed by the contract. Any attempt to change the delay value using the `setDelayBlocks` function should ensure that the new delay is larger than or equal to `minDelay`.

## Connext
We could add a minimum for when `delayBlocks` is not `0`, but that minimum will vary by chain/block time, so that minimum has to be configurable. We could add a separate configuration endpoint and make it so it takes 72 hours to change the delay blocks minimum. However, that feels more like DAO functionality/responsibility. For that reason, we are going with "acknowledged." At the very least, users can visibly check what the `delayBlocks` are set to on-chain to ensure it's reasonable.

## Spearbit
**Acknowledged**

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 4: [M-18] Node runners can lose all their stake rewards due to how the DAO commissions can be set to a 100%

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

Node runners can have all their stake rewards taken by the DAO as commissions can be set to a 100%.

### Proof of Concept

There is no limits on `_updateDAORevenueCommission()` except not exceeding `MODULO`, which means it can be set to a 100%.

[LiquidStakingManager.sol#L948-L955](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L948-L955)

```solidity
    function _updateDAORevenueCommission(uint256 _commissionPercentage) internal {
        require(_commissionPercentage <= MODULO, "Invalid commission");

        emit DAOCommissionUpdated(daoCommissionPercentage, _commissionPercentage);

        daoCommissionPercentage = _commissionPercentage;
    }
```

This percentage is used to calculate `uint256 daoAmount = (_received * daoCommissionPercentage) / MODULO` in `_calculateCommission()`.<br>
Remaining is then calculated with `uint256 rest = _received - daoAmount`, and in this case `rest = 0`.<br>
When node runner calls `claimRewardsAsNodeRunner()`, the node runner will receive 0 rewards.<br>

### Recommended Mitigation Steps

There should be maximum cap on how much commission DAO can take from node runners.

**[vince0656 (Stakehouse) disputed and commented](https://github.com/code-423n4/2022-11-stakehouse-findings/issues/190#issuecomment-1329453031):**
  > Node runners can see ahead of time what the % commission is and therefore, they can make a decision based on that. However, on 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 5: H-3: RageTrade senior vault USDC deposits are subject to utilization caps which can lock deposits for long periods of time leading to UXD instability

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/253 

## Found by 
clems4ever, ctf\_sec, 0x52, 0xNazgul

## Summary

RageTrade senior vault requires that it maintains deposits above and beyond the current amount loaned to the junior vault. Currently this is set at 90%, that is the vault must maintain at least 10% more deposits than loans. Currently the junior vault is in high demand and very little can be withdrawn from the senior vault. A situation like this is far from ideal because in the even that there is a strong depeg of UXD a large portion of the collateral could be locked in the vault unable to be withdrawn.

## Vulnerability Detail

[DnGmxSeniorVault.sol](https://arbiscan.io/address/0x66aca71a2e62022f9f23a50ab737ded372ad00cf#code#F31#L288)

    function beforeWithdraw(
        uint256 assets,
        uint256,
        address
    ) internal override {
        /// @dev withdrawal will fail if the utilization goes above maxUtilization value due to a withdrawal
        // totalUsdcBorrowed will reduce when borrower (junior vault) repays
        if (totalUsdcBorrowed() > ((totalAssets() - assets) * maxUtilizationBps) / MAX_BPS)
            revert MaxUtilizationBreached();

        // take out required assets from aave lending pool
        pool.withdraw(address(asset), assets, address(this));
    }

DnGmxSeniorVault.sol#beforeWithdraw is called before each withdraw and will revert if the withdraw lowers the utilization of the vault below a certain thr

*[Content truncated...]*

---

### Example 6: Limits in LIFuelFacet

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
LIFuelFacet.sol#L72-L101

## Description
The facet **LIFuelFacet** is meant for small amounts; however, it doesn't have any limits on the funds sent. This might result in funds getting stuck due to insufficient liquidity on the receiving side.

```solidity
function _startBridge(...) {
    ...
    if (LibAsset.isNativeAsset(_bridgeData.sendingAssetId)) {
        serviceFeeCollector.collectNativeGasFees{...}(...);
    } else {
        LibAsset.maxApproveERC20(...);
        serviceFeeCollector.collectTokenGasFees(...);
        ...
    }
}
```

## Recommendation
Consider enforcing limits in **LIFuelFacet**.

## LiFi
Limits apply to all bridges and depend on the liquidity on the receiving chain. This information is usually not available on the source chain. For sure, some high fixed limits could be added, but they don't really check that there is that much liquidity available. Checking limits and applying them to the calls is handled by the backend.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 7: ERC721A has mint caps that are not checked by ERC721SeaDrop

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: MEDIUM

**Details**:

## Medium Risk Severity Report

## Context
`ERC721SeaDrop.sol#L137-L145`

## Description
`ERC721SeaDrop` inherits from `ERC721A`, which packs `balance`, `numberMinted`, `numberBurned`, and an extra data chunk into one storage slot (64 bits per sub-storage) for every address. This creates an inherent cap of \( 2^{64} - 1 \) on all these different fields. Currently, there is no check in `ERC721A`'s `_mint` for quantity nor in `ERC721SeaDrop`'s `mintSeaDrop` function.

Additionally, if an owner is close to reaching the maximum cap for their balance and someone else transfers a token to this owner, an overflow may occur for the balance and possibly the number of mints in `_packedAddressData`. This overflow could potentially reduce the balance and the `numberMinted` to a much lower number, while `numberBurned` could be increased to a much higher number.

## Recommendation
We should implement an additional check to verify if the quantity would exceed the mint cap in `mintSeaDrop`.

## OpenSea
We will add checks regarding the `ERC721A` limits. A restraint has been implemented where `maxSupply` cannot be set greater than \( 2^{64} - 1 \) so that neither balance nor number minted can exceed this limit. See the commit `5a98d29`.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 8: [M-01] Attacker can list an NFT they own and inflate to zero all usersâ€™ contributions, keeping the NFT and all the money

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/crowdfund/BuyCrowdfundBase.sol#L117-L118


## Vulnerability details

## Description
Crowdfunds split the voting power and distribution of profits rights according to the percentage used to purchase the NFT. When an attacker lists his own NFT for sale and contributes to it, any sum he contributes will return to him once the sell is executed. This behavior is fine so long as the sell price is fair, as other contributors will receive a fair portion of voting power and equity.  Therefore, when a maximum price is defined, it is not considered a vulnerability that an attacker can contribute ```maximumPrice - totalContributions``` and take a potentially large stake of the Crowdfund, as user's have contributed knowing the potential maximum price. 

However, when maximum price is zero, which is allowed in BuyCrowdfund and CollectionBuyCrowdfund, the lister of the NFT can always steal the entirety of the fund and keep the NFT. Attacker can send a massive contribution, buy the NFT and pass a unanimous proposal to approve the NFT to his wallet. Attacker can use a flash loan to finance the initial contribution, which is easily paid back from the NFT lister wallet.

It is important to note that there is no way for the system to know if the Crowdfund creator and the NFT owner are the same entity, and therefore it is critical for the platform to defend users against this s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 9: [M-11] Position owner should set allowed slippage

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52_

[TopUpAction.sol#L154](https://github.com/code-423n4/2022-04-backd/blob/c856714a50437cb33240a5964b63687c9876275b/backd/contracts/actions/topup/TopUpAction.sol#L154)<br>
[TopUpAction.sol#L187](https://github.com/code-423n4/2022-04-backd/blob/c856714a50437cb33240a5964b63687c9876275b/backd/contracts/actions/topup/TopUpAction.sol#L187)<br>

The default swap slippage of 5% allows malicious keepers to sandwich attack topup. Additionally, up to 40% (\_MIN_SWAPPER_SLIPPAGE) slippage allows malicious owner to sandwich huge amounts from topup

### Proof of Concept

Keeper can bundle swaps before and after topup to sandwich topup action, in fact it's actually in their best interest to do so.

### Recommended Mitigation Steps

Allow user to specify max swap slippage when creating topup similar to how it's specified on uniswap or sushiswap to block attacks from both keepers and owners.

**[chase-manning (Backd) confirmed and resolved](https://github.com/code-423n4/2022-04-backd-findings/issues/87)**

**[gzeon (judge) commented](https://github.com/code-423n4/2022-04-backd-findings/issues/87#issuecomment-1121225398):**
 > According to [C4 Judging criteria](https://docs.code4rena.com/roles/judges/how-to-judge-a-contest#notes-on-judging)
> > Unless there is something uniquely novel created by combining vectors, most submissions regarding vulnerabilities that are inherent to a particular system or the Ethereum network as a whole should be considered QA. Examples of such vu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-backd)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## minout-maxin-validation-patterns.md
# MinOut/MaxIn Validation Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 0 | 0 |

**Common Sources**: Pashov Audit Group, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for minout/maxin validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-2: findMarketFor() missing check minAmountOut_

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/38 

## Found by 
bin2chen

## Summary
BondAggregator#findMarketFor() minAmountOut_ does not actually take effectï¼Œmay return a market's "payout" smaller than minAmountOut_ , Causes users to waste gas calls to purchase

## Vulnerability Detail
BondAggregator#findMarketFor() has check minAmountOut_ <= maxPayout
but the actual "payout" by "amountIn_" no check  greater than minAmountOut_
```solidity
    function findMarketFor(
        address payout_,
        address quote_,
        uint256 amountIn_,
        uint256 minAmountOut_,
        uint256 maxExpiry_
    ) external view returns (uint256) {
...
            if (expiry <= maxExpiry_) {
                payouts[i] = minAmountOut_ <= maxPayout
                    ? payoutFor(amountIn_, ids[i], address(0))
                    : 0;

                if (payouts[i] > highestOut) {//****@audit not check payouts[i] >= minAmountOut_******//
                    highestOut = payouts[i];
                    id = ids[i];
                }
            }

```


## Impact

The user gets the optimal market through BondAggregator#findMarketFor(), but incorrectly returns a market smaller than minAmountOut_, and the call to purchase must fail, resulting in wasted gas

## Code Snippet

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondAggregator.sol#L248

## Tool used

Manual Review

## Recommendation
```solidity
    function findMarketFor(
        address payout

*[Content truncated...]*

---

### Example 2: [M-02] Preventing any user from calling the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx`

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

It is possible that an attacker can prevent any user from calling the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx` by just manipulating the balance of token `gmxBaseReward`, so that during the function `compound` the swap will be reverted.

### Proof of Concept

Whenever a user calls the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx`, the function `compound` is called:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L321>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L345>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L379>

The function `compound` claims token `gmxBaseReward` from `rewardModule`:
<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L262>

Then, if the balance of the token `gmxBaseReward` in custodian of the contract `AutoPxGmx` is not zero, the token `gmxBaseReward` will be swapped to token `GMX` thrrough uniswap V3 by calling the function `exactInputSingle`. Then the total amount of token `GMX` in custodian of the contract `AutoPxGmx` will be deposited in the contract `PirexGmx` to receive token `pxGMX`:

    if (gmxBaseRewardAmountIn != 0) {
                gmxAmountOut = SWAP_ROUTER.exactInputSingle(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

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

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## from-to-patterns.md
# from=to Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 6 | 0 | 0 | 0 |

**Common Sources**: Code4rena, Halborn, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for from=to vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Transfering funds to yourself increases your balance

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L182><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L187><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L189-L192><br>

Using temporary variables to update balances is a dangerous construction that has led to several hacks in the past. Here, we can see that `_toBalance` can overwrite `_fromBalance`:

```solidity
File: LBToken.sol
176:     function _transfer(
177:         address _from,
178:         address _to,
179:         uint256 _id,
180:         uint256 _amount
181:     ) internal virtual {
182:         uint256 _fromBalance = _balances[_id][_from];
...
187:         uint256 _toBalance = _balances[_id][_to];
188: 
189:         unchecked {
190:             _balances[_id][_from] = _fromBalance - _amount;
191:             _balances[_id][_to] = _toBalance + _amount; //@audit : if _from == _to : rekt
192:         }
..
196:     }
```

Furthermore, the `safeTransferFrom` function has the `checkApproval` modifier which passes without any limit if `_owner == _spender` :

```solidity
File: LBToken.sol
32:     modifier checkApproval(address _from, address _spender) {
33:         if (!_isApprovedForAll(_from, _spender)) revert LBToken__SpenderNotApproved(_from, _spender);
34:         _;
35:     }
...
131:     function safeTransferFrom(
...
1

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 2: LACK OF EXTERNAL CALLS VALIDATION

**Source**: Halborn
**Protocol**: Account Abstraction Schnorr Signatures SDK
**Impact**: HIGH

**Details**:

##### Description

Non-validated external calls occur when a function invokes an external contract without verifying the return value or handling potential errors.

Several external calls were detected without proper validation.

### Impact

This can lead to reentrancy attacks or unexpected side effects if the external call fails or returns an unexpected result, directly causing a potential impact in the availability or integrity of the environment.

##### Proof of Concept

Listed below, there are some examples of unvalidated calls that may fail or cause an unconsistent or unexpected behavior of the application execution flow.

* `examples/account-address/account_address.ts`

```
async function getAddressAlchemyAASDK(combinedAddresses: Address[], salt: string) {
  const rpcUrl = process.env.ALCHEMY_RPC_URL
  const transport = http(rpcUrl)
  const multiSigSmartAccount = await createMultiSigSmartAccount({
    transport,
    chain: CHAIN,
    combinedAddress: combinedAddresses,
    salt: saltToHex(salt),
    entryPoint: getEntryPoint(CHAIN),
  })

  return multiSigSmartAccount.address
}


```

* `src/helpers/create2.ts`

```
export async function getAccountImplementationAddress(factoryAddress: string, ethersSignerOrProvider: Signer | Provider): Promise<string> {
  const smartAccountFactory = new ethers.Contract(factoryAddress, MultiSigSmartAccountFactory_abi, ethersSignerOrProvider)
  const accountImplementation = await smartAccountFactory.accountImplementation()
  return accoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/influx-technologies/account-abstraction-schnorr-signatures-sdk)

---

### Example 3: swapOut allows overwrite of token balance

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

**Note:** The same issue exists in `swapInternalOut()`, which is called from `swapFromLocalAssetIfNeededForExactOut()` via `_swapAssetOut()`. However, via this route, it is not possible to specify arbitrary token indexes. Therefore, there isnâ€™t an immediate risk here.

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

### Example 4: `AllocationVesting` contract can be exploited for infinite points via self-transfer

**Source**: Cyfrin
**Protocol**: Bima
**Impact**: HIGH

**Details**:

**Description:** The `AllocationVesting` contract gives points on vesting schedules to team members, investors, influencers and anyone else entitled to a token allocation.

`AllocationVesting::transferPoints` allows users to transfer points however this function does not correctly [handle](https://github.com/Bima-Labs/bima-v1-core/blob/09461f0d22556e810295b12a6d7bc5c0efec4627/contracts/dao/AllocationVesting.sol#L129-L133) self-transfer meaning users can exploit it by transferring points to themselves, giving themselves infinite points:
```solidity
// update storage - deduct points from `from` using memory cache
allocations[from].points = uint24(fromAllocation.points - points);

// we don't use fromAllocation as it's been modified with _claim()
allocations[from].claimed = allocations[from].claimed - claimedAdjustment;

// @audit doesn't correctly handle self-transfer since the memory
// cache of `toAllocation.points` will still contain the original
// value of `fromAllocation.points`, so this can be exploited by
// self-transfer to get infinite points
//
// update storage - add points to `to` using memory cache
allocations[to].points = toAllocation.points + uint24(points);
```

**Impact:** Anyone entitled to an allocation can give themselves infinite points and hence receive more tokens than they should receive.

**Proof of Concept:** Add the following PoC contract to `test/foundry/dao/AllocationInvestingTest.t.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2024-09-27-cyfrin-bima-v2.0.md)

---

### Example 5: [H-01] Duplication of Balance

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

### Example 6: [H-03] transferNotionalFrom doesnâ€™t check from != to

**Source**: Code4rena
**Protocol**: Swivel
**Impact**: HIGH

**Details**:

## Handle

gpersoon


## Vulnerability details

## Impact
The function transferNotionalFrom of VaultTracker.sol uses temporary variables to store the balances.
If the "from" and "to" address are the same then the balance of "from" is overwritten by the balance of "to".
This means the balance of "from" and "to" are increased and no balances are decreased, effectively printing money.

Note: transferNotionalFrom can be called via transferVaultNotional by everyone.

## Proof of Concept
https://github.com/Swivel-Finance/gost/blob/v2/test/vaulttracker/VaultTracker.sol#L144-L196

 function transferNotionalFrom(address f, address t, uint256 a) external onlyAdmin(admin) returns (bool) {
    Vault memory from = vaults[f];
    Vault memory to = vaults[t];
    ...
    vaults[f] = from;
    ...
    vaults[t] = to;    // if f==t then this will overwrite vaults[f] 


https://github.com/Swivel-Finance/gost/blob/v2/test/marketplace/MarketPlace.sol#L234-L238
function transferVaultNotional(address u, uint256 m, address t, uint256 a) public returns (bool) {
    require(VaultTracker(markets[u][m].vaultAddr).transferNotionalFrom(msg.sender, t, a), 'vault transfer failed');
   
## Tools Used

## Recommended Mitigation Steps
Add something like the following:
   require (f != t,"Same");

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-swivel)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## bypass-limit-patterns.md
# Bypass limit Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 11 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for bypass limit vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Reentrancy of fee payment can be used to circumvent max mints per wallet check

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`SeaDrop.sol#L586`

## Description
In case of a `mintPublic` call, the function `_checkMintQuantity` checks whether the minter has exceeded the parameter `maxMintsPerWallet`, among other things. However, re-entrancy in the above fee dispersal mechanism can be used to circumvent the check.

The following is an example contract that can be employed by the `feeRecipient` (assume that `maxMintsPerWallet` is 1):

```solidity
contract MaliciousRecipient {
    bool public startAttack;
    address public token;
    SeaDrop public seaDrop;

    fallback() external payable {
        if (startAttack) {
            startAttack = false;
            seaDrop.mintPublic{value: 1 ether}({
                nftContract: token,
                feeRecipient: address(this),
                minterIfNotPayer: address(this),
                quantity: 1
            });
        }
    }

    // Call `attack` with at least 2 ether.
    function attack(SeaDrop _seaDrop, address _token) external payable {
        token = _token;
        seaDrop = _seaDrop;
        startAttack = true;
        _seaDrop.mintPublic{value: 1 ether}({
            nftContract: _token,
            feeRecipient: address(this),
            minterIfNotPayer: address(this),
            quantity: 1
        });
        token = address(0);
        seaDrop = SeaDrop(address(0));
    }
}
```

This is especially problematic when the parameter `PublicDrop.restrictFeeRecipients` is

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] PartyGovernance: Can vote multiple times by transferring NFT in same block as proposal

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Lambda, also found by Trust_

`PartyGovernanceNFT` uses the voting power at the time of proposal when calling `accept`. The problem with that is that a user can vote, transfer the NFT (and the voting power) to a different wallet, and then vote from this second wallet again during the same block that the proposal was created.
This can also be repeated multiple times to get an arbitrarily high voting power and pass every proposal unanimously.

The consequences of this are very severe. Any user (no matter how small his voting power is) can propose and pass arbitrary proposals animously and therefore steal all assets (including the precious tokens) out of the party.

### Proof Of Concept

This diff shows how a user with a voting power of 50/100 gets a voting power of 100/100 by transferring the NFT to a second wallet that he owns and voting from that one:

```diff
--- a/sol-tests/party/PartyGovernanceUnit.t.sol
+++ b/sol-tests/party/PartyGovernanceUnit.t.sol
@@ -762,6 +762,7 @@ contract PartyGovernanceUnitTest is Test, TestUtils {
         TestablePartyGovernance gov =
             _createGovernance(100e18, preciousTokens, preciousTokenIds);
         address undelegatedVoter = _randomAddress();
+        address recipient = _randomAddress();
         // undelegatedVoter has 50/100 intrinsic VP (delegated to no one/self)
         gov.rawAdjustVotingPower(undelegatedVoter, 50e18, address(0));
 
@@ -772,38 +773,13 @@ contract PartyGovernanceUnitTest is Test, TestUtils {

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 3: [H-03] Withdrawal delay can be circumvented

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by IllIllI and leastwood_

[Collateral.sol#L97](https://github.com/code-423n4/2022-03-prepo/blob/f63584133a0329781609e3f14c3004c1ca293e71/contracts/core/Collateral.sol#L97)<br>

After initiating a withdrawal with `initiateWithdrawal`, it's still possible to transfer the collateral tokens.
This can be used to create a second account, transfer the accounts to them and initiate withdrawals at a different time frame such that one of the accounts is always in a valid withdrawal window, no matter what time it is.
If the token owner now wants to withdraw they just transfer the funds to the account that is currently in a valid withdrawal window.

Also, note that each account can withdraw the specified `amount`. Creating several accounts and circling & initiating withdrawals with all of them allows withdrawing larger amounts **even at the same block** as they are purchased in the future.

I consider this high severity because it breaks core functionality of the Collateral token.

### Proof of Concept

For example, assume the `_delayedWithdrawalExpiry = 20` blocks. Account A owns 1000 collateral tokens, they create a second account B.

*   At `block=0`, A calls `initiateWithdrawal(1000)`. They send their balance to account B.
*   At `block=10`, B calls `initiateWithdrawal(1000)`. They send their balance to account A.
*   They repeat these steps, alternating the withdrawal initiation every 10 blocks.
*   One of the accounts is always in a valid withdraw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-prepo)

---

### Example 4: [M-04] Withdrawing uncollateralized deposits is possible even though the position is in liquidation mode

**Source**: Code4rena
**Protocol**: Wise Lending
**Impact**: MEDIUM

**Details**:

Users can withdraw uncollateralized deposits even though their position is liquidable, [as opposed to the README](https://github.com/code-423n4/2024-02-wise-lending/blob/main/README.md?plain=1#L137). If the position is in liquidation mode, users should use their uncollateralized deposits to avoid liquidation instead of removing them.

### Proof of Concept

When withdrawing deposits from public pools, at the end of the tx is executed the [`WiseLending._healthStateCheck() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseLending.sol#L77-L90), which depending on the value of the `powerFarmCheck` will determine if the position's collateral is enough to cover the borrows.

- If `powerFarmCheck` is true, it will use the `bare` value of the collateral; meaning, the `collateralFactor` is not applied to the collateral's value.
- If `powerFarmCheck` is false, it will use the `weighted` value of the collateral; meaning, the `collateralFactor` is applied to the collateral's value.

When withdrawing an uncollateralized deposit, the [`WiseCore._coreWithdrawToken() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseCore.sol#L44-L100) calls the [`WiseSecurity.checksWithdraw() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseSecurity/WiseSecurity.sol#L237-L270) to determine the value of the `powerFarmCheck`. If the pool from where the tokens are being withdrawn is uncollateralized, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-wise-lending)

---

### Example 5: assets  s.depositCap invariant can be broken for public vaults with non-zero deposit caps

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- PublicVault.sol#L207-L208
- PublicVault.sol#L231-L232

## Description
The following check in `mint` / `deposit` does not take into consideration the new shares / amount supplied to the endpoint, since the `yIntercept` in `totalAssets()` is only updated after calling `super.mint(shares, receiver)` or `super.deposit(amount, receiver)` with the `afterDeposit` hook.

```solidity
uint256 assets = totalAssets();
if (s.depositCap != 0 && assets >= s.depositCap) {
    revert InvalidState(InvalidStates.DEPOSIT_CAP_EXCEEDED);
}
```

Thus the new shares or amount provided can be a really big number compared to `s.depositCap`, but the call will still go through.

## Recommendation
To have the inequality `assets < s.depositCap` to be always correct, we would need to calculate the to-be-updated value of `assets` beforehand and then perform the check.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 6: [M-04] Lender can trade claimToken in a malicious way to steal the borrowerâ€™s money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/modules/credit/SpigotedLine.sol#L106-L112
https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/utils/SpigotedLineLib.sol#L75-L85


## Vulnerability details

## Impact

Lender can trade claimToken in a malicious way to steal the borrower's money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData.

In the design of the protocol, the lender can use the function claimAndRepay(), the lender can take claimToken by spigot.claimEscrow and then trade the claimToken to the CreditTOken via ZeroEx exchange, then repay the credit. 

```
function claimAndRepay(address claimToken, bytes calldata zeroExTradeData) external
        whileBorrowing
        nonReentrant
        returns (uint256) { 

...
// Line 106 - Line 112
uint256 newTokens = claimToken == credit.token ?
          spigot.claimEscrow(claimToken) :  // same asset. dont trade
          _claimAndTrade(                   // trade revenue token for debt obligation
              claimToken,
              credit.token,
              zeroExTradeData
          );
...
// Line 128 - Line 130 
 credits[id] = _repay(credit, id, repaid);

        emit RevenuePayment(claimToken, repaid);

...

}

```

```
function _claimAndTrade(
      address claimToken,
      address targetToken,
      bytes calldata zeroExTradeData
    )
        internal
        returns (uint256)
    {
        (uint256 tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 7: [M-07] Oracleâ€™s two-day feature can be gamed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L124


## Vulnerability details

## Impact
The two-day feature of the oracle can be gamed where you only have to manipulate the oracle for ~2 blocks.

## Proof of Concept
The oracle computes the day using:
```sol
uint day = block.timestamp / 1 days;
```

Since we're working with `uint` values here, the following is true:
$1728799 / 86400 = 1$
$172800 / 86400 = 2$

Meaning, if you manipulate the oracle at the last block of day $X$, e.g. 23:59:50, and at the first block of day $X + 1$, e.g. 00:00:02, you bypass the two-day feature of the oracle. You only have to manipulate the oracle for two blocks.

This is quite hard to pull off. I'm also not sure whether there were any instances of Chainlink oracle manipulation before. But, since you designed this feature to prevent small timeframe oracle manipulation I think it's valid to point this out.

## Tools Used
none

## Recommended Mitigation Steps
If you increase it to a three-day interval you can fix this issue. Then, the oracle has to be manipulated for at least 24 hours.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 8: enableTradingWithWeights allow the Treasury to change the poolâ€™s weights even if the swap is not disabled

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
AeraVaultV1.sol#L574-L583

## Description
`enableTradingWithWeights` is a function that can only be called by the owner of the Aera Vault contract and that should be used only to re-enable the swap feature on the pool while updating token weights. The function does not verify if the poolâ€™s swap feature is enabled and for this reason, it allows the Treasury to act as the manager who is the only actor allowed to change the pool weights. The function should add a check to ensure that it is only callable when the poolâ€™s swap is disabled.

## Recommendation
Update the function to revert when the poolâ€™s swap is enabled.

```solidity
function enableTradingWithWeights(uint256[] calldata weights)
external
override
onlyOwner
whenInitialized
{
  bool isSwapEnabled = pool.getSwapEnabled();
  if( isSwapEnabled ) {
    revert Aera__PoolSwapIsAlreadyEnabled();
  }
  uint256 timestamp = block.timestamp;
  pool.updateWeightsGradually(timestamp, timestamp, weights);
  setSwapEnabled(true);
}
```

## Gauntlet
Fixed in PR #126.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 9: [M-06] Manager can get around min reserves check, draining all funds from Collateral.sol

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

When a manager withdraws funds from Collateral.sol, there is a check in the `managerWithdrawHook` to confirm that they aren't pushing the contract below the minimum reserve balance.

```solidity
require(collateral.getReserve() - _amountAfterFee >= getMinReserve(), "reserve would fall below minimum");
```

However, a similar check doesn't happen in the `withdraw()` function.

The manager can use this flaw to get around the reserve balance by making a large deposit, taking a manager withdrawal, and then withdrawing their deposit.

### Proof of Concept

Imagine a situation where the token has a balance of 100, deposits of 1000, and a reserve percentage of 10%. In this situation, the manager should not be able to make any withdrawal.

But, with the following series of events, they can:

*   Manager calls `deposit()` with 100 additional tokens
*   Manager calls `managerWithdraw()` to pull 100 tokens from the contract
*   Manager calls `withdraw()` to remove the 100 tokens they added

The result is that they are able to drain the balance of the contract all the way to zero, avoiding the intended restrictions.

### Recommended Mitigation Steps

Include a check on the reserves in the `withdraw()` function as well as `managerWithdraw()`.

**[Picodes (judge) commented](https://github.com/code-423n4/2022-12-prepo-findings/issues/254#issuecomment-1356147341):**
 > From what I understand, although it's not clear from the documentation or the code, this `minReserve` requirement is here to 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 10: [H-02] A whale user is able to cause freeze of funds of other users by bypassing withdraw limit

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/3541bc704ab185a969f300e96e2f744a572a3640/apps/smart-contracts/core/contracts/WithdrawHook.sol#L61>

<https://github.com/prepo-io/prepo-monorepo/blob/3541bc704ab185a969f300e96e2f744a572a3640/apps/smart-contracts/core/contracts/WithdrawHook.sol#L68>

### Description

In Collateral.sol, users may withdraw underlying tokens using withdraw. Importantly, the withdrawal must be approved by withdrawHook if set:

    function withdraw(uint256 _amount) external override nonReentrant {
      uint256 _baseTokenAmount = (_amount * baseTokenDenominator) / 1e18;
      uint256 _fee = (_baseTokenAmount * withdrawFee) / FEE_DENOMINATOR;
      if (withdrawFee > 0) { require(_fee > 0, "fee = 0"); }
      else { require(_baseTokenAmount > 0, "amount = 0"); }
      _burn(msg.sender, _amount);
      uint256 _baseTokenAmountAfterFee = _baseTokenAmount - _fee;
      if (address(withdrawHook) != address(0)) {
        baseToken.approve(address(withdrawHook), _fee);
        withdrawHook.hook(msg.sender, _baseTokenAmount, _baseTokenAmountAfterFee);
        baseToken.approve(address(withdrawHook), 0);
      }
      baseToken.transfer(msg.sender, _baseTokenAmountAfterFee);
      emit Withdraw(msg.sender, _baseTokenAmountAfterFee, _fee);
    }

The hook requires that two checks are passed:

    if (lastGlobalPeriodReset + globalPeriodLength < block.timestamp) {
      lastGlobalPeriodReset = block.timestamp;
      globalAmountWithdrawnThisPeriod = _amountBefor

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 11: Supplying and borrowing can recreate p2p credit lines even if p2p is disabled

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

**Context:** 
- aave-v2/EntryPositionsManager.sol#L117
- aave-v2/EntryPositionsManager.sol#L215
- compound/PositionsManager.sol#L258
- compound/PositionsManager.sol#L354

**Description:**  
When supplying/borrowing, the algorithm attempts to reduce the deltas `p2pBorrowDelta` and `p2pSupplyDelta` by moving borrowers and suppliers back to P2P. However, it does not check if P2P is enabled. This oversight has significant implications, especially when governance disables P2P and aims to redirect users and liquidity back to the pool through `increaseDelta` calls. Users could inadvertently re-enter P2P by supplying and borrowing.

**Recommendation:**  
Disable matching the initial delta-matching step in supply and borrow if P2P is disabled. This precaution is necessary only for supply and borrow operations and not for repay and withdraw. For repay and withdraw, while we are also reducing the delta, we are not creating new P2P credit lines (as `p2pAmount` also decreases, resulting in a differential of zero). This process can be viewed as unmatching our P2P balance, reducing the delta, shifting our P2P balance to the pool, and then withdrawing from the pool.

**Morpho:** Fixed in PR 1453.

**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MorphoV1-Spearbit-Security-Review.pdf)

---

### Example 12: [M-01] Bypass `userWithdrawLimitPerPeriod` check

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

User can bypass the `userWithdrawLimitPerPeriod` check by transferring the balance to another account.

### Proof of Concept

1.  Assume `userWithdrawLimitPerPeriod` is set to `1000`
2.  User A has current deposit of amount `2000` and wants to withdraw everything instantly
3.  User A calls the withdraw function and takes out the `1000` amount

<!---->

    function withdraw(uint256 _amount) external override nonReentrant {
        uint256 _baseTokenAmount = (_amount * baseTokenDenominator) / 1e18;
        uint256 _fee = (_baseTokenAmount * withdrawFee) / FEE_DENOMINATOR;
        if (withdrawFee > 0) { require(_fee > 0, "fee = 0"); }
        else { require(_baseTokenAmount > 0, "amount = 0"); }
        _burn(msg.sender, _amount);
        uint256 _baseTokenAmountAfterFee = _baseTokenAmount - _fee;
        if (address(withdrawHook) != address(0)) {
          baseToken.approve(address(withdrawHook), _fee);
          withdrawHook.hook(msg.sender, _baseTokenAmount, _baseTokenAmountAfterFee);
          baseToken.approve(address(withdrawHook), 0);
        }
        baseToken.transfer(msg.sender, _baseTokenAmountAfterFee);
        emit Withdraw(msg.sender, _baseTokenAmountAfterFee, _fee);
      }

4.  Remaining `1000` amount cannot be withdrawn since `userWithdrawLimitPerPeriod` is reached

<!---->

    function hook(
        address _sender,
        uint256 _amountBeforeFee,
        uint256 _amountAfterFee
      ) external override onlyCollateral {
    ...
    require(userToAmountWit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 13: FeeCollector not well integrated

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context: FeeCollector.sol

### Description
There is a contract to pay fees for using the bridge: **FeeCollector**. This is used by crafting a transaction via the frontend API, which then calls the contract through `_executeAndCheckSwaps()`. 

Here is an example of the contract of such a transaction. It is whitelisted, so no fees are paid if a developer is using the LiFi contracts directly. However, the current mechanism isn't suited for this purpose. The `_executeAndCheckSwaps()` function is geared for swaps and has several checks on balances. These (and future) checks could interfere with fee payments. Additionally, this is a complicated and non-transparent approach. The project has suggested viewing `_executeAndCheckSwaps()` as a multicall mechanism.

### Recommendation
- Use a dedicated mechanism to pay for fees.
- If `_executeAndCheckSwaps()` is intended to be a multicall mechanism, then rename the function.

## LiFi
We acknowledge the risk and encourage integrators to utilize our API at this time.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 14: [M-06] User can initiate withdraw for previous epoch if rebase hasn't been called since end of epoch

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52_

User is able to withdraw unstaked asset sooner than they should be.

### Proof of Concept

`Unstake()` allows the user to bypass the rebase() call by setting \_trigger to false. Since rebase() is bypassed, epoch.number could potentially be stale i.e. doesn't match the Tokemak epoch. A user could potentially call unstake() with \_trigger = false immediately after an epoch has ended but expiry would be set using the stale epoch.number because it wouldn't be updated by rebase(). This would allow the user to withdraw early before their funds were actually available in the contract because their withdrawal would be considered to be in the epoch before they actually initiated the withdrawal.

### Recommended Mitigation Steps

`Rebase()` cannot be optional when calling unstake.

**[toshiSat (Yieldy) acknowledged and commented](https://github.com/code-423n4/2022-06-yieldy-findings/issues/28#issuecomment-1168978499):**
 > We use a coolDownAmount of 2 to get around this.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 15: M-4: Users can avoid performance fees by withdrawing before the end of the epoch forcing other users to pay their fees

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/75 

## Found by 
0x52

## Summary

No performance fees are taken when user withdraws early from the vault but their withdrawal value will be used to take fees, which will be taken from other users.

## Vulnerability Detail

    uint256 adjustedTotalAssets = _totalAssets() + l.totalWithdrawals;

    if (adjustedTotalAssets > l.lastTotalAssets) {
        netIncome = adjustedTotalAssets - l.lastTotalAssets;

        feeInCollateral = l.performanceFee64x64.mulu(netIncome);

        ERC20.safeTransfer(l.feeRecipient, feeInCollateral);
    }

When taking the performance fees, it factors in both the current assets of the vault as well as the total value of withdrawals that happened during the epoch. Fees are paid from the collateral tokens in the vault, at the end of the epoch. Paying the fees like this reduces the share price of all users, which effectively works as a fee applied to all users. The problem is that withdraws that take place during the epoch are not subject to this fee and the total value of all their withdrawals are added to the adjusted assets of the vault. This means that they don't pay any performance fee but the fee is still taken from the vault collateral. In effect they completely avoid the fee force all there other users of the vault to pay it for them.

## Impact

User can avoid performance fees and force other users to pay them

## Code Snippet

[VaultInternal.sol#L504-L532](https://githu

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


