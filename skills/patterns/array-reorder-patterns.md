# Array Reorder Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for array reorder vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-4: Wrong implementation of orderbook can make user can't get their fund back

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/66 

## Found by 
Trumpero

## Lines of code 
https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L240
https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L182-L190

## Summary
When a user remove an order, next user call `addLimitOrder` can override the latest order with his/her order. It will make one who is owner of that latest order lose their fund. 

## Vulnerability Detail
Function `_remove` will decrease value of `index.length` by 1 when an order is removed
```solidity=
// url = https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L240
function _remove(Index storage index, uint256 id) internal returns (bool) {
    index.length = index.length > 0 ? index.length - 1 : 1;
    ...
}
```
Instead of reserving `id` of removed order to reuse for next created order, function `_insert` use the id of new order is `index.length + 1`
```solidity=
// url = https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L165-L172
function _insert(
    Index storage index,
    int128 price64x64,
    uint256 size,
    address buyer
) internal returns (uint256) {
    index.length = index.length > 0 ? index.length + 1 : 1;
    uint256 id = index.length;
    ...
}
```
It will override the latest order with new order's data.

For 

*[Content truncated...]*

---

### Example 2: M-1: `claimFromIndividualPlugin()` may endup claiming the reward from a different plugin with wrong `auxData` when the index as changed due to `removePlugin()`

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/86 

## Found by 
WATCHPUG

## Summary

When `removePlugin()` happens between the user sends the `claimFromIndividualPlugin()` transaction and before it gets minted, it may lead to lesser rewards as the `auxData` prepared for another plugin will now be used.

## Vulnerability Detail

When a user calls `claimFromIndividualPlugin()`, a `pluginIndex` is used to refer to a plugin.

However, if the `PLUGIN_EDITOR` removed a plugin before the transaction gets minted, the plugin referred by the `pluginIndex` can be changed to another plugin.

As a result, the `auxData` supposed to be supplied to the original plugin is now supplied to another plugin.

## Impact

The user may end up with lesser rewards as a wrong `auxData` is supplied to the wrong plugin.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L420-L429

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L178-L185

## Tool used

Manual Review

## Recommendation

Consider using `pluginAddress` instead.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/8

---

### Example 3: [M-07] User may get less tokens than expected when collateral list order changes

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/8a2c3aaf4bd054581b06d33049370a6f01b56d44/contracts/transmuter/libraries/LibSetters.sol#L123> <br><https://github.com/AngleProtocol/angle-transmuter/blob/8a2c3aaf4bd054581b06d33049370a6f01b56d44/contracts/transmuter/facets/Redeemer.sol#L64>

The order of `ts.collateralList` is not stable: Whenever `LibSetters.revokeCollateral` is used to revoke a collateral, it may change because of the swap that is performed. However, the function `Redeemer.redeem` relies on this order, as the user has to provide the `minAmountsOut` in the order of `ts.collateralList`. This can lead to situations where the user has crafted the `minAmountsOut` array when the order was still different, leading to unintended results (and potentially redemptions that the user did not want to accept). It also means that revoking a collateral can be challenging for the team / governance because it should never be done when a user has already prepared a redemption (either via the frontend which he had open or some other way to interact with the contract). But there is of course no way to know this.

### Proof of Concept

Let's say the system contains the collateral \[tokenA, tokenB, tokenC]. `normalizedStables` for tokenA is 0. The user therefore does not want to receive tokenA (and will not receive anything for it). However, it is extremely important to him that he receives 100,000 of tokenC. He therefore crafts a `minAmountsOut` of \[0, 10000, 100000]. Just b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
