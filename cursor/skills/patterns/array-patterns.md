# Array Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for array vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] User can steal tokens by using duplicated ERC20 tokens as parameter in `NounsDAOLogicV1Fork.quit`

**Source**: Code4rena
**Protocol**: Nouns DAO
**Impact**: HIGH

**Details**:

Calling [NounsDAOLogicV1Fork.quit](https://github.com/nounsDAO/nouns-monorepo/blob/718211e063d511eeda1084710f6a682955e80dcb/packages/nouns-contracts/contracts/governance/fork/newdao/governance/NounsDAOLogicV1Fork.sol#L206-L216) by using dupliated ERC20 tokens, malicious user can gain more ERC20 tokens than he/she is supposed to, even drain all ERC20 tokens.

### Proof of Concept

In function, [NounsDAOLogicV1Fork.quit](https://github.com/nounsDAO/nouns-monorepo/blob/718211e063d511eeda1084710f6a682955e80dcb/packages/nouns-contracts/contracts/governance/fork/newdao/governance/NounsDAOLogicV1Fork.sol#L206-L216), `erc20TokensToInclude` is used to specified tokens a user wants to get, but since the function doesn't verify if `erc20TokensToInclude` contains dupliated tokens, it's possible that a malicious user calls the function by specify the ERC20 more than once to get more share tokens.

```solidity
    function quit(uint256[] calldata tokenIds, address[] memory erc20TokensToInclude) external nonReentrant {
        // check that erc20TokensToInclude is a subset of `erc20TokensToIncludeInQuit`
        address[] memory erc20TokensToIncludeInQuit_ = erc20TokensToIncludeInQuit;
        for (uint256 i = 0; i < erc20TokensToInclude.length; i++) {
            if (!isAddressIn(erc20TokensToInclude[i], erc20TokensToIncludeInQuit_)) {
                revert TokensMustBeASubsetOfWhitelistedTokens();
            }
        }

        quitInternal(tokenIds, erc20TokensToInclude);
    }

    f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-nounsdao)

---

### Example 2: H-4: Wrong implementation of orderbook can make user can't get their fund back

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

### Example 3: H-12: Pending CRV rewards are not accounted for and can cause unfair liquidations

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

### Example 4: M-9: Bad debt may persist even after complete liquidation in Velo Vault due to truncation

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/174 

## Found by 
0x52

## Summary

When liquidating a user, if all their collateral is taken but it is not valuable enough to repay the entire loan they would be left with remaining debt. This is what is known as bad debt because there is no collateral left to take and the user has no obligation to pay it back. When this occurs, the vault will forgive the user's debts, clearing the bad debt. The problem is that the valuations are calculated in two different ways which can lead to truncation issue that completely liquidates a user but doesn't clear their bad debt.

## Vulnerability Detail

            uint256 totalUserCollateral = totalCollateralValue(_collateralAddress, _loanHolder);
            uint256 proposedLiquidationAmount;
            { //scope block for liquidationAmount due to stack too deep
                uint256 liquidationAmount = viewLiquidatableAmount(totalUserCollateral, 1 ether, isoUSDBorrowed, liquidatableMargin);
                require(liquidationAmount > 0 , "Loan not liquidatable");
                proposedLiquidationAmount = _calculateProposedReturnedCapital(_collateralAddress, _loanNFTs, _partialPercentage);
                require(proposedLiquidationAmount <= liquidationAmount, "excessive liquidation suggested");
            }
            uint256 isoUSDreturning = proposedLiquidationAmount*LIQUIDATION_RETURN/LOAN_SCALE;
            if(proposedLiquidationAmount >= totalUserColl

*[Content truncated...]*

---

### Example 5: [M-07] User may get less tokens than expected when collateral list order changes

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

- Total findings analyzed: 6
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

