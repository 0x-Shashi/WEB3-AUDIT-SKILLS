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
OpenZeppelin’s SafeERC20 library, the return values of calls to `transfer` and
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
