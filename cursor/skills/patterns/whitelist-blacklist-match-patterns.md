# Whitelist/Blacklist Match Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Codehawks, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for whitelist/blacklist match vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Improve dexAllowlist

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity: Medium Risk

### Context:
- **Files:** 
  - SwapperV2.sol (#L67-L81)
  - Swapper.sol (#L65-L78)
  - LibAccess.sol (#L13-L15)
  - DexManagerFacet.sol
  - AccessManagerFacet.sol

### Description:
The functions `_executeSwaps()` in both `SwapperV2.sol` and `Swapper.sol` employ a whitelist to ensure that the correct functions in the permitted DEXes are executed. The validation checks for `approveTo`, `callTo`, and `signature` (`callData`) are conducted independently. This independent approach creates a risk, as any signature can be considered valid for any DEX in conjunction with any `approveTo` address. This grants broader access than necessary.

This issue is critical because multiple functions may share the same signature. For instance, the following two functions have identical signatures:

- `gasprice_bit_ether(int128)`
- `transferFrom(address,address,uint256)`

The bytes4 signature for both is `0x23b872dd`. Notably, brute-forcing an innocuous-looking function is straightforward. 

The `transferFrom()` function poses a particular threat as it enables the sweeping of tokens from other users who have granted an allowance to the LiFi Diamond. If a DEX that contains a function with the same signature gets whitelisted, this could be exploited with the existing code.

**Present in both SwapperV2.sol and Swapper.sol:**
```solidity
function _executeSwaps(...) ... {
    ...
    if (
        !(appStorage.dexAllowlist[currentSwapData.approveTo]

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: [M-23] Calling updateNodeRunnerWhitelistStatus function always reverts

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L278-L284
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L684-L692
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L426-L492


## Vulnerability details

## Impact
Calling the `updateNodeRunnerWhitelistStatus` function by the DAO supposes to allow the trusted node runners to use and interact with the protocol when `enableWhitelisting` is set to `true`. However, since calling the `updateNodeRunnerWhitelistStatus` function executes `require(isNodeRunnerWhitelisted[_nodeRunner] != isNodeRunnerWhitelisted[_nodeRunner], "Unnecessary update to same status")`, which always reverts, the DAO is unable to whitelist any trusted node runners. Because none of them can be whitelisted, all trusted node runners cannot call functions like `registerBLSPublicKeys` when the whitelisting mode is enabled. As the major functionalities become unavailable, the protocol's usability becomes much limited, and the user experience becomes much degraded.

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L278-L284
```solidity
    function updateNodeRunnerWhitelistStatus(address _nodeRunner, bool isWhitelisted) external onlyDAO {
        require(_nodeRunner != address(0), "Zero address");
        require(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 3: Token withdrawal fails until someone manually approves spending

**Source**: Codehawks
**Protocol**: Tadle
**Impact**: HIGH

**Details**:

## Summary

The protocol uses a contract called TokenManager to control a capital pool that stores tokens.

When a user wants to withdraw, the TokenManager needs spender allowance on the capital pool, but this is not checked for, so the withdrawal fails.

## Vulnerability Details

We simulate a user creating an offer, closing it and then trying to withdraw. The withdrawal fails because of zero allowance for the TokenManager as a spender of the capital pool.

```Solidity
function test_token_withdrawal_fails() public {
    // Data for creating an offer, not relevant.
    uint256 points = 1000;
    uint256 amountToken = 1000000 * 1e18;
    uint256 collateralRate = 12000;
    uint256 eachTradeTax = 300;

    vm.startPrank(user);
    preMarktes.createOffer(
        CreateOfferParams(
            marketPlace,
            address(mockUSDCToken),
            points,
            amountToken,
            collateralRate,
            eachTradeTax,
            OfferType.Ask,
            OfferSettleType.Turbo
        )
    );

    // Close the offer.
    address offerAddr = GenerateAddress.generateOfferAddress(0);
    address stockAddr = GenerateAddress.generateStockAddress(0);

    preMarktes.closeOffer(stockAddr, offerAddr);

    tokenManager.withdraw(address(mockUSDCToken), TokenBalanceType.MakerRefund);
    vm.stopPrank();
}
```

> ```Solidity
> ├─ [8858] UpgradeableProxy::withdraw(MockERC20Token: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], 4)
> │   ├─ [8339] TokenManager::withdraw(M

*[Content truncated...]*

---

### Example 4: H-1: Bypass the blacklist restriction because the blacklist check is not done when minting or burning

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/64 

## Found by 
ctf\_sec, dirk\_y, p-tsanev, toshii
## Summary

Bypass the blacklist restriction because the blacklist check is not done when minting or burning

## Vulnerability Detail

In the whitepaper:

> the protocol emphasis that they implement a blacklist feature for enforcing OFAC, AML and other account security requirements
A blacklisted will not able to send or receive tokens

the protocol want to use the whitelist feature to be compliant to not let the blacklisted address send or receive dSahres

For this reason, before token transfer, the protocol check if address from or address to is blacklisted and the blacklisted address can still create buy order or sell order

```solidity
   function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // Restrictions ignored for minting and burning
        // If transferRestrictor is not set, no restrictions are applied

        // @audit
        // why don't you not apply mint and burn in blacklist?
        if (from == address(0) || to == address(0) || address(transferRestrictor) == address(0)) {
            return;
        }

        // Check transfer restrictions
        transferRestrictor.requireNotRestricted(from, to);
    }
```

this is calling

```solidity
function requireNotRestricted(address from, address to) external view virtual {
	// Check if either account is restricted
	if (blacklist[from] || blackl

*[Content truncated...]*

---

### Example 5: M-8: Teller Cannot Be Removed From Callback Contract

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/18 

## Found by 
xiaoming90

## Summary

If a vulnerable Teller is being exploited by an attacker, there is no way for the owner of the Callback Contract to remove the vulnerable Teller from their Callback Contract.

## Vulnerability Detail

The Callback Contract is missing the feature to remove a Teller. Once a Teller has been added to the whitelist (`approvedMarkets` mapping), it is not possible to remove the Teller from the whitelist.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseCallback.sol#L59

```solidity
File: BondBaseCallback.sol
56:     /* ========== WHITELISTING ========== */
57: 
58:     /// @inheritdoc IBondCallback
59:     function whitelist(address teller_, uint256 id_) external override onlyOwner {
60:         // Check that the market id is a valid, live market on the aggregator
61:         try _aggregator.isLive(id_) returns (bool live) {
62:             if (!live) revert Callback_MarketNotSupported(id_);
63:         } catch {
64:             revert Callback_MarketNotSupported(id_);
65:         }
66: 
67:         // Check that the provided teller is the teller for the market ID on the stored aggregator
68:         // We could pull the teller from the aggregator, but requiring the teller to be passed in
69:         // is more explicit about which contract is being whitelisted
70:         if (teller_ != address(_aggregator.getTeller(id_))) revert Callback_Teller

*[Content truncated...]*

---

### Example 6: M-11: Auctioneer Cannot Be Removed From The Protocol

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/13 

## Found by 
xiaoming90

## Summary

If a vulnerable Auctioneer is being exploited by an attacker, there is no way to remove the vulnerable Auctioneer from the protocol.

## Vulnerability Detail

The protocol is missing the feature to remove an auctioneer. Once an auctioneer has been added to the whitelist, it is not possible to remove the auctioneer from the whitelist.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondAggregator.sol#L62

```solidity
File: BondAggregator.sol
62:     function registerAuctioneer(IBondAuctioneer auctioneer_) external requiresAuth {
63:         // Restricted to authorized addresses
64: 
65:         // Check that the auctioneer is not already registered
66:         if (_whitelist[address(auctioneer_)])
67:             revert Aggregator_AlreadyRegistered(address(auctioneer_));
68: 
69:         // Add the auctioneer to the whitelist
70:         auctioneers.push(auctioneer_);
71:         _whitelist[address(auctioneer_)] = true;
72:     }
```

## Impact

In the event that a whitelisted Auctioneer is found to be vulnerable and has been actively exploited by an attacker in the wild, the protocol needs to mitigate the issue swiftly by removing the vulnerable Auctioneer from the protocol. However, the mitigation effort will be hindered by the fact there is no way to remove an Auctioneer within the protocol once it has been whitelisted. Thus, it might not be possible

*[Content truncated...]*

---

### Example 7: M-1: Non-whitelisted tokens cannot be added if the limit of token addresses is filled with whitelisted ones

**Source**: Sherlock
**Protocol**: OpenQ
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-openq-judging/issues/530 

## Found by 
rvierdiiev, ast3ros, 0xdeadbeef, RaymondFam, XKET, csanuragjain, HollaDieWaldfee, bin2chen, 0xbepresent, kiki\_dev, unforgiven, Breeje, yixxas, hake, libratus, cergyk, Ruhum, CodeFoxInc, Jeiwan, carrot

## Summary
Non-whitelisted tokens cannot be deposited to a bounty contract if too many whitelisted contracts were deposited.
## Vulnerability Detail
The [DepositManagerV1.fundBountyToken](https://github.com/sherlock-audit/2023-02-openq/blob/main/contracts/DepositManager/Implementations/DepositManagerV1.sol#L36) function allows depositing both whitelisted and non-whitelisted tokens by implementing the following check:
1. if a token is whitelisted, it [can be deposited without restrictions](https://github.com/sherlock-audit/2023-02-openq/blob/main/contracts/DepositManager/Implementations/DepositManagerV1.sol#L45);
1. if a token is not whitelisted, it [cannot be deposited if `openQTokenWhitelist.TOKEN_ADDRESS_LIMIT` tokens have already been deposited](https://github.com/sherlock-audit/2023-02-openq/blob/main/contracts/DepositManager/Implementations/DepositManagerV1.sol#L46-L49).

However, while the token addresses limit requirement is only applied to non-whitelisted tokens, whitelisted tokens also increase the counter of token addresses: both non-whitelisted and whitelisted token addresses are [added to the `tokenAddresses` set](https://github.com/sherlock-audit/2023-02-openq/blob/main/contr

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

