---
id: PAT-AUCTION
title: Auction Security Patterns
category: defi
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - auction
  - bidding
  - settlement

finding_count: 15
last_updated: 2026-01-31
---
# Auction Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 10 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Spearbit

---

## Detection Checklist

- [ ] Check for auction vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] User can bypass `MAX_EXPIRATION` when extend expiration

**Source**: Code4rena
**Protocol**: Initia
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2025-01-initia-move/blob/a96f5136c4808f6968564a4592fe2d6ac243a233/usernames-module/sources/name_service.move# L483>

### Finding Description and Impact

In the `extend_expiration` function, the validation for the duration is incorrect, allowing the user to bypass `MAX_EXPIRATION`:
```

 let expiration_date = metadata::get_expiration_date(token);
        let new_expiration_date = if (expiration_date > timestamp) {
            expiration_date + duration
        } else {
            timestamp + duration
        };

        assert!(
=>            new_expiration_date - expiration_date <= MAX_EXPIRATION,
            error::invalid_argument(EMIN_DURATION),
        );

        metadata::update_expiration_date(token, new_expiration_date);
```

The issue arises because the code subtracts `new_expiration_date - expiration_date` for validation.

Assume a user registers a domain and the `expiration_date` is equal to `MAX_EXPIRATION` `+` timestamp. Then, the user performs `extend_expiration` with a `duration` value equal to the `MAX_EXPIRATION`, the `new_expiration_date` becomes `expiration_date + duration`.

This leads to the following verification check passing:
```

assert!(
    new_expiration_date - expiration_date <= MAX_EXPIRATION,
    error::invalid_argument(EMIN_DURATION),
);
```

Since the `new_expiration_date` is calculated using `expiration_date` `+` `duration`, the subtraction `(new_expiration_date - expiration_date)` will always be less than to `

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2025-01-initia-move)

---

### Example 2: [H-03] `saleReceiver` and `feeReceiver` can steal refunds after sale has ended

**Source**: Code4rena
**Protocol**: Escher
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L67-L68>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L81-L88>

First, lets go over how a buy happens.

A buyer can buy NFTs at a higher price and then once the auction ends they can use `refund()` to return the over payments. The effect is that they bought the NFTs at the lowest price (Lowest Price Dutch Auction).

Now, let's move on to what happens when the sale ends:

The sale is considered ended when the last NFT is sold which triggers the payout to the seller and fee collector:

```javascript
81:        if (newId == temp.finalId) {
82:            sale.finalPrice = uint80(price);
83:            uint256 totalSale = price * amountSold;
84:            uint256 fee = totalSale / 20;
85:            ISaleFactory(factory).feeReceiver().transfer(fee);
86:            temp.saleReceiver.transfer(totalSale - fee);
87:            _end();
88:        }
```

Earlier there's also a check that you cannot continue buying once the `currentId` has reached `finalId`:

```javascript
67:        uint48 newId = amount + temp.currentId;
68:        require(newId <= temp.finalId, "TOO MANY");
```

However, it is still possible to buy `0` NFTs for whichever price you want even after the sale has ended. Triggering the "end of sale" snippet again, since `newId` will still equal `temp.finalId`.

The attacker, `saleReceiver` (or `feeReceiver`), buys `0` NFTs for the delta between `totalSale` and th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-escher)

---

### Example 3: settleAuction() doesn't check if the auction was successful

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Risk Report

## Severity
**High Risk**

## Context
`CollateralToken.sol#L600`

## Description
The `settleAuction()` function is a privileged functionality called by `LienToken.payDebtViaClearingHouse()`. It is intended to be called on a successful auction, but it lacks verification to ensure this is the case. 

Anyone can create a fake Seaport order with one of its considerations set as the `CollateralToken`, as described in Issue 93. Another potential issue arises if the Seaport orders can be "Restricted" in the future. In that scenario, an authorized entity could force the execution of `settleAuction()` on `CollateralToken`, and when Seaport tries to call back on the zone to validate, it would likely fail.

## Recommendation
The following validations can be performed:

- `CollateralToken` doesn't own the underlying NFT.
- `collateralIdToAuction[collateralId]` is active.

By implementing these checks, `settleAuction()` can only be called upon the successful completion of the Seaport auction created by the Astaria protocol.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: [H-14] Fund will be stuck if a buyout is started while there are pending migration proposals

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by shenwilly, also found by 0x52, codexploder, dipp, kenzo, Lambda, MEP, panprog, smiling&#95;heretic, Treasure-Seeker, TrungOre, xiaoming90, and zzzitron_

Funds in migration proposals could potentially be stuck forever if a buyout auction on the same vault is started by other party.

Most of the functions within `Migration.sol` can only be executed depending on the state of buyout auction in `Buyout.sol`. When there is no buyout happening, a migration proposal can be made and anyone can contribute to the proposal. However, it is possible that a buyout auction is started by another party while a pending proposal is not commited yet.

When this scenario happens, there is no action that could be taken to interact with the pending proposal. All funds that have been contributed cannot be withdrawn. This is because the functions only check for the state of the buyout auction, instead of also considering whether the buyout auction's proposer is `Migration.sol`:

    (address token, uint256 id) = IVaultRegistry(registry).vaultToToken(_vault);
    if (id == 0) revert NotVault(_vault);
    // Reverts if buyout state is not inactive
    (, , State current, , , ) = IBuyout(buyout).buyoutInfo(_vault);
    State required = State.INACTIVE;
    if (current != required) revert IBuyout.InvalidState(required, current);

Proposal contributors have to wait until the buyout failed before they can withdraw their funds. In case the buyout succeeded, their funds will be stuck forever.

#

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 5: M-1: Auction fails if the 'Honorarium Rate' is 0%

**Source**: Sherlock
**Protocol**: RadicalxChange
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-radicalxchange-judging/issues/31 

## Found by 
Al-Qa-qa, sammy
## Summary
The Honorarium Rate is the required percentage of a winning Auction Pitch bid that the Steward makes to the Creator Circle at the beginning of each Stewardship Cycle. 

`$$ Winning Bid * Honorarium Rate = Periodic Honorarium $$`

To mimic the dynamics of private ownership, the _Creator Circle_ may choose a 0% _Honorarium Rate_. However, doing so breaks the functionality of the protocol.
## Vulnerability Detail
To place a bid, a user must call the [`placeBid`](https://github.com/RadicalxChange/pco-art/blob/4acd6b06840028ba616b6200439ce0d6aa1e6276/contracts/auction/facets/EnglishPeriodicAuctionFacet.sol#L153) function in `EnglishPeriodicAuctionFacet.sol` and deposit collateral(`collateralAmount`) equal to `bidAmount + feeAmount`. The `feeAmount` here represents the _Honorarium Rate_ mentioned above. 
The `placeBid` function calls the [`_placeBid`](https://github.com/RadicalxChange/pco-art/blob/4acd6b06840028ba616b6200439ce0d6aa1e6276/contracts/auction/EnglishPeriodicAuctionInternal.sol#L286) internal function in `EnglishPeriodicAuctionInternal.sol` which calculates the  `totalCollateralAmount` as follows : 
```solidity
uint256 totalCollateralAmount = bid.collateralAmount + collateralAmount;
```
Here, `bid.collateralAmount` is the cumulative collateral deposited by the bidder in previous bids during the current auction round(i.e, zero if no bids were place

*[Content truncated...]*

---

### Example 6: M-16: Auction timers following liquidity can fall through the floor price causing pool insolvency

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/76 

## Found by 
CRYP70

## Summary
When a borrower cannot pay their debt in an ERC20 pool, their position is liquidated and their assets enter an auction for other users to purchase small pieces of their assets. Because of the incentive that users wish to not pay above the standard market price for a token, users will generally wait until assets on auction are as cheap as possible to purchase however, this is flawed because this guarantees a loss for all lenders participating in the protocol with each user that is liquidated.

## Vulnerability Detail
Consider a situation where a user decides to short a coin through a loan and refuses to take the loss to retain the value of their position. When the auction is kicked off using the `kick()` function on this user, as time moves forward, the price for puchasing these assets becomes increasingly cheaper. These prices can fall through the floor price of the lending pool which will allow anybody to buy tokens for only a fraction of what they were worth originally leading to a state where the pool cant cover the debt of the user who has not paid their loan back with interest. The issue lies in the `_auctionPrice()` function of the `Auctions.sol` contract which calculates the price of the auctioned assets for the taker. This function does not consider the floor price of the pool. The proof of concept below outlines this scenario:

*Proof of Concept:*
```solidity
  

*[Content truncated...]*

---

### Example 7: M-12: Deposits are eliminated before currently unclaimed reserves when there is no reserve auction

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/102 

## Found by 
hyh

## Summary

Reserves that were unclaimed during last reserve auction that's now ended are not utilized for bad debt coverage and are treated as liabilities despite it is the free reserve funds of the pool.

Due to that deposits are being written off when there are still reserve funds exist and deposits' turn as a last resort liquidity source aren't came yet.

## Vulnerability Detail

Suppose auctioned reserves weren't taken for any reason: say no market participants were there for that particular pool in the period when reserve auction implied Ajna token price was above market. Then there is no liability, i.e. that amount is free pool funds and to be used ahead of HPB deposits to cover any deficits.

Currently that's not happening, instead unclaimed reserves are frozen and aren't used. I.e. system treats these funds as being liable (while they aren't, auction is ended), so only very last reserve funds, that weren't yet added to the reserve auctions pot, can be used to cover bad debt. When there are not enough such funds, deposits are written off.

## Impact

Deposit holders take a loss when the pool in fact do have reserve funds to cover bad debt. This loss isn't a part of the declared mechanics of the protocol.

Reserve auction can end up with not all auctioned reserves taken frequently enough due to, for example:
- short period of time when Ajna token were overpriced in it,
- or th

*[Content truncated...]*

---

### Example 8: [M-10] Bidder Funds Can Become Unrecoverable Due to 1 second Overlap in `participateToAuction()` and `claimAuction()`

**Source**: Code4rena
**Protocol**: NextGen
**Impact**: MEDIUM

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-10-nextgen/blob/main/smart-contracts/AuctionDemo.sol#L57><br>
<https://github.com/code-423n4/2023-10-nextgen/blob/main/smart-contracts/AuctionDemo.sol#L104>

### Impact

Bidder funds may become irretrievable if the `participateToAuction()` function is executed after `claimAuction()` during a 1-second overlap.

### Proof of Concept

The protocol allows bidders to use the `participateToAuction()` function up to the auction's end time.

```solidity
    function participateToAuction(uint256 _tokenid) public payable {
      ->require(msg.value > returnHighestBid(_tokenid) && block.timestamp <= minter.getAuctionEndTime(_tokenid) && minter.getAuctionStatus(_tokenid) == true);
        auctionInfoStru memory newBid = auctionInfoStru(msg.sender, msg.value, true);
        auctionInfoData[_tokenid].push(newBid);
    }
```

However, the issue arises when an auction winner immediately calls `claimAuction()` right after the auction concludes, creating a 1-second window during which both `claimAuction()` and `participateToAuction()` can be executed.

```solidity
    function claimAuction(uint256 _tokenid) public WinnerOrAdminRequired(_tokenid,this.claimAuction.selector){
      ->require(block.timestamp >= minter.getAuctionEndTime(_tokenid) && auctionClaim[_tokenid] == false && minter.getAuctionStatus(_tokenid) == true);
        auctionClaim[_tokenid] = true;
        uint256 highestBid = returnHighestBid(_tokenid);
        address ownerOf

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-nextgen)

---

### Example 9: [M-04] Auction won't work correctly with fee-on-transfer & rebasing tokens

**Source**: Pashov Audit Group
**Protocol**: Rolling Dutch Auction
**Impact**: MEDIUM

**Details**:

**Impact:**
High, as it can lead to a loss of value

**Likelihood:**
Low, as such tokens are not so common

**Description**

The code in `createAuction` does the following:

```solidity
IERC20(reserveToken).transferFrom(msg.sender, address(this), reserveAmount);
...
...
state.reserves = reserveAmount;
```

so it basically caches the expected transferred amount. This will not work if the `reserveToken` has a fee-on-transfer mechanism, since the actual received amount will be less because of the fee. It is also a problem if the token used had a rebasing mechanism, as this can mean that the contract will hold less balance than what it cached in `state.reserves` for the auction, or it will hold more, which will be stuck in the protocol.

**Recommendations**

You can either explicitly document that you do not support tokens with a fee-on-transfer or rebasing mechanism or you can do the following:

1. For fee-on-transfer tokens, check the balance before and after the transfer and use the difference as the actual amount received.
2. For rebasing tokens, when they go down in value, you should have a method to update the cached `reserves` accordingly, based on the balance held. This is a complex solution.
3. For rebasing tokens, when they go up in value, you should add a method to actually transfer the excess tokens out of the protocol.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-03-01-Rolling Dutch Auction.md)

---

### Example 10: M-7: Malicious users can exploit the auction and make profit when the SetToken is not locked.

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/57 

## Found by 
ast3ros
## Summary

The SetToken can be minted and redeemed by anyone when it is not locked during rebalancing. This can allow malicious users to front-run and back-run the bidders and manipulate the auction outcome.

## Vulnerability Detail

When rebalancing, the token manager can configure if the SetToken is locked or not. If the SetToken is not locked, anyone can mint and redeem the SetToken using BasicIssuanceModule. The token manager can also configure the pricing mechanism via the priceAdapter. There are some mechanisms:
- ConstantPriceAdapter: the price is fixed - similar to place limit orders.
- BoundedStepWise adapters: like Dutch Auction which the price can increase/decrease over time.

Let's see an example: 

The current price of WETH is 1940 USDC.
Total supply of the SetToken is 10.

A Set Token with component WETH and current unit(1 WETH) wants to achieve target unit (0.5 WETH - 975 USDC).
- Current unit: 1 WETH => Current notional: 10 WETH
- Target unint: 0.5 WETH - 975 USDC => Target notional: (5 WETH - 9750 USDC)

To achieve this, it needs to sell WETH to buy USDC. The manager starts rebalancing using linear price curve: start at $2000, lower to minimum $1900, take steps of $0.1 every minute. It also chooses USDC as the quote token.

Assuming when the price of WETH reaches 1950 USDC, a bidder bids for all of the available WETH for the rebalance process, which is 0.5 WETH p

*[Content truncated...]*

---

### Example 11: M-6: Target raises can be highly damaging for dutch auctions with multiple components

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

### Example 12: M-4: Full inventory asset purchases can be DOS'd via frontrunning

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/41 

## Found by 
0x52, Arabadzhiev
## Summary

Users who attempt to swap the entire component value can be frontrun with a very small bid making their transaction revert

## Vulnerability Detail

[AuctionRebalanceModuleV1.sol#L795-L796](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L795-L796)

        // Ensure that the component quantity in the bid does not exceed the available auction quantity.
        require(_componentQuantity <= bidInfo.auctionQuantity, "Bid size exceeds auction quantity");

When creating a bid, it enforces the above requirement. This prevents users from buying more than they should but it is also a source of an easy DOS attack. Assume a user is trying to buy the entire balance of a component, a malicious user can frontrun them buying only a tiny amount. Since they requested the entire balance, the call with fail. This is a useful technique if an attacker wants to DOS other buyers to pass the time and get a better price from the dutch auction.

## Impact

Malicious user can DOS legitimate users attempting to purchase the entire amount of component

## Code Snippet

[AuctionRebalanceModuleV1.sol#L772-L836](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L772-L836)

## Tool used

Manual Review

## Recommendation

Allow

*[Content truncated...]*

---

### Example 13: [M-07] Attacker can force AuctionCrowdfunds to bid their entire contribution up to maxBid

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

_Submitted by Trust, also found by cccz_

AuctionCrowdfund's `bid()` allows any user to compete on an auction on the party's behalf. The code in `bid()` forbids placing a bid if party is already winning the auction:

    if (market.getCurrentHighestBidder(auctionId_) == address(this)) {
                revert AlreadyHighestBidderError();
            }

However, it does not account for attackers placing bids from their own wallet, and then immediately overbidding them using the party's funds. This can be used in two ways:

1.  Attacker which lists an NFT, can force the party to spend all its funds up to maxBid on the auction, even if the party could have purchased the NFT for much less.
2.  Attackers can grief random auctions, making them pay the absolute maximum for the item. Attackers can use this to drive the prices of NFT items up, profiting from this using secondary markets.

### Impact

Parties can be stopped from buying items at a good value without any risk to the attacker.

### Proof of Concept

1.  Attacker places an NFT for sale, valued at X
2.  Attacker creates an AuctionCrowdfund, with maxBid = Y such that Y = 2X
3.  Current bid for the NFT is X - AUCTION_STEP
4.  Users contribute to the fund, which now has 1.5X
5.  Users call `bid()` to bid X  for the NFT
6.  Attacker bids for the item externally for 1.5X - AUCTION_STEP
7.  Attacker calls `bid()` to bid 1.5X for the NFT
8.  Attacker sells his NFT for 1.5X although no one apart from the party was interested in buy

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 14: [L-04] Frontrunnable Initialization

**Source**: Pashov Audit Group
**Protocol**: Enclave_2025-10-25
**Impact**: LOW

**Details**:

_Acknowledged_

The `initialize` instruction creates the global `fund_pool` PDA (`seed = b"fund_pool"`) and sets `initial_admin` to an arbitrary public key supplied by the caller. There is no access control restricting who may invoke this first-use initializer. An attacker can front-run deployment, initialize the pool, and seize control over all admin- and signer-gated operations for the lifetime of the program (until redeploy).

**Recommendations**

Implement a robust access control mechanism that ensures only a trusted entity, such as the program's deployer or a predefined address, can call the `initialize` function. This restriction can be enforced by verifying the caller's identity or using a specific signature during initialization.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Enclave-security-review_2025-10-25.md)

---

### Example 15: M-3: No check for sequencer uptime can lead to dutch auctions executing at bad prices

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

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

