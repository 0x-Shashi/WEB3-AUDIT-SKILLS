# Timing Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 8 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for timing vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-34: liquidationAccountant can be claimed at any time

**Source**: Sherlock
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-astaria-judging/issues/46 

## Found by 
obront

## Summary

New liquidations are sent to the `liquidationAccountant` with a `finalAuctionTimestamp` value, but the actual value that is passed in is simply the duration of an auction. The `claim()` function uses this value in a require check, so this error will allow it to be called before the auction is complete.

## Vulnerability Detail

When a lien is liquidated, `AstariaRouter.sol:liquidate()` is called. If the lien is set to end in a future epoch, we call `handleNewLiquidation()` on the `liquidationAccountant`.

One of the values passed in this call is the `finalAuctionTimestamp`, which updates the `finalAuctionEnd` variable in the `liquidationAccountant`. This value is then used to protect the `claim()` function from being called too early.

However, when the router calls `handleLiquidationAccountant()`, it passes the duration of an auction rather than the final timestamp:

```solidity
LiquidationAccountant(accountant).handleNewLiquidation(
  lien.amount,
  COLLATERAL_TOKEN.auctionWindow() + 1 days
);
```
As a result, `finalAuctionEnd` will be set to 259200 (3 days). 

When `claim()` is called, it requires the final auction to have ended for the function to be called:

```solidity
require(
  block.timestamp > finalAuctionEnd || finalAuctionEnd == uint256(0),
  "final auction has not ended"
);
```
Because of the error above, `block.timestamp` will always be greater than `fi

*[Content truncated...]*

---

### Example 2: [M-06] `L1::xRenzoBridge` and `L2::xRenzoBridge` uses the `block.timestamp` as dependency, which can cause issues

**Source**: Code4rena
**Protocol**: Renzo
**Impact**: MEDIUM

**Details**:

In `L1::xRenzoBridge` the `block.timestamp` from L1 is encoded and sent to L2. When the message is delivered from L1 to L2  with `xRenzoBridge::_updatePrice()`, the function checks the `block.timestamp` like this:

```solidity
    if (_timestamp > block.timestamp) {
            revert InvalidTimestamp(_timestamp);
        }
```

This check is done to not allow future timestamps for updating the price But the timestamps between two chains L1 and L2 are different for chain like Arbitrum as there's a possibility that the sequencer fails to post batches on the parent chain (for example, Ethereum) for a period of time.

According to the [Arbitrum docs](<https://docs.arbitrum.io/build-decentralized-apps/arbitrum-vs-ethereum/block-numbers-and-time#block-timestamps-arbitrum-vs-ethereum>):

> **Timestamp boundaries of the sequencer**
>
> As mentioned, block timestamps are usually set based on the sequencer's clock. Because there's a possibility that the sequencer fails to post batches on the parent chain (for example, Ethereum) for a period of time, it should have the ability to slightly adjust the timestamp of the block to account for those delays and prevent any potential reorganisations of the chain. To limit the degree to which the sequencer can adjust timestamps, some boundaries are set, currently to 24 hours earlier than the current time, and 1 hour in the future.

So the issue is that timestamp validation for `_updatePrice()` won't be effective and can reject validation both l2

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-04-renzo)

---

### Example 3: The off-chain mechanism must be ensured to work in a correct order strictly

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `PriorityPool` contract relies on the distribution oracle for accounting and the accounting calculation is done off-chain.

According to the communication with the protocol team, the correct workflow for queued deposits can be described as below:
- Whenever there is a new room for deposit in the staking pool, the function `depositQueuedTokens` is called.
- The `PriorityPool` contract is paused by calling `pauseForUpdate()`.
- Accounting calculations happen off-chain using the function `getAccountData()` and `getDepositsSinceLastUpdate()`(`depositsSinceLastUpdate`) variable to compose the latest Merkle tree.
- The distribution oracle calls the function `updateDistribution()` and this will resume the `PriorityPool`.

The only purpose of pausing the queue contract is to prevent unqueue until the accounting status are updated.
Through an analysis we found that the off-chain mechanism MUST follow the order very strictly or else user funds can be stolen.
While we acknowledge that the protocol team will ensure it, we decided to keep this finding as a medium risk because we can not verify the off-chain mechanism.

**Impact:** If the off-chain mechanism occurs in a wrong order by any chance, user funds can be stolen.
Given the likelihood is low, we evaluate the impact to be Medium.

**Proof of Concept:** The below test case shows the attack scenario.
```javascript
  it('Cyfrin: off-chain mechanism in an incorrect order can lead to user funds 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 4: [M-16] Due to inappropriately short `votingPeriod`  and `votingDelay`, it is nearly impossible for the governance to function correctly.

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Proof of Concept

When making proposals with the [`Governor`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/Governor.sol#L299-L308) contract OZ uses `votingPeriod`.

```jsx
        uint256 snapshot = currentTimepoint + votingDelay();
        uint256 duration = votingPeriod();

        _proposals[proposalId] = ProposalCore({
            proposer: proposer,
            voteStart: SafeCast.toUint48(snapshot),//@audit votingDelay() for when the voting starts
            voteDuration: SafeCast.toUint32(duration),//@audit votingPeriod() for the duration
            executed: false,
            canceled: false
        });
```

But currently, Lybra has implemented the wrong amounts for bolt [`votingPeriod`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L143-L145) and [`votingDelay`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L147-L149), which means proposals from the governance will be nearly impossible to be voted on.

```jsx
    function votingPeriod() public pure override returns (uint256){
         return 3;//@audit this should be time in blocks 
    }

     function votingDelay() public pure override returns (uint256){
         return 1;//@audit this should be time in blocks 
    }
```

### HH PoC

<https://gist.github.com/0x3b33/dfd5a29d5fa50a00a149080280569d12>

### Tools Used

Manual Review

### Recommended Mitigation S

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 5: [M-15] Lack of timelock on `rigidRedemption`, enables to steal yield from other users

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

The withdraw function of the `LybraEUSDVaultBase` vaults, uses a time softlock to prevent users from hopping in and out of the protocol; to gain access to the yield generated by other users and then leave right away (by charging a small percentage from the withdrawn amount).

The same measure isn't applied to `rigidRedemptions`, which enable a user to withdraw most of the underlying assets at any time after deposit. This enables a user to deposit into the pool right before a rebase is about to happen, get access to the yield generated by other users and leave by calling `rigidRedemption` and withdraw on the tokens left by `rigidRedemption` (the amount charged on the leftovers assets, can be outbalanced by the yield).

Therefore, a malicious user to get access to yield that they didn't generate, effectively stealing it from others. The amount that the user will get access to will vary based on the deposited amounts.

### Proof of Concept

This issue involves 3 functions:

- `withdraw(address onBehalfOf, uint256 amount)` from the `LybraEUSDVaultBase` [contract](https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L98), which internally calls `checkWithdrawal(address user, uint256 amount)` to check that 3 days has passed after deposit and charges the user otherways:

    ```
    withdrawal = block.timestamp - 3 days >= depositedTime[user] ? amount : (amount * 999) / 1000;
    ```

- `rigidRede

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 6: [M-01] Malicious actor can win an auction unfavorably to the protocol by block stuffing

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L158-L202><br><https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L467-L470><br><https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L213>

When the protocol bad debt is auctioned off with 10% incentive at the beginning, a user who gives the best bid wins. The auction ends when at least one account placed a bid, and the current block number is bigger than `nextBidderBlockLimit`:

```jsx
function closeAuction(address comptroller) external nonReentrant {
        Auction storage auction = auctions[comptroller];

        require(_isStarted(auction), "no on-going auction");
        require(
            block.number > auction.highestBidBlock + nextBidderBlockLimit && auction.highestBidder != address(0),
            "waiting for next bidder. cannot close auction"
        );
```

`nextBidderBlockLimit` is set to 10 in the initializer, which means that other users have only 30 seconds to place a better bid. This is a serious problem because stuffing a whole block with dummy transactions is very cheap on Binance Smart Chain. According to <https://www.cryptoneur.xyz/en/gas-fees-calculator>, 15M gas - whole block - costs `$`14\~`$`15 on BSC. This makes a malicious user occasionally cheaply prohibit other users to overbid them, winning the auction at the least favorable price for the protocol. Because BSC is a centralized blockch

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-venus)

---

### Example 7: [M-01] Insufficient input validation

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

### Example 8: [M-19] `CLOCK_MODE()` will not work properly for Arbitrum or Optimism due to `block.number`

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Proof of Concept

According to [Arbitrum Docs](https://developer.offchainlabs.com/time), `block.number` returns the most recently synced L1 block number. Once per minute, the block number in the `Sequencer` is synced to the actual L1 block number. Using `block.number` as a clock can lead to inaccurate timing.

It also presents an issue for [Optimism](https://community.optimism.io/docs/developers/build/differences/#block-numbers-and-timestamps) because each transaction is it's own block.

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/LybraGovernance.sol#L152>

### Recommended Mitigation Steps

Use `block.timestamp` rather than `block.number`

### Assessed type

Timing

**[LybraFinance commented](https://github.com/code-423n4/2023-06-lybra-findings/issues/114#issuecomment-1639775144):**
 > The governance contract only exists on the Ethereum mainnet.

**[LybraFinance acknowledged](https://github.com/code-423n4/2023-06-lybra-findings/issues/114#issuecomment-1656708522)**

***

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 9: M-6: Auction date will drift irreversibly forward over time leading to loss of yield for bond holders

**Source**: Sherlock
**Protocol**: Plaza Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/446 

## Found by 
0x52

### Summary

During the creation of the auction, lastDistribution is set to block.timestamp. Delays are compounding and will lead to loss of yield over time as the subsequent distribution will be delayed.

[Pool.sol#L530-L571](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L530-L571)

        function startAuction() external whenNotPaused() {
            // Check if distribution period has passed
    @>      require(lastDistribution + distributionPeriod < block.timestamp, DistributionPeriodNotPassed());

            // Check if auction period hasn't passed
            require(lastDistribution + distributionPeriod + auctionPeriod >= block.timestamp, AuctionPeriodPassed());

            ... SNIP

            // Update last distribution time
    @>      lastDistribution = block.timestamp;
        }

Above we see that lastDistribution is used to determine if the auction can be started. Additionally, lastDistribution is set to block.timestamp which means that any delay between lastDistribution + distributionPeriod and block.timestamp will cause loss of yield in the subsequent quarter.

According to sherlock rules a loss of 0.01% qualifies as medium impact. The distribution period is 1 quarter or 90 days which is 7 776 000 seconds. This means that a delay of 777.6 seconds (13 minutes) will break this threshold. Given that the start of the

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

