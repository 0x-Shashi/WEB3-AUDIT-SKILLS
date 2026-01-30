# Gas Price Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for gas price vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Gas price spikes cause the selected operator to be vulnerable to frontrunning and be slashed

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L354](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L354)<br>

```solidity
require(gasPrice >= tx.gasprice, "HOLOGRAPH: gas spike detected");
```

```solidity
        /**
         * @dev select operator that failed to do the job, is slashed the pod base fee
         */
        _bondedAmounts[job.operator] -= amount;
        /**
         * @dev the slashed amount is sent to current operator
         */
        _bondedAmounts[msg.sender] += amount;
```

Since you have designed a mechanism to prevent other operators to slash the operator due to "the selected missed the time slot due to a gas spike". It can induce that operators won't perform their job if a gas price spike happens due to negative profit.

But your designed mechanism has a vulnerability. Other operators can submit their transaction to the mempool and queue it using `gasPrice in bridgeInRequestPayload`. It may get executed before the selected operator as the selected operator is waiting for the gas price to drop but doesn't submit any transaction yet. If it doesn't, these operators lose a little gas fee. But a slashed reward may be greater than the risk of losing a little gas fee.

```solidity
require(timeDifference > 0, "HOLOGRAPH: operator has time");
```

Once 1 epoch has passed, selected operator is vulnerable to slashing and frontrunning.

### Recommended Mitigation Steps

Modify your operator node software t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: [H-05] MEV: Operator can bribe miner and steal honest operator's bond amount if gas price went high

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L354](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L354)<br>

Operators in Holograph do their job by calling executeJob() with the bridged in bytes from source chain.<br>
If the primary job operator did not execute the job during his allocated block slot, he is punished by taking a single bond amount and transfer it to the operator doing it instead.<br>
The docs and code state that if there was a gas spike in the operator's slot, he shall not be punished. The way a gas spike is checked is with this code in executeJob:

    require(gasPrice >= tx.gasprice, "HOLOGRAPH: gas spike detected");

However, there is still a way for operator to claim primary operator's bond amount although gas price is high. Attacker can submit a flashbots bundle including the executeJob() transaction, and one additional "bribe" transaction. The bribe transaction will transfer some incentive amount to coinbase address (miner), while the executeJob is submitted with a low gasprice. Miner will accept this bundle as it is overall rewarding enough for them, and attacker will receive the base bond amount from victim operator. This threat is not theoretical because every block we see MEV bots squeezing value from such opportunities.

info about coinbase [transfer](https://docs.flashbots.net/flashbots-auction/searchers/advanced/coinbase-payment)<br>
info about bundle [selection](https://docs.flashbots.net/f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 3: [H-02] If user sets a low `gasPrice` the operator would have to choose between being locked out of the pod or executing the job anyway

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L202-L340](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L202-L340)<br>
[HolographOperator.sol#L593-L596](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L593-L596)<br>
[LayerZeroModule.sol#L277-L294](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/module/LayerZeroModule.sol#L277-L294)<br>

During the beaming process the user compensates the operator for the gas he has to pay by sending some source-chain-native-tokens via `hToken`.<br>
The amount he has to pay is determined according to the `gasPrice` set by the user, which is supposed to be the maximum gas price to be used on dest chain (therefore predicting the max gas fee the operator would pay and paying him the same value in src chain native tokens).<br>
However, in case the user sets a low price (as low as 1 wei) the operator can't skip the job because he's locked out of the pod till he executes the job.<br>
The operator would have to choose between loosing money by paying a higher gas fee than he's compensated for or being locked out of the pod - not able to execute additional jobs or get back his bonded amount.<br>

### Impact

Operator would be losing money by having to pay gas fee that's higher than the compensation (gas fee can be a few dozens of USD for heavy txs).<br>
This could also be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: [M-03] Beaming job might freeze on dest chain under some conditions, leading to owner losing (temporarily) access to token

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographOperator.sol#L255](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L255)<br>

If the following conditions have been met:

*   The selected operator doesn't complete the job, either intentionally (they're sacrificing their bonded amount to harm the token owner) or innocently (hardware failure that caused a loss of access to the wallet)
*   Gas price has spiked, and isn't going down than the `gasPrice` set by the user in the bridge out request

Then the bridging request wouldn't complete and the token owner would loos access to the token till the gas price goes back down again.

### Proof of Concept

The fact that no one but the selected operator can execute the job in case of a gas spike has been proven by the test ['Should fail if there has been a gas spike'](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/test/14\_holograph_operator_tests.ts#L834-L844) provided by the sponsor.

An example of a price spike can be in the recent month in the Ethereum Mainnet where the min gas price was 3 at Oct 8, but jumped to 14 the day after and didn't go down since then (the min on Oct 9 was lower than the avg of Oct8, but users might witness a momentarily low gas price and try to hope on it). See the [gas price chat on Etherscan](https://etherscan.io/chart/gasprice) for more details.

### Recommended Mitigation Steps

In case of a gas price spike, instead of refus

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 5: M-1: Determining how many votes to buy may run OOG.

**Source**: Sherlock
**Protocol**: Ethos Reputation Market Fix Review Contest
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-12-ethos-update-judging/issues/43 

## Found by 
bughuntoor

### Summary
The current way buying votes works is that a user sends a certain `msg.value` and a minimum and maximum amount they wish to buy, and the contract loops through the values to find the maximum amount the user can actually buy.

```solidity
    (, , , uint256 total) = _calculateBuy(markets[profileId], isPositive, minVotesToBuy);
    if (total > msg.value) revert InsufficientFunds();

    (
      uint256 purchaseCostBeforeFees,
      uint256 protocolFee,
      uint256 donation,
      uint256 totalCostIncludingFees
    ) = _calculateBuy(markets[profileId], isPositive, maxVotesToBuy);
    uint256 currentVotesToBuy = maxVotesToBuy;
    // if the cost is greater than the maximum votes to buy,
    // decrement vote count and recalculate until we identify the max number of votes they can afford
    while (totalCostIncludingFees > msg.value) {
      currentVotesToBuy--;
      (purchaseCostBeforeFees, protocolFee, donation, totalCostIncludingFees) = _calculateBuy(
        markets[profileId],
        isPositive,
        currentVotesToBuy
      );
    }
```

The problem is that this way is highly gas inefficient. And even though protocol is to be deployed on Base where gas costs are low, it would still be possible to reach significant gas costs.

Looping to check a certain buy's gas costs, costs around ~33k gas (PoC attached below). Considering

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

