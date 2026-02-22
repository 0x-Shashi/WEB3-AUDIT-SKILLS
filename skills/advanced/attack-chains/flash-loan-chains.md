# Flash Loan Attack Chains

## Chain 1: Flash Loan → Price Manipulation → Profit
```
Step 1: Borrow large amount via flash loan (Aave/dYdX)
Step 2: Dump borrowed tokens into AMM pool (crash price)
Step 3: Interact with victim protocol using manipulated price
Step 4: Extract profit (buy cheap / borrow more than should be allowed)
Step 5: Repay flash loan + fee
```

### Detection Points
- [ ] Protocol uses spot price from AMM? (VULNERABLE)
- [ ] Protocol uses TWAP oracle? (Check TWAP window — short = vulnerable)
- [ ] Protocol uses Chainlink? (Generally safe, check staleness)
- [ ] Large trades can move the price significantly?
- [ ] Price used for collateral valuation, liquidation, or swap execution?

### Real Example: Harvest Finance ($34M)
- Flash loan USDC from Uniswap
- Swap in Curve pool to manipulate price
- Deposit into Harvest at manipulated price
- Swap back in Curve to restore price
- Withdraw from Harvest at restored price (more than deposited)

## Chain 2: Flash Loan → Governance Manipulation
```
Step 1: Flash loan governance tokens
Step 2: Create/vote on malicious proposal (if snapshot vulnerable)
Step 3: Execute proposal in same transaction
Step 4: Drain treasury / change critical parameters
Step 5: Return flash-loaned tokens
```

### Detection Points
- [ ] Voting power based on current balance? (VULNERABLE)
- [ ] Snapshot mechanism enforced? (Must be from previous block)
- [ ] Proposal execution has timelock?
- [ ] Flash loan prevention in governance (block.number check)?
- [ ] Quorum requirements reasonable?

### Real Example: Beanstalk ($182M)
- Flash loaned $1B in tokens
- Achieved 79% voting power
- Passed malicious BIP-18 proposal
- Drained Beanstalk treasury
- Proposal had emergencyCommit (no timelock)

## Chain 3: Flash Loan → Reentrancy Amplification
```
Step 1: Flash loan large token amount
Step 2: Deposit into vulnerable protocol
Step 3: Trigger reentrancy during withdrawal
Step 4: Re-enter to withdraw multiple times
Step 5: Repay flash loan from drained funds
```

### Detection Points
- [ ] Flash loans allow atomically large positions
- [ ] Without flash loans, attack may not be profitable
- [ ] Reentrancy guards on all state-changing functions?
- [ ] CEI pattern followed?
- [ ] Cross-function reentrancy possible?

## Chain 4: Flash Loan → Liquidation Manipulation
```
Step 1: Flash loan tokens
Step 2: Manipulate collateral price downward
Step 3: Liquidate now-underwater positions
Step 4: Collect liquidation bonus
Step 5: Restore price, repay flash loan
```

### Detection Points
- [ ] Liquidation uses manipulable price source?
- [ ] Liquidation bonus large enough to incentivize manipulation?
- [ ] Price impact limits on oracle?
- [ ] Time delay between price update and liquidation?

## Chain 5: Flash Loan → Vault Share Inflation
```
Step 1: Be first depositor in empty vault
Step 2: Deposit minimum amount (1 wei)
Step 3: Flash loan large amount
Step 4: Donate directly to vault (inflate share price)
Step 5: Next depositor gets 0 shares due to rounding
Step 6: Withdraw donated amount (steal the deposit)
```

### Detection Points
- [ ] Vault uses dead shares or virtual offset? (ERC4626)
- [ ] Minimum first deposit enforced?
- [ ] Share calculation rounds in protocol's favor?
- [ ] Direct token transfers to vault handled correctly?

## Key Principle
Flash loans remove the capital requirement for attacks. Any vulnerability that requires large capital to exploit becomes freely exploitable with flash loans. Always assume the attacker has unlimited capital for one transaction.
