# Flash Loan Attack Chains

## Overview

Flash loans provide unlimited capital for single-transaction attacks. Combined with other vulnerabilities, they enable:

- Price manipulation at scale
- Governance attacks
- Arbitrage exploitation
- Liquidation cascades

---

## Chain 1: Flash Loan + Oracle Manipulation + Liquidation

**Components:**
1. Flash loan access (Info)
2. Spot price oracle (Medium)
3. Instant liquidation (Low)

**Attack Flow:**
```
1. Flash borrow $100M USDC
2. Dump into DEX pool → crash price
3. Liquidate underwater positions
4. Buy back at crashed price
5. Repay flash loan + profit
```

**Real Example:** Cream Finance ($130M)

**Detection:**
```solidity
// RED FLAG: Spot price used for liquidation
function liquidate(address user) {
    uint256 price = pair.getReserves();  // Manipulatable!
    if (getUserHealth(user, price) < 1) {
        // Liquidate
    }
}
```

**Mitigation:**
- Use TWAP oracles (time-weighted average)
- Add liquidation delay
- Use Chainlink or similar

---

## Chain 2: Flash Loan + Reentrancy + Withdrawal

**Components:**
1. Flash loan capital
2. Reentrancy vulnerability
3. Balance check before state update

**Attack Flow:**
```
1. Flash borrow 1000 ETH
2. Deposit to vulnerable protocol
3. Withdraw triggering reentrancy
4. Re-enter and withdraw again
5. Repeat until drained
6. Repay flash loan
```

**Real Example:** The DAO ($60M)

**Detection:**
```solidity
// RED FLAG: External call before state update
function withdraw() {
    uint256 balance = balances[msg.sender];
    (bool success,) = msg.sender.call{value: balance}("");  // Reentrant!
    balances[msg.sender] = 0;  // Too late
}
```

**Mitigation:**
- Checks-Effects-Interactions pattern
- Reentrancy guards
- Pull over push

---

## Chain 3: Flash Loan + Governance + Execution

**Components:**
1. Flash loan for tokens
2. No snapshot on voting
3. Instant execution

**Attack Flow:**
```
1. Flash borrow governance tokens
2. Create malicious proposal
3. Vote with borrowed tokens
4. Execute proposal immediately
5. Drain treasury
6. Repay flash loan
```

**Real Example:** Beanstalk ($182M)

**Detection:**
```solidity
// RED FLAG: No snapshot, votes counted on current balance
function vote(uint256 proposalId) {
    uint256 votes = token.balanceOf(msg.sender);  // Flash loanable!
    proposals[proposalId].votes += votes;
}
```

**Mitigation:**
- Snapshot voting power at proposal creation
- Timelock between vote and execution
- Minimum holding period

---

## Chain 4: Flash Loan + Token Price + Collateral Inflation

**Components:**
1. Flash loan capital
2. Token price based on pool reserves
3. Collateral valued at spot price

**Attack Flow:**
```
1. Flash borrow large amount
2. Buy illiquid token → pump price
3. Deposit as collateral at inflated price
4. Borrow max against inflated collateral
5. Default on loan
6. Protocol stuck with worthless collateral
```

**Real Example:** Cream Finance (multiple attacks)

**Detection:**
```solidity
// RED FLAG: Collateral value from DEX
function getCollateralValue(address token) view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return reserves0 / reserves1 * userBalance;  // Manipulatable!
}
```

**Mitigation:**
- Use decentralized oracles
- Add collateral caps
- Require price stability period

---

## Chain 5: Flash Loan + Donation + Share Inflation

**Components:**
1. Flash loan capital
2. Vault accepting donations
3. Share price based on balance

**Attack Flow:**
```
1. Deposit 1 wei to get 1 share
2. Flash borrow 1000 ETH
3. Donate to vault (no shares minted)
4. Share price = 1000 ETH per share
5. When others deposit, they get 0 shares (rounding)
6. Withdraw with all the funds
```

**Real Example:** ERC4626 vaults (various)

**Detection:**
```solidity
// RED FLAG: Share calculation without minimum
function deposit(uint256 assets) returns (uint256 shares) {
    shares = assets * totalSupply / totalAssets;  // Rounds to 0!
    // If totalAssets inflated by donation
}
```

**Mitigation:**
- Virtual shares/assets offset
- Minimum deposit amount
- Dead shares on first deposit

---

## Chain 6: Flash Loan + Reward Distribution + Timing

**Components:**
1. Flash loan tokens
2. Reward distribution based on current stake
3. No minimum stake duration

**Attack Flow:**
```
1. Wait for reward distribution time
2. Flash borrow stake tokens
3. Stake right before distribution
4. Claim large share of rewards
5. Unstake and repay flash loan
```

**Real Example:** Multiple yield farms

**Detection:**
```solidity
// RED FLAG: Rewards based on current balance
function claimRewards() {
    uint256 share = stakes[msg.sender] / totalStaked;
    uint256 reward = pendingRewards * share;
    // No time-weighted calculation
}
```

**Mitigation:**
- Time-weighted reward calculation
- Minimum stake duration
- Gradual vesting

---

## Flash Loan Attack Checklist

When auditing, check:

- [ ] Can large amounts be flash borrowed?
- [ ] Are prices derived from manipulatable sources?
- [ ] Is there reentrancy in any withdraw function?
- [ ] Can governance be influenced instantly?
- [ ] Are collateral values from spot prices?
- [ ] Can vault share prices be manipulated?
- [ ] Are rewards distributed based on current balance?

---

## Detection Script

```bash
# Find potential flash loan vulnerabilities

# Spot price usage
grep -rn "getReserves\|balanceOf.*price\|spot.*price" --include="*.sol"

# Reentrancy patterns
grep -rn "\.call{value\|\.transfer\|\.send" --include="*.sol"

# Governance without snapshot
grep -rn "balanceOf.*vote\|voting.*balance" --include="*.sol"

# Direct balance-based calculations
grep -rn "totalSupply.*balance\|balance.*totalSupply" --include="*.sol"
```
