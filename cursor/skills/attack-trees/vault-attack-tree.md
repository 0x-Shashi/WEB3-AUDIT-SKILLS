---
id: VAULT-ATTACK-TREE
title: Vault/Yield Aggregator Attack Tree
category: attack-tree
protocol: vault
triggers:
  - vault attack paths
  - how to attack vault
  - yield aggregator vulnerabilities
  - vault exploit tree
related_skills:
  - patterns/defi-vault-patterns.md
  - patterns/erc4626-patterns.md
  - patterns/strategy-patterns.md
  - exploit-forensics/yearn-2023.md
---

# Vault/Yield Aggregator Attack Tree

Visual decision path for attacking vaults and yield aggregators (Yearn, Beefy, etc.).

---

## ROOT: Steal Funds from Vault

```
ROOT: Steal Funds from Vault
│
├── [A] Share Price Manipulation
│   │
│   ├── [A1] First Depositor Attack
│   │   ├── Condition: No virtual shares offset
│   │   ├── Action: Deposit 1 wei → Donate large amount → Inflate price
│   │   ├── Result: Next depositor gets 0 shares, funds stolen
│   │   └── Check: patterns/defi-vault-patterns.md#first-depositor
│   │
│   ├── [A2] Donation Attack
│   │   ├── Condition: Direct transfers affect exchange rate
│   │   ├── Action: Donate tokens directly to vault
│   │   ├── Result: Inflate share price, harm subsequent users
│   │   └── Check: patterns/defi-vault-patterns.md#donation-attack
│   │
│   ├── [A3] Rounding Down Attack
│   │   ├── Condition: Rounding always rounds down shares
│   │   ├── Action: Repeatedly deposit/withdraw small amounts
│   │   ├── Result: Drain dust over time
│   │   └── Check: patterns/erc4626-patterns.md#rounding
│   │
│   ├── [A4] Fee Manipulation
│   │   ├── Condition: Fees calculated on manipulated assets
│   │   ├── Action: Inflate total assets → Claim excess fees
│   │   ├── Result: Steal vault funds as fees
│   │   └── Check: patterns/defi-vault-patterns.md#fee-calculation
│   │
│   └── [A5] Sandwich Deposit
│       ├── Condition: Share price changes within same block
│       ├── Action: Front-run deposit → Manipulate price → Back-run
│       ├── Result: Steal from depositor
│       └── Check: patterns/mev-patterns.md#vault-sandwich
│
├── [B] Strategy Exploits
│   │
│   ├── [B1] Strategy Reentrancy
│   │   ├── Condition: Strategy callback before state update
│   │   ├── Action: Harvest → Callback → Reenter
│   │   ├── Result: Drain vault via strategy
│   │   └── Check: patterns/reentrancy-patterns.md#strategy
│   │
│   ├── [B2] Malicious Strategy
│   │   ├── Condition: Strategy not validated before adding
│   │   ├── Action: Add malicious strategy → Drain funds
│   │   ├── Result: Steal all vault funds
│   │   └── Check: patterns/strategy-patterns.md#validation
│   │
│   ├── [B3] Strategy Loss Not Capped
│   │   ├── Condition: Strategy can lose unlimited funds
│   │   ├── Action: Exploit vulnerable strategy
│   │   ├── Result: Total vault loss
│   │   └── Check: patterns/strategy-patterns.md#loss-cap
│   │
│   ├── [B4] Strategy Debt Manipulation
│   │   ├── Condition: Debt tracking inconsistent
│   │   ├── Action: Report false debt to vault
│   │   ├── Result: Withdraw more than entitled
│   │   └── Check: patterns/strategy-patterns.md#debt-accounting
│   │
│   └── [B5] Emergency Withdraw Exploit
│       ├── Condition: Emergency withdraw bypasses checks
│       ├── Action: Trigger emergency → Withdraw at wrong price
│       ├── Result: Steal during emergency
│       └── Check: patterns/strategy-patterns.md#emergency
│
├── [C] Withdrawal Exploits
│   │
│   ├── [C1] Withdraw Before Fees
│   │   ├── Condition: Withdrawal before fees accrued
│   │   ├── Action: Withdraw before harvest
│   │   ├── Result: Avoid paying fees
│   │   └── Check: patterns/defi-vault-patterns.md#fee-timing
│   │
│   ├── [C2] Withdrawal Reentrancy
│   │   ├── Condition: External call before state update
│   │   ├── Action: Withdraw → Callback → Withdraw again
│   │   ├── Result: Drain vault
│   │   └── Check: patterns/reentrancy-patterns.md#withdrawal
│   │
│   ├── [C3] Max Withdraw Bypass
│   │   ├── Condition: maxWithdraw not enforced
│   │   ├── Action: Withdraw more than allowed
│   │   ├── Result: Drain liquidity needed for others
│   │   └── Check: patterns/erc4626-patterns.md#max-withdraw
│   │
│   ├── [C4] Slippage Exploit
│   │   ├── Condition: No slippage protection on withdrawal
│   │   ├── Action: Manipulate price during withdrawal
│   │   ├── Result: User receives less, attacker profits
│   │   └── Check: patterns/defi-vault-patterns.md#slippage
│   │
│   └── [C5] Withdrawal Queue Manipulation
│       ├── Condition: Queue ordering exploitable
│       ├── Action: Front-run withdrawal queue
│       ├── Result: Drain liquidity before others
│       └── Check: patterns/defi-vault-patterns.md#queue
│
├── [D] Oracle/Price Manipulation
│   │
│   ├── [D1] Flash Loan + Price Oracle
│   │   ├── Condition: Vault uses manipulable oracle
│   │   ├── Action: Flash loan → Manipulate → Deposit/Withdraw
│   │   ├── Result: Deposit at low price, withdraw at high
│   │   └── Check: patterns/oracle-patterns.md#flash-loan
│   │
│   ├── [D2] Stale Price
│   │   ├── Condition: No staleness check
│   │   ├── Action: Use stale favorable price
│   │   ├── Result: Profit from outdated pricing
│   │   └── Check: patterns/oracle-patterns.md#stale-price
│   │
│   ├── [D3] LP Token Price Manipulation
│   │   ├── Condition: LP token value calculated incorrectly
│   │   ├── Action: Manipulate underlying pool
│   │   ├── Result: Inflate LP token value
│   │   └── Check: patterns/defi-vault-patterns.md#lp-pricing
│   │
│   └── [D4] Yield Manipulation
│       ├── Condition: Yield reported without validation
│       ├── Action: Report fake high yield
│       ├── Result: Inflate share price
│       └── Check: patterns/strategy-patterns.md#yield-reporting
│
├── [E] ERC4626 Standard Violations
│   │
│   ├── [E1] Preview != Actual
│   │   ├── Condition: previewDeposit ≠ actual shares received
│   │   ├── Action: Exploit discrepancy
│   │   ├── Result: Receive more/less than expected
│   │   └── Check: patterns/erc4626-patterns.md#preview-accuracy
│   │
│   ├── [E2] Asset/Share Conversion Bug
│   │   ├── Condition: convertToShares math error
│   │   ├── Action: Exploit conversion
│   │   ├── Result: Inflate shares received
│   │   └── Check: patterns/erc4626-patterns.md#conversion
│   │
│   ├── [E3] MaxDeposit/MaxMint Not Enforced
│   │   ├── Condition: Deposit exceeds maxDeposit
│   │   ├── Action: Deposit more than should be allowed
│   │   ├── Result: Break vault invariants
│   │   └── Check: patterns/erc4626-patterns.md#limits
│   │
│   └── [E4] totalAssets() Manipulation
│       ├── Condition: totalAssets() not accurate
│       ├── Action: Manipulate underlying assets
│       ├── Result: Corrupt share price
│       └── Check: patterns/erc4626-patterns.md#total-assets
│
├── [F] Access Control & Admin
│   │
│   ├── [F1] Unprotected Initialization
│   │   ├── Condition: initialize() not protected
│   │   ├── Action: Initialize vault with malicious params
│   │   ├── Result: Set self as owner
│   │   └── Check: patterns/access-control-patterns.md#initialization
│   │
│   ├── [F2] Governance Attack
│   │   ├── Condition: Governance can change critical params instantly
│   │   ├── Action: Compromise governance → Steal funds
│   │   ├── Result: Drain vault
│   │   └── Check: patterns/governance-patterns.md#vault
│   │
│   ├── [F3] Fee Parameter Manipulation
│   │   ├── Condition: Fees can be set to 100%
│   │   ├── Action: Set max fees → Harvest
│   │   ├── Result: Steal all yield
│   │   └── Check: patterns/defi-vault-patterns.md#fee-limits
│   │
│   ├── [F4] Strategy Migration Attack
│   │   ├── Condition: Strategy can be changed without timelock
│   │   ├── Action: Migrate to malicious strategy
│   │   ├── Result: Steal funds during migration
│   │   └── Check: patterns/strategy-patterns.md#migration
│   │
│   └── [F5] Pause Exploit
│       ├── Condition: Pause can trap user funds
│       ├── Action: Pause vault → Users can't withdraw
│       ├── Result: DoS user funds
│       └── Check: patterns/pausable-patterns.md#vault
│
├── [G] Token-Specific Exploits
│   │
│   ├── [G1] Fee-on-Transfer Token
│   │   ├── Condition: Vault doesn't handle transfer fees
│   │   ├── Action: Deposit fee-on-transfer token
│   │   ├── Result: Vault receives less than accounted
│   │   └── Check: patterns/token-patterns.md#fee-on-transfer
│   │
│   ├── [G2] Rebasing Token
│   │   ├── Condition: Vault holds rebasing token
│   │   ├── Action: Deposit before positive rebase
│   │   ├── Result: Steal rebase rewards
│   │   └── Check: patterns/token-patterns.md#rebase
│   │
│   ├── [G3] ERC777 Callback
│   │   ├── Condition: Accepting ERC777 tokens
│   │   ├── Action: Deposit ERC777 → Callback → Reenter
│   │   ├── Result: Drain vault via callback
│   │   └── Check: patterns/token-patterns.md#erc777-hooks
│   │
│   ├── [G4] Approval Front-Running
│   │   ├── Condition: User approves vault with old approval still active
│   │   ├── Action: Front-run with old approval
│   │   ├── Result: Steal approved tokens
│   │   └── Check: patterns/erc20-patterns.md#approval-frontrun
│   │
│   └── [G5] Deflationary Token
│       ├── Condition: Token supply decreases over time
│       ├── Action: Deposit → Supply deflates → Withdraw more
│       ├── Result: Withdraw more than deposited
│       └── Check: patterns/token-patterns.md#deflationary
│
└── [H] Reward Distribution Exploits
    │
    ├── [H1] Reward Dilution
    │   ├── Condition: Rewards distributed before user snapshot
    │   ├── Action: Deposit just before harvest
    │   ├── Result: Steal others' rewards
    │   └── Check: patterns/defi-vault-patterns.md#reward-timing
    │
    ├── [H2] Flash Loan Reward Farming
    │   ├── Condition: Rewards based on instant balance
    │   ├── Action: Flash loan → Deposit → Harvest → Repay
    │   ├── Result: Steal rewards without actual deposit
    │   └── Check: patterns/flash-loan-patterns.md#reward-farming
    │
    ├── [H3] Reward Token Manipulation
    │   ├── Condition: Reward token price manipulable
    │   ├── Action: Manipulate reward token price
    │   ├── Result: Claim inflated rewards
    │   └── Check: patterns/defi-vault-patterns.md#reward-pricing
    │
    └── [H4] Reward Reentrancy
        ├── Condition: Claim rewards calls external contract
        ├── Action: Claim → Callback → Claim again
        ├── Result: Drain reward pool
        └── Check: patterns/reentrancy-patterns.md#rewards
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify vault type** - Single asset, multi-asset, LP token, strategy-based
2. **Check ERC4626 compliance** - If applicable
3. **Audit strategies** - Each strategy is a separate attack surface
4. **Test share math** - First depositor, rounding, precision
5. **Verify oracle usage** - Price manipulation risks

---

## Quick Reference by Severity

| Attack Branch | Impact | Likelihood | Severity |
|---------------|--------|------------|----------|
| [A1] First Depositor | Critical | High | Critical |
| [B2] Malicious Strategy | Critical | Low | High |
| [C2] Withdrawal Reentrancy | Critical | Medium | Critical |
| [D1] Flash Loan + Price Oracle | Critical | High | Critical |
| [E1] Preview != Actual | Medium | Medium | Medium |
| [F1] Unprotected Init | Critical | Low | High |
| [G1] Fee-on-Transfer | High | Medium | High |
| [H2] Flash Loan Reward Farming | High | High | High |

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Yearn Finance | 2023 | $11M | [A1] First Depositor | exploit-forensics/yearn-2023.md |
| Rari Capital | 2022 | $80M | [B2] Malicious Strategy | exploit-forensics/rari-2022.md |
| Beefy Finance | 2021 | $11M | [B3] Strategy Loss | exploit-forensics/beefy-2021.md |

---

## Checklist (Copy for Audit)

```markdown
## Vault Attack Surface

### Share Price [A]
- [ ] [A1] First depositor protection (virtual shares offset)
- [ ] [A2] Donation attack prevented
- [ ] [A3] Correct rounding direction
- [ ] [A4] Fee calculation uses correct base
- [ ] [A5] Sandwich protection on deposits

### Strategy [B]
- [ ] [B1] Strategy callback reentrancy protected
- [ ] [B2] Strategy validation before adding
- [ ] [B3] Strategy loss capped
- [ ] [B4] Debt accounting accurate
- [ ] [B5] Emergency withdraw secured

### Withdrawal [C]
- [ ] [C1] Fees accrued before withdrawal
- [ ] [C2] Withdrawal reentrancy protected
- [ ] [C3] maxWithdraw enforced
- [ ] [C4] Slippage protection
- [ ] [C5] Withdrawal queue fair

### Oracle/Price [D]
- [ ] [D1] Oracle manipulation resistant
- [ ] [D2] Stale price checks
- [ ] [D3] LP token pricing secure
- [ ] [D4] Yield reporting validated

### ERC4626 [E] (if applicable)
- [ ] [E1] Preview functions accurate
- [ ] [E2] Asset/share conversion correct
- [ ] [E3] Max limits enforced
- [ ] [E4] totalAssets() accurate

### Access Control [F]
- [ ] [F1] Initialization protected
- [ ] [F2] Governance has timelock
- [ ] [F3] Fee parameters capped
- [ ] [F4] Strategy migration secured
- [ ] [F5] Pause doesn't trap funds

### Token Handling [G]
- [ ] [G1] Fee-on-transfer handled or blocked
- [ ] [G2] Rebasing tokens handled or blocked
- [ ] [G3] ERC777 handled or blocked
- [ ] [G4] Approval front-running mitigated
- [ ] [G5] Deflationary tokens handled

### Rewards [H]
- [ ] [H1] Reward timing prevents dilution
- [ ] [H2] Flash loan reward farming prevented
- [ ] [H3] Reward token pricing secure
- [ ] [H4] Reward claim reentrancy protected
```
