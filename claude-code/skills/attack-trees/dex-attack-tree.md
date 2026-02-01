---
id: DEX-ATTACK-TREE
title: DEX/AMM Attack Tree
category: attack-tree
protocol: dex
triggers:
  - dex attack paths
  - how to attack dex
  - amm vulnerabilities
  - uniswap exploit tree
related_skills:
  - patterns/dex-patterns.md
  - patterns/oracle-patterns.md
  - patterns/flash-loan-patterns.md
  - exploit-forensics/uniswap-v3-oracle-2021.md
---

# DEX/AMM Attack Tree

Visual decision path for attacking decentralized exchanges and automated market makers.

---

## ROOT: Steal Funds from DEX/AMM

```
ROOT: Steal Funds from DEX/AMM
│
├── [A] Price Oracle Manipulation
│   │
│   ├── [A1] Spot Price Manipulation
│   │   ├── Condition: Protocol uses DEX spot price directly
│   │   ├── Action: Flash loan → Swap to manipulate price → Exploit
│   │   ├── Result: Borrow against inflated collateral
│   │   └── Check: patterns/oracle-patterns.md#spot-price
│   │
│   ├── [A2] TWAP Manipulation (Multi-Block)
│   │   ├── Condition: TWAP window too short
│   │   ├── Action: Maintain manipulated price across blocks
│   │   ├── Result: Poison TWAP oracle
│   │   └── Check: patterns/oracle-patterns.md#twap-manipulation
│   │
│   ├── [A3] Flash Loan + Oracle Read
│   │   ├── Condition: Oracle read not protected from same-block manipulation
│   │   ├── Action: Flash loan → Swap → Read oracle → Exploit → Repay
│   │   ├── Result: Use temporarily manipulated price
│   │   └── Check: patterns/flash-loan-patterns.md#oracle-manipulation
│   │
│   └── [A4] Low Liquidity Pool
│       ├── Condition: Oracle uses low-liquidity pool
│       ├── Action: Small swap causes large price impact
│       ├── Result: Cheap oracle manipulation
│       └── Check: patterns/oracle-patterns.md#liquidity-depth
│
├── [B] Liquidity Pool Exploits
│   │
│   ├── [B1] First LP Inflation Attack
│   │   ├── Condition: No minimum liquidity lock
│   │   ├── Action: Add 1 wei LP → Donate large amount → Inflate share price
│   │   ├── Result: Next LP gets 0 shares, funds stolen
│   │   └── Check: patterns/defi-vault-patterns.md#first-depositor
│   │
│   ├── [B2] LP Token Reentrancy
│   │   ├── Condition: LP token transfer before state update
│   │   ├── Action: Remove liquidity → Callback → Remove again
│   │   ├── Result: Drain pool
│   │   └── Check: patterns/reentrancy-patterns.md#lp-tokens
│   │
│   ├── [B3] Imbalanced Pool Drain
│   │   ├── Condition: No balance ratio check
│   │   ├── Action: Add unbalanced liquidity → Immediate arbitrage
│   │   ├── Result: Steal from pool via instant arb
│   │   └── Check: patterns/dex-patterns.md#balance-ratio
│   │
│   ├── [B4] LP Fee Manipulation
│   │   ├── Condition: Fees calculated on manipulated reserves
│   │   ├── Action: Inflate reserves → Claim excess fees
│   │   ├── Result: Steal protocol fees
│   │   └── Check: patterns/dex-patterns.md#fee-calculation
│   │
│   └── [B5] Sandwich LP Operations
│       ├── Condition: LP add/remove visible in mempool
│       ├── Action: Front-run LP add → Back-run for profit
│       ├── Result: MEV extraction from LP providers
│       └── Check: patterns/mev-patterns.md#lp-sandwich
│
├── [C] Swap Exploits
│   │
│   ├── [C1] Sandwich Attack
│   │   ├── Condition: No slippage protection
│   │   ├── Action: Front-run user swap → Back-run
│   │   ├── Result: Extract value from user trade
│   │   └── Check: patterns/mev-patterns.md#sandwich
│   │
│   ├── [C2] K-Value Manipulation
│   │   ├── Condition: x*y=k check vulnerable
│   │   ├── Action: Violate constant product formula
│   │   ├── Result: Drain pool funds
│   │   └── Check: patterns/dex-patterns.md#k-value
│   │
│   ├── [C3] Fee-on-Transfer Token
│   │   ├── Condition: No handling of transfer-fee tokens
│   │   ├── Action: Swap fee-on-transfer token
│   │   ├── Result: Pool receives less than accounted
│   │   └── Check: patterns/token-patterns.md#fee-on-transfer
│   │
│   ├── [C4] Rebase Token
│   │   ├── Condition: Pool doesn't handle rebasing tokens
│   │   ├── Action: Swap before rebase → Rebase → Swap after
│   │   ├── Result: Steal from rebase mismatch
│   │   └── Check: patterns/token-patterns.md#rebase
│   │
│   ├── [C5] Flash Swap Reentrancy
│   │   ├── Condition: Callback before state finalized
│   │   ├── Action: Flash swap → Callback → Reenter
│   │   ├── Result: Drain pool via reentrancy
│   │   └── Check: patterns/reentrancy-patterns.md#flash-swap
│   │
│   └── [C6] Rounding Errors
│       ├── Condition: Rounding favors user
│       ├── Action: Execute many tiny swaps
│       ├── Result: Drain dust over time
│       └── Check: patterns/dex-patterns.md#rounding
│
├── [D] Arbitrage & MEV
│   │
│   ├── [D1] Cross-Pool Arbitrage
│   │   ├── Condition: Price discrepancy across pools
│   │   ├── Action: Buy low pool → Sell high pool
│   │   ├── Result: Risk-free profit
│   │   └── Check: patterns/mev-patterns.md#arbitrage
│   │
│   ├── [D2] JIT Liquidity
│   │   ├── Condition: LP can add/remove within same block
│   │   ├── Action: Add LP → User swaps → Remove LP
│   │   ├── Result: Earn fees without risk
│   │   └── Check: patterns/mev-patterns.md#jit-liquidity
│   │
│   ├── [D3] Liquidation MEV
│   │   ├── Condition: Public liquidation + DEX price
│   │   ├── Action: Manipulate DEX → Liquidate → Profit
│   │   ├── Result: Unfair liquidations
│   │   └── Check: patterns/mev-patterns.md#liquidation
│   │
│   └── [D4] Backrunning
│       ├── Condition: Large swap changes price
│       ├── Action: Detect large swap → Arbitrage price back
│       ├── Result: Extract value from large trades
│       └── Check: patterns/mev-patterns.md#backrunning
│
├── [E] Concentrated Liquidity (Uniswap V3)
│   │
│   ├── [E1] Tick Manipulation
│   │   ├── Condition: Oracle depends on active tick
│   │   ├── Action: Manipulate price to specific tick
│   │   ├── Result: Poison oracle reading
│   │   └── Check: patterns/uniswap-v3-patterns.md#tick-oracle
│   │
│   ├── [E2] Position NFT Exploits
│   │   ├── Condition: NFT positions not validated
│   │   ├── Action: Create malicious position NFT
│   │   ├── Result: Bypass pool logic
│   │   └── Check: patterns/uniswap-v3-patterns.md#nft-positions
│   │
│   ├── [E3] Range Order MEV
│   │   ├── Condition: Single-tick liquidity visible
│   │   ├── Action: Front-run to consume range order
│   │   ├── Result: Steal liquidity provider profit
│   │   └── Check: patterns/uniswap-v3-patterns.md#range-orders
│   │
│   └── [E4] Fee Tier Manipulation
│       ├── Condition: Multiple fee tiers, routing not optimal
│       ├── Action: Route through manipulated high-fee pool
│       ├── Result: Force users to pay excess fees
│       └── Check: patterns/uniswap-v3-patterns.md#fee-tiers
│
├── [F] Router Exploits
│   │
│   ├── [F1] Reentrancy via Callback
│   │   ├── Condition: Router callback not protected
│   │   ├── Action: Swap → Callback → Reenter router
│   │   ├── Result: Drain router-held funds
│   │   └── Check: patterns/reentrancy-patterns.md#router
│   │
│   ├── [F2] Approval Front-Running
│   │   ├── Condition: User approves router with max uint
│   │   ├── Action: Front-run with malicious router call
│   │   ├── Result: Steal approved tokens
│   │   └── Check: patterns/erc20-patterns.md#approval-frontrun
│   │
│   ├── [F3] Path Validation Bypass
│   │   ├── Condition: Router doesn't validate swap path
│   │   ├── Action: Provide malicious path
│   │   ├── Result: Route through attacker pool
│   │   └── Check: patterns/dex-patterns.md#path-validation
│   │
│   └── [F4] Deadline Not Enforced
│       ├── Condition: Transaction deadline not checked
│       ├── Action: Submit old transaction with favorable price
│       ├── Result: Execute stale swap
│       └── Check: patterns/dex-patterns.md#deadline
│
└── [G] Governance & Admin
    │
    ├── [G1] Fee Parameter Manipulation
    │   ├── Condition: Admin can change fees without timelock
    │   ├── Action: Compromise admin → Set 100% fee
    │   ├── Result: Steal all swap fees
    │   └── Check: patterns/governance-patterns.md#parameter-changes
    │
    ├── [G2] Pause Exploit
    │   ├── Condition: Pause during user transaction
    │   ├── Action: Front-run user swap with pause
    │   ├── Result: Lock user funds
    │   └── Check: patterns/pausable-patterns.md#user-funds
    │
    └── [G3] Flash Loan Governance
        ├── Condition: LP tokens have immediate voting power
        ├── Action: Flash loan LP tokens → Vote → Repay
        ├── Result: Pass malicious proposal
        └── Check: patterns/governance-patterns.md#flash-loan-voting
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify pool type** - AMM (v2), Concentrated (v3), Stable (Curve), etc.
2. **Map attack surface** - Which branches apply to this DEX?
3. **Check each condition** - Does the vulnerability exist?
4. **Test exploits** - Write PoC for vulnerable paths
5. **Verify mitigations** - Are protections effective?

---

## Quick Reference by Severity

| Attack Branch | Impact | Likelihood | Severity |
|---------------|--------|------------|----------|
| [A1] Spot Price Manipulation | Critical | High | Critical |
| [B1] First LP Inflation | High | Medium | High |
| [C1] Sandwich Attack | Medium | Very High | Medium |
| [C5] Flash Swap Reentrancy | Critical | Low | High |
| [E1] Tick Manipulation | High | Medium | High |
| [F2] Approval Front-Running | High | Medium | High |

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Uniswap V3 Oracle | 2021 | N/A | [E1] Tick Manipulation | exploit-forensics/uniswap-v3-oracle-2021.md |
| Warp Finance | 2020 | $7.7M | [A3] Flash Loan + Oracle | exploit-forensics/warp-2020.md |
| Cream Finance | 2021 | $130M | [A1] Spot Price Manipulation | exploit-forensics/cream-2021.md |
| Harvest Finance | 2020 | $24M | [A1] Spot Price + [D1] Arbitrage | exploit-forensics/harvest-2020.md |

---

## Checklist (Copy for Audit)

```markdown
## DEX/AMM Attack Surface

### Oracle [A]
- [ ] [A1] Not using spot price for critical operations
- [ ] [A2] TWAP window sufficient (>30 min)
- [ ] [A3] Oracle reads protected from same-block manipulation
- [ ] [A4] Sufficient liquidity depth for oracle

### Liquidity Pool [B]
- [ ] [B1] Minimum liquidity locked (MINIMUM_LIQUIDITY)
- [ ] [B2] LP token transfers after state updates
- [ ] [B3] Balance ratio validated
- [ ] [B4] Fee calculation uses correct reserves
- [ ] [B5] LP operations not sandwichable

### Swaps [C]
- [ ] [C1] Slippage protection enforced
- [ ] [C2] K-value properly maintained
- [ ] [C3] Fee-on-transfer tokens handled
- [ ] [C4] Rebasing tokens blocked or handled
- [ ] [C5] Flash swap callback protected
- [ ] [C6] Rounding direction correct

### MEV [D]
- [ ] [D1] Arbitrage protection mechanisms
- [ ] [D2] JIT liquidity mitigations
- [ ] [D3] Liquidation front-running prevention
- [ ] [D4] Large swap protections

### Concentrated Liquidity [E] (if applicable)
- [ ] [E1] Tick-based oracle manipulation resistant
- [ ] [E2] Position NFT validation
- [ ] [E3] Range order MEV protections
- [ ] [E4] Fee tier routing secure

### Router [F]
- [ ] [F1] Callback reentrancy protected
- [ ] [F2] Approval front-running mitigated
- [ ] [F3] Swap path validation
- [ ] [F4] Deadline enforced

### Governance [G]
- [ ] [G1] Parameter changes have timelock
- [ ] [G2] Pause cannot trap user funds
- [ ] [G3] Flash loan voting prevented
```
