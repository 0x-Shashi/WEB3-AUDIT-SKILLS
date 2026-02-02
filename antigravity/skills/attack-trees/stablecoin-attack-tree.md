---
id: STABLECOIN-ATTACK-TREE
title: Stablecoin Attack Tree
category: attack-tree
protocol: stablecoin
triggers:
  - stablecoin attack paths
  - how to attack stablecoin
  - depeg vulnerabilities
  - stablecoin exploit tree
related_skills:
  - patterns/stablecoin-patterns.md
  - patterns/oracle-patterns.md
  - patterns/lending-pool-patterns.md
  - exploit-forensics/terra-luna-2022.md
  - exploit-forensics/usdc-depeg-2023.md
---

# Stablecoin Attack Tree

Visual decision path for attacking stablecoins (algorithmic, collateralized, and hybrid).

---

## ROOT: Break the Peg or Drain Reserves

```
ROOT: Break the Peg or Drain Reserves
│
├── [A] Depeg Attacks
│   │
│   ├── [A1] Death Spiral (Algorithmic)
│   │   ├── Condition: Peg maintained by mint/burn mechanism
│   │   ├── Action: Large sell → Price drops → More minting → Hyperinflation
│   │   ├── Result: Complete collapse (see Terra/UST)
│   │   └── Check: patterns/stablecoin-patterns.md#death-spiral
│   │
│   ├── [A2] Bank Run on Collateral
│   │   ├── Condition: Fractional reserve or slow liquidation
│   │   ├── Action: Mass redemptions → Collateral insufficient
│   │   ├── Result: Peg breaks, some users can't redeem
│   │   └── Check: patterns/stablecoin-patterns.md#bank-run
│   │
│   ├── [A3] Oracle Manipulation
│   │   ├── Condition: Peg relies on oracle price feed
│   │   ├── Action: Manipulate oracle → System mints/burns incorrectly
│   │   ├── Result: Depeg via incorrect stabilization
│   │   └── Check: patterns/oracle-patterns.md#stablecoin
│   │
│   ├── [A4] Liquidity Drain
│   │   ├── Condition: Peg depends on DEX liquidity
│   │   ├── Action: Remove liquidity from pools
│   │   ├── Result: High slippage causes depeg
│   │   └── Check: patterns/stablecoin-patterns.md#liquidity-attack
│   │
│   ├── [A5] Collateral Price Crash
│   │   ├── Condition: Collateral is volatile asset
│   │   ├── Action: Wait for/cause collateral crash
│   │   ├── Result: Undercollateralization → Depeg
│   │   └── Check: patterns/stablecoin-patterns.md#collateral-crash
│   │
│   └── [A6] Psychological/FUD Attack
│       ├── Condition: Peg relies on confidence
│       ├── Action: Spread FUD → Users panic sell
│       ├── Result: Self-fulfilling depeg prophecy
│       └── Check: patterns/stablecoin-patterns.md#confidence-attack
│
├── [B] Reserve Drain
│   │
│   ├── [B1] Reserve Accounting Error
│   │   ├── Condition: Reserve calculations have bugs
│   │   ├── Action: Exploit accounting to over-withdraw
│   │   ├── Result: Reserve drained, stablecoin unbacked
│   │   └── Check: patterns/stablecoin-patterns.md#reserve-accounting
│   │
│   ├── [B2] Collateralization Ratio Manipulation
│   │   ├── Condition: System checks collateral ratio incorrectly
│   │   ├── Action: Manipulate to appear over-collateralized
│   │   ├── Result: Mint more stablecoins than backed
│   │   └── Check: patterns/stablecoin-patterns.md#collateral-ratio
│   │
│   ├── [B3] Flash Loan Reserve Manipulation
│   │   ├── Condition: Reserve checks happen after flash loan
│   │   ├── Action: Flash loan → Inflate reserves → Mint → Repay
│   │   ├── Result: Unbacked stablecoins in circulation
│   │   └── Check: patterns/flash-loan-patterns.md#stablecoin
│   │
│   ├── [B4] Yield-Bearing Collateral Drain
│   │   ├── Condition: Collateral generates yield
│   │   ├── Action: Exploit yield accounting
│   │   ├── Result: Steal accrued yield from reserves
│   │   └── Check: patterns/stablecoin-patterns.md#yield-exploit
│   │
│   └── [B5] Cross-Chain Reserve Inconsistency
│       ├── Condition: Stablecoin on multiple chains
│       ├── Action: Exploit sync issues between chains
│       ├── Result: Mint on multiple chains, drain on one
│       └── Check: patterns/bridge-patterns.md#stablecoin
│
├── [C] Minting Exploits
│   │
│   ├── [C1] Infinite Minting
│   │   ├── Condition: Minting not properly capped
│   │   ├── Action: Mint unlimited stablecoins
│   │   ├── Result: Hyperinflation, complete depeg
│   │   └── Check: patterns/stablecoin-patterns.md#infinite-mint
│   │
│   ├── [C2] Mint Without Collateral
│   │   ├── Condition: Collateral check bypassable
│   │   ├── Action: Mint stablecoins with 0 collateral
│   │   ├── Result: Unbacked supply increase
│   │   └── Check: patterns/stablecoin-patterns.md#mint-bypass
│   │
│   ├── [C3] Minting Front-Running
│   │   ├── Condition: Large mint visible in mempool
│   │   ├── Action: Front-run mint with sell order
│   │   ├── Result: Profit from temporary depeg
│   │   └── Check: patterns/mev-patterns.md#stablecoin-mint
│   │
│   ├── [C4] Decimal Precision in Minting
│   │   ├── Condition: Rounding errors in mint calculations
│   │   ├── Action: Repeatedly mint small amounts
│   │   ├── Result: Accumulate unbacked coins via rounding
│   │   └── Check: patterns/stablecoin-patterns.md#mint-rounding
│   │
│   └── [C5] Rebasing Collateral Minting
│       ├── Condition: Collateral is rebasing token
│       ├── Action: Deposit → Rebase increases balance → Withdraw excess
│       ├── Result: Mint more than deserved
│       └── Check: patterns/token-patterns.md#rebase-collateral
│
├── [D] Redemption Exploits
│   │
│   ├── [D1] Redemption Front-Running
│   │   ├── Condition: Large redemptions visible
│   │   ├── Action: Front-run redemption to get best collateral
│   │   ├── Result: Later redeemers get worse collateral
│   │   └── Check: patterns/mev-patterns.md#redemption
│   │
│   ├── [D2] Selective Redemption
│   │   ├── Condition: Multiple collateral types
│   │   ├── Action: Only redeem best collateral
│   │   ├── Result: Reserve left with bad collateral
│   │   └── Check: patterns/stablecoin-patterns.md#selective-redemption
│   │
│   ├── [D3] Redemption DoS
│   │   ├── Condition: Redemption can be blocked
│   │   ├── Action: Prevent redemptions during depeg
│   │   ├── Result: Users trapped, peg worsens
│   │   └── Check: patterns/dos-patterns.md#redemption
│   │
│   ├── [D4] Redemption Rate Manipulation
│   │   ├── Condition: Redemption rate adjustable
│   │   ├── Action: Manipulate to favorable rate
│   │   ├── Result: Redeem for more than deposited
│   │   └── Check: patterns/stablecoin-patterns.md#redemption-rate
│   │
│   └── [D5] Redemption Rounding Exploit
│       ├── Condition: Rounding favors redeemer
│       ├── Action: Repeatedly redeem small amounts
│       ├── Result: Drain reserves via rounding
│       └── Check: patterns/stablecoin-patterns.md#redemption-rounding
│
├── [E] Liquidation Cascade
│   │
│   ├── [E1] Cascade Liquidation
│   │   ├── Condition: Many positions near liquidation
│   │   ├── Action: Trigger liquidation → Price drops → More liquidations
│   │   ├── Result: Spiral of liquidations, bad debt
│   │   └── Check: patterns/lending-pool-patterns.md#liquidation-cascade
│   │
│   ├── [E2] Liquidation DoS
│   │   ├── Condition: Liquidation can be prevented
│   │   ├── Action: Block liquidations during price crash
│   │   ├── Result: System accumulates bad debt
│   │   └── Check: patterns/dos-patterns.md#liquidation
│   │
│   ├── [E3] Liquidation MEV Extraction
│   │   ├── Condition: Liquidation bonus too high
│   │   ├── Action: Trigger liquidations for profit
│   │   ├── Result: Unnecessary liquidations, user loss
│   │   └── Check: patterns/mev-patterns.md#liquidation
│   │
│   ├── [E4] Flash Crash Liquidation
│   │   ├── Condition: Oracle uses short TWAP
│   │   ├── Action: Crash price briefly → Liquidate → Recover
│   │   ├── Result: Unfair liquidations
│   │   └── Check: patterns/oracle-patterns.md#flash-crash
│   │
│   └── [E5] Self-Liquidation
│       ├── Condition: User can liquidate own position
│       ├── Action: Self-liquidate to get bonus
│       ├── Result: Exploit liquidation incentives
│       └── Check: patterns/lending-pool-patterns.md#self-liquidation
│
├── [F] Governance Attacks on Stablecoin
│   │
│   ├── [F1] Parameter Manipulation
│   │   ├── Condition: Governance can change critical params
│   │   ├── Action: Pass proposal to destabilize (e.g., remove collateral requirement)
│   │   ├── Result: System becomes vulnerable
│   │   └── Check: patterns/governance-patterns.md#stablecoin
│   │
│   ├── [F2] Emergency Pause Abuse
│   │   ├── Condition: Admin can pause redemptions
│   │   ├── Action: Pause during depeg to trap users
│   │   ├── Result: Inability to exit, worsens panic
│   │   └── Check: patterns/pausable-patterns.md#stablecoin
│   │
│   ├── [F3] Collateral Whitelist Attack
│   │   ├── Condition: Governance controls accepted collateral
│   │   ├── Action: Add worthless collateral
│   │   ├── Result: System backs stablecoin with garbage
│   │   └── Check: patterns/governance-patterns.md#collateral-whitelist
│   │
│   └── [F4] Timelock Bypass for Stablecoin
│       ├── Condition: Critical changes lack timelock
│       ├── Action: Instant parameter change
│       ├── Result: No time to exit before destabilization
│       └── Check: patterns/governance-patterns.md#timelock
│
└── [G] Arbitrage & Economic Attacks
    │
    ├── [G1] Arbitrage Extraction
    │   ├── Condition: Price difference across venues
    │   ├── Action: Buy low → Sell high repeatedly
    │   ├── Result: Drain reserves via arbitrage
    │   └── Check: patterns/stablecoin-patterns.md#arbitrage
    │
    ├── [G2] Funding Rate Manipulation
    │   ├── Condition: Perpetual funding tied to peg
    │   ├── Action: Manipulate peg to extract funding
    │   ├── Result: Economic attack on perp traders
    │   └── Check: patterns/stablecoin-patterns.md#funding-rate
    │
    ├── [G3] Cross-Market Manipulation
    │   ├── Condition: Multiple trading venues
    │   ├── Action: Manipulate on one venue → Exploit others
    │   ├── Result: Profit from price discrepancies
    │   └── Check: patterns/stablecoin-patterns.md#cross-market
    │
    └── [G4] Yield Farming Drain
        ├── Condition: High yield offered for stablecoin
        ├── Action: Farm yield → Dump stablecoin
        ├── Result: Yield dilution, price pressure
        └── Check: patterns/stablecoin-patterns.md#yield-farming
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify stablecoin type** - Algorithmic, Fiat-backed, Crypto-collateralized, Hybrid
2. **Check peg mechanism** - Mint/burn, AMO, Redemption, Algorithmic rebalance
3. **Analyze collateral** - Type, ratio, oracle, liquidation
4. **Test depeg scenarios** - Bank run, death spiral, cascade
5. **Review governance** - Parameter changes, emergency powers, timelock

---

## Quick Reference by Stablecoin Type

### Algorithmic Stablecoins
**Critical Vulnerabilities:**
- [A1] Death Spiral (Critical)
- [A6] Psychological Attack (High)
- [G2] Funding Rate Manipulation (Medium)

**Examples:** Terra UST, FRAX (algorithmic portion), AMPL

### Fiat-Backed Stablecoins
**Critical Vulnerabilities:**
- [A2] Bank Run (High)
- [F2] Emergency Pause (Medium)
- [D3] Redemption DoS (High)

**Examples:** USDC, USDT, BUSD

### Crypto-Collateralized
**Critical Vulnerabilities:**
- [A5] Collateral Price Crash (Critical)
- [E1] Cascade Liquidation (Critical)
- [B2] Collateralization Ratio (High)

**Examples:** DAI, LUSD, sUSD

### Hybrid Stablecoins
**Critical Vulnerabilities:**
- All of the above
- [B5] Cross-Chain Inconsistency (High)
- [F1] Parameter Manipulation (High)

**Examples:** FRAX, UST (before collapse)

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Terra/Luna Collapse | 2022 | $40B | [A1] Death Spiral | Largest DeFi collapse ever |
| USDC Depeg | 2023 | Temporary | [A2] Bank Run + [A6] FUD | SVB collapse caused panic |
| Iron Finance | 2021 | $2B | [A1] Death Spiral | TITAN algorithmic stablecoin collapse |
| Beanstalk | 2022 | $182M | [F1] Governance → [B1] Reserve Drain | Flash loan governance attack |

---

## Checklist (Copy for Audit)

```markdown
## Stablecoin Attack Surface

### Depeg [A]
- [ ] [A1] Death spiral resistant (if algorithmic)
- [ ] [A2] Sufficient reserves for bank run
- [ ] [A3] Oracle manipulation resistant
- [ ] [A4] Liquidity requirements enforced
- [ ] [A5] Collateral diversification
- [ ] [A6] Confidence maintenance mechanisms

### Reserves [B]
- [ ] [B1] Reserve accounting accurate
- [ ] [B2] Collateralization ratio validated
- [ ] [B3] Flash loan protection on reserves
- [ ] [B4] Yield accounting secure
- [ ] [B5] Cross-chain reserve consistency

### Minting [C]
- [ ] [C1] Minting caps enforced
- [ ] [C2] Collateral required for all mints
- [ ] [C3] Front-running protection
- [ ] [C4] Precision/rounding correct
- [ ] [C5] Rebasing collateral handled

### Redemption [D]
- [ ] [D1] Redemption ordering fair
- [ ] [D2] Selective redemption prevented/managed
- [ ] [D3] Redemption cannot be DoS'd
- [ ] [D4] Redemption rate manipulation resistant
- [ ] [D5] Rounding direction correct

### Liquidation [E]
- [ ] [E1] Cascade liquidation circuit breakers
- [ ] [E2] Liquidation cannot be blocked
- [ ] [E3] Liquidation bonus reasonable
- [ ] [E4] Flash crash protection (TWAP)
- [ ] [E5] Self-liquidation prevented

### Governance [F]
- [ ] [F1] Parameter changes have limits/timelock
- [ ] [F2] Pause cannot trap users long-term
- [ ] [F3] Collateral whitelist vetted
- [ ] [F4] Critical changes have timelock

### Economic [G]
- [ ] [G1] Arbitrage bounds prevent drain
- [ ] [G2] Funding rate manipulation resistant
- [ ] [G3] Cross-market consistency
- [ ] [G4] Yield farming limits
```

---

## Specific Mechanism Analysis

### Mint/Burn Rebalancing
**Key Checks:**
- Mint/burn ratio correct
- Oracle price trusted
- Minting caps enforced
- Burning incentives aligned

### Collateral Ratio
**Key Checks:**
- Over-collateralization maintained
- Liquidation triggers appropriate
- Oracle accurate
- Emergency shutdown threshold

### Algorithmic Market Operations (AMO)
**Key Checks:**
- AMO operations audited
- Price impact limits
- Rebalance frequency reasonable
- Governance controls secure

### Redemption Mechanism
**Key Checks:**
- 1:1 redemption guaranteed
- Sufficient liquidity
- Fair ordering (no front-running)
- Redemption cannot be blocked

---

## See Also

- **Patterns:** [stablecoin-patterns.md](../patterns/stablecoin-patterns.md)
- **Oracle Patterns:** [oracle-patterns.md](../patterns/oracle-patterns.md)
- **Lending Patterns:** [lending-pool-patterns.md](../patterns/lending-pool-patterns.md)
- **Exploits:** exploit-forensics/terra-luna-2022.md, exploit-forensics/iron-finance-2021.md

---

**Last Updated:** 2025
**Version:** 1.0
