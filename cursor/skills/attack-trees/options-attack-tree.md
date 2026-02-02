---
id: OPTIONS-ATTACK-TREE
title: Options Protocol Attack Tree
category: attack-tree
protocol: options
triggers:
  - options attack paths
  - how to attack defi options
  - options vault vulnerabilities
  - greeks exploit tree
  - settlement attack
related_skills:
  - patterns/options-patterns.md
  - patterns/oracle-patterns.md
  - patterns/vault-patterns.md
  - exploit-forensics/ribbon-finance-2022.md
---

# Options Protocol Attack Tree

Visual decision path for attacking DeFi options protocols (Dopex, Lyra, Ribbon, Opyn, etc.).

---

## ROOT: Extract Value from Options Protocol

```
ROOT: Extract Value from Options Protocol
│
├── [A] Pricing/Oracle Manipulation
│   │
│   ├── [A1] Underlying Price Manipulation
│   │   ├── Condition: Option price depends on spot price
│   │   ├── Action: Manipulate spot → Change option value
│   │   ├── Result: Buy underpriced or sell overpriced options
│   │   └── Check: patterns/oracle-patterns.md#spot-price
│   │
│   ├── [A2] Implied Volatility Manipulation
│   │   ├── Condition: IV derived from on-chain data
│   │   ├── Action: Trade to manipulate IV
│   │   ├── Result: Mispriced options
│   │   └── Check: patterns/options-patterns.md#iv-manipulation
│   │
│   ├── [A3] Time-to-Expiry Exploitation
│   │   ├── Condition: Block timestamp used for time
│   │   ├── Action: Exploit timestamp manipulation
│   │   ├── Result: Incorrect theta decay
│   │   └── Check: patterns/options-patterns.md#time-exploit
│   │
│   ├── [A4] Interest Rate Oracle Attack
│   │   ├── Condition: Options pricing uses interest rates
│   │   ├── Action: Manipulate rate oracle
│   │   ├── Result: Mispriced options (especially puts)
│   │   └── Check: patterns/oracle-patterns.md#interest-rate
│   │
│   ├── [A5] Black-Scholes Approximation Exploit
│   │   ├── Condition: Simplified pricing model
│   │   ├── Action: Exploit model limitations
│   │   ├── Result: Arbitrage against model inaccuracies
│   │   └── Check: patterns/options-patterns.md#model-exploit
│   │
│   └── [A6] Multi-Leg Pricing Inconsistency
│       ├── Condition: Complex options strategies
│       ├── Action: Exploit pricing between legs
│       ├── Result: Risk-free profit on strategies
│       └── Check: patterns/options-patterns.md#multi-leg
│
├── [B] Exercise/Settlement Exploits
│   │
│   ├── [B1] Exercise Timing Attack
│   │   ├── Condition: American-style options
│   │   ├── Action: Exercise at manipulated price
│   │   ├── Result: Extract maximum intrinsic value
│   │   └── Check: patterns/options-patterns.md#exercise-timing
│   │
│   ├── [B2] Settlement Price Manipulation
│   │   ├── Condition: Settlement at specific timestamp
│   │   ├── Action: Manipulate price at settlement
│   │   ├── Result: Favorable settlement outcome
│   │   └── Check: patterns/options-patterns.md#settlement-price
│   │
│   ├── [B3] Auto-Exercise Exploitation
│   │   ├── Condition: Options auto-exercise if ITM
│   │   ├── Action: Manipulate to be barely ITM/OTM
│   │   ├── Result: Trigger/avoid exercise unfairly
│   │   └── Check: patterns/options-patterns.md#auto-exercise
│   │
│   ├── [B4] Cash Settlement Manipulation
│   │   ├── Condition: Cash-settled options
│   │   ├── Action: Manipulate settlement cash value
│   │   ├── Result: Extract more than entitled
│   │   └── Check: patterns/options-patterns.md#cash-settlement
│   │
│   ├── [B5] Physical Settlement Exploitation
│   │   ├── Condition: Physical delivery required
│   │   ├── Action: Exploit delivery mechanics
│   │   ├── Result: Arbitrage delivery vs cash
│   │   └── Check: patterns/options-patterns.md#physical-settlement
│   │
│   └── [B6] Expiry Race Condition
│       ├── Condition: Expiry timing critical
│       ├── Action: Exploit block timing at expiry
│       ├── Result: Exercise after knowing outcome
│       └── Check: patterns/options-patterns.md#expiry-race
│
├── [C] Vault/Writer Exploits
│   │
│   ├── [C1] Vault Share Inflation
│   │   ├── Condition: DOV (DeFi Option Vault) architecture
│   │   ├── Action: First depositor attack or share manipulation
│   │   ├── Result: Steal from other depositors
│   │   └── Check: patterns/vault-patterns.md#share-inflation
│   │
│   ├── [C2] Premium Extraction Attack
│   │   ├── Condition: Vault collects premiums
│   │   ├── Action: Exploit premium distribution timing
│   │   ├── Result: Capture premiums unfairly
│   │   └── Check: patterns/options-patterns.md#premium-extraction
│   │
│   ├── [C3] Collateral Ratio Manipulation
│   │   ├── Condition: Writers must maintain collateral
│   │   ├── Action: Manipulate ratio calculation
│   │   ├── Result: Under-collateralized positions
│   │   └── Check: patterns/options-patterns.md#collateral-ratio
│   │
│   ├── [C4] Writer Liquidation Attack
│   │   ├── Condition: Writers can be liquidated
│   │   ├── Action: Force liquidation through price manipulation
│   │   ├── Result: Acquire positions at discount
│   │   └── Check: patterns/liquidation-patterns.md#options
│   │
│   ├── [C5] Vault Strategy Gaming
│   │   ├── Condition: Vault follows predictable strategy
│   │   ├── Action: Front-run vault's option writing
│   │   ├── Result: Better prices at vault's expense
│   │   └── Check: patterns/options-patterns.md#strategy-gaming
│   │
│   ├── [C6] Epoch Timing Attack
│   │   ├── Condition: Vaults operate in epochs
│   │   ├── Action: Deposit/withdraw at epoch boundaries
│   │   ├── Result: Gaming entry/exit timing
│   │   └── Check: patterns/options-patterns.md#epoch-timing
│   │
│   └── [C7] Withdrawal Queue Manipulation
│       ├── Condition: Withdrawals queued
│       ├── Action: Front-run queue processing
│       ├── Result: Exit before losses materialize
│       └── Check: patterns/withdrawal-patterns.md#options-vault
│
├── [D] Greeks Manipulation
│   │
│   ├── [D1] Delta Hedging Exploitation
│   │   ├── Condition: Protocol delta hedges
│   │   ├── Action: Exploit hedging predictability
│   │   ├── Result: Profit from hedge trades
│   │   └── Check: patterns/options-patterns.md#delta-hedge
│   │
│   ├── [D2] Gamma Squeeze
│   │   ├── Condition: Large gamma positions
│   │   ├── Action: Force rapid price moves
│   │   ├── Result: Amplify gains via gamma
│   │   └── Check: patterns/options-patterns.md#gamma-squeeze
│   │
│   ├── [D3] Vega Manipulation
│   │   ├── Condition: Vega exposure significant
│   │   ├── Action: Manipulate implied volatility
│   │   ├── Result: Profit from vega positions
│   │   └── Check: patterns/options-patterns.md#vega-manipulation
│   │
│   ├── [D4] Theta Decay Gaming
│   │   ├── Condition: Options decay over time
│   │   ├── Action: Exploit theta decay mechanics
│   │   ├── Result: Maximize time decay profit
│   │   └── Check: patterns/options-patterns.md#theta-gaming
│   │
│   └── [D5] Cross-Greeks Arbitrage
│       ├── Condition: Greeks calculated independently
│       ├── Action: Exploit inconsistencies between greeks
│       ├── Result: Risk-free arbitrage
│       └── Check: patterns/options-patterns.md#cross-greeks
│
├── [E] AMM/Liquidity Pool Attacks
│   │
│   ├── [E1] Options AMM Price Manipulation
│   │   ├── Condition: Options traded via AMM
│   │   ├── Action: Large trades to move AMM price
│   │   ├── Result: Buy cheap, sell expensive
│   │   └── Check: patterns/amm-patterns.md#options
│   │
│   ├── [E2] LP Token Value Manipulation
│   │   ├── Condition: LPs provide option liquidity
│   │   ├── Action: Manipulate LP token value
│   │   ├── Result: Extract from LP pool
│   │   └── Check: patterns/options-patterns.md#lp-manipulation
│   │
│   ├── [E3] Skew Manipulation
│   │   ├── Condition: Put/call skew affects pricing
│   │   ├── Action: Manipulate market skew
│   │   ├── Result: Mispriced options
│   │   └── Check: patterns/options-patterns.md#skew
│   │
│   ├── [E4] Liquidity Fragmentation Exploit
│   │   ├── Condition: Liquidity across strikes/expiries
│   │   ├── Action: Exploit thin liquidity at certain strikes
│   │   ├── Result: Manipulate specific options
│   │   └── Check: patterns/options-patterns.md#fragmentation
│   │
│   └── [E5] Pool Reserve Manipulation
│       ├── Condition: Pool reserves determine pricing
│       ├── Action: Manipulate reserves
│       ├── Result: Mispriced options
│       └── Check: patterns/amm-patterns.md#reserves
│
├── [F] Structured Products Attacks
│   │
│   ├── [F1] Covered Call Vault Exploit
│   │   ├── Condition: Vault writes covered calls
│   │   ├── Action: Buy calls, pump underlying
│   │   ├── Result: Exercise at vault's expense
│   │   └── Check: patterns/options-patterns.md#covered-call
│   │
│   ├── [F2] Put Selling Vault Attack
│   │   ├── Condition: Vault sells puts
│   │   ├── Action: Buy puts, crash underlying
│   │   ├── Result: Exercise puts against vault
│   │   └── Check: patterns/options-patterns.md#put-selling
│   │
│   ├── [F3] Strangle/Straddle Manipulation
│   │   ├── Condition: Protocol offers complex strategies
│   │   ├── Action: Exploit strategy pricing
│   │   ├── Result: Arbitrage strategy legs
│   │   └── Check: patterns/options-patterns.md#strategies
│   │
│   ├── [F4] Barrier Option Trigger Attack
│   │   ├── Condition: Knock-in/knock-out barriers
│   │   ├── Action: Manipulate price to trigger barrier
│   │   ├── Result: Activate/deactivate options
│   │   └── Check: patterns/options-patterns.md#barrier
│   │
│   └── [F5] Exotic Option Pricing Exploit
│       ├── Condition: Complex exotic options
│       ├── Action: Exploit pricing model inaccuracies
│       ├── Result: Arbitrage mispriced exotics
│       └── Check: patterns/options-patterns.md#exotic
│
└── [G] Cross-Protocol/Systemic Attacks
    │
    ├── [G1] Options + Spot Manipulation
    │   ├── Condition: Options and spot on same assets
    │   ├── Action: Coordinate attack across markets
    │   ├── Result: Amplified profits
    │   └── Check: patterns/cross-protocol-patterns.md#options-spot
    │
    ├── [G2] Options + Perps Arbitrage
    │   ├── Condition: Both options and perps available
    │   ├── Action: Exploit pricing differences
    │   ├── Result: Risk-free arbitrage
    │   └── Check: patterns/cross-protocol-patterns.md#options-perps
    │
    ├── [G3] Insurance Fund Drain
    │   ├── Condition: Protocol has insurance fund
    │   ├── Action: Create maximum losses
    │   ├── Result: Deplete insurance
    │   └── Check: patterns/options-patterns.md#insurance
    │
    ├── [G4] Governance Attack on Parameters
    │   ├── Condition: Governance controls pricing/risk params
    │   ├── Action: Vote to change parameters maliciously
    │   ├── Result: Create exploitable conditions
    │   └── Check: patterns/governance-patterns.md#options-params
    │
    └── [G5] Oracle Dependency Chain Attack
        ├── Condition: Multiple oracles for different inputs
        ├── Action: Exploit dependency between oracles
        ├── Result: Cascading price manipulation
        └── Check: patterns/oracle-patterns.md#dependency-chain
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify option type** - European/American, Call/Put, Vanilla/Exotic
2. **Check pricing model** - Black-Scholes, Binomial, Custom AMM
3. **Analyze settlement** - Cash, Physical, Automatic
4. **Review collateral** - Full, Partial, Under-collateralized
5. **Test vault mechanics** - Epochs, Premiums, Withdrawals

---

## Quick Reference by Protocol Type

### DOVs (DeFi Option Vaults)
**Critical Vulnerabilities:**
- [C1] Vault share inflation (Critical)
- [C5] Strategy gaming (High)
- [C6] Epoch timing attacks (High)

**Examples:** Ribbon Finance, Dopex, Thetanuts

### Options AMMs (Lyra-style)
**Critical Vulnerabilities:**
- [E1] AMM price manipulation (Critical)
- [D1] Delta hedging exploitation (High)
- [A2] IV manipulation (High)

**Examples:** Lyra, Premia, Hegic

### Peer-to-Pool Options (Opyn-style)
**Critical Vulnerabilities:**
- [C3] Collateral ratio manipulation (Critical)
- [C4] Writer liquidation (High)
- [B2] Settlement price manipulation (Critical)

**Examples:** Opyn, Squeeth

### Structured Products
**Critical Vulnerabilities:**
- [F1] Covered call vault exploit (Critical)
- [F2] Put selling vault attack (Critical)
- [F4] Barrier trigger attack (High)

**Examples:** Ribbon, Friktion, Katana

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Ribbon Finance Auction | 2022 | Market impact | [C5] | Predictable strategy front-running |
| Opyn Gamma Attack | 2020 | $371K | [B1] | Exercise timing manipulation |
| Hegic IV Issue | 2021 | N/A | [A2] | IV not updating correctly |
| Dopex Atlantic | 2023 | N/A (caught) | [C3] | Collateral calculation error |

---

## Checklist (Copy for Audit)

```markdown
## Options Attack Surface

### Pricing/Oracle [A]
- [ ] [A1] Underlying price manipulation resistant
- [ ] [A2] IV calculation secure
- [ ] [A3] Time handling correct (no block manipulation)
- [ ] [A4] Interest rate oracle secure
- [ ] [A5] Pricing model appropriate
- [ ] [A6] Multi-leg pricing consistent

### Exercise/Settlement [B]
- [ ] [B1] Exercise timing fair
- [ ] [B2] Settlement price manipulation resistant
- [ ] [B3] Auto-exercise rules clear and fair
- [ ] [B4] Cash settlement calculation correct
- [ ] [B5] Physical settlement secure
- [ ] [B6] Expiry race conditions handled

### Vault/Writer [C]
- [ ] [C1] Vault share inflation prevented
- [ ] [C2] Premium distribution fair
- [ ] [C3] Collateral ratio enforced
- [ ] [C4] Writer liquidation fair
- [ ] [C5] Strategy not predictable
- [ ] [C6] Epoch boundaries secure
- [ ] [C7] Withdrawal queue fair

### Greeks [D]
- [ ] [D1] Delta hedging not exploitable
- [ ] [D2] Gamma squeeze resistant
- [ ] [D3] Vega calculation correct
- [ ] [D4] Theta decay calculated correctly
- [ ] [D5] Greeks consistent

### AMM/LP [E]
- [ ] [E1] AMM price manipulation resistant
- [ ] [E2] LP token value secure
- [ ] [E3] Skew handled correctly
- [ ] [E4] Thin liquidity handled
- [ ] [E5] Pool reserves manipulation resistant

### Structured Products [F]
- [ ] [F1] Covered call risks documented
- [ ] [F2] Put selling risks documented
- [ ] [F3] Complex strategy pricing correct
- [ ] [F4] Barrier triggers secure
- [ ] [F5] Exotic pricing verified

### Cross-Protocol [G]
- [ ] [G1] Spot market correlation considered
- [ ] [G2] Perps market correlation considered
- [ ] [G3] Insurance fund adequate
- [ ] [G4] Governance attack resistant
- [ ] [G5] Oracle dependencies mapped
```

---

## Protocol-Specific Considerations

### Lyra
- GWAV (geometric weighted average) for IV
- Delta hedging with spot AMM
- Circuit breakers on extreme moves

### Dopex
- Atlantic options (partial collateral release)
- rDPX rebate token mechanics
- Multiple vault strategies

### Ribbon Finance
- Weekly epochs - check timing
- Auction mechanism - check front-running
- Multiple underlying assets

### Opyn (Squeeth)
- Power perpetual - unique pricing
- Funding rate mechanics
- Crab strategy vaults

---

## Options-Specific Terminology

| Term | Definition | Attack Relevance |
|------|------------|------------------|
| ITM | In-the-money | Exercise profitable |
| OTM | Out-of-the-money | Exercise not profitable |
| ATM | At-the-money | Strike ≈ Spot |
| Delta | Price sensitivity | Hedging, manipulation |
| Gamma | Delta sensitivity | Squeeze attacks |
| Vega | IV sensitivity | IV manipulation |
| Theta | Time decay | Timing attacks |
| IV | Implied volatility | Pricing manipulation |

---

## See Also

- **Patterns:** [options-patterns.md](../patterns/options-patterns.md)
- **Vault Patterns:** [vault-patterns.md](../patterns/vault-patterns.md)
- **Oracle Patterns:** [oracle-patterns.md](../patterns/oracle-patterns.md)
- **Related:** [perpetuals-attack-tree.md](./perpetuals-attack-tree.md)

---

**Last Updated:** 2025
**Version:** 1.0
