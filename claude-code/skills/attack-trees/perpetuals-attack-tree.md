---
id: PERPETUALS-ATTACK-TREE
title: Perpetuals Protocol Attack Tree
category: attack-tree
protocol: perpetuals
triggers:
  - perp attack paths
  - how to attack perpetuals
  - futures vulnerabilities
  - liquidation exploit tree
  - funding rate attack
related_skills:
  - patterns/perpetuals-patterns.md
  - patterns/oracle-patterns.md
  - patterns/liquidation-patterns.md
  - exploit-forensics/mango-markets-2022.md
---

# Perpetuals Protocol Attack Tree

Visual decision path for attacking perpetual futures protocols (GMX, dYdX, Perp Protocol, etc.).

---

## ROOT: Extract Value from Perpetuals Protocol

```
ROOT: Extract Value from Perpetuals Protocol
│
├── [A] Oracle Manipulation
│   │
│   ├── [A1] Index Price Manipulation
│   │   ├── Condition: Index price from manipulatable exchanges
│   │   ├── Action: Pump/dump on low-liquidity exchanges
│   │   ├── Result: Trigger unfair liquidations or profit from price moves
│   │   └── Check: patterns/oracle-patterns.md#index-price
│   │
│   ├── [A2] Mark Price Manipulation
│   │   ├── Condition: Mark price calculation exploitable
│   │   ├── Action: Manipulate orderbook or funding
│   │   ├── Result: Artificial mark price for liquidations
│   │   └── Check: patterns/oracle-patterns.md#mark-price
│   │
│   ├── [A3] Oracle Front-Running
│   │   ├── Condition: Oracle update visible before execution
│   │   ├── Action: Front-run price updates
│   │   ├── Result: Risk-free directional positions
│   │   └── Check: patterns/oracle-patterns.md#front-running
│   │
│   ├── [A4] Oracle Delay Exploitation
│   │   ├── Condition: Price oracle has latency
│   │   ├── Action: Trade on stale prices
│   │   ├── Result: Arbitrage protocol vs real price
│   │   └── Check: patterns/oracle-patterns.md#delay
│   │
│   ├── [A5] Multi-Asset Oracle Inconsistency
│   │   ├── Condition: Different assets use different oracles
│   │   ├── Action: Exploit price divergence between oracles
│   │   ├── Result: Cross-margin arbitrage
│   │   └── Check: patterns/oracle-patterns.md#multi-asset
│   │
│   └── [A6] Extreme Volatility Exploitation
│       ├── Condition: Oracle fails during high volatility
│       ├── Action: Trade during oracle failure
│       ├── Result: Profit from stale/incorrect prices
│       └── Check: patterns/oracle-patterns.md#volatility
│
├── [B] Funding Rate Attacks
│   │
│   ├── [B1] Funding Rate Manipulation
│   │   ├── Condition: Funding based on open interest imbalance
│   │   ├── Action: Create large position to skew funding
│   │   ├── Result: Extract funding from other side
│   │   └── Check: patterns/perpetuals-patterns.md#funding-manipulation
│   │
│   ├── [B2] Funding Rate Prediction
│   │   ├── Condition: Funding rate predictable
│   │   ├── Action: Position before funding payment
│   │   ├── Result: Capture funding payments
│   │   └── Check: patterns/perpetuals-patterns.md#funding-prediction
│   │
│   ├── [B3] Cross-Protocol Funding Arbitrage
│   │   ├── Condition: Different funding rates across platforms
│   │   ├── Action: Long on one, short on another
│   │   ├── Result: Risk-free funding capture
│   │   └── Check: patterns/perpetuals-patterns.md#funding-arb
│   │
│   ├── [B4] Funding Rate Griefing
│   │   ├── Condition: Small positions affect funding calculation
│   │   ├── Action: Spam small positions
│   │   ├── Result: Disrupt funding mechanism
│   │   └── Check: patterns/perpetuals-patterns.md#funding-grief
│   │
│   └── [B5] Settlement Price Attack
│       ├── Condition: Settlement at specific time
│       ├── Action: Manipulate price at settlement
│       ├── Result: Favorable settlement
│       └── Check: patterns/perpetuals-patterns.md#settlement
│
├── [C] Liquidation Exploits
│   │
│   ├── [C1] Forced Liquidation Attack
│   │   ├── Condition: Can manipulate price to trigger liquidation
│   │   ├── Action: Pump/dump → Liquidate targets → Profit
│   │   ├── Result: Extract value from liquidated positions
│   │   └── Check: patterns/liquidation-patterns.md#forced
│   │
│   ├── [C2] Liquidation Cascade
│   │   ├── Condition: Liquidations cause further price impact
│   │   ├── Action: Trigger first liquidation → Chain reaction
│   │   ├── Result: Massive cascading liquidations
│   │   └── Check: patterns/liquidation-patterns.md#cascade
│   │
│   ├── [C3] Liquidation Bot Competition
│   │   ├── Condition: External liquidators compete
│   │   ├── Action: Front-run other liquidators
│   │   ├── Result: Capture liquidation bonus
│   │   └── Check: patterns/liquidation-patterns.md#bot-competition
│   │
│   ├── [C4] Partial Liquidation Gaming
│   │   ├── Condition: Partial liquidations allowed
│   │   ├── Action: Game partial liquidation mechanics
│   │   ├── Result: Keep position while extracting value
│   │   └── Check: patterns/liquidation-patterns.md#partial
│   │
│   ├── [C5] Liquidation Penalty Extraction
│   │   ├── Condition: Liquidation penalty to insurance fund
│   │   ├── Action: Self-liquidate to extract from fund
│   │   ├── Result: Drain insurance fund
│   │   └── Check: patterns/liquidation-patterns.md#penalty
│   │
│   ├── [C6] ADL (Auto-Deleveraging) Manipulation
│   │   ├── Condition: ADL used when insurance depleted
│   │   ├── Action: Force ADL on profitable positions
│   │   ├── Result: Close profitable positions unfairly
│   │   └── Check: patterns/liquidation-patterns.md#adl
│   │
│   └── [C7] Bankruptcy Price Exploitation
│       ├── Condition: Bankruptcy price calculation flawed
│       ├── Action: Exploit bankruptcy mechanics
│       ├── Result: Create socialized loss
│       └── Check: patterns/liquidation-patterns.md#bankruptcy
│
├── [D] Position Manipulation
│   │
│   ├── [D1] Position Size Manipulation
│   │   ├── Condition: No proper position limits
│   │   ├── Action: Open massive position → Dominate market
│   │   ├── Result: Market manipulation power
│   │   └── Check: patterns/perpetuals-patterns.md#position-limits
│   │
│   ├── [D2] Leverage Overflow
│   │   ├── Condition: Leverage calculation has precision issues
│   │   ├── Action: Exploit leverage edge cases
│   │   ├── Result: Higher effective leverage
│   │   └── Check: patterns/precision-patterns.md#leverage
│   │
│   ├── [D3] Cross-Margin Exploitation
│   │   ├── Condition: Cross-margin allows shared collateral
│   │   ├── Action: Exploit collateral sharing mechanics
│   │   ├── Result: Under-collateralized positions
│   │   └── Check: patterns/perpetuals-patterns.md#cross-margin
│   │
│   ├── [D4] Isolated Margin Escape
│   │   ├── Condition: Can switch margin modes
│   │   ├── Action: Switch at strategic times
│   │   ├── Result: Avoid liquidation unfairly
│   │   └── Check: patterns/perpetuals-patterns.md#margin-switch
│   │
│   ├── [D5] PnL Manipulation
│   │   ├── Condition: Unrealized PnL affects margin
│   │   ├── Action: Manipulate unrealized PnL
│   │   ├── Result: Artificially increase margin
│   │   └── Check: patterns/perpetuals-patterns.md#pnl
│   │
│   └── [D6] Hedged Position Exploitation
│       ├── Condition: Protocol allows hedge mode
│       ├── Action: Exploit long+short same asset
│       ├── Result: Gaming fee/funding mechanics
│       └── Check: patterns/perpetuals-patterns.md#hedge-mode
│
├── [E] Liquidity Pool Attacks (AMM-based Perps)
│   │
│   ├── [E1] LP Token Price Manipulation
│   │   ├── Condition: LP token price derivable
│   │   ├── Action: Manipulate LP token value
│   │   ├── Result: Steal from LPs or protocol
│   │   └── Check: patterns/perpetuals-patterns.md#lp-manipulation
│   │
│   ├── [E2] Liquidity Extraction Attack
│   │   ├── Condition: LP can be drained directionally
│   │   ├── Action: Take one-sided positions
│   │   ├── Result: Extract value from LP
│   │   └── Check: patterns/perpetuals-patterns.md#lp-extraction
│   │
│   ├── [E3] Vault Share Manipulation
│   │   ├── Condition: Vault shares represent LP
│   │   ├── Action: Inflate/deflate share value
│   │   ├── Result: Steal from other LPs
│   │   └── Check: patterns/vault-patterns.md#share-manipulation
│   │
│   ├── [E4] Utilization Rate Gaming
│   │   ├── Condition: Fees based on utilization
│   │   ├── Action: Manipulate utilization rate
│   │   ├── Result: Pay less fees or grief LPs
│   │   └── Check: patterns/perpetuals-patterns.md#utilization
│   │
│   └── [E5] Just-In-Time (JIT) Liquidity Attack
│       ├── Condition: LP can be added/removed instantly
│       ├── Action: Add LP before fees, remove after
│       ├── Result: Capture fees without risk
│       └── Check: patterns/perpetuals-patterns.md#jit
│
├── [F] Order Execution Attacks
│   │
│   ├── [F1] Front-Running Orders
│   │   ├── Condition: Orders visible in mempool
│   │   ├── Action: Front-run large orders
│   │   ├── Result: MEV extraction
│   │   └── Check: patterns/mev-patterns.md#front-running
│   │
│   ├── [F2] Order Book Spoofing
│   │   ├── Condition: Order book visible
│   │   ├── Action: Place and cancel orders
│   │   ├── Result: Mislead other traders
│   │   └── Check: patterns/perpetuals-patterns.md#spoofing
│   │
│   ├── [F3] Keeper/Relayer Manipulation
│   │   ├── Condition: Orders executed by keepers
│   │   ├── Action: Bribe or become keeper
│   │   ├── Result: Prioritize own orders
│   │   └── Check: patterns/perpetuals-patterns.md#keeper
│   │
│   ├── [F4] Limit Order Exploitation
│   │   ├── Condition: Limit orders at known prices
│   │   ├── Action: Manipulate price to trigger limits
│   │   ├── Result: Force unfavorable execution
│   │   └── Check: patterns/perpetuals-patterns.md#limit-orders
│   │
│   ├── [F5] Stop-Loss Hunting
│   │   ├── Condition: Stop-losses at predictable levels
│   │   ├── Action: Push price to trigger stops
│   │   ├── Result: Force exits at bad prices
│   │   └── Check: patterns/perpetuals-patterns.md#stop-hunting
│   │
│   └── [F6] Execution Price Manipulation
│       ├── Condition: Execution price calculable
│       ├── Action: Sandwich execution
│       ├── Result: Worse execution for victims
│       └── Check: patterns/mev-patterns.md#sandwich
│
└── [G] Systemic/Protocol Attacks
    │
    ├── [G1] Insurance Fund Drain
    │   ├── Condition: Insurance fund finite
    │   ├── Action: Create maximum losses
    │   ├── Result: Deplete insurance, cause socialized loss
    │   └── Check: patterns/perpetuals-patterns.md#insurance
    │
    ├── [G2] Open Interest Manipulation
    │   ├── Condition: OI affects protocol mechanics
    │   ├── Action: Inflate OI artificially
    │   ├── Result: Manipulate funding/fees
    │   └── Check: patterns/perpetuals-patterns.md#oi
    │
    ├── [G3] Market Creation Attack
    │   ├── Condition: Permissionless market creation
    │   ├── Action: Create manipulatable markets
    │   ├── Result: Exploit low-liquidity markets
    │   └── Check: patterns/perpetuals-patterns.md#market-creation
    │
    ├── [G4] Cross-Market Arbitrage
    │   ├── Condition: Multiple markets with same underlying
    │   ├── Action: Arbitrage price differences
    │   ├── Result: Extract value at protocol expense
    │   └── Check: patterns/perpetuals-patterns.md#cross-market
    │
    └── [G5] Governance Attack on Parameters
        ├── Condition: Governance controls risk parameters
        ├── Action: Vote to change max leverage, liquidation threshold
        ├── Result: Create exploitable conditions
        └── Check: patterns/governance-patterns.md#perp-params
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify perp type** - Order book, AMM (GMX-style), vAMM (Perp v1)
2. **Check oracle** - Chainlink, TWAP, Multi-source, Keepers
3. **Analyze liquidation** - Threshold, Penalty, Insurance, ADL
4. **Review funding** - Calculation, Frequency, Bounds
5. **Test position** - Leverage limits, Margin modes, PnL accounting

---

## Quick Reference by Protocol Type

### Order Book Perps (dYdX-style)
**Critical Vulnerabilities:**
- [F1] Front-running orders (Critical)
- [F2] Order book spoofing (High)
- [A3] Oracle front-running (Critical)

**Examples:** dYdX, Hyperliquid, Vertex

### AMM-based Perps (GMX-style)
**Critical Vulnerabilities:**
- [E2] Liquidity extraction (Critical)
- [A1] Index price manipulation (Critical)
- [E1] LP token manipulation (High)

**Examples:** GMX, GNS, MUX

### vAMM Perps (Perp Protocol-style)
**Critical Vulnerabilities:**
- [D1] Position size manipulation (Critical)
- [B1] Funding rate manipulation (High)
- [A2] Mark price manipulation (High)

**Examples:** Perp Protocol, Drift

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Mango Markets | 2022 | $114M | [D1] + [A1] | Position size + oracle manipulation |
| GMX Price Manipulation | 2022 | $565K | [A1] | AVAX price manipulation |
| Perp Protocol v2 | 2022 | $1M+ | [B1] | Funding rate manipulation |
| dYdX Flash Loan | 2022 | N/A | [A4] | Oracle delay exploitation |
| Gains Network | 2023 | $200K | [A3] | Oracle front-running |

---

## Checklist (Copy for Audit)

```markdown
## Perpetuals Attack Surface

### Oracle [A]
- [ ] [A1] Index price manipulation resistant
- [ ] [A2] Mark price calculation secure
- [ ] [A3] Oracle front-running prevented
- [ ] [A4] Oracle delay handled
- [ ] [A5] Multi-asset oracle consistency
- [ ] [A6] Extreme volatility handling

### Funding Rate [B]
- [ ] [B1] Funding manipulation prevented
- [ ] [B2] Funding rate bounds exist
- [ ] [B3] Cross-protocol arbitrage considered
- [ ] [B4] Funding griefing mitigated
- [ ] [B5] Settlement price manipulation prevented

### Liquidation [C]
- [ ] [C1] Forced liquidation resistant
- [ ] [C2] Liquidation cascade circuit breakers
- [ ] [C3] Liquidation incentives fair
- [ ] [C4] Partial liquidation correct
- [ ] [C5] Liquidation penalty reasonable
- [ ] [C6] ADL fair and transparent
- [ ] [C7] Bankruptcy handling correct

### Position [D]
- [ ] [D1] Position limits enforced
- [ ] [D2] Leverage calculation precise
- [ ] [D3] Cross-margin secure
- [ ] [D4] Margin mode switching restricted
- [ ] [D5] PnL accounting correct
- [ ] [D6] Hedge mode rules enforced

### Liquidity Pool [E]
- [ ] [E1] LP token price manipulation resistant
- [ ] [E2] Liquidity extraction prevented
- [ ] [E3] Vault share inflation prevented
- [ ] [E4] Utilization gaming mitigated
- [ ] [E5] JIT liquidity protected against

### Order Execution [F]
- [ ] [F1] Front-running mitigated
- [ ] [F2] Spoofing prevented
- [ ] [F3] Keeper/relayer trustless
- [ ] [F4] Limit orders secure
- [ ] [F5] Stop-loss hunting mitigated
- [ ] [F6] Execution price fair

### Systemic [G]
- [ ] [G1] Insurance fund adequate
- [ ] [G2] OI limits exist
- [ ] [G3] Market creation permissioned
- [ ] [G4] Cross-market risks considered
- [ ] [G5] Governance attack resistant
```

---

## Protocol-Specific Considerations

### GMX
- GLP pool as counterparty - check extraction attacks
- Multi-asset oracle - check consistency
- Position limits per asset - check bypass

### dYdX
- Order book model - check front-running
- StarkWare L2 - check bridge security
- Professional liquidity - check manipulation

### Perpetual Protocol
- vAMM model - check price impact
- Funding rate mechanics - check manipulation
- Insurance fund - check adequacy

### Gains Network
- Synthetic pricing - check oracle security
- High leverage - check liquidation cascade
- NFT positions - check accounting

---

## See Also

- **Patterns:** [perpetuals-patterns.md](../patterns/perpetuals-patterns.md)
- **Oracle Patterns:** [oracle-patterns.md](../patterns/oracle-patterns.md)
- **Liquidation:** [liquidation-patterns.md](../patterns/liquidation-patterns.md)
- **Related:** [dex-attack-tree.md](./dex-attack-tree.md)

---

**Last Updated:** 2025
**Version:** 1.0
