---
name: protocol-templates
description: "Deep specialized patterns for auditing specific protocol types. Load after context detection identifies the protocol type."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Protocol Templates Skill

## Purpose

Provide specialized, deep audit patterns for specific protocol types. These go beyond generic patterns to cover protocol-specific attack vectors.

---

## Available Templates

| Template | Protocol Type | Focus Areas |
|----------|--------------|-------------|
| amm-dex-template | AMM/DEX | Swap, liquidity, slippage |
| lending-template | Lending | Collateral, liquidation, interest |
| bridge-template | Cross-chain | Message passing, finality |
| staking-template | Staking | Rewards, slashing, delegation |
| nft-marketplace-template | NFT | Royalties, escrow, bidding |

---

## When to Use

1. After context-detection identifies protocol type
2. When auditing a known protocol fork
3. When deep-diving into specific functionality

---

## Template Structure

Each template contains:

```
template-name.md
 Architecture Overview
 Critical Functions
 Common Vulnerabilities
 Real Exploit Examples
 Audit Checklist
 Detection Commands
```

---

## Loading Templates

Based on context detection output:

```yaml
protocol:
  type: "lending"
  similar_to: ["Aave", "Compound"]
```

Load: `lending-template.md`

---

## Cross-Template Considerations

Some protocols combine multiple types:

| Combined Protocol | Templates to Load |
|------------------|-------------------|
| DEX + Lending | amm-dex + lending |
| Bridge + Staking | bridge + staking |
| NFT + DeFi | nft-marketplace + amm-dex |

---

## Template Usage Flow

```
1. Run context-detection
2. Identify primary protocol type
3. Load primary template
4. Check for secondary types
5. Load additional templates
6. Apply combined audit approach
```
