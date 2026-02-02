# YAML Frontmatter Schema Standard

> Metadata architecture enabling queryable, machine-readable security knowledge

---

## Overview

Every markdown file in this repository uses YAML frontmatter to enable:
- AI-powered semantic queries
- Automated cross-referencing
- Dynamic statistics generation
- Difficulty-based learning paths
- Protocol/chain-specific filtering

---

## Schema Definition

### Pattern Files

```yaml
---
id: PAT-REENTRANCY-001
title: Classic Single-Function Reentrancy
category: reentrancy
subcategory: classic
severity: critical
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
protocols:
  - lending
  - dex
  - vaults
tags:
  - external-call
  - state-update
  - cei-pattern
difficulty: intermediate
prerequisites:
  - solidity-basics
  - external-calls
related_patterns:
  - cross-function-reentrancy
  - cross-contract-reentrancy
  - read-only-reentrancy
related_exploits:
  - the-dao-2016
  - cream-finance-2021
defenses:
  - reentrancy-guard
  - checks-effects-interactions
  - pull-payment
finding_count: 59
last_updated: 2026-01-31
---
```

### Exploit Forensics Files

```yaml
---
id: EXP-2022-WORMHOLE
title: Wormhole Bridge Exploit
date: 2022-02-02
loss_usd: 325000000
chain: solana
attack_type:
  - signature-verification
  - bridge
  - cross-chain
attacker_address: "0x..."
transactions:
  - tx_hash: "2zCz8E..."
    action: setup
  - tx_hash: "9kWvFg..."
    action: exploit
  - tx_hash: "4mNpQr..."
    action: extraction
assets_stolen:
  - asset: ETH
    amount: 93750
    usd_value: 280000000
  - asset: wBTC
    amount: 432
    usd_value: 18000000
detection_time_minutes: 47
root_cause: deprecated-secp256k1-instruction
related_patterns:
  - signature-verification
  - bridge-security
post_mortem_link: "https://..."
last_updated: 2026-01-31
---
```

### Protocol Playbook Files

```yaml
---
id: PLAY-UNISWAP-V3
title: Uniswap V3 Secure Integration Guide
protocol: uniswap
version: v3
category: dex
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - base
integration_type:
  - swap
  - liquidity
  - oracle
common_mistakes:
  - slippage-not-set
  - deadline-not-enforced
  - price-manipulation
  - callback-reentrancy
secure_patterns:
  - exact-input-single
  - twap-oracle
  - deadline-validation
difficulty: advanced
prerequisites:
  - defi-basics
  - amm-mechanics
  - oracle-patterns
audit_checklist_items: 15
last_updated: 2026-01-31
---
```

### Evolution Timeline Files

```yaml
---
id: EVO-REENTRANCY
title: Reentrancy Vulnerability Evolution
vulnerability_type: reentrancy
timeline_start: 2016
timeline_end: 2026
major_exploits:
  - year: 2016
    name: The DAO
    loss: 60000000
    type: classic
  - year: 2020
    name: Lendf.Me
    loss: 25000000
    type: erc777
  - year: 2022
    name: Rari Capital
    loss: 80000000
    type: cross-contract
defense_evolution:
  - year: 2016
    defense: checks-effects-interactions
  - year: 2017
    defense: reentrancy-guard
  - year: 2022
    defense: read-only-locks
current_threat_level: medium
emerging_vectors:
  - cross-chain-callbacks
  - restaking-hooks
last_updated: 2026-01-31
---
```

### Learning Path Files

```yaml
---
id: LEARN-BEGINNER-01
title: Introduction to Smart Contract Security
difficulty: beginner
order: 1
estimated_hours: 4
prerequisites: []
learning_objectives:
  - understand-common-vulnerabilities
  - read-solidity-code
  - identify-red-flags
topics:
  - what-is-an-audit
  - common-vulnerability-types
  - reading-smart-contracts
exercises:
  - exercise: find-the-bug-1
    difficulty: easy
  - exercise: find-the-bug-2
    difficulty: easy
next_steps:
  - beginner-02-access-control
  - beginner-03-validation
assessment_available: true
last_updated: 2026-01-31
---
```

### Scanner Files

```yaml
---
id: SCAN-SOLANA
title: Solana Security Scanner
language: rust
framework: anchor
chain: solana
security_model: account-based
unique_risks:
  - account-validation
  - pda-seeds
  - cpi-vulnerabilities
  - signer-authorization
patterns_count: 45
checklist_items: 32
tools:
  - soteria
  - anchor-verify
related_scanners:
  - move-scanner
  - cosmwasm-scanner
last_updated: 2026-01-31
---
```

---

## Field Definitions

### Core Fields (Required)

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (PREFIX-NAME-NUMBER) |
| `title` | string | Human-readable title |
| `category` | string | Primary category |
| `last_updated` | date | Last modification date |

### Classification Fields

| Field | Type | Values |
|-------|------|--------|
| `severity` | string | critical, high, medium, low, informational, gas |
| `difficulty` | string | beginner, intermediate, advanced, expert |
| `chains` | array | ethereum, arbitrum, optimism, polygon, bsc, solana, sui, aptos, etc. |

### Relationship Fields

| Field | Type | Description |
|-------|------|-------------|
| `prerequisites` | array | Required knowledge before this content |
| `related_patterns` | array | Links to related pattern IDs |
| `related_exploits` | array | Links to related exploit IDs |
| `defenses` | array | Mitigation strategies |
| `next_steps` | array | Recommended follow-up content |

### Metrics Fields

| Field | Type | Description |
|-------|------|-------------|
| `finding_count` | number | Number of findings in this category |
| `loss_usd` | number | Financial loss in USD |
| `estimated_hours` | number | Learning time estimate |

---

## ID Prefixes

| Prefix | Content Type | Example |
|--------|--------------|---------|
| `PAT` | Pattern | PAT-REENTRANCY-001 |
| `EXP` | Exploit Forensics | EXP-2022-WORMHOLE |
| `PLAY` | Protocol Playbook | PLAY-UNISWAP-V3 |
| `EVO` | Evolution Timeline | EVO-REENTRANCY |
| `LEARN` | Learning Path | LEARN-BEGINNER-01 |
| `SCAN` | Scanner | SCAN-SOLANA |
| `CHECK` | Checklist | CHECK-DEFI-AUDIT |
| `DEF` | Defense | DEF-REENTRANCY-GUARD |

---

## Query Examples

### Find all HIGH severity reentrancy patterns
```
category: reentrancy AND severity: high
```

### Find patterns affecting Arbitrum
```
chains: arbitrum
```

### Find prerequisites for flash loan attacks
```
id: PAT-FLASH-LOAN-* -> prerequisites
```

### Find all exploits in 2023
```
id: EXP-2023-*
```

### Find beginner learning content
```
difficulty: beginner AND id: LEARN-*
```

### Find all oracle-related content
```
tags: oracle OR category: oracle OR related_patterns: oracle-*
```

---

## Validation Rules

1. **IDs must be unique** across all files
2. **Dates** use ISO 8601 format (YYYY-MM-DD)
3. **Arrays** must have at least one element if present
4. **References** must point to valid IDs
5. **Severity** must match allowed values
6. **Difficulty** must match allowed values
7. **Chains** must be from approved list

---

## Implementation Notes

### Adding Frontmatter to Existing Files

Frontmatter is added at the very beginning of the file:

```markdown
---
id: PAT-REENTRANCY-001
title: Reentrancy Security Patterns
category: reentrancy
...
---

# Reentrancy Security Patterns

[Rest of existing content...]
```

### Backward Compatibility

Files without frontmatter will still render correctly. The frontmatter is invisible in rendered markdown but parseable by tools.

### Tooling

- **Parser**: Use `gray-matter` (Node.js) or `python-frontmatter` to extract metadata
- **Validation**: JSON Schema validation against this specification
- **Indexing**: Build search index from extracted frontmatter
