---
id: CYFRIN-QUERY-TEMPLATES
title: Query Templates for Solodit API
parent: cyfrin-findings
type: resource
last_updated: 2025-01-31
---

# Query Templates for Cyfrin/Solodit

Ready-to-use query patterns for common smart contract audit research scenarios. All queries use the `GET /findings` endpoint at `https://api.solodit.xyz/findings`.

---

## By Vulnerability Type

### Reentrancy Variants

| Query | Description | Expected Results |
|-------|-------------|------------------|
| `?category=reentrancy&severity=high` | All high-severity reentrancy findings | ~39 findings |
| `?q=cross-function+reentrancy` | Cross-function reentrancy specifically | Subset of reentrancy involving multiple functions |
| `?q=read-only+reentrancy` | Read-only reentrancy (view function manipulation) | Growing category since 2023 |
| `?q=reentrancy+callback+ERC721` | Reentrancy via ERC721 onERC721Received callbacks | Common in NFT protocols |
| `?q=reentrancy+cross-contract` | Cross-contract reentrancy across protocol modules | Complex multi-contract attacks |

### Oracle Attacks

| Query | Description |
|-------|-------------|
| `?category=oracle-manipulation&severity=critical` | Critical oracle manipulation findings |
| `?q=oracle+stale+price` | Stale price feed vulnerabilities (missing freshness checks) |
| `?q=TWAP+manipulation+flash+loan` | TWAP oracle attacks using flash loans |
| `?q=Chainlink+sequencer+L2` | Chainlink sequencer uptime checks on L2 chains |
| `?q=spot+price+manipulation` | Direct spot price manipulation attacks |
| `?q=oracle+decimal+mismatch` | Oracle decimal/precision mismatch issues |

### Access Control

| Query | Description |
|-------|-------------|
| `?category=access-control&severity=critical` | Critical access control failures |
| `?q=unprotected+initialize` | Unprotected initializer functions (proxy pattern) |
| `?q=missing+access+control+admin` | Missing admin function protections |
| `?q=privilege+escalation` | Privilege escalation vulnerabilities |
| `?q=signature+replay` | Signature replay attacks (missing nonce/chainId) |
| `?q=front-run+initialize+proxy` | Front-running unprotected initializers on proxies |

### Flash Loan Attacks

| Query | Description |
|-------|-------------|
| `?q=flash+loan+governance+voting` | Flash loan governance manipulation |
| `?q=flash+loan+oracle+price` | Flash loan-powered oracle manipulation |
| `?q=flash+loan+liquidity+drain` | Flash loan liquidity draining attacks |
| `?q=flash+loan+collateral` | Flash loan collateral manipulation |

### Precision/Rounding

| Query | Description |
|-------|-------------|
| `?q=rounding+direction+favor` | Incorrect rounding direction (should favor protocol) |
| `?q=first+depositor+inflation+attack` | ERC4626 first depositor / share inflation attacks |
| `?q=integer+division+truncation+loss` | Integer division truncation causing value loss |
| `?q=dust+amount+rounding+zero` | Dust amounts rounding to zero |

---

## By Protocol Type

### Lending Protocols

```
# Top attack vectors in lending: oracle manipulation, liquidation logic, interest calculation
?protocol_type=lending&severity=critical&per_page=50
?protocol_type=lending&q=liquidation+threshold
?protocol_type=lending&q=interest+rate+manipulation
?protocol_type=lending&q=collateral+factor+calculation
?protocol_type=lending&q=bad+debt+socialization
?protocol_type=lending&q=borrow+cap+bypass
```

### DEX / AMM Protocols

```
# Top attack vectors in DEXs: slippage, MEV, price manipulation
?protocol_type=dex&severity=high&per_page=50
?protocol_type=dex&q=slippage+protection+bypass
?protocol_type=dex&q=sandwich+attack
?protocol_type=dex&q=concentrated+liquidity+manipulation
?protocol_type=dex&q=swap+fee+calculation+error
?protocol_type=dex&q=pool+imbalance+attack
```

### Bridge Protocols

```
# Top attack vectors in bridges: message verification, replay, finality
?protocol_type=bridge&severity=critical&per_page=50
?protocol_type=bridge&q=message+verification+bypass
?protocol_type=bridge&q=replay+attack+cross-chain
?protocol_type=bridge&q=finality+assumption
?protocol_type=bridge&q=relayer+manipulation
?protocol_type=bridge&q=double+spending+bridge
```

### Yield / Vault Protocols

```
# Top attack vectors in vaults: share inflation, withdrawal logic, strategy manipulation
?protocol_type=yield&severity=high&per_page=50
?protocol_type=yield&q=vault+inflation+first+depositor
?protocol_type=yield&q=withdrawal+queue+manipulation
?protocol_type=yield&q=strategy+migration+loss
?protocol_type=yield&q=harvest+sandwich+attack
?protocol_type=yield&q=reward+distribution+calculation
```

### Governance Protocols

```
# Top attack vectors in governance: flash loan voting, proposal manipulation
?protocol_type=governance&severity=high
?protocol_type=governance&q=flash+loan+voting+power
?protocol_type=governance&q=proposal+execution+bypass
?protocol_type=governance&q=timelock+bypass
?protocol_type=governance&q=quorum+manipulation
```

---

## By Severity Level

```
# Critical findings only — highest impact, typically fund loss
?severity=critical&per_page=100

# High severity — significant impact, exploitable under realistic conditions
?severity=high&per_page=100

# Medium severity — conditional impact or limited scope
?severity=medium&per_page=100

# Low severity — informational or best practice violations
?severity=low&per_page=100
```

---

## Combination Queries (Multi-Filter)

These queries combine multiple filters for precise research:

```
# Critical oracle bugs specifically in lending protocols
?protocol_type=lending&category=oracle-manipulation&severity=critical

# High-severity reentrancy in DeFi protocols on Arbitrum
?category=reentrancy&severity=high&chain=arbitrum

# Bridge replay attacks on Optimism
?protocol_type=bridge&q=replay&chain=optimism

# ERC4626 vault inflation attacks (any severity)
?q=vault+inflation+first+depositor+ERC4626

# All findings for a specific protocol (e.g., Aave)
?protocol=aave&per_page=100&sort=severity_desc

# Recent critical findings (last 6 months)
?severity=critical&date_from=2024-07-01&sort=date_desc

# Comparison: all findings from two different auditors for the same protocol type
?protocol_type=lending&auditor=code4rena&per_page=50
?protocol_type=lending&auditor=sherlock&per_page=50
```

---

## Chain-Specific Queries

```
# Ethereum-specific findings
?chain=ethereum&severity=critical&per_page=50

# Arbitrum — check for L2-specific issues (sequencer, gas pricing)
?chain=arbitrum&severity=high
?chain=arbitrum&q=sequencer+downtime

# Optimism — check for L2 bridge and messaging issues
?chain=optimism&q=cross-domain+message

# Polygon — check for PoS-specific issues
?chain=polygon&q=checkpoint+validation

# BSC — check for chain-specific token behaviors
?chain=bsc&q=token+deflation+fee
```

---

## Bulk Research Patterns

### Download All Findings for a Category (Paginated)

```bash
# Page through all reentrancy findings (59 total at ~50/page = 2 pages)
GET /findings?category=reentrancy&page=1&per_page=50
GET /findings?category=reentrancy&page=2&per_page=50

# For large categories, checkpoint every 50 pages
# Save checkpoint files: checkpoint_page_50.json, checkpoint_page_100.json, etc.
```

### Build a Protocol Threat Model

```bash
# Step 1: Get all findings for the protocol type
GET /findings?protocol_type=lending&per_page=100&page=1

# Step 2: Get severity distribution
# (Parse results, count by severity)

# Step 3: Get top vulnerability categories
# (Parse results, count by category, sort descending)

# Step 4: Get recent findings (freshest attack vectors)
GET /findings?protocol_type=lending&sort=date_desc&per_page=20
```

---

## Tips for Effective Queries

1. **Start broad, then narrow**: Begin with `?protocol_type=lending&severity=critical` before adding more filters
2. **Use free-text `q` for specificity**: The `q` parameter searches across title, description, and impact fields
3. **Combine `category` + `protocol_type`**: This gives you vulnerability-type-specific findings within a protocol class
4. **Check total counts first**: Look at `pagination.total` in the first response to plan your pagination strategy
5. **Sort by severity for triage**: Use `sort=severity_desc` when building audit checklists
6. **Sort by date for trends**: Use `sort=date_desc` to find the latest attack vectors
