# Protocol Categories Skill

## Quick Start

This folder contains security guidance specific to each protocol category. Different protocol types have different risk profiles, common vulnerabilities, and security considerations.

## Complete Category List

| Category | Risk Profile | Primary Concerns |
|----------|--------------|------------------|
| [DeFi](defi.md) | HIGH | Price manipulation, flash loans, reentrancy |
| [Lending](lending.md) | HIGH | Oracle attacks, liquidation logic, collateral |
| [DEX](dex.md) | HIGH | Front-running, price manipulation, slippage |
| [NFT](nft.md) | MEDIUM | Access control, royalties, metadata |
| [Staking](staking.md) | MEDIUM-HIGH | Reward calculation, withdrawal logic |
| [Governance](governance.md) | MEDIUM-HIGH | Vote manipulation, timelocks, flash loans |
| [Bridge](bridge.md) | CRITICAL | Message verification, replay attacks |
| [Yield Aggregator](yield-aggregator.md) | HIGH | Strategy risks, composability |
| [Options](options.md) | HIGH | Pricing, exercise logic, settlement |
| [Oracles](oracles.md) | HIGH | Data freshness, manipulation resistance |

## Category Risk Matrix

```
                     COMPLEXITY
           Low ─────────────────────► High
      │
  Low │  Basic Token    │   GameFi
      │  Simple NFT     │   Complex NFT
RISK  │─────────────────┼─────────────────
      │  Staking        │   Lending
 High │  Governance     │   DEX/AMM
      │                 │   Bridges
      ▼                 │   Yield Aggregators
```

## How to Query by Category

### Single Category

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Multiple Categories

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": [
        {"value": "DeFi"},
        {"value": "Lending"}
      ],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Category + Tags

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "tags": [{"value": "Oracle"}],
      "impact": ["HIGH"]
    }
  }'
```

## Available Categories in Solodit

Based on the API, these categories are available:

- DeFi
- NFT
- NFT Marketplace
- Lending
- NFT Lending
- DEX
- Staking
- Liquid Staking
- Governance
- DAO
- Bridge
- Cross-Chain
- Yield Aggregator
- Options
- Options Vault
- Oracles
- Gaming
- RWA (Real World Assets)

## Decision Matrix: Feature → Category

| Building Feature | Consult Category |
|-----------------|------------------|
| Token swapping | DEX |
| Borrowing/lending | Lending |
| NFT minting | NFT |
| Yield farming | Yield Aggregator, DeFi |
| Staking rewards | Staking |
| Voting system | Governance |
| Cross-chain transfers | Bridge |
| Options/derivatives | Options |
| Price feeds | Oracles |

## Cross-Category Vulnerabilities

Some vulnerabilities span multiple categories:

| Vulnerability | Affected Categories |
|---------------|---------------------|
| Oracle manipulation | Lending, DEX, Options |
| Flash loan attacks | Lending, DEX, Governance |
| Reentrancy | All |
| Access control | All |
| Price manipulation | Lending, DEX, Yield |

## Workflow for Category Research

1. **Identify your category**
   ```bash
   # Get HIGH findings for your category
   curl -X POST ... -d '{"filters": {"protocolCategory": [{"value": "YourCategory"}], "impact": ["HIGH"]}}'
   ```

2. **Identify common tags**
   ```bash
   # See what vulnerability types are common
   # Parse response for issues_issuetagscore
   ```

3. **Deep dive on top vulnerabilities**
   ```bash
   # Query specific tags found in step 2
   curl -X POST ... -d '{"filters": {"protocolCategory": [...], "tags": [...]}}'
   ```

4. **Build security checklist**
   - Extract patterns from findings
   - Create mitigation list

## Test This Skill

```bash
# Get category-specific findings
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, tags: [.issues_issuetagscore[]?.tags_tag.title]}'
```

## Cross-Reference

- For vulnerability types → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For language-specific → See [../languages/SKILL.md](../languages/SKILL.md)
- For audit workflows → See [../workflows/SKILL.md](../workflows/SKILL.md)
