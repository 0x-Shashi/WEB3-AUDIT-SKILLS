# Query Construction

## Quick Start

This guide covers how to build effective API queries for the Cyfrin Solodit API. Master these patterns to extract precise security insights from 50,000+ audit findings.

## Base Query Structure

Every query follows this structure:

```json
{
  "page": 1,
  "pageSize": 50,
  "filters": {
    // Your filters here
  }
}
```

**Required Fields:**
- `page`: Page number (default: 1, minimum: 1)
- `pageSize`: Results per page (default: 50, maximum: 100)

**Optional:** The entire `filters` object is optional. Without filters, you get all findings sorted by recency.

## Complete Filter Parameters

### Text Search

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `keywords` | string | Search in title and content | `"reentrancy attack"` |

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "flash loan oracle"
    }
  }'
```

### Impact Filtering

| Parameter | Type | Options | Default |
|-----------|------|---------|---------|
| `impact` | string[] | `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"GAS"` | All impacts |

```bash
# HIGH severity only
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "impact": ["HIGH"]
    }
  }'
```

```bash
# HIGH and MEDIUM severity
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Audit Firm Filtering

| Parameter | Type | Description |
|-----------|------|-------------|
| `firms` | object[] | Array of `{value: "FirmName"}` objects |

**Available Firms:** Cyfrin, Sherlock, Code4rena, Trail of Bits, OpenZeppelin, Consensys Diligence, Spearbit, Pashov Audit Group, Hacken, ChainSecurity, and more.

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [
        {"value": "Cyfrin"},
        {"value": "Trail of Bits"}
      ]
    }
  }'
```

### Vulnerability Tags

| Parameter | Type | Description |
|-----------|------|-------------|
| `tags` | object[] | Array of `{value: "TagName"}` objects |

**Common Tags:** Reentrancy, Oracle, Access Control, Integer Overflow/Underflow, Front-running, Price Manipulation, Flash Loan, DOS, Logic Error, Griefing

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "tags": [
        {"value": "Reentrancy"},
        {"value": "Flash Loan"}
      ],
      "impact": ["HIGH"]
    }
  }'
```

### Protocol Filtering

| Parameter | Type | Description |
|-----------|------|-------------|
| `protocol` | string | Protocol name (partial match) |
| `protocolCategory` | object[] | Array of `{value: "Category"}` objects |

**Categories:** DeFi, NFT, NFT Marketplace, Lending, NFT Lending, DEX, Staking, Liquid Staking, Governance, DAO, Bridge, Cross-Chain, Yield Aggregator, Options, Options Vault, Oracles, Gaming, RWA

```bash
# Filter by protocol name
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "protocol": "Uniswap"
    }
  }'
```

```bash
# Filter by protocol category
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}, {"value": "Lending"}]
    }
  }'
```

### Programming Language

| Parameter | Type | Description |
|-----------|------|-------------|
| `languages` | object[] | Array of `{value: "Language"}` objects |

**Available Languages:** Solidity, Rust, Cairo, Vyper, Move, Huff, Fe, Ink!

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "languages": [{"value": "Rust"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Finder (Auditor) Filtering

| Parameter | Type | Description |
|-----------|------|-------------|
| `user` | string | Finder/auditor handle (partial match) |
| `minFinders` | string | Minimum number of finders |
| `maxFinders` | string | Maximum number of finders |

```bash
# Findings discovered by a single auditor (unique finds)
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "maxFinders": "1",
      "impact": ["HIGH"]
    }
  }'
```

### Date Filtering

| Parameter | Type | Options |
|-----------|------|---------|
| `reported` | object | `{value: "30"}`, `{value: "60"}`, `{value: "90"}`, `{value: "after"}`, `{value: "alltime"}` |
| `reportedAfter` | string | ISO date string (used when `reported.value = "after"`) |

```bash
# Last 30 days
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "reported": {"value": "30"}
    }
  }'
```

```bash
# After specific date
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "reported": {"value": "after"},
      "reportedAfter": "2025-01-01"
    }
  }'
```

### Quality and Rarity Scoring

| Parameter | Type | Range | Default | Description |
|-----------|------|-------|---------|-------------|
| `qualityScore` | number | 0-5 | 1 | Minimum quality score |
| `rarityScore` | number | 0-5 | 1 | Minimum rarity score |

```bash
# High-quality findings only (score >= 4)
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "qualityScore": 4,
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Sorting

| Parameter | Type | Options | Default |
|-----------|------|---------|---------|
| `sortField` | string | `"Recency"`, `"Quality"`, `"Rarity"` | `"Recency"` |
| `sortDirection` | string | `"Desc"`, `"Asc"` | `"Desc"` |

```bash
# Sort by quality, highest first
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

```bash
# Sort by rarity (unique finds first)
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "sortField": "Rarity",
      "sortDirection": "Desc"
    }
  }'
```

## Combining Multiple Filters

Filters are combined with AND logic. Here's a comprehensive example:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "keywords": "oracle manipulation",
      "impact": ["HIGH"],
      "firms": [{"value": "Cyfrin"}, {"value": "Sherlock"}],
      "tags": [{"value": "Oracle"}, {"value": "Price Manipulation"}],
      "protocolCategory": [{"value": "DeFi"}],
      "languages": [{"value": "Solidity"}],
      "reported": {"value": "90"},
      "qualityScore": 3,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

## Pagination for Large Result Sets

```bash
# Get page 1
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-KEY: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 100, "filters": {"impact": ["HIGH"]}}'

# Get page 2
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 2, "pageSize": 100, "filters": {"impact": ["HIGH"]}}'
```

## When to Use Which Parameters

| User Intent | Recommended Filters |
|-------------|---------------------|
| "Check my swap function" | `keywords: "swap"`, `tags: ["Reentrancy", "Price Manipulation"]` |
| "DeFi security best practices" | `protocolCategory: ["DeFi"]`, `qualityScore: 4`, `sortField: "Quality"` |
| "Recent critical bugs" | `impact: ["HIGH"]`, `reported: {"value": "30"}`, `sortField: "Recency"` |
| "Learn from top auditors" | `firms: [{"value": "Trail of Bits"}]`, `qualityScore: 4` |
| "Unique/rare findings" | `sortField: "Rarity"`, `maxFinders: "1"` |
| "Oracle issues in lending" | `tags: ["Oracle"]`, `protocolCategory: ["Lending"]` |

## Test This Query

Verify your query construction with this comprehensive test:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

**Expected Response:**
- 5 HIGH severity findings
- All with quality_score >= 4
- Sorted by quality (highest first)
- `metadata.totalResults` shows total matching findings

## Common Mistakes

1. **Wrong array format for firms/tags:**
   - ❌ `"firms": ["Cyfrin"]`
   - ✅ `"firms": [{"value": "Cyfrin"}]`

2. **Wrong impact format:**
   - ❌ `"impact": "HIGH"`
   - ✅ `"impact": ["HIGH"]`

3. **Exceeding pageSize limit:**
   - ❌ `"pageSize": 200`
   - ✅ `"pageSize": 100` (maximum)

4. **Wrong date filter format:**
   - ❌ `"reported": "30"`
   - ✅ `"reported": {"value": "30"}`

## Checklist for Query Construction

- [ ] Set appropriate `page` and `pageSize`
- [ ] Use correct array format for `firms`, `tags`, `protocolCategory`, `languages`
- [ ] Use correct object format for `reported`
- [ ] Set `qualityScore` >= 3 for production-relevant findings
- [ ] Choose appropriate `sortField` for your use case
- [ ] Combine filters with AND logic in mind
- [ ] Check rate limit headers in response
