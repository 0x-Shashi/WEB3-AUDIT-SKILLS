# API Integration Skill

## Quick Start

This folder contains everything needed to interact with the Cyfrin Solodit API - the world's largest database of blockchain security findings with 50,000+ vulnerabilities.

**Base URL:** `https://solodit.cyfrin.io/api/v1/solodit`  
**Primary Endpoint:** `/findings`  
**Method:** `POST`  
**Rate Limit:** 20 requests per 60 seconds

## Setup

### 1. Get Your API Key

1. Create an account at [solodit.cyfrin.io](https://solodit.cyfrin.io)
2. Click your profile dropdown in the top right corner
3. Open "API Keys" modal and generate a new API key

### 2. Set Environment Variable

```bash
export CYFRIN_API_KEY="sk_your_api_key_here"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

For Windows PowerShell:
```powershell
$env:CYFRIN_API_KEY = "sk_your_api_key_here"
# For persistence, add to your PowerShell profile
```

## Authentication

All requests require the `X-Cyfrin-API-Key` header:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 10}'
```

## Sub-Skills in This Folder

| File | Purpose |
|------|---------|
| [query-construction.md](query-construction.md) | How to build effective API queries with all filter parameters |
| [filter-strategies.md](filter-strategies.md) | Strategic approaches to filtering for optimal results |
| [response-parsing.md](response-parsing.md) | Understanding and extracting insights from API responses |
| [rate-limiting.md](rate-limiting.md) | Managing rate limits, caching, and optimization |

## When to Use This Skill

**Use this skill when:**
- User needs to query the Solodit database directly
- Building automated security scanning workflows
- Integrating vulnerability data into development pipelines
- Debugging API issues or optimizing queries

**Triggers for Claude:**
- "Query Solodit for..." → Use query-construction.md
- "Find vulnerabilities related to..." → Use filter-strategies.md
- "Parse the response..." → Use response-parsing.md
- "API is slow/rate limited..." → Use rate-limiting.md

## Complete API Request Structure

```json
{
  "page": 1,
  "pageSize": 50,
  "filters": {
    "keywords": "string",
    "impact": ["HIGH", "MEDIUM", "LOW", "GAS"],
    "firms": [{"value": "Cyfrin"}],
    "tags": [{"value": "Reentrancy"}],
    "protocol": "string",
    "protocolCategory": [{"value": "DeFi"}],
    "languages": [{"value": "Solidity"}],
    "user": "string",
    "minFinders": "string",
    "maxFinders": "string",
    "reported": {"value": "30"},
    "qualityScore": 3,
    "rarityScore": 3,
    "sortField": "Recency",
    "sortDirection": "Desc"
  }
}
```

## Response Structure

```json
{
  "findings": [...],
  "metadata": {
    "totalResults": 50000,
    "currentPage": 1,
    "pageSize": 50,
    "totalPages": 1000,
    "elapsed": 0.123
  },
  "rateLimit": {
    "limit": 20,
    "remaining": 19,
    "reset": 1706400000
  }
}
```

## Error Handling

| Status | Meaning | Action |
|--------|---------|--------|
| 400 | Invalid request parameters | Check query structure |
| 401 | Missing or invalid API key | Verify CYFRIN_API_KEY |
| 429 | Rate limit exceeded | Wait and retry with backoff |

## Test This Skill

Run this minimal query to verify your setup:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 1}'
```

**Expected Response:**
- Status: 200 OK
- Body contains `findings` array with 1 item
- `metadata.totalResults` shows total findings count (50,000+)
- `rateLimit.remaining` shows remaining API calls

## Common Patterns

### Pattern 1: Basic Security Check
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "your-function-name",
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Pattern 2: High-Quality Findings Only
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "qualityScore": 4,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

### Pattern 3: Recent Critical Issues
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "impact": ["HIGH"],
      "reported": {"value": "30"},
      "sortField": "Recency"
    }
  }'
```

## Cross-Reference

- For vulnerability-specific queries → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For protocol-specific queries → See [../protocol-categories/SKILL.md](../protocol-categories/SKILL.md)
- For audit firm filtering → See [../audit-firms/SKILL.md](../audit-firms/SKILL.md)
- For workflow integration → See [../workflows/SKILL.md](../workflows/SKILL.md)
