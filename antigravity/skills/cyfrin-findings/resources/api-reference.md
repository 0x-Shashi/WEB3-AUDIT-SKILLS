# Cyfrin Solodit API Reference

## Overview

The Cyfrin Solodit API provides access to 50,000+ smart contract security findings from professional audits, bug bounties, and security contests.

---

## Authentication

### API Key Setup

1. Create account at [solodit.cyfrin.io](https://solodit.cyfrin.io)
2. Click profile dropdown → "API Keys"
3. Generate new API key

### Environment Variable

**Linux/macOS:**
```bash
export CYFRIN_API_KEY="sk_your_api_key_here"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

**Windows PowerShell:**
```powershell
$env:CYFRIN_API_KEY = "sk_your_api_key_here"
# Add to $PROFILE for persistence
```

**Windows Command Prompt:**
```cmd
set CYFRIN_API_KEY=sk_your_api_key_here
# Use setx for persistence
```

### Header Format

```http
X-Cyfrin-API-Key: sk_your_api_key_here
```

---

## Endpoints

### POST /findings

Query the security findings database.

**URL:** `https://solodit.cyfrin.io/api/v1/solodit/findings`

**Method:** `POST`

**Headers:**
```http
Content-Type: application/json
X-Cyfrin-API-Key: $CYFRIN_API_KEY
```

---

## Request Schema

```json
{
  "page": 1,
  "pageSize": 50,
  "filters": {
    "keywords": "string",
    "impact": ["HIGH", "MEDIUM", "LOW", "GAS"],
    "firms": ["string"],
    "tags": ["string"],
    "protocolCategory": ["string"],
    "languages": ["string"],
    "qualityScore": 0,
    "sortField": "Recency"
  }
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `page` | integer | No | 1 | Page number (min: 1) |
| `pageSize` | integer | No | 50 | Results per page (max: 100) |
| `filters` | object | No | {} | Filter criteria |

### Filter Parameters

| Filter | Type | Options | Description |
|--------|------|---------|-------------|
| `keywords` | string | - | Full-text search in title and content |
| `impact` | array | `HIGH`, `MEDIUM`, `LOW`, `GAS` | Severity levels |
| `firms` | array | Audit firm names | Filter by source firm |
| `tags` | array | Tag slugs | Vulnerability type tags |
| `protocolCategory` | array | Category names | Protocol type |
| `languages` | array | Language names | Programming language |
| `qualityScore` | integer | 0-5 | Minimum quality score |
| `sortField` | string | `Recency`, `Quality`, `Rarity` | Sort order |

---

## Available Values

### Impact Levels

| Value | Description |
|-------|-------------|
| `HIGH` | Critical vulnerabilities, direct fund loss |
| `MEDIUM` | Significant issues, conditional impact |
| `LOW` | Minor issues, limited impact |
| `GAS` | Gas optimization suggestions |

### Protocol Categories

```
DeFi, Lending, DEX, Staking, Governance, Bridge, 
NFT, Yield Aggregator, Options, Oracles, Gaming,
Infrastructure, Wallet, DAO, Insurance
```

### Languages

```
Solidity, Rust, Cairo, Vyper, Move, Go, 
TypeScript, JavaScript, Python
```

### Common Tags

```
reentrancy, oracle, access-control, integer-overflow,
front-running, price-manipulation, flash-loan, dos,
logic-error, griefing, storage, delegatecall,
signature, timestamp, randomness, upgrade
```

### Sort Fields

| Value | Description |
|-------|-------------|
| `Recency` | Most recent first (default) |
| `Quality` | Highest quality score first |
| `Rarity` | Most unique/rare patterns first |

---

## Response Schema

```json
{
  "findings": [
    {
      "id": "string",
      "title": "string",
      "content": "string (markdown)",
      "summary": "string",
      "impact": "HIGH|MEDIUM|LOW|GAS",
      "quality_score": 0,
      "general_score": 0,
      "firm_name": "string",
      "protocol_name": "string",
      "report_url": "string",
      "report_date": "2024-01-01",
      "issues_issuetagscore": [
        {
          "tags_tag": {
            "title": "string",
            "slug": "string"
          },
          "score": 0
        }
      ]
    }
  ],
  "metadata": {
    "totalResults": 0,
    "currentPage": 1,
    "pageSize": 50,
    "totalPages": 0
  },
  "rateLimit": {
    "limit": 20,
    "remaining": 19,
    "reset": 1706400060
  }
}
```

### Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier |
| `title` | string | Vulnerability title/summary |
| `content` | string | Full description (markdown) |
| `summary` | string | AI-generated summary |
| `impact` | string | Severity level |
| `quality_score` | integer | Quality rating (0-5) |
| `general_score` | integer | Rarity/uniqueness (0-5) |
| `firm_name` | string | Audit firm name |
| `protocol_name` | string | Affected protocol |
| `report_url` | string | Original report URL |
| `report_date` | string | Date (YYYY-MM-DD) |
| `issues_issuetagscore` | array | Associated tags with scores |

### Metadata Fields

| Field | Description |
|-------|-------------|
| `totalResults` | Total matching findings |
| `currentPage` | Current page number |
| `pageSize` | Results per page |
| `totalPages` | Total available pages |

### Rate Limit Fields

| Field | Description |
|-------|-------------|
| `limit` | Requests per window (20) |
| `remaining` | Requests left in window |
| `reset` | Unix timestamp for window reset |

---

## Example Requests

### Basic Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10
  }'
```

### Keyword Search

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "reentrancy external call"
    }
  }'
```

### High Severity + Category

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "impact": ["HIGH"],
      "protocolCategory": ["Lending"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Multiple Filters

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "keywords": "oracle price",
      "impact": ["HIGH", "MEDIUM"],
      "languages": ["Solidity"],
      "tags": ["oracle", "price-manipulation"],
      "qualityScore": 3,
      "sortField": "Recency"
    }
  }'
```

---

## Error Responses

### 401 Unauthorized

```json
{
  "error": "Invalid or missing API key"
}
```

**Solution:** Check `X-Cyfrin-API-Key` header.

### 429 Too Many Requests

```json
{
  "error": "Rate limit exceeded",
  "retryAfter": 45
}
```

**Solution:** Wait for `retryAfter` seconds.

### 400 Bad Request

```json
{
  "error": "Invalid request parameters",
  "details": "pageSize must be between 1 and 100"
}
```

**Solution:** Validate request parameters.

---

## Rate Limits

| Limit | Value |
|-------|-------|
| Requests per window | 20 |
| Window duration | 60 seconds |
| Reset behavior | Rolling window |

### Response Headers

```http
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 15
X-RateLimit-Reset: 1706400060
```

### Best Practices

1. Use maximum `pageSize` (100) to minimize requests
2. Cache responses for repeated queries
3. Implement exponential backoff on 429
4. Check `remaining` before making requests
5. Batch related queries together

---

## Pagination

For large result sets, iterate through pages:

```bash
# Page 1
curl -X POST ... -d '{"page": 1, "pageSize": 100}'

# Check metadata.totalPages
# Continue to page 2, 3, etc.

# Page 2
curl -X POST ... -d '{"page": 2, "pageSize": 100}'
```

**Tip:** Start broad, then narrow with filters rather than paginating through thousands of results.
