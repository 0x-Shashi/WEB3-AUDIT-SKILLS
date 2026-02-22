---
id: CYFRIN-API-REF
title: Solodit API Reference
parent: cyfrin-findings
type: resource
last_updated: 2025-01-31
---

# Cyfrin/Solodit API Reference

## Base URL

```
https://api.solodit.xyz
```

## Authentication

All requests require an API key passed in the request header:

```
X-API-Key: <your-api-key>
```

API keys can be obtained by registering at [solodit.xyz](https://solodit.xyz). Free-tier keys have reduced rate limits; premium keys support higher throughput for bulk research.

---

## Endpoints

### 1. GET /findings

Search and retrieve audit findings with filtering and pagination.

**Query Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `page` | integer | No | 1 | Page number for pagination |
| `per_page` | integer | No | 50 | Results per page (max: 100) |
| `severity` | string | No | all | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `category` | string | No | all | Filter by vulnerability category tag (see `/categories` for full list) |
| `chain` | string | No | all | Filter by blockchain: `ethereum`, `arbitrum`, `optimism`, `polygon`, `bsc`, `avalanche`, `solana` |
| `protocol` | string | No | all | Filter by protocol name (exact or partial match) |
| `protocol_type` | string | No | all | Filter by protocol category: `lending`, `dex`, `bridge`, `yield`, `governance`, `nft`, `stablecoin`, `derivatives` |
| `auditor` | string | No | all | Filter by audit firm name |
| `q` | string | No | — | Free-text search across title, description, and impact fields |
| `date_from` | string | No | — | ISO 8601 date, filter findings after this date |
| `date_to` | string | No | — | ISO 8601 date, filter findings before this date |
| `sort` | string | No | `date_desc` | Sort order: `date_desc`, `date_asc`, `severity_desc`, `severity_asc` |

**Example Request:**

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "https://api.solodit.xyz/findings?severity=critical&category=reentrancy&per_page=20&page=1"
```

**Response Schema:**

```json
{
  "data": [
    {
      "id": "finding-abc123",
      "title": "[H-02] Cross-function reentrancy allows draining of lending pool",
      "severity": "high",
      "description": "The withdraw() function makes an external call to transfer ETH before updating the user's balance, allowing a reentrant call to borrow() which reads the stale balance...",
      "impact": "An attacker can drain the entire lending pool by recursively calling withdraw and borrow in a single transaction.",
      "recommendation": "Apply the checks-effects-interactions pattern. Update the user balance before making the external call. Additionally, add a reentrancy guard modifier.",
      "protocol": "Compound Fork XYZ",
      "protocol_type": "lending",
      "chain": "ethereum",
      "category": "reentrancy",
      "tags": ["external-call", "state-update", "callback", "cei-violation"],
      "date": "2024-03-15",
      "auditor": "Code4rena",
      "url": "https://solodit.xyz/issues/finding-abc123",
      "code_references": [
        {
          "file": "src/LendingPool.sol",
          "line": 142,
          "snippet": "payable(msg.sender).call{value: amount}(\"\");"
        }
      ]
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 59,
    "total_pages": 3
  }
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the finding |
| `title` | string | Finding title (often includes severity tag like [H-02]) |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `info` |
| `description` | string | Detailed explanation of the vulnerability |
| `impact` | string | What an attacker can achieve by exploiting this |
| `recommendation` | string | How to fix the vulnerability |
| `protocol` | string | Name of the audited protocol |
| `protocol_type` | string | Category of the protocol (lending, dex, bridge, etc.) |
| `chain` | string | Target blockchain |
| `category` | string | Primary vulnerability category |
| `tags` | array | Additional tags for cross-referencing |
| `date` | string | Date the finding was published (ISO 8601) |
| `auditor` | string | Audit firm or contest platform |
| `url` | string | Direct link to the finding on Solodit |
| `code_references` | array | Code locations referenced in the finding (may be empty) |

---

### 2. GET /findings/:id

Retrieve complete details of a specific finding by its unique ID.

**Example Request:**

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "https://api.solodit.xyz/findings/finding-abc123"
```

**Response:** Same schema as a single item in the `/findings` response, but may include additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `full_report_url` | string | Link to the complete audit report |
| `related_findings` | array | IDs of related findings in the same audit |
| `status` | string | `confirmed`, `disputed`, `fixed`, `acknowledged` |
| `duplicates` | integer | Number of duplicate submissions (for contest findings) |

---

### 3. GET /protocols

List all protocols that have audit findings indexed in the database.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number |
| `per_page` | integer | Results per page (max: 100) |
| `protocol_type` | string | Filter by protocol category |
| `chain` | string | Filter by blockchain |
| `q` | string | Search by protocol name |

**Response Schema:**

```json
{
  "data": [
    {
      "name": "Aave V3",
      "type": "lending",
      "chain": "ethereum",
      "finding_count": 87,
      "auditors": ["Trail of Bits", "Sigma Prime", "Code4rena"],
      "last_audit_date": "2024-06-01"
    }
  ],
  "pagination": { "page": 1, "per_page": 50, "total": 2844, "total_pages": 57 }
}
```

---

### 4. GET /categories

List all vulnerability categories/tags used in the database.

**Response Schema:**

```json
{
  "data": [
    {
      "name": "reentrancy",
      "finding_count": 59,
      "description": "Vulnerabilities involving reentrant calls that exploit stale state"
    },
    {
      "name": "oracle-manipulation",
      "finding_count": 145,
      "description": "Price oracle attacks including spot price manipulation and stale feeds"
    }
  ],
  "total": 207
}
```

---

## Error Codes

| Status Code | Meaning | Action |
|-------------|---------|--------|
| `200` | Success | Process response normally |
| `400` | Invalid parameters | Check query parameter types and values |
| `401` | Invalid or missing API key | Verify `X-API-Key` header is set correctly |
| `404` | Finding/resource not found | Verify the ID or endpoint path |
| `429` | Rate limited | Implement exponential backoff, wait and retry |
| `500` | Server error | Retry after delay; if persistent, check API status page |

**Error Response Format:**

```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded. Please wait 60 seconds before retrying.",
    "retry_after": 60
  }
}
```

---

## Rate Limits

| Limit | Value |
|-------|-------|
| Per minute | 100 requests |
| Per day | 10,000 requests |
| Backoff strategy | Exponential with jitter (see [Rate Limiting](rate-limiting.md)) |

---

## Best Practices

1. **Always paginate**: Never try to fetch all 50,530+ findings in one request. Use `per_page=50` and iterate pages.
2. **Use filters first**: Apply `severity`, `category`, `protocol_type`, and `chain` filters to narrow results before paginating.
3. **Cache responses**: Findings data rarely changes — cache results locally and refresh periodically.
4. **Checkpoint bulk downloads**: When downloading large datasets, save checkpoint files every 50 pages to resume on failure.
5. **Respect rate limits**: Implement proper backoff. A 429 response includes a `retry_after` field indicating wait time in seconds.
6. **Use specific queries**: A query for `reentrancy lending critical` returns far fewer, more relevant results than an unfiltered request.
```
