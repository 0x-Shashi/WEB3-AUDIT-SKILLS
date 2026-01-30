---
name: cyfrin-findings
description: "Query Cyfrin Solodit's database of 50,000+ real smart contract security findings. Use when researching vulnerabilities, learning attack patterns, preparing for audits, or finding prevention strategies. Provides access to findings from professional audits, bug bounties, and security contests across all major blockchain platforms."
allowed-tools:
  - Read
  - Grep
  - Bash
  - WebFetch
---

# Cyfrin Solodit Findings Skill

## Purpose

I provide access to the world's largest database of smart contract security findings. With 50,000+ real vulnerabilities from professional audits, I help you:

- **Research** vulnerabilities before writing code
- **Learn** from real-world attack patterns
- **Validate** your security concerns with evidence
- **Prepare** comprehensive audit checklists
- **Prevent** known vulnerability patterns

---

## When to Use This Skill

**Ideal scenarios:**
- Starting a new smart contract project
- Reviewing code for security issues
- Learning about specific vulnerability types
- Preparing for professional audits
- Building security checklists
- Understanding protocol-specific risks

**Trigger phrases:**
- "Query Solodit for..."
- "Find vulnerabilities related to..."
- "What are common attacks on..."
- "Research [vulnerability type] patterns"
- "Show me findings from [audit firm]"

---

## When NOT to Use

Do NOT use this skill for:
- Deep line-by-line code analysis (use `audit-context-building`)
- Scanning code for vulnerabilities (use vulnerability scanners)
- Writing audit reports (use `audit-report-writer`)
- Static analysis tooling (use `static-analysis`)

---

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "I know this vulnerability type" | You don't know all variants | Query for edge cases and variants |
| "One finding is enough" | Patterns have many manifestations | Query multiple related findings |
| "Old findings don't matter" | Many old patterns still occur | Include historical data |
| "Only HIGH severity matters" | MEDIUM findings often chain | Include all severity levels |
| "I'll search later" | Pre-development research prevents bugs | Research BEFORE writing code |

---

## API Reference

### Base Configuration

| Parameter | Value |
|-----------|-------|
| **Base URL** | `https://solodit.cyfrin.io/api/v1/solodit` |
| **Endpoint** | `POST /findings` |
| **Auth Header** | `X-Cyfrin-API-Key: $CYFRIN_API_KEY` |
| **Rate Limit** | 20 requests per 60 seconds |
| **Max Page Size** | 100 |

### Quick Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "keywords": "reentrancy",
      "impact": ["HIGH"]
    }
  }'
```

### Complete Filter Reference

See [resources/api-reference.md](resources/api-reference.md) for complete API documentation.

---

## Query Patterns

### By Vulnerability Type

| Vulnerability | Keywords | Tags |
|--------------|----------|------|
| Reentrancy | `"reentrancy external call"` | `reentrancy` |
| Oracle Manipulation | `"oracle price manipulation"` | `oracle`, `price-manipulation` |
| Access Control | `"access control authorization"` | `access-control` |
| Flash Loans | `"flash loan attack"` | `flash-loan` |
| Front-Running | `"front-running MEV sandwich"` | `front-running` |
| Integer Overflow | `"overflow underflow"` | `integer-overflow` |
| DoS | `"denial of service dos"` | `dos` |
| Logic Errors | `"logic error incorrect"` | `logic-error` |

### By Protocol Category

| Category | Query |
|----------|-------|
| DeFi General | `{"protocolCategory": ["DeFi"]}` |
| Lending | `{"protocolCategory": ["Lending"]}` |
| DEX | `{"protocolCategory": ["DEX"]}` |
| Staking | `{"protocolCategory": ["Staking"]}` |
| Governance | `{"protocolCategory": ["Governance"]}` |
| Bridge | `{"protocolCategory": ["Bridge"]}` |
| NFT | `{"protocolCategory": ["NFT"]}` |
| Yield | `{"protocolCategory": ["Yield Aggregator"]}` |

### By Language

| Language | Query |
|----------|-------|
| Solidity | `{"languages": ["Solidity"]}` |
| Rust (Solana) | `{"languages": ["Rust"]}` |
| Cairo | `{"languages": ["Cairo"]}` |
| Vyper | `{"languages": ["Vyper"]}` |
| Move | `{"languages": ["Move"]}` |

### By Severity + Quality

```json
{
  "filters": {
    "impact": ["HIGH", "CRITICAL"],
    "qualityScore": 4,
    "sortField": "Quality"
  }
}
```

---

## Workflow Integration

### Pre-Development Research

Before writing code, query for your protocol type:

```bash
# Step 1: Get HIGH severity for your category
curl -X POST ... -d '{
  "filters": {
    "protocolCategory": ["Lending"],
    "impact": ["HIGH"],
    "qualityScore": 4
  }
}'

# Step 2: Extract vulnerability patterns
# Step 3: Create prevention checklist
# Step 4: Build with security in mind
```

See [workflows/pre-development-research.md](workflows/pre-development-research.md) for complete workflow.

### Code Review Enhancement

Combine findings with code review:

```bash
# Step 1: Identify code patterns (external calls, oracles, etc.)
# Step 2: Query related vulnerabilities
curl -X POST ... -d '{
  "filters": {
    "keywords": "external call callback",
    "tags": ["reentrancy"]
  }
}'

# Step 3: Verify code against findings
# Step 4: Document concerns
```

See [workflows/code-review-enhancement.md](workflows/code-review-enhancement.md).

### Audit Preparation

Maximize audit value with pre-research:

```bash
# Step 1: Query all relevant patterns
# Step 2: Create comprehensive checklist
# Step 3: Run automated tools first
# Step 4: Prepare for auditors
```

See [workflows/audit-preparation.md](workflows/audit-preparation.md).

---

## Response Parsing

### Key Fields to Extract

| Field | Purpose |
|-------|---------|
| `title` | Vulnerability summary |
| `impact` | Severity (HIGH/MEDIUM/LOW) |
| `content` | Full description (markdown) |
| `summary` | AI-generated summary |
| `quality_score` | Finding quality (0-5) |
| `general_score` | Rarity score (0-5) |
| `firm_name` | Audit firm |
| `protocol_name` | Affected protocol |
| `report_date` | When found |

### Example Response Handling

```javascript
// Extract actionable patterns
const findings = response.findings.map(f => ({
  title: f.title,
  severity: f.impact,
  pattern: extractPattern(f.content),
  prevention: extractMitigation(f.content),
  tags: f.issues_issuetagscore?.map(t => t.tags_tag.title)
}));

// Group by vulnerability type
const byType = groupBy(findings, f => f.tags[0]);
```

See [resources/response-parsing.md](resources/response-parsing.md) for parsing utilities.

---

## Query Templates

### Template 1: Protocol-Specific Research

```json
{
  "page": 1,
  "pageSize": 20,
  "filters": {
    "protocolCategory": ["YOUR_CATEGORY"],
    "impact": ["HIGH", "MEDIUM"],
    "qualityScore": 3,
    "sortField": "Quality"
  }
}
```

### Template 2: Vulnerability Deep Dive

```json
{
  "page": 1,
  "pageSize": 50,
  "filters": {
    "keywords": "YOUR_VULNERABILITY_TYPE",
    "tags": ["your-tag"],
    "sortField": "Recency"
  }
}
```

### Template 3: Language-Specific

```json
{
  "page": 1,
  "pageSize": 20,
  "filters": {
    "languages": ["Solidity"],
    "impact": ["HIGH"],
    "keywords": "YOUR_CONCERN"
  }
}
```

### Template 4: Firm-Specific Learning

```json
{
  "page": 1,
  "pageSize": 30,
  "filters": {
    "firms": ["Cyfrin"],
    "qualityScore": 4
  }
}
```

See [resources/query-templates.md](resources/query-templates.md) for more templates.

---

## Rate Limiting

### Specifications

| Parameter | Value |
|-----------|-------|
| Requests per window | 20 |
| Window duration | 60 seconds |
| Exceeded response | HTTP 429 |

### Response Headers

```http
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 15
X-RateLimit-Reset: 1706400060
```

### Best Practices

1. **Batch requests** - Get more per request (pageSize: 100)
2. **Cache results** - Store findings locally
3. **Check remaining** - Monitor rate limit headers
4. **Implement backoff** - Wait on 429 responses

See [resources/rate-limiting.md](resources/rate-limiting.md) for implementation patterns.

---

## Combining with Other Skills

### With audit-context-building

```
1. Query findings for protocol type
2. Use audit-context-building for deep code analysis
3. Map findings to code sections
4. Identify matching patterns
```

### With vulnerability-scanners

```
1. Query findings for vulnerability types
2. Extract detection patterns
3. Use scanner to find in codebase
4. Validate with original findings
```

### With audit-report-writer

```
1. Find relevant previous findings
2. Use as evidence/precedent
3. Reference in your findings
4. Build comprehensive report
```

---

## Output Requirements

When presenting findings, include:

1. **Finding Title** - Clear vulnerability summary
2. **Severity** - HIGH/MEDIUM/LOW/INFORMATIONAL
3. **Pattern** - Code pattern that causes issue
4. **Prevention** - How to avoid in your code
5. **Source** - Link to original finding
6. **Relevance** - How it applies to current code

---

## Resources

- [API Reference](resources/api-reference.md) - Complete API documentation
- [Query Templates](resources/query-templates.md) - Ready-to-use queries
- [Response Parsing](resources/response-parsing.md) - Extracting insights
- [Rate Limiting](resources/rate-limiting.md) - Handling limits

## Workflows

- [Pre-Development Research](workflows/pre-development-research.md)
- [Code Review Enhancement](workflows/code-review-enhancement.md)
- [Audit Preparation](workflows/audit-preparation.md)
- [Vulnerability Learning](workflows/vulnerability-learning.md)

