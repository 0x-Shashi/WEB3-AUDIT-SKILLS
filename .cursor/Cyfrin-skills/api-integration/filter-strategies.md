# Filter Strategies

## Quick Start

This guide covers strategic approaches to filtering Solodit's 50,000+ security findings. Learn when to start broad vs. narrow, how to iterate effectively, and which filter combinations yield the best results.

## Starting Strategies

### Strategy 1: Start Broad, Then Narrow

**Best for:** Exploratory research, learning new vulnerability types, understanding a protocol category.

```bash
# Step 1: Broad search - understand the landscape
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "oracle"
    }
  }'
# Check metadata.totalResults - if 5000+, add filters

# Step 2: Add impact filter
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "oracle",
      "impact": ["HIGH"]
    }
  }'

# Step 3: Add quality filter for production-relevant findings
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "oracle",
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Strategy 2: Start Narrow, Then Expand

**Best for:** Specific function reviews, targeted vulnerability checks, time-constrained audits.

```bash
# Step 1: Very specific search
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "transferFrom reentrancy",
      "impact": ["HIGH"],
      "tags": [{"value": "Reentrancy"}],
      "qualityScore": 4
    }
  }'
# If too few results (< 5), remove filters

# Step 2: Remove quality filter
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "transferFrom reentrancy",
      "impact": ["HIGH"],
      "tags": [{"value": "Reentrancy"}]
    }
  }'

# Step 3: Expand impact to include MEDIUM
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "keywords": "transferFrom",
      "impact": ["HIGH", "MEDIUM"],
      "tags": [{"value": "Reentrancy"}]
    }
  }'
```

## Quality vs. Quantity Trade-offs

### High Quality (Fewer Results)

Use when you need actionable, well-documented findings:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "qualityScore": 4,
      "impact": ["HIGH"],
      "firms": [{"value": "Trail of Bits"}, {"value": "OpenZeppelin"}],
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

**When to use:**
- Preparing security documentation
- Learning best practices
- Building security checklists
- Training developers

### High Quantity (More Results)

Use when you need comprehensive coverage:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "qualityScore": 1,
      "impact": ["HIGH", "MEDIUM", "LOW"],
      "sortField": "Recency",
      "sortDirection": "Desc"
    }
  }'
```

**When to use:**
- Comprehensive security reviews
- Pattern analysis across many findings
- Research on edge cases
- Building vulnerability databases

## Recommended Quality Score Settings

| Use Case | Quality Score | Rationale |
|----------|---------------|-----------|
| Production code review | 4-5 | Only well-documented, verified issues |
| Learning/research | 3-4 | Balance of quality and variety |
| Comprehensive audit | 2-3 | Include less common patterns |
| Edge case hunting | 1-2 | Explore unusual findings |

## Filter Priority Matrix

When building complex queries, add filters in this order:

| Priority | Filter | Reason |
|----------|--------|--------|
| 1 | `impact` | Quickly reduces to relevant severity |
| 2 | `protocolCategory` or `tags` | Context-specific filtering |
| 3 | `keywords` | Text-based refinement |
| 4 | `qualityScore` | Quality threshold |
| 5 | `firms` | Source credibility |
| 6 | `reported` | Recency |
| 7 | `languages` | Platform-specific |

## Scenario-Based Filter Combinations

### Scenario 1: Pre-Development Research

"I'm building a lending protocol. What should I watch out for?"

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 4,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

### Scenario 2: Function-Specific Security Check

"Is my `withdraw()` function secure?"

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "keywords": "withdraw",
      "tags": [
        {"value": "Reentrancy"},
        {"value": "Access Control"},
        {"value": "Integer Overflow/Underflow"}
      ],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Scenario 3: Oracle Integration Security

"I'm integrating Chainlink. What issues have been found?"

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 40,
    "filters": {
      "keywords": "Chainlink oracle",
      "tags": [{"value": "Oracle"}, {"value": "Price Manipulation"}],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }'
```

### Scenario 4: Recent Attack Patterns

"What are the latest HIGH severity issues in the last 30 days?"

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "impact": ["HIGH"],
      "reported": {"value": "30"},
      "sortField": "Recency",
      "sortDirection": "Desc"
    }
  }'
```

### Scenario 5: Learning from Top Auditors

"Show me the best findings from elite audit firms."

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [
        {"value": "Trail of Bits"},
        {"value": "OpenZeppelin"},
        {"value": "Consensys Diligence"}
      ],
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

### Scenario 6: Unique/Rare Findings

"Show me unusual vulnerabilities that only one auditor found."

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "maxFinders": "1",
      "impact": ["HIGH"],
      "sortField": "Rarity",
      "sortDirection": "Desc"
    }
  }'
```

## Iterative Filtering Approach

### Step-by-Step Refinement Process

```
1. Start Query (get baseline count)
   ↓
2. Check metadata.totalResults
   ↓
3. Too many results? (>500)
   → Add impact filter: ["HIGH"]
   → Add qualityScore: 3
   ↓
4. Still too many? (>200)
   → Add protocol category or tags
   → Add recency filter
   ↓
5. Too few results? (<10)
   → Remove strictest filter first
   → Expand impact to include MEDIUM
   → Lower qualityScore
   ↓
6. Optimal range: 20-100 results
```

## Anti-Patterns to Avoid

### 1. Over-Filtering
```bash
# ❌ Too many filters - may return 0 results
{
  "filters": {
    "keywords": "very specific function name",
    "impact": ["HIGH"],
    "tags": [{"value": "Reentrancy"}],
    "firms": [{"value": "Cyfrin"}],
    "protocolCategory": [{"value": "NFT"}],
    "qualityScore": 5,
    "reported": {"value": "30"}
  }
}

# ✅ Start with essential filters, add more if needed
{
  "filters": {
    "keywords": "function name",
    "impact": ["HIGH", "MEDIUM"],
    "qualityScore": 3
  }
}
```

### 2. Under-Filtering
```bash
# ❌ No filters - returns 50,000+ results
{
  "page": 1,
  "pageSize": 100
}

# ✅ At least add impact and quality
{
  "page": 1,
  "pageSize": 100,
  "filters": {
    "impact": ["HIGH"],
    "qualityScore": 3
  }
}
```

### 3. Wrong Sort for Use Case
```bash
# ❌ Using Recency when you need quality
{
  "filters": {
    "sortField": "Recency"
  }
}
# Returns recent but potentially low-quality findings

# ✅ Match sort to intent
{
  "filters": {
    "sortField": "Quality",
    "qualityScore": 4
  }
}
```

## Test This Strategy

Run this iterative filtering example:

```bash
# Iteration 1: Baseline
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 1,
    "filters": {
      "keywords": "flash loan"
    }
  }'
# Note the totalResults in metadata

# Iteration 2: Add severity
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 1,
    "filters": {
      "keywords": "flash loan",
      "impact": ["HIGH"]
    }
  }'
# Note reduced totalResults

# Iteration 3: Add quality threshold
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "flash loan",
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
# Now get optimal results
```

## Checklist for Filter Strategy

- [ ] Identified the use case (research vs. specific check)
- [ ] Chose starting strategy (broad vs. narrow)
- [ ] Set appropriate quality/quantity balance
- [ ] Applied filters in priority order
- [ ] Checked result count before fetching all pages
- [ ] Matched sort field to intent
- [ ] Ready to iterate if results are suboptimal
