# Pre-Development Research Workflow

## Purpose

Before writing code, research common vulnerabilities and attack patterns for your protocol type. This proactive approach helps you build security in from the start rather than fixing issues later.

## When to Use

- Starting a new smart contract project
- Adding major new features
- Building in a new protocol category
- Entering unfamiliar DeFi territory

## Time Required

30-60 minutes for comprehensive research

## Step-by-Step Workflow

### Step 1: Identify Your Protocol Category

First, determine which category best fits your project:

- DeFi (general financial operations)
- Lending (borrow/supply)
- DEX (token swaps)
- Staking (reward distribution)
- Governance (voting/proposals)
- Bridge (cross-chain)
- NFT (non-fungible tokens)
- Yield Aggregator (auto-compounding)

### Step 2: Query Category-Specific HIGH Severity

```bash
# Replace "YourCategory" with your protocol category
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": [{"value": "YourCategory"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Step 3: Identify Common Tags

From the response, extract which vulnerability tags appear most often:

```bash
# Parse and count tags
curl ... | jq '[.findings[].issues_issuetagscore[]?.tags_tag.title] | group_by(.) | map({tag: .[0], count: length}) | sort_by(-.count) | .[0:10]'
```

### Step 4: Deep Dive on Top Tags

For each common tag found, query for more detail:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "protocolCategory": [{"value": "YourCategory"}],
      "tags": [{"value": "TopTag"}],
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Step 5: Research Similar Protocols

If you know similar protocols, query by keyword:

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "keywords": "similar protocol name or feature",
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Step 6: Build Security Requirements

Based on findings, create a security requirements document:

```markdown
# Security Requirements for [Project Name]

## Must-Have Protections

Based on research of [X] findings in [category]:

### 1. [Vulnerability Type 1]
- Mitigation: [specific pattern]
- Reference: [Solodit finding ID]

### 2. [Vulnerability Type 2]
- Mitigation: [specific pattern]
- Reference: [Solodit finding ID]

## Pre-Development Checklist

- [ ] Requirement 1 addressed in design
- [ ] Requirement 2 addressed in design
- [ ] ...
```

## Example: Lending Protocol Research

### Query 1: Lending HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Expected Common Tags

- Oracle
- Liquidation
- Flash Loan
- Price Manipulation
- Reentrancy

### Query 2: Oracle + Lending

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "tags": [{"value": "Oracle"}],
      "impact": ["HIGH"]
    }
  }'
```

### Resulting Requirements

```markdown
# Lending Protocol Security Requirements

## Oracle Security (Found in 15/50 HIGH findings)
- [ ] Use Chainlink or equivalent trusted oracle
- [ ] Implement staleness checks
- [ ] Add price deviation bounds
- [ ] Consider fallback oracles

## Liquidation Logic (Found in 12/50 HIGH findings)
- [ ] Proper health factor calculation
- [ ] Liquidation incentives
- [ ] Bad debt handling
- [ ] Flash loan resistance

## Flash Loan Protection (Found in 8/50 HIGH findings)
- [ ] Same-block deposit/withdraw prevention
- [ ] Rate limiting on large operations
```

## Output Template

After completing this workflow, you should have:

1. **List of top vulnerability types** for your category
2. **Specific examples** of each vulnerability
3. **Mitigation patterns** from auditor recommendations
4. **Security requirements document** for your project
5. **Pre-development checklist** to verify during design

## Next Steps

After pre-development research:
- → Use [code-review.md](code-review.md) when implementing features
- → Use [function-security-check.md](function-security-check.md) for each function
- → Use [audit-preparation.md](audit-preparation.md) before external audit
