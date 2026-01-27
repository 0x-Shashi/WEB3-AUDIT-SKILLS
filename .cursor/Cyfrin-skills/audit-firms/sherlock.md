# Sherlock Audit Platform

## About

Sherlock is a decentralized audit contest platform that combines competitive auditing with protocol coverage. Auditors compete to find vulnerabilities, with quality judging and payouts for valid findings.

**Known For:**
- Decentralized audit contests
- Lead Senior Auditor (LSA) system
- Protocol coverage after audit
- High competition for findings
- Judging process for quality control

## Query Sherlock Findings

### All Sherlock HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Sherlock"}],
      "impact": ["HIGH"],
      "sortField": "Recency"
    }
  }'
```

### Sherlock + Protocol Category

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Sherlock"}],
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Top Quality Sherlock Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "firms": [{"value": "Sherlock"}],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## Why Use Sherlock Findings?

- **Volume:** Many auditors means more findings
- **Diverse Perspectives:** Different auditors find different things
- **Recent Protocols:** Covers newest DeFi projects
- **Judged Quality:** Invalid findings are filtered out

## Considerations

- Quality varies by auditor (use qualityScore filter)
- Some findings may be similar/duplicated
- Contest format means time-limited review
- May miss systemic issues that require deep analysis

## Best Use Cases

- Researching recent vulnerability patterns
- Finding edge cases and attack vectors
- Studying how different auditors approach the same code
- Volume learning across many protocols
