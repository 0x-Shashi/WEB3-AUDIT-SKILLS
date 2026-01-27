# Cyfrin Audit Firm

## About

Cyfrin is a leading smart contract security firm known for combining education with professional auditing. Founded by Patrick Collins, they focus on making security knowledge accessible while conducting high-quality audits.

**Known For:**
- Educational content (Cyfrin Updraft)
- High-quality, detailed reports
- DeFi expertise
- Cross-chain security
- Building Solodit database

## Query Cyfrin Findings

### All Cyfrin HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Cyfrin"}],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Cyfrin DeFi Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Cyfrin"}],
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Top Quality Cyfrin Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "firms": [{"value": "Cyfrin"}],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }'
```

## Why Use Cyfrin Findings?

- **Educational Value:** Reports are written to teach, not just report
- **Clear Explanations:** Good for learning vulnerability patterns
- **Modern Focus:** Cover recent DeFi patterns and cross-chain
- **Practical Mitigations:** Actionable fix recommendations

## Notable Audits

- Various DeFi protocols
- Cross-chain bridges
- Lending platforms
- Governance systems

## Best Use Cases

- Learning security patterns
- Understanding vulnerability root causes
- Finding detailed mitigation strategies
- Studying modern DeFi security
