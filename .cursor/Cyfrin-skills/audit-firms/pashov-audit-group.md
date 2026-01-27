# Pashov Audit Group

## About

Pashov Audit Group is a highly respected independent auditor known for thorough, detailed reports and exceptional findings. Pashov has been a top performer in audit contests and now leads a small team.

**Known For:**
- Solo/small team expertise
- Gas optimization findings
- Detailed code analysis
- DeFi specialization
- High hit rate on critical issues

## Query Pashov Findings

### All Pashov HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Pashov Audit Group"}],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Pashov Gas/Optimization Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Pashov Audit Group"}],
      "impact": ["GAS"]
    }
  }'
```

## Why Use Pashov Findings?

- **Quality over Quantity:** Focused, accurate findings
- **Gas Expertise:** Excellent optimization insights
- **Practical:** Real-world applicable recommendations
- **Detailed:** Thorough code-level analysis

## Best Use Cases

- Gas optimization research
- DeFi vulnerability patterns
- Learning detailed audit methodology
- Understanding code-level issues
