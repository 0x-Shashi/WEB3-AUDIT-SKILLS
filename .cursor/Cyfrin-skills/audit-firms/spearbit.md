# Spearbit

## About

Spearbit is an elite network of independent security researchers who collaborate on complex audits. They attract top auditors and focus on the most sophisticated DeFi protocols.

**Known For:**
- Elite auditor network
- Complex DeFi expertise
- Collaborative auditing
- High-quality deep dives
- Mathematical precision

## Query Spearbit Findings

### All Spearbit HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Spearbit"}],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Spearbit Complex Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Spearbit"}],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }'
```

## Why Use Spearbit Findings?

- **Elite Quality:** Top auditors in the industry
- **Complex Issues:** Find sophisticated vulnerabilities
- **DeFi Focus:** Deep protocol understanding
- **Collaborative:** Multiple expert perspectives

## Best Use Cases

- Complex DeFi protocol research
- Advanced vulnerability patterns
- Mathematical/economic attacks
- Learning from elite auditors
