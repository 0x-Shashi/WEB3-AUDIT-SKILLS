# Code4rena (C4) Audit Platform

## About

Code4rena is the original audit contest platform that pioneered competitive smart contract auditing. Wardens compete to find vulnerabilities with payouts based on severity and uniqueness.

**Known For:**
- Pioneer of audit contests
- Large warden community
- High finding volume
- Diverse protocol coverage
- Bot races and high-severity hunts

## Query Code4rena Findings

### All C4 HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Code4rena"}],
      "impact": ["HIGH"],
      "sortField": "Recency"
    }
  }'
```

### C4 + Vulnerability Tag

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Code4rena"}],
      "tags": [{"value": "Reentrancy"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Top Quality C4 Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "firms": [{"value": "Code4rena"}],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## Why Use C4 Findings?

- **Largest Database:** Thousands of findings across protocols
- **Wide Protocol Coverage:** From small to major protocols
- **Pattern Discovery:** See common issues across projects
- **Historical Data:** Years of audit findings

## Considerations

- Very variable quality (always filter by qualityScore)
- Many QA and gas findings mixed in
- Duplicate findings for same issues
- Time-limited contests may miss deep issues

## Best Use Cases

- Building vulnerability pattern databases
- Research across many protocols
- Understanding common pitfalls
- Learning from warden methodologies
