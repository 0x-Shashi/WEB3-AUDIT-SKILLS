# Consensys Diligence

## About

Consensys Diligence is the security arm of Consensys (creators of MetaMask, Infura). They focus on enterprise-grade audits with deep Ethereum ecosystem knowledge.

**Known For:**
- Enterprise-grade security
- Deep Ethereum knowledge
- L2 and scaling expertise
- Formal verification
- Comprehensive methodology

## Query Consensys Diligence Findings

### All Consensys HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Consensys Diligence"}],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Consensys DeFi Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Consensys Diligence"}],
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Why Use Consensys Findings?

- **Enterprise Quality:** Thorough, methodical approach
- **Ethereum Depth:** Core protocol understanding
- **L2 Expertise:** Scaling solution security
- **Formal Methods:** Mathematical verification

## Best Use Cases

- L2 and rollup security
- Enterprise DeFi protocols
- Core infrastructure
- Formal verification patterns
