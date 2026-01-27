# OpenZeppelin

## About

OpenZeppelin is the leading smart contract library provider and security firm. Their Contracts library is used by most Solidity projects, giving them unique insight into security patterns.

**Known For:**
- OpenZeppelin Contracts library
- Industry-standard implementations
- ERC standard expertise
- Upgrade patterns (UUPS, Transparent Proxy)
- Comprehensive security resources

## Query OpenZeppelin Findings

### All OZ HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "OpenZeppelin"}],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### OZ Token/Standard Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "firms": [{"value": "OpenZeppelin"}],
      "keywords": "ERC20 ERC721 token standard",
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Why Use OpenZeppelin Findings?

- **Standard Expertise:** Deep knowledge of ERC standards
- **Library Context:** Understand how their libraries should be used
- **Best Practices:** Industry-leading security patterns
- **Upgrade Security:** Proxy and upgrade expertise

## Notable Contributions

- OpenZeppelin Contracts
- Defender security platform
- AccessControl patterns
- ReentrancyGuard
- Upgrade patterns

## Best Use Cases

- Token and standard implementations
- Access control patterns
- Upgrade security
- Understanding library misuse
