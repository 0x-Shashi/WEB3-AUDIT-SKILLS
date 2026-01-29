# Query Templates

Ready-to-use query templates for common research scenarios.

---

## By Vulnerability Type

### Reentrancy

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "reentrancy external call callback",
      "tags": ["reentrancy"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Oracle Manipulation

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "oracle price manipulation stale",
      "tags": ["oracle", "price-manipulation"],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Access Control

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "access control authorization owner admin",
      "tags": ["access-control"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Flash Loan Attacks

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "flash loan atomic transaction",
      "tags": ["flash-loan"],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Integer Overflow/Underflow

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "overflow underflow unchecked arithmetic",
      "tags": ["integer-overflow"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Front-Running / MEV

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "front-running sandwich MEV mempool",
      "tags": ["front-running"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Denial of Service

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "denial of service dos gas limit block",
      "tags": ["dos"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

---

## By Protocol Category

### Lending Protocols

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": ["Lending"],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

### DEX / AMM

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": ["DEX"],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

### Staking Protocols

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": ["Staking"],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

### Bridge Protocols

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": ["Bridge"],
      "impact": ["HIGH"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

### Governance

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": ["Governance"],
      "keywords": "voting proposal flash loan",
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

---

## By Language / Platform

### Solidity (EVM)

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "languages": ["Solidity"],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Rust (Solana)

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "languages": ["Rust"],
      "keywords": "solana anchor CPI PDA",
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Cairo (StarkNet)

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "languages": ["Cairo"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Recency"
    }
  }'
```

### Vyper

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "languages": ["Vyper"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

---

## Combined Queries

### Lending + Oracle Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": ["Lending"],
      "tags": ["oracle", "price-manipulation"],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### DEX + Reentrancy

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": ["DEX"],
      "tags": ["reentrancy"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Staking + First Depositor

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": ["Staking"],
      "keywords": "first depositor donation inflation attack",
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

---

## Quality-Focused Queries

### Top Quality Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "qualityScore": 5,
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### Rare / Unique Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "qualityScore": 4,
      "impact": ["HIGH"],
      "sortField": "Rarity"
    }
  }'
```

### Recent Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Recency"
    }
  }'
```

---

## Audit Firm Queries

### Cyfrin Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "firms": ["Cyfrin"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

### Multiple Firms

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "firms": ["Cyfrin", "OpenZeppelin", "Sherlock"],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```
