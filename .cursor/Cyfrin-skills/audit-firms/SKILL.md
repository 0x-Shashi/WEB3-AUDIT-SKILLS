# Audit Firms Skill

## Quick Start

This folder contains information about major audit firms whose findings are available through the Solodit API. Filtering by firm can be useful when you want to:

- **Study specific methodologies** - Different firms have different strengths
- **Find high-quality reports** - Some firms are known for thorough analysis
- **Research firm-specific patterns** - Each firm tends to find certain vulnerability types

## Available Firms in Solodit

| Firm | Specialty | Report Quality | Focus Areas |
|------|-----------|----------------|-------------|
| [Cyfrin](cyfrin.md) | Education + Audit | HIGH | DeFi, Cross-chain |
| [Sherlock](sherlock.md) | Contest Platform | HIGH | Various |
| [Code4rena](code4rena.md) | Contest Platform | VARIABLE | Various |
| [Trail of Bits](trail-of-bits.md) | Research-focused | VERY HIGH | Complex systems |
| [OpenZeppelin](openzeppelin.md) | Library Authors | VERY HIGH | Standards, Libraries |
| [Consensys Diligence](consensys-diligence.md) | Enterprise | HIGH | DeFi, L2s |
| [Spearbit](spearbit.md) | Elite Network | VERY HIGH | Complex DeFi |
| [Pashov Audit Group](pashov-audit-group.md) | Solo Auditor | HIGH | DeFi, Gas |

## API Query: Filter by Firm

### Single Firm

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

### Multiple Firms (Top Tier)

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "firms": [
        {"value": "Trail of Bits"},
        {"value": "OpenZeppelin"},
        {"value": "Spearbit"}
      ],
      "impact": ["HIGH"],
      "qualityScore": 5
    }
  }'
```

### Firm + Vulnerability Type

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Cyfrin"}],
      "tags": [{"value": "Reentrancy"}],
      "impact": ["HIGH"]
    }
  }'
```

## Firm Selection Guide

### For Learning Security

```bash
# Educational, well-explained findings
{
  "filters": {
    "firms": [{"value": "Cyfrin"}, {"value": "Trail of Bits"}],
    "qualityScore": 5,
    "sortField": "Quality"
  }
}
```

### For Complex DeFi

```bash
# Deep technical analysis
{
  "filters": {
    "firms": [{"value": "Spearbit"}, {"value": "Trail of Bits"}],
    "protocolCategory": [{"value": "DeFi"}],
    "impact": ["HIGH"]
  }
}
```

### For Contest-Style Coverage

```bash
# High volume, diverse findings
{
  "filters": {
    "firms": [{"value": "Sherlock"}, {"value": "Code4rena"}],
    "impact": ["HIGH", "MEDIUM"]
  }
}
```

### For Standard Implementations

```bash
# Library and standard patterns
{
  "filters": {
    "firms": [{"value": "OpenZeppelin"}],
    "impact": ["HIGH", "MEDIUM"]
  }
}
```

## Firm Strengths Summary

| Need | Best Firms |
|------|-----------|
| Learning | Cyfrin, Trail of Bits |
| Complex math | Trail of Bits, Spearbit |
| DeFi protocols | Spearbit, Cyfrin, Sherlock |
| Standards/Libraries | OpenZeppelin |
| Gas optimization | Pashov Audit Group |
| Wide coverage | Code4rena, Sherlock |

## Quality Considerations

### Contest Platforms (C4, Sherlock)

**Pros:**
- Many eyes on code
- Diverse perspectives
- Quick turnaround

**Cons:**
- Variable quality (filter by score)
- May have duplicates
- Less deep system analysis

### Traditional Firms (ToB, OZ, Spearbit)

**Pros:**
- Deep system understanding
- Consistent methodology
- High-quality reports

**Cons:**
- Fewer findings per protocol
- May miss edge cases
- Longer timelines

## Test This Skill

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "firms": [{"value": "Cyfrin"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, protocol: .protocol_name, tags: [.issues_issuetagscore[]?.tags_tag.title] | unique}'
```

## Cross-Reference

- For vulnerability types → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For protocol categories → See [../protocol-categories/SKILL.md](../protocol-categories/SKILL.md)
- For workflows → See [../workflows/SKILL.md](../workflows/SKILL.md)
