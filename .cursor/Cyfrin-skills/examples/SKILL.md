# Examples Skill

## Quick Start

This folder contains curated examples from the Solodit database to help you understand real-world vulnerabilities, attack patterns, and best practices.

## Available Examples

| File | Description | Best For |
|------|-------------|----------|
| [High Severity Exploits](high-severity-exploits.md) | Critical vulnerabilities that led to major losses | Understanding worst-case scenarios |
| [Common Patterns](common-patterns.md) | Frequently recurring vulnerability patterns | Day-to-day development |
| [Best Practices](best-practices.md) | Security patterns from audit recommendations | Writing secure code |
| [Case Studies](case-studies.md) | In-depth analysis of notable exploits | Deep learning |

## How to Use These Examples

### 1. Learning Mode
Start with [common-patterns.md](common-patterns.md) to understand what vulnerabilities appear most often, then study [best-practices.md](best-practices.md) for mitigations.

### 2. Research Mode
Use [high-severity-exploits.md](high-severity-exploits.md) to understand the most impactful vulnerabilities and how they were exploited.

### 3. Deep Dive Mode
Study [case-studies.md](case-studies.md) for comprehensive analysis of notable exploits from start to finish.

## Example Query: Top Quality Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

## Example Query: Recent Notable Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "impact": ["HIGH"],
      "qualityScore": 4,
      "reported": {"value": "90"},
      "sortField": "Recency"
    }
  }'
```

## Cross-Reference

- For specific vulnerabilities → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For protocol-specific examples → See [../protocol-categories/SKILL.md](../protocol-categories/SKILL.md)
- For learning workflows → See [../workflows/vulnerability-learning.md](../workflows/vulnerability-learning.md)
