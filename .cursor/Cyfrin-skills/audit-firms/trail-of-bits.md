# Trail of Bits

## About

Trail of Bits is a premier security research and consulting firm known for deep technical analysis and building security tools. They've audited some of the most complex systems in crypto.

**Known For:**
- Deep technical research
- Building security tools (Slither, Echidna, Manticore)
- Academic-quality analysis
- Complex system understanding
- Cryptography expertise

## Query Trail of Bits Findings

### All ToB HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "firms": [{"value": "Trail of Bits"}],
      "impact": ["HIGH"],
      "sortField": "Quality"
    }
  }'
```

### ToB Complex Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "firms": [{"value": "Trail of Bits"}],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }'
```

## Why Use Trail of Bits Findings?

- **Highest Quality:** Deep, thorough analysis
- **Novel Vulnerabilities:** Find unique attack vectors
- **Tool-Augmented:** Use formal verification and fuzzing
- **Educational Reports:** Explain complex issues clearly

## Notable Contributions

- Slither static analyzer
- Echidna fuzzer
- Manticore symbolic executor
- Building Blocks blog
- Security guidelines

## Best Use Cases

- Learning complex vulnerability patterns
- Understanding formal verification findings
- Studying cryptographic issues
- Deep system architecture review
