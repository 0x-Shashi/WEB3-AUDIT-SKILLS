# Yield Aggregator Security

## Quick Start

Yield aggregators optimize returns by automatically moving funds between DeFi protocols. They inherit risks from all integrated protocols plus add their own strategy complexity.

**Risk Level:** HIGH  
**Common Attacks:** Strategy manipulation, composability exploits, oracle attacks  
**Key Considerations:** Strategy security, external protocol risks, share accounting

## API Query: Yield Aggregator Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Yield Aggregator"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## Key Security Considerations

### Strategy Risks
- External protocol dependencies
- Composability attacks
- Oracle manipulation
- Flash loan vulnerabilities
- Reward token handling

### Share Accounting
- First depositor attacks
- Donation attacks
- Rounding errors
- Fee calculation

### Access Control
- Strategy addition/removal
- Emergency functions
- Harvesting permissions

## Security Checklist

- [ ] Strategy whitelist
- [ ] Flash loan resistance (same-block deposit/withdraw)
- [ ] Oracle protection (TWAP, Chainlink)
- [ ] Share price manipulation prevention
- [ ] Proper reward harvesting
- [ ] Emergency withdrawal
- [ ] Loss limits per strategy

## Cross-Reference

- For flash loans → See [../vulnerability-tags/flash-loan.md](../vulnerability-tags/flash-loan.md)
- For oracle attacks → See [../vulnerability-tags/oracle.md](../vulnerability-tags/oracle.md)
- For DeFi → See [defi.md](defi.md)
