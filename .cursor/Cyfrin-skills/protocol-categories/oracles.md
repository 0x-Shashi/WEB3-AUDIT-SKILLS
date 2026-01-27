# Oracle Protocol Security

## Quick Start

Oracle protocols provide external data to on-chain applications. As critical infrastructure, their security directly impacts every protocol that depends on them.

**Risk Level:** CRITICAL  
**Common Attacks:** Data manipulation, stale data, single point of failure  
**Key Considerations:** Data freshness, manipulation resistance, redundancy

## API Query: Oracle Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Oracles"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## Key Security Considerations

### Data Integrity
- Source reliability
- Aggregation method
- Outlier handling
- Update frequency

### Manipulation Resistance
- Multi-source aggregation
- TWAP mechanisms
- Deviation bounds
- Flash loan resistance

### Availability
- Fallback mechanisms
- Heartbeat monitoring
- Grace periods

## Security Checklist

- [ ] Multiple data sources
- [ ] Staleness checks
- [ ] Price deviation bounds
- [ ] Fallback oracles
- [ ] L2 sequencer checks
- [ ] Manipulation resistance

## Cross-Reference

- For oracle vulnerabilities → See [../vulnerability-tags/oracle.md](../vulnerability-tags/oracle.md)
- For price manipulation → See [../vulnerability-tags/price-manipulation.md](../vulnerability-tags/price-manipulation.md)
