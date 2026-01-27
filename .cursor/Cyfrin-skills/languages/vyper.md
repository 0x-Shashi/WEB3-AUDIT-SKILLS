# Vyper Security

## Overview

Vyper is a Pythonic smart contract language for the EVM, designed to be simpler and more secure than Solidity. It intentionally excludes features that can be footguns.

**Maturity:** Medium  
**Ecosystem:** Ethereum, EVM chains  
**Key Tools:** Titanoboa, Limited static analysis

## Query Vyper Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "languages": [{"value": "Vyper"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Vyper-Specific Considerations

### 1. No Inheritance
Vyper doesn't support inheritance, reducing complexity.

### 2. Built-in Reentrancy Lock
```vyper
@external
@nonreentrant("lock")
def withdraw():
    # Protected from reentrancy
    pass
```

### 3. Bounds Checking
Vyper has stricter bounds checking than Solidity.

### 4. Compiler Bugs
Smaller community means less battle-testing.

**Notable:** The Curve hack (2023) was due to a Vyper compiler bug in the reentrancy lock.

## Vyper Security Checklist

- [ ] Using latest stable Vyper version
- [ ] `@nonreentrant` on sensitive functions
- [ ] Compiler version verified for known bugs
- [ ] Testing thorough (fewer tools available)

## Cross-Reference

- For reentrancy → See [../vulnerability-tags/reentrancy.md](../vulnerability-tags/reentrancy.md)
- For EVM considerations → See [solidity.md](solidity.md) (many apply to Vyper)
