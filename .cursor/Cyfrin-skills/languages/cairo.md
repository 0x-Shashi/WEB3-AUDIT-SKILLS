# Cairo Security

## Overview

Cairo is the programming language for Starknet, a ZK-rollup on Ethereum. It has unique characteristics due to its provable computation model.

**Maturity:** Medium  
**Ecosystem:** Starknet  
**Key Tools:** Protostar, Scarb, Cairo Test

## Query Cairo Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "languages": [{"value": "Cairo"}],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }'
```

## Cairo-Specific Vulnerabilities

### 1. Felt Overflow
The felt type has limited range.

```cairo
// Felt is modular arithmetic over a prime field
// Max value: P - 1 where P ≈ 2^251

// Be careful with assumptions about value ranges
```

### 2. Storage Key Collisions
Different from Solidity storage layout.

```cairo
// Storage is addressed by felt keys
// Ensure unique keys for different state
```

### 3. Reentrancy
Cairo 1.0+ has different execution model than Cairo 0.

```cairo
// Cairo 1.0: Calls are not synchronous like EVM
// Still verify state before/after external calls
```

### 4. Upgrade Patterns
Different proxy patterns than EVM.

```cairo
// Starknet has built-in upgrade mechanism
// Use replace_class_syscall carefully
```

## Cairo Security Checklist

- [ ] Felt arithmetic bounds considered
- [ ] Storage keys are unique
- [ ] Access control implemented
- [ ] Upgrade mechanism secured
- [ ] External call handling correct

## Cross-Reference

- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
- For logic errors → See [../vulnerability-tags/logic-error.md](../vulnerability-tags/logic-error.md)
