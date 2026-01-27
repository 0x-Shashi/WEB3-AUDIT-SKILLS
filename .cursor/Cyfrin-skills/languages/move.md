# Move Security

## Overview

Move is a smart contract language designed for safety, originally developed for Diem (Facebook's blockchain) and now used by Aptos and Sui.

**Maturity:** Medium  
**Ecosystem:** Aptos, Sui  
**Key Tools:** Move Prover (formal verification)

## Query Move Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "languages": [{"value": "Move"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Move-Specific Considerations

### 1. Resource Model
Move uses a unique resource ownership model.

```move
// Resources cannot be copied or implicitly dropped
struct Coin has store {
    value: u64,
}

// Must explicitly handle resources
public fun destroy_zero(coin: Coin) {
    let Coin { value } = coin;
    assert!(value == 0, 0);
}
```

### 2. Abilities
Types have explicit abilities that restrict usage.

```move
// copy: Can be copied
// drop: Can be implicitly dropped
// store: Can be stored in global storage
// key: Can be used as a key in global storage
struct Token has copy, drop, store {
    value: u64,
}
```

### 3. Formal Verification
Move has built-in prover support.

```move
spec verify_balance {
    ensures balance(account) >= min_balance;
}
```

### 4. Module System
Different from contract-based systems.

```move
module my_addr::my_module {
    // All code in modules
    // Visibility explicitly controlled
}
```

## Move Security Checklist

- [ ] Resources properly handled (no leaks)
- [ ] Abilities correctly specified
- [ ] Access control via visibility
- [ ] Prover specifications written
- [ ] Signer validation

## Cross-Reference

- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
- For logic errors → See [../vulnerability-tags/logic-error.md](../vulnerability-tags/logic-error.md)
