# Solidity Security

## Overview

Solidity is the most widely used smart contract language, running on Ethereum and EVM-compatible chains. It has the most mature security tooling and the largest body of audit findings.

**Maturity:** Very High  
**Ecosystem:** Ethereum, Polygon, Arbitrum, Optimism, BSC, Avalanche  
**Key Tools:** Slither, Foundry, Echidna, Mythril, Certora

## Query Solidity Findings

### All Solidity HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "languages": [{"value": "Solidity"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Solidity + Specific Vulnerability

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "languages": [{"value": "Solidity"}],
      "tags": [{"value": "Reentrancy"}],
      "impact": ["HIGH"]
    }
  }'
```

## Solidity-Specific Vulnerabilities

### 1. Reentrancy
Unique to EVM due to external call mechanics.

```solidity
// VULNERABLE
function withdraw() external {
    (bool success,) = msg.sender.call{value: balance[msg.sender]}("");
    balance[msg.sender] = 0;
}

// SECURE
function withdraw() external nonReentrant {
    uint256 amount = balance[msg.sender];
    balance[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
}
```

### 2. Delegatecall Dangers
Storage layout must match.

```solidity
// DANGEROUS
function upgrade(address newImpl) external {
    (bool success,) = newImpl.delegatecall(msg.data);
}
```

### 3. tx.origin Authentication
Never use for authorization.

```solidity
// VULNERABLE
function transfer() external {
    require(tx.origin == owner, "Not owner");  // Phishable
}

// SECURE
function transfer() external {
    require(msg.sender == owner, "Not owner");
}
```

### 4. Storage Collisions (Proxies)
Upgradeable contracts need careful storage layout.

```solidity
// Use EIP-1967 slots
bytes32 constant IMPLEMENTATION_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
```

### 5. Uninitialized Proxy
Implementation must be initialized.

```solidity
// Constructor doesn't run for proxies
constructor() {
    _disableInitializers();  // Prevent initialization of impl
}

function initialize() external initializer {
    __Ownable_init();
}
```

## Version-Specific Considerations

### Solidity 0.8+
- Built-in overflow/underflow checks
- Custom errors (gas efficient)
- Immutable and constant improvements

### Solidity < 0.8
- Require SafeMath for arithmetic
- More gas-intensive error messages
- Missing some safety features

## Security Best Practices for Solidity

### Use Established Libraries
```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
```

### Proper Visibility
```solidity
// Be explicit about visibility
function internalLogic() internal { }
function publicAction() public { }
function externalOnly() external { }
```

### Event Emission
```solidity
// Always emit events for state changes
event Deposited(address indexed user, uint256 amount);
emit Deposited(msg.sender, amount);
```

## Solidity Security Checklist

### Language Features
- [ ] Using Solidity 0.8+ for overflow protection
- [ ] No tx.origin for authentication
- [ ] Proper visibility on all functions
- [ ] No floating pragma (use fixed version)

### Patterns
- [ ] CEI pattern for external calls
- [ ] ReentrancyGuard where needed
- [ ] SafeERC20 for token operations
- [ ] Ownable2Step for ownership

### Proxies (if applicable)
- [ ] Storage layout preserved
- [ ] Implementation initialized
- [ ] Initializer modifier used
- [ ] UUPS or Transparent pattern correct

## Recommended Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| Slither | Static analysis | Always |
| Foundry | Testing, fuzzing | Development |
| Echidna | Property-based fuzzing | Pre-audit |
| Mythril | Symbolic execution | Deep analysis |
| Certora | Formal verification | Critical contracts |

## Cross-Reference

- For reentrancy → See [../vulnerability-tags/reentrancy.md](../vulnerability-tags/reentrancy.md)
- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
- For DeFi patterns → See [../protocol-categories/defi.md](../protocol-categories/defi.md)
