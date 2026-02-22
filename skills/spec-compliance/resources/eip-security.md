---
id: SPEC-EIP-SEC
title: EIP Security Implications
parent: spec-compliance
type: resource
last_updated: 2025-01-31
---

# EIP Security Implications

Security-critical considerations for infrastructure-level EIPs that affect smart contract architecture.

---

## EIP-712 (Typed Structured Data Hashing and Signing)

Used for off-chain signature verification (meta-transactions, permits, order books).

### Domain Separator

```solidity
bytes32 constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    DOMAIN_TYPEHASH,
    keccak256(bytes(name)),
    keccak256(bytes(version)),
    block.chainid,
    address(this)
));
```

### Security Requirements

| Requirement | Why | Vulnerability if Missing |
|-------------|-----|-------------------------|
| Include `chainId` | Prevents cross-chain replay | Signature valid on mainnet AND fork |
| Include `verifyingContract` | Prevents cross-contract replay | Signature valid on different contract |
| Use nonces | Prevents replay of same signature | Same signature usable multiple times |
| Check `deadline` | Prevents stale signatures | Signature valid forever |
| Correct type hash | Must match struct definition exactly | Signature verification always fails or accepts wrong data |

### Cross-Chain Replay Attack

```solidity
// VULNERABLE: Domain separator computed at deployment time
// If chain forks (like ETH/ETC), same DOMAIN_SEPARATOR on both chains
constructor() {
    DOMAIN_SEPARATOR = computeDomainSeparator(); // Cached!
}

// SAFE: Recompute if chainId changes (handles forks)
function domainSeparator() public view returns (bytes32) {
    if (block.chainid == INITIAL_CHAIN_ID) {
        return INITIAL_DOMAIN_SEPARATOR;
    } else {
        return computeDomainSeparator(); // Recompute for new chain
    }
}
```

### Signature Malleability

```solidity
// VULNERABLE: ecrecover is malleable
// For every valid (v, r, s), there exists another valid (v', r, s')
address signer = ecrecover(hash, v, r, s);

// SAFE: Use OpenZeppelin ECDSA which enforces s <= secp256k1n/2
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
address signer = ECDSA.recover(hash, v, r, s); // Reverts on malleability
```

### EIP-712 Checklist

- [ ] Domain separator includes `chainId` (handles forks)
- [ ] Domain separator includes `verifyingContract` (prevents cross-contract replay)
- [ ] Nonces used and incremented (prevents replay)
- [ ] Deadline checked (prevents stale signatures)
- [ ] Using OpenZeppelin `ECDSA.recover` (prevents malleability)
- [ ] Type hashes match struct definitions exactly
- [ ] `ecrecover` return checked for `address(0)` (invalid signature)

---

## EIP-1967 (Standard Proxy Storage Slots)

Defines standard storage slot locations for proxy contracts to prevent collision.

### Standard Slots

| Slot | Purpose | Value |
|------|---------|-------|
| `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)` | Implementation address | `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` |
| `bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)` | Admin address | `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103` |
| `bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)` | Beacon address | `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50` |

### Security Implications

| Risk | Description |
|------|-------------|
| Wrong slot used | Implementation address stored at non-standard slot = can't verify on explorer |
| Slot collision | Custom storage overlaps with EIP-1967 slot = implementation address corrupted |
| Admin slot writable | If admin slot is writable without auth, proxy can be taken over |
| Missing slot | No standard slot = can't use OpenZeppelin upgrade tools |

### EIP-1967 Checklist

- [ ] Implementation slot at correct EIP-1967 location
- [ ] Admin slot at correct EIP-1967 location (if used)
- [ ] No custom storage variables that could collide with standard slots
- [ ] Slots readable by standard tools (block explorers, etherscan)
- [ ] Implementation slot only modifiable by authorized upgrader

---

## EIP-2535 (Diamond Standard / Multi-Facet Proxy)

Allows a single proxy to delegate to multiple implementation contracts (facets).

### Architecture

```
Diamond Proxy
  ├── Facet A (functions: swap, addLiquidity)
  ├── Facet B (functions: stake, unstake)  
  ├── Facet C (functions: governance, vote)
  └── DiamondCut (functions: diamondCut)
```

### Security Risks

| Risk | Description | Impact |
|------|-------------|--------|
| **Selector collision** | Two facets have functions with same 4-byte selector | Wrong facet called, unexpected behavior |
| **Storage collision** | Two facets write to same storage slot | Data corruption |
| **DiamondCut authority** | `diamondCut()` can add/replace/remove any facet | Protocol takeover if not properly protected |
| **Missing loupe functions** | Can't inspect diamond's facets | Opaque proxy, unverifiable |
| **Facet removal** | Removing a facet without migrating state | Orphaned storage |

### Diamond Storage Pattern

```solidity
// CORRECT: Each facet uses a unique storage position
library FacetAStorage {
    bytes32 constant STORAGE_POSITION = keccak256("facet.a.storage");
    
    struct Storage {
        uint256 value;
        mapping(address => uint256) balances;
    }
    
    function getStorage() internal pure returns (Storage storage s) {
        bytes32 position = STORAGE_POSITION;
        assembly { s.slot := position }
    }
}
```

### EIP-2535 Checklist

- [ ] No function selector collisions across all facets
- [ ] Each facet uses isolated storage (Diamond Storage pattern)
- [ ] `diamondCut()` protected by owner/governance
- [ ] Loupe functions implemented (`facets()`, `facetAddresses()`, etc.)
- [ ] Initialization functions called during facet addition (not separately)

---

## EIP-4337 (Account Abstraction)

Allows smart contract wallets (accounts) to initiate transactions via `UserOperation` bundles.

### Architecture

```
User → Bundler → EntryPoint.handleOps([UserOperation]) → Account.__validateUserOp() → Account.__executeUserOp()
```

### Security Considerations

| Component | Risk | Mitigation |
|-----------|------|------------|
| `validateUserOp` | Must verify signature — if bypassed, anyone can execute | Always verify `userOp.signature` against stored keys |
| `validateUserOp` | Must return correct validation data | Return `SIG_VALIDATION_FAILED` on bad sig, not revert |
| `validateUserOp` | Storage access restrictions during validation | Can only access own storage + EntryPoint deposit |
| Paymaster | Pays gas for user — if exploited, drained of ETH | Rate limiting, allowed sender lists |
| EntryPoint | Single trusted contract — if compromised, all accounts at risk | Hardcoded `entryPoint()` address |
| Nonce management | Replay protection | Use EntryPoint's nonce management |

### EIP-4337 Checklist

- [ ] `validateUserOp` verifies signature correctly
- [ ] `validateUserOp` returns validation data (not just reverts)
- [ ] Time range validation if applicable
- [ ] Paymaster validates and limits what it pays for
- [ ] `entryPoint()` returns the correct singleton address
- [ ] Storage access rules followed during validation phase
- [ ] Nonce handling prevents replay

---

## EIP-1153 (Transient Storage)

`TSTORE` and `TLOAD` opcodes provide storage that resets after each transaction.

### Use Cases

| Use Case | Benefit |
|----------|----------|
| Reentrancy guard | No permanent storage cost |
| Callback data passing | Temporary data between calls within same tx |
| Flash loan flag | Mark ongoing flash loan |

### Security Considerations

| Risk | Description |
|------|-------------|
| Persistence assumption | Transient storage does NOT persist across transactions |
| Inner transaction visibility | ALL calls within the same transaction can read/write the same transient slots |
| Reentrancy with transient storage | If using `TSTORE` as reentrancy guard, must clear after use |
| Cross-call access | Called contracts can access the same transient storage if using same slot |

### EIP-1153 Checklist

- [ ] Transient storage not used for data that should persist
- [ ] Slots properly cleared after use (or relied on automatic transaction-end reset)
- [ ] No assumption about transient storage values at transaction start (always 0)
- [ ] Cross-call visibility understood (internal calls share transient storage)
