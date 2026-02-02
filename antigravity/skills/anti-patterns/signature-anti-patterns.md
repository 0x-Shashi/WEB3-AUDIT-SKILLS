# Signature & Cryptography Anti-Patterns

> Security anti-patterns for digital signatures, EIP-712, ECDSA, and cryptographic operations in smart contracts.
> 40 anti-patterns covering signature verification, replay attacks, malleability, and key management.

---

## Category Overview

| Category | ID Range | Count | Focus Area |
|----------|----------|-------|------------|
| ECDSA Vulnerabilities | SIG-AP-01 to 07 | 7 | ecrecover, malleability, v/r/s |
| EIP-712 Issues | SIG-AP-08 to 15 | 8 | Domain separation, typed data |
| Replay Attacks | SIG-AP-16 to 22 | 7 | Nonce, chain ID, deadlines |
| Permit & Meta-Tx | SIG-AP-23 to 29 | 7 | ERC20Permit, ERC2612, relayers |
| Multi-Signature | SIG-AP-30 to 35 | 6 | Threshold, ordering, timelock |
| Key Management | SIG-AP-36 to 40 | 5 | Derivation, rotation, compromise |

---

## Category 1: ECDSA Vulnerabilities

### SIG-AP-01: Missing Zero Address Check on ecrecover

**Severity:** Critical | **Likelihood:** High

**Description:**
`ecrecover` returns address(0) for invalid signatures instead of reverting. Missing check allows anyone to pass verification.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No zero address check
contract VulnerableRecover {
    function verify(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner
    ) public pure returns (bool) {
        address recovered = ecrecover(hash, v, r, s);
        // If signature invalid, recovered = address(0)
        // If expectedSigner = address(0), returns true!
        return recovered == expectedSigner;
    }
}

// Attack: Submit invalid signature for address(0) operations
```

**Real Exploits:**
- **Multiple protocols (2020-2023):** Zero address signer bypass
- **Permit implementations:** Missing validation

**Secure Pattern:**
```solidity
// SECURE: Check for zero address
contract SecureRecover {
    function verify(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner
    ) public pure returns (bool) {
        require(expectedSigner != address(0), "Invalid signer");
        
        address recovered = ecrecover(hash, v, r, s);
        require(recovered != address(0), "Invalid signature");
        
        return recovered == expectedSigner;
    }
    
    // Better: Use OpenZeppelin ECDSA
    function verifySecure(
        bytes32 hash,
        bytes memory signature,
        address expectedSigner
    ) public pure returns (bool) {
        // ECDSA.recover reverts on invalid signature
        address recovered = ECDSA.recover(hash, signature);
        return recovered == expectedSigner;
    }
}
```

**Detection Methods:**
- [ ] Search for direct `ecrecover` calls
- [ ] Check if return value compared against address(0)
- [ ] Check if expected signer can be address(0)
- [ ] Verify OpenZeppelin ECDSA is used

---

### SIG-AP-02: Signature Malleability

**Severity:** High | **Likelihood:** Medium

**Description:**
ECDSA signatures have malleability - for every valid signature (v,r,s), there's another valid signature (v',r,s') that verifies to same address.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No s-value check
contract VulnerableMalleability {
    mapping(bytes32 => bool) public usedSignatures;
    
    function executeWithSignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 sigHash = keccak256(abi.encodePacked(r, s, v));
        require(!usedSignatures[sigHash], "Signature used");
        
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorizedSigner, "Invalid signer");
        
        usedSignatures[sigHash] = true;
        // Execute action...
    }
    
    // Attack: Compute malleable signature
    // Original: (v, r, s)
    // Malleable: (v ^ 1, r, secp256k1n - s)
    // Both recover to same address but different hash
}
```

**Secure Pattern:**
```solidity
// SECURE: Enforce lower-s and proper v
contract SecureMalleability {
    // secp256k1n / 2
    uint256 constant HALF_CURVE_ORDER = 
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    
    function executeWithSignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Enforce lower-s
        require(uint256(s) <= HALF_CURVE_ORDER, "Invalid s value");
        
        // Enforce valid v
        require(v == 27 || v == 28, "Invalid v value");
        
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        require(signer == authorizedSigner, "Invalid signer");
        
        // Now safe to use hash as unique identifier
        bytes32 sigHash = keccak256(abi.encodePacked(hash));
        require(!usedHashes[sigHash], "Already executed");
        usedHashes[sigHash] = true;
    }
    
    // Better: Use ECDSA library
    function executeSecure(bytes32 hash, bytes memory signature) external {
        // OpenZeppelin ECDSA handles malleability
        address signer = ECDSA.recover(hash, signature);
        require(signer == authorizedSigner, "Invalid signer");
        
        require(!usedHashes[hash], "Already executed");
        usedHashes[hash] = true;
    }
}
```

---

### SIG-AP-03: Invalid v Value

**Severity:** Medium | **Likelihood:** Medium

**Description:**
ECDSA v value should be 27 or 28, but some implementations accept 0 or 1.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Inconsistent v handling
contract VulnerableVValue {
    function verify(
        bytes32 hash,
        bytes memory signature
    ) public pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Some chains/libraries use v = 0 or 1
        // Direct ecrecover expects 27 or 28
        return ecrecover(hash, v, r, s);  // May fail silently
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Normalize v value
contract SecureVValue {
    function verify(
        bytes32 hash,
        bytes memory signature
    ) public pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Normalize v
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid v");
        
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        
        return signer;
    }
}
```

---

### SIG-AP-04: Compact Signature Parsing

**Severity:** Medium | **Likelihood:** Medium

**Description:**
EIP-2098 compact signatures (64 bytes) require different parsing than standard (65 bytes).

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Only handles 65-byte signatures
contract VulnerableCompact {
    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        return ecrecover(hash, v, r, s);
        
        // Fails for 64-byte compact signatures
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle both formats
contract SecureCompact {
    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length == 65) {
            // Standard signature
            bytes32 r;
            bytes32 s;
            uint8 v;
            
            assembly {
                r := mload(add(signature, 32))
                s := mload(add(signature, 64))
                v := byte(0, mload(add(signature, 96)))
            }
            
            if (v < 27) v += 27;
            return ecrecover(hash, v, r, s);
            
        } else if (signature.length == 64) {
            // EIP-2098 compact signature
            bytes32 r;
            bytes32 vs;
            
            assembly {
                r := mload(add(signature, 32))
                vs := mload(add(signature, 64))
            }
            
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            
            return ecrecover(hash, v, r, s);
        }
        
        revert("Invalid signature length");
    }
}
```

---

### SIG-AP-05: Hash Collision in Signature

**Severity:** High | **Likelihood:** Low

**Description:**
Using keccak256 on unstructured data can lead to signature collisions.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Unstructured hash
contract VulnerableHashCollision {
    function verifyAction(
        address user,
        uint256 amount,
        bytes memory signature
    ) external {
        // Different (user, amount) pairs could hash to same value
        bytes32 hash = keccak256(abi.encodePacked(user, amount));
        
        // user = 0x0000...001, amount = 0x1000...000
        // vs
        // user = 0x0000...0011, amount = 0x000...000
        // Could collide with encodePacked!
        
        address signer = ECDSA.recover(hash, signature);
        require(signer == authorizedSigner, "Invalid");
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use abi.encode or EIP-712
contract SecureHashCollision {
    function verifyAction(
        address user,
        uint256 amount,
        bytes memory signature
    ) external {
        // abi.encode pads to 32 bytes, no collision
        bytes32 hash = keccak256(abi.encode(
            user,
            amount,
            address(this),
            block.chainid
        ));
        
        address signer = ECDSA.recover(hash, signature);
        require(signer == authorizedSigner, "Invalid");
    }
    
    // Better: Use EIP-712
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "Action(address user,uint256 amount)"
    );
    
    function verifyActionEIP712(
        address user,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            ACTION_TYPEHASH,
            user,
            amount
        ));
        
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        require(signer == authorizedSigner, "Invalid");
    }
}
```

---

### SIG-AP-06: Missing Message Prefix

**Severity:** High | **Likelihood:** Medium

**Description:**
Ethereum signed messages should include "\x19Ethereum Signed Message:\n" prefix to prevent transaction signing.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No message prefix
contract VulnerablePrefix {
    function verify(
        bytes memory message,
        bytes memory signature
    ) external view returns (bool) {
        // Raw hash - could be valid transaction hash!
        bytes32 hash = keccak256(message);
        
        address signer = ECDSA.recover(hash, signature);
        return signer == expectedSigner;
        
        // Attack: Trick user into signing transaction as "message"
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use eth_sign prefix or EIP-712
contract SecurePrefix {
    function verify(
        bytes memory message,
        bytes memory signature
    ) external view returns (bool) {
        // Add Ethereum signed message prefix
        bytes32 hash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n",
            Strings.toString(message.length),
            message
        ));
        
        address signer = ECDSA.recover(hash, signature);
        return signer == expectedSigner;
    }
    
    // Or use OpenZeppelin helper
    function verifyWithHelper(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bool) {
        bytes32 ethSignedHash = ECDSA.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(ethSignedHash, signature);
        return signer == expectedSigner;
    }
}
```

---

### SIG-AP-07: Signature Without Signer Binding

**Severity:** High | **Likelihood:** Medium

**Description:**
Signature doesn't bind to specific signer, allowing signature theft.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Signer not in signed data
contract VulnerableBinding {
    function executeOrder(
        address token,
        uint256 amount,
        uint256 price,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(token, amount, price));
        address signer = ECDSA.recover(hash, signature);
        
        // Anyone who intercepts signature can front-run
        // and claim they're the signer
        
        require(authorizedSigners[signer], "Not authorized");
        _executeOrder(signer, token, amount, price);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Include signer in hash
contract SecureBinding {
    function executeOrder(
        address maker,  // Explicit signer
        address token,
        uint256 amount,
        uint256 price,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(
            maker,  // Signer bound in message
            token,
            amount,
            price
        ));
        
        address signer = ECDSA.recover(hash, signature);
        require(signer == maker, "Invalid signer");
        require(authorizedSigners[maker], "Not authorized");
        
        _executeOrder(maker, token, amount, price);
    }
}
```

---

## Category 2: EIP-712 Issues

### SIG-AP-08: Missing Domain Separator

**Severity:** Critical | **Likelihood:** Medium

**Description:**
EIP-712 domain separator provides replay protection across contracts and chains.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No domain separator
contract VulnerableDomain {
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes memory signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonces[owner]++,
            deadline
        ));
        
        // No domain separator - signature valid on ALL contracts!
        address signer = ECDSA.recover(structHash, signature);
        require(signer == owner, "Invalid");
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Proper EIP-712 implementation
contract SecureDomain is EIP712 {
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    
    constructor() EIP712("TokenName", "1") {}
    
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes memory signature
    ) external {
        require(block.timestamp <= deadline, "Expired");
        
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonces[owner]++,
            deadline
        ));
        
        // EIP-712 typed data hash includes domain
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        require(signer == owner, "Invalid signature");
        
        _approve(owner, spender, value);
    }
    
    // Domain separator includes: name, version, chainId, verifyingContract
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
```

---

### SIG-AP-09: Cached Domain Separator on Chain Fork

**Severity:** High | **Likelihood:** Low

**Description:**
Cached domain separator doesn't update after chain fork, enabling cross-chain replay.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Immutable domain separator
contract VulnerableCachedDomain {
    bytes32 public immutable DOMAIN_SEPARATOR;
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Token"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
        // If chain forks, DOMAIN_SEPARATOR still has old chainId
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Recompute on chainId change
contract SecureCachedDomain {
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;
    
    constructor() {
        _HASHED_NAME = keccak256("Token");
        _HASHED_VERSION = keccak256("1");
        _TYPE_HASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
    }
    
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _buildDomainSeparator();
    }
    
    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(
            _TYPE_HASH,
            _HASHED_NAME,
            _HASHED_VERSION,
            block.chainid,
            address(this)
        ));
    }
}
```

---

### SIG-AP-10: Incorrect Type Hash

**Severity:** High | **Likelihood:** Medium

**Description:**
EIP-712 type hash must exactly match struct definition including nested types.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Type hash mismatch
contract VulnerableTypeHash {
    // Missing nested type encoding
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,address token,uint256 amount,OrderDetails details)"
        // Missing: "OrderDetails(uint256 price,uint256 expiry)"
    );
    
    struct Order {
        address maker;
        address token;
        uint256 amount;
        OrderDetails details;
    }
    
    struct OrderDetails {
        uint256 price;
        uint256 expiry;
    }
    
    function hashOrder(Order memory order) internal pure returns (bytes32) {
        // Hash computation doesn't match type hash
        return keccak256(abi.encode(
            ORDER_TYPEHASH,
            order.maker,
            order.token,
            order.amount,
            order.details.price,  // Wrong: should hash nested struct
            order.details.expiry
        ));
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Correct type encoding
contract SecureTypeHash {
    bytes32 public constant ORDER_DETAILS_TYPEHASH = keccak256(
        "OrderDetails(uint256 price,uint256 expiry)"
    );
    
    // Includes nested type definition
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,address token,uint256 amount,OrderDetails details)"
        "OrderDetails(uint256 price,uint256 expiry)"
    );
    
    function hashOrderDetails(OrderDetails memory details) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            ORDER_DETAILS_TYPEHASH,
            details.price,
            details.expiry
        ));
    }
    
    function hashOrder(Order memory order) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            ORDER_TYPEHASH,
            order.maker,
            order.token,
            order.amount,
            hashOrderDetails(order.details)  // Hash nested struct
        ));
    }
}
```

---

### SIG-AP-11: Dynamic Type Encoding

**Severity:** Medium | **Likelihood:** Medium

**Description:**
EIP-712 dynamic types (bytes, string, arrays) require special encoding.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Direct encoding of dynamic types
contract VulnerableDynamic {
    bytes32 public constant MESSAGE_TYPEHASH = keccak256(
        "Message(address sender,bytes data)"
    );
    
    function hashMessage(address sender, bytes memory data) internal pure returns (bytes32) {
        // Wrong: bytes should be hashed
        return keccak256(abi.encode(
            MESSAGE_TYPEHASH,
            sender,
            data  // Dynamic type encoded wrong
        ));
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Hash dynamic types
contract SecureDynamic {
    bytes32 public constant MESSAGE_TYPEHASH = keccak256(
        "Message(address sender,bytes data,string comment)"
    );
    
    function hashMessage(
        address sender,
        bytes memory data,
        string memory comment
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            MESSAGE_TYPEHASH,
            sender,
            keccak256(data),     // Hash bytes
            keccak256(bytes(comment))  // Hash string
        ));
    }
    
    // Arrays require encoding each element
    bytes32 public constant BATCH_TYPEHASH = keccak256(
        "Batch(uint256[] amounts)"
    );
    
    function hashBatch(uint256[] memory amounts) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            BATCH_TYPEHASH,
            keccak256(abi.encodePacked(amounts))  // Pack array
        ));
    }
}
```

---

### SIG-AP-12: Contract Address Not in Domain

**Severity:** High | **Likelihood:** Medium

**Description:**
Missing verifyingContract in domain allows signature reuse across contracts.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No verifyingContract
contract VulnerableNoDomain {
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId)"),
            keccak256("App"),
            keccak256("1"),
            block.chainid
            // Missing: address(this)
        ));
    }
    
    // Signature valid on any contract with same name/version
}
```

**Secure Pattern:**
```solidity
// SECURE: Include verifyingContract
contract SecureWithDomain {
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("App"),
            keccak256("1"),
            block.chainid,
            address(this)  // Contract bound
        ));
    }
}
```

---

### SIG-AP-13: Version Mismatch in Upgrades

**Severity:** Medium | **Likelihood:** Low

**Description:**
Domain version not updated after contract upgrade invalidates old signatures unintentionally.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Static version in upgradeable
contract VulnerableUpgradeable is EIP712Upgradeable {
    function initialize() external initializer {
        __EIP712_init("App", "1");  // Version hardcoded
    }
    
    // After upgrade, old signatures might need different behavior
    // But version is still "1"
}
```

**Secure Pattern:**
```solidity
// SECURE: Consider signature migration
contract SecureUpgradeable is EIP712Upgradeable {
    uint256 public signatureVersion;
    
    function initialize() external initializer {
        __EIP712_init("App", "1");
        signatureVersion = 1;
    }
    
    function upgradeSignatureVersion() external onlyOwner {
        // Re-initialize with new version
        signatureVersion++;
        // Properly handle domain separator update
    }
    
    // Track which version each signature uses
    mapping(bytes32 => uint256) public signatureVersionUsed;
}
```

---

### SIG-AP-14: Salt/Nonce Not in Struct

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Unique identifiers in domain but not struct allow signature reuse.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Nonce not in signed struct
contract VulnerableSaltMissing {
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "Action(address target,uint256 value)"
    );
    
    mapping(address => uint256) public nonces;
    
    function execute(
        address target,
        uint256 value,
        bytes memory signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            ACTION_TYPEHASH,
            target,
            value
            // Nonce not included!
        ));
        
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        
        // Increment nonce but it's not verified
        nonces[signer]++;  // Useless
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Nonce in signed struct
contract SecureWithNonce {
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "Action(address target,uint256 value,uint256 nonce)"
    );
    
    mapping(address => uint256) public nonces;
    
    function execute(
        address target,
        uint256 value,
        uint256 nonce,
        bytes memory signature
    ) external {
        require(nonce == nonces[msg.sender], "Invalid nonce");
        
        bytes32 structHash = keccak256(abi.encode(
            ACTION_TYPEHASH,
            target,
            value,
            nonce  // Nonce included in signature
        ));
        
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        
        nonces[signer]++;
    }
}
```

---

### SIG-AP-15: Missing EIP-712 Version

**Severity:** Low | **Likelihood:** Low

**Description:**
Domain missing version field complicates future upgrades.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No version
contract VulnerableNoVersion {
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("App"),
            // No version!
            block.chainid,
            address(this)
        ));
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Include version
contract SecureWithVersion {
    string public constant VERSION = "1";
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("App"),
            keccak256(bytes(VERSION)),
            block.chainid,
            address(this)
        ));
    }
}
```

---

## Category 3: Replay Attacks

### SIG-AP-16: Missing Nonce

**Severity:** Critical | **Likelihood:** High

**Description:**
Without nonce, same signature can be replayed multiple times.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No nonce
contract VulnerableNoNonce {
    function executeWithSignature(
        address to,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(to, amount));
        address signer = ECDSA.recover(hash, signature);
        
        require(signer == authorizedSigner, "Invalid");
        
        // Same signature works forever!
        token.transfer(to, amount);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Nonce tracking
contract SecureWithNonce {
    mapping(address => uint256) public nonces;
    
    function executeWithSignature(
        address to,
        uint256 amount,
        bytes memory signature
    ) external {
        uint256 nonce = nonces[authorizedSigner];
        
        bytes32 hash = keccak256(abi.encode(to, amount, nonce));
        address signer = ECDSA.recover(hash, signature);
        
        require(signer == authorizedSigner, "Invalid");
        
        nonces[authorizedSigner]++;  // Increment nonce
        token.transfer(to, amount);
    }
}
```

---

### SIG-AP-17: Nonce Not Incremented

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Nonce checked but not incremented allows replay.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Nonce not incremented
contract VulnerableNonceNotIncremented {
    mapping(address => uint256) public nonces;
    
    function execute(
        uint256 nonce,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(msg.sender, nonce));
        address signer = ECDSA.recover(hash, signature);
        
        require(nonce >= nonces[signer], "Old nonce");
        // Never incremented! Same nonce works forever
        
        _execute();
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Always increment
contract SecureNonceIncrement {
    mapping(address => uint256) public nonces;
    
    function execute(
        uint256 nonce,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(msg.sender, nonce));
        address signer = ECDSA.recover(hash, signature);
        
        require(nonce == nonces[signer], "Invalid nonce");
        nonces[signer]++;  // MUST increment
        
        _execute();
    }
    
    // Alternative: Use bitmap for non-sequential nonces
    mapping(address => mapping(uint256 => uint256)) public noncesBitmap;
    
    function executeNonSequential(uint256 nonce, bytes memory signature) external {
        uint256 wordIndex = nonce / 256;
        uint256 bitIndex = nonce % 256;
        uint256 word = noncesBitmap[msg.sender][wordIndex];
        uint256 bit = 1 << bitIndex;
        
        require(word & bit == 0, "Nonce used");
        noncesBitmap[msg.sender][wordIndex] = word | bit;
        
        // Continue with verification...
    }
}
```

---

### SIG-AP-18: Cross-Chain Replay

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Signature valid on one chain replayed on another (especially after forks).

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No chain ID
contract VulnerableCrossChain {
    function permit(
        address owner,
        address spender,
        uint256 value,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(
            owner,
            spender,
            value,
            nonces[owner]++
            // No chainId!
        ));
        
        address signer = ECDSA.recover(hash, signature);
        require(signer == owner, "Invalid");
        
        // Signature from mainnet works on all EVM chains!
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Include chain ID
contract SecureChainId {
    function permit(
        address owner,
        address spender,
        uint256 value,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(
            owner,
            spender,
            value,
            nonces[owner]++,
            block.chainid,  // Chain-specific
            address(this)   // Contract-specific
        ));
        
        address signer = ECDSA.recover(hash, signature);
        require(signer == owner, "Invalid");
    }
    
    // Better: Use EIP-712 which includes chainId in domain
}
```

---

### SIG-AP-19: Missing Deadline

**Severity:** High | **Likelihood:** High

**Description:**
Signatures without expiration remain valid forever.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No deadline
contract VulnerableNoDeadline {
    function executeOrder(
        uint256 price,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(price, amount));
        address signer = ECDSA.recover(hash, signature);
        
        // Order from 2 years ago still valid!
        // Price has changed dramatically
        
        require(signer == maker, "Invalid");
        _fillOrder(price, amount);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Enforce deadline
contract SecureWithDeadline {
    function executeOrder(
        uint256 price,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external {
        require(block.timestamp <= deadline, "Signature expired");
        
        bytes32 hash = keccak256(abi.encode(
            price,
            amount,
            deadline  // Deadline in signed data
        ));
        
        address signer = ECDSA.recover(hash, signature);
        require(signer == maker, "Invalid");
        
        _fillOrder(price, amount);
    }
}
```

---

### SIG-AP-20: Signature Hash Replay

**Severity:** High | **Likelihood:** Medium

**Description:**
Tracking signature hash instead of message hash allows malleable replay.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Track signature hash
contract VulnerableSignatureHash {
    mapping(bytes32 => bool) public usedSignatures;
    
    function execute(bytes32 messageHash, bytes memory signature) external {
        bytes32 sigHash = keccak256(signature);
        require(!usedSignatures[sigHash], "Used");
        
        address signer = ECDSA.recover(messageHash, signature);
        require(signer == authorizedSigner, "Invalid");
        
        usedSignatures[sigHash] = true;
        
        // Malleable signature bypasses!
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Track message hash
contract SecureMessageHash {
    mapping(bytes32 => bool) public executedMessages;
    
    function execute(bytes32 messageHash, bytes memory signature) external {
        require(!executedMessages[messageHash], "Already executed");
        
        // Use OZ ECDSA which handles malleability
        address signer = ECDSA.recover(messageHash, signature);
        require(signer == authorizedSigner, "Invalid");
        
        executedMessages[messageHash] = true;
        
        // Any malleable variant of signature still same messageHash
    }
}
```

---

### SIG-AP-21: Contract Upgrade Replay

**Severity:** Medium | **Likelihood:** Low

**Description:**
After proxy upgrade, old signatures may have different meaning.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Upgrade changes signature meaning
contract VulnerableUpgradeReplay is Initializable {
    // V1: Action struct has 2 fields
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "Action(address target,uint256 value)"
    );
    
    // After upgrade to V2, ACTION_TYPEHASH is same but
    // meaning changed (value is now in different units)
    
    // Old signatures still valid but misinterpreted
}
```

**Secure Pattern:**
```solidity
// SECURE: Version in signature
contract SecureUpgradeVersion is Initializable {
    uint256 public constant SIGNATURE_VERSION = 1;
    
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "Action(address target,uint256 value,uint256 sigVersion)"
    );
    
    function execute(
        address target,
        uint256 value,
        uint256 sigVersion,
        bytes memory signature
    ) external {
        require(sigVersion == SIGNATURE_VERSION, "Wrong version");
        
        bytes32 hash = keccak256(abi.encode(
            ACTION_TYPEHASH,
            target,
            value,
            sigVersion
        ));
        
        // After upgrade, increment SIGNATURE_VERSION
        // Old signatures automatically invalid
    }
}
```

---

### SIG-AP-22: Block-Based Replay Window

**Severity:** Medium | **Likelihood:** Low

**Description:**
Using block number for replay protection has reorg vulnerabilities.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Block-based expiry
contract VulnerableBlockExpiry {
    function execute(
        uint256 validUntilBlock,
        bytes memory signature
    ) external {
        require(block.number <= validUntilBlock, "Expired");
        
        bytes32 hash = keccak256(abi.encode(validUntilBlock));
        address signer = ECDSA.recover(hash, signature);
        
        // After reorg, block numbers change
        // Signature could be valid again
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use timestamp or nonce
contract SecureExpiry {
    mapping(address => uint256) public nonces;
    
    function execute(
        uint256 deadline,  // Timestamp, not block
        uint256 nonce,
        bytes memory signature
    ) external {
        require(block.timestamp <= deadline, "Expired");
        require(nonce == nonces[msg.sender], "Invalid nonce");
        
        bytes32 hash = keccak256(abi.encode(deadline, nonce));
        address signer = ECDSA.recover(hash, signature);
        
        nonces[signer]++;  // Nonce prevents replay regardless of reorg
    }
}
```

---

## Category 4: Permit & Meta-Transaction Anti-Patterns

### SIG-AP-23: Permit Front-Running

**Severity:** High | **Likelihood:** High

**Description:**
Permit signatures can be front-run to grief users.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Permit can be front-run
contract VulnerablePermitFrontRun {
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Attacker front-runs with same permit signature
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        
        // User's tx now fails because nonce incremented
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle permit failure gracefully
contract SecurePermitHandling {
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Try permit, but don't fail if it reverts
        try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {
            // Permit succeeded
        } catch {
            // Permit failed - maybe already approved or front-run
            // Continue anyway if allowance sufficient
        }
        
        // This works if permit succeeded OR user pre-approved
        require(
            token.allowance(msg.sender, address(this)) >= amount,
            "Insufficient allowance"
        );
        
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

---

### SIG-AP-24: Permit2 Allowance Drain

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Permit2's approval model allows draining if signature is leaked.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Permit2 with max approval
contract VulnerablePermit2 {
    IPermit2 public permit2;
    
    function swapWithPermit2(
        address token,
        uint256 amount,
        IPermit2.PermitSingle calldata permitSingle,
        bytes calldata signature
    ) external {
        // User signs max approval for convenience
        // permitSingle.details.amount = type(uint160).max
        
        permit2.permit(msg.sender, permitSingle, signature);
        
        // If this contract is malicious or compromised,
        // can drain entire token balance
    }
}
```

**Real Exploits:**
- **Socket Bridge (2024):** $3.3M drained via Permit2 approval

**Secure Pattern:**
```solidity
// SECURE: Bounded Permit2 usage
contract SecurePermit2 {
    IPermit2 public permit2;
    
    function swapWithPermit2(
        address token,
        uint256 amount,
        IPermit2.PermitSingle calldata permitSingle,
        bytes calldata signature
    ) external {
        // Validate permit matches expected amount
        require(permitSingle.details.amount == amount, "Amount mismatch");
        
        // Validate short expiration
        require(
            permitSingle.details.expiration <= block.timestamp + 1 hours,
            "Expiration too long"
        );
        
        permit2.permit(msg.sender, permitSingle, signature);
        
        // Use permit transfer (single use)
        permit2.transferFrom(
            msg.sender,
            address(this),
            uint160(amount),
            token
        );
    }
    
    // Better: Use SignatureTransfer for single-use permits
    function swapWithSignatureTransfer(
        IPermit2.PermitTransferFrom calldata permit,
        IPermit2.SignatureTransferDetails calldata transferDetails,
        bytes calldata signature
    ) external {
        // SignatureTransfer is single-use by design
        permit2.permitTransferFrom(
            permit,
            transferDetails,
            msg.sender,
            signature
        );
    }
}
```

---

### SIG-AP-25: Meta-Transaction Gas Griefing

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Relayer can manipulate gas to make inner call fail while consuming user's nonce.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No gas check
contract VulnerableMetaTx {
    function executeMetaTx(
        address from,
        bytes calldata data,
        bytes calldata signature
    ) external returns (bytes memory) {
        // Verify signature over (from, data, nonce)
        require(verify(from, data, nonces[from], signature), "Invalid");
        nonces[from]++;
        
        // Relayer forwards with insufficient gas
        (bool success, bytes memory result) = address(this).call(
            abi.encodePacked(data, from)
        );
        
        // Call fails due to OOG, but nonce already incremented
        // User's signed transaction is wasted
        
        return result;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Gas stipend requirement
contract SecureMetaTx {
    function executeMetaTx(
        address from,
        bytes calldata data,
        uint256 gasLimit,  // User specifies required gas
        bytes calldata signature
    ) external returns (bytes memory) {
        // Gas limit included in signature
        require(verify(from, data, nonces[from], gasLimit, signature), "Invalid");
        
        // Check sufficient gas
        require(gasleft() >= gasLimit + 50000, "Insufficient gas");
        
        nonces[from]++;
        
        (bool success, bytes memory result) = address(this).call{gas: gasLimit}(
            abi.encodePacked(data, from)
        );
        
        require(success, "Execution failed");
        return result;
    }
}
```

---

### SIG-AP-26: Permit Deadline Manipulation

**Severity:** Medium | **Likelihood:** Low

**Description:**
Permit with far-future deadline creates lingering approval risk.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Unlimited deadline accepted
contract VulnerablePermitDeadline {
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,  // Could be type(uint256).max
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
        
        // Approval remains forever
        // If contract is compromised later, can steal funds
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Enforce reasonable deadline
contract SecurePermitDeadline {
    uint256 public constant MAX_DEADLINE_DURATION = 1 hours;
    
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(
            deadline <= block.timestamp + MAX_DEADLINE_DURATION,
            "Deadline too far"
        );
        
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
        
        // Reset approval after use
        token.approve(msg.sender, 0);
    }
}
```

---

### SIG-AP-27: ERC20Permit Missing on Token

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Assuming token supports permit when it doesn't causes transaction failure.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Assumes permit support
contract VulnerableAssumePermit {
    function depositWithPermit(
        IERC20Permit token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Reverts if token doesn't support permit
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        IERC20(address(token)).transferFrom(msg.sender, address(this), amount);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Check permit support
contract SecurePermitCheck {
    function supportsPermit(address token) public view returns (bool) {
        try IERC20Permit(token).DOMAIN_SEPARATOR() returns (bytes32) {
            return true;
        } catch {
            return false;
        }
    }
    
    function depositWithPermit(
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (supportsPermit(token)) {
            try IERC20Permit(token).permit(
                msg.sender, address(this), amount, deadline, v, r, s
            ) {} catch {
                // Permit failed, continue if already approved
            }
        }
        
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
```

---

### SIG-AP-28: DAI-Style Permit Incompatibility

**Severity:** Medium | **Likelihood:** Medium

**Description:**
DAI uses non-standard permit with `allowed` bool instead of `value`.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Assumes standard permit
contract VulnerableDaiPermit {
    function depositDai(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // DAI permit signature: permit(holder, spender, nonce, expiry, allowed, v, r, s)
        // Standard permit: permit(owner, spender, value, deadline, v, r, s)
        
        // This will fail or produce wrong result
        IERC20Permit(DAI).permit(msg.sender, address(this), amount, deadline, v, r, s);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle DAI-style permit
interface IDaiPermit {
    function permit(
        address holder,
        address spender,
        uint256 nonce,
        uint256 expiry,
        bool allowed,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

contract SecureDaiPermit {
    address public constant DAI = 0x6B175474E89094C44Da98b954EescdeCB5f;
    
    function depositDai(
        uint256 amount,
        uint256 nonce,
        uint256 expiry,
        bool allowed,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        IDaiPermit(DAI).permit(
            msg.sender,
            address(this),
            nonce,
            expiry,
            allowed,
            v,
            r,
            s
        );
        
        IERC20(DAI).transferFrom(msg.sender, address(this), amount);
    }
}
```

---

### SIG-AP-29: Trusted Forwarder Bypass

**Severity:** High | **Likelihood:** Low

**Description:**
ERC2771 meta-transaction forwarders can be abused if trust is misplaced.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Trusts any forwarder
contract VulnerableForwarder is ERC2771Context {
    mapping(address => bool) public trustedForwarders;
    
    function setTrustedForwarder(address forwarder) external onlyOwner {
        trustedForwarders[forwarder] = true;
    }
    
    function isTrustedForwarder(address forwarder) public view override returns (bool) {
        return trustedForwarders[forwarder];
    }
    
    function sensitiveAction() external {
        address sender = _msgSender();  // Could be spoofed by malicious forwarder
        require(sender == admin, "Not admin");
        // ...
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Single trusted forwarder
contract SecureForwarder is ERC2771Context {
    address public immutable trustedForwarder;
    
    constructor(address _trustedForwarder) ERC2771Context(_trustedForwarder) {
        trustedForwarder = _trustedForwarder;
    }
    
    function isTrustedForwarder(address forwarder) public view override returns (bool) {
        return forwarder == trustedForwarder;
    }
    
    // Extra: Validate forwarder is legitimate contract
    modifier onlyTrustedForwarder() {
        require(msg.sender == trustedForwarder, "Not trusted forwarder");
        _;
    }
}
```

---

## Category 5: Multi-Signature Anti-Patterns

### SIG-AP-30: Threshold Not Enforced

**Severity:** Critical | **Likelihood:** Low

**Description:**
Multi-sig threshold can be bypassed through improper validation.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Threshold check bypassable
contract VulnerableThreshold {
    uint256 public threshold;
    
    function execute(
        bytes32 txHash,
        bytes[] memory signatures
    ) external {
        require(signatures.length >= threshold, "Not enough sigs");
        
        address lastSigner = address(0);
        for (uint i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(txHash, signatures[i]);
            require(isOwner[signer], "Not owner");
            require(signer > lastSigner, "Duplicate signer");
            lastSigner = signer;
        }
        
        // BUG: If threshold = 3 but only 2 valid signatures provided
        // and one signature is from non-owner, loop might not catch it
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Proper threshold enforcement
contract SecureThreshold {
    uint256 public threshold;
    
    function execute(
        bytes32 txHash,
        bytes[] memory signatures
    ) external {
        require(signatures.length >= threshold, "Not enough sigs");
        
        address lastSigner = address(0);
        uint256 validSignatures = 0;
        
        for (uint i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(txHash, signatures[i]);
            
            // Must be owner
            require(isOwner[signer], "Not owner");
            
            // Must be sorted (prevents duplicates)
            require(signer > lastSigner, "Invalid order");
            lastSigner = signer;
            
            validSignatures++;
        }
        
        // Explicit threshold check
        require(validSignatures >= threshold, "Threshold not met");
    }
}
```

---

### SIG-AP-31: Duplicate Signer

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Same signer can provide multiple signatures to meet threshold.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No duplicate check
contract VulnerableDuplicate {
    function execute(
        bytes32 txHash,
        bytes[] memory signatures
    ) external {
        require(signatures.length >= threshold, "Not enough");
        
        for (uint i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(txHash, signatures[i]);
            require(isOwner[signer], "Not owner");
            // Same signer can sign multiple times!
        }
        
        _execute();
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Track used signers
contract SecureNoDuplicate {
    function execute(
        bytes32 txHash,
        bytes[] memory signatures
    ) external {
        require(signatures.length >= threshold, "Not enough");
        
        address[] memory signers = new address[](signatures.length);
        
        for (uint i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(txHash, signatures[i]);
            require(isOwner[signer], "Not owner");
            
            // Check against all previous signers
            for (uint j = 0; j < i; j++) {
                require(signer != signers[j], "Duplicate signer");
            }
            
            signers[i] = signer;
        }
        
        _execute();
    }
    
    // Better: Require sorted signatures (Gnosis Safe style)
    function executeSorted(
        bytes32 txHash,
        bytes memory packedSignatures
    ) external {
        address lastSigner = address(0);
        uint256 count = packedSignatures.length / 65;
        
        for (uint i = 0; i < count; i++) {
            (address signer, ) = signatureSplit(packedSignatures, i);
            require(signer > lastSigner, "Invalid order");  // Sorted = no duplicates
            require(isOwner[signer], "Not owner");
            lastSigner = signer;
        }
        
        require(count >= threshold, "Threshold not met");
    }
}
```

---

### SIG-AP-32: Transaction Hash Reuse

**Severity:** High | **Likelihood:** Medium

**Description:**
Multi-sig transaction hash doesn't include nonce, allowing replay.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No nonce in hash
contract VulnerableTxHash {
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        bytes[] memory signatures
    ) external {
        bytes32 txHash = keccak256(abi.encode(to, value, data));
        
        // Verify signatures...
        
        // Same (to, value, data) can be executed multiple times
        (bool success, ) = to.call{value: value}(data);
        require(success, "Execution failed");
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Nonce in transaction hash
contract SecureTxHash {
    uint256 public nonce;
    
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        bytes[] memory signatures
    ) external {
        bytes32 txHash = keccak256(abi.encode(
            to,
            value,
            data,
            nonce,
            block.chainid,
            address(this)
        ));
        
        // Verify signatures...
        
        nonce++;  // Increment after successful verification
        
        (bool success, ) = to.call{value: value}(data);
        require(success, "Execution failed");
    }
}
```

---

### SIG-AP-33: Timelock Bypass

**Severity:** High | **Likelihood:** Low

**Description:**
Multi-sig with timelock can be bypassed by changing owners during delay.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Owner change during timelock
contract VulnerableTimelock {
    uint256 public constant DELAY = 2 days;
    
    struct QueuedTx {
        bytes32 txHash;
        uint256 executeAfter;
    }
    
    mapping(uint256 => QueuedTx) public queue;
    
    function queueTransaction(bytes32 txHash, bytes[] memory signatures) external {
        // Verify signatures from current owners
        verifySignatures(txHash, signatures);
        
        queue[nonce++] = QueuedTx({
            txHash: txHash,
            executeAfter: block.timestamp + DELAY
        });
    }
    
    function executeTransaction(uint256 txId) external {
        require(block.timestamp >= queue[txId].executeAfter, "Timelock");
        
        // Owners might have changed during delay!
        // Malicious new owner could execute
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Re-verify or lock owners
contract SecureTimelock {
    uint256 public constant DELAY = 2 days;
    
    struct QueuedTx {
        bytes32 txHash;
        uint256 executeAfter;
        bytes[] signatures;  // Store signatures
    }
    
    function queueTransaction(bytes32 txHash, bytes[] memory signatures) external {
        verifySignatures(txHash, signatures);
        
        queue[nonce++] = QueuedTx({
            txHash: txHash,
            executeAfter: block.timestamp + DELAY,
            signatures: signatures
        });
    }
    
    function executeTransaction(uint256 txId) external {
        QueuedTx storage qtx = queue[txId];
        require(block.timestamp >= qtx.executeAfter, "Timelock");
        
        // Re-verify with current owners
        verifySignatures(qtx.txHash, qtx.signatures);
        
        // Execute...
    }
    
    // Alternative: Lock owner changes during pending transactions
}
```

---

### SIG-AP-34: Signature Aggregation Order

**Severity:** Medium | **Likelihood:** Low

**Description:**
BLS or aggregate signature schemes have ordering requirements.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Wrong aggregation order
contract VulnerableAggregation {
    function verifyAggregate(
        bytes32[] memory messages,
        bytes memory aggregateSig,
        address[] memory signers
    ) external view returns (bool) {
        // Order of messages must match order of signers
        // If arrays are reordered, verification fails or accepts wrong data
        
        return BLS.verifyAggregate(messages, aggregateSig, signers);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Enforce ordering
contract SecureAggregation {
    function verifyAggregate(
        bytes32[] memory messages,
        bytes memory aggregateSig,
        address[] memory signers
    ) external view returns (bool) {
        // Verify arrays are same length
        require(messages.length == signers.length, "Length mismatch");
        
        // Verify signers are sorted
        for (uint i = 1; i < signers.length; i++) {
            require(signers[i] > signers[i-1], "Not sorted");
        }
        
        // Sort messages to match signer order
        bytes32[] memory sortedMessages = sortMessagesBySigners(messages, signers);
        
        return BLS.verifyAggregate(sortedMessages, aggregateSig, signers);
    }
}
```

---

### SIG-AP-35: Guardian Recovery Abuse

**Severity:** High | **Likelihood:** Low

**Description:**
Social recovery mechanisms can be abused if guardians collude.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Instant guardian recovery
contract VulnerableRecovery {
    mapping(address => bool) public guardians;
    uint256 public guardianThreshold;
    
    function recoverWallet(
        address newOwner,
        bytes[] memory guardianSignatures
    ) external {
        bytes32 hash = keccak256(abi.encode("recover", newOwner));
        
        uint256 validSigs = 0;
        for (uint i = 0; i < guardianSignatures.length; i++) {
            address signer = ECDSA.recover(hash, guardianSignatures[i]);
            if (guardians[signer]) validSigs++;
        }
        
        require(validSigs >= guardianThreshold, "Not enough guardians");
        
        // Instant recovery - no time for owner to react
        owner = newOwner;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Delayed recovery with cancellation
contract SecureRecovery {
    uint256 public constant RECOVERY_DELAY = 3 days;
    
    struct RecoveryRequest {
        address newOwner;
        uint256 executeAfter;
        bool cancelled;
    }
    
    RecoveryRequest public pendingRecovery;
    
    function initiateRecovery(
        address newOwner,
        bytes[] memory guardianSignatures
    ) external {
        // Verify guardian signatures...
        
        pendingRecovery = RecoveryRequest({
            newOwner: newOwner,
            executeAfter: block.timestamp + RECOVERY_DELAY,
            cancelled: false
        });
        
        emit RecoveryInitiated(newOwner, block.timestamp + RECOVERY_DELAY);
    }
    
    function cancelRecovery() external {
        require(msg.sender == owner, "Only owner");
        pendingRecovery.cancelled = true;
        emit RecoveryCancelled();
    }
    
    function executeRecovery() external {
        require(!pendingRecovery.cancelled, "Cancelled");
        require(block.timestamp >= pendingRecovery.executeAfter, "Too early");
        
        owner = pendingRecovery.newOwner;
        delete pendingRecovery;
    }
}
```

---

## Category 6: Key Management Anti-Patterns

### SIG-AP-36: Predictable Key Derivation

**Severity:** Critical | **Likelihood:** Low

**Description:**
Keys derived from predictable sources can be compromised.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Predictable derivation
contract VulnerableKeyDerivation {
    function generateKey(address user) internal view returns (bytes32) {
        // All inputs are public!
        return keccak256(abi.encode(
            user,
            block.timestamp,  // Predictable
            block.number      // Predictable
        ));
    }
    
    function createAccount() external {
        bytes32 key = generateKey(msg.sender);
        // Key can be computed by attacker
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use commitment scheme
contract SecureKeyDerivation {
    mapping(address => bytes32) public commitments;
    
    // Step 1: User commits hash of secret
    function commitKey(bytes32 commitment) external {
        require(commitments[msg.sender] == bytes32(0), "Already committed");
        commitments[msg.sender] = commitment;
    }
    
    // Step 2: User reveals secret (in later block)
    function revealKey(bytes32 secret) external {
        require(
            keccak256(abi.encode(secret)) == commitments[msg.sender],
            "Invalid reveal"
        );
        
        // Key derived from user-provided secret
        bytes32 key = keccak256(abi.encode(
            msg.sender,
            secret,
            blockhash(block.number - 1)  // Add some entropy
        ));
        
        // Use key...
    }
}
```

---

### SIG-AP-37: Key Stored On-Chain

**Severity:** Critical | **Likelihood:** Low

**Description:**
Private keys or secrets stored on-chain are publicly visible.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Secret on-chain
contract VulnerableKeyStorage {
    bytes32 private secretKey;  // "private" doesn't mean hidden!
    
    constructor(bytes32 _key) {
        secretKey = _key;  // Visible in deployment tx
    }
    
    function verify(bytes32 key) external view returns (bool) {
        return key == secretKey;  // Anyone can read storage
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Store commitment, not secret
contract SecureKeyStorage {
    bytes32 public keyCommitment;  // Hash of secret
    
    constructor(bytes32 _commitment) {
        keyCommitment = _commitment;
    }
    
    function verify(bytes32 key) external view returns (bool) {
        return keccak256(abi.encode(key)) == keyCommitment;
    }
    
    // Or: Use zero-knowledge proofs for verification
}
```

---

### SIG-AP-38: Single Point of Key Failure

**Severity:** High | **Likelihood:** Medium

**Description:**
Single compromised key leads to complete system compromise.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single admin key
contract VulnerableSingleKey {
    address public admin;
    
    function emergencyWithdraw() external {
        require(msg.sender == admin, "Not admin");
        // If admin key compromised, all funds lost
        payable(admin).transfer(address(this).balance);
    }
    
    function setAdmin(address newAdmin) external {
        require(msg.sender == admin, "Not admin");
        // No recovery if admin key lost
        admin = newAdmin;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Multi-key with timelocks
contract SecureMultiKey {
    address public admin;
    address public guardian;
    uint256 public constant TIMELOCK = 2 days;
    
    struct PendingAction {
        bytes32 actionHash;
        uint256 executeAfter;
    }
    
    PendingAction public pendingAdminChange;
    
    function proposeAdminChange(address newAdmin) external {
        require(msg.sender == admin || msg.sender == guardian, "Not authorized");
        
        pendingAdminChange = PendingAction({
            actionHash: keccak256(abi.encode("setAdmin", newAdmin)),
            executeAfter: block.timestamp + TIMELOCK
        });
    }
    
    function executeAdminChange(address newAdmin) external {
        require(
            keccak256(abi.encode("setAdmin", newAdmin)) == pendingAdminChange.actionHash,
            "Wrong action"
        );
        require(block.timestamp >= pendingAdminChange.executeAfter, "Timelock");
        
        admin = newAdmin;
        delete pendingAdminChange;
    }
    
    // Guardian can cancel malicious changes
    function cancelPending() external {
        require(msg.sender == guardian, "Not guardian");
        delete pendingAdminChange;
    }
}
```

---

### SIG-AP-39: No Key Rotation

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Inability to rotate keys increases risk from long-term exposure.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Immutable signer
contract VulnerableNoRotation {
    address public immutable signer;
    
    constructor(address _signer) {
        signer = _signer;
        // Can never be changed!
    }
    
    function verify(bytes memory signature) external view {
        address recovered = ECDSA.recover(hash, signature);
        require(recovered == signer, "Invalid");
        // If signer key compromised, contract is permanently vulnerable
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Key rotation support
contract SecureKeyRotation {
    address public currentSigner;
    address public pendingSigner;
    uint256 public signerChangeTime;
    uint256 public constant ROTATION_DELAY = 1 days;
    
    event SignerRotationInitiated(address newSigner, uint256 effectiveTime);
    event SignerRotated(address oldSigner, address newSigner);
    
    function initiateSkerRotation(address newSigner) external {
        require(msg.sender == currentSigner, "Not current signer");
        require(newSigner != address(0), "Zero address");
        
        pendingSigner = newSigner;
        signerChangeTime = block.timestamp + ROTATION_DELAY;
        
        emit SignerRotationInitiated(newSigner, signerChangeTime);
    }
    
    function completesignerRotation() external {
        require(pendingSigner != address(0), "No pending rotation");
        require(block.timestamp >= signerChangeTime, "Too early");
        
        emit SignerRotated(currentSigner, pendingSigner);
        
        currentSigner = pendingSigner;
        pendingSigner = address(0);
        signerChangeTime = 0;
    }
    
    function cancelRotation() external {
        require(msg.sender == currentSigner, "Not current signer");
        pendingSigner = address(0);
        signerChangeTime = 0;
    }
}
```

---

### SIG-AP-40: Compromised Key No Revocation

**Severity:** High | **Likelihood:** Medium

**Description:**
No mechanism to revoke compromised signing keys.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No revocation
contract VulnerableNoRevocation {
    mapping(address => bool) public authorizedSigners;
    
    function addSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
    }
    
    // No way to remove signer!
    // Once compromised, attacker has permanent access
    
    function verify(bytes memory signature) external view returns (bool) {
        address signer = ECDSA.recover(hash, signature);
        return authorizedSigners[signer];
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Key revocation support
contract SecureWithRevocation {
    mapping(address => bool) public authorizedSigners;
    mapping(address => uint256) public signerAddedAt;
    mapping(bytes32 => bool) public revokedSignatures;
    
    event SignerAdded(address signer);
    event SignerRemoved(address signer);
    event SignatureRevoked(bytes32 signatureHash);
    
    function addSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
        signerAddedAt[signer] = block.timestamp;
        emit SignerAdded(signer);
    }
    
    function removeSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = false;
        emit SignerRemoved(signer);
    }
    
    // Revoke specific signature (in case of leak)
    function revokeSignature(bytes32 signatureHash) external onlyOwner {
        revokedSignatures[signatureHash] = true;
        emit SignatureRevoked(signatureHash);
    }
    
    function verify(
        bytes32 messageHash,
        bytes memory signature,
        uint256 signedAt  // When signature was created
    ) external view returns (bool) {
        // Check signature not revoked
        bytes32 sigHash = keccak256(signature);
        if (revokedSignatures[sigHash]) return false;
        
        address signer = ECDSA.recover(messageHash, signature);
        
        // Check signer authorized
        if (!authorizedSigners[signer]) return false;
        
        // Check signature created after signer was added
        if (signedAt < signerAddedAt[signer]) return false;
        
        return true;
    }
}
```

---

## Audit Checklist Summary

### ECDSA
- [ ] ecrecover return checked for address(0)
- [ ] Signature malleability handled (lower-s)
- [ ] v value validated (27 or 28)
- [ ] Compact signatures supported if needed
- [ ] Message prefix used for eth_sign
- [ ] Signer bound in signed data

### EIP-712
- [ ] Domain separator includes all fields
- [ ] Domain separator recomputed on chainId change
- [ ] Type hash matches struct exactly
- [ ] Nested types encoded correctly
- [ ] Dynamic types hashed (bytes, string, arrays)
- [ ] verifyingContract in domain

### Replay Protection
- [ ] Nonce used and incremented
- [ ] Chain ID in signature
- [ ] Deadline enforced
- [ ] Message hash tracked (not signature hash)

### Permit & Meta-Tx
- [ ] Permit front-running handled
- [ ] Permit2 amounts bounded
- [ ] Gas griefing prevented
- [ ] Deadline reasonable
- [ ] DAI-style permit supported if needed

### Multi-Sig
- [ ] Threshold properly enforced
- [ ] No duplicate signers
- [ ] Transaction nonce used
- [ ] Timelock cannot be bypassed

### Key Management
- [ ] Keys not derived predictably
- [ ] Secrets not stored on-chain
- [ ] Multi-key architecture
- [ ] Key rotation supported
- [ ] Revocation mechanism exists

---

## References

- [OpenZeppelin ECDSA](https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [EIP-2612 (Permit)](https://eips.ethereum.org/EIPS/eip-2612)
- [Permit2](https://github.com/Uniswap/permit2)
- [Safe (Gnosis) Contracts](https://github.com/safe-global/safe-contracts)

---

## Related Documents

- [intent-based-attack-tree.md](../attack-trees/intent-based-attack-tree.md)
- [permit-patterns.md](../patterns/permit-patterns.md)
- [access-control-anti-patterns.md](access-control-anti-patterns.md)
