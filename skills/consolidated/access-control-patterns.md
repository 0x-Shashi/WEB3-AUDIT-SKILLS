# Consolidated: Access Control Patterns

## Overview

Access control vulnerabilities are among the most exploited in smart contracts. This document consolidates all access control anti-patterns, correct patterns, and real-world exploits.

---

## Anti-Patterns (Vulnerable)

### 1. Missing Access Control
```solidity
// [VULNERABLE] No access restriction
function mint(address to, uint256 amount) external {
    _mint(to, amount);  // Anyone can mint tokens!
}

// [VULNERABLE] Withdraw without owner check
function withdrawAll() external {
    payable(msg.sender).transfer(address(this).balance);
}
```

### 2. tx.origin Authentication
```solidity
// [VULNERABLE] tx.origin can be phished
function transfer(address to, uint256 amount) external {
    require(tx.origin == owner);  // Phishing attack possible!
    token.transfer(to, amount);
}
// Attack: Owner calls attacker's contract, which calls this function
// tx.origin is still the owner, so the check passes
```

### 3. Single-Step Ownership Transfer
```solidity
// [VULNERABLE] Typo in address = permanent loss of ownership
function transferOwnership(address newOwner) external onlyOwner {
    owner = newOwner;  // If wrong address, ownership lost forever
}

// [SAFE] Two-step transfer
function transferOwnership(address newOwner) external onlyOwner {
    pendingOwner = newOwner;
}
function acceptOwnership() external {
    require(msg.sender == pendingOwner);
    owner = msg.sender;
}
```

### 4. Unprotected Initializer
```solidity
// [VULNERABLE] Initialize can be called by anyone after deployment
function initialize(address _owner) external {
    owner = _owner;  // No check if already initialized!
}

// [SAFE] OpenZeppelin Initializable
function initialize(address _owner) external initializer {
    owner = _owner;
}
```

### 5. Default Visibility
```solidity
// [VULNERABLE] Solidity < 0.5.0 default visibility is public
function _internalTransfer(address to, uint256 amount) {
    // Missing 'internal' keyword - callable by anyone!
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

---

## Correct Patterns

### OpenZeppelin Ownable2Step
```solidity
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract MyContract is Ownable2Step {
    function adminFunction() external onlyOwner {
        // Only owner can call
    }
}
```

### Role-Based Access Control
```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract MyProtocol is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }
}
```

### Timelock Pattern
```solidity
// Governance/admin actions require delay
function scheduleAction(bytes32 actionId) external onlyOwner {
    scheduledActions[actionId] = block.timestamp + TIMELOCK_DELAY;
}

function executeAction(bytes32 actionId) external onlyOwner {
    require(block.timestamp >= scheduledActions[actionId], "Timelock active");
    require(scheduledActions[actionId] != 0, "Not scheduled");
    delete scheduledActions[actionId];
    _executeAction(actionId);
}
```

### Multi-Signature Pattern
```solidity
// Require multiple signers for critical actions
function executeWithMultisig(
    bytes calldata data,
    bytes[] calldata signatures
) external {
    require(signatures.length >= threshold, "Not enough signatures");
    bytes32 hash = keccak256(abi.encodePacked(data, nonce++));
    for (uint i = 0; i < signatures.length; i++) {
        address signer = ECDSA.recover(hash, signatures[i]);
        require(isAuthorizedSigner[signer], "Invalid signer");
    }
    // Execute action...
}
```

---

## Real-World Exploits

| Protocol | Loss | Access Control Issue | Year |
|----------|------|---------------------|------|
| Parity Wallet | $150M | Unprotected initialize function | 2017 |
| Poly Network | $611M | Cross-chain access control bypass | 2021 |
| Ronin Bridge | $624M | Compromised validator keys (5/9) | 2022 |
| Wintermute | $160M | Compromised vanity address (Profanity) | 2022 |
| Wormhole | $326M | Missing signer validation on Solana | 2022 |
| Cashio | $48M | Missing signer check (Solana) | 2022 |

---

## Audit Checklist Summary

- [ ] Every external/public function has appropriate access control
- [ ] No tx.origin for authentication
- [ ] Two-step ownership transfer
- [ ] Initializer protected against re-initialization
- [ ] Function visibility explicitly set
- [ ] Admin functions behind timelock or multisig
- [ ] Role hierarchy clearly defined and minimal
- [ ] Renounce ownership implications understood
- [ ] Default admin role properly managed
- [ ] Privileged addresses are contracts (not EOAs) for critical protocols

## Related Files
- [Access Control Patterns](../patterns/access-control-patterns.md)
- [Proxy Patterns](../patterns/proxy-patterns.md)
- [Governance Checklist](../checklists/governance-checklist.md)
