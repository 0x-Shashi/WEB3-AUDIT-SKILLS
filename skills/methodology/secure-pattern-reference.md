---
id: SECURE-PATTERN-REFERENCE
title: Secure Pattern Reference
category: methodology
triggers:
  - secure implementation
  - how to fix reentrancy
  - how to fix oracle
  - how to fix access control
  - what's the correct pattern
  - best practice implementation
  - OpenZeppelin pattern
  - standard secure pattern
related_skills:
  - patterns/reentrancy-patterns.md
  - patterns/oracle-patterns.md
  - patterns/access-control-patterns.md
  - patterns/defi-vault-patterns.md
  - patterns/signature-patterns.md
  - methodology/fix-verification-patterns.md
---

#  Secure Pattern Reference

## Overview

This document describes **what secure implementations look like** so you can identify when code deviates from best practices. Compare audited code against these patterns.

---

## 1. Reentrancy Protection Patterns

### Secure: Checks-Effects-Interactions (CEI)

**Pattern**: State changes BEFORE external calls

```
 SECURE ORDER:
1. Check: Validate conditions (require/revert)
2. Effect: Update state (balances, flags)
3. Interact: External call (transfer, call)

 VULNERABLE ORDER:
1. Check
2. Interact ← External call here
3. Effect ← State update too late!
```

**What to Look For**:
- Is `balances[user] -= amount` BEFORE `call{value: amount}`?
- Are all state updates complete before any external call?

### Secure: ReentrancyGuard

**Pattern**: Mutex lock using uint256 (not bool)

```
 SECURE:
uint256 private _status = 1;  // NOT_ENTERED
modifier nonReentrant() {
    require(_status != 2, "Reentrant");
    _status = 2;  // ENTERED
    _;
    _status = 1;  // NOT_ENTERED
}

 VULNERABLE (gas inefficient):
bool private locked;  // Zero→non-zero SSTORE costs more
```

**What to Look For**:
- Does every function with external calls have `nonReentrant`?
- Are related functions (withdraw, claim) ALL protected?
- Is read-only reentrancy considered for view functions?

---

## 2. Oracle Security Patterns

### Secure: Full Chainlink Validation

**Pattern**: Check ALL failure modes

```
 SECURE CHECKS:
1. Staleness: block.timestamp - updatedAt < maxAge
2. Zero/Negative: answer > 0
3. Round Complete: answeredInRound >= roundId
4. Circuit Breaker: minPrice < answer < maxPrice
5. Decimals: Scale to 18 decimals properly

 VULNERABLE (missing checks):
(, int price, , , ) = feed.latestRoundData();
return uint256(price);  // No validation!
```

**What to Look For**:
- Is staleness checked against the feed's heartbeat?
- What happens if price is 0 or negative?
- Are L2 sequencer checks present (Arbitrum/Optimism)?

### Secure: TWAP Instead of Spot

**Pattern**: Time-weighted average resists manipulation

```
 SECURE:
- Use Uniswap V3 TWAP with 10-30 minute window
- Verify sufficient liquidity depth
- Multi-block sampling

 VULNERABLE:
- Spot price from getReserves()
- Single-block price reading
- No liquidity verification
```

---

## 3. Access Control Patterns

### Secure: Two-Step Ownership Transfer

**Pattern**: Pending owner must accept

```
 SECURE:
function transferOwnership(newOwner) {
    pendingOwner = newOwner;  // Step 1: Nominate
}
function acceptOwnership() {
    require(msg.sender == pendingOwner);
    owner = pendingOwner;  // Step 2: Accept
}

 VULNERABLE:
function transferOwnership(newOwner) {
    owner = newOwner;  // Direct transfer - typo = lost forever
}
```

**What to Look For**:
- Can ownership be transferred to address(0) accidentally?
- Is there a way to recover from wrong address transfer?
- Is zero-address checked?

### Secure: Role-Based with Admin Separation

**Pattern**: Roles have separate admins

```
 SECURE:
- DEFAULT_ADMIN_ROLE manages other roles
- Each role can have different admin
- renounceRole only for msg.sender

 VULNERABLE:
- Single "admin" bool flag
- Hardcoded admin address
- Anyone can revoke others' roles
```

---

## 4. Vault/ERC4626 Patterns

### Secure: First Depositor Protection

**Pattern**: Virtual shares/assets offset

```
 SECURE:
totalSupply() = actualSupply + 1e3  // Virtual offset
totalAssets() = actualAssets + 1    // Virtual offset

Effect: Attacker needs massive capital to inflate shares

 VULNERABLE:
totalSupply() = actualSupply  // No offset
// First depositor can donate to inflate share price
```

**What to Look For**:
- Is there virtual share/asset offset?
- Is there minimum deposit requirement?
- Are "dead shares" minted to address(0)?

### Secure: Rounding Direction

**Pattern**: Always round against the user

```
 SECURE ROUNDING:
deposit(): shares = floor(assets * supply / total)  // DOWN
withdraw(): assets = floor(shares * total / supply)  // DOWN
mint(): assets = ceil(shares * total / supply)      // UP
redeem(): shares = ceil(assets * supply / total)    // UP

 VULNERABLE:
Always rounding in user's favor = protocol drained
```

---

## 5. Signature Security Patterns

### Secure: EIP-712 with Full Replay Protection

**Pattern**: Domain + nonce + deadline + chainId

```
 SECURE DOMAIN:
- name: Contract name
- version: "1"
- chainId: block.chainid (recomputed if changes)
- verifyingContract: address(this)

 SECURE MESSAGE:
- Include nonce (incremented after use)
- Include deadline (checked before use)
- Include all action parameters

 VULNERABLE:
- No chainId = cross-chain replay
- No nonce = unlimited replay
- No deadline = valid forever
```

**What to Look For**:
- Is nonce incremented AFTER signature use?
- Is domain separator correct (includes chainId)?
- Is ecrecover wrapped with malleability check?

### Secure: ECDSA Library Usage

**Pattern**: Use OpenZeppelin ECDSA, not raw ecrecover

```
 SECURE:
address signer = ECDSA.recover(hash, signature);
// Handles: zero address, malleability, compact sigs

 VULNERABLE:
address signer = ecrecover(hash, v, r, s);
// Returns 0 on failure, no malleability check
```

---

## 6. Flash Loan Patterns

### Secure: Lender Protection

**Pattern**: Balance check (not allowance), reentrancy guard

```
 SECURE:
- Check balance BEFORE loan
- Verify balance AFTER >= before + fee
- Reentrancy guard prevents nested loans
- Callback return value validated

 VULNERABLE:
- Checking allowance (doesn't guarantee tokens exist)
- No reentrancy protection
- Ignoring callback return value
```

### Secure: Borrower Protection

**Pattern**: Validate lender and initiator

```
 SECURE:
function onFlashLoan(...) {
    require(msg.sender == TRUSTED_LENDER);
    require(initiator == OWNER);
    // Execute strategy
}

 VULNERABLE:
function onFlashLoan(...) {
    // Anyone can trigger, drain tokens
}
```

---

## 7. Upgrade Patterns

### Secure: UUPS with Disabled Implementation

**Pattern**: Implementation cannot be initialized

```
 SECURE:
constructor() {
    _disableInitializers();  // Prevents takeover
}

function initialize(owner) initializer {
    __Ownable_init(owner);
}

function _authorizeUpgrade(newImpl) onlyOwner {}

 VULNERABLE:
// No _disableInitializers()
// Anyone can initialize implementation contract
```

### Secure: Storage Gaps

**Pattern**: Reserve slots for future variables

```
 SECURE:
contract V1 {
    uint256 public value;
    uint256[49] private __gap;  // Reserve 49 slots
}

contract V2 {
    uint256 public value;
    uint256 public newVar;      // Uses 1 gap slot
    uint256[48] private __gap;  // Now 48 slots
}

 VULNERABLE:
// No gap = can't add variables without collision
```

---

## Quick Reference Table

| Vulnerability | Secure Pattern | Key Check |
|--------------|----------------|-----------|
| Reentrancy | CEI + nonReentrant | State before call |
| Stale Oracle | Staleness + bounds check | updatedAt validation |
| Access Control | Two-step transfer | pendingOwner pattern |
| First Depositor | Virtual offset | 1e3 share offset |
| Signature Replay | Nonce + chainId | Domain separator |
| Flash Loan | Balance check | Before/after balance |
| Upgrade | Storage gap | __gap array |

---

## Using This Reference

When auditing:

1. **Identify** what the code is trying to do
2. **Find** the corresponding secure pattern above
3. **Compare** the implementation against the pattern
4. **Flag** any deviations as potential vulnerabilities
5. **Verify** if deviation is intentional and safe

Remember: Deviation from standard patterns isn't always a bug, but it always warrants investigation.
