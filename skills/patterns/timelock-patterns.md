---
id: PAT-TIMELOCK
title: Timelock Security Patterns
category: defi
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - timelock
  - delay
  - governance
  - emergency
  - admin
related_patterns:
  - dao-patterns
  - vote-patterns
  - access-control-patterns
  - cooldown-patterns
finding_count: 22
last_updated: 2026-02-24
---
# Timelock Security Patterns

## Overview

**Frequency**: 22 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 2 | 9 | 9 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, OpenZeppelin

---

## Detection Checklist

- [ ] Verify timelock delay cannot be set to zero or bypassed via emergency functions
- [ ] Check that queued transactions cannot be executed before delay expires
- [ ] Review cancellation logic — can only authorized parties cancel queued actions?
- [ ] Analyze all admin functions to ensure critical ones route through the timelock
- [ ] Test for delay bypass via contract upgrade, re-initialization, or proxy admin

---

## Key Vulnerability Classes

### 1. Timelock Bypass via Emergency Functions

Protocols often add emergency functions that bypass timelock delays. If access control is insufficient, these become the primary attack vector.

```solidity
// VULNERABLE: Emergency function bypasses timelock with weak access control
function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
    // ⚠ Completely bypasses timelock
    // ⚠ Owner (EOA or 1-of-n multisig) can drain funds instantly
    IERC20(token).transfer(owner, amount);
}

// SECURE: Emergency requires its own delay or multi-sig threshold
function emergencyWithdraw(address token, uint256 amount) external {
    require(emergencyMultisig.hasApproval(3, 5), "Need 3/5 approval");
    require(block.timestamp >= emergencyRequestTime + EMERGENCY_DELAY, "Delay");
}
```

### 2. Minimum Delay Not Enforced

The timelock delay itself should have a minimum that cannot be set to zero.

```solidity
// VULNERABLE: Delay can be set to zero
function setDelay(uint256 newDelay) external onlyAdmin {
    delay = newDelay; // ⚠ Admin sets to 0, then all actions are instant
}

// SECURE: Enforce minimum
function setDelay(uint256 newDelay) external {
    require(msg.sender == address(this), "Only via timelock");
    require(newDelay >= MINIMUM_DELAY, "Below minimum");
    require(newDelay <= MAXIMUM_DELAY, "Above maximum");
    delay = newDelay;
}
```

### 3. Transaction Replay / Re-queuing

After a timelock transaction expires or is cancelled, can it be re-queued and executed again?

```solidity
// VULNERABLE: Same tx can be queued multiple times
function queueTransaction(address target, uint256 value, bytes calldata data) external onlyAdmin {
    bytes32 txHash = keccak256(abi.encode(target, value, data, block.timestamp + delay));
    queuedTransactions[txHash] = true;
    // ⚠ If same parameters used, hash collides with previous queued tx
    //    Could execute an old transaction that was meant to expire
}

// SECURE: Include nonce in hash
bytes32 txHash = keccak256(abi.encode(target, value, data, eta, nonce++));
```

### 4. Grace Period Manipulation

Most timelocks have a grace period after the delay during which the transaction can be executed. If too long, it creates an indefinite execution window.

```solidity
// VULNERABLE: Overly long grace period
uint256 constant GRACE_PERIOD = 365 days; // ⚠ Queued tx executable for 1 year

// Standard: 14-day grace period (Compound Timelock)
uint256 constant GRACE_PERIOD = 14 days;
```

### 5. Cooldown Bypass via Same-Transaction Calls

When cooldown periods are enforced per-transaction rather than per-block, users can bypass them by batching calls.

```solidity
// VULNERABLE: Cooldown checks timestamp which doesn't change within a block
function stake() external {
    lastStakeTime[msg.sender] = block.timestamp;
    // ... staking logic
}

function unstake() external {
    require(block.timestamp >= lastStakeTime[msg.sender] + cooldownPeriod, "Cooldown");
    // ⚠ If stake and unstake are in the same block (via contract batch),
    //    and cooldownPeriod == 0 or check uses >=, this bypasses the cooldown
}
```

**Real-World**: Gauntlet/Spearbit — cooldown period could be bypassed when `stake()` and `unstake()` were called in the same transaction because the timestamp didn't advance.

### 6. Proxy Admin Bypasses Timelock

In upgradeable contracts, the proxy admin can change implementation without going through the timelock, even if all logic functions route through it.

```solidity
// The timelock controls the logic contract:
// timelock → governance → protocol.setParameter()  ✅ Timelocked

// But the proxy admin is separate:
// proxyAdmin → proxy.upgradeTo(newImplementation)  ❌ NOT timelocked!
// New implementation can have no timelock at all
```

**Fix**: Set the timelock as the proxy admin, or use `TimelockController` from OpenZeppelin that manages both.

---

## Real-World Examples

### Example 1: [H-01] Cooldown bypass via same-block stake/unstake

**Source**: Spearbit
**Protocol**: Gauntlet Staking
**Impact**: HIGH

**Details**:

The cooldown check used `>=` comparison with `block.timestamp`. Since `stake()` and `unstake()` execute within the same block, `block.timestamp` didn't change between calls. An attacker could batch both calls via a contract, staking and unstaking instantly to capture rewards without any lockup period.

---

### Example 2: [H-02] Emergency function bypasses 48-hour timelock

**Source**: Code4rena
**Protocol**: DAO Protocol
**Impact**: CRITICAL

**Details**:

The protocol enforced a 48-hour timelock on all governance actions. However, an `emergencyPause()` function existed with only `onlyOwner` access control. The owner was a 2-of-5 multisig. Two colluding signers could pause the protocol, then use `emergencyWithdraw()` to drain all funds — completely bypassing the timelock meant to protect users.

---

### Example 3: [M-01] Timelock delay set to zero renders governance protection useless

**Source**: Sherlock
**Protocol**: Governance Fork
**Impact**: MEDIUM

**Details**:

The `setDelay()` function had no minimum delay enforcement. Admin could reduce the delay to 0, making all subsequent governance actions execute instantly. This transforms the timelock from a security mechanism into a formality, as users have no window to exit before adverse changes take effect.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| Governance | Flash-loan voting to queue malicious timelock tx |
| Access control | Emergency functions bypassing timelock |
| Proxy upgrades | Implementation changes bypass timelocked logic |
| Cooldown periods | Same-block bypass of cooldown checks |
| Delegation | Delegated authority may not respect timelock |

---

## Recommended Secure Patterns

1. **Minimum delay enforcement**: `require(newDelay >= MIN_DELAY)` enforced at contract level
2. **Delay change via timelock**: Changing the delay itself must go through the timelock
3. **Bounded grace period**: 7-14 day grace period, not indefinite
4. **Nonce-based tx hashing**: Include incrementing nonce to prevent replay
5. **Emergency multi-sig**: Emergency functions require higher threshold than normal operations
6. **Proxy admin = timelock**: Set the timelock controller as the proxy admin
7. **Exit window**: Users should have at least `delay - 1 day` to exit before changes take effect
