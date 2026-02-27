---
id: PAT-EIP-7702-DELEGATION-SECURITY
title: EIP-7702 Delegation Security
category: patterns
severity: critical
chains: [ethereum, base, optimism, arbitrum]
languages: [solidity]
tags:
  - eip-7702
  - delegation
  - eoa-upgrade
  - smart-account
  - grant-scopes
  - permission-delegation
  - account-abstraction
last_updated: 2026-02-27
description: >-
  Use when auditing EIP-7702 implementations that allow EOAs to delegate
  execution to smart account code — covers delegation scope attacks,
  grant type confusion, revocation gaps, chain ID confusion, and
  private key exposure. Different from ERC-4337 patterns (which cover
  bundler/paymaster) and ERC-7715 patterns (which cover permission
  caveats) — this focuses on the EIP-7702 EOA→code delegation
  mechanism itself.
---

# EIP-7702 Delegation Security

## Overview

EIP-7702 allows EOAs to temporarily or persistently delegate their
execution to smart contract code. This transforms EOAs into smart
accounts WITHOUT deploying a new contract — the EOA's code pointer
is set to existing implementation code.

**Critical insight**: Unlike ERC-4337 where smart accounts are new
addresses, EIP-7702 EOAs retain their private key while gaining
programmable execution. The private key remains a SINGLE POINT OF
FAILURE — any delegation can be bypassed by signing directly.

### Architecture

```
BEFORE EIP-7702:
  EOA (private key) ──► direct tx execution

AFTER EIP-7702:
  EOA (private key) ──► delegate code ──► smart account logic
       │                                      │
       │ authorization_list: [{               │
       │   chainId, address, nonce,           │
       │   yParity, r, s                      │
       │ }]                                   │
       │                                      │
       └── STILL can sign direct txs ─────────┘
           (bypasses ALL delegation logic!)
```

## Delegation Grant Scopes

EIP-7702 implementations define grant scopes that control what delegated
code can do. Each scope type has unique attack surfaces:

### ERC-20 Transfer Amount

```
Scope: erc20TransferAmount
Parameters: token, amount, recipient
Attack surface: Accumulation over time
```

**Vulnerability**: Grants specify a one-time amount but may not track
cumulative usage. Attacker exploits by making many small transfers:

```solidity
// VULNERABLE: Checks amount per-call, not cumulative
function executeGrant(Grant memory grant, address to, uint256 amount) external {
    require(amount <= grant.maxAmount, "Exceeds grant"); // per-call check!
    IERC20(grant.token).transfer(to, amount);
}

// EXPLOIT: 100 calls × 1 ETH = 100 ETH stolen
// Grant was for maxAmount: 1 ETH (ONE transfer)
// But attacker calls 100 times

// SECURE: Track cumulative usage
mapping(bytes32 => uint256) public grantUsed;

function executeGrant(Grant memory grant, address to, uint256 amount) external {
    bytes32 grantId = keccak256(abi.encode(grant));
    grantUsed[grantId] += amount;
    require(grantUsed[grantId] <= grant.maxAmount, "Cumulative exceeded");
    IERC20(grant.token).transfer(to, amount);
}
```

### ERC-20 Period Transfer

```
Scope: erc20PeriodTransfer
Parameters: token, amountPerPeriod, periodDuration, startTime
Attack surface: Period boundary exploitation
```

**Vulnerability**: Transfer at end of Period N + start of Period N+1
gives double allowance in a short window:

```solidity
// Period 1: ends at block.timestamp = 1000
// Attacker transfers maxAmount at timestamp 999
// Period 2: starts at block.timestamp = 1000
// Attacker transfers maxAmount at timestamp 1000
// Result: 2x allowance withdrawn in 2 seconds

// SECURE: Enforce minimum gap between period-boundary transfers
require(
    block.timestamp >= lastTransferTime + MIN_TRANSFER_GAP,
    "Too soon after last transfer"
);
```

### ERC-20 Streaming

```
Scope: erc20Streaming
Parameters: token, ratePerSecond, startTime, endTime
Attack surface: Front-loaded withdrawal + rate manipulation
```

**Vulnerability**: Stream rate calculated at claim time, not at grant time.
If rate oracle is manipulable, attacker inflates rate before claiming:

```solidity
// VULNERABLE: Rate read at claim time
function claimStream(uint256 streamId) external {
    Stream storage s = streams[streamId];
    uint256 elapsed = block.timestamp - s.lastClaim;
    uint256 amount = elapsed * s.ratePerSecond; // rate could be manipulated
    s.lastClaim = block.timestamp;
    IERC20(s.token).transfer(msg.sender, amount);
}
```

### Native Token Transfer Amount

```
Scope: nativeTokenTransferAmount
Parameters: amount, recipient
Attack surface: Gas stipend + fallback execution
```

**Vulnerability**: ETH transfer to contract with fallback can execute
arbitrary logic within gas stipend. 7702-delegated EOA may not expect
this callback:

```solidity
// VULNERABLE: Delegated code sends ETH to unknown recipient
function executeNativeGrant(address to, uint256 amount) external {
    (bool ok, ) = to.call{value: amount}(""); // fallback may callback
    require(ok);
}

// If 'to' is a contract with a receive() that calls back into
// the delegated EOA, reentrancy may occur
```

### Function Call Grant

```
Scope: functionCall
Parameters: target, selector, arguments
Attack surface: Selector collision + argument manipulation
```

**Vulnerability**: Grant checks 4-byte selector but not full signature.
Different functions can share selectors:

```solidity
// Grant allows: target.transfer(address,uint256)
// Selector: 0xa9059cbb
//
// Attacker finds collision function with same selector
// but different behavior (rare but possible with crafted contracts)
//
// More common: Grant allows selector but doesn't validate arguments
// Grant: transfer(recipient, amount) where amount <= 100
// Attack: transfer(attacker, 100) — valid per selector + amount
//         but recipient was supposed to be restricted to specific address
```

### Ownership Transfer Grant

```
Scope: ownershipTransfer
Parameters: newOwner
Attack surface: Most dangerous scope — permanent control change
```

**Vulnerability**: Ownership transfer is irreversible. If granted to
a compromised or malicious delegate, the entire account is lost:

```solidity
// CRITICAL: One-shot ownership transfer
// Once executed, original owner loses ALL control
// No timelock, no multi-sig, no recovery

// SECURE: Require multi-step ownership transfer
// Step 1: Grant proposes new owner
// Step 2: Wait for timelock (e.g., 48 hours)
// Step 3: New owner accepts
// Step 4: Original owner can cancel during timelock
```

## Core Vulnerability Patterns

### 1. Private Key Bypass

**Severity**: Critical

The EOA's private key can ALWAYS sign transactions directly, bypassing
all delegation logic — session keys, spending limits, multi-sig:

```
DELEGATION LOGIC:
  ✅ Spending limit: 1 ETH/day
  ✅ Multi-sig: 2-of-3
  ✅ Timelock: 24 hours
  ✅ Allowlisted recipients only

PRIVATE KEY (bypasses ALL of above):
  ❌ Signs tx directly → unlimited ETH → any recipient → instantly
```

**Audit check**: Does the system assume EIP-7702 delegation provides
the SAME security as a native smart contract wallet?

If yes → Critical finding. The private key is an unrestricted backdoor.

### 2. Chain ID Confusion

**Severity**: High

EIP-7702 authorization includes a `chainId` field. Delegation valid
on one chain may be replayed on another if `chainId` is 0 (wildcard):

```solidity
// authorization_list: [{
//   chainId: 0,        // ← WILDCARD! Valid on ALL chains
//   address: impl,
//   nonce: 1,
//   yParity, r, s
// }]

// Delegation signed for Base can be replayed on:
// - Ethereum Mainnet
// - Optimism
// - Arbitrum
// - Any EVM chain supporting EIP-7702
```

**Audit check**: Is `chainId` validated to be non-zero and match the
expected chain?

### 3. Nonce Race Condition

**Severity**: High

EIP-7702 authorization nonces are separate from transaction nonces.
A delegation authorization may be front-run:

```
1. User signs authorization: {nonce: 5, address: safeImpl}
2. Attacker front-runs with tx that increments user's auth nonce
3. User's authorization becomes invalid (nonce already used)
4. User's delegation fails — DoS
```

**Audit check**: How does the implementation handle nonce invalidation?
Is there retry logic? Can an attacker permanently block delegation?

### 4. Delegation Revocation Gaps

**Severity**: High

Revoking a delegation requires a new EIP-7702 transaction setting the
code pointer to zero. But:

```
REVOCATION ASSUMPTIONS:
  EOA signs revocation tx → code pointer cleared → delegation gone

REALITY:
  1. Revocation tx must be mined (can be censored)
  2. Pending delegated txs in mempool still execute
  3. If delegate code self-destructs, revocation may fail
  4. Cross-chain delegations need per-chain revocation
  5. Gas price spike may make revocation economically infeasible
```

**Audit check**: What happens between revocation submission and
confirmation? Is there a revocation grace period?

### 5. Implementation Code Mutability

**Severity**: Critical

EIP-7702 points to an implementation address. If that implementation
is upgradeable (proxy), the delegation target changes without the
EOA re-signing:

```
DAY 1: EOA delegates to GnosisSafe implementation at 0xABC
DAY 2: 0xABC is upgraded (proxy pattern) to malicious code
DAY 3: EOA's delegation now executes malicious code
        EOA never re-signed anything
```

**Audit check**: Is the delegation target a proxy? If yes, who controls
upgrades? The EOA's security is now dependent on the proxy admin.

### 6. Inspection Command Spoofing

**Severity**: Medium

`inspect` functionality that shows current delegation state may not
read from the canonical source:

```solidity
// VULNERABLE: Reads cached state, not actual EIP-7702 code pointer
function getActiveDelegation() external view returns (address) {
    return _cachedDelegation; // may be stale
}

// SECURE: Read actual code pointer
function getActiveDelegation() external view returns (address) {
    address target;
    assembly {
        target := extcodecopy(...)  // Read actual EIP-7702 pointer
    }
    return target;
}
```

### 7. Grant Scope Interaction

**Severity**: High

Multiple active grants may interact in unexpected ways:

```
Grant A: erc20TransferAmount(USDC, 1000)
Grant B: functionCall(router, swap(USDC, ETH, ...))

ATTACK:
  1. Use Grant B to swap 1000 USDC → ETH via router
  2. Use Grant A to transfer 1000 USDC directly
  3. Total: 2000 USDC moved (each grant checked independently)

SECURE:
  Track total value moved across ALL grants, not per-grant
```

## Redeem Action Attacks

Redeem actions allow delegate code to execute pre-approved operations.
Attack vectors:

| Redeem Action | Attack Vector |
|--------------|--------------|
| `redeemToken` | Type confusion — grant says ERC-20 but target is ERC-721 |
| `redeemNative` | Gas stipend callback → reentrancy |
| `redeemBatch` | Partial execution — 3 of 5 actions succeed, state inconsistent |
| `redeemAndTransfer` | TOCTOU — balance checked before redeem, transferred after |
| `redeemWithCallback` | Callback target is attacker contract |

## Audit Checklist

### Core EIP-7702 Checks

- [ ] Private key can still bypass all delegation logic — is this documented?
- [ ] Chain ID is non-zero (no wildcard cross-chain delegation)
- [ ] Authorization nonce management prevents replay and front-running
- [ ] Delegation target is NOT an upgradeable proxy (or upgrade risk accepted)
- [ ] Revocation mechanism works under adversarial conditions (censorship, gas)
- [ ] Multiple active delegations don't interact unsafely

### Grant Scope Checks

- [ ] `erc20TransferAmount` tracks CUMULATIVE usage, not per-call
- [ ] `erc20PeriodTransfer` prevents period-boundary double-spend
- [ ] `erc20Streaming` rate is fixed at grant time, not read dynamically
- [ ] `nativeTokenTransferAmount` handles fallback reentrancy
- [ ] `functionCall` validates full arguments, not just selector
- [ ] `ownershipTransfer` has timelock + cancellation mechanism
- [ ] Cross-grant value tracking prevents scope interaction attacks

### Operational Checks

- [ ] Inspect/status commands read canonical EIP-7702 state
- [ ] Revocation is testable (can be dry-run before execution)
- [ ] Error messages distinguish between "grant expired" and "grant invalid"
- [ ] Batch redeem operations are atomic (all-or-nothing)

## Common Severity Classifications

| Finding | Typical Severity |
|---------|-----------------|
| Private key bypasses smart account logic | Critical |
| Chain ID = 0 allows cross-chain replay | Critical |
| Implementation target is upgradeable proxy | Critical |
| Grant amount not cumulative-tracked | High |
| Period boundary double-spend | High |
| Revocation can be DoS'd | High |
| Nonce front-running causes delegation DoS | Medium |
| Inspect shows stale delegation state | Medium |
| Missing error differentiation | Low |

## EIP-7702 vs ERC-4337 vs ERC-7715

| Property | EIP-7702 | ERC-4337 | ERC-7715 |
|----------|----------|----------|----------|
| Account type | EOA with code | New smart account | Delegated permissions |
| Private key | Always active | May not exist | N/A |
| Upgrade mechanism | Re-delegate | Proxy upgrade | Re-grant |
| Revocation | New 7702 tx | N/A | On-chain revoke |
| Cross-chain | Chain ID field | Per-chain deploy | Per-chain grant |
| Bundler dependency | No | Yes | No |
| Paymaster | No | Yes | No |

## Cross-References

- [aa-erc7715-permission-security.md](aa-erc7715-permission-security.md) — ERC-7715 permissions
- [account-abstraction-patterns.md](../patterns/account-abstraction-patterns.md) — ERC-4337
- [account-abstraction-attacks.md](../patterns/account-abstraction-attacks.md) — AA attack vectors
- [proxy-implementation-attacks.md](../patterns/proxy-implementation-attacks.md) — Proxy risks

## Sources

- MetaMask gator-cli: EIP-7702 delegation implementation with grant scopes
- EIP-7702: Set EOA account code specification
- Rhinestone: EIP-7702 security considerations
- Nethermind: EIP-7702 audit findings
