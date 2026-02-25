---
id: PAT-AA-DELEGATION-SESSION
title: Account Abstraction — Delegation, Session Keys & EIP-7702 Patterns
category: attack-patterns
difficulty: advanced
severity: high
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - base
tags:
  - erc4337
  - delegation
  - session-keys
  - eip7702
  - caveats
  - account-abstraction
  - smart-accounts
related_patterns:
  - account-abstraction-patterns.md
  - account-abstraction-attacks.md
  - access-control-patterns.md
  - delegate-patterns.md
last_updated: 2026-02-25
description: >-
  Use when auditing ERC-4337 smart account protocols that implement delegation
  frameworks, session keys, caveat enforcement, delegation chains, EIP-7702
  upgrades, or permissioned execution patterns. Covers security concerns NOT in
  the standard AA attack surface (bundler/paymaster/factory) — focuses on the
  delegation and permission layer.
---

# Account Abstraction — Delegation, Session Keys & EIP-7702 Patterns

## Overview

This pattern covers the **delegation and permission layer** of ERC-4337 smart accounts — a growing attack surface as protocols move beyond basic UserOp validation toward complex permission systems. These patterns are distinct from standard AA attacks (bundler manipulation, paymaster exploitation, factory attacks) covered in [account-abstraction-attacks.md](account-abstraction-attacks.md).

```
  DELEGATOR (Smart Account)          DELEGATE (Session/Agent)
       │  Signs Delegation                │  Receives Authority
       │  ┌─── Caveats ───┐              │  ┌─── Enforcement ───┐
       │  │ Time, Spend,   │              │  │ Enforcer Contracts │
       │  │ Target, Method │              │  │ validate pre/post  │
       │  └────────────────┘              │  └────────────────────┘
       └──────────────────────────────────┘

  ATTACK SURFACES:
  • Missing/weak caveats      • Delegation chain bypass
  • Session key persistence   • EIP-7702 migration risks
  • Nonce key collision       • Caveat enforcer bugs
  • Counterfactual deployment timing
```

**Related patterns:**
- [account-abstraction-attacks.md](account-abstraction-attacks.md) — Bundler, paymaster, factory, storage rule attacks
- [account-abstraction-patterns.md](account-abstraction-patterns.md) — Real-world AA findings from audits
- [access-control-patterns.md](access-control-patterns.md) — General access control patterns

---

## Detection Checklist

- [ ] Verify every delegation has **at least one restrictive caveat** (no unbounded delegations)
- [ ] Check that **session keys have expiration** (`timestamp` caveat or equivalent)
- [ ] Verify **delegation chain authority** — every link in the chain must be valid and signed
- [ ] Check for **nonce key reuse** in parallel UserOperation patterns
- [ ] Audit **caveat enforcer contracts** for bypass conditions
- [ ] Verify **counterfactual accounts are deployed** before delegation redemption
- [ ] Check **EIP-7702 upgrade paths** for storage collision and authority retention
- [ ] Verify **delegation revocation** actually prevents future redemptions
- [ ] Check for **re-delegation depth attacks** (unbounded chain length)
- [ ] Verify **caveat stacking** — restrictions must accumulate, not override

---

## Pattern 1: Session Key Over-Permissioning

### Description

Session keys (ephemeral signers acting as delegates) are granted authority to execute operations on behalf of a smart account. If delegations are created **without caveats** or with overly permissive caveats, a compromised session key can drain the entire account.

### Vulnerable Code

```solidity
// VULNERABLE: Delegation with NO caveats — grants unlimited authority
function createSessionKey(address sessionKey) external {
    Delegation memory delegation = Delegation({
        delegate: sessionKey,
        delegator: address(this),
        authority: ROOT_AUTHORITY,
        caveats: new Caveat[](0),  // ❌ No restrictions at all
        salt: 0, signature: ""
    });
    _signAndStore(delegation);
}
```

### Secure Code

```solidity
// SECURE: Delegation with MINIMUM 4 caveats
function createSessionKey(address sessionKey, uint48 expiry, uint256 maxCalls) external {
    Caveat[] memory caveats = new Caveat[](4);
    caveats[0] = Caveat({ enforcer: allowedTargetsEnforcer, terms: abi.encode(targets) });
    caveats[1] = Caveat({ enforcer: allowedMethodsEnforcer, terms: abi.encode(selectors) });
    caveats[2] = Caveat({ enforcer: timestampEnforcer, terms: abi.encode(block.timestamp, expiry) }); // ✅ Time-bound
    caveats[3] = Caveat({ enforcer: limitedCallsEnforcer, terms: abi.encode(maxCalls) }); // ✅ Bounded
    _createDelegation(sessionKey, caveats);
}
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| `caveats.length == 0` in delegation creation | **Critical** | Any delegation without caveats grants full authority |
| No `timestamp` or `blockNumber` caveat | **High** | Session persists forever if key is compromised |
| No `limitedCalls` or spend limit caveat | **High** | Unlimited executions possible |
| No `allowedMethods` caveat | **Medium** | Session can call any function on allowed targets |
| No `redeemer` caveat | **Medium** | Anyone with the delegation can redeem, not just intended delegate |

---

## Pattern 2: Counterfactual Account Deployment Timing

### Description

In ERC-4337, smart accounts can exist as "counterfactual" — their address is computed but no contract is deployed yet. Delegations signed by a counterfactual account **cannot be redeemed** until the account is deployed. This creates a timing vulnerability where an attacker can front-run the deployment to manipulate the account's initial state or prevent legitimate delegation redemption.

### Vulnerable Code

```solidity
// VULNERABLE: Race condition — separate deploy + redeem transactions
function deployAndRedeem(bytes calldata initCode, Delegation calldata delegation, bytes calldata execution) external {
    _deployAccount(initCode);
    // ❌ Between deployment and redemption, attacker can:
    //    - Front-run with their own delegation redemption
    //    - Call initialize() with malicious parameters
    _redeemDelegation(delegation, execution);
}
```

### Secure Code

```solidity
// SECURE: Atomic deployment + redemption via EntryPoint initCode
// Deploy is handled by initCode in the UserOp — no front-run window
function redeemWithDeployment(UserOperation calldata userOp) external {
    require(userOp.initCode.length > 0 || _isDeployed(userOp.sender),
        "Account must be deployed or initCode must be provided");
}
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| Delegation redemption without deployment check | **High** | Verify `code.length > 0` or handle `initCode` atomically |
| Separate deploy + redeem transactions | **High** | Window for front-running between transactions |
| `initialize()` callable by anyone | **Critical** | Attacker deploys account with malicious parameters |
| `initCode` not verified against expected factory | **High** | Attacker could deploy different implementation |

---

## Pattern 3: Nonce Key Collision in Parallel UserOperations

### Description

ERC-4337 uses a 256-bit nonce: **192 bits for key + 64 bits for sequence**. Different keys enable parallel UserOp execution. If a protocol generates nonce keys with insufficient entropy or predictable patterns, operations can collide — causing replacement instead of parallel execution, or enabling replay attacks.

### Vulnerable Code

```typescript
// VULNERABLE: Timestamp collision when multiple ops fire simultaneously
const ops = delegations.map(async (d, index) => {
    const key = BigInt(Date.now()); // ❌ Same millisecond = same key = collision
    const nonce = (key << 64n) | 0n;
    return bundlerClient.sendUserOperation({ nonce, ... });
});
```

### Secure Code

```typescript
// SECURE: Unique keys with proper entropy + sequence fetch
const ops = await Promise.all(delegations.map(async (d, index) => {
    const key = BigInt(Date.now()) * 1000n + BigInt(index); // ✅ Unique per op
    const nonce = await getAccountNonce(publicClient, {
        address: smartAccount.address, entryPointAddress: entryPoint07Address, key,
    });
    return bundlerClient.sendUserOperation({ nonce, ... });
}));
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| `Date.now()` used as sole nonce key | **Medium** | Simultaneous submissions collide |
| Sequential integers as nonce keys | **Medium** | Predictable, potentially front-runnable |
| No sequence number fetch before submission | **High** | May replace pending ops instead of running in parallel |
| Same nonce key for dependent operations | **Low** | Correct if order matters — but verify intentionality |

---

## Pattern 4: Delegation Chain Authority Bypass

### Description

Delegation can be **chained**: Alice delegates to Bob, Bob re-delegates to Carol. Each link in the chain must be validated. The security properties must be: (1) caveats accumulate — Carol's authority is the intersection of all caveats in the chain, (2) every signature in the chain is valid, (3) broken chain detection prevents skipping intermediate delegations.

### Vulnerable Code

```solidity
// VULNERABLE: Only validates the last delegation, not the full chain
function redeemDelegation(Delegation[] calldata chain, bytes calldata execution) external {
    Delegation memory last = chain[chain.length - 1];
    require(_isValidSignature(last), "Invalid signature");
    // ❌ No chain continuity check, no caveat accumulation from parents
    _execute(last.delegator, execution);
}
```

### Secure Code

```solidity
// SECURE: Full chain validation with accumulated caveats
function redeemDelegation(Delegation[] calldata chain, bytes calldata execution) external {
    require(chain.length > 0, "Empty chain");
    for (uint i = 1; i < chain.length; i++) {
        require(chain[i].delegator == chain[i-1].delegate, "Broken chain"); // ✅ Continuity
    }
    for (uint i = 0; i < chain.length; i++) {
        require(_isValidSignature(chain[i]), "Invalid sig");
        require(!disabledDelegations[_getDelegationHash(chain[i])], "Disabled");
        _enforceCaveats(chain[i].caveats, execution); // ✅ Accumulate ALL caveats
    }
    _execute(chain[0].delegator, execution);
}
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| Chain validation checks only last link | **Critical** | Attacker skips restrictive intermediate delegations |
| Caveats not accumulated across chain | **Critical** | Child delegation can exceed parent's restrictions |
| No `delegator == previous.delegate` check | **High** | Arbitrary delegation injection into chain |
| No disabled/revoked check on each chain link | **High** | Revoked delegation still usable via chain |
| Unbounded chain depth | **Medium** | Gas griefing via deep delegation chains |

---

## Pattern 5: EIP-7702 Upgrade Risks (EOA → Smart Account)

### Description

EIP-7702 allows an EOA to temporarily delegate its code execution to a smart contract implementation, effectively turning an EOA into a smart account **while keeping the same address**. This introduces risks around storage collision, authority retention after un-delegation, and the ability for EOAs to have code — breaking the `tx.origin == msg.sender` assumption.

### Vulnerable Code

```solidity
// VULNERABLE: Assumes EOAs cannot have code
function restrictToEOA() external {
    require(msg.sender == tx.origin, "No contracts allowed");
    // ❌ EIP-7702 accounts satisfy this check but ARE smart accounts
}

// VULNERABLE: Storage collision after EIP-7702 implementation switch
contract SmartAccountImpl {
    address public owner;  // Slot 0 — ❌ may contain stale data from previous 7702 delegation
    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;  // ❌ owner might not be zero if previous impl used slot 0
    }
}
```

### Secure Code

```solidity
// SECURE: ERC-7201 namespaced storage for 7702-compatible implementations
contract SafeSmartAccountImpl {
    bytes32 private constant STORAGE_SLOT = 
        keccak256(abi.encode(uint256(keccak256("safe.smart.account.storage")) - 1))
            & ~bytes32(uint256(0xff)); // ✅ Namespaced — no collision across implementations
    
    struct AccountStorage { address owner; uint256 nonce; bool initialized; }
    
    function _getStorage() internal pure returns (AccountStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }
    function initialize(address _owner) external {
        AccountStorage storage s = _getStorage();
        require(!s.initialized, "Already initialized"); // ✅ Survives impl switch
        s.owner = _owner;
        s.initialized = true;
    }
}
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| `extcodesize == 0` used to detect EOAs | **High** | Breaks with EIP-7702 delegated EOAs |
| `msg.sender == tx.origin` for EOA gating | **High** | EIP-7702 EOAs pass this check but can run complex logic |
| Direct storage slot usage (slot 0, 1, 2...) | **Medium** | Collision risk when EOA switches 7702 implementations |
| Missing `initialized` flag in 7702 implementation | **High** | Re-initialization after implementation switch |
| No check for 7702 delegation prefix (`0xef0100`) | **Medium** | Cannot distinguish between EOA types |

---

## Pattern 6: Paymaster Validation Bypass via Delegation

### Description

When a paymaster sponsors UserOperations, it validates the operation during `validatePaymasterUserOp`. If the smart account uses delegation-based execution, the paymaster may validate a benign-looking UserOp, but the actual execution through delegation redemption may perform completely different (and expensive) operations.

### Vulnerable Code

```solidity
// VULNERABLE: Paymaster validates top-level callData but delegation wraps arbitrary execution
contract NaivePaymaster is IPaymaster {
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256)
        external returns (bytes memory context, uint256 validationData) {
        bytes4 selector = bytes4(userOp.callData[:4]);
        require(selector == APPROVED_SELECTOR, "Unapproved");
        // ❌ redeemDelegations() is approved, but the INNER execution could be anything
        return (abi.encode(userOp.sender), 0);
    }
}
```

### Secure Code

```solidity
// SECURE: Paymaster decodes delegation calldata to validate actual targets
contract DelegationAwarePaymaster is IPaymaster {
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256)
        external returns (bytes memory context, uint256 validationData) {
        bytes4 selector = bytes4(userOp.callData[:4]);
        if (selector == IDelegationManager.redeemDelegations.selector) {
            (,, Execution[][] memory executions) = abi.decode(
                userOp.callData[4:], (Delegation[][], bytes[], Execution[][])
            );
            for (uint i = 0; i < executions.length; i++)
                for (uint j = 0; j < executions[i].length; j++)
                    require(approvedTargets[executions[i][j].target], "Unapproved target"); // ✅
        }
        return (abi.encode(userOp.sender), 0);
    }
}
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| Paymaster only validates top-level selector | **High** | Delegation wraps arbitrary execution under one selector |
| Paymaster doesn't decode `redeemDelegations` calldata | **High** | Cannot enforce target/method restrictions |
| No gas limit per delegation in paymaster validation | **Medium** | Single expensive delegation drains paymaster deposit |
| Paymaster signature replay across delegation calls | **High** | Same signature reused for different delegations |

---

## Pattern 7: EntryPoint Reentrancy via handleOps Callback

### Description

The EntryPoint's `handleOps` function processes UserOperations sequentially: validate → execute for each op. During execution, the smart account may call back into the EntryPoint or interact with contracts that are also being validated as part of the same bundle. This creates reentrancy vectors specific to the AA execution flow.

### Vulnerable Code

```solidity
// VULNERABLE: Paymaster postOp modifies state read during validation
contract VulnerablePaymaster is IPaymaster {
    mapping(address => uint256) public sponsoredAmount;
    function validatePaymasterUserOp(UserOperation calldata userOp, ...) external {
        require(sponsoredAmount[userOp.sender] < MAX_SPONSORED, "Limit");
        // ❌ If multiple UserOps from same sender in one bundle,
        //    each validation reads STALE sponsoredAmount
    }
    function _postOp(PostOpMode, bytes calldata context, uint256 actualGasCost) internal {
        sponsoredAmount[abi.decode(context, (address))] += actualGasCost;
    }
}
```

### Secure Code

```solidity
// SECURE: Reentrancy guard on account execution + per-bundle tracking
contract SecureAccount {
    uint256 private _lock;
    function execute(address target, bytes calldata data) external onlyEntryPoint {
        require(_lock == 0, "Reentrant"); _lock = 1;
        (bool ok, ) = target.call(data);
        require(ok, "Failed"); _lock = 0;
    }
}
```

### Detection Signals

| Signal | Risk Level | Check |
|--------|-----------|-------|
| Account `execute` makes unbounded external calls without reentrancy guard | **High** | Reentrant callbacks via bundled operations |
| Paymaster reads/writes same state in `validate` and `_postOp` | **Medium** | Stale reads when multiple ops from same sender in bundle |
| No consideration of multi-op bundles in rate limiting | **Medium** | Per-op limits bypassed by submitting multiple ops in one bundle |
| Shared state between bundled accounts' execution | **High** | Cross-account state manipulation within single `handleOps` call |

---

## Audit Methodology for Delegation Systems

1. **Map delegation creation** — Are minimum caveats enforced? Can zero-caveat delegations be created? Who can create them?
2. **Trace redemption flow** — Is full chain validated? All caveats accumulated? Deployed account required?
3. **Audit caveat enforcers** — Can enforcers be bypassed? Do they check pre AND post state? Handle edge cases?
4. **Check session lifecycle** — Expiration on all sessions? Revocation path? Secure key storage?
5. **Verify EIP-7702 compat** — Namespaced storage (ERC-7201)? No `extcodesize == 0` EOA assumptions? Re-init protection?

---

## Delegation Framework Error Codes (MetaMask v1.3.0)

Useful for auditors tracing revert conditions in delegation-based protocols.

### DelegationManager Errors

| Error Code | Name | Audit Implication |
|------------|------|-------------------|
| `0xb5863604` | `InvalidDelegate()` | Caller != delegation's `to` — check delegate resolution |
| `0xb9f0f171` | `InvalidDelegator()` | Wrong source, or **counterfactual account not deployed** |
| `0x05baa052` | `CannotUseADisabledDelegation()` | Delegation revoked — check revocation completeness |
| `0xded4370e` | `InvalidAuthority()` | Broken delegation chain — audit chain ordering (leaf → root) |
| `0x1bcaf69f` | `BatchDataLengthMismatch()` | Array length mismatch in `redeemDelegations` — input validation issue |
| `0x3db6791c` | `InvalidEOASignature()` | Wrong chain ID or delegation manager used in signing |
| `0x155ff427` | `InvalidERC1271Signature()` | Smart contract signature (ERC-1271) verification failed |

### DeleGatorCore Errors

| Error Code | Name | Audit Implication |
|------------|------|-------------------|
| `0xd663742a` | `NotEntryPoint()` | Caller != EntryPoint — access control bypass attempt |
| `0x0796d945` | `NotEntryPointOrSelf()` | Missing auth on self-call path |
| `0x1a4b3a04` | `NotDelegationManager()` | Direct call instead of through DelegationManager |
| `0xb96fcfe4` | `UnsupportedCallType(bytes1)` | Unsupported execution mode — check batch/single handling |

### Common Caveat Enforcer Reverts

| Revert String | Meaning | Audit Check |
|---------------|---------|-------------|
| `AllowedTargetsEnforcer:target-address-not-allowed` | Target not in allowlist | Can attacker add targets? |
| `ERC20TransferAmountEnforcer:allowance-exceeded` | Transfer > delegated limit | Can limit be reset or bypassed? |
| `ERC20TransferAmountEnforcer:invalid-contract` | Wrong token address | Cross-token confusion possible? |
| `CaveatEnforcer:invalid-call-type` | Must use single call type | Can batch mode bypass caveat? |

---

## Statistics

- Attack surface first documented: 2023 (ERC-4337 v0.6)
- Delegation frameworks emerged: 2024 (MetaMask Delegation Framework v1.0)
- EIP-7702 introduced: 2024 (Pectra upgrade)
- Growing adoption in: Session key wallets, multi-signer setups, automated DeFi agents
- Key audit reports: Biconomy (Code4rena 2023), Ambire Wallet, Safe{Core}, ZeroDev Kernel

---

## References

- [ERC-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [ERC-7710: Delegation via Smart Contracts](https://eips.ethereum.org/EIPS/eip-7710)
- [ERC-7715: Permission Requests](https://eips.ethereum.org/EIPS/eip-7715)
- [EIP-7702: EOA Code Delegation](https://eips.ethereum.org/EIPS/eip-7702)
- [ERC-7201: Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
- [MetaMask Delegation Framework](https://github.com/metamask/delegation-framework)
- [Code4rena Biconomy Audit (2023)](https://code4rena.com/reports/2023-01-biconomy)
