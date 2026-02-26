---
id: PAT-AA-ERC7715-PERMISSIONS
title: ERC-7715 Advanced Permission Security Patterns
category: pattern
severity: high
chains: [ethereum, base, polygon, arbitrum, optimism]
languages: [solidity, typescript]
tags:
  - erc-4337
  - erc-7715
  - erc-7710
  - smart-accounts
  - permissions
  - delegations
  - caveat-enforcers
  - session-keys
last_updated: 2026-02-25
description: >-
  Use when auditing protocols using ERC-7715 advanced permissions, MetaMask
  Delegation Framework (ERC-7710), caveat enforcers, delegation chains,
  or smart account permission systems — covers permission type attacks,
  enforcer bypass, delegation chain validation, counterfactual deployment
  risks, and nonce key manipulation.
---

# ERC-7715 Advanced Permission Security Patterns

## Overview

ERC-7715 extends ERC-4337 smart accounts with a **permission request/grant** system
that enables dApps to request specific capabilities (ERC-20 spending, native token
transfers) with structured limits. MetaMask's Delegation Framework (ERC-7710) provides
the enforcement layer with caveat enforcers — on-chain contracts that validate each
operation against granted constraints.

This pattern builds on [aa-delegation-session-patterns.md](aa-delegation-session-patterns.md)
with deeper coverage of permission types, enforcer-specific attacks, error analysis,
and production gotchas from the MetaMask Smart Accounts Kit.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                  dApp (Requester)                    │
│     requestPermissions(ERC-7715)                     │
├─────────────────────────────────────────────────────┤
│                  Wallet (Grantor)                    │
│     User approves → creates Delegation              │
├────────────────┬────────────────────────────────────┤
│ DelegationMgr  │ CaveatEnforcers[]                  │
│ (ERC-7710)     │ • AllowedTargets                   │
│                │ • AllowedMethods                    │
│ validate →     │ • NativeTokenTransferAmount         │
│ execute →      │ • ERC20TransferAmount               │
│                │ • LimitedCallsEnforcer              │
│                │ • TimestampEnforcer (before/after)   │
│                │ • DeployedEnforcer                  │
│                │ • NonceEnforcer                      │
└────────────────┴────────────────────────────────────┘
```

## 1. Permission Type Attacks

### 1.1 ERC-20 Permission Over-Granting

ERC-7715 supports `erc20-token-transfer` permissions with per-token spending limits:

```typescript
const permission = {
  type: "erc20-token-transfer",
  data: {
    address: "0xUSDC...",  // Token contract
    allowance: "0x2710",   // 10000 wei — BUT which unit?
  },
  policies: [{
    type: "token-allowance",
    data: { allowance: "0x2710" },
  }],
};
```

**Attack vector**: If allowance is specified in base units (wei) but the UI displays
it as token units (e.g., USDC = 6 decimals), a permission for "10000" could mean
10000 USDC ($10,000) or 0.01 USDC depending on interpretation.

**What to check**:
- [ ] Is the allowance in base units (wei) or human-readable units?
- [ ] Does the wallet UI clearly show the decimal-adjusted amount?
- [ ] Is the token address validated against a known token list?
- [ ] Can the token address point to a malicious contract that returns inflated `decimals()`?

### 1.2 Native Token Permission Unbounded

```typescript
const permission = {
  type: "native-token-transfer",
  data: {
    allowance: "0xFFFFFFFFFFFFFFFF",  // ~18.4 ETH — too generous?
  },
  policies: [{
    type: "native-token-transfer-amount",
    data: { allowance: "0xFFFFFFFFFFFFFFFF" },
  }],
};
```

**Attack vector**: dApp requests a very large native token allowance under the guise
of "gas sponsoring" or "multiple transactions." Once granted, the delegate can drain
up to the full allowance.

**What to check**:
- [ ] Is the native token allowance reasonable for the use case?
- [ ] Are there time limits on the permission?
- [ ] Can the permission be revoked before the allowance is consumed?

## 2. Caveat Enforcer Attacks

### 2.1 AllowedTargets Bypass via Fallback

The `AllowedTargetsEnforcer` restricts which contracts can be called:

```solidity
// CaveatEnforcer checks target address
function beforeHook(
    bytes calldata terms,   // encoded list of allowed targets
    bytes calldata,         // args (unused)
    ModeCode mode,
    bytes calldata executionCallData,
    bytes32,                // delegationHash
    address,                // delegator
    address                 // redeemer
) external pure override {
    address target = address(bytes20(executionCallData[0:20]));
    // Check target is in allowed list
}
```

**Attack vector**: Target contract has a fallback function that delegates to another
contract. The enforcer validates the top-level target but not the delegate call target.

**What to check**:
- [ ] Does the target contract use `delegatecall`?
- [ ] Is `AllowedMethods` enforcer combined with `AllowedTargets`?
- [ ] Can the target contract be upgraded to add malicious methods?

### 2.2 ERC20TransferAmount Accumulation

The `ERC20TransferAmountEnforcer` tracks cumulative spending against an allowance:

```solidity
// Tracks spending per delegation hash
mapping(address => mapping(bytes32 => uint256)) public spentMap;

function beforeHook(...) external override {
    (address token, uint256 limit) = abi.decode(terms, (address, uint256));
    uint256 spent = spentMap[delegationManager][delegationHash];
    uint256 amount = getTransferAmount(executionCallData);
    require(spent + amount <= limit, "Overspend");
    spentMap[delegationManager][delegationHash] = spent + amount;
}
```

**Attack vector**: If `getTransferAmount()` doesn't validate the function selector,
a call to `approve()` instead of `transfer()` won't be counted toward the spending
limit but grants the delegate unlimited spending on the token.

**What to check**:
- [ ] Does the enforcer validate the function selector (transfer vs approve vs transferFrom)?
- [ ] Is there a separate enforcer for `approve()` calls?
- [ ] Can batch calls (multicall) mix enforced and non-enforced operations?
- [ ] Is the `spentMap` correctly scoped per delegation hash?

### 2.3 Timestamp Enforcer Manipulation

```solidity
// TimestampAfterEnforcer — only valid after a timestamp
function beforeHook(...) external view override {
    uint128 afterTimestamp = abi.decode(terms, (uint128));
    require(block.timestamp >= afterTimestamp, "Too early");
}
```

**Attack vector**: Block timestamps can be manipulated by validators within limits
(~15 seconds on Ethereum). For tight time windows, this manipulation may allow
premature or delayed execution.

**What to check**:
- [ ] Are time windows large enough to tolerate small timestamp manipulation?
- [ ] Is the "before" timestamp enforced strictly (not just "after")?
- [ ] Are both `TimestampAfterEnforcer` and `TimestampBeforeEnforcer` used?

### 2.4 NonceEnforcer Replay

```solidity
// NonceEnforcer — prevents replay using sequential nonces
function beforeHook(...) external override {
    uint256 nonce = abi.decode(terms, (uint256));
    require(!usedNonces[delegationHash][nonce], "Nonce used");
    usedNonces[delegationHash][nonce] = true;
}
```

**Attack vector**: If nonces are not sequential (just "not used"), an attacker can
pre-compute valid nonces and execute operations in unexpected order.

**What to check**:
- [ ] Are nonces strictly sequential or just unique-per-use?
- [ ] Can nonce gaps be exploited for ordering attacks?
- [ ] Is the nonce scoped to the delegation hash (not global)?

## 3. Delegation Chain Attacks

### 3.1 Redelegation Authority Escalation

The Delegation Framework supports redelegation — a delegate can create a sub-delegation
with reduced permissions. But if the reduction is not properly enforced:

```solidity
// VULNERABLE: Sub-delegate grants MORE than parent allowed
Delegation parentDelegation = {
    delegate: sessionKey,
    authority: ROOT_AUTHORITY,
    caveats: [AllowedTargets([contractA])]  // Only contractA
};

// Session key creates sub-delegation
Delegation subDelegation = {
    delegate: attackerKey,
    authority: parentDelegationHash,
    caveats: [AllowedTargets([contractB])]  // Tries to add contractB!
};
```

**Attack vector**: Each link in the delegation chain must enforce AT LEAST the same
restrictions as the parent. If the DelegationManager doesn't verify caveat
attenuation, a delegate can escalate permissions.

**What to check**:
- [ ] Does the DelegationManager verify that child caveats are SUBSET of parent caveats?
- [ ] Can a child delegation ADD new allowed targets not in the parent?
- [ ] Is there a maximum chain depth to prevent gas-limit attacks?
- [ ] Does each enforcer in the chain execute in the correct order?

### 3.2 Broken Chain Continuity

```solidity
// CORRECT: Chain links must be continuous
// chain[i].delegator == chain[i-1].delegate
for (uint i = 1; i < chain.length; i++) {
    require(
        chain[i].delegator == chain[i-1].delegate,
        "Broken chain"
    );
}
```

**Attack vector**: Missing continuity check allows injection of arbitrary delegations
into the middle of a chain, bypassing the intended permission hierarchy.

**What to check**:
- [ ] Is `delegator == previous.delegate` enforced at every link?
- [ ] Can a signed delegation be injected into an unrelated chain?
- [ ] Is the root authority (first delegation) verified?

## 4. Execution Mode Attacks

### 4.1 Batch Mode Flag Confusion

Smart accounts support multiple execution modes:

| Mode | Hex | Meaning |
|------|-----|---------|
| Single | `0x00000000...01...` | Single call execution |
| Batch | `0x00000000...01...` | Batch of calls |
| DelegateCall | `0x00000000...ff...` | Execute in account's context |

**Attack vector**: If the caveat enforcer doesn't check the execution mode, a
delegation that should only allow `call` mode could be used with `delegatecall`,
executing in the smart account's storage context.

**What to check**:
- [ ] Does the enforcer validate the `ModeCode` parameter?
- [ ] Can batch mode bypass per-call enforcers?
- [ ] Is `delegatecall` mode explicitly blocked for non-admin delegations?

### 4.2 Try/Revert Mode Exploitation

```solidity
// Try mode: Doesn't revert on failure, returns success flag
// Attack: Use try mode to silently fail enforcer reverts
```

**Attack vector**: If the delegation system supports "try" mode where individual
calls don't revert the batch, enforcer rejections are silently swallowed.

**What to check**:
- [ ] Does try mode propagate enforcer failures?
- [ ] Is try mode restricted for permission-delegated calls?

## 5. Counterfactual Account Deployment Risks

Smart accounts can be used before deployment (counterfactual deployment):

```typescript
// Account address is deterministic (CREATE2)
const accountAddress = getCounterfactualAddress(implementation, salt, factoryAddress);

// First UserOp deploys the account AND executes in one transaction
```

**Attack vector**: If permissions are granted to the counterfactual address before
deployment, and the factory is upgradeable, the factory could deploy a different
implementation that doesn't enforce the granted permissions.

**What to check**:
- [ ] Is the factory address fixed or upgradeable?
- [ ] Are pre-deployment permissions stored on-chain or only in the dApp?
- [ ] Can the implementation be changed between permission grant and deployment?
- [ ] Is the CREATE2 salt deterministic and not controllable by the factory operator?

## 6. Error Code Analysis

The MetaMask DelegationManager and DeleGatorCore emit specific errors.
Understand these for audit findings:

### DelegationManager Errors

| Error | Meaning | What to Check |
|-------|---------|---------------|
| `AlreadyDisabled` | Delegation already revoked | Is re-enable possible? |
| `CannotDisableRootAuthority` | Can't revoke root | Is root authority changeable? |
| `InvalidDelegation` | Signature or chain invalid | Is off-chain signing correct? |
| `InvalidDelegatorAccount` | Account doesn't exist | Counterfactual account issue |
| `NoDelegationsProvided` | Empty chain | Input validation gap |

### DeleGatorCore Errors

| Error | Meaning | What to Check |
|-------|---------|---------------|
| `NotEntryPoint` | Call not from EntryPoint | Is EntryPoint address hardcoded? |
| `NotEntryPointOrSelf` | Not EntryPoint or self-call | Can be bypassed via CPI? |
| `ExecModeNotSupported` | Invalid execution mode | All modes properly validated? |
| `InvalidCallType` | Wrong call/delegatecall | Mode validation complete? |

### Caveat Enforcer Errors

| Error | Meaning | Severity |
|-------|---------|----------|
| `TargetNotAllowed` | Call to non-whitelisted target | Expected |
| `MethodNotAllowed` | Call to non-whitelisted method | Expected |
| `NativeTransferExceeded` | Exceeds native token limit | Expected |
| `ERC20TransferExceeded` | Exceeds ERC-20 limit | Expected |
| `LimitExceeded` | Call count exceeded | Expected |
| `TooEarly` / `TooLate` | Outside time window | Expected |
| `NotDeployed` | Required contract not deployed | Counterfactual issue |

## Security Review Checklist

### Permission Grant
- [ ] Verify allowance units (wei vs token units)
- [ ] Check for time-bounded permissions
- [ ] Verify revocation mechanism
- [ ] Check wallet UI display accuracy

### Caveat Enforcers
- [ ] Verify function selector validation (transfer vs approve)
- [ ] Check timestamp manipulation tolerance
- [ ] Verify nonce scoping (per-delegation, not global)
- [ ] Check batch mode interaction with per-call enforcers
- [ ] Verify `delegatecall` mode is restricted

### Delegation Chains
- [ ] Verify continuity (`delegator == previous.delegate`)
- [ ] Verify attenuation (child ⊆ parent permissions)
- [ ] Check maximum chain depth
- [ ] Verify root authority is not revocable

### Execution
- [ ] Verify `ModeCode` validation in enforcers
- [ ] Check try/revert mode propagation
- [ ] Verify counterfactual deployment security

## Cross-References

- [aa-delegation-session-patterns.md](aa-delegation-session-patterns.md) — Broader delegation and session key patterns
- [erc-8004-agent-security.md](erc-8004-agent-security.md) — AI agent sessions that use permissions
- [ai-agent-payment-patterns.md](ai-agent-payment-patterns.md) — Agent payment authorization chains

## Sources

- MetaMask Smart Accounts Kit: https://github.com/metamask/accounts-kit
- ERC-7715 Specification: https://eips.ethereum.org/EIPS/eip-7715
- ERC-7710 Delegation Framework: https://eips.ethereum.org/EIPS/eip-7710
- ERC-4337 Account Abstraction: https://eips.ethereum.org/EIPS/eip-4337
- Consensys Audits: MetaMask smart account and Gator audit findings
