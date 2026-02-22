---
id: APTOS-SCAN
title: Aptos Specialized Scanner
category: chain-scanner
trigger: "Audit Aptos|Aptos Move"
last_updated: 2025-01-31
---

# Aptos Specialized Scanner

Specialized security scanner for Aptos Move smart contracts. Extends the general [Move Scanner](../move-scanner/SKILL.md) with Aptos-specific patterns, framework modules, and the global storage model.

---

## Why a Separate Aptos Scanner?

While the Move Scanner covers language-level patterns shared between Aptos and Sui, Aptos has a fundamentally different **storage model** (global resources under addresses), **framework** (AptosFramework), and **upgrade system** that require dedicated detection rules.

| Feature | Aptos | Sui |
|---------|-------|-----|
| Storage | Global resources under addresses | Object model |
| Resource access | `move_to`, `borrow_global`, `move_from` | Passed as function parameters |
| Upgrade | Module upgrade with compatibility policy | Package upgrade with UpgradeCap |
| Tokens | `aptos_framework::coin` | `sui::coin` with TreasuryCap |
| Accounts | Account + AuthenticationKey | No account concept |
| Randomness | `aptos_framework::randomness` (commit-reveal) | `sui::random` |

---

## Detection Capabilities

| Category | Detection | Severity |
|----------|-----------|----------|
| **Resource Safety** | Resource created but never stored (`move_to` missing) | High |
| **Resource Safety** | `borrow_global_mut` without authorization check | Critical |
| **Resource Safety** | `move_from` extracting resource without ownership proof | Critical |
| **Resource Safety** | Missing `exists<T>(addr)` check before access | Medium |
| **Abilities** | Value-holding type with `copy` ability (duplication) | Critical |
| **Abilities** | Capability with `drop` (can be silently discarded) | High |
| **Upgrade** | Module upgrade authority is single EOA | High |
| **Upgrade** | `compatible` upgrade policy on critical module | Medium |
| **Coin** | `MintCapability` stored in publicly accessible location | Critical |
| **Coin** | `CoinStore` registration not checked before deposit | Medium |
| **Auth** | Missing `signer` parameter on privileged entry function | Critical |
| **Auth** | `signer::address_of()` not compared to authorized address | High |
| **Auth** | Resource account `SignerCapability` exposed publicly | Critical |
| **Storage** | `Table`/`SimpleMap` with unbounded growth | Medium |
| **Storage** | `acquires` annotation missing (compile-time, but indicates design) | Low |
| **Events** | State change without event emission | Low |

---

## Aptos Framework Security-Critical Modules

| Module | Functions to Audit | Key Risk |
|--------|--------------------|----------|
| `aptos_framework::coin` | `initialize`, `mint`, `burn`, `transfer`, `register` | Cap management |
| `aptos_framework::account` | `create_account`, `rotate_authentication_key` | Auth key rotation |
| `aptos_framework::resource_account` | `create_resource_account`, `retrieve_resource_account_cap` | Signer cap leak |
| `aptos_framework::object` | `create_object`, `transfer`, `generate_signer` | Object ownership |
| `aptos_framework::fungible_asset` | `mint`, `burn`, `transfer`, `deposit`, `withdraw` | New token standard |
| `aptos_framework::multisig_account` | `create`, `execute_transaction` | Multisig logic |
| `aptos_framework::staking_contract` | `create_staking_contract`, `distribute` | Reward calculation |
| `aptos_framework::governance` | `create_proposal`, `vote` | Voting power |

---

## Common Aptos Vulnerability Examples

### Resource Account Signer Capability Leak

```move
// CRITICAL: SignerCapability stored with 'store' ability allows extraction
struct ResourceAccountCap has key, store {
    signer_cap: account::SignerCapability,
}

// If anyone can get a reference to this struct, they can create a signer
// for the resource account and drain all its assets
public fun get_resource_signer(cap: &ResourceAccountCap): signer {
    account::create_signer_with_capability(&cap.signer_cap)
}

// SAFE: No public accessor, internal only
struct ResourceAccountCap has key {
    signer_cap: account::SignerCapability,
}

fun internal_get_signer() acquires ResourceAccountCap {
    let cap = borrow_global<ResourceAccountCap>(@resource_addr);
    let signer = account::create_signer_with_capability(&cap.signer_cap);
    // Use signer internally only
}
```

### Coin Registration Race Condition

```move
// VULNERABLE: Depositing without checking CoinStore registration
public fun distribute_rewards(recipients: &vector<address>) {
    let i = 0;
    while (i < vector::length(recipients)) {
        let addr = *vector::borrow(recipients, i);
        // ABORTS if addr doesn't have CoinStore<RewardToken> registered!
        coin::deposit(addr, reward_coins);
        i = i + 1;
    };
}

// SAFE: Check registration first
public fun distribute_rewards(recipients: &vector<address>) {
    let i = 0;
    while (i < vector::length(recipients)) {
        let addr = *vector::borrow(recipients, i);
        if (coin::is_account_registered<RewardToken>(addr)) {
            coin::deposit(addr, reward_coins);
        } else {
            // Handle: skip, queue for later, or register for them
        };
        i = i + 1;
    };
}
```

---

## Resources
- [Aptos Patterns](resources/aptos-patterns.md)

## Workflows
- [Aptos Audit](workflows/aptos-audit.md)

## See Also
- [Move Scanner](../move-scanner/SKILL.md) for general Move patterns
- [Chain Guide: Aptos](../chain-guides/aptos.md) for chain-specific context
