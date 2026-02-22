---
id: SCANNER-MOVE
title: Move Smart Contract Security Scanner
category: chain-scanner
chains: [aptos, sui]
languages: [move]
last_updated: 2025-01-31
---

# Move Scanner Skill

## Purpose

Analyze Move smart contracts for security vulnerabilities on both Aptos and Sui. Move's resource-oriented programming model — with linear types, abilities system, and the borrow checker — provides stronger safety guarantees than Solidity, but introduces unique vulnerability classes around capability management, module upgrades, and cross-module trust.

## Move Security Model

Move was designed by Meta (formerly Facebook) for the Diem blockchain with safety as a first-class priority. The type system enforces:

| Safety Property | How Move Enforces It | Residual Risk |
|----------------|---------------------|---------------|
| No resource duplication | Linear types: resources can't be copied unless explicitly marked `copy` | Incorrect `copy` ability on value types |
| No resource loss | Resources must be explicitly destroyed or stored | Incorrect `drop` ability allows silent discard |
| Type safety | Static type checking + bytecode verification | Type confusion via deserialization |
| Access control | Module encapsulation + `public` vs `public(friend)` | Overly permissive friend declarations |
| Memory safety | No raw pointers, borrow checker | Logic errors in state transitions |

## Aptos vs Sui — Key Differences

| Feature | Aptos | Sui |
|---------|-------|-----|
| State model | Global storage (`move_to`, `borrow_global`) | Object model (owned, shared, immutable) |
| Execution | Sequential | Parallel (for owned objects) |
| Upgrade model | Module upgrade authority | Package upgrade via UpgradeCap |
| Initialization | `init_module` (called once on publish) | `init` function with one-time witness |
| Identity | Account addresses | Object IDs |
| Token standard | `aptos_framework::coin` | `sui::coin` with TreasuryCap |
| Randomness | `aptos_framework::randomness` | `sui::random` |

## Detection Capabilities

### Critical — Direct Fund Loss

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Capability leak** | AdminCap, MintCap, or TreasuryCap stored in publicly accessible location | Capability with `store` ability + `move_to` to accessible address |
| **Missing signer check** | Entry function doesn't validate caller identity | `public entry fun` without `signer` parameter or authority check |
| **Resource duplication** | Value-holding resource has `copy` ability | `has copy` on struct holding coins or tokens |
| **Unsafe module upgrade** | Upgrade authority not protected | Upgrade policy set to `compatible` with weak authority check |
| **Unauthorized minting** | Token mint function callable by anyone | `mint` function without capability or authority gate |

### High — Significant Impact

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Friend function abuse** | Friend modules can bypass internal invariants | `public(friend)` on sensitive functions with excessive friends |
| **Integer overflow** | Move integers overflow without abort by default | `+`, `*` without checked arithmetic or `assert!` bounds |
| **Object access bypass (Sui)** | Shared object manipulation or wrapped object extraction | `shared` object without proper access control |
| **Capability not burned** | One-time capabilities not destroyed after use | Init witness or admin cap not consumed |
| **Acquires annotation missing** | Resource access without proper `acquires` | Compile-time error on Aptos, but indicates design issue |

### Medium — Conditional Impact

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Dynamic field overflow (Sui)** | Unbounded dynamic fields on objects | `dynamic_field::add` without count limits |
| **Missing abort codes** | Generic aborts make debugging/monitoring difficult | `abort` without code or `assert!` without message |
| **Event missing** | State changes without event emission | `move_to` / `move_from` without `event::emit` |
| **Shared object contention (Sui)** | Shared objects create bottlenecks | Frequently-accessed shared objects |
| **Phantom type confusion** | Phantom type parameters misused | `phantom` type enabling cross-type access |

## Move Type System — Abilities Audit Guide

The four abilities control what you can do with a type:

| Ability | What It Allows | Security Concern |
|--------|---------------|------------------|
| `key` | Can be stored in global storage (Aptos) or as an object (Sui) | Required for top-level storage — ensure access control |
| `store` | Can be nested inside other resources | Values with `store` can be transferred — check if intended |
| `copy` | Can be duplicated | **DANGEROUS for value types** — duplicating coins = minting |
| `drop` | Can be discarded without destruction | **Careful with capabilities** — dropping an admin cap means losing it |

### Secure Capability Pattern

```move
// SECURE: Capability without copy or drop — must be stored or explicitly destroyed
struct AdminCap has key, store {
    id: UID,  // Sui
}

// INSECURE: copy + drop allows duplication and silent discard
struct AdminCap has key, store, copy, drop {
    id: UID,
}
```

## Resources

| Resource | Description |
|----------|-------------|
| [Move Patterns](resources/move-patterns.md) | Common vulnerability patterns in Move with code examples |
| [Aptos Security](resources/aptos-security.md) | Aptos-specific security: global storage, coin module, upgrade policy |
| [Sui Security](resources/sui-security.md) | Sui-specific security: object model, shared objects, UpgradeCap |

## Workflows

| Workflow | Description |
|----------|-------------|
| [Move Audit](workflows/move-audit.md) | Unified audit workflow for Move contracts (Aptos + Sui) |

## Notable Move Ecosystem Security Incidents

| Incident | Chain | Root Cause | Impact |
|----------|-------|-----------|--------|
| Pontem DEX exploit | Aptos | Price oracle manipulation via flash loan | Fund theft |
| Tortuga staking issue | Aptos | Staking reward calculation error | Incorrect APY |
| Various Sui DeFi issues | Sui | Shared object contention + flash loan attacks | Trading manipulation |
| Module upgrade attacks | Aptos | Unprotected upgrade authority | Protocol takeover |

## Integration with Other Skills

| Skill | Connection |
|-------|-----------|
| `aptos-scanner/` | Aptos-specific patterns and audit workflow |
| `chain-guides/aptos.md` | Chain context for Aptos (validators, gas, modules) |
| `patterns/` | Cross-reference with general vulnerability categories |
| `exploit-forensics/` | Move-based exploit analysis |
