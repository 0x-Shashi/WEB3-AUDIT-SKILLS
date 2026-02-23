---
id: SUI-SCANNER
title: Sui Smart Contract Security Scanner
category: chain-specific
difficulty: advanced
triggers:
  - sui smart contract audit
  - sui move security
  - sui object model
  - sui vulnerability
related_skills:
  - sui-scanner/resources/sui-patterns.md
  - sui-scanner/resources/object-security.md
  - sui-scanner/workflows/sui-audit.md
  - move-scanner/SKILL.md
tags:
  - sui
  - move
  - object-model
  - security
last_updated: 2026-01-31
---

# Sui Scanner Skill

## Purpose

Specialized scanner for Sui Move smart contracts. Sui uses a unique **object-centric model** where state is organized as typed objects with ownership semantics, not as a global address-keyed storage. This fundamentally changes the security surface compared to both EVM and other Move chains (Aptos).

## Sui vs Aptos: Key Differences

| Aspect | Sui Move | Aptos Move |
|---|---|---|
| State Model | Object-centric (owned/shared/immutable) | Global storage (`move_to`, `borrow_global`) |
| Parallelism | Owned objects processed in parallel, no consensus | All transactions sequenced |
| Transaction Input | Objects passed explicitly as params | Resources accessed via address |
| Upgrade | `UpgradeCap` object required | Module publisher authority |
| Init Pattern | One-Time Witness (`init(otw: OTW, ctx: &mut TxContext)`) | `init_module(account: &signer)` |
| Transfer | `transfer::transfer` / `transfer::public_transfer` | `move_to(signer, resource)` |
| Custom Types | Abilities: `key`, `store`, `copy`, `drop` | Same abilities, different usage |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Sui Network                            │
│                                                             │
│  ┌───────────────────┐    ┌───────────────────┐             │
│  │  Owned Objects    │    │ Shared Objects     │             │
│  │  (No consensus)   │    │ (Consensus needed) │             │
│  │                   │    │                    │             │
│  │  ┌────────┐       │    │  ┌────────┐        │             │
│  │  │ Coin   │ ←owner│    │  │ DEX    │ ←shared│             │
│  │  └────────┘       │    │  │ Pool   │        │             │
│  │  ┌────────┐       │    │  └────────┘        │             │
│  │  │ NFT    │ ←owner│    │  ┌────────┐        │             │
│  │  └────────┘       │    │  │ Config │ ←shared│             │
│  └───────────────────┘    │  └────────┘        │             │
│                           └───────────────────┘             │
│  ┌───────────────────┐    ┌───────────────────┐             │
│  │ Immutable Objects │    │ Wrapped Objects    │             │
│  │ (Frozen forever)  │    │ (Inside another)   │             │
│  │  ┌────────┐       │    │  ┌────────────┐    │             │
│  │  │Package │       │    │  │ Parent Obj  │    │             │
│  │  └────────┘       │    │  │  ┌───────┐  │    │             │
│  └───────────────────┘    │  │  │ Child │  │    │             │
│                           │  │  └───────┘  │    │             │
│                           │  └────────────┘    │             │
│                           └───────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## Detection Capabilities

### Critical Vulnerabilities
- **Object ownership bypass**: Shared objects accessed/modified without authorization checks
- **UpgradeCap leak**: Upgrade capability transferred to wrong address or left publicly accessible
- **Dynamic field manipulation**: Unbounded or attacker-controlled dynamic field growth
- **Missing One-Time Witness**: Module initialization can be replayed

### High Vulnerabilities
- **Missing `TxContext::sender` check**: Privileged operations without caller validation
- **Shared object contention DoS**: Spamming shared objects to create sequencing bottleneck
- **Transfer policy bypass**: Using `transfer::transfer` instead of `transfer::public_transfer` for types with `store`
- **Object ID prediction**: Assuming object IDs are random when they're deterministic

### Medium Vulnerabilities
- **Object wrapping/unwrapping bugs**: Wrapped objects not properly lifecycle-managed
- **Clock dependency manipulation**: Time-sensitive logic relying on `Clock` shared object
- **Dynamic field key collision**: Different logical fields mapped to same dynamic field key
- **Frozen object mutability attempt**: Logic that attempts to modify frozen objects

## Real-World Sui Incidents

| Incident | Vulnerability | Impact |
|---|---|---|
| Various DEX implementations | Shared object contention | Performance degradation, elevated fees |
| NFT marketplace bugs | Transfer policy bypass | Royalty enforcement circumvented |
| Early DeFi protocols | Missing sender checks on admin functions | Unauthorized parameter changes |
| Bridge implementations | Object ownership not validated | Cross-chain message spoofing |

## Resources
- [Sui Patterns](resources/sui-patterns.md) — Full vulnerability patterns with Move code
- [Object Security](resources/object-security.md) — Deep dive on object ownership model

## Workflows
- [Sui Audit](workflows/sui-audit.md) — Step-by-step Sui audit methodology

## Related Scanners
- [Move Scanner](../move-scanner/SKILL.md) — Generic Move language patterns (shared with Aptos)
- [Aptos Scanner](../aptos-scanner/SKILL.md) — Aptos-specific global storage patterns
