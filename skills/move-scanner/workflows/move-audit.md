---
id: MOVE-WF-AUDIT
title: Move Contract Audit Workflow
parent: move-scanner
type: workflow
last_updated: 2025-01-31
---

# Move Audit Workflow

Unified audit workflow for Move smart contracts on both Aptos and Sui. Steps marked (Aptos) or (Sui) are platform-specific; unmarked steps apply to both.

---

## Prerequisites

| Item | Aptos | Sui |
|------|-------|-----|
| Compiler | `aptos move compile` | `sui move build` |
| Config | `Move.toml` | `Move.toml` |
| Dependencies | `AptosFramework` | `Sui`, `MoveStdlib` |
| Testing | `aptos move test` | `sui move test` |
| Version | Check `Move.toml` for framework rev | Check `Move.toml` for framework rev |

---

## Step 1: Module Structure Mapping

Map the complete module architecture:

```
sources/
├── my_protocol.move     → Main module
├── token.move           → Token definition and operations
├── pool.move            → Liquidity pool (shared/global state)
├── governance.move      → Governance module
└── utils.move           → Helper functions
```

Document for each module:
- All structs with their abilities (`key`, `store`, `copy`, `drop`)
- Public functions (`public entry fun`, `public fun`, `public(friend) fun`)
- Friend declarations
- Constants and error codes
- Events/event types

---

## Step 2: Ability Analysis (Move-Critical)

This is the **most Move-specific** audit step. For every struct in the codebase:

| Struct Type | Expected Abilities | Red Flag |
|-------------|-------------------|----------|
| Value token / coin | `key` (maybe `store`) | `copy` = infinite duplication |
| Capability (Admin, Mint) | `key` only | `copy` or `drop` = leak risk |
| Config / metadata | `key, store` | `copy` usually fine |
| Event | `copy, drop` | Normal — events are ephemeral |
| One-time witness (Sui) | `drop` only | Any other ability = violation |

**What to Check:**
- [ ] No value-holding type has `copy`
- [ ] Capabilities don't have `drop` (unless intentional burn)
- [ ] `store` on capabilities carefully evaluated
- [ ] Phantom types properly constrained

---

## Step 3: Access Control

### Aptos

| Pattern | How It Works |
|---------|--------------|
| Signer-based | `entry fun action(admin: &signer)` + check `signer::address_of(admin)` |
| Capability-based | Pass `&AdminCap` as parameter |
| Resource-based | Check `exists<AdminRole>(addr)` |

### Sui

| Pattern | How It Works |
|---------|--------------|
| Owned object | `fun action(cap: &AdminCap, ...)` — only holder can pass it |
| Address check | `assert!(tx_context::sender(ctx) == admin, E_UNAUTHORIZED)` |
| Capability pattern | AdminCap as owned object — only owner possesses it |

**What to Check:**
- [ ] All entry functions validate caller authority
- [ ] Privileged functions require capability object or signer proof
- [ ] No public function allows unauthorized state modification
- [ ] Init function properly restricts who receives capabilities

---

## Step 4: Resource/Object Lifecycle

Trace the full lifecycle of every important data type:

```
Creation → Storage → Access → Modification → Destruction
```

| Lifecycle Phase | Aptos | Sui |
|-----------------|-------|-----|
| Create | `let r = MyStruct {}` | `let obj = MyStruct { id: object::new(ctx) }` |
| Store | `move_to(signer, r)` | `transfer::transfer(obj, addr)` or `transfer::share_object(obj)` |
| Read | `borrow_global<T>(addr)` | Passed as `&T` parameter |
| Modify | `borrow_global_mut<T>(addr)` | Passed as `&mut T` parameter |
| Destroy | `move_from<T>(addr)` then destructure | Destructure: `let MyStruct { id, ... } = obj; object::delete(id)` |

**What to Check:**
- [ ] Resources/objects can only be created by authorized parties
- [ ] Resources/objects can only be destroyed by authorized parties
- [ ] No orphaned resources (created but never stored or used)
- [ ] Wrapping/unwrapping (Sui) has proper authorization

---

## Step 5: Module Upgrade Review

### Aptos
- [ ] Upgrade policy identified (`compatible` vs `immutable`)
- [ ] Upgrade authority is multisig (not single EOA)
- [ ] If upgraded, verify storage layout compatibility
- [ ] Critical protocols should be `immutable`

### Sui
- [ ] UpgradeCap properly secured or burned
- [ ] Upgrade policy set (e.g., `package::make_immutable`)
- [ ] Package dependencies pinned to specific versions

---

## Step 6: Friend Function Audit

```move
// List all friend declarations
friend my_package::module_a;
friend my_package::module_b;
```

- [ ] Every `public(friend)` function has documented reason for each friend
- [ ] Friend modules can't bypass critical invariants
- [ ] No circular friend dependencies
- [ ] Friend list is minimal (principle of least privilege)

---

## Step 7: Math Review

Move integers (`u8`, `u64`, `u128`, `u256`) **abort on overflow** (unlike Solidity <0.8 or Solana release mode). However:

| Risk | Description |
|------|-------------|
| DoS via overflow abort | Attacker causes legitimate user tx to abort |
| Precision loss | `u64` for timestamps or amounts may truncate |
| Division by zero | Always aborts — ensure denominator can't be zero |

- [ ] Accumulator variables use `u128` or `u256` (prevent overflow DoS)
- [ ] Division operations check denominator != 0
- [ ] Price/rate calculations have sufficient precision

---

## Step 8: Platform-Specific Checks

### If Aptos:
- [ ] `acquires` annotations correct and complete
- [ ] `init_module` properly restricted and idempotent
- [ ] Resource account SignerCapability not leaked
- [ ] Coin operations use `aptos_framework::coin` correctly
- [ ] Table/SimpleMap growth bounded

See [Aptos Security](resources/aptos-security.md) for details.

### If Sui:
- [ ] Object ownership model appropriate (owned vs shared vs immutable)
- [ ] Shared objects minimal (performance + contention)
- [ ] One-Time Witness used for singleton init
- [ ] TreasuryCap properly secured
- [ ] Dynamic fields bounded
- [ ] `transfer::transfer` vs `transfer::public_transfer` correct

See [Sui Security](resources/sui-security.md) for details.

---

## Step 9: Events

- [ ] All significant state changes emit events
- [ ] Event data is sufficient for off-chain indexing
- [ ] Events include relevant identifiers (addresses, amounts, IDs)

---

## Step 10: Report

Structure findings with Move-specific context:

| Severity | Criteria | Example |
|----------|----------|---------|
| **Critical** | Direct fund theft or protocol takeover | Capability leak allowing unauthorized minting |
| **High** | Fund loss under specific conditions | Integer overflow abort causing DoS on deposits |
| **Medium** | Incorrect behavior, limited impact | Shared object contention affecting throughput |
| **Low** | Best practice violation | Missing abort codes |
| **Info** | Suggestion | Consider making package immutable |

### Move-Specific Report Notes

When documenting Move findings, always specify:
- Platform (Aptos or Sui)
- Relevant abilities of affected types
- Whether the issue is type-system-related or logic-related
- Whether the fix requires a module upgrade or is possible via configuration
