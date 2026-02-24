---
id: SUI-AUDIT
title: Sui Smart Contract Audit Workflow
category: sui-scanner
difficulty: advanced
triggers:
  - sui audit workflow
  - sui move audit steps
  - sui security review
related_skills:
  - sui-scanner/SKILL.md
  - sui-scanner/resources/sui-patterns.md
  - sui-scanner/resources/object-security.md
tags:
  - sui
  - audit
  - workflow
  - move
last_updated: 2026-02-24
---

# Sui Smart Contract Audit Workflow

> Sui Move auditing centers on object ownership and lifecycle. Every step of this workflow maps to the object-centric model: who owns what, who can access what, and how objects move through the system.

---

## Step 1: Module & Struct Mapping

**Goal**: Build a complete inventory of all modules, structs, functions, and their visibility.

### What to Record
```move
// For each module, document:
module protocol::lending {
    // 1. All structs and their abilities
    struct LendingPool has key { ... }          // Shared? Owned?
    struct UserPosition has key, store { ... }  // What abilities? Why?
    struct AdminCap has key { ... }             // Capability — who holds it?

    // 2. All public functions and their access patterns
    public entry fun deposit(...)     // Who can call? What objects needed?
    public entry fun borrow(...)      // What shared objects touched?
    public fun internal_calc(...)     // Helper — verify not misused

    // 3. init function — what's created at publish time?
    fun init(otw: LENDING, ctx: &mut TxContext) { ... }

    // 4. Friend modules — who has internal access?
    friend protocol::liquidation;
}
```

### Checklist
- [ ] All modules listed with dependency graph
- [ ] All structs documented with abilities (`key`, `store`, `copy`, `drop`)
- [ ] All public/entry functions mapped with required parameters
- [ ] Module `init` function reviewed for OTW compliance
- [ ] Friend declarations justified

---

## Step 2: Object Classification

**Goal**: Classify every `key` struct into ownership categories and verify the choice is appropriate.

| Object | Type | Created In | Transferred To | Appropriate? |
|---|---|---|---|---|
| `LendingPool` | Shared | `init()` | `share_object` | Yes — global state |
| `UserPosition` | Owned | `deposit()` | `transfer::transfer(user)` | Yes — per-user |
| `AdminCap` | Owned | `init()` | `transfer::transfer(deployer)` | Review: multisig? |
| `Config` | Immutable | `init()` | `freeze_object` | Yes — constants |
| `UpgradeCap` | Owned | Publish tx | ? | **Where did it go?** |

### Critical Questions
- Could any shared object be owned instead (reducing contention)?
- Are any owned objects that should be shared (needed by multiple users)?
- Is the `UpgradeCap` accounted for? (Made immutable or sent to governance?)
- Are all dynamic fields on each object bounded?

---

## Step 3: Access Control Review

**Goal**: Verify every privileged operation validates the caller.

```move
// Pattern: Every entry function on a shared object
// MUST validate tx_context::sender() or require a capability object

// SAFE: Capability-based (only cap holder can call)
public entry fun admin_action(
    _cap: &AdminCap,   // Ownership of cap IS the auth check
    pool: &mut Pool,
    ...
) { ... }

// SAFE: Sender check (explicit validation)
public entry fun admin_action(
    pool: &mut Pool,
    ctx: &mut TxContext,
) {
    assert!(tx_context::sender(ctx) == pool.admin, E_NOT_ADMIN);
    ...
}

// UNSAFE: No auth!
public entry fun admin_action(
    pool: &mut Pool,  // Shared — anyone can pass this
    // No cap, no sender check
) { ... }
```

### Checklist
- [ ] Every `public entry fun` on shared objects has auth (cap or sender check)
- [ ] `AdminCap` / governance cap secured (owned by multisig or governance)
- [ ] Cap objects use `key` only (not `store`) to prevent unauthorized transfer
- [ ] No way to create new capabilities outside `init()`

---

## Step 4: Dynamic Field Analysis

**Goal**: Verify dynamic fields are bounded, properly keyed, and cleaned up.

```move
// Audit each dynamic field usage:

// 1. What is the key type? (prefer typed structs over raw strings)
struct TickKey has copy, drop, store { tick_index: i32 }
df::add(&mut pool.id, TickKey { tick_index: 100 }, tick_data);

// 2. Is there a maximum number of entries?
assert!(pool.field_count < MAX_FIELDS, E_TOO_MANY);

// 3. Is there a cleanup path?
public entry fun remove_entry(pool: &mut Pool, key: TickKey) {
    let _data: TickData = df::remove(&mut pool.id, key);
    pool.field_count = pool.field_count - 1;
}

// 4. Before deleting parent, are all dynamic fields removed?
public entry fun destroy_pool(pool: Pool, ...) {
    // DANGER: If pool has dynamic fields, deleting it orphans them
    // Must remove all dynamic fields first
    let Pool { id, ... } = pool;
    object::delete(id);  // Dynamic fields become orphans!
}
```

### Checklist
- [ ] Typed keys used (not raw strings/bytes)
- [ ] Maximum entry count enforced
- [ ] Cleanup functions exist for removing entries
- [ ] Parent deletion preceded by dynamic field cleanup

---

## Step 5: Object Lifecycle Tracing

**Goal**: Trace every object from creation to final state (transferred, frozen, deleted, or wrapped).

```
For each key struct, trace the full lifecycle:

  CREATE ──► TRANSFER ──► USE ──► DELETE/FREEZE
    │          │           │         │
    │          │           │         ├── object::delete (destructured)
    │          │           │         ├── freeze_object (permanent)
    │          │           │         └── wrap (inside another object)
    │          │           │
    │          │           ├── &T (read)
    │          │           ├── &mut T (modify)
    │          │           └── T (consume/move)
    │          │
    │          ├── transfer::transfer (owner only, no store)
    │          ├── transfer::public_transfer (anyone, needs store)
    │          ├── transfer::share_object (make shared)
    │          └── transfer::freeze_object (make immutable)
    │
    └── object::new(ctx)
```

### Checklist
- [ ] No objects created without a transfer/share/freeze/wrap path
- [ ] No objects silently dropped (Move prevents this for `key` types)
- [ ] Wrapping operations verified (wrapped objects properly unwrapped later)
- [ ] Shared objects never transferred back to owned (impossible after share)

---

## Step 6: UpgradeCap Security

**Goal**: Verify the module upgrade path is properly secured.

### Questions
1. Where is the `UpgradeCap` after the publish transaction?
2. Is it held by a multisig/governance contract, or a single EOA?
3. Is the upgrade policy restricted? (`additive`, `dep_only`, or `immutable`)
4. Can the upgrade authority be changed?

```move
// Review upgrade restrictions:
use sui::package;

fun init(otw: MY_PROTOCOL, ctx: &mut TxContext) {
    // ...
    // upgrade_cap is produced by the publish transaction
    // Check what happens to it:

    // BEST: Make immutable (no upgrades ever)
    // package::make_immutable(upgrade_cap);

    // GOOD: Restrict to additive only
    // package::only_additive_upgrades(&mut upgrade_cap);
    // transfer::transfer(upgrade_cap, @governance_multisig);

    // RISKY: Full upgrade to a single address
    // transfer::transfer(upgrade_cap, tx_context::sender(ctx));
}
```

---

## Step 7: One-Time Witness Verification

**Goal**: Confirm init patterns are correct and cannot be replayed.

### OTW Validity Checks
```move
// Valid OTW — all criteria met:
module protocol::my_token {
    struct MY_TOKEN has drop {}  // Name matches module (uppercase), only `drop`

    fun init(otw: MY_TOKEN, ctx: &mut TxContext) {
        // otw is consumed here — can never be created again
        let (treasury, metadata) = coin::create_currency(otw, ...);
    }
}

// INVALID OTW patterns:
struct my_token has drop {}     // Wrong: lowercase name
struct MY_TOKEN has drop, copy {} // Wrong: has copy ability
struct MY_TOKEN has drop { x: u64 } // Wrong: has non-bool field
```

---

## Step 8: Transfer Policy Review

**Goal**: Verify custom transfer logic is enforced correctly.

### Checklist
- [ ] Types requiring custom transfer (NFTs with royalties) use `transfer::transfer` (not `public_transfer`)
- [ ] `TransferPolicy` objects created and configured for NFT types
- [ ] Types with `store` ability reviewed — can be freely moved with `public_transfer`
- [ ] Types that should NOT be transferable lack `store` ability

---

## Step 9: Integer & Math Review

**Goal**: Check arithmetic operations for overflow, underflow, and division issues.

```move
// Move aborts on overflow by default (safe from corruption, DoS risk)
let result = a + b;  // Aborts if overflow

// Check for:
// 1. Division by zero (causes abort)
let ratio = amount / total_supply;  // If total_supply == 0 → abort

// 2. Precision loss in division
let share = (user_amount * PRECISION) / total;  // Multiply first, divide second

// 3. Rounding direction (protocol should never round in user's favor)
let fee = (amount * fee_rate + PRECISION - 1) / PRECISION;  // Round up
```

### Checklist
- [ ] Division operations check for zero divisor
- [ ] Multiplication before division to preserve precision
- [ ] Rounding direction always favors the protocol
- [ ] Large value multiplication checked for overflow

---

## Step 10: Report & Findings

### Sui-Specific Finding Template
```markdown
## Finding: [Title]

**Severity**: Critical | High | Medium | Low
**Category**: Object Security | Access Control | Dynamic Fields | Upgrade | Transfer Policy
**Module**: protocol::module_name
**Object**: StructName (Shared/Owned/Immutable/Wrapped)

### Description
[Describe vulnerability in terms of Sui's object model]

### Object Impact
[Which objects are affected? How does ownership change?]

### Proof of Concept
[Show the transaction that exploits the vulnerability]

### Recommendation
[Fix with Move code, referencing object ownership patterns]
```

---

## Related Files

- [Sui Scanner Overview](../SKILL.md) — Architecture, Sui vs Aptos
- [Sui Patterns](../resources/sui-patterns.md) — Vulnerability patterns with code
- [Object Security](../resources/object-security.md) — Deep dive on ownership model
