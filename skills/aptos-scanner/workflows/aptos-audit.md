---
id: APTOS-WF-AUDIT
title: Aptos Move Audit Workflow
parent: aptos-scanner
type: workflow
last_updated: 2025-01-31
---

# Aptos Move Audit Workflow

Specialized 10-step audit workflow for Aptos Move smart contracts. This extends the general [Move Audit Workflow](../move-scanner/workflows/move-audit.md) with Aptos-specific checks.

---

## Step 1: Module Mapping

List all modules in the package by reading `Move.toml` and `sources/`:

```toml
# Move.toml
[package]
name = "my_protocol"
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/aptos-framework", rev = "mainnet" }

[addresses]
my_protocol = "0x1234..."
```

For each module, document:
- All `struct` definitions with abilities
- All `public entry fun` (externally callable)
- All `public fun` (callable by other modules)
- All `public(friend) fun` (callable by friend modules)
- All `fun` (internal only)
- `friend` declarations
- Constants and error codes

---

## Step 2: Ability Audit

For every struct in every module:

| Struct Purpose | Required Abilities | Dangerous If |
|---------------|-------------------|---------------|
| Token/Coin | `key` | Has `copy` (infinite minting) |
| Admin Capability | `key` | Has `copy` or `store` (leakable) |
| Config | `key, store` | Has `drop` on critical config |
| Event | `copy, drop, store` | Normal — expected for events |
| Receipt/Hot Potato | None (or just `drop`) | Has `key` or `store` (escapable) |

- [ ] No `copy` on any value-holding type
- [ ] Capabilities have minimal abilities (prefer `key` only)
- [ ] Hot potato pattern enforced where needed (no abilities = must be consumed)

---

## Step 3: Signer Validation

Every `entry fun` that modifies state must validate the signer:

```move
// CHECK: Does every entry fun with storage writes have a signer param?
public entry fun action(account: &signer, ...) {
    let addr = signer::address_of(account);
    // Is addr checked against an authorized address?
    assert!(addr == @admin || exists<AdminRole>(addr), E_UNAUTHORIZED);
}
```

For each entry function, confirm:
- [ ] Takes `&signer` parameter (not just `address`)
- [ ] `signer::address_of()` result compared to authorized identity
- [ ] Authorization check happens BEFORE any state mutation

---

## Step 4: Capability Review

Trace every capability type from creation to usage:

```
Capability Lifecycle:
Created in init_module() → Stored via move_to() → Accessed via borrow_global() → Used in function call
```

For each capability (MintCapability, BurnCapability, FreezeCapability, AdminCap, etc.):
- [ ] Created only in `init_module` (or equivalent initialization)
- [ ] Stored under a known, restricted address
- [ ] No public function returns the capability or a reference to it
- [ ] No public function accepts the capability as an owned (non-reference) parameter (would allow extraction)
- [ ] Destruction path exists and is authorized (if needed)

---

## Step 5: Module Upgrade Policy

```bash
# Check on-chain upgrade policy
aptos move show --module-id <address>::<module_name>
```

| Policy | Risk | Recommendation |
|--------|------|----------------|
| `compatible` | HIGH — module can be upgraded | Ensure upgrade auth is multisig |
| `immutable` | LOW — no changes possible | Best for finalized protocols |
| No policy set | UNKNOWN | Investigate default behavior |

- [ ] Upgrade policy explicitly set
- [ ] Upgrade authority is multisig or governance (not single EOA)
- [ ] If `compatible`, verify that upgrader cannot brick the protocol
- [ ] Storage layout won't break across upgrades

---

## Step 6: Coin Safety

If the protocol defines custom coins or interacts with `aptos_framework::coin`:

```move
// Standard coin initialization
let (burn_cap, freeze_cap, mint_cap) = coin::initialize<MyCoin>(
    account, name, symbol, decimals, monitor_supply
);
```

- [ ] Capabilities stored securely (not with `store` allowing extraction)
- [ ] `coin::register<T>()` called before `coin::deposit()` (or checked with `is_account_registered`)
- [ ] Supply monitoring enabled if total supply tracking is needed
- [ ] Consider migration to `fungible_asset` for new protocols (newer standard)

---

## Step 7: Global Storage Operations

Audit all global storage operations:

| Operation | Risk | Check |
|-----------|------|-------|
| `move_to(signer, resource)` | Low | Only stores under signer's address |
| `move_from<T>(addr)` | HIGH | Can extract resource — verify who calls this |
| `borrow_global<T>(addr)` | Medium | Read access — verify `addr` is correct |
| `borrow_global_mut<T>(addr)` | HIGH | Write access — verify authorization |
| `exists<T>(addr)` | Low | Read-only check |

- [ ] Every `move_from` is preceded by authorization check
- [ ] Every `borrow_global_mut` is preceded by authorization check
- [ ] `exists<T>` checked before `borrow_global` to avoid abort
- [ ] No TOCTOU between `exists` check and actual access (within same function: safe; across functions: check)

---

## Step 8: Friend Module Audit

```move
// List all friend declarations across all modules
friend my_protocol::module_a;
friend my_protocol::module_b;
```

- [ ] Every `friend` declaration has a documented reason
- [ ] `public(friend)` functions don't expose internal state destructively
- [ ] Friend modules can't bypass critical invariants (e.g., calling internal mint without cap check)
- [ ] No third-party modules declared as friends

---

## Step 9: Math & Integer Review

Aptos Move integers abort on overflow (safe from wrapping), but the **abort itself** can be weaponized:

- [ ] Accumulator variables (`total_supply`, `total_staked`) use `u128` or `u256`
- [ ] Division operations verify denominator != 0
- [ ] Percentage calculations: `(amount * rate) / RATE_PRECISION` order avoids unnecessary precision loss
- [ ] No integer truncation in downcasts (e.g., `(value as u64)` when value might exceed u64)

---

## Step 10: Report

### Severity + Aptos Context

| Severity | Aptos-Specific Example |
|----------|------------------------|
| **Critical** | SignerCapability exposed via public function; MintCapability with `copy` ability |
| **High** | Module upgradeable by single EOA; `move_from` without auth check |
| **Medium** | `compatible` upgrade policy on finalized protocol; Table without growth limit |
| **Low** | Missing events; generic abort codes |

For each finding, include:
- Move source with exact module::function location
- Ability analysis of affected types
- Whether fix requires module upgrade
- Aptos-specific remediation (e.g., "set upgrade policy to immutable")
