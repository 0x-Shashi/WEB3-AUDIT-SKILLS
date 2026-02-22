---
id: MOVE-APTOS-SEC
title: Aptos Security Considerations
parent: move-scanner
type: resource
last_updated: 2025-01-31
---

# Aptos Security Considerations

Aptos-specific security concerns, patterns, and audit guidance. Aptos uses Move with a global storage model where resources are stored under account addresses.

---

## Account & Global Storage Model

Aptos uses a **global storage** model where resources are stored under account addresses:

| Operation | Purpose | Security Concern |
|-----------|---------|------------------|
| `move_to(signer, resource)` | Store resource under signer's address | Requires signer — can only store under own address |
| `move_from<T>(addr)` | Remove resource from address | Requires `acquires` — check authorization |
| `borrow_global<T>(addr)` | Immutable reference to resource | Read-only — safer but still needs `acquires` |
| `borrow_global_mut<T>(addr)` | Mutable reference to resource | Can modify — verify caller is authorized |
| `exists<T>(addr)` | Check if resource exists | Read-only check — safe |

### Storage Security Rules

- **`move_to` requires a `&signer`** — you can only place resources under your own address
- **`move_from` can extract resources from any address** (if you have `acquires`) — verify the caller should be allowed to do this
- **Resources at an address are unique by type** — only one `T` per address
- **Accessing non-existent resource aborts** — always check `exists<T>(addr)` first

---

## Module Upgrade System

Aptos modules are upgradeable by default, which is a significant security consideration.

### Upgrade Policies

| Policy | Description | Security Level |
|--------|-------------|----------------|
| `compatible` | Module can be upgraded with compatible changes (default) | LOW — upgrade authority can change logic |
| `immutable` | Module cannot be upgraded after deployment | HIGH — code is permanent |

### Compatibility Requirements for Upgrades

When upgrading with `compatible` policy:
- Public function signatures cannot change
- Struct layouts cannot change (new fields can be added, none removed)
- `friend` declarations can be added but not removed
- New modules can be added to the package

### Upgrade Authority Security

```move
// Check: Who holds the upgrade authority?
// The account that published the module holds the upgrade authority
// If this is an EOA (externally owned account), a single compromised key = protocol takeover

// BETTER: Set upgrade policy to immutable after deployment
aptos_framework::code::publish_package_txn(
    account,
    metadata,
    code,
    // Set policy to immutable
);
```

### Upgrade Audit Checklist

- [ ] Upgrade policy identified (`compatible` or `immutable`)
- [ ] Upgrade authority secured (multisig, not single EOA)
- [ ] If `compatible`, review what changed in upgrade
- [ ] Storage layout compatibility verified
- [ ] Critical protocols should consider `immutable` policy

---

## Aptos Framework Modules — Security-Critical

| Module | Purpose | Audit Focus |
|--------|---------|-------------|
| `aptos_framework::coin` | Fungible token standard | Mint/burn authority, registration, transfer safety |
| `aptos_framework::account` | Account creation and auth key | Auth key rotation, signing capability |
| `aptos_framework::resource_account` | Create deterministic accounts | Signer capability management |
| `aptos_framework::object` | Object model (newer) | Object ownership, transfer logic |
| `aptos_framework::randomness` | On-chain randomness | Not manipulable by validators (commit-reveal) |
| `aptos_framework::staking_contract` | Delegation staking | Reward calculation, commission |
| `aptos_framework::governance` | On-chain governance | Proposal execution, voting power |

### Coin Module Security

```move
// CRITICAL: MintCapability and BurnCapability must be properly stored
struct MyToken {}

fun init_module(admin: &signer) {
    let (burn_cap, freeze_cap, mint_cap) = coin::initialize<MyToken>(
        admin,
        string::utf8(b"My Token"),
        string::utf8(b"MTK"),
        8, // decimals
        true, // monitor supply
    );
    
    // SECURE: Store caps under admin address (not publicly accessible)
    move_to(admin, Caps { burn_cap, freeze_cap, mint_cap });
}

// SECURE: Only cap holder can mint
public entry fun mint(admin: &signer, to: address, amount: u64) acquires Caps {
    let caps = borrow_global<Caps>(signer::address_of(admin));
    let coins = coin::mint(amount, &caps.mint_cap);
    coin::deposit(to, coins);
}
```

---

## Common Aptos Vulnerabilities

### 1. Missing `acquires` Annotation

```move
// COMPILE ERROR: move_from requires acquires
public fun extract(addr: address): MyResource {
    move_from<MyResource>(addr) // Error: function must be annotated with 'acquires'
}

// CORRECT:
public fun extract(addr: address): MyResource acquires MyResource {
    move_from<MyResource>(addr)
}
```

While this is a compile-time check, its presence/absence indicates design intent.

### 2. Signer vs Address Confusion

```move
// VULNERABLE: Takes address, not signer — no authentication
public entry fun withdraw(user_addr: address, amount: u64) acquires Balance {
    let balance = borrow_global_mut<Balance>(user_addr);
    // Anyone can call this with any user_addr!
}

// SAFE: Takes signer — proves caller identity
public entry fun withdraw(user: &signer, amount: u64) acquires Balance {
    let addr = signer::address_of(user);
    let balance = borrow_global_mut<Balance>(addr);
}
```

### 3. Resource Account Signer Capability Leak

```move
// Resource accounts use SignerCapability for programmatic signing
// DANGEROUS: If SignerCapability leaks, anyone can sign as the resource account

struct Config has key {
    signer_cap: account::SignerCapability, // Must be protected!
}

// VULNERABLE: Public function exposes signer capability
public fun get_signer(config: &Config): signer {
    account::create_signer_with_capability(&config.signer_cap)
}

// SAFE: Only accessible through controlled paths
fun internal_get_signer(config: &Config): signer {
    account::create_signer_with_capability(&config.signer_cap)
}
```

### 4. Table/SimpleMap Unbounded Growth

```move
// RISKY: Tables can grow without bound
struct Registry has key {
    entries: Table<address, EntryData>,
    // No count limit — could become expensive to iterate or manage
}

// BETTER: Track count and enforce limit
struct Registry has key {
    entries: Table<address, EntryData>,
    count: u64,
}
const MAX_ENTRIES: u64 = 100000;
assert!(registry.count < MAX_ENTRIES, E_REGISTRY_FULL);
```

---

## Aptos Audit Checklist

- [ ] Module upgrade policy assessed and appropriate
- [ ] Upgrade authority is multisig or governance-controlled
- [ ] All capabilities (Mint, Burn, Freeze) properly stored and access-controlled
- [ ] All entry functions use `&signer` for authentication (not just `address`)
- [ ] `acquires` annotations present on all functions that access global storage
- [ ] Resource account SignerCapability not publicly accessible
- [ ] Friend module declarations are minimal and justified
- [ ] Coin operations use `aptos_framework::coin` correctly
- [ ] Events emitted for all significant state changes
- [ ] Integer types appropriately sized (u64 vs u128 for large values)
- [ ] Tables/SimpleMaps have growth bounds
