---
id: FUEL-PATTERNS
title: Fuel / Sway Vulnerability Patterns
parent: fuel-scanner
type: resource
last_updated: 2025-01-31
---

# Fuel / Sway Vulnerability Patterns

Detailed vulnerability patterns for Fuel Network smart contracts written in Sway, organized by severity.

---

## Critical

### 1. UTXO Double Consumption

In Fuel's UTXO model, each coin is a distinct unspent output. The FuelVM enforces that a UTXO can only be spent once per transaction, but **logical double-spend** can occur at the application layer:

```sway
// VULNERABLE: Contract tracks deposits by amount, not by UTXO
storage {
    deposits: StorageMap<Identity, u64> = StorageMap {},
}

#[storage(read, write)]
fn deposit() {
    let sender = msg_sender().unwrap();
    let current = storage.deposits.get(sender).try_read().unwrap_or(0);
    // If called twice in same transaction with same amount,
    // the balance is double-counted
    storage.deposits.insert(sender, current + msg_amount());
}
```

**Mitigation:** Use unique identifiers (UTXO IDs or nonces) for deposit tracking rather than just sender + amount.

---

### 2. Predicate Logic Bypass

Predicates are stateless spending conditions. A logic error means anyone can spend the locked UTXOs:

```sway
predicate;

// VULNERABLE: Time-lock predicate with off-by-one
fn main(unlock_time: u64) -> bool {
    // height() returns current block height
    // BUG: Should be >= not >
    // At exactly unlock_time, the predicate returns false
    // But more critically: what prevents the spender from providing
    // a different unlock_time argument?
    height() > unlock_time
}

// SAFE: Hardcode the unlock time (predicates are deployed with fixed bytecode)
predicate;

configurable {
    UNLOCK_HEIGHT: u64 = 1000000,
    AUTHORIZED_RECIPIENT: Address = Address::zero(),
}

fn main() -> bool {
    // Configurable values are baked into predicate bytecode
    // Cannot be changed by the spender
    height() >= UNLOCK_HEIGHT
    && output_address_matches(AUTHORIZED_RECIPIENT)
}
```

**Key Principle:** Predicates should use `configurable` for constants (baked into bytecode) rather than function parameters (supplied by spender and thus controllable by anyone).

---

### 3. Asset Confusion

```sway
// VULNERABLE: Accepts any asset as payment
#[storage(read, write), payable]
fn buy_nft(nft_id: u64) {
    let payment = msg_amount();
    require(payment >= PRICE, "insufficient payment");
    // BUG: Never checks msg_asset_id()
    // Attacker sends worthless custom asset with enough amount
    transfer_nft(msg_sender().unwrap(), nft_id);
}

// SAFE: Explicitly validate asset ID
#[storage(read, write), payable]
fn buy_nft(nft_id: u64) {
    require(msg_asset_id() == AssetId::base(), "wrong asset");
    require(msg_amount() >= PRICE, "insufficient payment");
    transfer_nft(msg_sender().unwrap(), nft_id);
}
```

---

## High

### 4. Missing `msg_sender()` Validation

```sway
// VULNERABLE: Privileged function without access control
#[storage(read, write)]
fn set_price(new_price: u64) {
    storage.price.write(new_price);
    // Anyone can call this!
}

// SAFE: Owner check
#[storage(read, write)]
fn set_price(new_price: u64) {
    require(
        msg_sender().unwrap() == storage.owner.read(),
        "only owner"
    );
    storage.price.write(new_price);
}
```

### 5. Identity Type Confusion

Fuel has two identity types: `Address` (EOA) and `ContractId` (contract). The `Identity` enum wraps both:

```sway
pub enum Identity {
    Address: Address,
    ContractId: ContractId,
}

// VULNERABLE: Comparing Address to ContractId
fn check_owner(caller: Identity) -> bool {
    // If storage.owner is Address but caller is ContractId (or vice versa),
    // this comparison is always false even if the bytes are the same
    caller == storage.owner.read()
}

// SAFE: Match on identity variant explicitly when needed
fn check_owner(caller: Identity) -> bool {
    match caller {
        Identity::Address(addr) => {
            match storage.owner.read() {
                Identity::Address(owner_addr) => addr == owner_addr,
                _ => false,
            }
        },
        Identity::ContractId(id) => {
            match storage.owner.read() {
                Identity::ContractId(owner_id) => id == owner_id,
                _ => false,
            }
        },
    }
}
```

### 6. Storage Key Collision

```sway
// Sway auto-generates storage slot keys from variable names
// But manual slot assignment can collide:
storage {
    // These use automatic slot derivation — safe
    balance: u64 = 0,
    owner: Identity = Identity::Address(Address::zero()),
    
    // DANGEROUS: Manual storage access with raw slots
    // Can potentially collide with auto-generated slots
}

// Also risky in proxy/upgrade patterns:
// If upgraded contract changes storage layout,
// new variable names may generate different slots,
// corrupting existing state
```

---

## Medium

### 7. Integer Overflow

Sway uses `u8`, `u16`, `u32`, `u64`, `u256`. Overflow behavior depends on context:

| Context | u64 behavior | u256 behavior |
|---------|-------------|---------------|
| Debug mode | Panics | Panics |
| Release mode | Wraps | Wraps |
| FuelVM ops | VM-defined | VM-defined |

```sway
// RISKY: Addition may wrap in release builds
let total = balance + deposit; // If balance + deposit > u64::MAX, wraps to small number

// SAFER: Use checked arithmetic
let total = balance.checked_add(deposit).unwrap_or_revert();
```

### 8. Script Return Value Not Validated

```sway
// Script calls multiple contracts in sequence
script;

fn main(pool: ContractId, token: ContractId) {
    let pool_contract = abi(Pool, pool.into());
    let token_contract = abi(Token, token.into());
    
    // RISKY: Not checking return values
    pool_contract.swap(100, 0);
    token_contract.transfer(recipient, amount);
    // If swap fails silently, transfer still proceeds
}
```

### 9. Predicate Gas Limit

```sway
predicate;

// VULNERABLE: Complex predicate that may exceed gas limit
fn main(data: Vec<u64>) -> bool {
    let mut i = 0;
    while i < data.len() { // O(n) loop
        // Complex validation
        i += 1;
    }
    true
}
// If gas limit exceeded, predicate ALWAYS returns false
// Funds locked in predicate forever!
```

---

## Fuel Audit Checklist

- [ ] `msg_sender()` validated on all privileged contract functions
- [ ] `msg_asset_id()` explicitly checked (never assumed) on all `payable` functions
- [ ] Predicate logic uses `configurable` for constants, not function parameters
- [ ] Predicate gas consumption estimated and within limits
- [ ] `Identity` type comparisons handle `Address` vs `ContractId` correctly
- [ ] Storage keys unique and non-colliding (especially in upgrade patterns)
- [ ] Integer arithmetic uses checked operations in critical paths
- [ ] Script return values validated
- [ ] UTXO tracking uses unique identifiers (not just amount)
- [ ] All asset types explicitly validated in multi-asset operations
