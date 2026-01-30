# FuelVM Sway Vulnerability Patterns

Comprehensive database of Fuel-specific vulnerability patterns.

---

## UTXO Patterns

### Pattern UX-01: Missing Input Validation

**Risk Level:** High

**Description:** Payable functions must verify the amount and asset ID of inputs.

**Detection Pattern:**
```
1. Find #[payable] functions
2. Check if msg_amount() verified
3. Check if msg_asset_id() verified
4. Flag missing validation
```

**Vulnerable:**
```sway
contract;

use std::context::msg_amount;

#[payable]
#[storage(write)]
fn deposit() {
    // Not checking amount or asset!
    let sender = msg_sender().unwrap();
    storage.balances.insert(sender, 100);  // Hardcoded!
}
```

**Secure:**
```sway
contract;

use std::context::{msg_amount, msg_asset_id};
use std::constants::BASE_ASSET_ID;

#[payable]
#[storage(read, write)]
fn deposit() {
    let sender = msg_sender().unwrap();
    let amount = msg_amount();
    let asset = msg_asset_id();
    
    require(asset == BASE_ASSET_ID, "Wrong asset");
    require(amount > 0, "Zero amount");
    
    let current = storage.balances.get(sender).try_read().unwrap_or(0);
    storage.balances.insert(sender, current + amount);
}
```

---

### Pattern UX-04: Asset ID Confusion

**Risk Level:** Critical

**Description:** Accepting wrong asset type can drain protocol funds.

**Detection Pattern:**
```
1. Find functions accepting assets
2. Check if msg_asset_id() compared to expected
3. Flag if any asset accepted
```

**Vulnerable:**
```sway
#[payable]
fn swap_for_token() {
    let amount = msg_amount();
    // Any asset can be swapped for tokens!
    
    mint(amount);
    transfer(msg_sender().unwrap(), AssetId::default(), amount);
}
```

**Secure:**
```sway
#[payable]
#[storage(read)]
fn swap_for_token() {
    let amount = msg_amount();
    let asset = msg_asset_id();
    
    require(
        asset == storage.accepted_asset.read(),
        "Invalid asset"
    );
    
    let output_amount = calculate_swap(amount);
    mint(output_amount);
    transfer(msg_sender().unwrap(), AssetId::default(), output_amount);
}
```

---

### Pattern UX-03: Missing Change Output

**Risk Level:** High

**Description:** If change is not returned, excess funds are locked.

**Detection Pattern:**
```
1. Find functions that spend partial amounts
2. Check if excess returned
3. Flag missing refund logic
```

**Vulnerable:**
```sway
#[payable]
fn purchase(item_id: u64) {
    let price = get_price(item_id);
    let paid = msg_amount();
    
    require(paid >= price, "Insufficient payment");
    
    // Excess funds not returned!
    deliver_item(msg_sender().unwrap(), item_id);
}
```

**Secure:**
```sway
#[payable]
fn purchase(item_id: u64) {
    let price = get_price(item_id);
    let paid = msg_amount();
    let asset = msg_asset_id();
    
    require(paid >= price, "Insufficient payment");
    
    // Return excess
    if paid > price {
        let change = paid - price;
        transfer(msg_sender().unwrap(), asset, change);
    }
    
    deliver_item(msg_sender().unwrap(), item_id);
}
```

---

## Predicate Patterns

### Pattern PR-01: Always-True Predicate

**Risk Level:** Critical

**Description:** Predicate that always returns true allows anyone to spend UTXOs.

**Detection Pattern:**
```
1. Find main() in predicates
2. Trace all return paths
3. Flag if any path always returns true
```

**Vulnerable:**
```sway
predicate;

fn main() -> bool {
    // Bug: Condition always true
    let x = 1;
    x > 0  // Always true!
}
```

**Secure:**
```sway
predicate;

use std::tx::{tx_id, tx_witness_data};
use std::ecr::ec_recover_address;

fn main(signer: Address) -> bool {
    let signature: B512 = tx_witness_data(0);
    let tx_hash = tx_id();
    
    match ec_recover_address(signature, tx_hash) {
        Ok(address) => address == signer,
        Err(_) => false
    }
}
```

---

### Pattern PR-02: Missing Signature Verification

**Risk Level:** Critical

**Description:** Predicates controlling valuable UTXOs must verify signatures.

**Detection Pattern:**
```
1. Find predicate main()
2. Check for ec_recover_address or similar
3. Flag if no cryptographic check
```

**Vulnerable:**
```sway
predicate;

// VULNERABLE: Anyone who knows the secret can spend
fn main(password: u64) -> bool {
    password == 12345  // Hardcoded secret - public on chain!
}
```

**Secure:**
```sway
predicate;

use std::tx::{tx_id, tx_witness_data};
use std::ecr::ec_recover_address;
use std::b512::B512;

fn main(expected_signer: Address) -> bool {
    // Signature is provided as witness data
    let signature: B512 = tx_witness_data(0);
    let message = tx_id();  // Unique per tx
    
    match ec_recover_address(signature, message) {
        Ok(recovered) => recovered == expected_signer,
        Err(_) => false
    }
}
```

---

### Pattern PR-03: Signature Replay

**Risk Level:** High

**Description:** If signature doesn't include unique transaction data, it can be reused.

**Detection Pattern:**
```
1. Find signature verification
2. Check what message is signed
3. Flag if message is static or predictable
```

**Vulnerable:**
```sway
predicate;

fn main(signature: B512, signer: Address) -> bool {
    // Static message - same signature works forever!
    let message = sha256("approve");
    let recovered = ec_recover_address(signature, message);
    recovered.unwrap() == signer
}
```

**Secure:**
```sway
predicate;

use std::tx::tx_id;

fn main(signer: Address) -> bool {
    let signature: B512 = tx_witness_data(0);
    // tx_id is unique per transaction
    let message = tx_id();
    
    match ec_recover_address(signature, message) {
        Ok(recovered) => recovered == signer,
        Err(_) => false
    }
}
```

---

## Access Control Patterns

### Pattern AC-01: Missing msg_sender Check

**Risk Level:** Critical

**Description:** Functions that modify state must verify the caller.

**Detection Pattern:**
```
1. Find #[storage(write)] functions
2. Check if msg_sender() used
3. Verify authorization check exists
```

**Vulnerable:**
```sway
#[storage(write)]
fn set_price(new_price: u64) {
    // Anyone can set price!
    storage.price.write(new_price);
}
```

**Secure:**
```sway
#[storage(read, write)]
fn set_price(new_price: u64) {
    let caller = msg_sender().unwrap();
    let admin = storage.admin.read();
    
    require(caller == admin, "Not admin");
    require(new_price > 0, "Invalid price");
    
    storage.price.write(new_price);
}
```

---

### Pattern AC-02: Identity Type Confusion

**Risk Level:** High

**Description:** Identity can be Address or ContractId. Mixing them up can cause issues.

**Detection Pattern:**
```
1. Find Identity comparisons
2. Check if type is verified
3. Flag if Address vs Contract not distinguished
```

**Vulnerable:**
```sway
#[storage(read)]
fn is_admin(caller: Identity) -> bool {
    caller == storage.admin.read()
    // What if admin is Address but caller is ContractId with same bits?
}
```

**Secure:**
```sway
#[storage(read)]
fn is_admin(caller: Identity) -> bool {
    match (caller, storage.admin.read()) {
        (Identity::Address(a), Identity::Address(b)) => a == b,
        (Identity::ContractId(a), Identity::ContractId(b)) => a == b,
        _ => false  // Different types never match
    }
}
```

---

## Storage Patterns

### Pattern ST-02: Uninitialized Storage Read

**Risk Level:** High

**Description:** Reading uninitialized storage slots panics.

**Detection Pattern:**
```
1. Find storage.*.read() calls
2. Check if storage initialized before read
3. Flag raw read() without try_read()
```

**Vulnerable:**
```sway
#[storage(read)]
fn get_user_balance(user: Identity) -> u64 {
    storage.balances.get(user).read()  // Panics if not set!
}
```

**Secure:**
```sway
#[storage(read)]
fn get_user_balance(user: Identity) -> u64 {
    storage.balances.get(user).try_read().unwrap_or(0)
}
```

---

### Pattern ST-03: Unbounded Storage Growth

**Risk Level:** Medium

**Description:** Storage that grows without bounds can cause DoS.

**Detection Pattern:**
```
1. Find storage collections (Vec, StorageMap)
2. Check if bounded
3. Flag unbounded growth
```

**Vulnerable:**
```sway
#[storage(write)]
fn add_entry(data: u64) {
    // Vector grows forever!
    storage.entries.push(data);
}
```

**Secure:**
```sway
const MAX_ENTRIES: u64 = 1000;

#[storage(read, write)]
fn add_entry(data: u64) {
    require(
        storage.entry_count.read() < MAX_ENTRIES,
        "Max entries reached"
    );
    
    storage.entries.push(data);
    storage.entry_count.write(storage.entry_count.read() + 1);
}
```

---

## Native Asset Patterns

### Pattern NA-01: Unrestricted Minting

**Risk Level:** Critical

**Description:** Minting must be restricted to authorized parties.

**Detection Pattern:**
```
1. Find mint() calls
2. Check authorization before mint
3. Flag unrestricted minting
```

**Vulnerable:**
```sway
fn mint_tokens(amount: u64, recipient: Identity) {
    // Anyone can mint!
    mint(amount);
    transfer(recipient, AssetId::default(), amount);
}
```

**Secure:**
```sway
#[storage(read, write)]
fn mint_tokens(amount: u64, recipient: Identity) {
    let caller = msg_sender().unwrap();
    require(caller == storage.minter.read(), "Not minter");
    
    let new_supply = storage.total_supply.read() + amount;
    require(new_supply <= storage.max_supply.read(), "Exceeds cap");
    
    mint(amount);
    transfer(recipient, AssetId::default(), amount);
    
    storage.total_supply.write(new_supply);
    
    log(MintEvent { amount, recipient });
}
```

---

## Reentrancy Patterns

### Pattern RE-01: External Call Before State Update

**Risk Level:** High

**Description:** Calling external contracts before updating state enables reentrancy.

**Detection Pattern:**
```
1. Find external calls (call, transfer)
2. Check if state updated before
3. Flag external call before state update
```

**Vulnerable:**
```sway
#[storage(read, write)]
fn withdraw(amount: u64) {
    let caller = msg_sender().unwrap();
    let balance = storage.balances.get(caller).read();
    require(balance >= amount, "Insufficient");
    
    // Transfer BEFORE state update - reentrancy!
    transfer(caller, BASE_ASSET_ID, amount);
    
    storage.balances.insert(caller, balance - amount);
}
```

**Secure:**
```sway
#[storage(read, write)]
fn withdraw(amount: u64) {
    let caller = msg_sender().unwrap();
    let balance = storage.balances.get(caller).try_read().unwrap_or(0);
    require(balance >= amount, "Insufficient");
    
    // State update FIRST
    storage.balances.insert(caller, balance - amount);
    
    // Transfer AFTER state update
    transfer(caller, BASE_ASSET_ID, amount);
}
```

---

## Script Patterns

### Pattern SC-01: Script Authorization

**Risk Level:** Medium

**Description:** Scripts can call contracts but have no persistent state.

**Secure Pattern:**
```sway
script;

use std::auth::msg_sender;

fn main(target: ContractId, action: u64) {
    // Scripts should validate the caller context
    let caller = msg_sender();
    
    // Call target contract
    abi(TargetContract, target).perform_action(action);
}
```

---

## Quick Detection Commands

```bash
# Find all Sway files
find . -name "*.sw"

# Find contracts
grep -r "contract;" src/

# Find predicates
grep -r "predicate;" src/

# Find scripts
grep -r "script;" src/

# Find payable functions
grep -r "#\[payable\]" src/

# Find storage operations
grep -r "#\[storage" src/

# Find msg_sender
grep -r "msg_sender()" src/

# Find asset operations
grep -r "msg_amount\|msg_asset_id" src/

# Find transfers
grep -r "transfer\|mint\|burn" src/

# Find authentication
grep -r "ec_recover\|ed_verify" src/
```
