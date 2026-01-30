# Starknet Cairo 1.0 Vulnerability Patterns

Comprehensive database of Starknet-specific vulnerability patterns.

---

## Account Abstraction Patterns

### Pattern AA-01: Signature Replay

**Risk Level:** Critical

**Description:** Without proper nonce and chain_id verification, signed transactions can be replayed.

**Detection Pattern:**
```
1. Find __validate__ function
2. Check if nonce verified from tx_info
3. Check if chain_id verified
4. Flag missing checks
```

**Vulnerable:**
```cairo
#[starknet::contract]
mod VulnerableAccount {
    use starknet::get_tx_info;
    use starknet::account::Call;
    
    #[storage]
    struct Storage {
        public_key: felt252,
    }
    
    #[external(v0)]
    fn __validate__(
        self: @ContractState,
        calls: Array<Call>
    ) -> felt252 {
        let tx_info = get_tx_info().unbox();
        
        // Only checks signature, not nonce!
        let valid = check_ecdsa_signature(
            tx_info.transaction_hash,
            self.public_key.read(),
            *tx_info.signature.at(0),
            *tx_info.signature.at(1)
        );
        
        assert(valid, 'Invalid signature');
        starknet::VALIDATED
    }
}
```

**Secure:**
```cairo
#[starknet::contract]
mod SecureAccount {
    use starknet::get_tx_info;
    use starknet::account::Call;
    
    #[storage]
    struct Storage {
        public_key: felt252,
        nonce: felt252,
    }
    
    const EXPECTED_CHAIN_ID: felt252 = 'SN_MAIN';
    
    #[external(v0)]
    fn __validate__(
        self: @ContractState,
        calls: Array<Call>
    ) -> felt252 {
        let tx_info = get_tx_info().unbox();
        
        // Verify nonce
        assert(tx_info.nonce == self.nonce.read(), 'Invalid nonce');
        
        // Verify chain
        assert(tx_info.chain_id == EXPECTED_CHAIN_ID, 'Wrong chain');
        
        // Verify signature
        let valid = check_ecdsa_signature(
            tx_info.transaction_hash,
            self.public_key.read(),
            *tx_info.signature.at(0),
            *tx_info.signature.at(1)
        );
        assert(valid, 'Invalid signature');
        
        starknet::VALIDATED
    }
    
    #[external(v0)]
    fn __execute__(
        ref self: ContractState,
        calls: Array<Call>
    ) -> Array<Span<felt252>> {
        // Increment nonce
        self.nonce.write(self.nonce.read() + 1);
        execute_calls(calls)
    }
}
```

---

### Pattern AA-02: __validate__ Bypass

**Risk Level:** Critical

**Description:** If __validate__ can be bypassed, unauthorized transactions execute.

**Detection Pattern:**
```
1. Check __validate__ always returns VALIDATED or reverts
2. Verify no early returns without validation
3. Check all code paths
```

**Vulnerable:**
```cairo
#[external(v0)]
fn __validate__(
    self: @ContractState,
    calls: Array<Call>
) -> felt252 {
    // VULNERABLE: Returns validated even if signature fails
    if (calls.len() == 0) {
        return starknet::VALIDATED;  // Bypass for empty calls
    }
    
    // Signature check only happens for non-empty
    verify_signature(...);
    starknet::VALIDATED
}
```

**Secure:**
```cairo
#[external(v0)]
fn __validate__(
    self: @ContractState,
    calls: Array<Call>
) -> felt252 {
    // SECURE: Always validate, no special cases
    verify_signature(...);  // Reverts if invalid
    starknet::VALIDATED
}
```

---

### Pattern AA-03: Multicall Reentrancy

**Risk Level:** High

**Description:** Multicall executes multiple calls atomically. State changes between calls can be exploited.

**Detection Pattern:**
```
1. Find __execute__ multicall implementation
2. Check if state is modified between calls
3. Look for cross-call dependencies
```

**Vulnerable:**
```cairo
fn execute_calls(mut calls: Array<Call>) -> Array<Span<felt252>> {
    let mut results = ArrayTrait::new();
    
    loop {
        match calls.pop_front() {
            Option::Some(call) => {
                // Each call can see state from previous calls
                // Attacker can exploit ordering
                let result = execute_single_call(call);
                results.append(result);
            },
            Option::None => { break; }
        }
    };
    
    results
}
```

**Mitigation:**
```cairo
// Be aware of ordering dependencies
// Consider batching reads before writes
// Add reentrancy guards if needed
```

---

## L1L2 Messaging Patterns

### Pattern L2-01: L1 Handler Replay

**Risk Level:** Critical

**Description:** L1L2 messages must only be processed once.

**Note:** Starknet automatically consumes messages, but logic errors can allow similar attacks.

**Detection Pattern:**
```
1. Find #[l1_handler] functions
2. Check if idempotent
3. Verify no double-processing logic
```

**Secure Pattern:**
```cairo
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256,
    nonce: u256  // Optional: application-level nonce
) {
    // Verify L1 sender
    assert(from_address == self.l1_bridge.read().into(), 'Invalid sender');
    
    // Optional: Check nonce hasn't been used (for extra safety)
    assert(!self.processed_nonces.read(nonce), 'Already processed');
    self.processed_nonces.write(nonce, true);
    
    // Process deposit
    self.mint(user, amount);
}
```

---

### Pattern L2-02: L1 Sender Verification

**Risk Level:** Critical

**Description:** L1 handler must verify the L1 sender is trusted.

**Detection Pattern:**
```
1. Find #[l1_handler] functions
2. Check if from_address verified
3. Flag if any caller accepted
```

**Vulnerable:**
```cairo
#[l1_handler]
fn handle_message(
    ref self: ContractState,
    from_address: felt252,  // Not checked!
    payload: felt252
) {
    // Any L1 contract can send messages to this handler
    process_payload(payload);
}
```

**Secure:**
```cairo
#[l1_handler]
fn handle_message(
    ref self: ContractState,
    from_address: felt252,
    payload: felt252
) {
    // Only accept from our L1 contract
    assert(from_address == self.trusted_l1_contract.read().into(), 'Untrusted sender');
    process_payload(payload);
}
```

---

### Pattern L2-03: L2L1 Message Consumption

**Risk Level:** High

**Description:** L2L1 messages require proof verification on L1. Premature state changes can be exploited.

**Detection Pattern:**
```
1. Find send_message_to_l1 calls
2. Check if state changes assume successful delivery
3. Verify L1 side handles failures
```

**Vulnerable:**
```cairo
#[external(v0)]
fn withdraw(ref self: ContractState, amount: u256) {
    let user = get_caller_address();
    
    // Burn tokens immediately
    self.burn(user, amount);
    
    // Send message to L1 (might fail to be proven!)
    starknet::send_message_to_l1_syscall(
        self.l1_bridge.read().into(),
        array![user.into(), amount.low.into(), amount.high.into()].span()
    );
    
    // If L1 tx fails, user loses funds
}
```

**Secure:**
```cairo
#[external(v0)]
fn withdraw(ref self: ContractState, amount: u256) {
    let user = get_caller_address();
    let withdrawal_id = self.next_withdrawal_id.read();
    self.next_withdrawal_id.write(withdrawal_id + 1);
    
    // Lock tokens (don't burn yet)
    self.locked_for_withdrawal.write((user, withdrawal_id), amount);
    
    starknet::send_message_to_l1_syscall(
        self.l1_bridge.read().into(),
        array![withdrawal_id.into(), user.into(), amount.low.into(), amount.high.into()].span()
    );
    
    // L1 confirms withdrawal  call finalize_withdrawal
    // If L1 fails  user can cancel after timeout
}

#[external(v0)]
fn cancel_withdrawal(ref self: ContractState, withdrawal_id: u256) {
    // Allow cancellation after timeout if L1 didn't confirm
    let locked = self.locked_for_withdrawal.read((get_caller_address(), withdrawal_id));
    assert(locked > 0, 'No withdrawal');
    
    let created = self.withdrawal_time.read(withdrawal_id);
    assert(get_block_timestamp() > created + TIMEOUT, 'Too early');
    
    self.locked_for_withdrawal.write((get_caller_address(), withdrawal_id), 0);
    self.transfer(get_caller_address(), locked);
}
```

---

## Storage Patterns

### Pattern ST-01: Storage Slot Collision

**Risk Level:** Critical

**Description:** Changing storage struct layout can cause slot collisions after upgrade.

**Detection Pattern:**
```
1. Compare V1 and V2 storage layouts
2. Check if any fields inserted (not appended)
3. Verify slot calculations match
```

**Vulnerable:**
```cairo
// V1
#[storage]
struct Storage {
    admin: ContractAddress,
    balance: u256,
}

// V2 - WRONG
#[storage]
struct Storage {
    admin: ContractAddress,
    paused: bool,   // Inserted! Shifts balance slot
    balance: u256,
}
```

**Secure:**
```cairo
// V1
#[storage]
struct Storage {
    admin: ContractAddress,
    balance: u256,
}

// V2 - CORRECT
#[storage]
struct Storage {
    admin: ContractAddress,
    balance: u256,
    paused: bool,  // Appended at end
}
```

---

### Pattern ST-02: Uninitialized Storage

**Risk Level:** High

**Description:** Storage defaults to 0/false. Assuming initialization can be dangerous.

**Detection Pattern:**
```
1. Find storage reads without prior write
2. Check if zero value has meaning
3. Flag assumptions about initialized state
```

**Vulnerable:**
```cairo
#[external(v0)]
fn get_owner(self: @ContractState) -> ContractAddress {
    self.owner.read()  // Returns 0 if not initialized
}

#[external(v0)]
fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
    assert(get_caller_address() == self.owner.read(), 'Not owner');
    // If owner never set (0), anyone where caller == 0 can call
    // But caller is never 0... so NO ONE can call!
}
```

**Secure:**
```cairo
#[constructor]
fn constructor(ref self: ContractState, owner: ContractAddress) {
    assert(owner.is_non_zero(), 'Invalid owner');
    self.owner.write(owner);
    self.initialized.write(true);
}

#[external(v0)]
fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
    assert(self.initialized.read(), 'Not initialized');
    assert(get_caller_address() == self.owner.read(), 'Not owner');
    self.owner.write(new_owner);
}
```

---

## Cairo Type Patterns

### Pattern CS-01: felt252 Overflow

**Risk Level:** High

**Description:** felt252 operations wrap modulo the prime. This can cause unexpected behavior.

**Detection Pattern:**
```
1. Find arithmetic on felt252
2. Check if result can exceed prime
3. Flag unchecked operations
```

**Vulnerable:**
```cairo
fn add_balances(a: felt252, b: felt252) -> felt252 {
    a + b  // Wraps on overflow!
}
```

**Secure:**
```cairo
// Use u256 for amounts
fn add_balances(a: u256, b: u256) -> u256 {
    a + b  // Panics on overflow in Cairo 1.0
}

// Or explicit felt252 check
fn add_balances_felt(a: felt252, b: felt252) -> felt252 {
    let result = a + b;
    // Check for wrap (simplified - real check needs more care)
    assert(result >= a || result >= b, 'Overflow');
    result
}
```

---

### Pattern CS-03: Option Unwrap on None

**Risk Level:** Medium

**Description:** Calling unwrap on None panics. Must handle None case.

**Detection Pattern:**
```
1. Find .unwrap() calls
2. Check if None is possible
3. Flag unsafe unwraps
```

**Vulnerable:**
```cairo
fn get_user(self: @ContractState, user: ContractAddress) -> User {
    self.users.read(user).unwrap()  // Panics if user not found
}
```

**Secure:**
```cairo
fn get_user(self: @ContractState, user: ContractAddress) -> Option<User> {
    self.users.read(user)
}

// Or with default
fn get_balance(self: @ContractState, user: ContractAddress) -> u256 {
    match self.balances.read(user) {
        Option::Some(balance) => balance,
        Option::None => 0_u256,
    }
}
```

---

## Access Control Patterns

### Pattern AC-01: Missing Caller Verification

**Risk Level:** Critical

**Description:** External functions must verify the caller is authorized.

**Detection Pattern:**
```
1. Find #[external(v0)] functions
2. Check if get_caller_address() used
3. Verify authorization check exists
```

**Vulnerable:**
```cairo
#[external(v0)]
fn set_admin(ref self: ContractState, new_admin: ContractAddress) {
    // Anyone can call!
    self.admin.write(new_admin);
}
```

**Secure:**
```cairo
#[external(v0)]
fn set_admin(ref self: ContractState, new_admin: ContractAddress) {
    assert(get_caller_address() == self.admin.read(), 'Not admin');
    assert(new_admin.is_non_zero(), 'Invalid admin');
    self.admin.write(new_admin);
}
```

---

### Pattern AC-03: Library Call Injection

**Risk Level:** Critical

**Description:** library_call executes code in caller's context. Untrusted class_hash is dangerous.

**Detection Pattern:**
```
1. Find library_call_syscall usage
2. Check if class_hash is hardcoded or verified
3. Flag user-controlled class_hash
```

**Vulnerable:**
```cairo
#[external(v0)]
fn execute_library(
    ref self: ContractState,
    class_hash: ClassHash,  // User controlled!
    selector: felt252,
    calldata: Array<felt252>
) -> Span<felt252> {
    starknet::library_call_syscall(
        class_hash,
        selector,
        calldata.span()
    ).unwrap()
}
```

**Secure:**
```cairo
#[external(v0)]
fn execute_library(
    ref self: ContractState,
    selector: felt252,
    calldata: Array<felt252>
) -> Span<felt252> {
    // Use hardcoded or stored verified class_hash
    let class_hash = self.trusted_library.read();
    
    starknet::library_call_syscall(
        class_hash,
        selector,
        calldata.span()
    ).unwrap()
}
```

---

## Event Patterns

### Pattern EV-01: Missing Events

**Risk Level:** Low-Medium

**Description:** Critical state changes should emit events for tracking.

**Secure Pattern:**
```cairo
#[event]
#[derive(Drop, starknet::Event)]
enum Event {
    Transfer: Transfer,
    Approval: Approval,
    OwnershipTransferred: OwnershipTransferred,
}

#[derive(Drop, starknet::Event)]
struct Transfer {
    #[key]
    from: ContractAddress,
    #[key]
    to: ContractAddress,
    amount: u256,
}

#[external(v0)]
fn transfer(ref self: ContractState, to: ContractAddress, amount: u256) {
    let from = get_caller_address();
    // ... transfer logic
    
    self.emit(Transfer { from, to, amount });
}
```

---

## Quick Detection Commands

```bash
# Find external functions
grep -r "#\[external" src/ --include="*.cairo"

# Find L1 handlers
grep -r "#\[l1_handler\]" src/

# Find storage struct
grep -r "#\[storage\]" src/ -A 20

# Find caller checks
grep -r "get_caller_address" src/

# Find upgrades
grep -r "replace_class_syscall" src/

# Find assertions
grep -r "assert(" src/

# Find unwrap calls
grep -r "\.unwrap()" src/

# Find library calls
grep -r "library_call" src/
```
