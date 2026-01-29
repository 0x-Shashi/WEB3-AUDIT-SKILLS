# Cairo Vulnerability Patterns

Detailed vulnerability patterns for Cairo smart contracts on StarkNet.

---

## ST-01: Storage Collision

### Description
Different storage variables mapping to the same storage slot, causing data corruption.

### Vulnerable Code
```cairo
// Cairo 0 - Manual storage addresses can collide
@storage_var
func balance() -> (value: felt) {
}

@storage_var  
func balance() -> (value: felt) {  // Same name = collision!
}
```

### Secure Code
```cairo
// Unique names for all storage vars
#[storage]
struct Storage {
    user_balance: LegacyMap<ContractAddress, u256>,
    total_supply: u256,  // Unique naming
}
```

### Detection
- Check for duplicate storage variable names
- Verify storage struct field uniqueness
- In Cairo 0, verify @storage_var names don't repeat

---

## ST-02: Uninitialized Storage

### Description
Reading from storage before any value is written, returning default (0).

### Vulnerable Code
```cairo
fn get_admin(self: @ContractState) -> ContractAddress {
    self.admin.read()  // Returns zero if never set!
}

fn admin_action(ref self: ContractState) {
    let admin = self.admin.read();
    assert(get_caller_address() == admin, 'Not admin');
    // If admin never initialized, zero address check fails
}
```

### Secure Code
```cairo
#[constructor]
fn constructor(ref self: ContractState, admin: ContractAddress) {
    assert(!admin.is_zero(), 'Invalid admin');
    self.admin.write(admin);
    self.initialized.write(true);
}

fn admin_action(ref self: ContractState) {
    assert(self.initialized.read(), 'Not initialized');
    let admin = self.admin.read();
    assert(get_caller_address() == admin, 'Not admin');
}
```

---

## AC-01: Missing Caller Validation

### Description
External function doesn't verify the caller's identity/permissions.

### Vulnerable Code
```cairo
#[abi(embed_v0)]
impl VulnerableImpl of IContract<ContractState> {
    fn withdraw(ref self: ContractState, amount: u256) {
        // No caller check - anyone can withdraw!
        let recipient = get_caller_address();
        self._transfer(recipient, amount);
    }
}
```

### Secure Code
```cairo
#[abi(embed_v0)]
impl SecureImpl of IContract<ContractState> {
    fn withdraw(ref self: ContractState, amount: u256) {
        let caller = get_caller_address();
        let owner = self.owner.read();
        assert(caller == owner, 'Only owner can withdraw');
        
        self._transfer(caller, amount);
    }
}
```

---

## AC-04: Unprotected Initializer

### Description
Initializer can be called multiple times, allowing attacker to reset state.

### Vulnerable Code
```cairo
fn initialize(ref self: ContractState, owner: ContractAddress) {
    // No check if already initialized!
    self.owner.write(owner);
}
```

### Secure Code
```cairo
fn initialize(ref self: ContractState, owner: ContractAddress) {
    assert(!self.initialized.read(), 'Already initialized');
    assert(!owner.is_zero(), 'Invalid owner');
    
    self.owner.write(owner);
    self.initialized.write(true);
}
```

---

## AR-01: Integer Overflow

### Description
Arithmetic operations exceeding type bounds.

### Vulnerable Code
```cairo
fn add_balance(ref self: ContractState, amount: u256) {
    let current = self.balance.read();
    self.balance.write(current + amount);  // Can overflow in some contexts
}
```

### Secure Code
```cairo
use core::integer::u256_checked_add;

fn add_balance(ref self: ContractState, amount: u256) {
    let current = self.balance.read();
    let new_balance = match u256_checked_add(current, amount) {
        Option::Some(result) => result,
        Option::None => panic_with_felt252('Balance overflow'),
    };
    self.balance.write(new_balance);
}
```

---

## AR-05: Unsafe felt252 Casts

### Description
Improper conversion between felt252 and other types causing data loss or overflow.

### Vulnerable Code
```cairo
fn convert_amount(amount: u256) -> felt252 {
    amount.try_into().unwrap()  // Panics if > FELT_MAX
}

fn process(value: felt252) -> u128 {
    value.try_into().unwrap()  // Panics if > u128::MAX
}
```

### Secure Code
```cairo
const FELT252_PRIME: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;

fn convert_amount(amount: u256) -> Option<felt252> {
    if amount < FELT252_PRIME {
        amount.try_into()
    } else {
        Option::None
    }
}

fn process(value: felt252) -> Result<u128, felt252> {
    match value.try_into() {
        Option::Some(v) => Result::Ok(v),
        Option::None => Result::Err('Value too large'),
    }
}
```

---

## MSG-01: Message Replay

### Description
L1-L2 messages can be replayed if nonce not properly tracked.

### Vulnerable Code
```cairo
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256
) {
    // No nonce check - message can be replayed!
    self._mint(user, amount);
}
```

### Secure Code
```cairo
#[storage]
struct Storage {
    processed_messages: LegacyMap<felt252, bool>,
}

#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256,
    nonce: felt252
) {
    // Compute unique message hash
    let message_hash = pedersen::pedersen(
        pedersen::pedersen(from_address, user.into()),
        pedersen::pedersen(amount.low.into(), nonce)
    );
    
    // Check not already processed
    assert(!self.processed_messages.read(message_hash), 'Message already processed');
    
    // Mark as processed
    self.processed_messages.write(message_hash, true);
    
    self._mint(user, amount);
}
```

---

## MSG-03: Improper L1 Handler

### Description
L1 handler doesn't validate the expected L1 contract origin.

### Vulnerable Code
```cairo
#[l1_handler]
fn handle_message(
    ref self: ContractState,
    from_address: felt252,  // Not validated!
    data: felt252
) {
    // Any L1 address can send messages
    self._process(data);
}
```

### Secure Code
```cairo
#[storage]
struct Storage {
    l1_contract: felt252,  // Expected L1 contract address
}

#[l1_handler]
fn handle_message(
    ref self: ContractState,
    from_address: felt252,
    data: felt252
) {
    // Verify sender is expected L1 contract
    let expected = self.l1_contract.read();
    assert(from_address == expected, 'Invalid L1 sender');
    
    self._process(data);
}
```

---

## RE-01: External Call Before State Update

### Description
Making external calls before updating contract state, enabling reentrancy.

### Vulnerable Code
```cairo
fn withdraw(ref self: ContractState, amount: u256) {
    let caller = get_caller_address();
    let balance = self.balances.read(caller);
    assert(balance >= amount, 'Insufficient balance');
    
    // External call BEFORE state update
    IERC20Dispatcher { contract_address: self.token.read() }
        .transfer(caller, amount);
    
    // State update AFTER - vulnerable!
    self.balances.write(caller, balance - amount);
}
```

### Secure Code
```cairo
fn withdraw(ref self: ContractState, amount: u256) {
    let caller = get_caller_address();
    let balance = self.balances.read(caller);
    assert(balance >= amount, 'Insufficient balance');
    
    // State update FIRST
    self.balances.write(caller, balance - amount);
    
    // External call AFTER
    IERC20Dispatcher { contract_address: self.token.read() }
        .transfer(caller, amount);
}
```

---

## CS-01: Felt252 Range Issues

### Description
felt252 has range [0, P-1] where P is the Cairo prime. Values >= P are invalid.

### Vulnerable Code
```cairo
// Assuming user input is always valid felt252
fn process_input(input: felt252) {
    // Input could be >= P (invalid)
    let result = input * 2;  // Modular arithmetic surprise
}
```

### Secure Code
```cairo
const MAX_SAFE_FELT: felt252 = 0x400000000000000000000000000000000000000000000000000000000000000;

fn process_input(input: felt252) -> Result<felt252, felt252> {
    // For critical operations, validate range
    // Or use bounded types like u256, u128
    if input < MAX_SAFE_FELT {
        Result::Ok(input * 2)
    } else {
        Result::Err('Input too large')
    }
}
```

---

## CS-05: Unsafe unwrap() Usage

### Description
Using .unwrap() on Option/Result without handling the None/Err case.

### Vulnerable Code
```cairo
fn get_balance(self: @ContractState, user: ContractAddress) -> u256 {
    // Will panic if conversion fails
    let balance: u256 = self.raw_balance.read(user).try_into().unwrap();
    balance
}
```

### Secure Code
```cairo
fn get_balance(self: @ContractState, user: ContractAddress) -> Option<u256> {
    let raw = self.raw_balance.read(user);
    raw.try_into()  // Return Option, let caller handle
}

// Or with explicit handling
fn get_balance_safe(self: @ContractState, user: ContractAddress) -> u256 {
    let raw = self.raw_balance.read(user);
    match raw.try_into() {
        Option::Some(balance) => balance,
        Option::None => 0_u256,  // Default value
    }
}
```

---

## UP-01: Unprotected Upgrade

### Description
Upgrade function can be called by unauthorized accounts.

### Vulnerable Code
```cairo
use starknet::ClassHash;

fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    // No access control!
    starknet::replace_class_syscall(new_class_hash);
}
```

### Secure Code
```cairo
use starknet::ClassHash;
use starknet::get_caller_address;

fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    // Verify caller is owner
    let caller = get_caller_address();
    assert(caller == self.owner.read(), 'Only owner can upgrade');
    
    // Verify valid class hash
    assert(!new_class_hash.is_zero(), 'Invalid class hash');
    
    // Emit event before upgrade
    self.emit(Upgraded { new_class_hash });
    
    // Perform upgrade
    starknet::replace_class_syscall(new_class_hash);
}
```

---

## UP-02: Storage Layout Change

### Description
Changing storage layout during upgrade corrupts existing data.

### Vulnerable Pattern
```cairo
// Version 1
#[storage]
struct Storage {
    owner: ContractAddress,    // Slot 0
    balance: u256,             // Slot 1
}

// Version 2 - WRONG
#[storage]
struct Storage {
    admin: ContractAddress,    // Renamed but same slot - OK
    total: u256,               // Renamed but same slot - OK
    new_field: u256,           // Added at end - OK
}

// Version 2 - DANGEROUS
#[storage]
struct Storage {
    new_field: u256,           // Inserted at beginning!
    owner: ContractAddress,    // Now at different slot - CORRUPTED
    balance: u256,             // Now at different slot - CORRUPTED
}
```

### Secure Pattern
```cairo
// Always append new fields at the end
// Never remove or reorder existing fields
// Use reserved slots for future additions

#[storage]
struct Storage {
    owner: ContractAddress,    // Slot 0 - never change
    balance: u256,             // Slot 1 - never change
    _reserved1: felt252,       // Reserved for future
    _reserved2: felt252,       // Reserved for future
    new_field: u256,           // Added after reserved slots
}
```
