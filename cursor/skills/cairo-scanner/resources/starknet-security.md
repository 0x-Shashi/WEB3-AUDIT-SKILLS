# StarkNet-Specific Security

Security considerations unique to StarkNet blockchain and Cairo smart contracts.

---

## StarkNet Architecture Security

### Account Abstraction

StarkNet uses native account abstraction where every account is a smart contract.

```cairo
// Account Contract Must Implement
trait IAccount {
    fn __validate__(calls: Array<Call>) -> felt252;
    fn __execute__(calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate_declare__(class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        class_hash: felt252, 
        salt: felt252, 
        public_key: felt252
    ) -> felt252;
}
```

**Security Considerations:**
- `__validate__` must properly verify signatures
- Failed validation still consumes gas
- Custom validation logic can introduce vulnerabilities
- Replay protection must be implemented (nonces)

### Class Hash vs Contract Address

```cairo
// Class = The code (like a Solidity contract)
// Instance = Deployed contract with state

// Verify you're calling the right implementation
let expected_class: ClassHash = 0x123...;
let actual_class = starknet::get_class_hash_at(contract_address);
assert(actual_class == expected_class, 'Wrong implementation');
```

---

## Fee Mechanism

### Sequencer Fee Payment

```cairo
// Transactions pay fees in ETH or STRK
// Fee = gas_consumed * gas_price

// Security: 
// - Users can specify max_fee
// - Unused fee is refunded
// - Failed transactions still pay for execution up to failure

// Attack vector: Gas griefing
// Defense: Set appropriate gas limits
```

---

## Syscalls Security

### get_caller_address

```cairo
use starknet::get_caller_address;

// Returns zero address for:
// 1. L1 handler invocations (from_address is separate)
// 2. Direct sequencer calls (constructor, etc.)

fn secure_caller_check(self: @ContractState) {
    let caller = get_caller_address();
    
    // IMPORTANT: Check for zero address
    assert(!caller.is_zero(), 'Invalid caller');
    assert(caller == self.owner.read(), 'Not owner');
}
```

### get_contract_address

```cairo
use starknet::get_contract_address;

// Returns the address of the current contract
// Useful for:
// - Self-referential logic
// - Token approvals from contract
// - Verifying callback targets

fn verify_callback(expected: ContractAddress) {
    assert(get_contract_address() == expected, 'Wrong callback target');
}
```

### get_tx_info

```cairo
use starknet::get_tx_info;

fn get_transaction_info() {
    let tx_info = get_tx_info().unbox();
    
    // Available fields:
    // - version: felt252
    // - account_contract_address: ContractAddress
    // - max_fee: u128
    // - signature: Span<felt252>
    // - transaction_hash: felt252
    // - chain_id: felt252
    // - nonce: felt252
    
    // Security: Don't rely on tx_info for authorization
    // Signature verification should be in account contract
}
```

### get_block_info

```cairo
use starknet::get_block_info;

fn check_block_info() {
    let block_info = get_block_info().unbox();
    
    // Available:
    // - block_number: u64
    // - block_timestamp: u64
    // - sequencer_address: ContractAddress
    
    // SECURITY WARNINGS:
    // 1. block_timestamp can be manipulated by sequencer (within bounds)
    // 2. Don't use for high-precision timing
    // 3. Use for relative time comparisons, not absolute
}
```

---

## L1-L2 Messaging Security

### L1  L2 Messages

```cairo
// L1 Handler - receives messages from Ethereum

#[l1_handler]
fn handle_l1_message(
    ref self: ContractState,
    from_address: felt252,  // L1 sender address
    // ... payload parameters
) {
    // CRITICAL CHECKS:
    
    // 1. Verify L1 sender
    assert(from_address == self.l1_bridge.read(), 'Unknown L1 sender');
    
    // 2. Validate payload
    // ... validate all parameters
    
    // 3. Prevent replay (if needed beyond StarkNet's built-in)
    // StarkNet handles message consumption, but additional
    // application-level replay protection may be needed
}
```

### L2  L1 Messages

```cairo
use starknet::send_message_to_l1_syscall;

fn send_to_l1(
    ref self: ContractState,
    to_address: felt252,  // L1 recipient
    payload: Span<felt252>
) {
    // SECURITY CONSIDERATIONS:
    
    // 1. Verify caller has permission
    self._assert_authorized();
    
    // 2. Validate destination
    assert(to_address == self.l1_contract.read(), 'Invalid L1 target');
    
    // 3. Include nonce for ordering/replay protection on L1
    let nonce = self.message_nonce.read();
    self.message_nonce.write(nonce + 1);
    
    // 4. Build payload with nonce
    let mut full_payload = array![nonce];
    // ... append rest of payload
    
    // 5. Send message
    send_message_to_l1_syscall(to_address, full_payload.span());
    
    // 6. Emit event for off-chain tracking
    self.emit(MessageSent { to: to_address, nonce });
}
```

### Message Consumption

```
L1  L2 Flow:
1. L1 contract calls starknetCore.sendMessageToL2()
2. Message is added to L1L2 message queue
3. StarkNet sequencer includes message in block
4. L1 handler on L2 contract is invoked
5. Message is consumed (one-time)

L2  L1 Flow:
1. L2 contract calls send_message_to_l1_syscall()
2. Message hash included in state diff
3. State diff proven on L1
4. L1 contract calls starknetCore.consumeMessageFromL2()
5. Message is consumed (one-time)
```

---

## Contract Deployment Security

### Deploy Syscall

```cairo
use starknet::deploy_syscall;

fn deploy_contract(
    ref self: ContractState,
    class_hash: ClassHash,
    salt: felt252,
    calldata: Span<felt252>
) -> ContractAddress {
    // SECURITY:
    // 1. Verify class_hash is expected implementation
    assert(self.allowed_classes.read(class_hash), 'Class not allowed');
    
    // 2. Salt considerations - predictable addresses
    // Attacker can front-run deployments if salt is known
    
    // 3. Constructor calldata validation
    // Ensure calldata won't cause issues in new contract
    
    let (address, _) = deploy_syscall(
        class_hash,
        salt,
        calldata,
        false  // deploy_from_zero
    ).unwrap();
    
    address
}
```

### Address Calculation

```cairo
// Contract address is deterministic:
// address = hash(
//     "STARKNET_CONTRACT_ADDRESS",
//     deployer_address,
//     salt,
//     class_hash,
//     hash(constructor_calldata)
// )

// SECURITY: Addresses can be pre-computed
// - Use for CREATE2-style patterns
// - Risk: Front-running deployments
```

---

## Component Security

### OpenZeppelin Cairo Components

```cairo
// Using OZ components safely

use openzeppelin::access::ownable::OwnableComponent;
use openzeppelin::security::reentrancy_guard::ReentrancyGuardComponent;

component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
component!(path: ReentrancyGuardComponent, storage: reentrancy, event: ReentrancyEvent);

// SECURITY: Ensure proper initialization
#[constructor]
fn constructor(ref self: ContractState, owner: ContractAddress) {
    // Initialize ownable
    self.ownable.initializer(owner);
    // ReentrancyGuard doesn't need initialization
}

// Using reentrancy guard
fn protected_function(ref self: ContractState) {
    self.reentrancy.start();
    // ... do work with external calls
    self.reentrancy.end();
}
```

---

## Testing & Verification

### Starknet Foundry

```bash
# Run tests
snforge test

# Test with specific contract
snforge test --contract-name MyContract

# Coverage (if available)
snforge test --coverage
```

### Test Patterns

```cairo
#[cfg(test)]
mod tests {
    use super::MyContract;
    use starknet::ContractAddress;
    use starknet::testing::{set_caller_address, set_contract_address};

    #[test]
    fn test_access_control() {
        // Setup
        let owner: ContractAddress = 0x123.try_into().unwrap();
        let attacker: ContractAddress = 0x456.try_into().unwrap();
        
        // Deploy with owner
        let mut state = MyContract::contract_state_for_testing();
        set_caller_address(owner);
        MyContract::constructor(ref state, owner);
        
        // Try unauthorized action
        set_caller_address(attacker);
        // This should panic
        // MyContract::admin_function(ref state);
    }
    
    #[test]
    #[should_panic(expected: ('Not owner',))]
    fn test_unauthorized_rejected() {
        // ... test that unauthorized calls are rejected
    }
}
```

---

## Audit Checklist

### StarkNet-Specific Checks

- [ ] Account abstraction assumptions validated
- [ ] L1 handler origin verification
- [ ] L2L1 message replay protection on L1 side
- [ ] Zero address checks (get_caller_address can return zero)
- [ ] Class hash verification for external calls
- [ ] Upgrade protection (replace_class_syscall)
- [ ] Storage layout preserved across upgrades
- [ ] Sequencer trust assumptions understood
- [ ] Block timestamp manipulation tolerance
- [ ] Fee payment mechanism understood

