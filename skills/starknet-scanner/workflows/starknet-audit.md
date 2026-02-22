---
id: STARKNET-WF-AUDIT
title: Starknet Cairo Contract Audit Workflow
parent: starknet-scanner
type: workflow
last_updated: 2025-01-31
---

# Starknet Cairo Contract Audit Workflow

Specialized 10-step audit workflow for Starknet contracts written in Cairo. Extends the general [Cairo Scanner](../cairo-scanner/SKILL.md) with Starknet infrastructure-specific checks.

---

## Prerequisites

| Requirement | Details |
|-------------|----------|
| Language | Cairo (latest stable, using Sierra compilation) |
| Compiler | `scarb build` (Scarb package manager + Cairo compiler) |
| Framework | OpenZeppelin Cairo Contracts (common components) |
| Testing | `scarb test` (unit) + `starknet-foundry` `snforge` (integration) |
| Deployment | `starknet-foundry` `sncast` or `starkli` |
| Explorer | Starkscan, Voyager (for deployed contract verification) |

---

## Step 1: Contract and Component Mapping

List all contracts and their components:

```cairo
// Identify from #[starknet::contract] declarations
// and component!() macros

#[starknet::contract]
mod MyProtocol {
    // Components used
    component!(path: OwnableComponent, ...);
    component!(path: ERC20Component, ...);
    component!(path: ReentrancyGuardComponent, ...);
    
    // Interfaces implemented
    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
}
```

For each contract, document:
- All `#[external(v0)]` functions (public API)
- All `#[l1_handler]` functions (L1→L2 entry points)
- All components and their versions
- Interfaces implemented (`#[abi(embed_v0)]`)
- Constructor (`#[constructor]`)
- Events

---

## Step 2: Storage Analysis

Starknet storage uses Pedersen-hashed addresses:

```cairo
#[storage]
struct Storage {
    // Simple variable: stored at sn_keccak("variable_name")
    owner: ContractAddress,
    total_supply: u256,
    
    // Mapping: stored at h(sn_keccak("map_name"), key)
    balances: Map<ContractAddress, u256>,
    
    // Component storage: uses #[substorage(v0)] for isolation
    #[substorage(v0)]
    ownable: OwnableComponent::Storage,
}
```

### Storage Checklist

- [ ] No manual storage access that could collide with named variables
- [ ] Map keys properly serialized (no truncation for u256 keys)
- [ ] `#[substorage(v0)]` used for all component storage
- [ ] Storage layout documented for upgrade compatibility
- [ ] No unused storage variables (dead state)
- [ ] u256 values stored correctly (uses 2 felt252 storage slots)

---

## Step 3: Access Control

Check every `#[external(v0)]` function:

| Pattern | Implementation | Security |
|---------|---------------|----------|
| Open function | No caller check | DANGEROUS unless intended |
| Owner-only | `self.ownable.assert_only_owner()` | SAFE (if ownable initialized) |
| Role-based | `self.accesscontrol.assert_only_role(ROLE)` | SAFE (if roles properly assigned) |
| Custom check | `assert(get_caller_address() == allowed, 'unauthorized')` | VERIFY correctness |

### Access Control Checklist

- [ ] Every state-modifying external function has access control
- [ ] `get_caller_address()` used correctly (returns 0 for direct calls from account)
- [ ] OwnableComponent initialized in constructor
- [ ] Owner transfer is two-step (prevent accidental transfer to wrong address)
- [ ] Zero address checks on admin/owner parameters

---

## Step 4: Felt Arithmetic Safety

Cairo's base type is `felt252` (field element modulo p = 2^251 + 17*2^192 + 1):

```cairo
// DANGEROUS: felt252 arithmetic wraps modulo p
let a: felt252 = 0;
let b: felt252 = a - 1; // b = p - 1 (very large number, NOT -1)

// SAFE: Use u256/u128 for amounts and values
let a: u256 = 0_u256;
let b: u256 = a - 1_u256; // PANICS (underflow) — safe
```

- [ ] Amounts and balances use `u256` or `u128` (NOT `felt252`)
- [ ] `felt252` used only for hashes, addresses, and identifiers
- [ ] Comparisons on `felt252` understand field element ordering
- [ ] No implicit felt252-to-integer conversions in arithmetic

---

## Step 5: Upgrade Security (`replace_class_syscall`)

```cairo
// Starknet upgrade pattern
#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    self.ownable.assert_only_owner();
    assert(!new_class_hash.is_zero(), 'invalid class hash');
    replace_class_syscall(new_class_hash).unwrap();
    self.emit(Upgraded { new_class_hash });
}
```

- [ ] `replace_class_syscall` protected by owner/governance
- [ ] New class hash validated (non-zero)
- [ ] Upgrade event emitted
- [ ] Consider timelock for critical protocols
- [ ] Storage layout compatibility verified between versions
- [ ] If using proxy pattern: upgrade on proxy, not implementation

---

## Step 6: L1-L2 Messaging

### L1 → L2 (L1Handler)

```cairo
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,  // L1 sender address
    user: ContractAddress,
    amount: u256
) {
    // CRITICAL: Validate from_address is the expected L1 contract
    assert(from_address == self.l1_bridge_address.read(), 'unauthorized L1 sender');
    
    // Process deposit
    self.balances.write(user, self.balances.read(user) + amount);
}
```

### L2 → L1

```cairo
fn withdraw(ref self: ContractState, amount: u256, l1_recipient: felt252) {
    // Burn tokens on L2
    self.balances.write(get_caller_address(), self.balances.read(get_caller_address()) - amount);
    
    // Send message to L1
    let mut payload = ArrayTrait::new();
    payload.append(l1_recipient);
    payload.append(amount.low.into());
    payload.append(amount.high.into());
    send_message_to_l1_syscall(self.l1_bridge_address.read(), payload.span()).unwrap();
}
```

- [ ] `#[l1_handler]` validates `from_address` against known L1 contract
- [ ] L2→L1 messages include all necessary data for L1 execution
- [ ] Message format (payload layout) matches between L1 and L2
- [ ] No message replay possible (Starknet guarantees unique consumption)
- [ ] Cancellation mechanism exists for stuck messages

---

## Step 7: Account Abstraction

If the contract is an account contract (`#[starknet::contract(account)]`):

- [ ] `__validate__` verifies transaction signature against stored public key
- [ ] `__validate__` returns `VALIDATED` constant only on success
- [ ] `__execute__` correctly executes array of calls
- [ ] `__validate_declare__` implemented if contract can declare classes
- [ ] `__validate_deploy__` implemented for counterfactual deployment
- [ ] Key rotation mechanism secure (two-step preferred)
- [ ] Multicall atomicity handled correctly
- [ ] Gas estimation for validation bounded (prevent DoS)

---

## Step 8: Component Review

- [ ] All components initialized in `#[constructor]`
- [ ] No conflicting component implementations (same interface)
- [ ] Component storage isolated via `#[substorage(v0)]`
- [ ] Component versions compatible with Cairo compiler version
- [ ] Internal component functions properly exposed (or kept internal)
- [ ] Embed vs. not-embed carefully chosen for each component impl

---

## Step 9: Syscall Review

Audit all syscall invocations:

| Syscall | Purpose | Security Focus |
|---------|---------|----------------|
| `get_caller_address()` | Current caller | Returns 0 in some contexts |
| `get_contract_address()` | Self address | Generally safe |
| `get_block_timestamp()` | Block timestamp | Sequencer-controlled |
| `get_block_number()` | Block number | Sequencer-controlled |
| `get_tx_info()` | Transaction info | Nonce, chain_id, signatures |
| `call_contract_syscall()` | External call | Reentrancy, return value validation |
| `deploy_syscall()` | Deploy contract | Class hash validation |
| `replace_class_syscall()` | Upgrade | Must be access-controlled |
| `send_message_to_l1_syscall()` | L2→L1 message | Payload validation |
| `library_call_syscall()` | Delegatecall equivalent | Class hash trust |

- [ ] `get_block_timestamp()` not used for critical randomness
- [ ] `call_contract_syscall()` return values checked
- [ ] `library_call_syscall()` only calls trusted class hashes
- [ ] All syscall errors handled (`.unwrap()` or explicit match)

---

## Step 10: Report

### Severity Guide for Starknet

| Severity | Criteria | Example |
|----------|----------|---------|
| **Critical** | Fund theft, unauthorized upgrade, account takeover | `replace_class_syscall` without auth check |
| **High** | Fund lock, L1-L2 desync, access control bypass | L1 handler without sender validation |
| **Medium** | Felt arithmetic issue, storage collision | Comparison on felt252 values |
| **Low** | Best practice, informational | Missing upgrade event |

### Starknet-Specific Report Notes

For each finding, include:
- Cairo source location and function
- Whether the issue is Cairo-level (language) or Starknet-level (infrastructure)
- Sequencer trust implications (if relevant)
- L1-L2 impact (if cross-chain)
- Storage layout impact (if upgrade-related)
- `snforge` test case demonstrating the issue
