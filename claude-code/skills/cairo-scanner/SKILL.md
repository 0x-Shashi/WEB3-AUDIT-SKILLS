---
name: Cairo Scanner
description: StarkNet Cairo smart contract vulnerability scanner with 50+ security patterns
version: 1.0.0
author: Web3 Security Plugin
tags: [cairo, starknet, security, audit, scanner, vulnerability]
---

# Cairo Scanner Skill

Comprehensive security scanner for StarkNet Cairo smart contracts. Covers Cairo 0, Cairo 1, and Cairo 2 syntax with StarkNet-specific security patterns.

## Capabilities

- **Cairo 0 Legacy Analysis**: Identify issues in older Cairo syntax
- **Cairo 1/2 Modern Analysis**: Current Cairo language security patterns
- **StarkNet Syscalls**: Storage, messaging, cryptographic operations
- **Component Security**: OpenZeppelin Cairo component patterns
- **L1-L2 Messaging**: Cross-layer communication security
- **Access Control**: Ownable, roles, and permission patterns

## Vulnerability Categories

### Category 1: Storage Security (ST)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| ST-01 | Storage Collision | Critical | All |
| ST-02 | Uninitialized Storage | High | All |
| ST-03 | Storage Key Predictability | High | All |
| ST-04 | Missing Storage Updates | Medium | All |
| ST-05 | Improper Struct Storage | High | Cairo 0 |

### Category 2: Access Control (AC)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| AC-01 | Missing Caller Validation | Critical | All |
| AC-02 | Improper Role Assignment | Critical | All |
| AC-03 | Missing Ownership Checks | Critical | All |
| AC-04 | Unprotected Initializer | Critical | All |
| AC-05 | Missing Zero Address Check | Medium | All |

### Category 3: Arithmetic (AR)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| AR-01 | Integer Overflow | Critical | All |
| AR-02 | Integer Underflow | Critical | All |
| AR-03 | Division by Zero | High | All |
| AR-04 | Precision Loss | Medium | All |
| AR-05 | Unsafe felt252 Casts | High | Cairo 1+ |

### Category 4: L1-L2 Messaging (MSG)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| MSG-01 | Message Replay | Critical | All |
| MSG-02 | Missing Message Validation | High | All |
| MSG-03 | Improper L1 Handler | Critical | All |
| MSG-04 | Message Nonce Issues | High | All |
| MSG-05 | Unverified Message Origin | Critical | All |

### Category 5: Reentrancy (RE)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| RE-01 | External Call Before State Update | Critical | All |
| RE-02 | Missing Reentrancy Guard | High | All |
| RE-03 | Cross-Contract Reentrancy | High | All |

### Category 6: Logic Errors (LG)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| LG-01 | Incorrect Condition | Varies | All |
| LG-02 | Missing Return Value Check | High | All |
| LG-03 | Improper Loop Bounds | Medium | All |
| LG-04 | Unhandled Option/Result | High | Cairo 1+ |
| LG-05 | Missing Event Emission | Low | All |

### Category 7: Cairo-Specific (CS)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| CS-01 | Felt252 Range Issues | High | All |
| CS-02 | Short String Limitations | Low | All |
| CS-03 | Improper Trait Implementation | Medium | Cairo 1+ |
| CS-04 | Missing Drop/Destruct | Medium | Cairo 1+ |
| CS-05 | Unsafe unwrap() Usage | High | Cairo 1+ |
| CS-06 | Snapshot Misuse | Medium | Cairo 1+ |

### Category 8: Upgradeability (UP)

| ID | Pattern | Severity | Cairo Version |
|----|---------|----------|---------------|
| UP-01 | Unprotected Upgrade | Critical | All |
| UP-02 | Storage Layout Change | Critical | All |
| UP-03 | Missing Upgrade Events | Low | All |
| UP-04 | Initializer Replay | Critical | All |

---

## Quick Reference

### Cairo 2 Contract Structure

```cairo
#[starknet::interface]
trait IMyContract<TContractState> {
    fn get_value(self: @TContractState) -> u256;
    fn set_value(ref self: TContractState, value: u256);
}

#[starknet::contract]
mod MyContract {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    
    #[storage]
    struct Storage {
        owner: ContractAddress,
        value: u256,
    }
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ValueChanged: ValueChanged,
    }
    
    #[derive(Drop, starknet::Event)]
    struct ValueChanged {
        old_value: u256,
        new_value: u256,
    }
    
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }
    
    #[abi(embed_v0)]
    impl MyContractImpl of super::IMyContract<ContractState> {
        fn get_value(self: @ContractState) -> u256 {
            self.value.read()
        }
        
        fn set_value(ref self: ContractState, value: u256) {
            // Access control check
            assert(get_caller_address() == self.owner.read(), 'Not owner');
            
            let old = self.value.read();
            self.value.write(value);
            
            self.emit(ValueChanged { old_value: old, new_value: value });
        }
    }
}
```

### Common Secure Patterns

**Access Control:**
```cairo
//  Owner check
fn only_owner(self: @ContractState) {
    let caller = get_caller_address();
    let owner = self.owner.read();
    assert(caller == owner, 'Caller is not owner');
}

//  Zero address check
fn assert_valid_address(address: ContractAddress) {
    assert(!address.is_zero(), 'Invalid zero address');
}
```

**Safe Arithmetic:**
```cairo
//  Use checked arithmetic when needed
use core::integer::u256_checked_add;
use core::integer::u256_checked_sub;

fn safe_add(a: u256, b: u256) -> u256 {
    match u256_checked_add(a, b) {
        Option::Some(result) => result,
        Option::None => panic_with_felt252('Overflow'),
    }
}
```

**Reentrancy Guard:**
```cairo
#[storage]
struct Storage {
    reentrancy_guard: bool,
}

fn reentrancy_start(ref self: ContractState) {
    assert(!self.reentrancy_guard.read(), 'ReentrancyGuard: reentrant');
    self.reentrancy_guard.write(true);
}

fn reentrancy_end(ref self: ContractState) {
    self.reentrancy_guard.write(false);
}
```

---

## Protocol-Specific Checklists

### DeFi Protocols on StarkNet

```markdown
## AMM/DEX Checklist
- [ ] Slippage protection implemented
- [ ] Minimum output enforced
- [ ] LP token math verified (no inflation/deflation bugs)
- [ ] Price oracle manipulation resistant
- [ ] Flash loan integration considered
- [ ] Reentrancy on swap functions

## Lending Protocol Checklist
- [ ] Collateral ratio calculations verified
- [ ] Liquidation threshold correct
- [ ] Interest rate model audited
- [ ] Oracle price freshness checked
- [ ] Bad debt handling implemented

## Bridge Checklist
- [ ] L1-L2 message validation
- [ ] Message replay prevention
- [ ] Proper nonce handling
- [ ] Origin verification
- [ ] Deposit/withdrawal matching
```

### Token Standards

```markdown
## ERC20 on StarkNet
- [ ] Balance overflow protection
- [ ] Zero address checks on transfer
- [ ] Approval race condition mitigated
- [ ] Return values correct (no bool issues)
- [ ] Events emitted properly

## ERC721 on StarkNet
- [ ] Ownership correctly tracked
- [ ] Transfer validations complete
- [ ] Approval properly scoped
- [ ] Reentrancy on transfers
```

---

## Analysis Commands

```bash
# Build contract
scarb build

# Run tests
scarb test

# Format check
scarb fmt --check

# Check for warnings
scarb build 2>&1 | grep -i "warning"
```

### Grep Patterns for Cairo

```bash
# Find external functions
grep -rn "#\[external\|#\[abi" src/

# Find storage access
grep -rn "\.read()\|\.write(" src/

# Find syscalls
grep -rn "get_caller_address\|get_contract_address\|send_message" src/

# Find L1 handlers
grep -rn "#\[l1_handler\]" src/

# Find assertions
grep -rn "assert(" src/

# Find unwrap usage
grep -rn "\.unwrap()" src/

# Find arithmetic operations
grep -rn "[+\-*/]" src/ | grep -v "//"
```

---

## Resources

- [cairo-patterns.md](resources/cairo-patterns.md) - Detailed vulnerability patterns
- [starknet-security.md](resources/starknet-security.md) - StarkNet-specific security
- [messaging-security.md](resources/messaging-security.md) - L1-L2 messaging security

## Workflows

- [cairo-audit.md](workflows/cairo-audit.md) - Complete Cairo contract audit process
- [starknet-bridge-audit.md](workflows/starknet-bridge-audit.md) - L1-L2 bridge security review

---

## Integration with Cyfrin Solodit

```markdown
## Search Queries for StarkNet Findings

- "starknet" - All StarkNet findings
- "cairo" - Cairo-specific issues
- "l1 l2 message" - Cross-layer messaging bugs
- "felt252" - Cairo felt type issues
- "starknet storage" - Storage collision/issues
```

