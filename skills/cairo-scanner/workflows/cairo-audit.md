---
id: CAIRO-WF-AUDIT
title: Cairo Contract Audit Workflow
parent: cairo-scanner
type: workflow
last_updated: 2025-01-31
---

# Cairo Audit Workflow

Step-by-step security audit workflow for Cairo smart contracts on Starknet. Cairo's unique type system, field element arithmetic, and native account abstraction require specialized audit techniques beyond standard EVM review.

---

## Prerequisites

- Cairo compiler version identified (check `Scarb.toml`)
- All contracts, components, and interfaces mapped
- Starknet network target confirmed (mainnet, testnet, appchain)
- OpenZeppelin Cairo contracts version checked (if used)

---

## Step 1: Contract Structure Mapping

Map the complete contract architecture:

```
project/
├── src/
│   ├── lib.cairo          → Module declarations
│   ├── contract.cairo     → Main contract with #[starknet::contract]
│   ├── components/        → Reusable components (ownable, upgradeable, etc.)
│   ├── interfaces/        → Trait definitions (#[starknet::interface])
│   └── utils.cairo        → Helper functions
├── tests/
│   └── test_contract.cairo
└── Scarb.toml             → Dependencies (OpenZeppelin, etc.)
```

Document:
- All `#[starknet::contract]` declarations
- All `#[starknet::interface]` trait definitions
- Component usage: which components does each contract embed?
- Storage variables: map all `#[storage]` struct fields
- External functions: list all `#[external(v0)]` and `#[l1_handler]` functions

---

## Step 2: Access Control Review

For every external function, determine who should be able to call it:

| Function Type | Required Check | Cairo Pattern |
|---------------|---------------|---------------|
| Admin-only | Owner/role validation | `self.ownable.assert_only_owner()` |
| User-specific | Caller owns the resource | `assert(get_caller_address() == owner, 'Not authorized')` |
| Anyone | No restriction needed | No check required |
| L1 handler | L1 sender validation | `assert(from_address == expected, 'Invalid L1 sender')` |
| Internal only | Not externally callable | `fn _internal_fn()` (no `#[external]`) |

### Red Flags

- `#[external(v0)]` function with no caller validation that modifies state
- `replace_class_syscall` without `assert_only_owner`
- `l1_handler` without `from_address` validation
- Missing `Ownable` component on contracts that need admin functions

---

## Step 3: Felt Arithmetic Safety

**The #1 Cairo-specific vulnerability.** Audit ALL arithmetic operations:

| Operation | Felt252 Behavior | Safe Alternative |
|-----------|-----------------|-----------------|
| `a - b` where `b > a` | Wraps to $P - (b - a)$ | Use `u256`: will panic on underflow |
| `a + b` | Wraps if `a + b >= P` | Use `u256`: will panic on overflow |
| `a / b` | Modular inverse (NOT integer division) | Use `u256`: integer truncation |
| `a < b` | Comparison on field elements | Use `u256` for ordered comparisons |

### What to Check

- [ ] All balance/amount variables use `u256` or `u128` (not `felt252`)
- [ ] All arithmetic on financial values uses integer types
- [ ] No `felt252` subtraction on potentially larger values
- [ ] Division operations use integer types when truncation is expected
- [ ] Type conversions between `felt252` and integer types are safe

---

## Step 4: Storage Safety

Verify storage layout correctness:

- [ ] Standard `#[storage]` macro used (handles address calculation)
- [ ] No manual `storage_address_from_base` with collision risk
- [ ] Component storage isolated (each component has its own namespace)
- [ ] Storage layout compatible across contract versions (for upgradeable contracts)
- [ ] Maps with complex keys use proper hashing
- [ ] Large dynamic data structures have growth bounds

---

## Step 5: Upgrade Security

If the contract uses `replace_class_syscall`:

- [ ] Upgrade function protected by `assert_only_owner` or governance
- [ ] New class hash validated as non-zero
- [ ] Event emitted on upgrade
- [ ] Storage layout compatibility verified (new class must use same storage variable names)
- [ ] Timelock recommended for high-value contracts
- [ ] No way to brick the contract (can't upgrade to class without upgrade function)

---

## Step 6: L1-L2 Messaging

If the contract handles cross-layer messages:

- [ ] All `#[l1_handler]` functions validate `from_address` (L1 sender)
- [ ] Message replay protection implemented (nonce or hash tracking)
- [ ] `u256` encoding between L1/L2 handles low/high split correctly
- [ ] L2→L1 messages debit state BEFORE sending (CEI pattern)
- [ ] Proof finalization timing understood for L2→L1 messages
- [ ] Error handling for edge cases (zero amounts, invalid addresses)

See [Messaging Security](resources/messaging-security.md) for detailed patterns.

---

## Step 7: Reentrancy Analysis

Cairo has no built-in reentrancy guard. Audit all cross-contract calls:

| Syscall | Reentrancy Risk |
|---------|----------------|
| `call_contract_syscall` | HIGH — external code executes |
| `library_call_syscall` | MEDIUM — runs foreign code with local storage |
| `send_message_to_l1_syscall` | LOW — no immediate callback |
| `deploy_syscall` | LOW — constructor runs but doesn't call back |

### What to Check

- [ ] All external calls follow Checks-Effects-Interactions pattern
- [ ] Manual reentrancy guard implemented for sensitive functions
- [ ] State is finalized before `call_contract_syscall`
- [ ] Token transfers (ERC20 dispatchers) don't introduce callback reentrancy

---

## Step 8: Event Emission

```cairo
// All significant state changes should emit events
#[event]
#[derive(Drop, starknet::Event)]
enum Event {
    Transfer: Transfer,
    Approval: Approval,
    Upgraded: Upgraded,
    OwnershipTransferred: OwnershipTransferred,
}
```

- [ ] Transfer/approval events emitted (ERC20/ERC721 compliance)
- [ ] Upgrade events emitted
- [ ] Admin action events emitted
- [ ] Events include sufficient data for off-chain indexing

---

## Step 9: Account Abstraction Audit

If auditing an account contract:

- [ ] `__validate__` verifies cryptographic signature
- [ ] Signature scheme is secure (Stark curve, secp256k1, or secp256r1)
- [ ] Transaction hash correctly computed and verified
- [ ] Nonce management prevents replay
- [ ] `__execute__` handles multicall correctly
- [ ] Gas estimation is accurate (`__validate__` gas must be predictable)
- [ ] Account cannot be tricked into signing malicious transactions

---

## Step 10: Report

Structure findings with Cairo-specific context:

| Severity | Criteria | Example |
|----------|----------|---------|
| **Critical** | Direct fund theft or contract takeover | Felt overflow allowing balance inflation |
| **High** | Fund loss under specific conditions | Missing L1 sender validation in l1_handler |
| **Medium** | Incorrect behavior, limited impact | Missing reentrancy guard on non-critical function |
| **Low** | Best practice violation | Missing events on state changes |
| **Informational** | Suggestion | Could use OpenZeppelin component instead of custom code |

### Cairo-Specific Report Notes

When documenting Cairo findings, include:
- Whether the issue is felt252-related (unique to Cairo)
- Whether the issue affects account contracts vs regular contracts
- Whether the issue relates to L1-L2 messaging
- Whether the fix requires storage migration (upgrade-breaking)

---

## Integration

| Resource | Use |
|----------|-----|
| [Cairo Patterns](resources/cairo-patterns.md) | Reference for vulnerability patterns with code examples |
| [Starknet Security](resources/starknet-security.md) | Architecture-level concerns (sequencer, AA, storage) |
| [Messaging Security](resources/messaging-security.md) | L1-L2 messaging patterns and vulnerabilities |
