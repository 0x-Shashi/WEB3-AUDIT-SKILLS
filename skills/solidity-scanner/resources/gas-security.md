---
id: gas-security
title: Gas Optimization & Security Implications
category: solidity-scanner
difficulty: intermediate
triggers:
  - gas optimization security
  - gas audit
  - storage packing
  - unchecked arithmetic
  - compiler settings
  - gas profiling
related_skills:
  - solidity-scanner/SKILL.md
  - solidity-scanner/resources/vulnerability-patterns.md
  - solidity-scanner/resources/foundry-testing.md
tags:
  - gas
  - optimization
  - security
  - foundry
last_updated: 2026-02-26
description: >-
  Gas optimization techniques with security implications for auditors.
  Storage packing, unchecked arithmetic safety, compiler settings,
  transient storage, EVM opcode costs, and Foundry gas profiling.
  Every optimization is evaluated for its security trade-offs.
  Sourced from claude-plugins foundry-solidity.
---

# Gas Optimization & Security Implications

> **For Auditors**: Gas optimization is NOT just a "low/informational" finding. Storage packing errors, unchecked arithmetic, and compiler settings can introduce critical vulnerabilities. Evaluate every optimization for its security trade-off.

---

## Storage Optimization

### Variable Packing

Pack multiple variables into single 32-byte storage slots:

```solidity
// ❌ BAD: 3 storage slots (3 × 20,000 gas on first write)
contract Unoptimized {
    uint256 amount;      // slot 0
    uint8 status;        // slot 1
    address owner;       // slot 2
}

// ✅ GOOD: 2 storage slots
contract Optimized {
    uint128 amount;      // slot 0 (16 bytes)
    uint96 lockTime;     // slot 0 (12 bytes)
    uint8 status;        // slot 0 (1 byte)  — 29 bytes total in slot 0
    address owner;       // slot 1 (20 bytes)
}
```

**Savings**: 15,000+ gas per packed write

**Security Implication**: Downcasting from `uint256` to `uint128` can truncate values. Verify all packed variables have sufficient range for the protocol's needs. A lending protocol that packs `amount` into `uint128` is capped at ~340 undecillion — usually safe, but verify.

### Struct Packing

```solidity
// ❌ 3 slots
struct BadPacking {
    uint256 a;           // slot 0
    uint8 b;             // slot 1
    uint256 c;           // slot 2
}

// ✅ 2 slots
struct GoodPacking {
    uint256 a;           // slot 0
    uint128 c;           // slot 1 (16 bytes)
    uint8 b;             // slot 1 (1 byte)
}
```

**Security Implication**: Struct packing in upgradeable contracts is dangerous — adding fields can shift slots and break storage layout. Always use `__gap` variables.

---

## Storage vs Memory vs Calldata

### Gas Costs Reference

| Operation | Gas | Notes |
|-----------|-----|-------|
| SLOAD (cold) | 2,100 | First storage read in transaction |
| SLOAD (warm) | 100 | Subsequent reads of same slot |
| SSTORE (0 → non-zero) | 20,000 | New storage slot |
| SSTORE (non-zero → non-zero) | 5,000 | Update existing |
| SSTORE (non-zero → 0) | 5,000 | +15,000 refund |
| TLOAD/TSTORE | 100 | Transient storage (Cancun+) |
| MLOAD/MSTORE | 3 | Per word |
| Calldata read | 3 | Per byte |
| CALL | 700+ | External call base |
| KECCAK256 | 30 | +6 per word |

### Cache Storage Reads

```solidity
// ❌ BAD: 3 SLOAD operations (300-6300 gas)
function process() external returns (uint256) {
    return value * 2 + value * 3 + value * 4;
}

// ✅ GOOD: 1 SLOAD + memory operations
function process() external returns (uint256) {
    uint256 v = value;
    return v * 2 + v * 3 + v * 4;
}
```

### Use Calldata for External Arrays

```solidity
// ❌ BAD: Copies entire array to memory
function batchProcess(uint256[] memory values) external { }

// ✅ GOOD: Reads directly from calldata
function batchProcess(uint256[] calldata values) external {
    for (uint256 i; i < values.length; ) {
        // Process values[i]
        unchecked { i++; }
    }
}
```

---

## Arithmetic Optimization

### Unchecked Blocks

Solidity 0.8+ adds overflow checks by default (~50-100 gas per operation):

```solidity
// ❌ Slower: Overflow check on every increment
for (uint256 i = 0; i < 100; i++) {
    result += i;
}

// ✅ Faster: Unchecked increment (safe when bounded by loop condition)
for (uint256 i = 0; i < 100; ) {
    result += i;
    unchecked { i++; }
}
```

**Savings**: 50-100 gas per iteration

**⚠️ SECURITY WARNING**: `unchecked` blocks disable overflow/underflow protection. Only use when:
1. The operation is provably bounded (loop counter < array length)
2. The subtraction is preceded by a `require(a >= b)` check
3. The multiplication won't overflow (verified by analysis)

```solidity
// ❌ DANGEROUS: Balance subtraction in unchecked block
unchecked {
    balance -= amount; // Can underflow to type(uint256).max!
}

// ✅ SAFE: Check first, then unchecked subtract
require(balance >= amount, "Insufficient balance");
unchecked { balance -= amount; }
```

### Short-Circuit Logic

```solidity
// Put cheap/likely-to-fail check first
if (amount > 0 && expensiveValidation(amount)) {
    // ...
}
```

---

## Variable Declaration

### Immutable vs Constant vs Storage

```solidity
// Storage variable: 2,100 gas (cold read)
uint256 public maxSupply = 1_000_000;

// Constant: ~3 gas (embedded in bytecode, compile-time)
uint256 public constant MAX_SUPPLY = 1_000_000;

// Immutable: ~100 gas (set once in constructor, inlined in deployed bytecode)
uint256 public immutable maxSupply;
constructor(uint256 _max) { maxSupply = _max; }
```

**Security Implication**: `immutable` variables cannot be changed after construction — they are safe for critical parameters like protocol addresses. But they also cannot be updated if the referenced contract is compromised.

---

## Error Handling

### Custom Errors vs Require Strings

```solidity
// ❌ Expensive: String stored in bytecode (~50+ gas per deployment)
require(msg.sender == owner, "Unauthorized access");

// ✅ Cheap: Custom error (~24 gas, selector only)
error Unauthorized();
if (msg.sender != owner) revert Unauthorized();

// ✅ Solidity 0.8.26+ syntax
require(msg.sender == owner, Unauthorized());
```

**Savings**: 20-50 gas per error path, plus reduced contract size

---

## Bitwise Flag Packing

```solidity
// ❌ 4 storage slots (4 × bool)
bool isActive;
bool isVerified;
bool isPaused;
bool isBlocked;

// ✅ 1 storage slot with bit manipulation
uint256 flags;

function isActive() view returns (bool) {
    return (flags & (1 << 0)) != 0;
}

function setActive(bool _active) {
    if (_active) flags |= (1 << 0);
    else flags &= ~(1 << 0);
}
```

**Security Implication**: Bitwise operations are harder to audit and more prone to off-by-one errors. Ensure thorough test coverage for all flag combinations.

---

## Events vs Storage

```solidity
// ❌ 20,000+ gas per write
uint256[] public transfers;
function recordTransfer(uint256 amount) external {
    transfers.push(amount);
}

// ✅ ~375 gas base + 8 gas per byte
event Transfer(address indexed to, uint256 amount);
function recordTransfer(address to, uint256 amount) external {
    emit Transfer(to, amount);
}
```

**Security Implication**: Event data cannot be read on-chain. If the protocol needs on-chain access to historical data, storage is required despite the gas cost.

---

## Transient Storage (Solidity 0.8.28+)

| Operation | Persistent Storage | Transient Storage |
|-----------|-------------------|-------------------|
| First write | 20,000+ gas | 100 gas |
| Subsequent write | 2,900 gas | 100 gas |
| Read | 100 gas | 100 gas |
| Cleared after tx? | No | **Yes** |

**Security Implication**: Transient storage is automatically cleared at the end of each transaction. This is ideal for reentrancy guards but **must be reset at function exit** for composability. A transient reentrancy lock that isn't reset will block all subsequent calls in the same transaction from other protocols composing with the contract.

---

## Compiler Settings

```toml
# foundry.toml
[profile.default]
optimizer = true
optimizer_runs = 200     # Balance size/runtime

[profile.production]
optimizer = true
optimizer_runs = 1000000 # Optimize for runtime cost
via_ir = true            # IR pipeline (best optimization, slowest compile)
bytecode_hash = "none"   # Skip metadata (smaller bytecode)
cbor_metadata = false    # Disable CBOR metadata
```

**Optimizer runs guidance**:
- `200` runs: Smaller deployment cost, higher runtime cost
- `10000+` runs: Larger deployment, lower runtime cost per call
- `via_ir = true`: Best optimization, but verify behavior matches non-IR build

**⚠️ SECURITY WARNING**: Different optimizer settings can produce different bytecode behavior. Always verify the deployed bytecode matches the audited source with identical compiler settings.

---

## Foundry Gas Profiling

### Gas Reports

```bash
# Generate gas report for all tests
forge test --gas-report

# Filter by contract
forge test --match-contract MyContract --gas-report
```

### Gas Snapshots

```bash
# Create baseline snapshot
forge snapshot

# Compare against previous
forge snapshot --diff

# Fail CI if gas increases beyond threshold
forge snapshot --check --tolerance 5
```

### Inline Gas Measurement

```solidity
function testGasUsage() public {
    uint256 gasBefore = gasleft();
    contract.doSomething();
    uint256 gasUsed = gasBefore - gasleft();
    console.log("Gas used:", gasUsed);
}

// Section snapshots (more precise)
function testOptimization() public {
    vm.startSnapshotGas("operation");
    value = 1;
    uint256 gasUsed = vm.stopSnapshotGas();
}
```

---

## EVM Opcode Reference

| Operation | Gas | Notes |
|-----------|-----|-------|
| ADD/SUB/MUL | 3 | Basic arithmetic |
| DIV/MOD | 5 | Division operations |
| SLOAD (cold) | 2,100 | First storage read |
| SLOAD (warm) | 100 | Subsequent reads |
| SSTORE (0→non-0) | 20,000 | New storage slot |
| SSTORE (non-0→non-0) | 5,000 | Update existing |
| SSTORE (→0) | 5,000 | +15,000 refund |
| TLOAD/TSTORE | 100 | Transient storage (Cancun+) |
| CALL | 700+ | External call base |
| KECCAK256 | 30 | +6 per word |
| LOG0-LOG4 | 375-1,875 | Events |
| MCOPY | 3 | +3 per word (Cancun+) |

---

## Gas Optimization Checklist

### Storage
- [ ] Pack related variables together in 32-byte slots
- [ ] Use smaller integer types when range allows (verify no truncation!)
- [ ] Cache frequently accessed storage variables in local memory
- [ ] Use mappings instead of arrays for lookups
- [ ] Use `immutable`/`constant` for fixed values

### Functions
- [ ] Mark `external` (not `public`) when not called internally
- [ ] Use `calldata` for array parameters in external functions
- [ ] Use `unchecked` blocks for provably-safe arithmetic
- [ ] Short-circuit expensive conditions
- [ ] Use custom errors instead of require strings

### Compilation
- [ ] Enable optimizer
- [ ] Set appropriate `optimizer_runs` for use case
- [ ] Consider `via_ir` for production deployment

### Testing
- [ ] Run `forge test --gas-report` regularly
- [ ] Create gas snapshots for regression detection
- [ ] Profile critical functions with inline measurement

---

## Quick Wins

| Pattern | Gas Saved | Effort | Security Risk |
|---------|-----------|--------|---------------|
| Custom errors | 20-50/revert | Low | None |
| Unchecked loops | 50-100/iter | Low | Low (if bounded) |
| Calldata vs memory | 5,000+ | Low | None |
| Variable packing | 15,000/write | Low | Medium (truncation) |
| Immutable vars | 2,000/read | Low | None |
| Bitwise flags | 15,000 | Medium | Medium (complexity) |
| Events vs storage | 19,000+ | Medium | Medium (no on-chain read) |
| Transient storage | 19,900/write | Medium | Medium (composability) |

---

## Related Files

- [Vulnerability Patterns](vulnerability-patterns.md) — Complete vulnerability catalog
- [Foundry Testing](foundry-testing.md) — Gas profiling in test suites
- [Foundry Cheatcodes](foundry-cheatcodes.md) — Gas metering cheatcodes
- [Foundry CI/CD](foundry-ci-cd.md) — Gas regression detection in CI

---

*Source: claude-plugins foundry-solidity gas-optimization.md, solidity-modern.md (February 2026)*
