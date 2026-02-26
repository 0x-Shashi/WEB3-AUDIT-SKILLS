---
id: foundry-testing-guide
title: Foundry Testing — Fuzz, Invariant, Fork & Differential
category: solidity-scanner
difficulty: advanced
triggers:
  - foundry fuzz test
  - invariant testing
  - fork testing
  - foundry handler pattern
  - forge test
  - differential testing
related_skills:
  - solidity-scanner/SKILL.md
  - solidity-scanner/resources/foundry-security.md
  - solidity-scanner/resources/foundry-cheatcodes.md
tags:
  - foundry
  - testing
  - fuzz
  - invariant
  - fork
last_updated: 2026-02-26
description: >-
  Complete Foundry testing guide for security auditors: fuzz testing with
  bound()/assume(), invariant testing with handler patterns and ghost
  variables, fork testing against mainnet state, differential testing,
  and configuration best practices. Sourced from claude-plugins foundry-solidity.
---

# Foundry Testing — Fuzz, Invariant, Fork & Differential

> **For Auditors**: These patterns are the foundation for writing exploit PoCs, verifying invariants, and testing integrations against real mainnet state.

---

## Test Structure

### File Conventions & Prefixes

| Prefix | Purpose |
|--------|---------|
| `test_` | Unit test |
| `testFuzz_` | Fuzz test |
| `testFork_` | Fork test |
| `invariant_` | Invariant test |
| `test_RevertIf_` | Expected revert |
| `test_RevertWhen_` | Expected revert |

### Basic Test Contract

```solidity
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";

contract VaultTest is Test {
    Vault public vault;
    address public alice;
    address public bob;

    function setUp() public {
        vault = new Vault();
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        deal(alice, 100 ether);
        deal(bob, 100 ether);
    }

    function test_Deposit() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();
        assertEq(vault.balanceOf(alice), 1 ether);
    }
}
```

---

## Unit Testing

### Assertions

```solidity
// Equality
assertEq(actual, expected);
assertEq(actual, expected, "custom message");
assertNotEq(actual, expected);

// Comparisons
assertGt(a, b);    // a > b
assertGe(a, b);    // a >= b
assertLt(a, b);    // a < b
assertLe(a, b);    // a <= b

// Boolean
assertTrue(condition);
assertFalse(condition);

// Approximation (critical for DeFi rounding tests)
assertApproxEqAbs(actual, expected, maxDelta);
assertApproxEqRel(actual, expected, maxPercentDelta); // 1e18 = 100%

// Decimal formatting for human-readable output
assertEqDecimal(1e18, 1e18, 18); // Shows "1.0" not "1000000000000000000"
```

### Testing Reverts

```solidity
// Expect any revert
vm.expectRevert();
vault.withdraw(1000 ether);

// Expect specific message
vm.expectRevert("Insufficient balance");
vault.withdraw(1000 ether);

// Expect custom error (selector only)
vm.expectRevert(InsufficientBalance.selector);
vault.withdraw(1000 ether);

// Expect custom error with parameters
vm.expectRevert(
    abi.encodeWithSelector(
        InsufficientBalance.selector,
        0,      // available
        1000    // required
    )
);
vault.withdraw(1000 ether);

// Partial revert (match selector only)
vm.expectPartialRevert(InsufficientBalance.selector);
vault.withdraw(1000 ether);

// Standard error selectors (from StdError)
vm.expectRevert(stdError.arithmeticError);     // overflow/underflow
vm.expectRevert(stdError.divisionError);       // division by zero
vm.expectRevert(stdError.indexOOBError);       // array out of bounds
vm.expectRevert(stdError.popEmptyArrayError);  // pop empty array
```

### Testing Events

```solidity
// Expect event emission
vm.expectEmit(true, true, false, true);
//            topic1, topic2, topic3, data
emit Transfer(alice, bob, 100);
token.transfer(bob, 100);  // Call that should emit

// Record and inspect logs
vm.recordLogs();
token.transfer(bob, 100);
Vm.Log[] memory logs = vm.getRecordedLogs();
assertEq(logs[0].topics[0], keccak256("Transfer(address,address,uint256)"));
```

---

## Fuzz Testing

Forge automatically generates random inputs for test parameters.

### Basic Fuzz Test

```solidity
function testFuzz_Deposit(uint256 amount) public {
    amount = bound(amount, 0.01 ether, 100 ether);

    deal(alice, amount);
    vm.prank(alice);
    vault.deposit{value: amount}();

    assertEq(vault.balanceOf(alice), amount);
}
```

### Using `bound()` vs `vm.assume()`

```solidity
// PREFERRED: bound() — constrains value, never rejects
function testFuzz_transfer(uint256 amount) public {
    amount = bound(amount, 0, token.balanceOf(address(this)));
    token.transfer(alice, amount);
}

// USE SPARINGLY: vm.assume() — rejects inputs, reduces coverage
function testFuzz_transfer(address recipient) public {
    vm.assume(recipient != address(0));
    vm.assume(recipient != address(token));

    // Or use helpers
    assumeNotZeroAddress(recipient);
    assumeNotPrecompile(recipient);
    assumeNotBlacklisted(address(usdc), recipient); // USDC/USDT aware
}
```

### Fixtures (Pre-defined Values)

```solidity
// Array fixture — must match parameter name
uint256[] public fixtureAmount = [0, 1, 100, type(uint256).max];

// Function fixture
function fixtureUser() public returns (address[] memory) {
    address[] memory users = new address[](3);
    users[0] = makeAddr("alice");
    users[1] = makeAddr("bob");
    users[2] = address(0);
    return users;
}

function testFuzz_Transfer(uint256 amount, address user) public {
    // amount drawn from fixtureAmount, user from fixtureUser()
}
```

### Fuzz Configuration

```toml
# foundry.toml
[fuzz]
runs = 256               # Default (development)
seed = 42                # Deterministic seed for reproducibility
max_test_rejects = 65536
dictionary_weight = 40   # % of discovered values reused (edge case coverage)
include_storage = true   # Seed dictionary from contract storage
include_push_bytes = true # Seed from PUSH instructions

[profile.ci.fuzz]
runs = 10000             # CI (production audit minimum)
```

---

## Invariant Testing

Test that properties hold across random function call sequences. **This is the most powerful security testing technique in Foundry.**

### Basic Invariant Test

```solidity
contract VaultInvariantTest is Test {
    Vault public vault;
    VaultHandler public handler;

    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);

        // Only fuzz the handler
        targetContract(address(handler));
    }

    function invariant_SolvencyCheck() public view {
        assertGe(
            address(vault).balance,
            vault.totalDeposits(),
            "Vault is insolvent"
        );
    }

    function invariant_TotalSupplyConsistent() public view {
        assertEq(
            vault.totalSupply(),
            sumAllBalances(),
            "Supply mismatch"
        );
    }
}
```

### Handler Pattern (Core Technique)

Wrap target contract to bound inputs and track state:

```solidity
contract VaultHandler is Test {
    Vault public vault;
    uint256 public ghost_totalDeposited;
    address[] public actors;

    constructor(Vault _vault) {
        vault = _vault;
        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        actors.push(makeAddr("charlie"));
    }

    function deposit(uint256 actorIndex, uint256 amount) external {
        // Bound inputs to valid ranges
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        amount = bound(amount, 0.01 ether, 10 ether);

        address actor = actors[actorIndex];
        deal(actor, amount);

        vm.prank(actor);
        vault.deposit{value: amount}();

        // Track ghost variable for invariant assertions
        ghost_totalDeposited += amount;
    }

    function withdraw(uint256 actorIndex, uint256 amount) external {
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        address actor = actors[actorIndex];

        uint256 balance = vault.balanceOf(actor);
        amount = bound(amount, 0, balance);
        if (amount == 0) return; // Skip zero withdrawals

        vm.prank(actor);
        vault.withdraw(amount);

        ghost_totalDeposited -= amount;
    }

    function getUsers() external view returns (address[] memory) {
        return actors;
    }
}
```

### Target Configuration

```solidity
function setUp() public {
    // Only fuzz specific contracts
    targetContract(address(handler));

    // Exclude contracts from fuzzing
    excludeContract(address(vault));
    excludeContract(address(token));

    // Only use specific senders
    targetSender(alice);
    targetSender(bob);

    // Exclude specific senders
    excludeSender(address(0));

    // Target specific functions only
    bytes4[] memory selectors = new bytes4[](2);
    selectors[0] = handler.deposit.selector;
    selectors[1] = handler.withdraw.selector;
    targetSelector(FuzzSelector({
        addr: address(handler),
        selectors: selectors
    }));
}
```

### Invariant Configuration

```toml
# foundry.toml
[invariant]
runs = 256                          # Number of sequences
depth = 50                          # Calls per sequence
fail_on_revert = false              # Continue on reverts
shrink_run_limit = 5000             # Counter-example minimization
max_fuzz_dictionary_addresses = 15  # Address dictionary size
max_fuzz_dictionary_values = 10     # Value dictionary size

[profile.ci.invariant]
runs = 1000
depth = 100
```

---

## Fork Testing

Test against live blockchain state — essential for integration verification.

### Basic Fork Test

```solidity
contract ForkTest is Test {
    uint256 mainnetFork;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WHALE = 0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503;

    function setUp() public {
        mainnetFork = vm.createFork(vm.envString("MAINNET_RPC_URL"));
        vm.selectFork(mainnetFork);
    }

    function testFork_USDCTransfer() public {
        vm.prank(WHALE);
        IERC20(USDC).transfer(address(this), 1000e6);
        assertEq(IERC20(USDC).balanceOf(address(this)), 1000e6);
    }
}
```

### Fork Cheatcodes

```solidity
// Create fork
uint256 forkId = vm.createFork("mainnet");         // Uses foundry.toml endpoints
uint256 forkId = vm.createFork("mainnet", 18000000); // Pin to specific block

// Create and select in one call
vm.createSelectFork("mainnet");

// Switch between forks
vm.selectFork(mainnetFork);
vm.selectFork(arbitrumFork);

// Roll fork to different block
vm.rollFork(18500000);
vm.rollFork(arbitrumFork, 150000000);

// Make contracts persist across fork switches
vm.makePersistent(address(myContract));
vm.makePersistent(alice, bob, charlie);

// Check/revoke persistence
bool isPersistent = vm.isPersistent(address(myContract));
vm.revokePersistent(address(myContract));
```

### Multi-Fork Cross-Chain Testing

```solidity
function testFork_CrossChain() public {
    // Deploy on mainnet
    vm.selectFork(mainnetFork);
    address mainnetToken = address(new Token());

    // Deploy on Arbitrum
    vm.selectFork(arbitrumFork);
    address arbitrumToken = address(new Token());

    // Verify different deployments
    vm.selectFork(mainnetFork);
    assertEq(Token(mainnetToken).name(), "Token");

    vm.selectFork(arbitrumFork);
    assertEq(Token(arbitrumToken).name(), "Token");
}
```

### Fork Configuration

```toml
# foundry.toml
[rpc_endpoints]
mainnet = "${MAINNET_RPC_URL}"
sepolia = "${SEPOLIA_RPC_URL}"
arbitrum = "${ARBITRUM_RPC_URL}"
optimism = "${OPTIMISM_RPC_URL}"

[rpc_storage_caching]
chains = "all"
endpoints = "all"
```

---

## Differential Testing

Compare implementations against a reference — powerful for finding rounding/precision bugs.

```solidity
function testDifferential_MerkleRoot(bytes32[] memory leaves) public {
    vm.assume(leaves.length > 0 && leaves.length < 100);

    // Solidity implementation
    bytes32 solidityRoot = merkle.getRoot(leaves);

    // Reference implementation via FFI
    string[] memory cmd = new string[](3);
    cmd[0] = "node";
    cmd[1] = "scripts/merkle.js";
    cmd[2] = vm.toString(abi.encode(leaves));

    bytes memory result = vm.ffi(cmd);
    bytes32 jsRoot = abi.decode(result, (bytes32));

    assertEq(solidityRoot, jsRoot, "Merkle root mismatch");
}
```

---

## Snapshots for State Isolation

```solidity
function test_stateSnapshot() public {
    uint256 snapshot = vm.snapshot();

    // Modify state
    vault.deposit{value: 1 ether}();
    assertEq(vault.totalDeposits(), 1 ether);

    // Revert to clean state
    vm.revertTo(snapshot);
    assertEq(vault.totalDeposits(), 0);
}
```

---

## Verbosity Levels

```bash
forge test           # Summary only
forge test -v        # + Logs
forge test -vv       # + Assertion errors
forge test -vvv      # + Stack traces (failures)
forge test -vvvv     # + Stack traces (all) + setup traces
forge test -vvvvv    # + All traces always + storage changes
```

---

## Best Practices

### Fuzz Testing
1. Always `bound()` numeric inputs — never rely on raw random values
2. Use `vm.assume()` sparingly — each rejection reduces coverage
3. Use fixtures for edge cases (0, 1, MAX)
4. Set deterministic seed in CI for reproducibility

### Invariant Testing
1. Use the handler pattern for any non-trivial protocol
2. Track ghost variables for every state-changing operation
3. Start with simple invariants, increase depth/runs gradually
4. Set `fail_on_revert = false` initially, then tighten

### Fork Testing
1. **Always pin to specific block** for reproducibility
2. Configure RPC endpoints in `foundry.toml`, not in test code
3. Use `vm.makePersistent()` for contracts deployed in tests
4. Cache RPC responses with deterministic seed

### General
1. Test public interface, not internal state
2. Use `makeAddr()` for labeled addresses — traces become readable
3. Use `deal()` instead of minting for token setup
4. Test both success AND failure paths
5. One test file per contract, group related tests

---

## Related Files

- [Foundry Security Testing](foundry-security.md) — Vulnerability PoCs with Foundry
- [Foundry Cheatcodes](foundry-cheatcodes.md) — Complete cheatcode reference
- [Foundry CI/CD](foundry-ci-cd.md) — Automated testing pipelines
- [Vulnerability Patterns](vulnerability-patterns.md) — Complete pattern catalog

---

*Source: claude-plugins foundry-solidity testing.md (February 2026)*
