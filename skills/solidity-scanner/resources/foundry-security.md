---
id: foundry-security-testing
title: Foundry Security Testing — Vulnerability PoCs
category: solidity-scanner
difficulty: advanced
triggers:
  - foundry security test
  - foundry PoC
  - foundry exploit test
  - forge security
  - test vulnerability foundry
related_skills:
  - solidity-scanner/SKILL.md
  - solidity-scanner/resources/vulnerability-patterns.md
  - solidity-scanner/resources/foundry-testing.md
  - solidity-scanner/resources/foundry-cheatcodes.md
tags:
  - foundry
  - security
  - testing
  - PoC
  - exploit
last_updated: 2026-02-26
description: >-
  10 vulnerability categories with concrete Foundry PoC tests for each.
  Every vulnerability has a ReentrancyAttacker/exploit contract plus a
  Forge test demonstrating how to verify defenses. Pre-audit checklist
  included. Sourced from claude-plugins foundry-solidity (Feb 2026).
---

# Foundry Security Testing — Vulnerability PoCs

> **For Auditors**: Every vulnerability pattern below includes a runnable Foundry test. Copy these into your audit test suite and adapt for the specific protocol under review.

---

## 1. Reentrancy

**Risk**: External calls allow recursive entry before state updates, draining contracts.

### Vulnerable vs Secure Code

```solidity
// ❌ VULNERABLE: State update after external call
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    (bool sent,) = msg.sender.call{value: amount}("");
    require(sent);
    balances[msg.sender] -= amount; // Too late!
}

// ✅ SECURE: CEI pattern + reentrancy guard
function withdraw(uint256 amount) public nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;    // Effects first
    (bool sent,) = msg.sender.call{value: amount}("");
    require(sent);                      // Interactions last
}
```

### Foundry PoC Test

```solidity
contract ReentrancyAttacker {
    Vault vault;
    uint256 count;

    constructor(Vault _vault) { vault = _vault; }

    receive() external payable {
        if (count++ < 5 && address(vault).balance > 0) {
            vault.withdraw(1 ether);
        }
    }

    function attack() external {
        vault.withdraw(1 ether);
    }

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }
}

function test_reentrancy_protected() public {
    ReentrancyAttacker attacker = new ReentrancyAttacker(vault);
    deal(address(attacker), 2 ether);
    attacker.deposit{value: 1 ether}();

    vm.expectRevert("ReentrancyGuard");
    attacker.attack();
}
```

### Transient Storage Guard (Solidity 0.8.28+)

```solidity
// 200 gas vs 5,000 gas for storage-based guard (25x cheaper)
contract TransientReentrancyGuard {
    modifier nonReentrant() {
        assembly {
            if tload(0) { revert(0, 0) }
            tstore(0, 1)
        }
        _;
        assembly {
            tstore(0, 0)  // CRITICAL: Reset for composability
        }
    }
}
```

---

## 2. Access Control

**Risk**: Missing permission checks allow unauthorized privileged operations.

### Foundry PoC Test

```solidity
function test_accessControl_unauthorized() public {
    vm.prank(attacker);
    vm.expectRevert(
        abi.encodeWithSelector(
            AccessControl.AccessControlUnauthorizedAccount.selector,
            attacker,
            vault.ADMIN_ROLE()
        )
    );
    vault.drain();
}

function test_accessControl_txOrigin_phishing() public {
    // Simulate phishing: admin interacts with attacker contract
    // which then calls the vulnerable contract using tx.origin
    vm.prank(admin, admin); // sender=admin, origin=admin
    vm.expectRevert(); // Should fail if using msg.sender properly
    attackerContract.exploit();
}
```

---

## 3. Oracle Manipulation

**Risk**: Manipulated price feeds cause unfair liquidations or loan exploits.

### Secure Chainlink Pattern

```solidity
function getPrice() public view returns (int256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    require(price > 0, "Invalid price");
    require(answeredInRound >= roundId, "Stale round");
    require(block.timestamp - updatedAt < 3600, "Price too old");

    return price;
}
```

### Foundry PoC Test

```solidity
function test_oracle_staleness() public {
    vm.warp(block.timestamp + 4000); // Past staleness threshold

    vm.expectRevert("Price too old");
    oracle.getPrice();
}

function test_oracle_negative_price() public {
    // Mock Chainlink aggregator returning negative price
    mockAggregator.setLatestRoundData(1, -100, 0, block.timestamp, 1);

    vm.expectRevert("Invalid price");
    oracle.getPrice();
}
```

---

## 4. Integer Overflow/Underflow

**Risk**: Solidity 0.8+ has built-in checks, but `unchecked` blocks and type casting bypass them.

### Foundry PoC Test

```solidity
function test_unchecked_underflow() public {
    // Test that unchecked blocks are safe
    vm.expectRevert(stdError.arithmeticError);
    vault.withdrawUnsafe(type(uint256).max);
}

function test_type_truncation() public {
    // uint256 → uint8 truncates silently
    uint256 largeAmount = 256;
    uint8 small = uint8(largeAmount); // == 0!
    assertEq(small, 0, "Truncation vulnerability");
}
```

---

## 5. Front-Running / MEV

**Risk**: Attackers see pending transactions and extract value.

### Commit-Reveal Pattern

```solidity
function commit(bytes32 hash) external {
    commits[msg.sender] = hash;
    commitTime[msg.sender] = block.timestamp;
}

function reveal(uint256 value, bytes32 salt) external {
    require(block.timestamp >= commitTime[msg.sender] + 1 hours);
    require(commits[msg.sender] == keccak256(abi.encode(value, salt)));
    // Process value
}
```

### Foundry PoC Test

```solidity
function test_frontRunning_slippage() public {
    // Simulate sandwich attack: attacker front-runs with large swap
    vm.prank(attacker);
    dex.swap(tokenA, tokenB, 1_000_000e18); // Front-run

    vm.prank(victim);
    vm.expectRevert("Slippage exceeded");
    dex.swap(tokenA, tokenB, 100e18); // minAmountOut protects
}
```

---

## 6. Flash Loan Attacks

**Risk**: Attackers borrow large amounts to manipulate protocol state within a single transaction.

### Foundry PoC Test (Fork)

```solidity
function test_flashLoan_priceManipulation() public {
    vm.createSelectFork(vm.envString("MAINNET_RPC_URL"));

    // Step 1: Flash borrow large token amount
    // Step 2: Dump into DEX pool → crash spot price
    // Step 3: Liquidate under-collateralized positions at discount
    // Step 4: Repay flash loan + profit

    uint256 balanceBefore = IERC20(token).balanceOf(attacker);
    // ... execute attack ...
    uint256 profit = IERC20(token).balanceOf(attacker) - balanceBefore;
    assertGt(profit, 0, "Flash loan attack should be profitable");
}
```

---

## 7. Signature Malleability

**Risk**: Attackers modify or replay signatures.

### Foundry PoC Test

```solidity
function test_signature_replay_prevented() public {
    (address signer, uint256 pk) = makeAddrAndKey("signer");

    bytes32 digest = keccak256(abi.encode(signer, 100, block.timestamp));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

    // First use succeeds
    vault.permitWithdraw(signer, 100, block.timestamp, v, r, s);

    // Replay should fail (nonce incremented)
    vm.expectRevert("Invalid nonce");
    vault.permitWithdraw(signer, 100, block.timestamp, v, r, s);
}
```

---

## 8. Storage Collision (Proxies)

**Risk**: Proxy and implementation have different storage layouts.

### Foundry PoC Test

```solidity
function test_proxy_storage_collision() public {
    // Read implementation slot (EIP-1967)
    bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 storedImpl = vm.load(address(proxy), implSlot);

    assertEq(
        address(uint160(uint256(storedImpl))),
        address(implementation),
        "Implementation address mismatch"
    );

    // Verify no storage collision between proxy admin and impl slot 0
    bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 slot0 = vm.load(address(proxy), bytes32(0));
    assertTrue(slot0 != storedImpl, "Storage collision detected");
}
```

---

## 9. Denial of Service

**Risk**: Unbounded loops, external call reverts, or block gas limit exhaustion.

### Foundry PoC Test

```solidity
function test_dos_unbounded_loop() public {
    // Add 1000 users to demonstrate gas limit risk
    for (uint256 i = 0; i < 1000; i++) {
        address user = makeAddr(string(abi.encode("user", i)));
        deal(user, 1 ether);
        vm.prank(user);
        vault.deposit{value: 0.01 ether}();
    }

    // distributeAll() should revert or be paginated
    uint256 gasBefore = gasleft();
    vault.distributeBatch(0, 100); // Paginated version works
    uint256 gasUsed = gasBefore - gasleft();
    assertLt(gasUsed, 5_000_000, "Gas usage within limits");
}
```

---

## 10. Common Audit Findings

### Missing Return Value Check

```solidity
// ❌ BAD
token.transfer(user, amount);

// ✅ GOOD
require(token.transfer(user, amount), "Transfer failed");

// ✅ BEST
IERC20(token).safeTransfer(user, amount);
```

### Precision Loss

```solidity
// ❌ BAD: Division before multiplication
uint256 share = (amount / total) * balance; // Rounds to 0!

// ✅ GOOD: Multiplication before division
uint256 share = (amount * balance) / total;
```

### Uninitialized Proxy

```solidity
function test_proxy_uninitialized() public {
    // Deploy implementation without calling initialize
    MyContract impl = new MyContract();

    // Attacker can initialize the implementation directly
    vm.prank(attacker);
    impl.initialize(attacker); // Should fail if _disableInitializers() used
}
```

---

## Invariant Testing for Security

### Handler Pattern with Ghost Variables

```solidity
contract VaultHandler is Test {
    Vault vault;
    uint256 public ghost_totalDeposited;
    address[] public users;

    constructor(Vault _vault) {
        vault = _vault;
        users.push(makeAddr("alice"));
        users.push(makeAddr("bob"));
    }

    function deposit(uint256 userSeed, uint256 amount) external {
        address user = users[bound(userSeed, 0, users.length - 1)];
        amount = bound(amount, 1, 1e24);

        deal(address(vault.asset()), user, amount);
        vm.startPrank(user);
        vault.asset().approve(address(vault), amount);
        vault.deposit(amount, user);
        vm.stopPrank();

        ghost_totalDeposited += amount;
    }

    function withdraw(uint256 userSeed, uint256 shares) external {
        address user = users[bound(userSeed, 0, users.length - 1)];
        shares = bound(shares, 0, vault.balanceOf(user));
        if (shares == 0) return;

        vm.prank(user);
        uint256 assets = vault.redeem(shares, user, user);
        ghost_totalDeposited -= assets;
    }
}

contract VaultInvariant is Test {
    Vault vault;
    VaultHandler handler;

    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);
        targetContract(address(handler));
    }

    function invariant_solvency() public view {
        assertGe(vault.totalAssets(), vault.totalSupply(), "Vault insolvent");
    }

    function invariant_balanceSum() public view {
        uint256 sum = 0;
        address[] memory users = handler.getUsers();
        for (uint256 i = 0; i < users.length; i++) {
            sum += vault.balanceOf(users[i]);
        }
        assertEq(sum, vault.totalSupply());
    }
}
```

---

## Fork Testing for Security

### Mainnet Integration Verification

```solidity
function setUp() public {
    vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), 18000000);
}

function testFork_usdcIntegration() public {
    IERC20 usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address whale = 0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503;

    uint256 balanceBefore = usdc.balanceOf(address(this));

    vm.prank(whale);
    usdc.transfer(address(this), 1_000_000e6);

    assertEq(usdc.balanceOf(address(this)), balanceBefore + 1_000_000e6);
}
```

### Symbolic Execution (Halmos)

```solidity
function check_transferPreservesSupply(address from, address to, uint256 amount) public {
    uint256 supplyBefore = token.totalSupply();
    token.transfer(from, to, amount);
    assert(token.totalSupply() == supplyBefore);
}
// Run: halmos --contract MyTest
```

---

## Pre-Audit Checklist

### Code Quality
- [ ] NatSpec documentation on all public functions
- [ ] No `console.log` or debug statements
- [ ] All TODO/FIXME resolved
- [ ] Consistent naming conventions

### Security Patterns
- [ ] Reentrancy guards on external-calling functions
- [ ] CEI pattern followed
- [ ] Access control on privileged functions
- [ ] No `tx.origin` for authentication
- [ ] `SafeERC20` for token transfers
- [ ] Input validation on all parameters

### Testing
- [ ] >95% code coverage
- [ ] Fuzz tests with 10,000+ runs
- [ ] Invariant tests for core properties
- [ ] Edge case tests (zero, max values)
- [ ] Fork tests for integrations

### Static Analysis
- [ ] Slither: no HIGH/CRITICAL issues
- [ ] Manual review of MEDIUM issues

### Documentation
- [ ] README with security assumptions
- [ ] Threat model documented
- [ ] Known limitations listed
- [ ] Admin functions documented

---

## Foundry Security Commands

```bash
# Run all tests with coverage
forge coverage --report lcov

# Fuzz with high iterations
forge test --fuzz-runs 50000

# Invariant testing
forge test --match-contract Invariant -vv

# Fork testing
forge test --fork-url $RPC_URL

# Gas analysis
forge test --gas-report

# Debug failing test
forge test --match-test testName -vvvv

# Slither integration
slither . --json report.json
```

---

## Security Tools Integration

| Tool | Type | Command |
|------|------|---------|
| Slither | Static analysis | `slither . --json report.json` |
| Mythril | Symbolic execution | `myth analyze contracts/Vault.sol` |
| Echidna | Property-based fuzzing | `echidna test/Invariant.sol` |
| Halmos | Symbolic execution | `halmos --contract MyTest` |
| Certora | Formal verification | `certoraRun spec/rules.spec` |

---

## Related Files

- [Vulnerability Patterns](vulnerability-patterns.md) — Complete pattern catalog with code
- [Foundry Testing](foundry-testing.md) — Fuzz, invariant, fork testing deep dive
- [Foundry Cheatcodes](foundry-cheatcodes.md) — Complete cheatcode reference
- [Gas & Security](gas-security.md) — Gas optimization with security implications
- [Foundry CI/CD](foundry-ci-cd.md) — Automated security testing pipelines

---

*Source: claude-plugins foundry-solidity security.md, testing.md, patterns.md (February 2026)*
