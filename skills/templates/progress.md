# Progress Log: [Protocol Name]

<!--
  WHAT: Your session log - chronological record of what you did, tested, and attempted.
  WHY: Answers "What have I done?" after context resets. Tracks exploit attempts.
  WHEN: Update after each contract reviewed, each PoC attempted, each phase completed.
-->

## Audit Info

| Field | Value |
|-------|-------|
| **Protocol** | [Name] |
| **Auditor** | [Your name] |
| **Start Date** | [Date] |
| **Current Phase** | [Phase X] |

---

## Session Log

### Session 1: [Date]

**Phase:** Phase 1 - Protocol Understanding  
**Duration:** [X hours]

#### Actions Taken
- [ ] Read documentation
- [ ] Identified protocol type: [Type]
- [ ] Loaded attack tree: `attack-trees/[type]-attack-tree.md`
- [ ] Created `threat_model.md`

#### Files Reviewed
| File | Lines | Status | Time Spent | Notes |
|------|-------|--------|------------|-------|
| Protocol.sol | XXX | Complete | 30m | Entry point |
| Oracle.sol | XXX | In Progress | 15m | |

#### Findings This Session
- [Finding ID if any]

#### Notes
- [Session notes]

---

### Session 2: [Date]

**Phase:** Phase 2 - Attack Surface Mapping  
**Duration:** [X hours]

#### Actions Taken
- [ ] Followed attack tree branch [A]
- [ ] Checked anti-patterns
- [ ] Documented suspicious code

#### Files Reviewed
| File | Lines | Status | Time Spent | Notes |
|------|-------|--------|------------|-------|

#### Attack Tree Branches Checked
- [x] [A1] Stale Oracle - No issue found
- [x] [A2] Flash Loan + Spot Price - **Suspicious, investigating**
- [ ] [A3] Zero Price

#### Findings This Session
- [Finding ID if any]

---

## Exploit Attempts

<!--
  CRITICAL: Track every exploit attempt.
  This prevents repeating failed approaches after context reset.
-->

| # | Attack Vector | PoC File | Target | Result | Next Step |
|---|---------------|----------|--------|--------|-----------|
| 1 | [A1] Stale Oracle | `test/StaleOracle.t.sol` | Oracle.sol | ❌ Reverts - oracle has staleness check | Move to [A2] |
| 2 | [A2] Flash Loan | `test/FlashLoan.t.sol` | Lending.sol | ✅ SUCCESS - 10x profit | Document in findings |
| 3 | [D1] Reentrancy | `test/Reentrancy.t.sol` | Vault.sol | ❌ nonReentrant guard | Check cross-function |

### Exploit Attempt Details

#### Attempt #1: Stale Oracle
```solidity
// test/StaleOracle.t.sol
function testStaleOracle() public {
    // Wait for oracle to become stale
    vm.warp(block.timestamp + 2 hours);
    
    // Try to exploit stale price
    vm.expectRevert("Stale price");  // ← Has protection
    protocol.borrow(1000e18);
}
```
**Result:** Protocol has staleness check. Not exploitable.

#### Attempt #2: Flash Loan + Oracle Manipulation
```solidity
// test/FlashLoan.t.sol
function testFlashLoanExploit() public {
    uint256 initialBalance = usdc.balanceOf(attacker);
    
    // 1. Flash loan 1M USDC
    aavePool.flashLoan(address(this), usdc, 1_000_000e6, "");
    
    // 2. Manipulate pool price
    // 3. Borrow at inflated price
    // 4. Repay flash loan
    
    assertGt(usdc.balanceOf(attacker), initialBalance);
}
```
**Result:** ✅ Profit: 500,000 USDC. Documented as H-01.

---

## Files Created/Modified

<!--
  Track what files you've created during the audit.
-->

| File | Type | Created | Last Modified |
|------|------|---------|---------------|
| threat_model.md | Planning | [Date] | [Date] |
| findings_report.md | Findings | [Date] | [Date] |
| test/FlashLoan.t.sol | PoC | [Date] | [Date] |

---

## Test Results

<!--
  Track all test executions.
-->

| Test | Command | Expected | Actual | Status |
|------|---------|----------|--------|--------|
| Flash Loan PoC | `forge test --match-test testFlashLoan` | Profit > 0 | Profit = 500K | ✅ Pass |
| Reentrancy PoC | `forge test --match-test testReentrancy` | Revert bypass | Reverted | ❌ Fail |

---

## Error Log

<!--
  Log ALL errors encountered during audit.
  Helps avoid repeating failed approaches.
-->

| Timestamp | Error | Context | Resolution |
|-----------|-------|---------|------------|
| [Date Time] | `EvmError: Revert` | FlashLoan test | Added proper callback |
| [Date Time] | `Arithmetic overflow` | Interest calc | Used unchecked block |

---

## Context Checkpoint

<!--
  THE 5-QUESTION REBOOT TEST:
  If you can answer these, your context is solid.
-->

| Question | Answer |
|----------|--------|
| **Where am I?** | Phase [X], reviewing [Contract] |
| **Where am I going?** | [Next task] |
| **What's the goal?** | [Audit deliverable] |
| **What have I learned?** | [Key findings so far] |
| **What have I tried?** | [See Exploit Attempts table] |

---

## Gas Used on PoCs

<!--
  Track gas costs for exploit PoCs.
-->

| PoC | Gas Used | Profitable at Gas Price | Notes |
|-----|----------|------------------------|-------|
| FlashLoan.t.sol | 150,000 | Yes @ 50 gwei | $7.50 cost, $500K profit |

---

## Time Tracking

| Phase | Estimated | Actual | Status |
|-------|-----------|--------|--------|
| Phase 1: Understanding | 4h | 3h | ✅ Complete |
| Phase 2: Attack Surface | 8h | 5h | 🔄 In Progress |
| Phase 3: PoC Development | 6h | - | ⏸️ Pending |
| Phase 4: Report | 4h | - | ⏸️ Pending |
| **Total** | **22h** | **8h** | |

---

## Quick Commands

```bash
# Run all tests
forge test -vvv

# Run specific PoC
forge test --match-test testFlashLoan -vvv

# Generate gas report
forge test --gas-report

# Fork mainnet for testing
forge test --fork-url $ETH_RPC_URL
```

---

*Update after EVERY exploit attempt.*
*Never repeat a failed approach.*
