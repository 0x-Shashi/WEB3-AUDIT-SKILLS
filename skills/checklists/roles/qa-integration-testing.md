---
id: QA-INTEGRATION-TESTING
title: QA Integration Testing Checklist
category: checklist
role: qa-tester
phase: integration-testing
triggers:
  - integration testing
  - qa checklist
  - testing checklist
  - integration test scenarios
  - how to test integration
related_skills:
  - methodology/poc-writing-guide.md
  - checklists/comprehensive-checklist.md
---

# QA Integration Testing Checklist

For testing protocol interactions, edge cases, and cross-contract behavior.

---

## Test Environment Setup

- [ ] Forked mainnet at recent block
- [ ] All dependency addresses match production
- [ ] Test accounts funded with realistic amounts
- [ ] Block explorer integration working
- [ ] Gas reporter enabled
- [ ] Coverage enabled

**Setup Commands:**
```bash
forge test --fork-url $MAINNET_RPC_URL
forge test --gas-report
forge coverage
```

---

## Oracle Integration

### Chainlink Oracle Tests

- [ ] Mock oracle returns stale price
- [ ] Mock oracle returns zero price
- [ ] Mock oracle returns negative price
- [ ] Test with answeredInRound < roundId (incomplete round)
- [ ] Test with updatedAt older than heartbeat
- [ ] Test oracle switching (fallback)
- [ ] Test with wrong decimals (6 vs 8 vs 18)

**Test Template:**
```solidity
function testStalePrice() public {
    // Set stale timestamp
    mockOracle.setUpdatedAt(block.timestamp - 2 hours);
    // Should revert
    vm.expectRevert(StalePrice.selector);
    protocol.getPrice();
}
```

### L2 Sequencer Tests

- [ ] Test with sequencer down (answer = 1)
- [ ] Test grace period after sequencer restart
- [ ] Test with stale sequencer feed

---

## Token Integration

### Standard ERC20 Tests

- [ ] Test with 6 decimal token (USDC)
- [ ] Test with 8 decimal token (WBTC)
- [ ] Test with 18 decimal token (DAI)
- [ ] Test with 0 amount deposits/withdrawals
- [ ] Test with max uint256 amounts

### Weird ERC20 Tests

- [ ] Fee-on-transfer tokens (e.g., PAXG, STA)
- [ ] Rebasing tokens (e.g., stETH, aToken)
- [ ] Non-standard return values (e.g., USDT)
- [ ] Pausable tokens
- [ ] Tokens with blacklist (e.g., USDC)
- [ ] Tokens with multiple entry points

**Test Template:**
```solidity
function testFeeOnTransfer() public {
    // Use a token that takes 1% fee
    FeeToken fee = new FeeToken();
    vm.prank(user);
    protocol.deposit(fee, 100e18);
    // Should handle 99e18 actual received
    assertEq(protocol.balanceOf(user), 99e18);
}
```

### Token Return Value Tests

- [ ] Test with tokens that return false (not revert)
- [ ] Test with tokens that don't return bool
- [ ] Verify SafeERC20 used everywhere

---

## DEX/AMM Integration

### Uniswap V2 Tests

- [ ] Mock pool with manipulated reserves
- [ ] Test with very low liquidity
- [ ] Test with K constant violation
- [ ] Test with zero liquidity

### Uniswap V3 Tests

- [ ] Mock TWAP manipulation
- [ ] Test with liquidity in single tick
- [ ] Test with wide tick spacing
- [ ] Test with negative ticks
- [ ] Test cardinality too low for TWAP window

**Test Template:**
```solidity
function testLowLiquidity() public {
    // Set pool to minimal liquidity
    mockPool.setReserves(1, 1);
    // Should revert or detect manipulation
    vm.expectRevert(InsufficientLiquidity.selector);
    protocol.swap();
}
```

---

## External Protocol Integration

### Lending Protocol (Aave/Compound)

- [ ] Test when pool is at utilization cap
- [ ] Test when user hits borrow limit
- [ ] Test liquidation threshold
- [ ] Test with paused market
- [ ] Test with deprecated market

### Vault Integration (Yearn/ERC4626)

- [ ] Test share inflation attack (first depositor)
- [ ] Test with 0 total supply
- [ ] Test deposit/withdraw rounding
- [ ] Test with vault paused
- [ ] Test with vault at cap

---

## Signature/Permit Tests

### EIP-2612 Permit

- [ ] Test with expired deadline
- [ ] Test with wrong nonce
- [ ] Test with signature replay
- [ ] Test cross-chain replay (wrong chainId)
- [ ] Test with malformed signature

**Test Template:**
```solidity
function testExpiredPermit() public {
    uint256 deadline = block.timestamp - 1;
    bytes memory sig = getPermitSignature(user, spender, amount, deadline);
    vm.expectRevert(ExpiredDeadline.selector);
    protocol.permit(user, spender, amount, deadline, sig);
}
```

### EIP-712 Signatures

- [ ] Test nonce replay
- [ ] Test with wrong domain separator
- [ ] Test signature malleability
- [ ] Test with compact signature (64 bytes)

---

## Reentrancy Tests

### Classic Reentrancy

- [ ] Test callback before state update
- [ ] Test with malicious ERC777 receiver
- [ ] Test with ERC721 onReceive callback
- [ ] Test with ERC1155 callback

**Test Template:**
```solidity
contract ReentrancyAttacker {
    function receive() external payable {
        // Reenter
        target.withdraw(1 ether);
    }
}
```

### Read-Only Reentrancy

- [ ] Test view function called during reentrant state
- [ ] Test LP share calculation during callback
- [ ] Test totalSupply during minting

---

## Access Control Tests

### Role-Based Tests

- [ ] Test unauthorized user calling restricted function
- [ ] Test role revocation mid-operation
- [ ] Test role renouncement
- [ ] Test admin role self-revocation

### Upgrade Tests

- [ ] Test upgrade by non-owner
- [ ] Test upgrade to invalid implementation
- [ ] Test initialize on already initialized
- [ ] Test storage collision after upgrade

---

## Economic Attack Tests

### Flash Loan Tests

- [ ] Simulate flash loan + price manipulation
- [ ] Test with flash-minted tokens (if applicable)
- [ ] Test MEV sandwich attack
- [ ] Test with multiple flash loans in sequence

**Test Template:**
```solidity
function testFlashLoanAttack() public {
    uint256 loanAmount = 1000000e18;
    // Get flash loan
    flashLender.loan(loanAmount);
    // Manipulate price
    dex.swap(loanAmount);
    // Exploit protocol
    protocol.exploit();
    // Repay loan
    flashLender.repay(loanAmount);
}
```

### Front-Running Tests

- [ ] Test transaction ordering (MEV)
- [ ] Test with different gas prices
- [ ] Test slippage protection

---

## Edge Cases

### Boundary Values

- [ ] Test with amount = 0
- [ ] Test with amount = 1 wei
- [ ] Test with amount = type(uint256).max
- [ ] Test with empty arrays
- [ ] Test with max array length

### Time Manipulation

- [ ] Test with block.timestamp at boundaries
- [ ] Fast forward time (years ahead)
- [ ] Test with timestamp = 0
- [ ] Test reward calculation over long periods

**Test Template:**
```solidity
function testMaxUint() public {
    vm.expectRevert(Overflow.selector);
    protocol.deposit(type(uint256).max);
}
```

---

## Gas Limits & DoS

- [ ] Test functions with unbounded loops
- [ ] Test with max gas usage
- [ ] Test with array length DoS
- [ ] Test with max iterations

---

## Multi-Step Interactions

### Typical User Flow

- [ ] Deposit → Wait → Withdraw
- [ ] Approve → Deposit → Approve More → Deposit
- [ ] Stake → Claim Rewards → Unstake
- [ ] Borrow → Repay Partial → Borrow More → Repay Full

### Interleaved Actions

- [ ] User A deposits while User B withdraws
- [ ] Multiple users simultaneously
- [ ] Deposit/withdraw in same block

---

## Failure Recovery Tests

### Paused State

- [ ] Test all functions while paused
- [ ] Test unpause by unauthorized
- [ ] Test re-pause immediately

### Emergency Shutdown

- [ ] Test emergency withdraw
- [ ] Test partial recovery
- [ ] Test resume after shutdown

---

## Cross-Chain Tests (if applicable)

### Bridge Tests

- [ ] Test message verification
- [ ] Test replay on different chain
- [ ] Test with wrong chain ID
- [ ] Test bridge unavailable

### L1 ↔ L2 Tests

- [ ] Test L1 → L2 message
- [ ] Test L2 → L1 message
- [ ] Test sequencer downtime
- [ ] Test reorg handling

---

## Fuzz Testing Scenarios

### Property-Based Tests

- [ ] Invariant: totalSupply = sum(balances)
- [ ] Invariant: assets >= liabilities
- [ ] Invariant: balance never negative
- [ ] Invariant: shares never exceed totalSupply

**Fuzz Template:**
```solidity
function testFuzz_DepositWithdraw(uint256 amount) public {
    vm.assume(amount > 0 && amount < 1e30);
    vault.deposit(amount);
    uint256 shares = vault.balanceOf(user);
    vault.withdraw(shares);
    assertEq(vault.balanceOf(user), 0);
}
```

---

## Performance Tests

- [ ] Gas cost within budget
- [ ] Response time acceptable
- [ ] Max users supported
- [ ] Max transactions per block

---

## Documentation Tests

- [ ] NatSpec matches behavior
- [ ] README examples work
- [ ] Error messages clear
- [ ] Events match documentation

---

## Test Coverage Goals

- [ ] Line coverage > 95%
- [ ] Branch coverage > 90%
- [ ] Function coverage = 100%
- [ ] Critical paths 100% covered

---

## Regression Tests

After each bug fix:

- [ ] Add test reproducing the bug
- [ ] Verify fix works
- [ ] Test related functions
- [ ] Document in changelog

---

## Test Checklist Template (Copy-Paste)

```markdown
## Integration Test Results

**Protocol:** [Name]
**Date:** [Date]
**Tester:** [Name]

### Oracle Integration
- [ ] Stale price handling
- [ ] Zero/negative price handling
- [ ] Sequencer checks (L2)
- [ ] Multi-oracle fallback

### Token Integration
- [ ] 6/8/18 decimal tokens tested
- [ ] Fee-on-transfer tokens tested
- [ ] Rebasing tokens tested
- [ ] Non-standard returns handled

### External Protocols
- [ ] DEX integration tested
- [ ] Lending protocol tested
- [ ] Oracle integration tested

### Attack Scenarios
- [ ] Reentrancy tested
- [ ] Flash loan attacks tested
- [ ] Front-running tested
- [ ] Price manipulation tested

### Edge Cases
- [ ] Zero amounts tested
- [ ] Max uint tested
- [ ] Empty arrays tested
- [ ] Time boundaries tested

### Coverage
- Line: [X%]
- Branch: [X%]
- Function: [X%]

### Issues Found
1. [Issue description]
2. [Issue description]

### Sign-Off
- [ ] All critical paths tested
- [ ] All issues documented
- [ ] Ready for audit
```
