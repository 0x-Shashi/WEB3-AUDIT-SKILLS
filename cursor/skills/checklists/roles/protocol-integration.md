---
id: PROTOCOL-INTEGRATION
title: Protocol Integration Checklist
category: checklist
role: developer
phase: integration
triggers:
  - integrating with protocol
  - using external protocol
  - protocol integration
  - third party integration
related_skills:
  - protocol-playbooks/index.md
  - methodology/secure-pattern-reference.md
---

# Protocol Integration Checklist

When integrating with external protocols (Uniswap, Aave, Chainlink, etc), use this checklist.

---

## Pre-Integration Research

- [ ] Read protocol documentation thoroughly
- [ ] Check if protocol is upgradeable
- [ ] Review recent audit reports
- [ ] Check for known vulnerabilities
- [ ] Join protocol Discord/community
- [ ] Check protocol's pausability/killswitch

---

## Chainlink Oracle Integration

### Basic Setup
- [ ] Use correct feed address for network
- [ ] Check feed decimals (8 for most, but verify)
- [ ] Store feed as immutable or configurable
- [ ] Have fallback oracle plan

### Validation (MUST HAVE)
- [ ] Check `updatedAt` for staleness
- [ ] Validate `answer > 0`
- [ ] Check `answeredInRound >= roundId`
- [ ] Set reasonable min/max price bounds
- [ ] Handle feed deprecation

**Secure Pattern:**
```solidity
(uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = 
    feed.latestRoundData();
require(updatedAt > block.timestamp - STALENESS_THRESHOLD, "Stale price");
require(answer > 0, "Invalid price");
require(answeredInRound >= roundId, "Incomplete round");
```

### L2 Specific (Arbitrum/Optimism)
- [ ] Add sequencer uptime feed
- [ ] Check grace period after sequencer restart
- [ ] Handle sequencer downtime gracefully

---

## Uniswap V2/V3 Integration

### V2 Integration
- [ ] Never use spot price for critical decisions
- [ ] Use TWAP with sufficient window (30+ min)
- [ ] Validate reserves are reasonable
- [ ] Check for flash loan attacks
- [ ] Verify pair exists before using

**Vulnerable Pattern (DON'T DO THIS):**
```solidity
(uint112 reserve0, uint112 reserve1,) = pair.getReserves();
price = reserve1 / reserve0; // Flash loan manipulable!
```

### V3 Integration
- [ ] Use `observe()` for TWAP, not slot0
- [ ] Set TWAP window >= 10 minutes
- [ ] Check observation cardinality sufficient
- [ ] Handle tick math overflow
- [ ] Verify pool fee tier

**Secure Pattern:**
```solidity
uint32[] memory secondsAgos = new uint32[](2);
secondsAgos[0] = twapWindow;
secondsAgos[1] = 0;
(int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(twapWindow)));
```

---

## Aave V3 Integration

### Lending
- [ ] Check `getUserAccountData()` before borrow
- [ ] Monitor health factor
- [ ] Handle liquidation threshold
- [ ] Check reserve is active (not paused/frozen)
- [ ] Implement liquidation protection

### Flash Loans
- [ ] Validate `msg.sender` is Aave pool
- [ ] Validate `initiator` is authorized
- [ ] Repay exactly `amount + premium`
- [ ] Use balance checks, not allowance

**Secure Pattern:**
```solidity
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    require(msg.sender == AAVE_POOL, "Unauthorized");
    require(initiator == address(this), "Wrong initiator");
    // Your logic here
    // Approve repayment
    IERC20(assets[0]).approve(AAVE_POOL, amounts[0] + premiums[0]);
    return true;
}
```

---

## Lido Integration

### stETH/wstETH
- [ ] Understand stETH rebases daily
- [ ] Use wstETH for accounting (non-rebasing)
- [ ] Handle 1-2 wei rounding errors
- [ ] Account for share-based transfers
- [ ] Monitor stake limits

**Key Difference:**
```solidity
// stETH rebases (balance changes)
uint256 balance = stETH.balanceOf(user); // Changes daily

// wstETH doesn't rebase (wrap for accounting)
uint256 shares = wstETH.balanceOf(user); // Stays constant
```

- [ ] Never store stETH balance in state
- [ ] Always use shares for accounting
- [ ] Convert at transaction time

---

## Curve Integration

### StableSwap
- [ ] Understand pool is for similar-price assets
- [ ] Check A parameter (amplification)
- [ ] Monitor pool balance
- [ ] Handle admin fee
- [ ] Check coin decimals

### Vyper Contracts
- [ ] Review Vyper-specific quirks
- [ ] Check function signatures manually
- [ ] Test thoroughly (Vyper != Solidity)

---

## Balancer Integration

### Weighted Pools
- [ ] Understand weights (80/20 vs 50/50)
- [ ] Check spot price manipulation
- [ ] Use TWAP oracle if available
- [ ] Handle protocol fees

### Composable Pools
- [ ] Understand BPT as collateral
- [ ] Handle phantom BPT correctly
- [ ] Check pool composition

---

## Yearn Vaults

- [ ] Check `pricePerShare()` before deposit
- [ ] Understand share-based accounting
- [ ] Handle first depositor attack
- [ ] Check deposit/withdrawal limits
- [ ] Monitor vault strategy changes

**First Depositor Protection:**
```solidity
require(vault.totalSupply() > MIN_TOTAL_SUPPLY, "Vault manipulation");
```

---

## MakerDAO Integration

### DAI
- [ ] DAI is standard ERC20 (with permit)
- [ ] Check DSR (savings rate) if relevant
- [ ] Handle PSM interactions
- [ ] Monitor governance changes

### Collateral
- [ ] Check debt ceiling
- [ ] Monitor liquidation ratio
- [ ] Handle price feed delays

---

## Compound Integration

### Lending/Borrowing
- [ ] Check `exchangeRateStored()` before deposit
- [ ] Understand cToken exchange rate increases
- [ ] Handle error codes (not reverts!)
- [ ] Check supply/borrow caps

**Important:** Compound returns error codes, not reverts!
```solidity
uint error = cToken.mint(amount);
require(error == 0, "Mint failed");
```

---

## EIP-4626 Vault Integration

### Standard Functions
- [ ] Use `previewDeposit()` before deposit
- [ ] Use `previewWithdraw()` before withdraw
- [ ] Check `maxDeposit()` / `maxWithdraw()`
- [ ] Handle rounding correctly

### Security
- [ ] Protect against inflation attacks
- [ ] Validate share price reasonable
- [ ] Check for donation attacks

---

## Common Integration Pitfalls

### Don't Trust
- [ ] Spot prices from DEXs
- [ ] Unchecked oracle prices
- [ ] External contract state mid-transaction
- [ ] Assumed token decimals
- [ ] Protocol won't change/pause

### Always Validate
- [ ] Return values from external calls
- [ ] Token amounts received (actual vs expected)
- [ ] State consistency after external call
- [ ] Revert if oracle stale/invalid
- [ ] Minimum output amounts (slippage)

### Plan for Failure
- [ ] Protocol paused/deprecated
- [ ] Oracle feed stopped
- [ ] Pool liquidity drained
- [ ] Unexpected upgrades
- [ ] Emergency withdrawals

---

## Integration Testing Must-Haves

- [ ] Test on forked mainnet with real addresses
- [ ] Test with realistic amounts
- [ ] Test protocol pause scenarios
- [ ] Test oracle manipulation
- [ ] Test with malicious inputs
- [ ] Test upgrade scenarios

**Fork Test Example:**
```solidity
function testRealIntegration() public {
    vm.createSelectFork(vm.envString("MAINNET_RPC"));
    address realUniswapPool = 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640;
    // Test with real pool
}
```

---

## Documentation Requirements

- [ ] Document protocol version used
- [ ] List all external addresses
- [ ] Document assumptions made
- [ ] Note any deviations from standard
- [ ] Plan for protocol upgrades
- [ ] Emergency procedures if protocol fails

---

## Version Tracking

Keep track of:
- [ ] Protocol contract versions
- [ ] Deployment addresses per network
- [ ] Interface versions used
- [ ] Known bugs/quirks per version

**Example:**
```solidity
// Uniswap V3 Factory: 0x1F98431c8aD98523631AE4a59f267346ea31F984
// Router: 0xE592427A0AEce92De3Edee1F18E0157C05861564
// USDC/WETH Pool (0.3%): 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640
// As of: Jan 2026
```

---

## Red Flags (Stop Integration If)

- [ ] [!] Protocol recently exploited
- [ ] [!] No recent audits
- [ ] [!] Upgradeable without timelock
- [ ] [!] No test coverage
- [ ] [!] Unverified contracts
- [ ] [!] No active community
- [ ] [!] Centralized control
- [ ] [!] Can't test on fork

---

## Post-Integration Monitoring

- [ ] Set up alerts for protocol pauses
- [ ] Monitor oracle health
- [ ] Track protocol upgrades
- [ ] Watch for security incidents
- [ ] Join protocol security channels
- [ ] Review new audit reports
