# DeFi Vulnerability Patterns

> **AI Skill**: This file contains real-world DeFi vulnerability patterns extracted from audit reports. Use these patterns to identify similar vulnerabilities in code you're reviewing.

## Quick Reference Index

| Category | Pattern | Severity |
|----------|---------|----------|
| [Pools](#1-liquidity-pool-vulnerabilities) | Slippage Protection, LP Manipulation | High-Medium |
| [Oracles](#2-oracle-vulnerabilities) | TWAP vs Spot, Price Manipulation | Critical-High |
| [Liquidation](#3-liquidation-vulnerabilities) | Cooldown Bypass, Bad Debt | High |
| [Tokens](#4-token-vulnerabilities) | Rebasing, Fee-on-Transfer | High-Medium |
| [Lending](#5-lending-vulnerabilities) | Interest Calculation, Debt Auctions | High |
| [Hooks](#6-hook-vulnerabilities) | Hook Reentrancy, Hook DoS | High-Medium |
| [Math](#7-math-vulnerabilities) | Division, Rounding, Precision | Critical-High |

---

## 1. Liquidity Pool Vulnerabilities

### 1.1 Missing Slippage Protection in Withdraw/Redeem

**Vulnerability**: Vault withdraw/redeem functions allow users to receive fewer assets than expected when underlying yield vault incurs losses.

**Pattern to Look For**:
```solidity
// VULNERABLE: No slippage parameter
function withdraw(uint256 assets) external returns (uint256 shares) {
    shares = previewWithdraw(assets);
    _burn(msg.sender, shares);
    asset.transfer(msg.sender, assets);
}

// VULNERABLE: Exchange rate can change
function convertToAssets(uint256 shares) public view returns (uint256) {
    if (_totalAssets >= totalDebt) {
        return shares;
    } else {
        // Proportional reduction - user may receive less
        return shares.mulDiv(_totalAssets, totalDebt, Math.Rounding.Down);
    }
}
```

**Secure Pattern**:
```solidity
function withdraw(uint256 assets, uint256 minShares) external returns (uint256 shares) {
    shares = previewWithdraw(assets);
    require(shares >= minShares, "Slippage too high");
    // ...
}
```

**Audit Checklist**:
- [ ] Does withdraw/redeem have slippage protection?
- [ ] Can underlying vault incur losses?
- [ ] Is user protected from exchange rate changes?

---

### 1.2 Protocol Assumes Full Liquidity Ownership

**Vulnerability**: Protocol calculates amounts based on total pool reserves instead of protocol-owned liquidity.

**Pattern to Look For**:
```solidity
// VULNERABLE: Uses total reserves, not protocol balance
function reLP() external {
    (uint256 reserveA, uint256 reserveB) = pair.getReserves();
    uint256 lpToRemove = (reserveA * factor) / 1e18;  // Wrong!
    // Should use: pair.balanceOf(address(this))
}
```

**Impact**: If protocol doesn't own majority of LP, calculations fail or revert with underflow.

**Audit Checklist**:
- [ ] Does protocol track its own LP balance separately?
- [ ] Are calculations based on protocol-owned vs total reserves?
- [ ] Can external LPs affect protocol operations?

---

## 2. Oracle Vulnerabilities

### 2.1 TWAP vs Spot Price Mismatch

**Vulnerability**: Using spot prices (manipulable) vs TWAP (resistant) creates arbitrage opportunities and enables liquidation attacks.

**Pattern to Look For**:
```solidity
// VULNERABLE: Chainlink = instant spot, AMM = manipulable spot
function getPrice() public view returns (uint256) {
    uint256 chainlinkPrice = chainlinkFeed.latestAnswer();
    uint256 ammPrice = getAmmSpotPrice();  // Manipulable!
    return (chainlinkPrice + ammPrice) / 2;
}
```

**Attack Scenario**:
1. Flash loan large amount
2. Manipulate AMM spot price
3. Trigger liquidation or arbitrage
4. Repay flash loan with profit

**Secure Pattern**:
```solidity
function getPrice() public view returns (uint256) {
    // Use TWAP for on-chain prices
    uint256 twap = oracle.consult(token, 30 minutes);
    // Or use only trusted oracle with heartbeat checks
    require(block.timestamp - lastUpdate < HEARTBEAT, "Stale price");
}
```

**Audit Checklist**:
- [ ] Is price source TWAP or spot?
- [ ] Can price be manipulated within one transaction?
- [ ] Is there a fallback if oracle fails?
- [ ] Is heartbeat/staleness checked?

---

### 2.2 Stablecoin Depeg During Minting

**Vulnerability**: Protocol assumes stablecoin = $1 USD without validation, allowing excessive minting during depeg events.

**Pattern to Look For**:
```solidity
// VULNERABLE: Assumes USDC = $1
function mint(uint256 usdcAmount) external returns (uint256 tokens) {
    uint256 price = oracle.getRWAPrice();  // Only checks RWA price
    tokens = usdcAmount * 1e18 / price;     // Assumes 1 USDC = 1 USD
    _mint(msg.sender, tokens);
}
```

**Impact**: If USDC depegs to $0.90, attacker mints 11% more tokens than deserved.

**Secure Pattern**:
```solidity
function mint(uint256 usdcAmount) external returns (uint256 tokens) {
    uint256 usdcPrice = usdcOracle.getPrice();  // Check USDC price too
    require(usdcPrice >= MIN_USDC_PRICE, "USDC depeg");
    uint256 actualValue = usdcAmount * usdcPrice / 1e18;
    tokens = actualValue * 1e18 / rwaPrice;
}
```

---

## 3. Liquidation Vulnerabilities

### 3.1 Cooldown Manipulation to Evade Liquidation

**Vulnerability**: Depositing small amounts resets cooldown timer, blocking liquidation.

**Pattern to Look For**:
```solidity
// VULNERABLE: Any deposit resets cooldown
function deposit(uint256 amount) external {
    require(amount >= DUST, "Too small");
    balances[msg.sender] += amount;
    cooldownExpiration[msg.sender] = block.timestamp + COOLDOWN;  // Reset!
}

function liquidate(address user) external {
    require(block.timestamp > cooldownExpiration[user], "Cooldown active");
    // ... liquidation logic
}
```

**Attack**: User front-runs liquidation tx with dust deposit, resetting cooldown.

**Secure Pattern**:
```solidity
function liquidate(address user) external {
    // Check position health regardless of cooldown
    require(isUndercollateralized(user), "Position healthy");
    // Skip cooldown check for underwater positions
    // ... liquidation logic
}
```

---

### 3.2 Bad Debt Creation Cascade

**Vulnerability**: Creating bad debt (credit markdown) forces other auctions to also create bad debt due to snapshot-based debt calculation.

**Pattern to Look For**:
```solidity
// VULNERABLE: Debt snapshot at auction start
function startAuction(bytes32 loanId) external {
    uint256 debt = getLoanDebt(loanId);
    auctions[loanId] = Auction({
        callDebt: debt,  // Snapshot - doesn't update if creditMultiplier changes
        startTime: block.timestamp
    });
}
```

**Problem**: If `creditMultiplier` decreases during auction, `callDebt` underestimates actual debt.

**Audit Checklist**:
- [ ] Is debt calculated dynamically or snapshot?
- [ ] Can external factors change debt during auction?
- [ ] Does bad debt in one loan affect others?

---

### 3.3 USDS Repayment to Wrong Address (POL Exhaustion)

**Vulnerability**: Repaid stablecoins sent to wrong address, forcing Protocol Owned Liquidity to cover the gap.

**Pattern to Look For**:
```solidity
function repay(uint256 amount) external {
    usds.transferFrom(msg.sender, WRONG_ADDRESS);  // Not Liquidizer!
    usdsThatShouldBeBurned += amount;  // Counter increases
    // Liquidizer never receives USDS but counter increases
    // Forces POL to be sold to cover burns
}
```

**Impact**: Attacker can exhaust POL by repeatedly borrowing and repaying.

---

## 4. Token Vulnerabilities

### 4.1 Rebasing Token Approval Exploit

**Vulnerability**: Rebasing tokens change balances based on factor; approvals calculated incorrectly.

**Pattern to Look For**:
```solidity
// VULNERABLE: Approval based on fragments, not gons
function transferAllowance(address router, uint256 amount) external {
    token.approve(router, amount);  // Fixed fragment amount
    // After rebase, this approval allows more/fewer gons
}
```

**Attack Scenario**:
1. Deposit 1000 tokens when rebase factor = 1
2. Wait for rebase factor = 2 (balances halved)
3. Approval still allows transferring 1000 fragments
4. But 1000 fragments now = 2000 gons worth of value

**Audit Checklist**:
- [ ] Does protocol support rebasing tokens?
- [ ] Are approvals gon-based or fragment-based?
- [ ] Is balance tracking gon-based?

---

### 4.2 Fee-on-Transfer Token Handling

**Vulnerability**: Protocol assumes received amount equals sent amount; fee-on-transfer tokens break this.

**Pattern to Look For**:
```solidity
// VULNERABLE: Assumes full amount received
function _transferOutAndCallV5(address token, uint256 amount) internal {
    token.transfer(aggregator, amount);
    aggregator.swapOut(amount);  // Aggregator may receive less!
}
```

**Secure Pattern**:
```solidity
function safeTransfer(address token, uint256 amount) internal returns (uint256 received) {
    uint256 balanceBefore = token.balanceOf(recipient);
    token.transfer(recipient, amount);
    received = token.balanceOf(recipient) - balanceBefore;
    // Use 'received' for subsequent operations
}
```

---

## 5. Lending Vulnerabilities

### 5.1 Zero Interest Partial Repay Blocked

**Vulnerability**: Partial repay requires non-zero interest, blocking repayment for zero-interest loans.

**Pattern to Look For**:
```solidity
// VULNERABLE: interestRepaid check
function _partialRepay(bytes32 loanId, uint256 amount) internal {
    uint256 interestRepaid = calculateInterest(loanId, amount);
    require(interestRepaid != 0, "repay too small");  // Blocks 0% loans!
    // ... repayment logic
}
```

**Fix**: Remove `interestRepaid != 0` check or handle zero-interest case separately.

---

### 5.2 Gauge Weight Manipulation

**Vulnerability**: Tolerance factor allows unstaking despite full debt allocation.

**Pattern to Look For**:
```solidity
// Protocol allows 120% debt ceiling via tolerance
function getDebtCeiling(address gauge) public view returns (uint256) {
    uint256 gaugeWeight = getGaugeWeight(gauge);
    uint256 ceiling = (gaugeWeight * totalBorrowed) / totalWeight;
    return ceiling * 120 / 100;  // 20% tolerance
}
```

**Attack**: Exploit tolerance to unstake ~16.6% of weight each time, eventually unstaking 90%+ while debt remains at "100%".

---

## 6. Hook Vulnerabilities

### 6.1 Prize Claim Fee Theft via Hooks

**Vulnerability**: Hook allows user to claim prize directly, avoiding claimer fees.

**Pattern to Look For**:
```solidity
// VULNERABLE: beforeClaimPrize hook can claim directly
function beforeClaimPrize(address winner, uint8 tier, uint32 prizeIndex) external {
    // Malicious hook claims prize here, returns winner address
    prizePool.claimPrize(winner, tier, prizeIndex, winner, 0, address(0));
    // Claimer's subsequent claim fails - prize already claimed
}
```

**Defense**: Check prize state before/after hook execution; revert if claimed during hook.

---

### 6.2 BeforeSend Hook DoS Attack

**Vulnerability**: Token creator sets BeforeSendHook to invalid address, blocking all transfers.

**Pattern to Look For**:
```go
// VULNERABLE: Any address can be hook
func (k Keeper) SetBeforeSendHook(denom string, hookAddr string) error {
    // No validation that hookAddr is valid contract
    k.beforeSendHooks[denom] = hookAddr
}
```

**Impact**: Staking rewards distribution fails, ABCI processes break.

**Defense**: Whitelist valid hook contracts or require hook address validation.

---

## 7. Math Vulnerabilities

### 7.1 Missing Remainder < Divisor Constraint

**Vulnerability**: Division opcode doesn't verify remainder is less than divisor.

**zkSync/ZK Context**:
```rust
// VULNERABLE: No constraint that remainder < divisor
let (q, r) = src0.div_mod(src1);
// Attacker can submit invalid proof with r >= divisor
```

**Impact**: Malicious validator can manipulate DEX calculations, steal assets.

---

### 7.2 Debt Calculation with Changing Multiplier

**Vulnerability**: Debt snapshot doesn't account for credit multiplier changes during auction.

**Pattern**:
```solidity
// At auction start: debt = principal * creditMultiplier_start
// If creditMultiplier decreases during auction:
// Actual debt = principal * creditMultiplier_current < callDebt
// But callDebt is frozen at snapshot value
```

**Fix**: Calculate debt dynamically using current `creditMultiplier`.

---

## 8. EVM Data Location Vulnerabilities

### 8.1 Storage vs Memory Confusion

**Vulnerability**: Using `memory` when `storage` is needed causes updates to not persist.

**Pattern to Look For**:
```solidity
// VULNERABLE: Creates memory copy, original unchanged
function updateUser(address user) internal {
    User memory userData = users[user];  // Memory copy!
    userData.balance += 100;
    // Changes lost - should be `storage`
}

// CORRECT
function updateUser(address user) internal {
    User storage userData = users[user];
    userData.balance += 100;  // Persists
}
```

---

### 8.2 Log Sorter Queue Manipulation

**Vulnerability**: Sorted queue in log sorter can be manipulated to emit reverted logs.

**zkSync Context**: Two adjacent logs with same timestamp can be submitted as `wr rw wr rw` pattern, causing reverted logs to appear in result queue.

---

## Audit Integration Prompts

### For Pool Audits
```
Analyze this pool contract for:
1. Slippage protection in withdraw/redeem
2. Proper tracking of protocol-owned vs total liquidity
3. LP token handling edge cases
4. Flash loan attack vectors on reserves
```

### For Oracle Audits
```
Check this oracle integration for:
1. TWAP vs spot price usage
2. Staleness/heartbeat validation
3. Fallback oracle availability
4. Stablecoin depeg handling
5. Multi-block manipulation resistance
```

### For Lending Audits
```
Review this lending protocol for:
1. Interest calculation in edge cases (0% APR)
2. Debt snapshot vs dynamic calculation
3. Bad debt cascade scenarios
4. Collateral value during liquidation
5. Cooldown manipulation vectors
```

### For Token Audits
```
Check token integration for:
1. Rebasing token support
2. Fee-on-transfer handling
3. Approval amount vs actual transfer
4. Balance tracking accuracy
5. Hook attack surfaces
```

---

## Cross-Reference Sources

| Pattern | Source Report | Protocol |
|---------|--------------|----------|
| Slippage Protection | Code4rena 2024-03 | PoolTogether |
| LP Manipulation | Code4rena 2023-08 | Dopex |
| TWAP vs Spot | Code4rena 2024-01 | Salty |
| Cooldown Bypass | Code4rena 2024-01 | Salty |
| Bad Debt Cascade | Code4rena 2023-12 | Ethereum Credit Guild |
| Rebasing Tokens | Code4rena 2024-06 | THORChain |
| Fee-on-Transfer | Code4rena 2024-06 | THORChain |
| Hook DoS | Code4rena 2024-11 | MANTRA Chain |
| Zero Interest | Code4rena 2023-12 | Ethereum Credit Guild |
| Gauge Manipulation | Code4rena 2023-12 | Ethereum Credit Guild |

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - General vulnerability patterns
- [severity-scoring.md](severity-scoring.md) - How to score findings
- [comprehensive-checklist.md](../checklists/comprehensive-checklist.md) - Full audit checklist
