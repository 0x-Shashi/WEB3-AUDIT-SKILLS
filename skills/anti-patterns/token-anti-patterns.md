---
id: TOKEN-ANTI-PATTERNS
title: Token Anti-Patterns
category: anti-pattern
tags: [token, erc20, fee-on-transfer, rebasing, deflationary]
severity_range: Medium-Critical
real_exploits: $50M+
related_skills:
  - patterns/token-patterns.md
  - patterns/vault-patterns.md
  - patterns/lending-pool-patterns.md
---

# Token Anti-Patterns

Common mistakes when handling non-standard ERC20 tokens. Total losses from these patterns exceed $50M+.

---

## Anti-Pattern 1: Fee-on-Transfer Token Mishandling

### Description
Protocol assumes `transfer()` or `transferFrom()` moves exact amount specified, but some tokens charge fees/burn on transfer, resulting in less received than sent.

### Vulnerable Code
```solidity
// VULNERABLE
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    // Assumes 'amount' received
    balances[msg.sender] += amount;  // Wrong! May receive less
}

function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);  // May send less than debited
}
```

### Why It's Vulnerable
- **Fee-on-transfer tokens** (e.g., SAFEMOON, REFLECT) deduct a % on every transfer
- Protocol credits user for `amount` but receives `amount - fee`
- User can withdraw more than deposited → Protocol drained
- Accounting becomes inconsistent

### Secure Pattern
```solidity
// SECURE
function deposit(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = token.balanceOf(address(this));
    
    uint256 actualReceived = balanceAfter - balanceBefore;
    balances[msg.sender] += actualReceived;  // Credit actual amount
}
```

### Detection Checklist
- [ ] Balance snapshot before/after transfer
- [ ] Credits based on actual received amount
- [ ] Withdrawal debits match actual sent
- [ ] Test with known fee-on-transfer tokens

### Real-World Impact
- **Balancer (2021):** $500K+ loss from deflationary tokens
- **SushiSwap:** Multiple pools drained
- **Severity:** High (theft of funds)

---

## Anti-Pattern 2: Rebasing Token Accounting

### Description
Protocol stores token balance as state variable, but rebasing tokens (e.g., AMPL, stETH) change balance automatically. Stored balance becomes stale.

### Vulnerable Code
```solidity
// VULNERABLE
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    userDeposits[msg.sender] += amount;
    totalDeposits += amount;  // Doesn't track rebases
}

function withdraw() external {
    uint256 amount = userDeposits[msg.sender];
    token.transfer(msg.sender, amount);  // May send more/less than deserved
    userDeposits[msg.sender] = 0;
}
```

### Why It's Vulnerable
- **Positive rebase:** User withdraws more than they contributed (theft)
- **Negative rebase:** User withdraws less than deserved (loss)
- Accounting diverges from actual holdings
- First withdrawer may drain pool

### Secure Pattern
```solidity
// SECURE - Use shares instead of amounts
uint256 public totalShares;
mapping(address => uint256) public userShares;

function deposit(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = token.balanceOf(address(this));
    uint256 actualReceived = balanceAfter - balanceBefore;
    
    uint256 shares = (totalShares == 0) 
        ? actualReceived 
        : (actualReceived * totalShares) / balanceBefore;
    
    userShares[msg.sender] += shares;
    totalShares += shares;
}

function withdraw() external {
    uint256 shares = userShares[msg.sender];
    uint256 totalBalance = token.balanceOf(address(this));
    uint256 amount = (shares * totalBalance) / totalShares;
    
    userShares[msg.sender] = 0;
    totalShares -= shares;
    token.transfer(msg.sender, amount);
}
```

### Detection Checklist
- [ ] Uses share-based accounting
- [ ] Rebases automatically handled
- [ ] First depositor attack mitigated
- [ ] Test with known rebasing tokens (AMPL, stETH)

### Real-World Impact
- **Numerous protocols:** Incorrect stETH accounting
- **Rari Capital (2021):** $11M+ loss (multiple issues including rebasing)
- **Severity:** Critical (fund theft)

---

## Anti-Pattern 3: ERC777 Re-entrancy

### Description
ERC777 tokens call `tokensReceived` hook on recipient, enabling re-entrancy before state updates complete.

### Vulnerable Code
```solidity
// VULNERABLE
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    // tokensReceived hook called here!
    balances[msg.sender] += amount;  // State updated AFTER hook
}

function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State updated first
    token.transfer(msg.sender, amount);  // But hook allows re-entry
}
```

### Why It's Vulnerable
- `tokensReceived` hook executes during transfer
- Attacker can re-enter before state updates
- Classic re-entrancy pattern
- Similar to ETH re-entrancy but via ERC777

### Secure Pattern
```solidity
// SECURE - Use Checks-Effects-Interactions + ReentrancyGuard
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // Effect before interaction
    token.transfer(msg.sender, amount);
}

// Or explicitly block ERC777
require(token.code.length > 0 && !_isERC777(token), "No ERC777");
```

### Detection Checklist
- [ ] ReentrancyGuard on all token interactions
- [ ] Checks-Effects-Interactions pattern
- [ ] Token whitelist excludes ERC777
- [ ] Test with actual ERC777 tokens

### Real-World Impact
- **Uniswap V1:** Required explicit ERC777 handling
- **Imbtc (2020):** $300K+ via ERC777 re-entrancy
- **Severity:** Critical (full drain)

---

## Anti-Pattern 4: Approval Race Condition

### Description
Changing approval from N to M allows front-running attack to spend N+M tokens.

### Vulnerable Code
```solidity
// VULNERABLE USER CODE
// User has approved spender for 100 tokens
token.approve(spender, 50);  // Change approval to 50
// Spender front-runs:
// 1. Spend 100 (old approval)
// 2. New approval goes through (50)
// 3. Spend another 50
// Total spent: 150 instead of intended 50
```

### Why It's Vulnerable
- Front-running allows double spend
- Standard ERC20 `approve` is vulnerable
- User intends to decrease, but attacker spends both

### Secure Pattern
```solidity
// SECURE - Use increase/decrease OR reset to zero first
token.approve(spender, 0);  // Reset to zero
token.approve(spender, 50);  // Then set new value

// Or use OpenZeppelin's increaseAllowance
token.increaseAllowance(spender, 50);
token.decreaseAllowance(spender, 100);
```

### Detection Checklist
- [ ] Use `increaseAllowance`/`decreaseAllowance`
- [ ] OR reset to zero before new approval
- [ ] Educate users about race condition
- [ ] Consider permit (EIP-2612) instead

### Real-World Impact
- **Widespread issue:** Theoretical > practical
- **DEX frontends:** Many implement increase/decrease
- **Severity:** Medium (requires user mistake + MEV)

---

## Anti-Pattern 5: Deflationary Token Math Errors

### Description
Tokens with burn mechanisms or reflection rewards cause protocol math to break due to changing total supply.

### Vulnerable Code
```solidity
// VULNERABLE
uint256 public constant TOTAL_SUPPLY = 1_000_000e18;

function calculateReward(address user) public view returns (uint256) {
    uint256 balance = token.balanceOf(user);
    // Assumes total supply is constant
    return (balance * rewardPool) / TOTAL_SUPPLY;  // Wrong! Supply may have decreased
}
```

### Why It's Vulnerable
- Deflationary tokens burn on transfer
- Total supply decreases over time
- Hardcoded supply causes incorrect calculations
- Rewards miscalculated → underpayment or overpayment

### Secure Pattern
```solidity
// SECURE
function calculateReward(address user) public view returns (uint256) {
    uint256 balance = token.balanceOf(user);
    uint256 currentSupply = token.totalSupply();  // Dynamic supply
    return (balance * rewardPool) / currentSupply;
}
```

### Detection Checklist
- [ ] Never hardcode total supply
- [ ] Use `token.totalSupply()` dynamically
- [ ] Test with deflationary tokens
- [ ] Account for burns in calculations

### Real-World Impact
- **Multiple yield farms:** Incorrect reward calculations
- **Severity:** Medium (incorrect accounting)

---

## Anti-Pattern 6: Multiple Entry Point Confusion

### Description
Some tokens have multiple entry points (`transfer`, `send`, `move`) or non-standard naming, causing protocol to miss transfers.

### Vulnerable Code
```solidity
// VULNERABLE - Only tracks standard transfer
mapping(address => uint256) public balances;

function _onTokenTransfer(address from, address to, uint256 amount) internal {
    // Tracks transfer() calls
    if (to == address(this)) {
        balances[from] += amount;
    }
}

// But token also has send() or move()!
// Those bypass tracking → accounting breaks
```

### Why It's Vulnerable
- Non-standard tokens may use different function names
- Protocol only monitors `transfer`/`transferFrom`
- Alternative entry points bypass accounting
- Balance tracking becomes inconsistent

### Secure Pattern
```solidity
// SECURE - Whitelist approach
mapping(address => bool) public supportedTokens;

function deposit(address token, uint256 amount) external {
    require(supportedTokens[token], "Token not supported");
    // Only allow vetted, standard tokens
}

// OR - Balance snapshot approach
function deposit(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    // User sends tokens (any method)
    uint256 balanceAfter = token.balanceOf(address(this));
    require(balanceAfter >= balanceBefore + amount, "Insufficient received");
    balances[msg.sender] += (balanceAfter - balanceBefore);
}
```

### Detection Checklist
- [ ] Token whitelist with vetted contracts
- [ ] Balance snapshot method for deposits
- [ ] No assumptions about function names
- [ ] Test with non-standard tokens

### Real-World Impact
- **Rare but impactful:** DSToken has `push`, `pull`, `move`
- **Severity:** Medium (accounting errors)

---

## Anti-Pattern 7: Return Value Not Checked

### Description
Some ERC20s don't revert on failure but return `false`. Not checking return value causes silent failures.

### Vulnerable Code
```solidity
// VULNERABLE
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);  // Return value ignored!
    // If transfer fails (returns false), state already updated
}
```

### Why It's Vulnerable
- Not all ERC20s revert on failure (e.g., USDT, BNB)
- Transfer may fail silently
- State updated even though transfer didn't succeed
- User loses accounting but doesn't receive tokens

### Secure Pattern
```solidity
// SECURE - Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    token.safeTransfer(msg.sender, amount);  // Reverts if returns false
}

// Or manual check
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    bool success = token.transfer(msg.sender, amount);
    require(success, "Transfer failed");
}
```

### Detection Checklist
- [ ] Use SafeERC20 for all token interactions
- [ ] OR manually check return values
- [ ] Test with non-reverting tokens (USDT, BNB)
- [ ] Never ignore return values

### Real-World Impact
- **Multiple protocols:** Silent failures cause accounting errors
- **Severity:** High (user loses funds, protocol accounting breaks)

---

## Comparison Table

| Anti-Pattern | Severity | Exploitability | Fix Difficulty | Common Tokens Affected |
|--------------|----------|----------------|----------------|------------------------|
| Fee-on-Transfer | High | Easy | Easy | SAFEMOON, REFLECT, SRG |
| Rebasing | Critical | Medium | Medium | AMPL, stETH, aTokens |
| ERC777 Re-entrancy | Critical | Medium | Easy | Any ERC777 (rare) |
| Approval Race | Medium | Hard | Easy | All ERC20s |
| Deflationary Math | Medium | Easy | Easy | RFI, SAFEMOON, BabyDoge |
| Multiple Entry Points | Medium | Medium | Medium | DSToken, ERC223 |
| Return Value Ignored | High | Easy | Easy | USDT, BNB, OMG |

---

## Quick Detection Guide

```solidity
// Token Safety Checklist

// 1. Fee-on-Transfer Detection
uint256 balanceBefore = token.balanceOf(address(this));
token.transferFrom(user, address(this), 100);
uint256 balanceAfter = token.balanceOf(address(this));
bool hasFee = (balanceAfter - balanceBefore) < 100;

// 2. Rebasing Detection
uint256 balance1 = token.balanceOf(someAddress);
// Wait or trigger rebase
uint256 balance2 = token.balanceOf(someAddress);
bool isRebasing = balance1 != balance2;  // Despite no transfers

// 3. ERC777 Detection
try IERC1820Registry(0x1820...).getInterfaceImplementer(
    token, keccak256("ERC777Token")
) returns (address implementer) {
    bool isERC777 = implementer != address(0);
}

// 4. Return Value Detection
bytes memory payload = abi.encodeWithSignature("transfer(address,uint256)", to, amount);
(bool success, bytes memory returndata) = token.call(payload);
bool returnsValue = returndata.length > 0;
```

---

## Mitigation Strategy

### 1. Token Whitelisting
- Vet all tokens before integration
- Maintain list of safe, standard tokens
- Test deposits/withdrawals extensively

### 2. Balance Snapshot Pattern
```solidity
uint256 balanceBefore = token.balanceOf(address(this));
// Token operation
uint256 balanceAfter = token.balanceOf(address(this));
uint256 actualAmount = balanceAfter - balanceBefore;
// Use actualAmount for accounting
```

### 3. Use SafeERC20
```solidity
using SafeERC20 for IERC20;
token.safeTransfer(to, amount);
token.safeTransferFrom(from, to, amount);
```

### 4. Share-Based Accounting
- For yield-bearing/rebasing tokens
- Insulates from balance changes
- Ensures fair distribution

### 5. Re-entrancy Protection
```solidity
modifier nonReentrant() { /* ... */ }
// Apply to all token-interacting functions
```

---

## Testing Recommendations

### Test Token Suite
1. **Standard ERC20:** DAI, USDC
2. **Fee-on-Transfer:** SAFEMOON, REFLECT
3. **Rebasing:** AMPL, stETH
4. **No Return Value:** USDT, BNB
5. **Deflationary:** RFI, BabyDoge
6. **ERC777:** (if accepting)

### Test Scenarios
- Deposit → Withdraw (exact amounts)
- Multiple deposits → Single withdraw
- Concurrent operations
- Edge cases (zero amounts, max uint)
- Front-running simulations

---

## See Also

- **Attack Trees:** [vault-attack-tree.md](../attack-trees/vault-attack-tree.md)
- **Patterns:** [token-patterns.md](../patterns/token-patterns.md)
- **Related:** [reentrancy-anti-patterns.md](./reentrancy-anti-patterns.md)

---

**Last Updated:** 2025  
**Version:** 1.0  
**Total Known Losses:** $50M+
