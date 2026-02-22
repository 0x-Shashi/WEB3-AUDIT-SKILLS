# Token Integration Patterns

## Safe Integration Patterns

### Pattern 1: Handle Fee-on-Transfer
```solidity
// WRONG — assumes amount received equals amount sent
token.transferFrom(msg.sender, address(this), amount);
balances[msg.sender] += amount;

// CORRECT — measure actual received amount
uint256 balanceBefore = token.balanceOf(address(this));
token.transferFrom(msg.sender, address(this), amount);
uint256 received = token.balanceOf(address(this)) - balanceBefore;
balances[msg.sender] += received;
```

### Pattern 2: Handle Missing Return Values (USDT)
```solidity
// WRONG — USDT doesn't return bool
bool success = token.transfer(to, amount);

// CORRECT — use SafeERC20
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

token.safeTransfer(to, amount);
```

### Pattern 3: Handle Approval Race Condition
```solidity
// WRONG — front-runnable if previous approval exists
token.approve(spender, newAmount);

// CORRECT — reset to 0 first (required by USDT)
token.safeApprove(spender, 0);
token.safeApprove(spender, newAmount);

// BETTER — use increaseAllowance/decreaseAllowance
token.safeIncreaseAllowance(spender, amount);
```

### Pattern 4: Handle Rebasing Tokens
```solidity
// WRONG — stores absolute amounts that change
mapping(address => uint256) public deposits;

// CORRECT — store shares, convert to assets on withdrawal
mapping(address => uint256) public shares;
uint256 public totalShares;

function deposit(uint256 amount) external {
    uint256 sharesToMint = totalShares == 0
        ? amount
        : (amount * totalShares) / token.balanceOf(address(this));
    shares[msg.sender] += sharesToMint;
    totalShares += sharesToMint;
    token.safeTransferFrom(msg.sender, address(this), amount);
}
```

### Pattern 5: Handle Tokens with Callbacks (ERC777)
```solidity
// WRONG — vulnerable to reentrancy via token callback
function withdraw(uint256 amount) external {
    token.transfer(msg.sender, amount);  // ERC777 calls tokensReceived
    balances[msg.sender] -= amount;       // State update AFTER transfer

// CORRECT — CEI pattern + reentrancy guard
function withdraw(uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;       // State update BEFORE transfer
    token.safeTransfer(msg.sender, amount);
}
```

### Pattern 6: Handle Double-Entry Tokens
```solidity
// Some tokens (legacy TUSD) have two addresses pointing to same balance
// Verify token addresses are not duplicates before allowing deposits
// Use a token registry or whitelist

mapping(address => bool) public supportedTokens;

function addToken(address token) external onlyOwner {
    require(!_isDuplicate(token), "Duplicate entry point");
    supportedTokens[token] = true;
}
```

## Token Compatibility Matrix

| Feature | USDC | USDT | DAI | WETH | WBTC |
|---------|------|------|-----|------|------|
| Returns bool | ✅ | ❌ | ✅ | ✅ | ✅ |
| Blacklist | ✅ | ✅ | ❌ | ❌ | ❌ |
| Pausable | ✅ | ✅ | ❌ | ❌ | ❌ |
| Approve(0) first | ❌ | ✅ | ❌ | ❌ | ❌ |
| Fee-on-transfer | ❌ | ⚠️ (toggle) | ❌ | ❌ | ❌ |
| Decimals | 6 | 6 | 18 | 18 | 8 |
| Upgradeable | ✅ | ✅ | ❌ | ❌ | ❌ |

## Checklist for Code Review
- [ ] Uses SafeERC20 for all transfers
- [ ] Measures actual received amounts (not assumed)
- [ ] Handles tokens with different decimal counts
- [ ] Does not hardcode token addresses
- [ ] Handles zero-amount transfers
- [ ] Considers blacklisted addresses
- [ ] Handles pausable tokens gracefully
- [ ] No approval race conditions
- [ ] Reentrancy protection against callback tokens
