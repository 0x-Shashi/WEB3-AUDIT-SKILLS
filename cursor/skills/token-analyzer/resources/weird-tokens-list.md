# Comprehensive Weird ERC20 Tokens List

This document catalogs all known non-standard ERC20 token behaviors that can cause issues in DeFi protocol integrations.

---

## 1. Fee-on-Transfer Tokens (T-01)

**Behavior**: A percentage of each transfer is deducted as a fee.

**Impact**: Protocol receives less than the amount parameter in `transfer()`/`transferFrom()`.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Assumes amount received equals amount sent
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    userBalance[msg.sender] += amount;  // BUG: User credited with more than received
}

function withdraw(uint256 amount) external {
    require(userBalance[msg.sender] >= amount);
    userBalance[msg.sender] -= amount;
    token.transfer(msg.sender, amount);  // May fail if contract balance < sum of user balances
}
```

### Secure Code
```solidity
// ✅ SECURE: Measures actual received amount
function deposit(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    
    userBalance[msg.sender] += received;  // Credit only what was actually received
}
```

### Known Fee-on-Transfer Tokens
| Token | Chain | Fee | Notes |
|-------|-------|-----|-------|
| SAFEMOON | BSC | 10% | Reflection + Liquidity |
| SHIB (some variants) | Multi | Varies | Not original SHIB |
| RFI | ETH | 1% | Redistribution |
| ELON | ETH | Varies | |
| PAXG | ETH | 0.02% | Gold-backed |
| STA | ETH | 1% | Deflationary |

### Detection Pattern
```solidity
function detectFeeOnTransfer(address token, address holder, uint256 amount) external view returns (bool) {
    // Simulate transfer and compare
    uint256 holderBalance = IERC20(token).balanceOf(holder);
    uint256 thisBalance = IERC20(token).balanceOf(address(this));
    
    // In practice, use try-catch with actual transfer in test environment
    // Cannot detect without actual transfer
    return false;
}
```

### Grep Patterns
```
# Find unsafe deposit patterns
transferFrom.*\n.*\+=.*amount
safeTransferFrom.*\n.*\+=.*amount

# Find proper patterns (good)
balanceOf.*Before
received.*=.*balanceOf.*-
```

---

## 2. Rebasing Tokens - Positive (T-02)

**Behavior**: Token balances automatically increase over time (staking rewards, yield).

**Impact**: `balanceOf()` returns different values at different times without transfers.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Caches balance that will become stale
mapping(address => uint256) public stakedBalance;

function stake(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    stakedBalance[msg.sender] = amount;  // BUG: This becomes stale as balance rebases up
}

function unstake() external {
    uint256 amount = stakedBalance[msg.sender];
    token.transfer(msg.sender, amount);  // User loses rebased gains
}
```

### Secure Code
```solidity
// ✅ SECURE: Use shares for rebasing tokens
mapping(address => uint256) public shares;
uint256 public totalShares;

function stake(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    
    uint256 sharesToMint = totalShares == 0 
        ? received 
        : (received * totalShares) / balanceBefore;
    
    shares[msg.sender] += sharesToMint;
    totalShares += sharesToMint;
}

function unstake() external {
    uint256 userShares = shares[msg.sender];
    uint256 amount = (userShares * token.balanceOf(address(this))) / totalShares;
    
    shares[msg.sender] = 0;
    totalShares -= userShares;
    
    token.transfer(msg.sender, amount);  // User receives proportional share including rebases
}
```

### Known Positive Rebasing Tokens
| Token | Chain | Mechanism | Notes |
|-------|-------|-----------|-------|
| stETH | ETH | Lido staking | Daily rebase |
| aTokens | ETH/Multi | Aave lending | Continuous |
| AMPL (up) | ETH | Elastic supply | Can go both ways |
| yTokens | ETH | Yearn yield | |
| OHM (staked) | ETH | Protocol rewards | |

### Wrapper Pattern
```solidity
// For stETH, use wstETH instead (non-rebasing wrapper)
// wstETH represents shares of stETH, doesn't rebase
IWstETH(wstETH).wrap(stETHAmount);  // Convert stETH to wstETH
IWstETH(wstETH).unwrap(wstETHAmount);  // Convert back
```

---

## 3. Rebasing Tokens - Negative (T-03)

**Behavior**: Token balances automatically decrease (negative rebase, demurrage).

**Impact**: Users may have less than expected, can cause underflows.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Stored balance may exceed actual balance after negative rebase
function withdraw(uint256 storedAmount) external {
    require(userBalance[msg.sender] >= storedAmount);
    userBalance[msg.sender] -= storedAmount;
    token.transfer(msg.sender, storedAmount);  // May revert if contract balance < storedAmount
}
```

### Known Negative Rebasing Tokens
| Token | Chain | Mechanism | Notes |
|-------|-------|-----------|-------|
| AMPL (down) | ETH | Elastic supply | When price < target |
| BASED | ETH | Algorithmic | Deprecated |
| Demurrage tokens | Various | Time-based decay | |

---

## 4. Transfer Hooks (T-04)

**Behavior**: Token executes callback before/after transfer (ERC777 hooks).

**Impact**: Reentrancy attacks possible even with simple transfers.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: No reentrancy protection on ERC777
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    userBalance[msg.sender] += amount;
}

function withdraw(uint256 amount) external {
    require(userBalance[msg.sender] >= amount);
    userBalance[msg.sender] -= amount;
    token.transfer(msg.sender, amount);  // ERC777 hook can reenter deposit
}
```

### Secure Code
```solidity
// ✅ SECURE: Use reentrancy guard and CEI pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureVault is ReentrancyGuard {
    function withdraw(uint256 amount) external nonReentrant {
        require(userBalance[msg.sender] >= amount);
        
        // Effects before interactions
        userBalance[msg.sender] -= amount;
        
        // Interaction last
        token.transfer(msg.sender, amount);
    }
}
```

### Known Tokens with Hooks
| Token | Chain | Hook Type | Notes |
|-------|-------|-----------|-------|
| ERC777 tokens | ETH | tokensReceived/tokensToSend | Full ERC777 |
| imBTC | ETH | ERC777 | Caused $25M hack |
| Some bridged tokens | Multi | Custom hooks | |

### Detection
```solidity
// Check if token is ERC777
function isERC777(address token) view returns (bool) {
    try IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24)
        .getInterfaceImplementer(token, keccak256("ERC777Token")) returns (address impl) {
        return impl != address(0);
    } catch {
        return false;
    }
}
```

---

## 5. Blacklist/Whitelist Tokens (T-05, T-06)

**Behavior**: Certain addresses are blocked from sending or receiving tokens.

**Impact**: Transfers to/from blacklisted addresses revert.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Doesn't handle blacklist failures
function distributeRewards(address[] calldata users, uint256[] calldata amounts) external {
    for (uint i = 0; i < users.length; i++) {
        token.transfer(users[i], amounts[i]);  // Reverts if any user is blacklisted
    }
}
```

### Secure Code
```solidity
// ✅ SECURE: Handle potential blacklist failures
function distributeRewards(address[] calldata users, uint256[] calldata amounts) external {
    for (uint i = 0; i < users.length; i++) {
        try token.transfer(users[i], amounts[i]) {
            // Success
        } catch {
            // Store failed distribution for later claim
            pendingRewards[users[i]] += amounts[i];
            emit DistributionFailed(users[i], amounts[i]);
        }
    }
}
```

### Known Blacklistable Tokens
| Token | Chain | Admin | Notes |
|-------|-------|-------|-------|
| USDC | Multi | Centre | Can freeze accounts |
| USDT | Multi | Tether | Can freeze accounts |
| BUSD | Multi | Paxos | Can freeze accounts |
| PAXG | ETH | Paxos | Can freeze accounts |
| TUSD | Multi | TrustToken | Can freeze accounts |

### Considerations
- Liquidation may fail if borrower or liquidator is blacklisted
- Withdrawals may be locked if protocol address is blacklisted
- DAO governance may be blocked

---

## 6. Pausable Tokens (T-07)

**Behavior**: All transfers can be globally paused by admin.

**Impact**: Entire protocol may become non-functional during pause.

### Known Pausable Tokens
| Token | Chain | Admin | Notes |
|-------|-------|-------|-------|
| USDC | Multi | Centre | Emergency pause |
| BNB | BSC | Binance | |
| WBTC | Multi | BitGo | |
| Most bridged tokens | Multi | Bridge operators | |

### Risk Mitigation
```solidity
// Allow emergency withdrawal during pause
function emergencyWithdraw(IERC20[] calldata tokens) external onlyEmergency {
    for (uint i = 0; i < tokens.length; i++) {
        try tokens[i].transfer(treasury, tokens[i].balanceOf(address(this))) {
            // Success
        } catch {
            // Token may be paused, log and continue
            emit WithdrawalFailed(address(tokens[i]));
        }
    }
}
```

---

## 7. No Return Value (R-01)

**Behavior**: `transfer()` and `approve()` don't return a boolean.

**Impact**: Standard ERC20 interface calls revert.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Expects return value
function transferToken(address token, address to, uint256 amount) external {
    require(IERC20(token).transfer(to, amount), "Transfer failed");  // Reverts for USDT
}
```

### Secure Code
```solidity
// ✅ SECURE: Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

function transferToken(IERC20 token, address to, uint256 amount) external {
    token.safeTransfer(to, amount);  // Handles no-return tokens
}
```

### Known No-Return Tokens
| Token | Chain | Functions Affected |
|-------|-------|-------------------|
| USDT | ETH | transfer, approve |
| BNB | ETH | transfer |
| OMG | ETH | transfer |
| MKR | ETH | transfer, approve |
| ZRX | ETH | Old version |

---

## 8. Non-Zero to Non-Zero Approval Block (A-02)

**Behavior**: Cannot change non-zero allowance directly to another non-zero value.

**Impact**: Must set allowance to 0 first, then to new value.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Direct approval change
function setAllowance(address spender, uint256 amount) external {
    token.approve(spender, amount);  // Reverts if current allowance != 0
}
```

### Secure Code
```solidity
// ✅ SECURE: Reset to zero first
function setAllowance(IERC20 token, address spender, uint256 amount) external {
    token.safeApprove(spender, 0);  // Reset first
    token.safeApprove(spender, amount);  // Then set new value
}

// Or use forceApprove from OZ 5.x
token.forceApprove(spender, amount);
```

### Known Tokens with This Behavior
| Token | Chain | Notes |
|-------|-------|-------|
| USDT | ETH | Most famous example |
| KNC | ETH | Kyber Network |

---

## 9. Low Decimals (S-06)

**Behavior**: Token has fewer than 18 decimals (commonly 6 or 8).

**Impact**: Precision loss in calculations, especially divisions.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Precision loss with low decimals
function calculateShare(uint256 amount, uint256 totalSupply, uint256 myBalance) external view returns (uint256) {
    return (amount * myBalance) / totalSupply;  // May truncate to 0 for small amounts
}
```

### Secure Code
```solidity
// ✅ SECURE: Scale up for precision
uint256 constant PRECISION = 1e18;

function calculateShare(uint256 amount, uint256 totalSupply, uint256 myBalance) external view returns (uint256) {
    return (amount * myBalance * PRECISION) / totalSupply / PRECISION;
}

// Or better: scale to common base
function normalizeAmount(uint256 amount, uint8 tokenDecimals) internal pure returns (uint256) {
    if (tokenDecimals < 18) {
        return amount * (10 ** (18 - tokenDecimals));
    } else if (tokenDecimals > 18) {
        return amount / (10 ** (tokenDecimals - 18));
    }
    return amount;
}
```

### Common Low Decimal Tokens
| Token | Decimals | Chain |
|-------|----------|-------|
| USDC | 6 | Multi |
| USDT | 6 | Multi |
| WBTC | 8 | ETH |
| GUSD | 2 | ETH |

---

## 10. Large/High Decimals (S-07, S-10)

**Behavior**: Token has more than 18 decimals or extremely large total supply.

**Impact**: Overflow risks in multiplication, storage issues.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: May overflow with high decimals
function calculateValue(uint256 amount, uint256 price) external pure returns (uint256) {
    return amount * price;  // Overflow if amount and price are both large
}
```

### Secure Code
```solidity
// ✅ SECURE: Use mulDiv for large numbers
import "@openzeppelin/contracts/utils/math/Math.sol";

function calculateValue(uint256 amount, uint256 price, uint256 decimals) external pure returns (uint256) {
    return Math.mulDiv(amount, price, 10 ** decimals);
}
```

---

## 11. Flash Mintable Tokens (S-03)

**Behavior**: Tokens can be minted and burned in same transaction.

**Impact**: Total supply and balances can be manipulated within transaction.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: Uses balanceOf for voting power snapshot
function captureVotingPower() external {
    votingPower[msg.sender] = token.balanceOf(msg.sender);  // Can be manipulated with flash mint
}
```

### Known Flash Mintable Tokens
| Token | Chain | Notes |
|-------|-------|-------|
| DAI | ETH | Via DSR flash mint |
| Some yield tokens | Multi | Flash loan + stake |
| Protocol specific | Multi | Native flash mint |

---

## 12. Upgradeable Tokens (S-01)

**Behavior**: Token logic can be changed by admin.

**Impact**: Token behavior may change without notice, breaking integrations.

### Known Upgradeable Tokens
| Token | Chain | Proxy Type | Notes |
|-------|-------|------------|-------|
| USDC | Multi | Transparent proxy | Centre controls |
| USDT | ETH | Ad-hoc | Tether controls |
| Most bridged tokens | Multi | Various | Bridge operators |

### Considerations
- Token may add/remove features
- Fee structure may change
- Blacklist behavior may change
- Should monitor token governance

---

## 13. Revert on Zero Transfer (S-09)

**Behavior**: `transfer(addr, 0)` reverts instead of succeeding.

**Impact**: Loops that may transfer 0 will revert.

### Vulnerable Code
```solidity
// ❌ VULNERABLE: May revert on zero amount
function distributeProRata(address[] calldata users) external {
    uint256 totalRewards = getRewards();
    for (uint i = 0; i < users.length; i++) {
        uint256 share = (totalRewards * balances[users[i]]) / totalBalance;
        token.transfer(users[i], share);  // Reverts if share rounds to 0
    }
}
```

### Secure Code
```solidity
// ✅ SECURE: Skip zero transfers
function distributeProRata(address[] calldata users) external {
    uint256 totalRewards = getRewards();
    for (uint i = 0; i < users.length; i++) {
        uint256 share = (totalRewards * balances[users[i]]) / totalBalance;
        if (share > 0) {
            token.safeTransfer(users[i], share);
        }
    }
}
```

### Known Tokens
| Token | Chain | Notes |
|-------|-------|-------|
| LEND (old Aave) | ETH | |
| Some wrapped tokens | Multi | |

---

## Master Compatibility Matrix

| Token | Fee | Rebase | Hooks | Blacklist | Pause | NoReturn | Approval | LowDec | Upgradeable |
|-------|-----|--------|-------|-----------|-------|----------|----------|--------|-------------|
| USDT | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | Partial |
| USDC | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| DAI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| stETH | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SAFEMOON | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ERC777 | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| AMPL | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| WBTC | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅(8) | ❌ |

---

## Protocol-Specific Recommendations

### Lending Protocols
1. **Collateral**: Avoid rebasing tokens or use wrapped versions
2. **Liquidation**: Handle blacklist failures gracefully
3. **Interest**: Account for fee-on-transfer in repayments

### AMMs/DEXs
1. **Reserves**: Sync after each operation for rebasing tokens
2. **Fees**: Measure actual amounts received, not amounts sent
3. **Pairs**: Consider token compatibility before creating pairs

### Yield Aggregators
1. **Accounting**: Use shares, not absolute balances
2. **Harvest**: Account for any transfer fees
3. **Withdraw**: Handle partial failures gracefully

### Cross-Chain Bridges
1. **Verification**: Confirm token behavior on both chains
2. **Wrapped versions**: May have different behavior than original
3. **Admin keys**: Consider centralization risks
