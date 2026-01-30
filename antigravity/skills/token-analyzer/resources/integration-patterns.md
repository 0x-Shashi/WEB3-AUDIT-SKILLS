# Safe Token Integration Patterns

This document provides secure code patterns for integrating with all types of ERC20 tokens, including weird/non-standard tokens.

---

## 1. Universal Safe Transfer Library

A comprehensive library that handles all edge cases:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title UniversalTokenHandler
 * @notice Safe token transfer handling for all ERC20 types including weird tokens
 */
library UniversalTokenHandler {
    using SafeERC20 for IERC20;
    
    error TransferFailed();
    error ZeroAddress();
    error InsufficientBalance();
    
    /**
     * @notice Transfer tokens from sender to recipient, accounting for fee-on-transfer
     * @param token The ERC20 token to transfer
     * @param from Source address
     * @param to Destination address  
     * @param amount Amount to transfer
     * @return received Actual amount received after any fees
     */
    function safeTransferFromWithBalance(
        IERC20 token,
        address from,
        address to,
        uint256 amount
    ) internal returns (uint256 received) {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) return 0;
        
        uint256 balanceBefore = token.balanceOf(to);
        token.safeTransferFrom(from, to, amount);
        received = token.balanceOf(to) - balanceBefore;
        
        if (received == 0) revert TransferFailed();
    }
    
    /**
     * @notice Transfer tokens to recipient, accounting for fee-on-transfer
     * @param token The ERC20 token to transfer
     * @param to Destination address
     * @param amount Amount to transfer
     * @return received Actual amount received after any fees
     */
    function safeTransferWithBalance(
        IERC20 token,
        address to,
        uint256 amount
    ) internal returns (uint256 received) {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) return 0;
        
        uint256 balanceBefore = token.balanceOf(to);
        token.safeTransfer(to, amount);
        received = token.balanceOf(to) - balanceBefore;
    }
    
    /**
     * @notice Safe approve that handles USDT-style tokens
     * @param token The ERC20 token to approve
     * @param spender Address to approve
     * @param amount Amount to approve
     */
    function forceApprove(
        IERC20 token,
        address spender,
        uint256 amount
    ) internal {
        // Try direct approval first (gas optimization)
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.approve.selector, spender, amount)
        );
        
        if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
            // If failed, try reset to 0 then approve
            token.safeApprove(spender, 0);
            token.safeApprove(spender, amount);
        }
    }
    
    /**
     * @notice Get token decimals safely, defaulting to 18 if not available
     * @param token The ERC20 token
     * @return decimals Token decimals (18 if call fails)
     */
    function safeDecimals(IERC20 token) internal view returns (uint8) {
        (bool success, bytes memory data) = address(token).staticcall(
            abi.encodeWithSignature("decimals()")
        );
        
        if (success && data.length >= 32) {
            return abi.decode(data, (uint8));
        }
        return 18; // Default to 18 decimals
    }
}
```

---

## 2. Fee-on-Transfer Safe Vault

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title FeeOnTransferVault
 * @notice Vault that correctly handles fee-on-transfer tokens
 */
contract FeeOnTransferVault is ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    IERC20 public immutable token;
    
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    
    event Deposit(address indexed user, uint256 amountIn, uint256 amountReceived);
    event Withdraw(address indexed user, uint256 amount);
    
    constructor(IERC20 _token) {
        token = _token;
    }
    
    /**
     * @notice Deposit tokens, accounting for fee-on-transfer
     * @param amount Amount to transfer (may receive less due to fees)
     * @return received Actual amount credited to user
     */
    function deposit(uint256 amount) external nonReentrant returns (uint256 received) {
        // Measure balance before transfer
        uint256 balanceBefore = token.balanceOf(address(this));
        
        // Transfer tokens
        token.safeTransferFrom(msg.sender, address(this), amount);
        
        // Calculate actual received amount
        received = token.balanceOf(address(this)) - balanceBefore;
        
        // Credit user with actual received amount
        balances[msg.sender] += received;
        totalDeposited += received;
        
        emit Deposit(msg.sender, amount, received);
    }
    
    /**
     * @notice Withdraw tokens
     * @param amount Amount to withdraw
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Effects before interactions (CEI pattern)
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
        
        // Interaction
        token.safeTransfer(msg.sender, amount);
        
        emit Withdraw(msg.sender, amount);
    }
}
```

---

## 3. Rebasing Token Vault with Shares

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title RebasingTokenVault
 * @notice Vault that correctly handles rebasing tokens using share accounting
 */
contract RebasingTokenVault is ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    IERC20 public immutable token;
    
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    
    uint256 private constant INITIAL_SHARES_PER_TOKEN = 1e18;
    
    event Deposit(address indexed user, uint256 assets, uint256 shares);
    event Withdraw(address indexed user, uint256 assets, uint256 shares);
    
    constructor(IERC20 _token) {
        token = _token;
    }
    
    /**
     * @notice Get total assets held by vault (current, may have rebased)
     */
    function totalAssets() public view returns (uint256) {
        return token.balanceOf(address(this));
    }
    
    /**
     * @notice Convert asset amount to shares
     * @param assets Amount of assets
     * @return Number of shares
     */
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets * INITIAL_SHARES_PER_TOKEN;
        }
        return (assets * supply) / totalAssets();
    }
    
    /**
     * @notice Convert shares to asset amount
     * @param _shares Number of shares
     * @return Amount of assets
     */
    function convertToAssets(uint256 _shares) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return _shares / INITIAL_SHARES_PER_TOKEN;
        }
        return (_shares * totalAssets()) / supply;
    }
    
    /**
     * @notice Get user's current asset balance (includes any rebases)
     * @param user User address
     * @return Current asset value
     */
    function balanceOf(address user) external view returns (uint256) {
        return convertToAssets(shares[user]);
    }
    
    /**
     * @notice Deposit assets and receive shares
     * @param assets Amount of assets to deposit
     * @return sharesReceived Number of shares minted
     */
    function deposit(uint256 assets) external nonReentrant returns (uint256 sharesReceived) {
        require(assets > 0, "Zero deposit");
        
        // Calculate shares before transfer (using current ratio)
        uint256 balanceBefore = token.balanceOf(address(this));
        
        // Transfer tokens
        token.safeTransferFrom(msg.sender, address(this), assets);
        
        // Calculate actual received (fee-on-transfer support)
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        
        // Calculate shares based on received amount
        if (totalShares == 0) {
            sharesReceived = received * INITIAL_SHARES_PER_TOKEN;
        } else {
            sharesReceived = (received * totalShares) / balanceBefore;
        }
        
        require(sharesReceived > 0, "Zero shares");
        
        shares[msg.sender] += sharesReceived;
        totalShares += sharesReceived;
        
        emit Deposit(msg.sender, received, sharesReceived);
    }
    
    /**
     * @notice Withdraw assets by burning shares
     * @param _shares Number of shares to burn
     * @return assets Amount of assets withdrawn
     */
    function withdraw(uint256 _shares) external nonReentrant returns (uint256 assets) {
        require(_shares > 0 && shares[msg.sender] >= _shares, "Invalid shares");
        
        // Calculate assets for shares
        assets = convertToAssets(_shares);
        
        // Effects
        shares[msg.sender] -= _shares;
        totalShares -= _shares;
        
        // Interaction
        token.safeTransfer(msg.sender, assets);
        
        emit Withdraw(msg.sender, assets, _shares);
    }
}
```

---

## 4. ERC777 Reentrancy Safe Pattern

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title ERC777SafeVault
 * @notice Vault pattern safe against ERC777 reentrancy attacks
 */
contract ERC777SafeVault is ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    IERC20 public immutable token;
    
    mapping(address => uint256) public balances;
    
    // ERC1820 Registry for ERC777 detection
    address constant ERC1820_REGISTRY = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
    bytes32 constant ERC777_TOKEN_INTERFACE_HASH = keccak256("ERC777Token");
    
    error ERC777NotSupported();
    
    constructor(IERC20 _token, bool allowERC777) {
        // Optionally block ERC777 tokens
        if (!allowERC777 && isERC777(address(_token))) {
            revert ERC777NotSupported();
        }
        token = _token;
    }
    
    /**
     * @notice Check if token is ERC777
     */
    function isERC777(address _token) public view returns (bool) {
        if (ERC1820_REGISTRY.code.length == 0) return false;
        
        (bool success, bytes memory data) = ERC1820_REGISTRY.staticcall(
            abi.encodeWithSignature(
                "getInterfaceImplementer(address,bytes32)",
                _token,
                ERC777_TOKEN_INTERFACE_HASH
            )
        );
        
        if (success && data.length >= 32) {
            address implementer = abi.decode(data, (address));
            return implementer != address(0);
        }
        return false;
    }
    
    /**
     * @notice Deposit - protected against reentrancy
     * Uses check-effects-interactions + nonReentrant
     */
    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0, "Zero amount");
        
        // Check
        uint256 balanceBefore = token.balanceOf(address(this));
        
        // Interaction (ERC777 hook can trigger here)
        token.safeTransferFrom(msg.sender, address(this), amount);
        
        // Effect (after interaction - can't reenter due to nonReentrant)
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        balances[msg.sender] += received;
    }
    
    /**
     * @notice Withdraw - CEI pattern with nonReentrant
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        
        // Effects BEFORE interactions
        balances[msg.sender] -= amount;
        
        // Interaction last (ERC777 hook can trigger here, but state already updated)
        token.safeTransfer(msg.sender, amount);
    }
}
```

---

## 5. Blacklist-Resilient Distribution

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title ResilientDistributor
 * @notice Token distributor that handles blacklisted recipients gracefully
 */
contract ResilientDistributor {
    using SafeERC20 for IERC20;
    
    IERC20 public immutable token;
    
    // Pending claims for failed distributions
    mapping(address => uint256) public pendingClaims;
    
    event DistributionSuccess(address indexed recipient, uint256 amount);
    event DistributionFailed(address indexed recipient, uint256 amount);
    event Claimed(address indexed recipient, uint256 amount);
    
    constructor(IERC20 _token) {
        token = _token;
    }
    
    /**
     * @notice Distribute tokens to multiple recipients
     * @dev Continues even if some transfers fail (blacklisted recipients)
     */
    function distribute(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        require(recipients.length == amounts.length, "Length mismatch");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            if (amounts[i] == 0) continue;
            
            // Try to transfer, store in pending if fails
            bool success = _tryTransfer(recipients[i], amounts[i]);
            
            if (success) {
                emit DistributionSuccess(recipients[i], amounts[i]);
            } else {
                pendingClaims[recipients[i]] += amounts[i];
                emit DistributionFailed(recipients[i], amounts[i]);
            }
        }
    }
    
    /**
     * @notice Claim pending tokens
     * @dev For users who were previously blacklisted but are now cleared
     */
    function claim() external {
        uint256 amount = pendingClaims[msg.sender];
        require(amount > 0, "Nothing to claim");
        
        pendingClaims[msg.sender] = 0;
        
        // This may still fail if still blacklisted
        token.safeTransfer(msg.sender, amount);
        
        emit Claimed(msg.sender, amount);
    }
    
    /**
     * @notice Try to transfer, return success status
     */
    function _tryTransfer(address to, uint256 amount) internal returns (bool) {
        try token.transfer(to, amount) returns (bool success) {
            return success;
        } catch {
            return false;
        }
    }
}
```

---

## 6. Low Decimal Precision Handler

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title PrecisionHandler
 * @notice Safe math for tokens with varying decimals
 */
library PrecisionHandler {
    using Math for uint256;
    
    uint256 constant PRECISION = 1e18;
    
    /**
     * @notice Normalize amount to 18 decimals
     * @param amount Raw token amount
     * @param decimals Token decimals
     * @return Normalized amount (18 decimals)
     */
    function normalize(uint256 amount, uint8 decimals) internal pure returns (uint256) {
        if (decimals < 18) {
            return amount * (10 ** (18 - decimals));
        } else if (decimals > 18) {
            return amount / (10 ** (decimals - 18));
        }
        return amount;
    }
    
    /**
     * @notice Denormalize from 18 decimals to token decimals
     * @param amount Normalized amount (18 decimals)
     * @param decimals Token decimals
     * @return Raw token amount
     */
    function denormalize(uint256 amount, uint8 decimals) internal pure returns (uint256) {
        if (decimals < 18) {
            return amount / (10 ** (18 - decimals));
        } else if (decimals > 18) {
            return amount * (10 ** (decimals - 18));
        }
        return amount;
    }
    
    /**
     * @notice Safe percentage calculation with precision
     * @param amount Base amount
     * @param bps Basis points (1 bps = 0.01%)
     * @return Result with proper rounding
     */
    function bpsMul(uint256 amount, uint256 bps) internal pure returns (uint256) {
        return amount.mulDiv(bps, 10000);
    }
    
    /**
     * @notice Safe division with precision scaling
     * @param a Numerator
     * @param b Denominator
     * @param decimals Result precision
     * @return Scaled result
     */
    function divPrecise(
        uint256 a, 
        uint256 b, 
        uint8 decimals
    ) internal pure returns (uint256) {
        return a.mulDiv(10 ** decimals, b);
    }
}

/**
 * @title MultiDecimalPool
 * @notice Pool that handles tokens with different decimals
 */
contract MultiDecimalPool {
    using PrecisionHandler for uint256;
    
    struct TokenInfo {
        IERC20 token;
        uint8 decimals;
        uint256 normalizedBalance; // Stored in 18 decimals
    }
    
    mapping(address => TokenInfo) public tokens;
    
    /**
     * @notice Register token with its decimals
     */
    function registerToken(address _token) external {
        uint8 decimals = IERC20Metadata(_token).decimals();
        tokens[_token] = TokenInfo({
            token: IERC20(_token),
            decimals: decimals,
            normalizedBalance: 0
        });
    }
    
    /**
     * @notice Get normalized value for cross-token calculations
     */
    function getNormalizedValue(
        address _token, 
        uint256 rawAmount
    ) external view returns (uint256) {
        return rawAmount.normalize(tokens[_token].decimals);
    }
    
    /**
     * @notice Convert between tokens accounting for decimals
     */
    function convertAmount(
        address fromToken,
        address toToken,
        uint256 amount
    ) external view returns (uint256) {
        // Normalize from source decimals
        uint256 normalized = amount.normalize(tokens[fromToken].decimals);
        
        // Denormalize to target decimals
        return normalized.denormalize(tokens[toToken].decimals);
    }
}
```

---

## 7. Complete Token Validation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title TokenValidator
 * @notice Validate token behavior before integration
 */
contract TokenValidator {
    
    struct TokenProperties {
        bool hasTransfer;
        bool hasBalanceOf;
        bool hasDecimals;
        bool hasTotalSupply;
        bool transferReturnsValue;
        bool approveReturnsValue;
        uint8 decimals;
        uint256 totalSupply;
    }
    
    /**
     * @notice Validate basic ERC20 interface implementation
     */
    function validateBasicERC20(address token) external view returns (TokenProperties memory props) {
        // Check balanceOf
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSelector(IERC20.balanceOf.selector, address(this))
        );
        props.hasBalanceOf = success && data.length >= 32;
        
        // Check totalSupply
        (success, data) = token.staticcall(
            abi.encodeWithSelector(IERC20.totalSupply.selector)
        );
        props.hasTotalSupply = success && data.length >= 32;
        if (props.hasTotalSupply) {
            props.totalSupply = abi.decode(data, (uint256));
        }
        
        // Check decimals
        (success, data) = token.staticcall(
            abi.encodeWithSignature("decimals()")
        );
        props.hasDecimals = success && data.length >= 32;
        if (props.hasDecimals) {
            props.decimals = abi.decode(data, (uint8));
        } else {
            props.decimals = 18; // Assume 18 if missing
        }
        
        return props;
    }
    
    /**
     * @notice Test token transfer behavior (requires holding tokens)
     * @dev Should be called in a test environment
     */
    function testTransferBehavior(
        IERC20 token,
        address from,
        address to,
        uint256 amount
    ) external returns (
        bool feeOnTransfer,
        uint256 feeAmount,
        bool revertsOnZero
    ) {
        // Test for fee-on-transfer
        uint256 balanceBefore = token.balanceOf(to);
        token.transferFrom(from, to, amount);
        uint256 received = token.balanceOf(to) - balanceBefore;
        
        feeOnTransfer = received < amount;
        feeAmount = amount - received;
        
        // Test zero transfer
        try token.transfer(to, 0) {
            revertsOnZero = false;
        } catch {
            revertsOnZero = true;
        }
    }
}
```

---

## 8. Pausable Token Handler

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title PausableTokenHandler
 * @notice Handle tokens that can be paused
 */
contract PausableTokenHandler {
    using SafeERC20 for IERC20;
    
    mapping(address => bool) public tokenPaused;
    mapping(address => mapping(address => uint256)) public pendingWithdrawals;
    
    event WithdrawalQueued(address indexed user, address indexed token, uint256 amount);
    event WithdrawalExecuted(address indexed user, address indexed token, uint256 amount);
    
    /**
     * @notice Withdraw with pause handling
     * @dev If token is paused, queues withdrawal for later
     */
    function safeWithdraw(
        IERC20 token,
        address to,
        uint256 amount
    ) external returns (bool immediate) {
        try token.transfer(to, amount) {
            emit WithdrawalExecuted(to, address(token), amount);
            return true;
        } catch {
            // Token may be paused, queue for later
            pendingWithdrawals[to][address(token)] += amount;
            emit WithdrawalQueued(to, address(token), amount);
            return false;
        }
    }
    
    /**
     * @notice Retry queued withdrawal
     */
    function retryWithdrawal(IERC20 token) external {
        uint256 amount = pendingWithdrawals[msg.sender][address(token)];
        require(amount > 0, "No pending withdrawal");
        
        pendingWithdrawals[msg.sender][address(token)] = 0;
        token.safeTransfer(msg.sender, amount);
        
        emit WithdrawalExecuted(msg.sender, address(token), amount);
    }
}
```

---

## Best Practices Summary

### Always Do

1. **Use SafeERC20** for all token interactions
2. **Measure actual received amounts** for deposits
3. **Use shares** for rebasing token accounting  
4. **Apply reentrancy guards** for all external calls
5. **Follow CEI pattern** (Check-Effects-Interactions)
6. **Handle zero amount** transfers explicitly
7. **Normalize decimals** for cross-token calculations

### Never Do

1. **Trust amount parameter** equals amount received
2. **Cache balanceOf** for rebasing tokens
3. **Assume approve** returns bool
4. **Direct approve** non-zero to non-zero (USDT)
5. **Batch without try-catch** for blacklistable tokens
6. **Multiply before divide** with low decimals
7. **Integrate without testing** token behavior

