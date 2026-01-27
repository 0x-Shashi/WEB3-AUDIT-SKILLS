# Security Best Practices

## Overview

These are the recommended security patterns extracted from auditor recommendations across thousands of findings.

## Core Security Patterns

### 1. Checks-Effects-Interactions (CEI)

**Always perform operations in this order:**

```solidity
function withdraw(uint256 amount) external {
    // 1. CHECKS
    require(balances[msg.sender] >= amount, "Insufficient");
    require(amount > 0, "Zero amount");
    
    // 2. EFFECTS
    balances[msg.sender] -= amount;
    totalDeposits -= amount;
    
    // 3. INTERACTIONS
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    emit Withdrawal(msg.sender, amount);
}
```

### 2. Use SafeERC20

**For all ERC20 operations:**

```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MyContract {
    using SafeERC20 for IERC20;
    
    function deposit(IERC20 token, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
    }
}
```

### 3. ReentrancyGuard

**On all state-changing external functions:**

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract MyContract is ReentrancyGuard {
    function sensitiveOperation() external nonReentrant {
        // Protected from reentrancy
    }
}
```

### 4. Access Control

**Use role-based access:**

```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract MyContract is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    function adminAction() external onlyRole(ADMIN_ROLE) {
        // Only admins
    }
    
    function operatorAction() external onlyRole(OPERATOR_ROLE) {
        // Only operators
    }
}
```

### 5. Two-Step Ownership Transfer

**For critical ownership changes:**

```solidity
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract MyContract is Ownable2Step {
    // Ownership transfer requires new owner to accept
}
```

### 6. Pausable Emergency Stop

**For emergency situations:**

```solidity
import "@openzeppelin/contracts/security/Pausable.sol";

contract MyContract is Pausable {
    function sensitiveOperation() external whenNotPaused {
        // Only when not paused
    }
    
    function pause() external onlyOwner {
        _pause();
    }
}
```

## Input Validation Best Practices

### Always Validate

```solidity
function setParameters(
    uint256 fee,
    address recipient,
    uint256 deadline
) external onlyOwner {
    // Validate all inputs
    require(fee <= MAX_FEE, "Fee too high");
    require(fee >= MIN_FEE, "Fee too low");
    require(recipient != address(0), "Zero address");
    require(deadline > block.timestamp, "Past deadline");
    
    protocolFee = fee;
    feeRecipient = recipient;
    operationDeadline = deadline;
}
```

### Handle Edge Cases

```solidity
function deposit(uint256 amount) external {
    require(amount > 0, "Zero deposit");
    require(amount >= MIN_DEPOSIT, "Below minimum");
    require(totalDeposits + amount <= MAX_CAPACITY, "Capacity exceeded");
    
    // Handle first deposit specially if needed
    if (totalDeposits == 0) {
        // First depositor logic
    }
}
```

## Oracle Best Practices

### Complete Oracle Validation

```solidity
function getPrice(address token) public view returns (uint256) {
    AggregatorV3Interface feed = priceFeeds[token];
    require(address(feed) != address(0), "No feed");
    
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = feed.latestRoundData();
    
    // All validation checks
    require(price > 0, "Invalid price");
    require(updatedAt > 0, "Round not complete");
    require(updatedAt > block.timestamp - STALENESS_PERIOD, "Stale price");
    require(answeredInRound >= roundId, "Stale round");
    
    // L2 sequencer check if applicable
    if (address(sequencerFeed) != address(0)) {
        (, int256 answer, uint256 startedAt,,) = sequencerFeed.latestRoundData();
        require(answer == 0, "Sequencer down");
        require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period");
    }
    
    return uint256(price);
}
```

## Flash Loan Protection

### Block Same-Block Operations

```solidity
mapping(address => uint256) public lastDepositBlock;

function deposit(uint256 amount) external {
    lastDepositBlock[msg.sender] = block.number;
    // Deposit logic
}

function withdraw(uint256 amount) external {
    require(block.number > lastDepositBlock[msg.sender], "Same block");
    // Withdrawal logic
}
```

## Slippage and Deadline Protection

### Always Include Both

```solidity
function swap(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,  // Slippage protection
    uint256 deadline       // Deadline protection
) external returns (uint256 amountOut) {
    require(block.timestamp <= deadline, "Transaction expired");
    
    amountOut = _executeSwap(tokenIn, tokenOut, amountIn);
    require(amountOut >= minAmountOut, "Slippage exceeded");
    
    return amountOut;
}
```

## Event Emission Best Practices

### Emit Events for State Changes

```solidity
event Deposited(address indexed user, uint256 amount, uint256 shares);
event Withdrawn(address indexed user, uint256 amount, uint256 shares);
event ParameterUpdated(string indexed param, uint256 oldValue, uint256 newValue);

function deposit(uint256 amount) external {
    uint256 shares = _calculateShares(amount);
    // State changes
    emit Deposited(msg.sender, amount, shares);
}
```

## Query Best Practices Examples

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "best practice recommendation mitigation",
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }'
```

## Security Checklist

### Before Deployment

- [ ] All inputs validated with appropriate bounds
- [ ] CEI pattern followed everywhere
- [ ] ReentrancyGuard on external state-changing functions
- [ ] SafeERC20 for all token operations
- [ ] Access control on admin functions
- [ ] Two-step ownership transfer
- [ ] Pausability for emergencies
- [ ] Oracle data fully validated
- [ ] Slippage and deadline on swaps
- [ ] Flash loan protection where needed
- [ ] Events emitted for all state changes
- [ ] No hardcoded addresses
- [ ] Proper error messages

## Cross-Reference

- For vulnerability patterns → See [common-patterns.md](common-patterns.md)
- For detailed vulnerabilities → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
