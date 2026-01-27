# Common Vulnerability Patterns

## Overview

These are the most frequently occurring vulnerability patterns across all audits. Knowing these patterns helps prevent the majority of security issues.

## Query: Most Common Patterns

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }' | jq '[.findings[].issues_issuetagscore[]?.tags_tag.title] | group_by(.) | map({pattern: .[0], count: length}) | sort_by(-.count) | .[0:20]'
```

## Pattern 1: Missing Input Validation

**Frequency:** Very High  
**Typical Impact:** MEDIUM to HIGH

```solidity
// VULNERABLE
function setFee(uint256 newFee) external onlyOwner {
    fee = newFee;  // No bounds check
}

// SECURE
function setFee(uint256 newFee) external onlyOwner {
    require(newFee <= MAX_FEE, "Fee too high");
    require(newFee >= MIN_FEE, "Fee too low");
    fee = newFee;
}
```

**Query:**
```bash
curl -X POST ... -d '{"filters": {"keywords": "validation bounds check", "impact": ["HIGH", "MEDIUM"]}}'
```

## Pattern 2: Unchecked Return Values

**Frequency:** High  
**Typical Impact:** MEDIUM

```solidity
// VULNERABLE
function transfer(address token, address to, uint256 amount) external {
    IERC20(token).transfer(to, amount);  // Unchecked
}

// SECURE
function transfer(address token, address to, uint256 amount) external {
    require(IERC20(token).transfer(to, amount), "Transfer failed");
    // Or use SafeERC20
    IERC20(token).safeTransfer(to, amount);
}
```

## Pattern 3: Centralization Risks

**Frequency:** Very High  
**Typical Impact:** MEDIUM (informational in some cases)

```solidity
// RISKY
function emergencyWithdraw() external onlyOwner {
    // Owner can drain all funds at any time
    payable(owner).transfer(address(this).balance);
}

// BETTER
function emergencyWithdraw() external onlyOwner {
    require(paused, "Only when paused");
    // Add timelock, multisig, or governance
}
```

## Pattern 4: Front-Running Vulnerabilities

**Frequency:** High  
**Typical Impact:** MEDIUM to HIGH

```solidity
// VULNERABLE
function swap(uint256 amountIn) external returns (uint256) {
    // No slippage or deadline
    return _executeSwap(amountIn);
}

// SECURE
function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external returns (uint256) {
    require(block.timestamp <= deadline, "Expired");
    uint256 amountOut = _executeSwap(amountIn);
    require(amountOut >= minAmountOut, "Slippage");
    return amountOut;
}
```

## Pattern 5: Integer Overflow/Underflow

**Frequency:** Medium (less since Solidity 0.8)  
**Typical Impact:** HIGH when occurs

```solidity
// VULNERABLE (pre-0.8)
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // Can overflow
}

// SECURE (Solidity 0.8+ or SafeMath)
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // Auto-reverts on overflow in 0.8+
}
```

## Pattern 6: Reentrancy

**Frequency:** Medium  
**Typical Impact:** HIGH

```solidity
// VULNERABLE
function withdraw() external {
    (bool success,) = msg.sender.call{value: balances[msg.sender]}("");
    balances[msg.sender] = 0;  // After external call
}

// SECURE (CEI)
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;  // Before external call
    (bool success,) = msg.sender.call{value: amount}("");
}
```

## Pattern 7: Oracle Misuse

**Frequency:** Medium  
**Typical Impact:** HIGH

```solidity
// VULNERABLE
function getPrice() public view returns (uint256) {
    (, int256 price,,,) = oracle.latestRoundData();
    return uint256(price);  // No validation
}

// SECURE
function getPrice() public view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = oracle.latestRoundData();
    
    require(price > 0, "Invalid price");
    require(updatedAt > block.timestamp - 1 hours, "Stale");
    require(answeredInRound >= roundId, "Incomplete round");
    
    return uint256(price);
}
```

## Pattern 8: Access Control Gaps

**Frequency:** High  
**Typical Impact:** MEDIUM to HIGH

```solidity
// VULNERABLE
function setAdmin(address newAdmin) external {
    admin = newAdmin;  // Anyone can call
}

// SECURE
function setAdmin(address newAdmin) external onlyAdmin {
    require(newAdmin != address(0), "Zero address");
    admin = newAdmin;
}
```

## Quick Reference Table

| Pattern | Prevalence | Impact | Prevention |
|---------|------------|--------|------------|
| Missing validation | Very High | M-H | Always validate inputs |
| Unchecked returns | High | M | Use SafeERC20 |
| Centralization | Very High | M | Multi-sig, timelocks |
| Front-running | High | M-H | Slippage, deadlines |
| Overflow | Medium | H | Solidity 0.8+ |
| Reentrancy | Medium | H | CEI, ReentrancyGuard |
| Oracle misuse | Medium | H | Full validation |
| Access control | High | M-H | Modifiers, roles |

## Cross-Reference

- For detailed vulnerability patterns → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For best practices → See [best-practices.md](best-practices.md)
