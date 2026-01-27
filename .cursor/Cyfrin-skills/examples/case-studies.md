# Security Case Studies

## Overview

In-depth analysis of notable security incidents and audit findings, examining root causes, attack mechanics, and lessons learned.

## Case Study 1: Reentrancy Evolution

### Classic DAO Hack (2016)

**The Attack:**
```solidity
// Vulnerable withdraw function
function withdraw() public {
    uint256 amount = balances[msg.sender];
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] = 0;  // Updated AFTER external call
}
```

**Attack Contract:**
```solidity
contract Attacker {
    DAO public dao;
    
    receive() external payable {
        if (address(dao).balance >= 1 ether) {
            dao.withdraw();  // Re-enter before balance updated
        }
    }
}
```

**Query Related Findings:**
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "tags": [{"value": "Reentrancy"}],
      "impact": ["HIGH"],
      "qualityScore": 5
    }
  }'
```

### Read-Only Reentrancy (Modern)

**Evolution of the attack:**
```solidity
// Protocol A: Lending
function getCollateralValue(address user) public view returns (uint256) {
    return curvePool.get_virtual_price() * userCollateral[user];
}

// Protocol B: Curve Pool (during remove_liquidity)
// get_virtual_price() returns stale value during callback
```

**Lesson:** Reentrancy isn't just about state changes—view functions can return stale data during reentrancy.

---

## Case Study 2: Oracle Manipulation Attacks

### Mango Markets ($110M, 2022)

**Attack Pattern:**
1. Open large perpetual position
2. Use spot market buys to pump the price oracle
3. Perp position now shows massive profit
4. Borrow against "profit" as collateral
5. Never repay—profit extracted

**Key Vulnerability:** Oracle used was too easily manipulated.

**Query Related Findings:**
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "tags": [{"value": "Price Manipulation"}, {"value": "Oracle"}],
      "impact": ["HIGH"]
    }
  }'
```

**Lessons:**
- TWAP oracles resist manipulation
- Consider cost of manipulation vs. profit
- Use multiple oracle sources

---

## Case Study 3: Bridge Exploits

### Wormhole ($320M, 2022)

**The Vulnerability:**
```solidity
// Simplified: Signature verification bypassed
function complete_transfer(bytes calldata vaa) external {
    // VAA (Verifiable Action Approval) verification
    // VULNERABLE: Verification could be bypassed
    _process_transfer(vaa);
}
```

**Attack:** Attacker forged a valid-looking VAA by exploiting a vulnerability in the Solana side of the verification.

**Query Related Findings:**
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "protocolCategory": [{"value": "Bridge"}],
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

**Lessons:**
- Bridges have massive attack surface
- Cross-chain verification is extremely complex
- Defense in depth: rate limits, pauses, monitoring

---

## Case Study 4: Flash Loan + Governance

### Beanstalk ($182M, 2022)

**Attack Pattern:**
1. Flash loan massive governance tokens
2. Create and vote on malicious proposal (immediate execution enabled)
3. Proposal drains treasury
4. Return governance tokens

**Key Vulnerability:** Governance allowed flash-loaned tokens for voting.

**Prevention Pattern:**
```solidity
// Secure: Use historical snapshots
function getVotes(address account, uint256 blockNumber) public view returns (uint256) {
    // Must hold tokens at snapshot block, not current block
    return _getPastVotes(account, blockNumber);
}

function propose() external {
    // Snapshot taken at proposal creation
    uint256 snapshot = block.number - 1;
}
```

**Query Related Findings:**
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "protocolCategory": [{"value": "Governance"}],
      "tags": [{"value": "Flash Loan"}],
      "impact": ["HIGH"]
    }
  }'
```

---

## Case Study 5: First Depositor Attack

### Euler ($197M, 2023)

**The Vulnerability:**
Share-based accounting can be manipulated when total supply is very low.

**Attack Simplified:**
```solidity
// Attacker:
1. Deposit 1 wei (get 1 share)
2. Donate large amount directly to contract
3. Share price now: largeAmount / 1 share
4. Next depositor: deposits X, gets X / largeAmount shares = 0 shares (rounded)
5. Attacker redeems their 1 share for everything
```

**Prevention:**
```solidity
function deposit(uint256 assets) external returns (uint256 shares) {
    if (totalSupply() == 0) {
        shares = assets - MINIMUM_SHARES;
        _mint(address(0), MINIMUM_SHARES);  // Lock minimum
    } else {
        shares = assets * totalSupply() / totalAssets();
    }
    _mint(msg.sender, shares);
}
```

**Query Related Findings:**
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "keywords": "first depositor donation share",
      "impact": ["HIGH"]
    }
  }'
```

---

## Key Takeaways

| Case | Root Cause | Prevention |
|------|------------|------------|
| DAO Hack | State update after external call | CEI pattern, ReentrancyGuard |
| Mango | Manipulable price oracle | TWAP, multiple sources |
| Wormhole | Signature verification bypass | Defense in depth, monitoring |
| Beanstalk | Flash loan voting | Snapshot-based voting |
| Euler | Share price manipulation | Minimum shares, virtual offset |

## How to Study Cases

For each case study:
1. Understand the normal operation
2. Identify what assumption was violated
3. Trace the exact attack path
4. Understand why prevention works
5. Query Solodit for similar patterns

## Cross-Reference

- For specific vulnerabilities → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For learning workflow → See [../workflows/vulnerability-learning.md](../workflows/vulnerability-learning.md)
