# Security Auditor Learning Path & Attack Vectors

> **AI Skill**: This file provides a structured curriculum for learning smart contract security and a comprehensive attack vector reference. Based on Cyfrin's Security & Auditing Course.

## Learning Path Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Fundamentals (2-4 weeks)                              │
│  • Solidity basics, EVM, storage, encoding                      │
│  • Foundry tooling, fuzzing basics                              │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2: First Audits (2-4 weeks)                              │
│  • PasswordStore: Access control, private data                  │
│  • Puppy Raffle: Reentrancy, DoS, RNG, arithmetic              │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3: DeFi & Invariants (4-6 weeks)                         │
│  • T-Swap: AMMs, invariants, stateful fuzzing                   │
│  • Thunder Loan: Flash loans, oracles, proxies                  │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 4: Advanced (4-6 weeks)                                  │
│  • Boss Bridge: Signatures, L2, assembly                        │
│  • Vault Guardians: MEV, governance, complex systems            │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 5: Professional Practice (Ongoing)                       │
│  • Competitive audits, bug bounties, private audits             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Attack Vector Reference

### Top Attack Vectors (2025)

Based on real-world exploit data:

| Rank | Attack Vector | Prevalence | Typical Severity |
|------|--------------|------------|------------------|
| 1 | Access Control | Very High | Critical-High |
| 2 | Price/Oracle Manipulation | High | Critical-High |
| 3 | Reentrancy | High | High-Critical |
| 4 | Logic Errors | High | High-Medium |
| 5 | Input Validation | Medium-High | High-Medium |
| 6 | Arithmetic Issues | Medium | High-Medium |
| 7 | Weak Randomness | Medium | Medium-High |
| 8 | Centralization | Medium | Medium-High |
| 9 | Signature Replay | Medium | High |
| 10 | MEV/Frontrunning | Medium | Medium-High |

---

## Detailed Attack Patterns

### 1. Access Control Vulnerabilities

**Types**:
- Missing access modifiers (`onlyOwner`, `onlyRole`)
- Unprotected sensitive functions
- Role misconfiguration
- Privilege escalation

**Detection Pattern**:
```solidity
// LOOK FOR: Public/external functions without access checks
function setAdmin(address newAdmin) external {  // Missing onlyOwner!
    admin = newAdmin;
}

// LOOK FOR: Incorrect modifier application
function withdraw() external onlyUser {  // Should be onlyOwner?
    payable(owner).transfer(address(this).balance);
}
```

**Audit Prompt**:
```
Analyze access control in this contract:
1. List all state-changing functions
2. Identify which have access modifiers
3. Check if modifiers are appropriate for function sensitivity
4. Look for privilege escalation paths
```

---

### 2. Private Data Exposure

**Vulnerability**: Storing secrets in "private" variables (all storage is readable on-chain).

**Detection Pattern**:
```solidity
// VULNERABLE: "Private" doesn't mean hidden
string private s_password;  // Readable via eth_getStorageAt!
bytes32 private secretKey;  // Can be extracted from storage

function setPassword(string memory password) external {
    s_password = password;
}
```

**Attack**:
```javascript
// Read "private" storage slot
const password = await ethers.provider.getStorageAt(contractAddress, 1);
```

**Audit Prompt**:
```
Check this contract for private data exposure:
1. Identify all private/internal state variables
2. Determine if any contain sensitive data
3. Verify sensitive data is properly encrypted before storage
4. Check if any function parameters expose secrets in calldata
```

---

### 3. Reentrancy Attacks

**Famous Case**: The DAO Hack (2016) - $60M stolen

**Types**:
- Single-function reentrancy
- Cross-function reentrancy
- Cross-contract reentrancy
- Read-only reentrancy

**Detection Pattern**:
```solidity
// VULNERABLE: External call before state update
function withdraw() external {
    uint256 balance = balances[msg.sender];
    (bool success,) = msg.sender.call{value: balance}("");  // External call
    require(success);
    balances[msg.sender] = 0;  // State update AFTER call!
}

// SECURE: Checks-Effects-Interactions (CEI)
function withdraw() external {
    uint256 balance = balances[msg.sender];
    balances[msg.sender] = 0;  // State update FIRST
    (bool success,) = msg.sender.call{value: balance}("");  // External call LAST
    require(success);
}
```

**Modern Reentrancy (ERC777/Hooks)**:
```solidity
// VULNERABLE: ERC777 token callback before state update
function deposit(uint256 amount) external {
    token.safeTransferFrom(msg.sender, address(this), amount);  // Has callback!
    balances[msg.sender] += amount;  // Updated after callback
}
```

**Prevention**:
- CEI (Checks-Effects-Interactions) pattern
- CEII (Checks-Effects-Interactions-Interactions)
- FREI-PI pattern
- ReentrancyGuard modifier

---

### 4. Weak Randomness

**Famous Case**: Meebits NFT exploit

**Vulnerability**: Using on-chain data for randomness.

**Predictable Sources**:
```solidity
// ALL OF THESE ARE PREDICTABLE:
block.timestamp      // Miner can manipulate
block.number         // Known in advance
block.prevrandao     // Known before block (limited manipulation)
blockhash(block.number - 1)  // Known
tx.origin           // Known
msg.sender          // Known
```

**Detection Pattern**:
```solidity
// VULNERABLE: Predictable randomness
function selectWinner() external {
    uint256 winnerIndex = uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.prevrandao,
        msg.sender
    ))) % players.length;
    // Attacker can predict and manipulate
}
```

**Secure Alternative**: Chainlink VRF

---

### 5. Arithmetic Issues

**Types**:
- Integer overflow/underflow (pre-0.8.0)
- Rounding errors
- Precision loss
- Division by zero

**Detection Patterns**:
```solidity
// VULNERABLE: Divide before multiply (precision loss)
uint256 result = (amount / totalShares) * price;  // Wrong order!
// FIX: Multiply first
uint256 result = (amount * price) / totalShares;

// VULNERABLE: Unchecked overflow in 0.8+
unchecked {
    uint256 newBalance = balance + amount;  // Can overflow!
}

// VULNERABLE: Division truncation
uint256 feePercent = 3;
uint256 fee = amount * feePercent / 100;  // Truncates for small amounts
```

---

### 6. DoS (Denial of Service)

**Types**:
- Block gas limit (unbounded loops)
- External call failures
- Unexpected reverts
- Griefing

**Detection Pattern**:
```solidity
// VULNERABLE: Unbounded loop
function refundAll() external {
    for (uint256 i = 0; i < participants.length; i++) {  // Can exceed gas limit
        payable(participants[i]).transfer(amounts[i]);
    }
}

// VULNERABLE: Single failure breaks all
function distribute() external {
    for (uint256 i = 0; i < recipients.length; i++) {
        require(token.transfer(recipients[i], amounts[i]));  // One failure = all fail
    }
}
```

**Prevention**:
- Pagination / batching
- Pull over push pattern
- Try/catch for external calls

---

### 7. Oracle & Price Manipulation

**Famous Cases**: Alpha Homora, Cream Finance

**Vulnerability**: Using spot prices or manipulable price sources.

**Detection Pattern**:
```solidity
// VULNERABLE: AMM spot price (flash loan manipulable)
function getPrice() public view returns (uint256) {
    (uint256 reserve0, uint256 reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // Spot price!
}

// VULNERABLE: Single oracle without staleness check
function getPrice() public view returns (uint256) {
    return oracle.latestAnswer();  // No staleness check!
}
```

**Secure Pattern**:
```solidity
function getPrice() public view returns (uint256) {
    (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = oracle.latestRoundData();
    
    require(updatedAt > block.timestamp - MAX_STALENESS, "Stale price");
    require(answer > 0, "Invalid price");
    require(answeredInRound >= roundId, "Stale round");
    
    return uint256(answer);
}
```

---

### 8. Signature Replay

**Types**:
- Cross-chain replay
- Cross-contract replay
- Nonce reuse

**Detection Pattern**:
```solidity
// VULNERABLE: No nonce, no chain ID, no contract address
function executeWithSig(
    address to,
    uint256 amount,
    bytes memory signature
) external {
    bytes32 hash = keccak256(abi.encode(to, amount));
    address signer = hash.recover(signature);
    // Same sig works on multiple chains/contracts!
}

// SECURE: Include nonce, chain ID, contract address
function executeWithSig(
    address to,
    uint256 amount,
    uint256 nonce,
    bytes memory signature
) external {
    require(nonces[msg.sender] == nonce, "Invalid nonce");
    nonces[msg.sender]++;
    
    bytes32 hash = keccak256(abi.encode(
        block.chainid,
        address(this),
        to,
        amount,
        nonce
    ));
    // Use EIP-712 for even better security
}
```

---

### 9. Proxy & Upgrade Issues

**Types**:
- Uninitialized proxy
- Storage collision
- Function selector collision
- Silent/malicious upgrade

**Detection Patterns**:
```solidity
// VULNERABLE: No initializer protection
function initialize(address owner) public {
    _owner = owner;  // Can be called multiple times!
}

// SECURE: Use initializer modifier
function initialize(address owner) public initializer {
    _owner = owner;
}

// STORAGE COLLISION: Different storage layouts
// Implementation v1:
uint256 public value;  // slot 0

// Implementation v2:
address public newOwner;  // slot 0 - collides with value!
uint256 public value;     // slot 1 - wrong slot!
```

**Case Study**: Parity Wallet - "I accidentally killed it" ($280M frozen)

---

### 10. MEV (Maximal Extractable Value)

**Types**:
- Frontrunning (sandwich attacks)
- Backrunning (arbitrage)
- Liquidation racing

**Vulnerable Operations**:
- DEX swaps without slippage protection
- NFT mints with predictable outcomes
- Auction bids
- Large liquidations

**Detection Pattern**:
```solidity
// VULNERABLE: No slippage protection
function swap(address tokenIn, uint256 amountIn, address tokenOut) external {
    uint256 amountOut = calculateOutput(amountIn);
    // No minimum output specified - sandwich attack!
}

// SECURE: Slippage protection
function swap(
    address tokenIn,
    uint256 amountIn,
    address tokenOut,
    uint256 minAmountOut  // Slippage protection
) external {
    uint256 amountOut = calculateOutput(amountIn);
    require(amountOut >= minAmountOut, "Slippage too high");
}
```

---

## Finding Report Template

```markdown
### [S-#] Title (Root Cause + Impact)

**Description:** 
Explain the vulnerability mechanism clearly.

**Impact:** 
- Severity: Critical/High/Medium/Low
- Who is affected
- Financial impact estimate

**Proof of Concept:**
```solidity
function testVulnerability() public {
    // Setup
    // Attack steps
    // Verify impact
}
```

**Recommended Mitigation:** 
Specific code changes with examples.
```

---

## Audit Workflow Phases

### Phase 1: Scoping
- Review documentation
- Understand protocol purpose
- Count SLOC (`cloc`)
- Identify external dependencies
- Define what's in/out of scope

### Phase 2: Reconnaissance
- Read code top-to-bottom
- Note questions and hypotheses
- Identify protocol invariants
- Map out function call graph
- Understand token flows

### Phase 3: Vulnerability Identification
- Manual review (line by line)
- Static analysis (Slither, Aderyn)
- Fuzz testing
- Invariant testing
- Cross-reference attack vectors

### Phase 4: Reporting
- Write clear findings
- Include PoC code
- Provide specific mitigations
- Classify severity accurately

---

## Essential Tools

| Tool | Purpose | Link |
|------|---------|------|
| Foundry | Testing, fuzzing | getfoundry.sh |
| Slither | Static analysis | github.com/crytic/slither |
| Aderyn | Rust-based static analysis | github.com/Cyfrin/aderyn |
| Echidna | Fuzzing | github.com/crytic/echidna |
| Certora | Formal verification | certora.com |
| Tenderly | Debugging, simulation | tenderly.co |
| Solodit | Finding database | solodit.xyz |

---

## Career Paths

1. **Competitive Audits**: CodeHawks, Code4rena, Sherlock
2. **Bug Bounties**: Immunefi, HackerOne, Hats Finance
3. **Private Audits**: Cyfrin, Trail of Bits, OpenZeppelin
4. **Independent Researcher**: Solo auditing practice
5. **Protocol Security**: In-house security teams

---

## Resources

### Learning
- [Cyfrin Updraft](https://updraft.cyfrin.io/)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)
- [Ethernaut](https://ethernaut.openzeppelin.com/)

### Research
- [Solodit](https://solodit.xyz/) - Finding database
- [Rekt News](https://rekt.news/) - Exploit analysis
- [DeFi Llama](https://defillama.com/) - Protocol data

### Community
- CodeHawks Discord
- Ethereum Security Telegram
- Security Twitter

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - Pattern details
- [defi-vulnerabilities.md](defi-vulnerabilities.md) - DeFi-specific patterns
- [comprehensive-checklist.md](../checklists/comprehensive-checklist.md) - Audit checklist
- [llm-audit-workflow.md](../methodology/llm-audit-workflow.md) - LLM audit prompts

