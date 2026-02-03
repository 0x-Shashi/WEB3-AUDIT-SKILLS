# Sanitization Rules for Community Contributions

## Overview

All community contributions must be sanitized to protect client confidentiality, prevent exploitation, and focus on the educational value of the vulnerability pattern.

---

## Categories of Information

### MUST REMOVE (Never Include)

| Category | Examples | Reason |
|----------|----------|--------|
| Protocol Names | "Aave", "Compound", "UniswapV3" | Client confidentiality |
| Contract Addresses | "0x1234...", "0xdead..." | Identifiable |
| Developer Names | "John Doe", "@dev_handle" | Privacy |
| Client Information | Company names, engagement details | Confidentiality |
| Transaction Hashes | "0xabc123..." | Traceable |
| Block Numbers | "Block 18500000" | Traceable |
| Private Keys/Seeds | Any cryptographic secrets | Security |
| Internal Communications | Slack messages, emails | Confidentiality |
| Audit Report References | "As noted in our Q3 report..." | Confidentiality |
| Bounty/Payment Details | "$50,000 bounty", "Severity: Critical" | Privacy |

### MUST ANONYMIZE (Replace with Generic)

| Original | Replacement | Example |
|----------|-------------|---------|
| Protocol name | "Protocol X", "Target Protocol" | "Compound" → "Protocol X" |
| Contract name | "VulnerableContract", "TargetVault" | "AavePool" → "LendingPool" |
| Token names | "TokenA", "TokenB", "RewardToken" | "AAVE" → "TokenA" |
| Function names (unique) | Generic equivalent | "claimAaveRewards" → "claimRewards" |
| Variable names (unique) | Generic equivalent | "aaveOracle" → "priceOracle" |
| Event names (unique) | Generic equivalent | "AaveDeposit" → "Deposit" |
| Error names (unique) | Generic equivalent | "AaveError" → "CustomError" |
| Admin roles (named) | "ADMIN_ROLE", "OWNER" | "AAVE_ADMIN" → "ADMIN_ROLE" |

### CAN KEEP (Safe to Include)

| Category | Examples | Reason |
|----------|----------|--------|
| Standard interfaces | ERC20, ERC721, ERC4626 | Public standards |
| Common libraries | OpenZeppelin, Solmate | Public code |
| Generic patterns | CEI, pull-over-push | Educational |
| Solidity keywords | require, revert, modifier | Language features |
| Common function names | transfer, approve, mint | Standard naming |
| Chain names | Ethereum, Arbitrum, Optimism | Public information |
| Public exploit references | "Similar to Euler exploit" | Public knowledge |
| Academic/research refs | "As described in paper X" | Public knowledge |

---

## Sanitization Process

### Step 1: Identify Sensitive Content

Read through your contribution and highlight:
- [ ] All protocol/project names
- [ ] All addresses
- [ ] All person names
- [ ] All unique identifiers
- [ ] All specific values that could identify the source

### Step 2: Apply Replacements

Use find-and-replace with consistent naming:

```
Original              →  Replacement
ProtocolName          →  Protocol X
ProtocolNameToken     →  TokenA
ProtocolNameVault     →  TargetVault
ProtocolNameOracle    →  PriceOracle
specificFunctionName  →  genericFunction
0x1234...5678        →  [REMOVED]
```

### Step 3: Verify Code Compiles

After sanitization, verify:
- [ ] Code examples still compile (conceptually)
- [ ] Logic is preserved
- [ ] Vulnerability is still demonstrable
- [ ] Fix still works

### Step 4: Review for Leaks

Final check for any remaining identifying information:
- [ ] No protocol names in comments
- [ ] No addresses in any form
- [ ] No URLs to specific deployments
- [ ] No references to specific audits
- [ ] No time-specific references that could identify

---

## Sanitization Examples

### Example 1: Contract Code

**Before (DO NOT SUBMIT):**
```solidity
// AavePool.sol - Vulnerable to reentrancy
contract AavePool {
    mapping(address => uint256) public aaveBalances;
    IERC20 public aaveToken;
    
    function withdrawFromAave(uint256 amount) external {
        require(aaveBalances[msg.sender] >= amount, "AaveError: Insufficient");
        aaveToken.transfer(msg.sender, amount);  // External call first
        aaveBalances[msg.sender] -= amount;       // State update after
        emit AaveWithdraw(msg.sender, amount);
    }
}
```

**After (SAFE TO SUBMIT):**
```solidity
// VulnerableVault.sol - Vulnerable to reentrancy
contract VulnerableVault {
    mapping(address => uint256) public balances;
    IERC20 public token;
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        token.transfer(msg.sender, amount);  // External call first
        balances[msg.sender] -= amount;      // State update after
        emit Withdraw(msg.sender, amount);
    }
}
```

### Example 2: Description Text

**Before (DO NOT SUBMIT):**
```
During our audit of Aave V3 on Arbitrum in Q3 2024, we discovered that the 
AavePool contract at 0x794a61358D6845594F94dc1DB02A252b5b4814aD was vulnerable 
to a read-only reentrancy attack. The client, Aave Labs, confirmed this finding.
```

**After (SAFE TO SUBMIT):**
```
During a private audit, we discovered that a lending protocol's main pool 
contract was vulnerable to a read-only reentrancy attack. The protocol team 
confirmed this finding.
```

### Example 3: Attack Scenario

**Before (DO NOT SUBMIT):**
```
1. Attacker takes a 1M USDC flash loan from Aave
2. Attacker deposits USDC into CompoundV3 cUSDC market
3. Attacker manipulates the cUSDC/ETH Chainlink oracle
4. Attacker borrows against inflated collateral on TargetProtocol
5. Attacker repays flash loan, keeping profits
```

**After (SAFE TO SUBMIT):**
```
1. Attacker takes a flash loan of TokenA from a lending protocol
2. Attacker deposits TokenA into a money market
3. Attacker manipulates the price oracle for the collateral token
4. Attacker borrows against inflated collateral on the target protocol
5. Attacker repays flash loan, keeping profits
```

---

## Special Cases

### Referencing Known Exploits

If referencing a public exploit:
- ✅ "Similar to the read-only reentrancy pattern seen in public exploits"
- ✅ "This is a variant of the oracle manipulation class of vulnerabilities"
- ❌ "This is exactly how the [Protocol] exploit worked on [date]"

### Referencing Public Audit Findings

If referencing public audit findings:
- ✅ "This pattern has been documented in various public audits"
- ✅ "See academic paper X for detailed analysis of this class"
- ❌ "Trail of Bits found this in their Aave audit"

### Using Real Interface Names

Standard interfaces are okay:
- ✅ `IERC20`, `IERC721`, `IUniswapV2Router`
- ✅ `AggregatorV3Interface` (Chainlink standard)
- ❌ `IAavePool`, `ICompoundComptroller` (protocol-specific)

---

## Verification Checklist

Before submitting, verify each item:

### Protocol/Project Identity
- [ ] No protocol names
- [ ] No project names
- [ ] No governance token names
- [ ] No specific deployment addresses

### Personal Information
- [ ] No developer names
- [ ] No Twitter/GitHub handles
- [ ] No company names
- [ ] No team references

### Traceability
- [ ] No transaction hashes
- [ ] No block numbers
- [ ] No timestamps that identify
- [ ] No specific values from real transactions

### Confidentiality
- [ ] No audit engagement details
- [ ] No bounty information
- [ ] No communication excerpts
- [ ] No internal references

### Code Quality
- [ ] Generic contract names
- [ ] Generic function names
- [ ] Generic variable names
- [ ] Generic event names
- [ ] Code still compiles conceptually

---

## When in Doubt

If unsure whether something should be sanitized:

1. **Ask:** "Could this information identify the source?"
2. **If yes:** Anonymize or remove
3. **If maybe:** Anonymize to be safe
4. **If no:** Can likely keep

The goal is educational value without identification.

---

## Related Files

- [Community Feedback Guide](../COMMUNITY_FEEDBACK.md)
- [New Pattern Template](new-pattern-template.md)
