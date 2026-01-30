---
name: Variant Analysis
description: Find similar bugs across codebase after discovering an initial vulnerability
version: 1.0.0
author: Web3 Security Plugin
tags: [variant-analysis, security, patterns, audit, code-review]
---

# Variant Analysis Skill

Systematic methodology for finding similar vulnerabilities across a codebase after discovering an initial bug. One vulnerability often indicates more of the same type.

## Capabilities

- **Pattern Extraction**: Abstract vulnerability patterns from specific findings
- **Variant Hunting**: Find similar patterns throughout codebase
- **Root Cause Analysis**: Identify systemic issues causing variants
- **Remediation Scope**: Ensure complete fix coverage

---

## Variant Analysis Framework

### The SCARV Method

**S** - Specific: Document the specific vulnerability found
**C** - Characterize: Extract the vulnerability pattern/signature
**A** - Abstract: Generalize the pattern for broader search
**R** - Reconnaissance: Search codebase for variants
**V** - Verify: Confirm each potential variant is exploitable

---

## Step 1: Document the Initial Finding

### Finding Documentation Template

```markdown
## Initial Finding Documentation

### Vulnerability Details
- **ID**: V-001
- **Type**: Reentrancy
- **Severity**: Critical
- **Location**: src/Vault.sol:withdraw():45-60

### Vulnerable Code
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    
    // External call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    
    // State update after external call
    balances[msg.sender] -= amount;
}
```

### Vulnerability Signature
- External call before state update
- State variable modified after external call
- No reentrancy guard
- User-controlled call recipient

### Exploitation Requirements
1. Contract holds ETH
2. User has balance
3. Attacker implements receive()
```

---

## Step 2: Extract the Pattern

### Pattern Extraction Process

```markdown
## Pattern Extraction

### Specific Pattern (This Bug)
1. `call{value: X}("")` to msg.sender
2. State variable `balances[msg.sender]` decremented after
3. No `nonReentrant` modifier

### Generalized Pattern (Variant Search)
1. ANY external call (call, delegatecall, transfer, send)
2. ANY state variable modified after external call
3. Missing reentrancy protection

### Search Signatures
```regex
# External calls
\.call\{.*\}\(
\.delegatecall\(
\.transfer\(
\.send\(

# State updates after calls (need manual verification)
# Look for storage writes after external calls
```

### Related Patterns
- ERC777 token hooks (tokensReceived)
- ERC721 safeTransfer hooks (onERC721Received)
- ERC1155 hooks (onERC1155Received)
- Callback patterns (flash loans, etc.)
```

---

## Step 3: Build Search Queries

### Grep/Regex Patterns

```bash
# Search for external calls
grep -rn "\.call\{" contracts/
grep -rn "\.call(" contracts/
grep -rn "\.delegatecall(" contracts/
grep -rn "\.transfer(" contracts/
grep -rn "\.send(" contracts/

# Search for safeTransfer (potential callbacks)
grep -rn "safeTransfer\|safeTransferFrom" contracts/

# Search for missing reentrancy guards
# Find functions with external calls
grep -rn "\.call\{" contracts/ | grep -v "nonReentrant"

# Search for state updates
grep -rn "\[msg.sender\].*=" contracts/
grep -rn "balances\[" contracts/
grep -rn "\_balances\[" contracts/
```

### Semgrep Rules for Variants

```yaml
# variant-reentrancy.yaml
rules:
  - id: reentrancy-state-after-call
    patterns:
      - pattern: |
          $CALL{...}(...)
          ...
          $STATE[$KEY] = $VAL
      - metavariable-regex:
          metavariable: $CALL
          regex: (call|delegatecall|send|transfer)
    message: "State modification after external call - potential reentrancy variant"
    languages: [solidity]
    severity: ERROR

  - id: reentrancy-erc721-hook
    patterns:
      - pattern: |
          safeTransferFrom(...)
          ...
          $STATE = $VAL
    message: "State modification after safeTransfer - potential reentrancy via ERC721 hook"
    languages: [solidity]
    severity: WARNING
```

### Slither Custom Detector

```python
# Check for state changes after any external call
for function in contract.functions:
    external_call_found = False
    for node in function.nodes:
        # Check for external calls
        if node.contains_external_call():
            external_call_found = True
        
        # If we've seen an external call, check for state changes
        if external_call_found:
            for ir in node.irs:
                if isinstance(ir, StateVariableWrite):
                    report_variant(function, node)
```

---

## Step 4: Systematic Reconnaissance

### Search Checklist

```markdown
## Variant Search Checklist

### Direct Pattern Matches
- [ ] Same function pattern in other contracts
- [ ] Similar function names (withdraw, claim, redeem)
- [ ] Same developer patterns elsewhere

### Related Patterns
- [ ] Other external call types
- [ ] Other callback mechanisms
- [ ] Other state-modifying patterns

### Cross-Contract
- [ ] Inherited contracts
- [ ] Library functions
- [ ] Interface implementations

### Cross-Module
- [ ] Core contracts
- [ ] Periphery contracts
- [ ] Helper contracts
```

### Search Results Tracking

```markdown
## Variant Search Results

| Location | Pattern Match | Variant? | Status |
|----------|---------------|----------|--------|
| Pool.sol:78 | withdraw() with call{} | LIKELY | REVIEW |
| Lending.sol:234 | liquidate() with transfer | POSSIBLE | REVIEW |
| Token.sol:89 | _transfer with callback | NO | FP - internal |
| Router.sol:156 | swap() with safeTransfer | LIKELY | REVIEW |
```

---

## Step 5: Verify Each Variant

### Variant Verification Process

```markdown
## Variant Verification: Pool.sol:withdraw()

### Code Analysis
```solidity
function withdraw(uint256 shares) external {
    uint256 amount = convertToAssets(shares);
    
    // External call
    asset.safeTransfer(msg.sender, amount);
    
    // State update
    _burn(msg.sender, shares);
}
```

### Vulnerability Assessment

1. **External Call Present?** ✅
   - `safeTransfer` calls token transfer

2. **Callback Possible?**
   - ERC20: Generally NO (unless ERC777)
   - Need to verify asset is standard ERC20

3. **State Update After Call?** ✅
   - `_burn` modifies `_balances`

4. **Reentrancy Guard?** ❌
   - No `nonReentrant` modifier

5. **Exploitable?**
   - Depends on asset token type
   - If ERC777: YES, exploitable
   - If standard ERC20: NO

### Verdict
- Standard ERC20: NOT VULNERABLE (no callback)
- ERC777 asset: VULNERABLE
- Recommendation: Add `nonReentrant` as defense in depth
```

---

## Common Variant Categories

### Reentrancy Variants

```markdown
## Reentrancy Pattern Variants

### Type 1: ETH Transfer
- call{value: X}
- transfer()
- send()

### Type 2: Token Hooks
- ERC777 tokensReceived
- ERC721 onERC721Received
- ERC1155 onERC1155Received

### Type 3: Callback Patterns
- Flash loan callbacks
- Uniswap swap callbacks
- Chainlink VRF callbacks

### Type 4: Cross-Contract
- External contract calls back
- Proxy/Implementation interactions
- Library delegatecalls
```

### Access Control Variants

```markdown
## Access Control Pattern Variants

### Type 1: Missing Check
- No onlyOwner modifier
- No role check
- No msg.sender validation

### Type 2: Incorrect Check
- Using tx.origin
- Checking wrong role
- Incomplete validation

### Type 3: Bypasses
- Initialization bypass
- Proxy admin confusion
- Inheritance shadows

### Search Pattern
```bash
# Find admin functions
grep -rn "function set\|function add\|function remove\|function update" contracts/

# Check for access control
grep -rn "onlyOwner\|onlyAdmin\|onlyRole\|auth" contracts/

# Find potentially unprotected
grep -rn "external\|public" contracts/ | grep -v "view\|pure" | grep -v "onlyOwner"
```
```

### Integer Overflow Variants

```markdown
## Integer Overflow Pattern Variants

### Type 1: Direct Arithmetic
- Unchecked additions
- Unchecked multiplications
- Unchecked subtractions (underflow)

### Type 2: Casting Issues
- Downcasting (uint256 to uint128)
- Signed/unsigned confusion
- Assembly operations

### Type 3: External Inputs
- User-provided amounts
- Oracle data
- Timestamp values

### Search Pattern
```bash
# Find unchecked blocks
grep -rn "unchecked" contracts/

# Find casting
grep -rn "uint8\|uint16\|uint128" contracts/

# Find multiplication
grep -rn "\*" contracts/
```
```

### Oracle Manipulation Variants

```markdown
## Oracle Pattern Variants

### Type 1: Spot Price
- Direct balanceOf ratio
- Single-block reserve ratio
- No time-weighting

### Type 2: Stale Data
- No freshness check
- Old roundId accepted
- Unlimited staleness

### Type 3: Price Bounds
- No min/max validation
- No deviation check
- Accepts zero price

### Search Pattern
```bash
# Find oracle calls
grep -rn "latestRoundData\|getPrice\|getAmountOut" contracts/

# Find reserve ratios
grep -rn "reserve0\|reserve1\|getReserves" contracts/

# Find balance ratios
grep -rn "balanceOf.*balanceOf\|totalSupply" contracts/
```
```

---

## Variant Analysis Workflow

```markdown
## Complete Workflow

### Phase 1: Initial Finding (30 min)
- [ ] Document vulnerability completely
- [ ] Identify all components of the bug
- [ ] Write PoC for initial finding

### Phase 2: Pattern Extraction (30 min)
- [ ] Extract specific pattern
- [ ] Generalize to broader pattern
- [ ] Identify related patterns
- [ ] Build search queries

### Phase 3: Codebase Search (1-2 hours)
- [ ] Run grep searches
- [ ] Run Semgrep rules
- [ ] Check Slither output
- [ ] Manual code review

### Phase 4: Variant Verification (variable)
For each potential variant:
- [ ] Analyze code path
- [ ] Check exploitation requirements
- [ ] Verify exploitability
- [ ] Document as variant or false positive

### Phase 5: Root Cause Analysis (30 min)
- [ ] Why do these variants exist?
- [ ] Developer pattern issue?
- [ ] Missing security guidelines?
- [ ] Copy-paste problem?

### Phase 6: Comprehensive Fix (30 min)
- [ ] Fix covers all variants
- [ ] Fix addresses root cause
- [ ] Preventive measures added
```

---

## Variant Analysis Checklist

```markdown
## Quick Checklist

### After Finding a Bug
- [ ] Is this pattern used elsewhere?
- [ ] Are there similar function names?
- [ ] Same developer, same mistakes?
- [ ] Inherited code has same bug?

### Pattern Types to Check
- [ ] Reentrancy variants
- [ ] Access control variants
- [ ] Input validation variants
- [ ] Oracle/price variants
- [ ] Arithmetic variants

### Search Locations
- [ ] Same contract
- [ ] Related contracts
- [ ] Inherited contracts
- [ ] Library code
- [ ] External integrations

### Documentation
- [ ] All variants documented
- [ ] False positives explained
- [ ] Root cause identified
- [ ] Comprehensive fix proposed
```

---

## Resources

- [variant-patterns.md](resources/variant-patterns.md) - Common variant pattern library

## Workflows

- [variant-hunt.md](workflows/variant-hunt.md) - Variant hunting workflow

---

## Integration Tips

### With Cyfrin Solodit
Search for similar findings in historical audits:
- "reentrancy" + protocol type
- Specific function names
- Similar DeFi patterns

### With Static Analysis
- Configure Slither for specific detector
- Build custom Semgrep rules
- Run focused scans on related code

