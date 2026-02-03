# Gradient Template: Missed Reentrancy

## Vulnerability Class
Reentrancy (all variants)

---

## Detection Signals

### Classic Reentrancy
```solidity
// Signal: State update AFTER external call
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // [SIGNAL] External call
    require(success);
    balances[msg.sender] -= amount;  // [SIGNAL] State update after call
}
```

### Cross-Function Reentrancy
```solidity
// Signal: Shared state between functions + external call
function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}

function withdrawAll() external {
    uint256 amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");  // Can re-enter transfer()
    balances[msg.sender] = 0;
}
```

### Cross-Contract Reentrancy
```solidity
// Signal: Protocol A calls Protocol B which can call back to A
function depositAndBorrow() external {
    lendingPool.deposit(amount);      // [SIGNAL] External protocol call
    lendingPool.borrow(borrowAmount); // State in lending pool inconsistent
    // Callback here can exploit inconsistent state
}
```

### Read-Only Reentrancy
```solidity
// Signal: View function + external protocol integration
function getSharePrice() external view returns (uint256) {
    return totalAssets() / totalSupply();  // [SIGNAL] Reads state mid-transaction
}

// Another protocol:
function liquidate(address vault) external {
    uint256 price = IVault(vault).getSharePrice();  // Called during vault's withdraw
    // Price is stale/manipulated during reentrancy window
}
```

---

## Common Miss Reasons

| Reason | Frequency | Fix |
|--------|-----------|-----|
| Focused on classic pattern only | HIGH | Add all variants to checklist |
| Assumed `view` functions are safe | HIGH | Check view function external usage |
| Didn't trace cross-contract flows | MEDIUM | Map all external integrations |
| Trusted nonReentrant modifier blindly | MEDIUM | Verify modifier scope |
| Missed ERC777/ERC1155 hooks | MEDIUM | Always check token callbacks |
| Didn't check upgrade proxy state | LOW | Verify storage layout preserved |

---

## Critique Template

### Section 1: Identify the Miss
```markdown
**Vulnerability Missed:** [Describe the specific reentrancy]
**Contract:** [contract.sol]
**Function:** [function name]
**Severity:** [CRITICAL/HIGH]
**Discovery Source:** [How was it found?]
```

### Section 2: Analyze Why
```markdown
**What pattern file should have caught this?**
- patterns/reentrancy-patterns.md

**Was the attack vector documented?**
- [ ] Yes, fully documented
- [ ] Partially documented
- [ ] No documentation exists

**What code signal was present?**
- [Describe the signal that should have triggered detection]

**Why was it missed?**
- [ ] Signal not in detection checklist
- [ ] Cross-contract flow not traced
- [ ] Variant not documented
- [ ] Time pressure / rushed review
- [ ] Assumed protection was sufficient
```

### Section 3: Root Cause
```markdown
**Root Cause Analysis:**
[Detailed explanation of the systemic issue that allowed this miss]

**Pattern Gap:**
[What pattern knowledge was missing?]

**Process Gap:**
[What process step was skipped or insufficient?]
```

---

## Edit Targets

### If Classic Reentrancy Missed
```yaml
update_files:
  - patterns/reentrancy-patterns.md:
      add: "## Classic Reentrancy Checklist"
      location: "Top of detection section"
  - checklists/comprehensive-checklist.md:
      add: "[ ] All external calls use CEI pattern"
      location: "Reentrancy section"
```

### If Cross-Function Reentrancy Missed
```yaml
update_files:
  - patterns/reentrancy-patterns.md:
      add: "## Cross-Function Reentrancy"
      location: "After classic reentrancy"
  - anti-patterns/reentrancy-anti-patterns.md:
      add: "Anti-Pattern: Shared State Cross-Function"
```

### If Read-Only Reentrancy Missed
```yaml
update_files:
  - patterns/reentrancy-patterns.md:
      add: "## Read-Only Reentrancy"
  - checklists/defi-checklist.md:
      add: "[ ] View functions safe during external protocol calls"
  - TRIGGERS.md:
      add: "| ERC4626 | read-only-reentrancy.md, vault-patterns.md |"
```

---

## Edit Templates

### Checklist Addition
```markdown
## Reentrancy - [VARIANT NAME]

**Quick Check:**
- [ ] [First check item]
- [ ] [Second check item]
- [ ] [Third check item]

**Deep Dive When Triggered:**
- [ ] [Detailed check 1]
- [ ] [Detailed check 2]
```

### Pattern Addition
```markdown
## [Variant] Reentrancy Pattern

### Vulnerable Code
```solidity
// [Show vulnerable pattern]
```

### Safe Code
```solidity
// [Show fixed pattern]
```

### Detection Query
"Search for [specific pattern] in all contracts"

### Related Vulnerabilities
- [Link to related patterns]
```

### Anti-Pattern Addition
```markdown
## Anti-Pattern: [Name]

[VULNERABLE]
```solidity
// Bad code
```

[SAFE]
```solidity
// Fixed code
```

**Why it's dangerous:** [Explanation]
**Fix:** [Solution]
```

---

## Validation Query

After applying edits, verify with this test:

```markdown
## Validation Test

1. Take the original vulnerable code
2. Run audit checklist against it
3. Verify vulnerability is now detected
4. Check for false positives on similar-looking safe code

### Test Case
```solidity
// Paste the original vulnerable code here
```

### Expected Detection
- [ ] Flagged by checklist item: [which item]
- [ ] Pattern file loaded: [which pattern]
- [ ] Severity correctly assessed: [severity]

### False Positive Check
```solidity
// Similar but safe code that should NOT flag
```

- [ ] No false positive generated
```

---

## Example Gradient

### GRAD-001: Read-Only Reentrancy in ERC4626 Vault

**Miss Details:**
- Contract: LPVault.sol (ERC4626)
- Function: `convertToAssets()` view function
- Discovery: Post-audit exploit on integrated lending protocol

**Critique:**
The auditor checked all state-modifying functions for reentrancy but assumed view functions were safe. The `convertToAssets()` function returns stale data when called during a withdraw transaction's external callback, allowing price manipulation.

**Signal Present But Missed:**
```solidity
function convertToAssets(uint256 shares) public view returns (uint256) {
    uint256 supply = totalSupply();  // [SIGNAL] Reads state
    return supply == 0 ? shares : shares.mulDivDown(totalAssets(), supply);
}
```

**Applied Edits:**
1. Added "Read-Only Reentrancy" section to `reentrancy-patterns.md`
2. Added checklist item: "View functions safe during external calls"
3. Added trigger: "ERC4626 → load read-only-reentrancy.md"
4. Added anti-pattern example to `reentrancy-anti-patterns.md`

**Validation:**
Re-audited with new patterns → vulnerability detected at checklist step 3.

---

## Related Templates

- [Missed Oracle Manipulation](missed-oracle-manipulation.md)
- [Missed Access Control](missed-access-control.md)
- [Pattern Addition Template](../apply-edit-templates/pattern-addition.md)
- [Checklist Expansion Template](../apply-edit-templates/checklist-expansion.md)
