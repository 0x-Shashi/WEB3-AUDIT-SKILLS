# Gradient Template: Missed Access Control

## Vulnerability Class
Access Control & Authorization Flaws

---

## Detection Signals

### Missing Access Modifier
```solidity
// Signal: Admin function without modifier
function setFeeRecipient(address newRecipient) external {  // [SIGNAL] No modifier
    feeRecipient = newRecipient;
}
```

### Incorrect Modifier Logic
```solidity
// Signal: Modifier that doesn't revert properly
modifier onlyOwner() {
    if (msg.sender == owner) {  // [SIGNAL] Missing revert on else
        _;
    }
}
```

### Centralization in Sensitive Function
```solidity
// Signal: Single address controls critical parameter
function setMaxLTV(uint256 newLTV) external onlyOwner {  // [SIGNAL]
    maxLTV = newLTV;  // Can be set to 100% instantly
}
```

### Missing Validation on Setter
```solidity
// Signal: No bounds checking on parameter
function setSlippageTolerance(uint256 tolerance) external onlyOwner {
    slippageTolerance = tolerance;  // [SIGNAL] Can be set to 0 or 100%
}
```

### Unprotected Initialize
```solidity
// Signal: Initialize can be called by anyone
function initialize(address _owner) external {  // [SIGNAL] No initializer modifier
    owner = _owner;
}
```

### Privilege Escalation Path
```solidity
// Signal: Role can grant itself more roles
function grantRole(bytes32 role, address account) public {
    require(hasRole(getRoleAdmin(role), msg.sender));  // [SIGNAL]
    _grantRole(role, account);
}
// Admin of MINTER_ROLE can grant ADMIN_ROLE if misconfigured
```

### Front-Running Protected Functions
```solidity
// Signal: Sensitive function without commit-reveal
function claimReward(uint256 rewardId) external {  // [SIGNAL]
    require(rewards[rewardId].claimer == address(0));
    rewards[rewardId].claimer = msg.sender;
}
```

---

## Common Miss Reasons

| Reason | Frequency | Fix |
|--------|-----------|-----|
| Trusted "admin is safe" assumption | HIGH | Document centralization risks |
| Didn't check all public functions | HIGH | Systematic function audit |
| Missed initializer re-call | HIGH | Check initializer modifier |
| Didn't trace role relationships | MEDIUM | Map all role hierarchies |
| Assumed modifier works correctly | MEDIUM | Verify modifier logic |
| Didn't consider front-running | MEDIUM | Check for MEV exposure |

---

## Critique Template

### Section 1: Identify the Miss
```markdown
**Vulnerability Missed:** [Describe the access control issue]
**Contract:** [contract.sol]
**Function:** [affected function]
**Access Level:** [Who can call vs who should]
**Severity:** [CRITICAL/HIGH/MEDIUM]
**Discovery Source:** [How was it found?]
```

### Section 2: Analyze Why
```markdown
**What pattern file should have caught this?**
- patterns/access-control-patterns.md

**Was the attack vector documented?**
- [ ] Yes, fully documented
- [ ] Partially documented
- [ ] No documentation exists

**What code signal was present?**
- [Describe the signal]

**Why was it missed?**
- [ ] Function not audited (missed in scope)
- [ ] Modifier assumed correct
- [ ] Role hierarchy not traced
- [ ] Centralization not flagged as risk
- [ ] Initialize protection not checked
```

### Section 3: Root Cause
```markdown
**Root Cause Analysis:**
[Detailed explanation]

**Pattern Gap:**
[What access control pattern was missing?]

**Process Gap:**
[What validation step was skipped?]
```

---

## Edit Targets

### If Missing Modifier
```yaml
update_files:
  - checklists/comprehensive-checklist.md:
      add: "[ ] All state-changing functions have appropriate access control"
  - patterns/access-control-patterns.md:
      add: "## Function Access Audit Checklist"
```

### If Unprotected Initialize
```yaml
update_files:
  - patterns/proxy-patterns.md:
      add: "## Initializer Protection"
  - checklists/proxy-checklist.md:
      add: "[ ] Initialize can only be called once"
  - anti-patterns/access-control-anti-patterns.md:
      add: "Anti-Pattern: Unprotected Initializer"
```

### If Centralization Risk
```yaml
update_files:
  - checklists/roles/owner-role-checklist.md:
      add: "[ ] Admin powers documented with risk level"
  - templates/centralization-table.md:
      update: "Add new centralization risk type"
```

### If Role Misconfiguration
```yaml
update_files:
  - patterns/access-control-patterns.md:
      add: "## Role Hierarchy Audit"
  - checklists/comprehensive-checklist.md:
      add: "[ ] Role admin relationships traced and validated"
```

---

## Edit Templates

### Checklist Addition
```markdown
## Access Control Checklist

**Function Level:**
- [ ] All external/public functions audited for access
- [ ] State-changing functions have modifiers
- [ ] View functions don't expose sensitive data

**Modifier Level:**
- [ ] Modifier logic verified (proper revert)
- [ ] Modifier applied to all relevant functions
- [ ] No modifier bypass paths

**Role Level:**
- [ ] Role hierarchy documented
- [ ] Role admins cannot escalate beyond design
- [ ] Default admin role secured

**Initialize:**
- [ ] Initializer modifier used
- [ ] Cannot be re-initialized
- [ ] Initial state is secure
```

### Pattern Addition
```markdown
## [Access Control Issue] Pattern

### Vulnerable Code
```solidity
// [Show vulnerable access control]
```

### Safe Code
```solidity
// [Show proper access control]
```

### Detection Query
"Search for external/public functions without access modifiers"

### Risk Level
[Severity and impact]
```

---

## Validation Query

```markdown
## Validation Test

### Test Case: Missing Modifier
```solidity
function setConfig(uint256 value) external {
    config = value;
}
```

### Expected Detection
- [ ] Flagged by: "Function without access control"
- [ ] Severity: HIGH

### Test Case: Unprotected Initialize
```solidity
function initialize(address _owner) external {
    owner = _owner;
}
```

### Expected Detection
- [ ] Flagged by: "Initializer not protected"
- [ ] Severity: CRITICAL
```

---

## Example Gradient

### GRAD-003: Unprotected Initialize Function

**Miss Details:**
- Contract: TokenVault.sol (upgradeable)
- Function: `initialize()`
- Discovery: Attacker re-initialized contract post-deployment

**Critique:**
The auditor checked the initialize function parameters but did not verify that the `initializer` modifier was applied. The function could be called multiple times, allowing an attacker to reset the owner after deployment.

**Signal Present But Missed:**
```solidity
function initialize(address _owner, address _token) external {
    // [MISSING] initializer modifier
    owner = _owner;
    token = _token;
}
```

**Applied Edits:**
1. Added "Initialize Protection" to proxy patterns
2. Added checklist: "[ ] Initialize protected with initializer modifier"
3. Added anti-pattern: "Unprotected Initializer"
4. Added to TRIGGERS: "| Proxy | initializer-patterns.md |"

**Validation:**
Re-audited → detected at "Initialize" checklist section.

---

## Complete Access Control Checklist

After processing access control gradients, ensure:

```markdown
## Master Access Control Checklist

### Function Audit
- [ ] Every external function access requirements documented
- [ ] Every public function access requirements documented
- [ ] Internal functions only called from authorized paths

### Modifier Verification
- [ ] All modifiers revert on failure (not silent)
- [ ] Modifier conditions are correct
- [ ] No modifier ordering issues

### Role Management
- [ ] All roles documented with purpose
- [ ] Role hierarchy mapped
- [ ] Admin role transitions secured
- [ ] Time locks on sensitive role changes

### Initialize/Constructor
- [ ] Initialize protected (OZ initializer)
- [ ] Constructor initializes all critical state
- [ ] Implementation contract initialized (for proxies)

### Centralization Risks
- [ ] Single points of failure documented
- [ ] Admin key compromise impact assessed
- [ ] Multisig recommended where appropriate

### Edge Cases
- [ ] Self-referential role grants blocked
- [ ] Zero address checks on role assignment
- [ ] Renounce ownership implications documented
```

---

## Access Control Severity Guide

| Issue | Typical Severity |
|-------|-----------------|
| Missing modifier on fund transfer | CRITICAL |
| Unprotected initialize | CRITICAL |
| Missing modifier on config change | HIGH |
| Role escalation possible | HIGH |
| Centralization without timelock | MEDIUM |
| Missing zero address check | LOW-MEDIUM |

---

## Related Templates

- [Missed Reentrancy](missed-reentrancy.md)
- [Missed Oracle Manipulation](missed-oracle-manipulation.md)
- [Pattern Addition Template](../apply-edit-templates/pattern-addition.md)
- [Checklist Expansion Template](../apply-edit-templates/checklist-expansion.md)
