# Apply Edit Template: Checklist Expansion

## Purpose
Template for adding new checklist items based on audit misses or new vulnerability discoveries.

---

## When to Use

Use this template when:
- A vulnerability was missed that should have been caught by a checklist
- A new attack vector is discovered that needs checklist coverage
- An existing checklist item needs expansion or clarification
- Cross-cutting concerns need systematic checking

---

## Expansion Process

### Step 1: Identify Target Checklist

```markdown
**Primary Checklist:** [e.g., checklists/comprehensive-checklist.md]
**Section:** [e.g., Reentrancy, Oracle, Access Control]
**Related Checklists:** [List any role/feature specific checklists]
```

### Step 2: Draft New Item

```markdown
**New Checklist Item:**
- [ ] [Clear, actionable check]

**Trigger Condition:**
When this should be checked (e.g., "When ERC4626 vault detected")

**False Positive Risk:** [Low/Medium/High]
**Miss Risk if Omitted:** [Low/Medium/High/Critical]
```

### Step 3: Position in Checklist

```markdown
**Insert After:** [Existing checklist item or section header]
**Insert Before:** [Existing checklist item or section header]

**Rationale for Position:**
[Why this location makes sense in the audit flow]
```

### Step 4: Add Supporting Context

```markdown
**Quick Reference:**
[1-2 line explanation auditors can reference]

**Code Signal:**
```solidity
// What to look for
```

**Link to Pattern:**
[patterns/relevant-pattern.md](../patterns/relevant-pattern.md)
```

---

## Checklist Item Format Standards

### Basic Item
```markdown
- [ ] Brief actionable description
```

### Item with Sub-checks
```markdown
- [ ] Main check
  - [ ] Sub-check A
  - [ ] Sub-check B
  - [ ] Sub-check C
```

### Item with Severity Indicator
```markdown
- [ ] [C] Check that could be Critical if missed
- [ ] [H] Check that could be High if missed
- [ ] [M] Check that could be Medium if missed
```

### Item with Conditional
```markdown
- [ ] If [condition], then [check]
```

---

## Example Expansions

### Example 1: Adding Read-Only Reentrancy Check

**Target:** `checklists/comprehensive-checklist.md`
**Section:** Reentrancy

**Current State:**
```markdown
## Reentrancy
- [ ] State changes before external calls (CEI pattern)
- [ ] ReentrancyGuard on all external entry points
- [ ] Cross-function reentrancy paths checked
```

**Expanded State:**
```markdown
## Reentrancy
- [ ] State changes before external calls (CEI pattern)
- [ ] ReentrancyGuard on all external entry points
- [ ] Cross-function reentrancy paths checked
- [ ] [H] Read-only reentrancy: View functions safe during external calls
  - [ ] Price/share calculations not exploitable mid-transaction
  - [ ] External protocols integrating view functions identified
```

### Example 2: Adding L2 Sequencer Check

**Target:** `checklists/defi-checklist.md`
**Section:** Oracle Security

**Current State:**
```markdown
## Oracle Security
- [ ] Using TWAP or Chainlink (not spot prices)
- [ ] Staleness check on price data
- [ ] Fallback oracle configured
```

**Expanded State:**
```markdown
## Oracle Security
- [ ] Using TWAP or Chainlink (not spot prices)
- [ ] Staleness check on price data
- [ ] Fallback oracle configured
- [ ] [H] L2 Deployment: Sequencer uptime check implemented
  - [ ] Sequencer feed address correct for chain
  - [ ] Grace period after sequencer restart
```

### Example 3: Adding Initialize Protection

**Target:** `checklists/proxy-checklist.md`
**Section:** Upgrade Safety

**Current State:**
```markdown
## Upgrade Safety
- [ ] Storage layout preserved between versions
- [ ] No selfdestruct in implementation
- [ ] Admin cannot be locked out
```

**Expanded State:**
```markdown
## Upgrade Safety
- [ ] Storage layout preserved between versions
- [ ] No selfdestruct in implementation
- [ ] Admin cannot be locked out
- [ ] [C] Initialize function protected
  - [ ] Using OpenZeppelin's `initializer` modifier
  - [ ] Cannot be called more than once
  - [ ] Implementation contract also initialized
```

---

## Validation Checklist

Before finalizing expansion, verify:

- [ ] Item is actionable (auditor knows what to do)
- [ ] Item is specific (not vague/general)
- [ ] Item has appropriate severity indicator
- [ ] Item is in logical position in audit flow
- [ ] Sub-checks are included where needed
- [ ] Related pattern/documentation linked
- [ ] No duplicate of existing item
- [ ] Wording matches checklist style

---

## Multi-Checklist Propagation

When an item affects multiple checklists:

```markdown
**Primary Addition:**
checklists/comprehensive-checklist.md → Section: [X]

**Secondary Additions:**
checklists/defi-checklist.md → Section: [Y] (if DeFi specific)
checklists/roles/[role]-checklist.md → (if role specific)

**Cross-Reference:**
Add "See also: [other-checklist.md]" where relevant
```

---

## Edit Commands

### Adding to Comprehensive Checklist
```yaml
file: checklists/comprehensive-checklist.md
action: insert_after
marker: "## [Section Name]"
content: |
  - [ ] [New checklist item]
    - [ ] [Sub-check if needed]
```

### Adding to Role Checklist
```yaml
file: checklists/roles/[role]-role-checklist.md
action: insert_after
marker: "## [Section Name]"
content: |
  - [ ] [New checklist item]
```

### Adding New Section
```yaml
file: checklists/comprehensive-checklist.md
action: insert_before
marker: "## [Next Section]"
content: |
  ## [New Section Name]
  
  - [ ] [First item]
  - [ ] [Second item]
```

---

## Template for Submission

When contributing checklist expansions:

```markdown
## Checklist Expansion Request

**Source:** [Gradient ID or discovery reference]
**Target File:** [path/to/checklist.md]
**Section:** [Section name]

### New Item(s)
```markdown
- [ ] [Item text]
  - [ ] [Sub-item if any]
```

### Rationale
[Why this item is needed]

### Code Signal
```solidity
// Example of what to look for
```

### Validation
- [ ] Tested against known vulnerable code
- [ ] No false positives on safe code
- [ ] Consistent with checklist style

### Related Changes
- [ ] Pattern file updated: [path]
- [ ] Anti-pattern added: [path]
- [ ] Trigger added: [path]
```

---

## Related Templates

- [Pattern Addition](pattern-addition.md)
- [Feedback Loop](../FEEDBACK_LOOP.md)
- [Missed Reentrancy Gradient](../gradient-templates/missed-reentrancy.md)
