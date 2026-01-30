# Competitive Audit Workflow

Optimized workflow for competitive audit platforms where speed and finding unique bugs matters.

---

## Overview

Competitive audits differ from private audits:
- **Time-boxed:** Usually 1-7 days
- **Competition:** Multiple auditors reviewing same code
- **Rewards:** Payment per valid finding
- **Strategy:** Balance breadth vs depth

This workflow maximizes your chances of finding valid, unique bugs.

---

## Pre-Contest Preparation

### Before Contest Starts

```markdown
## Pre-Contest Checklist

- [ ] Read contest announcement
- [ ] Note start/end times
- [ ] Identify protocol type
- [ ] Review any pre-released docs
- [ ] Prepare environment (tools, templates)
- [ ] Block calendar for focus time
```

### Protocol Type Advantage

Prepare mental models for common types:

| Protocol Type | Common Bugs | Focus Areas |
|---------------|-------------|-------------|
| DEX/AMM | Price manipulation, sandwich | Swap math, oracle |
| Lending | Liquidation, interest | Health factor, rates |
| Vault/Yield | Share manipulation, rug | Entry/exit, strategy |
| NFT | Reentrancy, mint bypass | Callbacks, signatures |
| Bridge | Message verification | Cross-chain state |
| Staking | Reward calculation | Timing, inflation |

---

## Hour 0-1: Rapid Assessment

### First 15 Minutes

```bash
# Clone and compile
git clone [repo]
cd [repo]
forge build

# Get overview
slither . --print human-summary
wc -l contracts/**/*.sol
```

Document immediately:

```markdown
## Rapid Assessment

**Protocol:** [Name]
**Type:** [DEX/Lending/NFT/etc.]
**Contracts:** [count]
**LOC:** [count]
**Complexity:** Low / Medium / High

**First Impressions:**
- [Notable pattern 1]
- [Notable pattern 2]
- [Any red flags]
```

### Minutes 15-45: Entry Point Map

Quick list of all entry points:

```bash
# Extract external functions
grep -rn "external" contracts/ | grep "function" > entry_points.txt
```

Rapid categorize:

| Function | Risk Level | Why |
|----------|------------|-----|
| deposit() | 🔴 Critical | Receives value |
| withdraw() | 🔴 Critical | Sends value |
| setConfig() | 🟡 Medium | Admin only |
| getBalance() | 🟢 Low | View only |

### Minutes 45-60: High-Value Target Selection

Pick 3-5 functions to deep dive first:

```markdown
## Priority Targets

1. **[Function]** - [Why high priority]
2. **[Function]** - [Why high priority]
3. **[Function]** - [Why high priority]

## Deprioritize
- View functions (unless oracle-related)
- Standard OZ implementations
- Simple getters/setters
```

---

## Hours 1-4: Targeted Deep Dives

### Strategy: Depth Over Breadth Initially

Focus on finding ONE good bug rather than surface-level coverage.

### For Each Priority Function

```markdown
## Deep Dive: [Function Name]

### 5-Minute Scan
- Purpose: [What it does]
- Value: [Handles value?]
- External Calls: [Any?]
- State Changes: [What?]

### Red Flag Check
- [ ] External call + state after? → Reentrancy
- [ ] User input in calculation? → Manipulation
- [ ] Access control present? → Auth issues
- [ ] Token interaction? → Weird token issues
- [ ] Oracle used? → Price manipulation

### Deep Analysis (if flags found)
[Continue with full analysis]
```

### Bug Hunting Patterns

Most competitive bugs fall into:

1. **Logic Errors** (40%)
   - Incorrect conditions
   - Wrong order of operations
   - Edge case handling

2. **Integration Issues** (25%)
   - Token compatibility
   - Oracle manipulation
   - External protocol interaction

3. **Access Control** (15%)
   - Missing checks
   - Incorrect role logic

4. **Economic Attacks** (15%)
   - Flash loans
   - MEV/front-running
   - Inflation attacks

5. **Other** (5%)
   - Reentrancy, DoS, etc.

---

## Hours 4-12: Systematic Coverage

### Automated Scan Review

```bash
# If not done yet, run full scans
slither . --json slither.json
slither . --detect all 2>&1 | grep -E "High|Medium" > high_medium.txt
```

Review automated findings:
- [ ] Check each High/Medium
- [ ] Dismiss false positives with notes
- [ ] Deep dive on promising leads

### Category Sweep

Quickly check each category:

```markdown
## Category Sweep

### Reentrancy
Locations checked: [list]
Status: ✅ Clear / ⚠️ Potential / ❌ Found

### Access Control
Locations checked: [list]
Status: ✅ Clear / ⚠️ Potential / ❌ Found

### Oracle/Price
Locations checked: [list]
Status: ✅ Clear / ⚠️ Potential / ❌ Found

[Continue for each category...]
```

### Cross-Reference Cyfrin Solodit

```bash
# Search for similar protocol audits
# Use cyfrin-findings skill to query:
# - Same protocol type
# - Same patterns (AMM, lending pool, etc.)
# - Same external integrations
```

Apply found patterns to current codebase.

---

## Finding Submission Strategy

### Quality Over Quantity

```markdown
## Submission Checklist

Before submitting, verify:
- [ ] Bug is real (can exploit/demonstrate)
- [ ] Impact is clear and significant
- [ ] Root cause identified
- [ ] Not a duplicate of known issue
- [ ] PoC is clean and runnable
- [ ] Recommendation is actionable
```

### Competitive Finding Template

```markdown
## [Title - Clear and Specific]

### Severity
[Critical/High/Medium/Low] - [One line justification]

### Summary
[1-2 sentences describing the bug]

### Vulnerability Detail
[Technical explanation of the bug]

### Impact
[What can attacker achieve? Quantify if possible]

### Proof of Concept

```solidity
function test_exploit() public {
    // Step 1: Setup
    // Step 2: Attack
    // Step 3: Verify impact
}
```

### Recommended Mitigation
```solidity
// Fixed code
```
```

### Timing Submissions

- **Don't submit immediately** if you found something big
- Search for related issues (might find more)
- But don't wait too long - others might find it
- Submit core finding, note "related issues being investigated"

---

## Hour 12+: Expansion and Edge Cases

### Second Pass Targets

Functions you skipped initially:
- Internal functions (can they be abused?)
- View functions (read-only reentrancy?)
- Admin functions (if admin is compromised?)

### Edge Case Hunting

```markdown
## Edge Case Checklist

### Numeric
- [ ] Zero values
- [ ] Type max values (type(uint256).max)
- [ ] Precision edge cases

### Array/Mapping
- [ ] Empty arrays
- [ ] Maximum length arrays
- [ ] Non-existent keys

### Time
- [ ] Same block operations
- [ ] Just before deadline
- [ ] Just after deadline

### State
- [ ] Paused contract
- [ ] First user (bootstrap)
- [ ] Last user (drain)
```

### Integration Edge Cases

```markdown
## Integration Edge Cases

### Token Weirdness
- [ ] Fee-on-transfer tokens
- [ ] Rebasing tokens
- [ ] Pausable tokens
- [ ] Blacklist tokens
- [ ] Low decimals (USDC: 6)
- [ ] High decimals (some: 24)

### Oracle Weirdness
- [ ] Stale prices
- [ ] Zero/negative prices
- [ ] Extreme prices
- [ ] Sequencer downtime (L2)

### Protocol Weirdness
- [ ] Upgrade in progress
- [ ] Governance attack
- [ ] Emergency mode
```

---

## Final Hours: Cleanup

### Review All Notes

Go through notes for anything missed:

```markdown
## Final Review

### Unfinished Items
1. [Item] - [Do now or skip?]
2. [Item] - [Do now or skip?]

### Weak Leads Worth Revisiting
1. [Lead] - [Quick recheck]
2. [Lead] - [Quick recheck]

### Submissions to Improve
1. [Submission] - [Add PoC / clarity]
```

### Submission Quality Check

Before contest ends:
- [ ] All findings have PoC
- [ ] Impact clearly stated
- [ ] No duplicates submitted
- [ ] Formatting is clean

---

## Post-Contest

### Learning from Results

```markdown
## Post-Contest Review

### My Findings
| ID | Title | My Severity | Judge Severity | Status |
|----|-------|-------------|----------------|--------|
| 1 | [Title] | High | High | Valid |
| 2 | [Title] | Medium | Low | Downgraded |

### Missed Findings
| ID | Title | Severity | Why I Missed |
|----|-------|----------|--------------|
| 1 | [Title] | High | [Reason] |

### Lessons Learned
1. [Lesson]
2. [Lesson]
3. [Lesson]
```

### Build Pattern Library

Save successful patterns:
```markdown
## Pattern: [Name]

**Found in:** [Contest]
**Type:** [Bug type]

**Pattern:**
[Description]

**Detection:**
[How to find]

**Example:**
[Code]
```

---

## Time Management

### Short Contest (24-48 hours)

| Phase | Time | Focus |
|-------|------|-------|
| Assessment | 1h | Prioritize ruthlessly |
| Deep Dives | 8h | Top 5 functions only |
| Category Sweep | 4h | Critical categories only |
| Edge Cases | 4h | High-impact edges |
| Submissions | 3h | Polish existing |

### Medium Contest (1 week)

| Phase | Time | Focus |
|-------|------|-------|
| Assessment | 2h | Thorough mapping |
| Deep Dives | 16h | Top 10 functions |
| Category Sweep | 8h | All categories |
| Edge Cases | 8h | Comprehensive |
| Expansion | 8h | Second pass |
| Submissions | 6h | All findings polished |

---

## Pro Tips

### Finding Edge

1. **Read the docs first** - Spec vs implementation bugs
2. **Check test files** - What are they testing? What aren't they?
3. **Previous audits** - What was fixed? Did fix introduce new bug?
4. **Similar protocols** - Cyfrin findings from same type
5. **Upgrade context** - Is this v2? What changed from v1?

### Efficiency

1. **Templates ready** - Finding, PoC, analysis templates
2. **Tools configured** - Don't waste time on setup
3. **Notes organized** - Can't find = can't use
4. **Focus blocks** - No distractions during deep work

### Psychology

1. **Don't panic** - Others have same code, same time
2. **Take breaks** - Fresh eyes find more
3. **Trust process** - Systematic beats frantic
4. **Quality > quantity** - One good High > ten invalid Mediums

