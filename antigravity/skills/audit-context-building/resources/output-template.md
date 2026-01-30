# Output Template

Copy and fill this template for each function analysis.

---

## Function: `functionName(param1, param2, ...)`

**File:** `path/to/Contract.sol`  
**Lines:** XX-YY  
**Visibility:** public | external | internal | private  
**Modifiers:** [list modifiers]

---

### Purpose

[Write 2-3 sentences explaining:
1. Why this function exists
2. Its role in the system
3. Expected behavior summary]

---

### Inputs & Assumptions

| Input | Type | Validation | Trust Level |
|-------|------|------------|-------------|
| param1 | type | Describe validation | Trusted/Untrusted |
| param2 | type | Describe validation | Trusted/Untrusted |

**Implicit Inputs:**
- `msg.sender`: [What assumption about caller?]
- `msg.value`: [If payable, what assumption?]
- `block.timestamp`: [If used, what assumption?]
- [State variable]: [What assumption about its value?]

**Preconditions:**
1. [Condition that must be true before call]
2. [Another precondition]
3. [At least 3 preconditions]

**Documented Assumptions:**
1. [Assumption about input validity]
2. [Assumption about state]
3. [Assumption about external contracts]
4. [Assumption about caller behavior]
5. [At least 5 assumptions total]

---

### Outputs & Effects

**Returns:** `type` - Description of return value

**State Changes:**
1. `variable1` - How it changes
2. `variable2` - How it changes

**Events Emitted:**
- `EventName(param1, param2)` - When emitted

**External Calls:**
1. `target.method(args)` at Line XX
   - Payload: [describe]
   - Return handling: [describe]
   - Failure handling: [describe]

**Postconditions:**
1. [What must be true after successful execution]
2. [Another postcondition]
3. [At least 3 postconditions]

---

### Block-by-Block Analysis

#### Block 1: [Descriptive Name] (Lines XX-YY)

```solidity
// Paste the actual code block
```

**What:** [1-2 sentences on what this block does]

**Why Here:** [Why does this block appear at this position in the function?]

**Assumptions:**
- [Assumption this block relies on]
- [Another assumption]

**Invariant Maintained:** [What invariant does this establish or maintain?]

**Depends On:** [What previous blocks or state does this depend on?]

**Later Logic Depends On:** [What subsequent blocks depend on this?]

**First Principles / 5 Whys / 5 Hows:** (Apply at least one)
- Q: [The question]
- A: [The answer with reasoning]

---

#### Block 2: [Descriptive Name] (Lines XX-YY)

[Repeat same structure]

---

#### Block N: [Final Block] (Lines XX-YY)

[Repeat same structure]

---

### Invariants Identified

| # | Invariant | Maintained By | Violated If |
|---|-----------|---------------|-------------|
| 1 | [Invariant description] | Block X | [Condition] |
| 2 | [Invariant description] | Block Y | [Condition] |
| 3 | [Invariant description] | Block Z | [Condition] |

---

### Risk Analysis

| Risk | Likelihood | Impact | Current Mitigation | Status |
|------|------------|--------|-------------------|--------|
| [Risk 1] | Low/Med/High | Low/Med/High/Crit | [Mitigation or None] | // |
| [Risk 2] | Low/Med/High | Low/Med/High/Crit | [Mitigation or None] | // |
| [Risk 3] | Low/Med/High | Low/Med/High/Crit | [Mitigation or None] | // |

**Status Legend:**
-  Fully mitigated
-  Partially mitigated
-  Not mitigated

---

### Cross-References

**Calls (Internal):**
- `_helperFunction()` at Line XX - [Brief purpose]
- `_anotherHelper()` at Line YY - [Brief purpose]

**Calls (External):**
- `ExternalContract.method()` at Line XX - [Brief purpose and trust level]

**Called By:**
- `otherFunction()` in same contract
- `ExternalContract.caller()` (if applicable)

**Shares State With:**
- `functionA()` - Both read/write `stateVar`
- `functionB()` - Both read `anotherVar`

---

### Notes & Observations

**Concerns Identified:**
-  [Concern that warrants further investigation]
-  [Another concern]

**Questions for Protocol:**
-  [Question about intended behavior]
-  [Question about edge case handling]

**Positive Observations:**
-  [Good practice observed]
-  [Another positive pattern]

---

## Compact Template (For Simpler Functions)

```markdown
## Function: `simpleFn(param)`
**Lines:** XX-YY | **Visibility:** external | **Modifiers:** none

### Purpose
[1 sentence]

### Key Points
- **Input:** param (type) - [validation]
- **Output:** [return type and meaning]
- **State Change:** [what changes]
- **External Call:** [if any]

### Analysis
[Block-by-block in paragraph form for simple functions]

### Invariants
1. [Invariant]
2. [Invariant]
3. [Invariant]

### Risks
- [Risk]: [Mitigation status]

### Cross-Refs
- Calls: [list]
- Called by: [list]
```

---

## Usage Instructions

1. **Copy the full template** for complex functions (>20 lines, external calls, state changes)
2. **Use compact template** for simple getters, view functions, or trivial helpers
3. **Never skip sections** - write "N/A" if truly not applicable
4. **Always cite line numbers** - enables verification
5. **Mark uncertainties** with  or 
6. **Apply analytical methods** - at least one First Principles OR 5 Whys OR 5 Hows per function

