---
id: AUDIT-CTX-WF-DEEP
title: Deep Code Review Workflow
parent: audit-context-building
type: workflow
last_updated: 2025-01-31
---

# Deep Code Review Workflow

Function-by-function analysis after architecture context is complete. Every external and public function must be analyzed. This workflow uses the [Function Analysis Template](../resources/function-analysis-example.md).

---

## Prerequisites

Before starting deep code review:
- [ ] Architecture analysis completed (contract inventory, inheritance, interactions)
- [ ] All roles and permissions documented
- [ ] Token/value flows mapped
- [ ] Key invariants identified
- [ ] Risk areas prioritized

---

## Step 1: Build Function Inventory

List every external/public function across all in-scope contracts:

```bash
# Slither function summary (best)
slither . --print function-summary

# Manual grep
grep -rn "function " src/ --include="*.sol" | grep -E "external|public"

# Foundry
forge inspect ContractName methods
```

Organize into analysis table:

| Contract | Function | Visibility | Modifiers | Moves Value? | Priority |
|----------|----------|-----------|-----------|-------------|----------|
| Vault | `deposit(uint256,address)` | external | nonReentrant | YES | 1 |
| Vault | `withdraw(uint256,address,address)` | external | nonReentrant | YES | 1 |
| Vault | `setStrategy(address)` | external | onlyOwner | NO (indirect) | 2 |
| Vault | `totalAssets()` | public | view | NO | 6 |
| Strategy | `harvest()` | external | onlyVault | YES | 1 |

---

## Step 2: Priority-Ordered Analysis

Analyze functions in strict priority order:

### Priority 1: Functions That Move Tokens/ETH

These are the highest risk — direct path to fund loss.

**What to check:**
- Correct accounting (amount in = amount credited)
- CEI pattern (Checks-Effects-Interactions)
- Reentrancy protection
- Access control (who can trigger the transfer?)
- Edge cases: zero amount, max uint, self-transfer
- Fee-on-transfer / rebasing token handling
- Return value checking on external calls
- Slippage protection on swaps

**Common findings in Priority 1 functions:**

| Issue | Pattern |
|-------|---------|
| Missing reentrancy guard | `withdraw()` calls external token before updating state |
| Accounting mismatch | `deposited += amount` but actual received is less (fee-on-transfer) |
| Missing slippage check | `swap()` accepts any output amount |
| Unchecked transfer return | `token.transfer()` return value ignored |
| Flash loan exploitation | Price calculated within same tx can be manipulated |

### Priority 2: Functions That Modify Access Control

These can escalate to Priority 1 (change who controls funds).

**What to check:**
- Two-step ownership transfer (Ownable2Step preferred)
- Role grant/revoke events emitted
- Can admin grant themselves more power?
- Can roles be renounced? (Dangerous if admin renounces critical role)
- Timelock on role changes

### Priority 3: Functions Using Oracle Data

Oracle manipulation is a top attack vector in DeFi.

**What to check:**
- Staleness check (is `updatedAt` compared to `block.timestamp`?)
- Round completeness (`answeredInRound >= roundId`)
- Price bounds (reject negative or zero prices)
- Multi-oracle / fallback (what happens when oracle fails?)
- TWAP window size (short windows are manipulable)
- Flash loan resistance (can price be manipulated in same block?)

### Priority 4: Functions That Modify Protocol Parameters

**What to check:**
- Parameter bounds (can fee be set to 100%?)
- Timelock requirement
- Events emitted on parameter change
- Impact analysis: what does changing this parameter affect?
- Can parameter change be front-run by users?

### Priority 5: Complex State Transitions

**What to check:**
- State machine correctness (valid transitions only)
- Atomicity (partial state updates = inconsistency)
- Cross-function state consistency
- Reentrancy between related state-changing functions

### Priority 6: Initialization / Constructor

**What to check:**
- Initializer guard (`initializer` modifier for upgradeable)
- Can `initialize()` be called multiple times?
- Can it be front-run?
- All state variables set correctly
- Implementation contract initialized (prevent takeover)

### Priority 7: View / Pure Functions

**What to check:**
- Correct calculation logic
- Can return value be manipulated by flash loan?
- Is it used as input to state-changing functions? (if yes, higher risk)
- Division by zero
- Overflow/underflow in unchecked blocks

---

## Step 3: Per-Function Analysis

For each function, use the [analysis template](../resources/function-analysis-example.md):

```
### Contract.functionName(params)

**Basics**
- Visibility | Access | Modifiers | Payable

**State Changes**
- Reads | Writes | Order

**External Interactions**
- Calls | Transfers | Callbacks

**Events** - emitted

**Control Flow**
- CEI | Revert conditions | Branches

**Security Analysis**
- Reentrancy | Validation | Edge cases | Arithmetic

**Risk Level** | **Attack surface** | **Notes**
```

---

## Step 4: Cross-Function Analysis

After individual function analysis, check cross-function interactions:

| Check | What to Look For |
|-------|------------------|
| Cross-function reentrancy | Function A writes partial state, calls external, function B reads inconsistent state |
| State ordering dependencies | Function A must be called before B, but B can be called first |
| Shared state mutation | Functions A and B both modify same mapping — race condition? |
| Read-only reentrancy | View function returns wrong value during mid-execution of state-changing function |
| Privilege escalation chain | Low-privilege function feeds input to high-privilege function |

---

## Step 5: Modifier and Library Review

Review all modifiers and internal libraries:

```bash
grep -rn "modifier " src/ --include="*.sol"
```

| Modifier | Contract | Purpose | Correct? |
|----------|----------|---------|----------|
| `nonReentrant` | ReentrancyGuard | Prevents reentrancy | Check version |
| `whenNotPaused` | Pausable | Emergency stop | Check who pauses |
| `onlyOwner` | Ownable | Access control | Verify owner() |
| Custom modifier | Various | Custom logic | Analyze carefully |

---

## Step 6: Document Findings

For each issue found, document:

| Field | Content |
|-------|--------|
| Title | Descriptive name |
| Severity | Critical / High / Medium / Low / Info |
| Contract | Which contract |
| Function | Which function |
| Line | Line number |
| Description | What's wrong |
| Impact | What an attacker can do |
| PoC | Steps to reproduce or Foundry test |
| Recommendation | How to fix (with code diff if possible) |
