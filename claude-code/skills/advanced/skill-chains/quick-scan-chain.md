# Quick Scan Chain

## Overview

Fast initial assessment to identify obvious issues and prioritize further review.

**Duration:** 30-60 minutes  
**Output:** Initial risk assessment with high-priority findings

---

## When to Use

- First look at new codebase
- Time-constrained review
- Triage before full audit
- Competition scouting
- Quick sanity check

---

## Chain Steps

```
┌────────────────────────────────────────────────────────────────┐
│                    QUICK SCAN CHAIN                             │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 1: Auto-Detect                               [5 min]     │
│  ├─ Identify chain/language                                    │
│  ├─ Count files/lines                                          │
│  └─ Identify framework                                         │
│                                                                 │
│  Step 2: High-Priority Patterns                    [15 min]    │
│  ├─ Critical vulnerability patterns only                       │
│  ├─ Known exploit signatures                                   │
│  └─ Red flag detection                                         │
│                                                                 │
│  Step 3: Attack Surface Map                        [10 min]    │
│  ├─ External entry points                                      │
│  ├─ Value handling functions                                   │
│  └─ Privileged functions                                       │
│                                                                 │
│  Step 4: Quick Report                              [5 min]     │
│  └─ Summary of findings and recommendations                    │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Auto-Detect

**Commands:**

```bash
# Count codebase size
echo "=== Codebase Size ==="
find . -name "*.sol" -o -name "*.rs" -o -name "*.move" | wc -l
find . -name "*.sol" -o -name "*.rs" -o -name "*.move" | xargs wc -l 2>/dev/null | tail -1

# Detect chain
echo "=== Chain Detection ==="
if ls *.sol 2>/dev/null || ls contracts/*.sol 2>/dev/null; then
    echo "Chain: EVM/Solidity"
elif grep -q "anchor" Cargo.toml 2>/dev/null; then
    echo "Chain: Solana"
elif ls *.cairo 2>/dev/null; then
    echo "Chain: Starknet"
fi

# Detect framework
echo "=== Framework Detection ==="
if [ -f "hardhat.config.js" ] || [ -f "hardhat.config.ts" ]; then
    echo "Framework: Hardhat"
elif [ -f "foundry.toml" ]; then
    echo "Framework: Foundry"
fi
```

---

## Step 2: High-Priority Patterns

Run only the most critical checks:

### Critical Checks (Solidity)

```bash
echo "=== CRITICAL: Reentrancy ==="
grep -rn "\.call{value" --include="*.sol"

echo "=== CRITICAL: Unprotected Functions ==="
grep -rn "function.*external\|function.*public" --include="*.sol" | grep -v "onlyOwner\|require\|modifier"

echo "=== CRITICAL: Arbitrary Calls ==="
grep -rn "\.call\(.*\)" --include="*.sol"
grep -rn "delegatecall" --include="*.sol"

echo "=== CRITICAL: Self-destruct ==="
grep -rn "selfdestruct\|suicide" --include="*.sol"

echo "=== CRITICAL: tx.origin ==="
grep -rn "tx.origin" --include="*.sol"

echo "=== HIGH: Unchecked Math ==="
grep -rn "unchecked" --include="*.sol"

echo "=== HIGH: External Calls ==="
grep -rn "\.transfer\|\.send" --include="*.sol"

echo "=== HIGH: Price Oracle ==="
grep -rn "getReserves\|getPrice" --include="*.sol" | grep -v "TWAP"
```

---

## Step 3: Attack Surface Map

```bash
echo "=== Entry Points ==="
grep -rn "function.*external\|function.*public" --include="*.sol" | wc -l

echo "=== Value Functions ==="
grep -rn "payable\|transfer\|\.call{value" --include="*.sol"

echo "=== Admin Functions ==="
grep -rn "onlyOwner\|onlyAdmin\|onlyRole" --include="*.sol"

echo "=== Upgradability ==="
grep -rn "upgradeTo\|_setImplementation\|Proxy" --include="*.sol"

echo "=== External Dependencies ==="
grep -rn "import.*@openzeppelin\|import.*@chainlink" --include="*.sol"
```

---

## Step 4: Quick Report Template

```markdown
# Quick Scan Report

## Codebase Overview
- Chain: [detected]
- Language: [detected]
- Files: [count]
- Lines: [count]
- Framework: [detected]

## Risk Level: [LOW/MEDIUM/HIGH/CRITICAL]

## Immediate Concerns
1. [Issue if found]
2. [Issue if found]

## Attack Surface Summary
- External functions: [count]
- Value-handling functions: [count]
- Admin functions: [count]
- Upgradeable: [yes/no]

## Recommendations
- [ ] [Next step based on findings]
- [ ] [Areas needing deeper review]

## Time for Full Audit: [estimate]
```

---

## Red Flags Quick Reference

### Instant Critical
- `selfdestruct` usage
- `delegatecall` to user input
- Unprotected ETH transfers
- `tx.origin` authentication

### Likely High
- No reentrancy guards
- Spot price oracles
- Unchecked external calls
- No access control

### Common Medium
- Missing slippage protection
- No deadline checks
- Centralization risks
- Missing events

---

## One-Liner Full Scan

Run this for instant overview:

```bash
echo "=== QUICK SCAN ===" && \
echo "Files: $(find . -name '*.sol' | wc -l)" && \
echo "Lines: $(find . -name '*.sol' | xargs wc -l 2>/dev/null | tail -1)" && \
echo "=== RED FLAGS ===" && \
echo "selfdestruct: $(grep -rn 'selfdestruct' --include='*.sol' | wc -l)" && \
echo "delegatecall: $(grep -rn 'delegatecall' --include='*.sol' | wc -l)" && \
echo "tx.origin: $(grep -rn 'tx.origin' --include='*.sol' | wc -l)" && \
echo "call{value: $(grep -rn '.call{value' --include='*.sol' | wc -l)" && \
echo "=== COUNTS ===" && \
echo "External funcs: $(grep -rn 'external' --include='*.sol' | wc -l)" && \
echo "Payable funcs: $(grep -rn 'payable' --include='*.sol' | wc -l)" && \
echo "onlyOwner: $(grep -rn 'onlyOwner' --include='*.sol' | wc -l)"
```

---

## Output Format

After quick scan, output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QUICK SCAN COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Level: 🔴 HIGH

Critical Issues Found:
  ❌ Reentrancy patterns detected (3)
  ❌ Spot price oracle usage (2)

Attack Surface:
  📍 47 external functions
  💰 12 value-handling functions
  👑 8 admin functions

Recommendation:
  → Full audit required
  → Prioritize: Reentrancy, Oracle manipulation

Estimated Full Audit Time: 6-8 hours
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
