# Fix Verification Patterns

## Overview

This directory contains detailed fix verification guides for specific vulnerability categories. Each guide includes:

- ✅ **Before/After Code Comparisons** - Vulnerable vs fixed code
- ✅ **Regression Test Templates** - Foundry tests to verify fixes
- ✅ **Fix Gone Wrong Examples** - Common mistakes when fixing
- ✅ **Verification Checklists** - Step-by-step validation

---

## Directory Structure

```
fix-patterns/
├── INDEX.md                           # This file
├── reentrancy-fix-verification.md     # Reentrancy fix patterns
├── oracle-fix-verification.md         # Oracle/price manipulation fixes
├── access-control-fix-verification.md # Access control fixes
```

---

## Quick Reference

| Vulnerability | Key Fix Pattern | Common Mistake |
|--------------|-----------------|----------------|
| Reentrancy | CEI + ReentrancyGuard | Only adding guard, not fixing CEI |
| Oracle Manipulation | TWAP + bounds | Window too short, no staleness check |
| Access Control | Role-based + 2-step | Missing function, wrong modifier |

---

## Related Resources

- [Fix Verification Methodology](../methodology/fix-verification-patterns.md)
- [Reentrancy Anti-Patterns](../patterns/reentrancy-antipatterns.md)
- [Oracle Anti-Patterns](../patterns/oracle-antipatterns.md)
- [Access Control Anti-Patterns](../patterns/access-control-antipatterns.md)

---

## Usage

When reviewing a fix:

1. **Identify the vulnerability type** from the original finding
2. **Load the corresponding fix-verification guide**
3. **Run the regression test template** with the original PoC
4. **Check for "fix gone wrong" patterns**
5. **Complete the verification checklist**

```bash
# Example: Reviewing a reentrancy fix
1. Read fix-patterns/reentrancy-fix-verification.md
2. Copy regression test template
3. Adapt original PoC to new code
4. Verify CEI pattern is correct
5. Check for cross-function reentrancy
```
