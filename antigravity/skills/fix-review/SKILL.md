# Fix Review Skill

## Purpose
Verify that bug fixes correctly address reported vulnerabilities without introducing new issues.

## Fix Review Checklist
- [ ] Fix addresses the root cause (not just the symptom)
- [ ] Fix doesn't introduce new vulnerabilities
- [ ] Fix doesn't break existing functionality
- [ ] Fix is minimal (no unnecessary changes)
- [ ] Edge cases covered by the fix
- [ ] Tests added for the specific vulnerability
- [ ] Related code paths reviewed for same vulnerability pattern

## Common Fix Review Issues
1. **Incomplete fix**: Addresses one variant but misses others
2. **Side effects**: Fix breaks another feature
3. **Regression**: Fix reverts to previous vulnerable state
4. **Over-fix**: Fix is too restrictive, blocking legitimate use
