# Differential Audit Workflow

## Steps
1. **Diff generation**: Get git diff between versions
2. **Change classification**: Categorize changes (logic, config, deps, formatting)
3. **Impact assessment**: For each logic change, assess security impact
4. **New code audit**: Full audit of newly added functions
5. **Modified code audit**: Verify changes don't break existing invariants
6. **Removed code**: Check if removed code was security-critical
7. **Storage layout**: Verify compatibility for upgradeable contracts
8. **Integration test**: Verify unchanged code still works with changes
9. **Report**: Document changes and their security implications
