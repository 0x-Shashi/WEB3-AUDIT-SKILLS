# Skill Chains Skill

## Purpose
Skill chains define ordered sequences of individual audit skills to execute for different audit depth levels. They ensure comprehensive, systematic coverage appropriate to the engagement scope.

## Available Chains

| Chain | Duration | Depth | Use Case |
|-------|----------|-------|----------|
| [Quick Scan](quick-scan-chain.md) | 1-2 hours | Surface | Initial assessment, triage |
| [Deep Dive](deep-dive-chain.md) | 1-2 days | Focused | Specific contract/module analysis |
| [Full Audit](full-audit-chain.md) | 1-2 weeks | Comprehensive | Complete protocol audit |

## Chain Selection Guide
```
Time < 2 hours?  → Quick Scan
Focused on specific area? → Deep Dive
Full engagement? → Full Audit
```

## Design Principles
1. **Progressive Depth**: Each chain level includes all previous levels plus more
2. **Exit Early**: If critical issue found, can escalate from Quick Scan to Deep Dive
3. **Composable**: Deep Dive can be run on specific modules identified by Quick Scan
4. **Reproducible**: Same chain on same code produces same coverage
