# Web3 Audit Skills - Master Index

> **For AI Assistants**: This is the master index for all smart contract auditing skills. Use this file to navigate to specific skill areas when helping users with audit tasks.

## Quick Navigation

```
skills/
├── patterns/           # Vulnerability patterns & detection
├── checklists/         # Audit checklists
└── methodology/        # Audit workflow & processes
```

---

## 🔍 Vulnerability Patterns

### Core Patterns
| Skill File | Description | Use When |
|------------|-------------|----------|
| [vulnerability-patterns.md](patterns/vulnerability-patterns.md) | 30+ Solidity patterns with regex/descriptions | General vulnerability detection |
| [vulnerability-taxonomy.md](patterns/vulnerability-taxonomy.md) | 14 categories, SWC/CWE mappings | Classifying findings |
| [severity-scoring.md](patterns/severity-scoring.md) | CVSS-like scoring (0-10 scale) | Determining severity |

### DeFi Patterns
| Skill File | Description | Use When |
|------------|-------------|----------|
| [defi-vulnerabilities.md](patterns/defi-vulnerabilities.md) | Pool, oracle, lending, token patterns | Auditing DeFi protocols |
| [protocol-specific-patterns.md](patterns/protocol-specific-patterns.md) | GMX, Synthetix, AMM, vault patterns | Protocol-specific audits |

### Platform-Specific
| Skill File | Description | Use When |
|------------|-------------|----------|
| [l2-security.md](patterns/l2-security.md) | Arbitrum, Optimism, zkSync, Base | Auditing L2 deployments |
| [bridge-security.md](patterns/bridge-security.md) | Bridge attacks, message validation | Auditing cross-chain bridges |
| [evm-gas-dos.md](patterns/evm-gas-dos.md) | Gas, DoS, context vulnerabilities | EVM-specific issues |

### Testing
| Skill File | Description | Use When |
|------------|-------------|----------|
| [invariant-testing.md](patterns/invariant-testing.md) | Foundry invariant test templates | Writing fuzz/invariant tests |

---

## ✅ Checklists

| Skill File | Description | Use When |
|------------|-------------|----------|
| [comprehensive-checklist.md](checklists/comprehensive-checklist.md) | 50+ items with SWC codes | Complete audit review |

---

## 📋 Methodology

| Skill File | Description | Use When |
|------------|-------------|----------|
| [llm-audit-workflow.md](methodology/llm-audit-workflow.md) | 5-phase LLM audit, SCAN modes | Conducting AI-assisted audits |
| [learning-path-attack-vectors.md](methodology/learning-path-attack-vectors.md) | Top attack vectors, career path | Learning/reference |

---

## Skill Selection Guide

### By Task Type

**"Find vulnerabilities in this contract"**
1. Start with → [vulnerability-patterns.md](patterns/vulnerability-patterns.md)
2. Check DeFi-specific → [defi-vulnerabilities.md](patterns/defi-vulnerabilities.md)
3. Use checklist → [comprehensive-checklist.md](checklists/comprehensive-checklist.md)

**"Audit this L2 protocol"**
1. L2 patterns → [l2-security.md](patterns/l2-security.md)
2. General patterns → [vulnerability-patterns.md](patterns/vulnerability-patterns.md)
3. If bridge → [bridge-security.md](patterns/bridge-security.md)

**"Help me understand this finding severity"**
1. Scoring guide → [severity-scoring.md](patterns/severity-scoring.md)
2. Taxonomy → [vulnerability-taxonomy.md](patterns/vulnerability-taxonomy.md)

**"Write invariant tests for this protocol"**
1. Templates → [invariant-testing.md](patterns/invariant-testing.md)
2. DeFi invariants → [defi-vulnerabilities.md](patterns/defi-vulnerabilities.md)

**"Conduct a full audit"**
1. Workflow → [llm-audit-workflow.md](methodology/llm-audit-workflow.md)
2. Checklist → [comprehensive-checklist.md](checklists/comprehensive-checklist.md)
3. Protocol type → [protocol-specific-patterns.md](patterns/protocol-specific-patterns.md)

---

## Pattern Quick Reference

### Critical Vulnerabilities
- Reentrancy → [vulnerability-patterns.md#reentrancy](patterns/vulnerability-patterns.md)
- Access Control → [vulnerability-patterns.md#access-control](patterns/vulnerability-patterns.md)
- Oracle Manipulation → [defi-vulnerabilities.md#oracle](patterns/defi-vulnerabilities.md)
- Bridge Replay → [bridge-security.md](patterns/bridge-security.md)

### High Vulnerabilities
- Integer Overflow → [vulnerability-patterns.md#arithmetic](patterns/vulnerability-patterns.md)
- Flash Loan Attacks → [defi-vulnerabilities.md#flash-loan](patterns/defi-vulnerabilities.md)
- L2 Sequencer → [l2-security.md#sequencer](patterns/l2-security.md)
- Signature Replay → [bridge-security.md#signature](patterns/bridge-security.md)

### Medium Vulnerabilities
- Centralization → [learning-path-attack-vectors.md](methodology/learning-path-attack-vectors.md)
- DoS → [evm-gas-dos.md#dos](patterns/evm-gas-dos.md)
- Weak Randomness → [vulnerability-patterns.md#randomness](patterns/vulnerability-patterns.md)

---

## Integration Instructions

### For Claude Code
```bash
# Point Claude to skills when reviewing contracts
"Using the skills in skills/patterns/, audit this contract for vulnerabilities"
```

### For Cursor
```
# Add to .cursorrules
When auditing smart contracts, reference skills/ folder for patterns and checklists.
```

### For Any AI
```
Before auditing, read:
1. skills/INDEX.md (this file)
2. Relevant pattern files for the protocol type
3. skills/checklists/comprehensive-checklist.md for full coverage
```

---

## File Statistics

| Category | Files | Total Patterns |
|----------|-------|----------------|
| Patterns | 9 | 200+ |
| Checklists | 1 | 50+ items |
| Methodology | 2 | 5 phases |
| **Total** | **12** | **250+** |

---

## Changelog

### v1.0 - Initial Release
- Extracted patterns from ETAAcademy-Audit (10 DeFi categories)
- Extracted from SmartContracts-audit-checklist (50+ items)
- Extracted from audit-assistant-playbook (LLM workflow)
- Extracted from Cyfrin security course (attack vectors)
- Created protocol patterns from 50+ real audits (GMX, Synthetix, etc.)
- Added L2, bridge, invariant testing skills
- Created comprehensive index

---

## Contributing

To add new skills:
1. Create markdown file in appropriate folder
2. Use consistent header structure
3. Include "AI Skill" note at top
4. Add "Audit Prompt" sections
5. Cross-reference related skills
6. Update this INDEX.md

---

## Related Resources

**External**:
- [Solodit](https://solodit.xyz) - Finding database
- [SWC Registry](https://swcregistry.io) - Vulnerability classification
- [Rekt News](https://rekt.news) - Exploit analysis

**Internal REPO Reference** (in parent folder):
- `REPO/Audits/` - 50+ real audit PDFs
- `REPO/ETAAcademy-Audit/` - DeFi patterns with PoCs
- `REPO/security-and-auditing-full-course-s23/` - Cyfrin course
