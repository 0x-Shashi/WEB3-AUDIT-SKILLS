---
name: web3-audit
description: "Master orchestrator for Web3 smart contract security auditing. Routes to specialized skills based on task: vulnerability scanning, findings research, deep context analysis, token security, spec compliance, static analysis, and audit reporting. Use as the primary entry point for any blockchain security task."
---

# Web3 Audit Plugin - Master Skill

## Purpose

I am the central orchestrator for comprehensive Web3 security auditing. I route your requests to the most appropriate specialized skill based on your task.

## Skill Selection Matrix

### What Are You Trying to Do?

| Your Goal | Recommended Skill | Trigger Phrases |
|-----------|-------------------|-----------------|
| Research vulnerabilities | `cyfrin-findings` | "find vulnerabilities", "query Solodit", "research attacks" |
| Deep code understanding | `audit-context-building` | "analyze this code", "line-by-line", "understand this function" |
| Scan Solidity/EVM | `solidity-scanner` | "scan Solidity", "EVM vulnerabilities", "check this contract" |
| Scan Solana | `solana-scanner` | "Solana security", "Anchor program", "CPI check" |
| Scan Cairo | `cairo-scanner` | "StarkNet", "Cairo contract", "felt overflow" |
| Scan Move | `move-scanner` | "Aptos", "Sui", "Move contract" |
| Scan Cosmos | `cosmos-scanner` | "Cosmos SDK", "IBC", "keeper security" |
| Scan TON | `ton-scanner` | "TON contract", "FunC", "message handling" |
| Check token security | `token-integration` | "ERC20", "token integration", "weird tokens" |
| Verify spec compliance | `spec-compliance` | "whitepaper", "spec to code", "compliance" |
| Run static analysis | `static-analysis` | "Slither", "Echidna", "Semgrep", "fuzzing" |
| Find similar bugs | `variant-analysis` | "find similar", "variant", "pattern search" |
| Review fix commits | `fix-review` | "verify fix", "check remediation", "fix correct" |
| Review PR security | `differential-review` | "PR review", "diff review", "code change" |
| Write audit report | `audit-report-writer` | "generate report", "write finding", "audit report" |

---

## Quick Start Workflows

### Workflow 1: Full Contract Audit

```
Step 1: Deep Context Building
"Perform ultra-granular analysis of this contract to understand its architecture"

Step 2: Vulnerability Research  
"Query Cyfrin Solodit for vulnerabilities relevant to this [lending/DEX/staking] protocol"

Step 3: Automated Scanning
"Run Slither and check for the patterns found in the research"

Step 4: Manual Review
"Scan for [reentrancy/oracle/access-control] vulnerabilities"

Step 5: Report Generation
"Generate a professional audit report with all findings"
```

### Workflow 2: Quick Security Check

```
"Scan this Solidity contract for HIGH severity vulnerabilities"
```

### Workflow 3: Pre-Development Research

```
"Query Solodit for the top 10 vulnerabilities in lending protocols, then show me prevention patterns"
```

### Workflow 4: PR Security Review

```
"Perform a differential security review on this PR focusing on authentication changes"
```

---

## Decision Tree

```
START
  │
  ├─► Need to understand code deeply first?
  │     └─► Use: audit-context-building
  │
  ├─► Want to learn from real audit findings?
  │     └─► Use: cyfrin-findings
  │
  ├─► Need to scan for vulnerabilities?
  │     │
  │     ├─► Solidity/EVM? → solidity-scanner
  │     ├─► Solana/Anchor? → solana-scanner  
  │     ├─► Cairo/StarkNet? → cairo-scanner
  │     ├─► Move/Aptos/Sui? → move-scanner
  │     ├─► Cosmos SDK? → cosmos-scanner
  │     └─► TON/FunC? → ton-scanner
  │
  ├─► Working with tokens?
  │     └─► Use: token-integration
  │
  ├─► Verifying implementation matches spec?
  │     └─► Use: spec-compliance
  │
  ├─► Need automated tooling?
  │     └─► Use: static-analysis
  │
  ├─► Looking for similar bugs?
  │     └─► Use: variant-analysis
  │
  ├─► Reviewing audit fixes?
  │     └─► Use: fix-review
  │
  ├─► Reviewing code changes/PRs?
  │     └─► Use: differential-review
  │
  └─► Need to write report?
        └─► Use: audit-report-writer
```

---

## Platform Detection

I automatically detect the blockchain platform from your code:

### Solidity/EVM Indicators
```solidity
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/...";
contract MyContract { }
```

### Solana/Anchor Indicators
```rust
use anchor_lang::prelude::*;
#[program]
pub mod my_program { }
```

### Cairo/StarkNet Indicators
```cairo
#[starknet::contract]
mod MyContract { }
use starknet::ContractAddress;
```

### Move Indicators
```move
module my_address::my_module {
    use std::signer;
    struct MyResource has key { }
}
```

### Cosmos SDK Indicators
```go
import "github.com/cosmos/cosmos-sdk/..."
type Keeper struct { }
```

### TON/FunC Indicators
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body)
```

---

## Severity Classification

I use consistent severity levels across all skills:

| Severity | Definition | Example |
|----------|------------|---------|
| **CRITICAL** | Direct fund loss, protocol takeover | Reentrancy draining funds |
| **HIGH** | Significant value at risk | Oracle manipulation |
| **MEDIUM** | Limited impact or conditional | DoS under specific conditions |
| **LOW** | Minor issues, gas inefficiency | Missing event emissions |
| **INFORMATIONAL** | Best practices, suggestions | Code style improvements |

---

## Cross-Skill Integration

Skills work together seamlessly:

### Context → Scan → Report
1. `audit-context-building` builds mental model
2. `solidity-scanner` finds vulnerabilities
3. `audit-report-writer` generates report

### Research → Scan → Verify
1. `cyfrin-findings` identifies relevant patterns
2. `solidity-scanner` checks for patterns
3. `fix-review` verifies remediation

### Spec → Code → Compliance
1. `spec-compliance` extracts requirements
2. `audit-context-building` analyzes implementation
3. Gap analysis and findings

---

## 📚 Comprehensive Knowledge Base (NEW)

### Master Index
Start here for all patterns: [INDEX.md](INDEX.md)

### Vulnerability Patterns (250+)
| Skill File | Use For |
|------------|---------|
| [patterns/vulnerability-patterns.md](patterns/vulnerability-patterns.md) | 30+ Solidity patterns with regex |
| [patterns/vulnerability-taxonomy.md](patterns/vulnerability-taxonomy.md) | SWC/CWE classification |
| [patterns/severity-scoring.md](patterns/severity-scoring.md) | CVSS-like 0-10 scoring |
| [patterns/defi-vulnerabilities.md](patterns/defi-vulnerabilities.md) | Pool, oracle, lending, token |
| [patterns/protocol-specific-patterns.md](patterns/protocol-specific-patterns.md) | GMX, Synthetix, AMM, vault |
| [patterns/l2-security.md](patterns/l2-security.md) | Arbitrum, Optimism, zkSync, Base |
| [patterns/bridge-security.md](patterns/bridge-security.md) | Cross-chain, replay attacks |
| [patterns/evm-gas-dos.md](patterns/evm-gas-dos.md) | Gas, DoS, L1↔L2 |
| [patterns/invariant-testing.md](patterns/invariant-testing.md) | Foundry fuzz/invariant templates |

### Checklists
| Skill File | Use For |
|------------|---------|
| [checklists/comprehensive-checklist.md](checklists/comprehensive-checklist.md) | 50+ items with SWC codes |

### Methodology
| Skill File | Use For |
|------------|---------|
| [methodology/llm-audit-workflow.md](methodology/llm-audit-workflow.md) | 5-phase LLM audit, SCAN modes |
| [methodology/learning-path-attack-vectors.md](methodology/learning-path-attack-vectors.md) | Top 10 attack vectors |

---

## Best Practices

### DO:
- Start with `audit-context-building` for complex codebases
- Query `cyfrin-findings` for protocol-specific patterns
- Use automated scanning before manual review
- Document findings immediately in report format
- Verify fixes don't introduce new issues

### DON'T:
- Skip context building and jump to vulnerability hunting
- Ignore platform-specific vulnerability patterns
- Rely solely on automated tools
- Rush the analysis process
- Submit findings without verification

---

## Getting Help

If unsure which skill to use, just describe your task:

> "I need to audit a Solana lending protocol before it goes to mainnet"

I'll recommend:
1. Start with `audit-context-building` for architecture understanding
2. Query `cyfrin-findings` for lending + Solana patterns
3. Run `solana-scanner` for platform-specific issues
4. Use `token-integration` for SPL token handling
5. Generate report with `audit-report-writer`

---

## Skill Index

### Core Skills
- [cyfrin-findings](cyfrin-findings/SKILL.md) - 50,000+ real audit findings
- [audit-context-building](audit-context-building/SKILL.md) - Deep code analysis
- [audit-report-writer](audit-report-writer/SKILL.md) - Report generation

### Vulnerability Scanners
- [solidity-scanner](vulnerability-scanners/solidity-scanner/SKILL.md)
- [solana-scanner](vulnerability-scanners/solana-scanner/SKILL.md)
- [cairo-scanner](vulnerability-scanners/cairo-scanner/SKILL.md)
- [move-scanner](vulnerability-scanners/move-scanner/SKILL.md)
- [cosmos-scanner](vulnerability-scanners/cosmos-scanner/SKILL.md)
- [ton-scanner](vulnerability-scanners/ton-scanner/SKILL.md)

### Specialized Analysis
- [token-integration](token-integration/SKILL.md)
- [spec-compliance](spec-compliance/SKILL.md)
- [static-analysis](static-analysis/SKILL.md)
- [variant-analysis](variant-analysis/SKILL.md)
- [fix-review](fix-review/SKILL.md)
- [differential-review](differential-review/SKILL.md)
