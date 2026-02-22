# How It Works

## System Architecture

Web3 Audit Skills is a multi-layered system that combines AI capabilities with structured security knowledge to perform smart contract audits.

```
┌─────────────────────────────────────────────┐
│              AI Platform Layer              │
│    (Claude Code / Cursor / Antigravity)     │
├─────────────────────────────────────────────┤
│              Skills Layer                   │
│  ┌─────────┐ ┌──────────┐ ┌─────────────┐  │
│  │Scanners │ │Checklists│ │  Templates  │  │
│  │(per     │ │(per      │ │(per protocol│  │
│  │ chain)  │ │ protocol)│ │   type)     │  │
│  └─────────┘ └──────────┘ └─────────────┘  │
│  ┌─────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ Attack  │ │ Variant  │ │   Report    │  │
│  │ Chains  │ │ Analysis │ │   Writer    │  │
│  └─────────┘ └──────────┘ └─────────────┘  │
├─────────────────────────────────────────────┤
│           Intelligence Core                 │
│  Pattern Matcher | Severity Scorer          │
│  Classifier | Semantic Search               │
├─────────────────────────────────────────────┤
│           Data Layer                        │
│  Cyfrin Findings | Solodit Patterns         │
│  Vulnerability DB | Chain Guides            │
└─────────────────────────────────────────────┘
```

## Audit Flow

### 1. Context Detection
When given a codebase, the system:
- Identifies the blockchain platform (Solidity, Rust/Anchor, Cairo, Move, etc.)
- Detects the protocol type (lending, DEX, bridge, staking, governance, NFT)
- Loads appropriate scanners, checklists, and templates

### 2. Static Analysis
Automated tools run first:
- **Slither**: Fast pattern-based detection for Solidity
- **Mythril**: Symbolic execution for deeper path analysis
- **Aderyn**: Modern Rust-based scanner
- Results are triaged: True Positive / False Positive with reasoning

### 3. Pattern Matching
The intelligence module compares code against known vulnerability patterns:
- 200+ patterns from real exploits ($10B+ in historical losses)
- Categorized by vulnerability class (reentrancy, oracle, access control, etc.)
- Severity pre-scored based on historical impact

### 4. Manual Review Guidance
The AI guides manual review using:
- **Protocol-specific checklists**: Every relevant check for the protocol type
- **Attack chain analysis**: Multi-step exploit sequences to verify
- **Function-by-function workflow**: Systematic line-by-line review methodology

### 5. Variant Analysis
When a vulnerability is found:
- The pattern is abstracted to its root cause
- The entire codebase is searched for variants
- Historical databases are checked for the same pattern class
- All instances are reported as a single root-cause finding

### 6. Report Generation
Findings are formatted using standardized templates:
- Title, severity, location, description
- Impact assessment and exploitability
- Proof of concept steps
- Remediation recommendation

## Key Design Decisions

### Why Skills-Based Architecture?
Skills are modular, composable, and platform-agnostic. The same vulnerability knowledge works across Claude Code, Cursor, and Antigravity without duplication.

### Why Chain-Specific Scanners?
Each blockchain has unique security properties. Solidity reentrancy is irrelevant to Solana. Move's type system prevents certain bugs. Chain-specific scanners focus on what actually matters per platform.

### Why Attack Chains?
Real exploits are rarely single-bug. The $624M Ronin hack combined social engineering + key management + threshold bypass. Attack chains model how vulnerabilities combine into actual exploits.

### Why Historical Data Integration?
Learning from past exploits is the most efficient way to find similar bugs. The Cyfrin findings database and Solodit patterns provide thousands of real audit findings to match against.
