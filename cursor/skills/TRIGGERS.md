# AI Trigger Phrases (TRIGGERS.md)

Maps user phrases → AI loads specific skill files. When a user says certain keywords, the AI assistant knows exactly which files to load.

---

## How This Works

When a user asks a question, the AI checks this file to see if any trigger phrases match. If yes, it loads the referenced files to provide expert-level answers.

**Example:**
```
User: "I need to audit a lending protocol"
AI sees: "audit lending" → Loads ROUTE-MAP.md, lending-attack-tree.md, lending-pool-patterns.md
AI responds with comprehensive lending audit guidance
```

---

## Trigger Mapping

### Audit Initiation

| User Says | AI Loads |
|-----------|----------|
| "audit this" | ROUTE-MAP.md, MASTER_CHECKLIST.md |
| "start an audit" | ROUTE-MAP.md, audit-context-building/ |
| "how do I audit" | ROUTE-MAP.md, methodology/llm-audit-workflow.md |
| "audit workflow" | ROUTE-MAP.md, methodology/llm-audit-workflow.md |
| "audit methodology" | methodology/llm-audit-workflow.md, ROUTE-MAP.md |

---

### Protocol-Specific Audits

| User Says | AI Loads |
|-----------|----------|
| **Lending Protocols** |
| "audit lending", "audit compound fork" | attack-trees/lending-attack-tree.md, patterns/lending-pool-patterns.md, patterns/oracle-patterns.md |
| "audit aave fork", "audit borrowing" | attack-trees/lending-attack-tree.md, patterns/lending-pool-patterns.md |
| "liquidation issues" | attack-trees/lending-attack-tree.md#[B], patterns/lending-pool-patterns.md#liquidation |
| **DEX/AMM** |
| "audit dex", "audit amm", "audit uniswap" | attack-trees/dex-attack-tree.md, patterns/dex-patterns.md |
| "audit uniswap v3", "concentrated liquidity" | attack-trees/dex-attack-tree.md#[E], patterns/uniswap-v3-patterns.md |
| "audit curve", "stableswap" | attack-trees/dex-attack-tree.md, patterns/curve-patterns.md |
| "lp token issues" | attack-trees/dex-attack-tree.md#[B], patterns/defi-vault-patterns.md#lp-pricing |
| **Bridges** |
| "audit bridge", "cross-chain audit" | attack-trees/bridge-attack-tree.md, patterns/bridge-patterns.md, patterns/signature-patterns.md |
| "audit wormhole", "audit layerzero" | attack-trees/bridge-attack-tree.md, patterns/bridge-patterns.md |
| "signature issues", "validator issues" | attack-trees/bridge-attack-tree.md#[A], patterns/signature-patterns.md |
| **Vaults/Yield** |
| "audit vault", "audit yield aggregator" | attack-trees/vault-attack-tree.md, patterns/defi-vault-patterns.md |
| "audit yearn", "audit beefy" | attack-trees/vault-attack-tree.md, patterns/defi-vault-patterns.md, patterns/strategy-patterns.md |
| "erc4626 audit" | attack-trees/vault-attack-tree.md#[E], patterns/erc4626-patterns.md |
| "strategy issues" | attack-trees/vault-attack-tree.md#[B], patterns/strategy-patterns.md |

---

### Vulnerability-Specific

| User Says | AI Loads |
|-----------|----------|
| **Oracle Issues** |
| "oracle manipulation", "price oracle issues" | patterns/oracle-patterns.md, anti-patterns/oracle-anti-patterns.md, XREF.md#oracle |
| "spot price attack", "flash loan oracle" | anti-patterns/oracle-anti-patterns.md#1, attack-trees/lending-attack-tree.md#[A2] |
| "stale oracle", "oracle not updating" | anti-patterns/oracle-anti-patterns.md#2, patterns/oracle-patterns.md#staleness |
| "chainlink integration" | patterns/oracle-patterns.md#chainlink, patterns/chainlink-patterns.md |
| **Reentrancy** |
| "reentrancy", "reenter" | patterns/reentrancy-patterns.md, anti-patterns/reentrancy-anti-patterns.md, XREF.md#reentrancy |
| "read-only reentrancy", "view function reentrancy" | anti-patterns/reentrancy-anti-patterns.md#3, attack-trees/lending-attack-tree.md#[D3] |
| "erc777 issues", "erc777 attack" | anti-patterns/reentrancy-anti-patterns.md#4, patterns/token-patterns.md#erc777 |
| "cross-function reentrancy" | anti-patterns/reentrancy-anti-patterns.md#2, patterns/reentrancy-patterns.md#cross-function |
| **Access Control** |
| "access control issues", "authorization" | patterns/access-control-patterns.md, anti-patterns/access-control-anti-patterns.md |
| "unprotected initialize", "initialize front-run" | anti-patterns/access-control-anti-patterns.md#1, XREF.md |
| "missing onlyOwner", "missing modifier" | anti-patterns/access-control-anti-patterns.md#2 |
| "tx.origin issues", "tx.origin auth" | anti-patterns/access-control-anti-patterns.md#3, patterns/access-control-patterns.md#tx-origin |
| **First Depositor** |
| "first depositor", "inflation attack" | anti-patterns/oracle-anti-patterns.md#5, patterns/defi-vault-patterns.md#first-depositor, attack-trees/vault-attack-tree.md#[A1] |
| "share price manipulation", "donate to pool" | patterns/defi-vault-patterns.md#donation-attack, attack-trees/vault-attack-tree.md#[A] |

---

### Attack Research

| User Says | AI Loads |
|-----------|----------|
| "euler hack", "euler exploit" | XREF.md#euler, attack-trees/lending-attack-tree.md#[B2] |
| "wormhole hack", "wormhole exploit" | XREF.md#wormhole, attack-trees/bridge-attack-tree.md |
| "the dao hack", "dao reentrancy" | XREF.md#dao, anti-patterns/reentrancy-anti-patterns.md#1 |
| "ronin hack", "ronin bridge" | XREF.md#ronin, attack-trees/bridge-attack-tree.md#[A5] |
| "poly network hack" | XREF.md#poly, anti-patterns/access-control-anti-patterns.md#2 |
| "recent exploits", "latest hacks" | XREF.md#by-real-exploit |

---

### Learning Paths

| User Says | AI Loads |
|-----------|----------|
| "learn auditing", "how to become auditor" | methodology/learning-path-attack-vectors.md, ROUTE-MAP.md |
| "attack vectors", "common vulnerabilities" | methodology/learning-path-attack-vectors.md, XREF.md |
| "defi patterns" | patterns/INDEX.md, patterns/lending-pool-patterns.md, patterns/dex-patterns.md |
| "bad code examples", "what not to do" | anti-patterns/INDEX.md |
| "attack trees", "attack paths" | attack-trees/INDEX.md |

---

### Tool-Specific

| User Says | AI Loads |
|-----------|----------|
| "slither scan", "static analysis" | static-analysis/, commands/slither-commands.md |
| "foundry test", "write foundry test" | commands/foundry-commands.md |
| "aderyn scan", "aderyn" | static-analysis/, commands/aderyn-commands.md |
| "mythril scan" | static-analysis/, commands/mythril-commands.md |

---

### Checklist Requests

| User Says | AI Loads |
|-----------|----------|
| "audit checklist", "what should I check" | MASTER_CHECKLIST.md, checklists/comprehensive-checklist.md |
| "pre-deployment checklist" | checklists/roles/developer-pre-deployment.md |
| "first pass", "quick scan" | checklists/roles/auditor-first-pass.md |
| "integration testing" | checklists/roles/qa-integration-testing.md |
| "protocol integration" | checklists/roles/protocol-integration.md |

---

### Pattern Types

| User Says | AI Loads |
|-----------|----------|
| "0x patterns", "0x security" | patterns/0x-patterns.md |
| "erc20 patterns", "token patterns" | patterns/token-patterns.md, patterns/erc20-patterns.md |
| "erc4626 patterns", "vault standard" | patterns/erc4626-patterns.md |
| "governance patterns", "governance issues" | patterns/governance-patterns.md |
| "signature patterns", "ecdsa issues" | patterns/signature-patterns.md |
| "flash loan patterns", "flash loan issues" | patterns/flash-loan-patterns.md |
| "mev patterns", "mev issues" | patterns/mev-patterns.md |

---

### Chain-Specific

| User Says | AI Loads |
|-----------|----------|
| "solidity audit", "evm audit" | solidity-scanner/, patterns/INDEX.md |
| "cairo audit", "starknet audit" | cairo-scanner/ |
| "solana audit", "rust audit" | solana-scanner/ |
| "move audit", "aptos audit", "sui audit" | move-scanner/ |
| "cosmos audit", "cosmwasm audit" | cosmos-scanner/ |
| "ton audit", "tact audit", "func audit" | ton-scanner/ |

---

## Complex Triggers (Multi-File Loads)

### "Full audit of a lending protocol"
**AI Loads:**
1. ROUTE-MAP.md (methodology)
2. attack-trees/lending-attack-tree.md (attack surface)
3. patterns/lending-pool-patterns.md (correct patterns)
4. patterns/oracle-patterns.md (oracle security)
5. anti-patterns/oracle-anti-patterns.md (common mistakes)
6. anti-patterns/reentrancy-anti-patterns.md (reentrancy risks)
7. MASTER_CHECKLIST.md (coverage verification)
8. checklists/roles/auditor-first-pass.md (quick scan)

### "How was [Protocol] exploited?"
**AI Loads:**
1. XREF.md (find the exploit)
2. Relevant attack-tree (based on protocol type)
3. Relevant anti-pattern (based on vulnerability)
4. exploit-forensics/[protocol]-[year].md (if exists)

### "First time auditing, need guidance"
**AI Loads:**
1. ROUTE-MAP.md
2. methodology/llm-audit-workflow.md
3. methodology/learning-path-attack-vectors.md
4. checklists/roles/auditor-first-pass.md
5. attack-trees/INDEX.md

---

## Context-Aware Triggers

The AI should also detect context from the codebase:

| Code Contains | AI Auto-Loads |
|---------------|---------------|
| `latestRoundData()` | patterns/oracle-patterns.md, anti-patterns/oracle-anti-patterns.md |
| `initialize()` function | anti-patterns/access-control-anti-patterns.md#1 |
| `nonReentrant` modifier | patterns/reentrancy-patterns.md |
| `ERC4626` inheritance | patterns/erc4626-patterns.md, attack-trees/vault-attack-tree.md |
| `flash loan`, `flashLoan` | patterns/flash-loan-patterns.md |
| `signature`, `ecrecover` | patterns/signature-patterns.md, anti-patterns for signatures |
| `liquidate`, `liquidation` | attack-trees/lending-attack-tree.md#[B] |
| `IUniswapV2Pair` | patterns/dex-patterns.md, attack-trees/dex-attack-tree.md |

---

## Priority Loading

When multiple triggers match, load in this order:

1. **Attack Tree** - Visual attack surface
2. **Pattern File** - Correct implementation
3. **Anti-Pattern** - What to avoid
4. **XREF** - Cross-reference if needed
5. **Checklist** - Coverage verification

---

## Negative Triggers (What NOT to Load)

| User Says | Don't Load | Instead Load |
|-----------|------------|--------------|
| "What is DeFi?" | Skills files | Basic explanation |
| "How does Ethereum work?" | Audit skills | General knowledge |
| "Write me a contract" | Audit files | Code generation (outside scope) |

---

## Special Commands

| User Says | AI Action |
|-----------|-----------|
| "show me all skills" | Display INDEX.md, attack-trees/INDEX.md, anti-patterns/INDEX.md, patterns/INDEX.md |
| "cross reference [term]" | Search XREF.md for the term |
| "what files should I read?" | Ask about protocol type, then recommend loading sequence |
| "update triggers" | This file (TRIGGERS.md) |

---

## Usage Examples

### Example 1: User asks about oracle security
```
User: "How do I audit chainlink oracle integration?"

AI recognizes: "audit", "oracle", "chainlink"
AI loads:
  1. patterns/oracle-patterns.md#chainlink
  2. anti-patterns/oracle-anti-patterns.md
  3. attack-trees/lending-attack-tree.md#[A]
  
AI responds: Comprehensive guide on chainlink integration security
```

### Example 2: User mentions specific exploit
```
User: "What happened in the Euler hack?"

AI recognizes: "Euler hack"
AI loads:
  1. XREF.md (finds Euler entry)
  2. attack-trees/lending-attack-tree.md#[B2]
  3. patterns/dos-patterns.md#liquidation
  
AI responds: Detailed explanation of Euler liquidation DoS exploit
```

### Example 3: User starting first audit
```
User: "I need to audit my first lending protocol"

AI recognizes: "first", "audit", "lending"
AI loads:
  1. ROUTE-MAP.md
  2. methodology/llm-audit-workflow.md
  3. attack-trees/lending-attack-tree.md
  4. checklists/roles/auditor-first-pass.md
  
AI responds: Step-by-step guide for first lending audit
```

---

## File References

All trigger targets should reference actual files in this repository:

**Core Files:**
- `ROUTE-MAP.md` - Main audit methodology
- `MASTER_CHECKLIST.md` - Comprehensive checklist
- `XREF.md` - Cross-reference index
- `STATISTICS.md` - Exploit statistics

**Directories:**
- `attack-trees/` - Visual attack paths
- `anti-patterns/` - Bad code examples
- `patterns/` - Correct implementations
- `checklists/` - Coverage verification
- `methodology/` - Learning and workflows
- `exploit-forensics/` - Real exploit analysis
- `static-analysis/` - Tool configurations
- `commands/` - CLI commands for tools

---

## Maintenance

**When adding new files:**
1. Add trigger phrases to this file
2. Test triggers with sample questions
3. Update XREF.md cross-references
4. Update relevant INDEX.md files

**When removing files:**
1. Remove triggers from this file
2. Update XREF.md
3. Check for broken links

---

**Last Updated:** 2024
**Version:** 1.0
