---
id: solidity-scanner
title: Solidity Scanner Skill
category: scanner
difficulty: intermediate
triggers:
  - solidity audit
  - smart contract security
  - EVM vulnerability
  - solidity scan
  - ethereum audit
related_skills:
  - methodology/SKILL.md
  - severity/SKILL.md
  - checklists/SKILL.md
  - patterns/SKILL.md
  - variant-analysis/SKILL.md
  - static-analysis/SKILL.md
  - exploit-forensics/SKILL.md
tags:
  - solidity
  - evm
  - scanner
  - security
last_updated: 2026-02-24
---

# Solidity Scanner Skill

## Purpose

Analyze Solidity smart contracts for security vulnerabilities across all EVM-compatible chains. This is the primary scanner for the most widely-deployed smart contract language, covering DeFi, NFTs, governance, bridges, and all Ethereum-ecosystem protocols.

## Supported Chains

| Chain | EVM Compatibility | Key Differences |
|---|---|---|
| Ethereum | Full | Baseline — all patterns apply |
| Arbitrum | Full | L2 sequencer risk, `block.number` returns L1 block, gas pricing differs |
| Optimism / Base | Full | L2 sequencer risk, `TIMESTAMP` from L1, cross-domain messaging |
| Polygon | Full | Different gas token (MATIC), PoS consensus, reorg risk higher |
| BSC | Full | Lower gas costs enable different attack economics |
| Avalanche | Full | Subnet awareness, different finality model |
| Scroll | Full | zkEVM — some precompile differences |
| Linea | Full | zkEVM — some opcode cost differences |
| zkSync Era | Partial | Different address derivation, no `SELFDESTRUCT`, custom deployment model |
| Blast | Full | Native yield — `WETH.balance()` increases, rebasing assumptions |

### Chain-Specific Audit Considerations

When auditing for a specific chain, check these additional concerns:

```
Arbitrum/Optimism:
  ├── Sequencer downtime → oracle stale price risk
  ├── L1-to-L2 message delay → bridge timing attacks
  └── block.number semantics differ from L1

zkSync Era:
  ├── msg.value behaves differently in system contracts
  ├── Contract deployment uses CREATE2-like hash, not CREATE
  ├── Some opcodes unavailable or priced differently
  └── Native account abstraction changes tx.origin semantics

Blast:
  ├── ETH and USDB are rebasing tokens by default
  ├── Protocol must explicitly configure yield mode
  └── balanceOf(address) can change between transactions without transfers
```

## Detection Capabilities

### Critical / High Severity

| Category | Specific Patterns | Detection Method |
|---|---|---|
| **Reentrancy** | Classic single-function, cross-function, cross-contract, read-only, ERC777 callback, ERC721 callback | State write after external call analysis |
| **Access control** | Missing modifiers, `tx.origin` auth, unprotected `initialize()`, unprotected `selfdestruct`, privilege escalation | Public/external function modifier scan |
| **Unsafe external calls** | Unchecked `transfer()` return, unchecked low-level call, unchecked `approve()`, USDT non-standard behavior | Return value tracking |
| **Oracle manipulation** | Uniswap V2/V3 spot price, missing Chainlink staleness check, reserve-based pricing, circular pricing | Oracle usage pattern matching |
| **Flash loan vectors** | Balance-based pricing, single-tx manipulation, donation attacks | Balance-as-input detection |
| **Proxy vulnerabilities** | Uninitialized impl, storage collision, missing `_disableInitializers()`, UUPS auth bypass | Proxy pattern recognition |

### Medium Severity

| Category | Specific Patterns | Detection Method |
|---|---|---|
| **Integer issues** | Unsafe downcast, truncation on assignment, rounding errors in share math, first depositor inflation | `SafeCast` absence, division analysis |
| **Token handling** | Fee-on-transfer incompatibility, rebasing token assumption, non-standard decimals, approve race condition | Token interaction pattern scan |
| **MEV exposure** | Missing deadline, missing slippage protection, sandwich vulnerability, permit front-running | Swap/router call analysis |
| **Centralization** | Untimelocked admin powers, excessive owner privileges, upgradeable without governance | Admin function audit |
| **Signature issues** | Missing nonce, missing chainId, missing deadline, ecrecover zero-address, malleable signatures | Signature verification scan |
| **DoS vectors** | Unbounded loops, external call revert in batch, force-sent ETH breaking balance checks | Loop and batch analysis |

### Low / Informational

| Category | Specific Patterns |
|---|---|
| **Gas optimization** | Storage vs memory, redundant SLOADs, unchecked math for bounded loops, calldata vs memory |
| **Code quality** | Missing events, missing NatSpec, unused variables, floating pragma, unlocked compiler |
| **Best practices** | `block.timestamp` dependency, missing zero-address checks, magic numbers, missing error messages |

## Compiler Version Awareness

| Solidity Version | Key Security Considerations |
|---|---|
| < 0.8.0 | No built-in overflow protection — check for SafeMath usage |
| 0.8.0–0.8.12 | Built-in overflow but `unchecked` blocks bypass it — audit all `unchecked` usage |
| 0.8.13–0.8.14 | ABI encoder bug with nested arrays (fixed in 0.8.15) |
| 0.8.15–0.8.19 | Optimizer bug with `Yul` code (fixed in 0.8.20) |
| 0.8.20+ | Default EVM target = Shanghai (`PUSH0`) — may not deploy on all L2s |
| 0.8.24+ | Transient storage (`TSTORE`/`TLOAD`) available — new reentrancy guard patterns |
| 0.8.26+ | Custom storage layouts, event errors in interfaces |

## Workflows

| Workflow | Duration | Best For | Link |
|---|---|---|---|
| Quick Scan | 15–20 min | Triage, contest warm-up, initial assessment | [quick-scan.md](workflows/quick-scan.md) |
| Comprehensive Audit | 3–5 days | Protocol launch, client engagement, major upgrade | [comprehensive-audit.md](workflows/comprehensive-audit.md) |
| Competitive Audit | 8–16 hours | Code4rena, Sherlock, CodeHawks contests | [competitive-audit.md](workflows/competitive-audit.md) |

## Resources

| Resource | Purpose | Link |
|---|---|---|
| Vulnerability Patterns | Complete pattern catalog with code examples | [vulnerability-patterns.md](resources/vulnerability-patterns.md) |
| Severity Guide | Classification criteria with decision tree | [severity-guide.md](resources/severity-guide.md) |
| Tool Configs | Slither, Aderyn, Mythril, Semgrep setup | [tool-configs.md](resources/tool-configs.md) |
| False Positives | Common FPs with reasoning for each | [false-positives.md](resources/false-positives.md) |

## Standard Audit Procedure

```
1. Load Solidity contract(s) and note compiler version
2. Map inheritance tree and external dependencies
3. Identify protocol type (DeFi, NFT, governance, bridge, etc.)
4. Select workflow based on engagement type
5. Run static analysis tools (Slither → Aderyn → Mythril)
6. Execute manual review per methodology
7. Classify each finding with severity guide
8. Run variant analysis on confirmed findings
9. Generate structured report
```

## Integration with Other Skills

| Skill | How Solidity Scanner Uses It |
|---|---|
| `methodology/` | Provides the audit methodology framework (phases, timing, approach) |
| `severity/` | Classifies each finding into Critical/High/Medium/Low |
| `scoring/` | Scores overall protocol security posture |
| `checklists/` | Protocol-specific security checklists (ERC-20, vault, AMM, etc.) |
| `patterns/` | Vulnerability pattern database for cross-reference |
| `variant-analysis/` | When one bug is found, hunt for all variants |
| `static-analysis/` | Tool configuration and integration |
| `exploit-forensics/` | Real-world exploit case studies for pattern awareness |
| `fix-review/` | Verify proposed fixes after initial audit |
| `differential-review/` | Compare upgraded contract versions |
| `chain-guides/` | Chain-specific considerations when target != Ethereum mainnet |
