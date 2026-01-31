---
id: ATTACK-CHAIN-INDEX
title: Attack Chains - Multi-Step Exploit Patterns
category: attack-chains
difficulty: advanced
tags: [attack-chain, multi-step, exploit-pattern, methodology]
last_updated: 2026-01-31
---

# Attack Chains

Attack chains show how individual vulnerabilities combine to create devastating exploits. Understanding these patterns separates good auditors from great ones.

## What is an Attack Chain?

An attack chain is a sequence of vulnerabilities or techniques that, when combined, achieve an exploit objective that no single vulnerability could accomplish alone.

```
[Entry Point] → [Amplification] → [Exploitation] → [Extraction]
```

## Available Attack Chains

| Attack Chain | Steps | Key Techniques | Typical Loss |
|--------------|-------|----------------|--------------|
| [Flash Loan Oracle Manipulation](flash-loan-oracle-chain.md) | 4 | Flash loan, price manipulation, liquidation | $50M-200M |
| [Governance Takeover](governance-takeover-chain.md) | 5 | Token accumulation, proposal, execution | $50M-200M |
| [Bridge Exploit](bridge-exploit-chain.md) | 4 | Fake proof, message replay, mint/drain | $100M-600M |
| [Reentrancy State Desync](reentrancy-desync-chain.md) | 3 | Reenter, corrupt state, drain | $10M-80M |
| [Sandwich MEV](sandwich-mev-chain.md) | 3 | Frontrun, victim tx, backrun | $1K-1M per tx |
| [Cross-Contract Manipulation](cross-contract-chain.md) | 4 | Oracle, lending, liquidation cascade | $50M-130M |

## Attack Chain Categories

### 1. DeFi Economic Attacks
- Flash loan arbitrage
- Oracle manipulation
- Liquidation cascades

### 2. Governance Attacks
- Flash loan voting
- Delegate manipulation
- Timelock bypass

### 3. Bridge/Cross-Chain Attacks
- Message replay
- Proof forgery
- Validator compromise

### 4. MEV/Ordering Attacks
- Sandwich attacks
- JIT liquidity
- Time bandit attacks

### 5. State Manipulation
- Reentrancy chains
- Read-only reentrancy
- Cross-function attacks

## How to Use Attack Chains

### During Audits
1. Identify potential entry points
2. Map possible amplification vectors
3. Consider what state can be corrupted
4. Trace extraction paths

### Building Detection Rules
```
For each attack chain:
1. Identify invariants that should hold
2. Define checkpoints between steps
3. Create detection signatures
4. Build monitoring alerts
```

## Attack Chain Template

Each attack chain follows this structure:

```markdown
## Overview
Brief description of the attack

## Prerequisites
- What conditions enable this attack?
- Required capital/access

## Attack Steps
1. Step 1: [Action] → [State Change]
2. Step 2: [Action] → [State Change]
...

## Real-World Examples
Links to actual exploits using this chain

## Detection Points
Where to catch the attack in progress

## Prevention
How to prevent each step
```

## Quick Reference

| If you see... | Check for... | Attack Chain |
|---------------|--------------|--------------|
| Large flash loan + DEX swap | Price manipulation | Flash Loan Oracle |
| Token transfer before governance | Vote manipulation | Governance Takeover |
| Bridge message without proof | Message forgery | Bridge Exploit |
| Callback during token transfer | State desync | Reentrancy Chain |
| Two txs same block sandwiching | MEV extraction | Sandwich MEV |
