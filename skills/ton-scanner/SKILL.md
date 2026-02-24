---
id: TON-SCANNER
title: TON Smart Contract Security Scanner
category: chain-specific
difficulty: advanced
triggers:
  - ton smart contract audit
  - func security
  - tact security
  - ton vulnerability
  - message chain analysis
related_skills:
  - ton-scanner/resources/ton-patterns.md
  - ton-scanner/workflows/ton-audit.md
tags:
  - ton
  - func
  - tact
  - actor-model
  - security
last_updated: 2026-02-24
---

# TON Scanner Skill

## Purpose

Analyze TON (The Open Network) smart contracts written in FunC or Tact for security vulnerabilities. TON's actor-model architecture, asynchronous message passing, and TVM (TON Virtual Machine) create a fundamentally different security model from EVM-based chains.

## TON Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         TON Network                             │
│                                                                 │
│  ┌──────────────┐    async messages     ┌──────────────┐        │
│  │  Contract A   │ ──────────────────► │  Contract B   │        │
│  │  (Shard 1)    │ ◄────────────────── │  (Shard 2)    │        │
│  │               │    bounce/reply      │               │        │
│  │  FunC / Tact  │                      │  FunC / Tact  │        │
│  └──────┬───────┘                      └──────┬───────┘        │
│         │                                      │                │
│         ▼                                      ▼                │
│  ┌──────────────┐                      ┌──────────────┐        │
│  │    Storage    │                      │    Storage    │        │
│  │  (Cells/BoC)  │                      │  (Cells/BoC)  │        │
│  │  pays rent    │                      │  pays rent    │        │
│  └──────────────┘                      └──────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Key Differences from EVM

| Aspect | EVM (Solidity) | TON (FunC/Tact) |
|---|---|---|
| Execution Model | Synchronous, atomic | Asynchronous, actor-based messages |
| Cross-Contract Calls | Atomic within transaction | Non-atomic, separate transactions |
| Storage Cost | One-time gas | Ongoing rent (storage fees) |
| Data Structure | Key-value mapping | Cell trees (max 1023 bits, 4 refs) |
| Reentrancy | Within same transaction | Not possible (async messages) |
| Failure Handling | Revert entire tx | Bounce messages, partial failure |
| Languages | Solidity, Vyper | FunC (low-level), Tact (high-level) |
| Address Format | 20-byte, single chain | Workchain ID + 256-bit hash |

### Languages

| Language | Level | Usage | Security Characteristics |
|---|---|---|---|
| **FunC** | Low-level | Core contracts, jettons, NFTs | Direct TVM access, manual cell serialization, easy to misuse |
| **Tact** | High-level | Modern contracts | Type-safe, auto-serialization, safer defaults but newer |
| **Fift** | Assembly-level | Deployment scripts | Direct TVM opcodes, used for contract deployment |

## Detection Capabilities

### Critical Vulnerabilities
- **Message chain gas exhaustion**: Multi-hop messages run out of gas before completing all operations
- **Missing bounce handling**: Bounced messages not processed → permanent fund loss
- **Unbounded storage growth**: Attacker-controlled data storage drains contract balance via rent
- **Missing replay protection**: Same message processed multiple times

### High Vulnerabilities
- **Carry-value attacks**: Incoming message value used to fund outgoing messages without accounting
- **Cell overflow/underflow**: Exceeding 1023-bit or 4-reference cell limits during serialization
- **Workchain ID confusion**: Not validating workchain in address leads to cross-chain issues
- **Incorrect message mode flags**: Wrong send mode causes unintended gas forwarding or balance drain

### Medium Vulnerabilities
- **Storage fee drain**: Contract balance slowly depleted by rent payments on stored data
- **Sharded message ordering**: Assuming message order across shards causes race conditions
- **Tick-tock contract abuse**: Automatic execution contracts with expensive operations
- **Missing `accept_message()` in external handlers**: External messages silently dropped without gas acceptance

## Real-World TON Incidents

| Incident | Vulnerability | Impact |
|---|---|---|
| Early Jetton implementations | Missing bounce handling | Token loss on failed transfers |
| DNS auction contracts | Gas exhaustion in multi-message chains | Auctions stuck irrecoverably |
| Various NFT marketplaces | Replay attacks (no seqno) | Duplicate sales/purchases |
| Storage-based attacks | Unbounded storage growth | Contract balance drained by rent |

## Resources
- [TON Patterns](resources/ton-patterns.md) — Full vulnerability patterns with FunC/Tact code
- [TON Audit Workflow](workflows/ton-audit.md) — Step-by-step audit methodology

## Related Scanners
- [Solidity Scanner](../solidity-scanner/) — EVM comparison for cross-chain auditors
- [Solana Scanner](../solana-scanner/) — Another non-EVM async model for comparison
