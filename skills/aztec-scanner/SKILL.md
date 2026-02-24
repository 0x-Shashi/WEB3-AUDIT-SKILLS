---
id: AZTEC-SCAN
title: Aztec Network Security Scanner
category: chain-scanner
trigger: "Audit Aztec|Noir|private contract"
last_updated: 2026-02-24
---

# Aztec Network Security Scanner

Security scanner for Aztec Network smart contracts written in Noir. Aztec is a privacy-focused L2 on Ethereum with a unique dual public/private state model.

---

## Language & Runtime

| Attribute | Value |
|-----------|-------|
| Chain | Aztec Network (Ethereum L2) |
| Language | Noir (Rust-inspired, ZK-circuit language) |
| Proof System | Ultra-PLONK (client-side proving) |
| State Model | Dual: Private (UTXO/notes) + Public (storage slots) |
| Privacy | Private functions hide inputs, outputs, and who called them |
| Execution | Private: client-side → Public: sequencer-side |
| Token Standard | Private tokens via note encryption |

---

## Architecture: Public vs Private

```
┌─────────────────────────────────────────────────────────┐
│  Aztec Contract                                         │
├──────────────────────────┬──────────────────────────────┤
│  Private Functions          │  Public Functions               │
│  (Client-side execution)    │  (Sequencer-side execution)     │
│  - Hidden inputs/outputs    │  - Visible state changes        │
│  - Note creation/nullifying │  - Storage slot reads/writes    │
│  - ZK proof generation      │  - Similar to Solidity          │
├──────────────────────────┴──────────────────────────────┤
│  Private State: Notes (UTXO-like, encrypted)             │
│  Public State: Storage slots (like Solidity)             │
│  Shared: Nullifier tree, note hash tree, L1-L2 messages  │
└─────────────────────────────────────────────────────────┘
```

### Private State: Notes

Aztec uses a UTXO-like model for private state:

1. **Notes** are encrypted data stored in the note hash tree
2. To "read" a note, the owner decrypts it client-side
3. To "spend" a note, a **nullifier** is emitted (marks the note as consumed)
4. To "create" a note, a new note hash is added to the tree
5. Notes are **immutable** — to update, nullify the old note and create a new one

### Execution Order

Private functions execute FIRST (client-side), then public functions execute SECOND (sequencer-side). This ordering has security implications:
- Private can enqueue calls to public, but not vice versa
- Private computations can't read current public state (stale reads)
- Public functions see the effects of private functions

---

## Detection Capabilities

| Category | Detection | Severity |
|----------|-----------|----------|
| **Privacy** | Private data exposed via public state or function args | Critical |
| **Privacy** | Note content leaked through observable behavior (timing, gas) | High |
| **Privacy** | Encryption key mismanagement (wrong recipient) | Critical |
| **Nullifier** | Nullifier collision (two notes produce same nullifier) | Critical |
| **Nullifier** | Nullifier not emitted when note consumed (double-spend) | Critical |
| **Nullifier** | Nullifier predictable (allows front-running) | High |
| **State Sync** | Public/private state inconsistency | High |
| **State Sync** | Private function reads stale public state | Medium |
| **Circuit** | Under-constrained circuit (invalid proofs accepted) | Critical |
| **Circuit** | Over-constrained circuit (valid transactions rejected) | Medium |
| **Oracle** | Untrusted oracle data used in circuit constraints | High |
| **Access** | Private function callable without proper auth | High |
| **Notes** | Note not encrypted for correct recipient | Critical |
| **Notes** | Note discovery failure (recipient can't find their notes) | High |

---

## Privacy Threat Model

| Threat | Attack Vector | Mitigation |
|--------|--------------|-------------|
| Transaction graph analysis | Linking sender/receiver via timing | Add delay, use shield/unshield |
| Amount leakage | Fixed denomination reveals nothing | Use uniform note sizes |
| Metadata leakage | Public function calls reveal intent | Minimize public function usage |
| Sequencer censorship | Sequencer refuses to include tx | Forced inclusion via L1 |
| Nullifier linking | Linking nullifiers to note creation | Nullifier derived from note secret + position |

---

## Resources
- [Aztec Patterns](resources/aztec-patterns.md)

## Workflows
- [Aztec Audit](workflows/aztec-audit.md)

## Overview
Aztec is a privacy-focused L2 with:
- Private and public state separation
- UTXO-like note model for private data
- Noir language for circuit programming
- Encrypted function arguments
- Client-side proof generation
