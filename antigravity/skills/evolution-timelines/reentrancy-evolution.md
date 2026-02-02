---
id: EVO-REENTRANCY
title: Reentrancy Vulnerability Evolution
vulnerability_type: reentrancy
timeline_start: 2016
timeline_end: 2026
major_exploits:
  - year: 2016
    name: The DAO
    loss: 60000000
    type: classic
  - year: 2020
    name: Lendf.Me
    loss: 25000000
    type: erc777
  - year: 2022
    name: Rari Capital
    loss: 80000000
    type: cross-contract
  - year: 2023
    name: Curve
    loss: 70000000
    type: read-only
defense_evolution:
  - year: 2016
    defense: checks-effects-interactions
  - year: 2017
    defense: reentrancy-guard
  - year: 2022
    defense: read-only-locks
current_threat_level: medium
emerging_vectors:
  - cross-chain-callbacks
  - restaking-hooks
  - transient-storage-reentrancy
last_updated: 2026-01-31
---

# Reentrancy Vulnerability Evolution

## Timeline

### 2016 - The DAO
- Classic single-function reentrancy
- Resulted in Ethereum hard fork
- Defense: CEI pattern introduced

### 2017-2019 - Defense Era
- ReentrancyGuard becomes standard
- OpenZeppelin library adoption

### 2020 - ERC777 Hooks
- Lendf.Me exploited via token hooks
- New attack surface through callbacks

### 2022 - Cross-Contract & Read-Only
- Rari Capital: cross-contract reentrancy
- Read-only reentrancy emerges as new vector

### 2023-2024 - Advanced Variants
- Curve: read-only reentrancy via Vyper
- Transient storage considerations

### 2025-2026 - Emerging Vectors
- Cross-chain callback reentrancy
- Restaking protocol hooks
- Transient storage edge cases

## Current Threat Level
**Medium** - Well-understood but new variants continue to emerge.

## Defenses Today
- CEI pattern
- ReentrancyGuard on all entry points
- Read-only locks where needed
- Careful review of all hooks and callbacks
