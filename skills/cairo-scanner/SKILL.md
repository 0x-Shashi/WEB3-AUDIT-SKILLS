---
id: SCANNER-CAIRO
title: Cairo Smart Contract Security Scanner
category: chain-scanner
chains: [starknet]
languages: [cairo]
version: cairo-2.x
last_updated: 2025-01-31
---

# Cairo Scanner Skill

## Purpose

Analyze Cairo smart contracts deployed on Starknet for security vulnerabilities. Cairo's unique computational model — based on field elements (felts), STARK proofs, and native account abstraction — creates attack surfaces that don't exist on EVM chains.

## Cairo Security Model

| Property | Cairo/Starknet | EVM/Solidity |
|----------|---------------|-------------|
| Integer type | Felt252 (field element, $0$ to $P-1$ where $P = 2^{251} + 17 \cdot 2^{192} + 1$) | uint256, int256 |
| Arithmetic | Modular (wraps around $P$) | Checked (reverts in Solidity 0.8+) |
| Division | Modular inverse (not integer division) | Integer truncation |
| Account model | All accounts are smart contracts (native AA) | EOAs + smart contracts |
| Upgrades | `replace_class_syscall` (instant) | Proxy patterns (delegatecall) |
| Storage | Pedersen hash-based addresses | Sequential slots (keccak256) |
| L1 interaction | L1-L2 messaging via Starknet Core on Ethereum | Bridges required |
| Proving | STARK proofs for L1 verification | No proofs needed |

## Detection Capabilities

### Critical — Direct Fund Loss

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Felt overflow wrapping** | Arithmetic on felt252 wraps around $P$, enabling underflow/overflow | Felt252 used for balances or amounts without range checks |
| **Unprotected `replace_class_syscall`** | Anyone can upgrade the contract logic | `replace_class_syscall` without `assert_only_owner` or equivalent |
| **L1-L2 message replay** | Same L1→L2 message consumed multiple times | Missing nonce or message hash tracking in `l1_handler` |
| **Account validation bypass** | Custom `__validate__` skips critical checks | `__validate__` returns success without signature verification |
| **Storage collision** | Two different state variables map to same storage slot | Custom `storage_address_from_base` with colliding inputs |

### High — Significant Impact

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Reentrancy via `call_contract_syscall`** | External contract call re-enters before state update | `call_contract_syscall` before storage writes |
| **Missing caller validation** | External function callable by anyone | `get_caller_address()` not checked in sensitive functions |
| **Felt252 comparison pitfalls** | Comparing felts that represent "negative" numbers (near $P$) | `<` or `>` on felts where semantic negativity matters |
| **Component storage isolation failure** | Components sharing storage addresses | Overlapping `#[storage]` declarations across components |
| **Incorrect modular division** | Using `/` operator expecting integer division | `a / b` on felt252 produces modular inverse, not truncation |

### Medium — Conditional Impact

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Unbounded storage growth** | Maps or arrays without size limits | `Map<K, V>` without pruning mechanism |
| **Missing events** | State changes without event emission | `write` to storage without `emit` |
| **Library dispatch trust** | Using `library_call_syscall` with unchecked class hash | External class hash in library call |
| **Paymaster manipulation** | Transaction fee payment logic exploitable | Custom `__validate__` with fee token handling |
| **Felt-to-u256 conversion errors** | Incorrect type casting between felt and uint types | `felt252.into()` or `TryInto::<u256>` without bounds |

## Cairo-Specific Pitfalls

### Felt Arithmetic Is Modular

```cairo
// DANGEROUS: Felt subtraction wraps around P
let balance: felt252 = 100;
let amount: felt252 = 200;
let result = balance - amount;
// result is NOT -100, it is P - 100 (a very large number)
// Any comparison result > 0 will be TRUE

// SAFE: Use u256 for amounts
let balance: u256 = 100;
let amount: u256 = 200;
assert(balance >= amount, 'Insufficient balance'); // Correctly reverts
```

### Division Is Not Integer Division

```cairo
// UNEXPECTED: Felt division is modular inverse
let a: felt252 = 7;
let b: felt252 = 2;
let result = a / b;
// result is NOT 3 (integer truncation)
// result is the felt252 x such that x * 2 ≡ 7 (mod P)
// This is (P + 7) / 2 = a very large number

// SAFE: Use u256 for integer division
let a: u256 = 7;
let b: u256 = 2;
let result = a / b; // result is 3 (integer truncation, as expected)
```

## Resources

| Resource | Description |
|----------|-------------|
| [Cairo Patterns](resources/cairo-patterns.md) | Vulnerability patterns specific to Cairo language and Starknet |
| [Starknet Security](resources/starknet-security.md) | Starknet architecture security: sequencer, proofs, upgrades |
| [Messaging Security](resources/messaging-security.md) | L1-L2 messaging: message replay, nonce handling, proof finalization |

## Workflows

| Workflow | Description |
|----------|-------------|
| [Cairo Audit](workflows/cairo-audit.md) | Step-by-step audit workflow for Cairo contracts on Starknet |

## Notable Starknet Security Incidents

| Incident | Root Cause | Impact |
|----------|-----------|--------|
| Various DeFi exploits on Starknet testnet | Felt overflow in token balances | Fund inflation |
| L1→L2 message replay in early bridges | Missing consumed message tracking | Double-spending |
| Account contract vulnerabilities | Insufficient `__validate__` logic | Transaction forging |

## Integration with Other Skills

| Skill | Connection |
|-------|-----------|
| `starknet-scanner/` | Shares Cairo language patterns; this skill focuses on language, starknet-scanner focuses on chain |
| `chain-guides/starknet.md` | Chain-level context for Starknet architecture |
| `patterns/` | Cross-reference with general vulnerability categories (reentrancy, access control) |
| `exploit-forensics/` | Limited Starknet exploits but growing as ecosystem matures |
