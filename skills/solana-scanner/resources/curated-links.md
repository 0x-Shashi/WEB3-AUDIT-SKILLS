---
id: SOLANA-CURATED-LINKS
title: Curated Solana Security & Development Resources
category: solana-scanner
difficulty: beginner
triggers:
  - solana resources
  - solana security links
  - solana audit tools
  - solana learning
  - pinocchio docs
  - anchor docs
related_skills:
  - solana-scanner/SKILL.md
  - solana-scanner/resources/solana-patterns.md
  - solana-scanner/resources/anchor-security.md
  - solana-scanner/resources/pinocchio-security.md
  - solana-scanner/resources/solana-testing-for-auditors.md
tags:
  - solana
  - resources
  - tools
  - documentation
last_updated: 2026-02-25
description: >-
  Curated links to official Solana documentation, security courses, program
  frameworks, testing tools, and performance resources. Source-of-truth first.
  Sourced from Solana Foundation's official solana-dev-skill (Jan 2026).
---

# Curated Solana Security & Development Resources

> **For Auditors**: Bookmark these links. When reviewing a Solana program, these are the authoritative references for framework behavior, security best practices, and testing tools.

---

## Security (Start Here)

| Resource | Why Auditors Need It |
|----------|---------------------|
| [Solana Security Best Practices](https://solana.com/docs/programs/security) | Official security guidance — the baseline for every audit |
| [Blueshift Program Security Course](https://learn.blueshift.gg/en/courses/program-security) | Free, open-source course covering all 9 Solana vulnerability categories |
| [Blueshift GitHub](https://github.com/blueshift-gg) | Course content, tools, and example vulnerable programs |

## Program Frameworks

### Anchor (>90% of new projects)

| Resource | Description |
|----------|-------------|
| [Anchor Repository](https://github.com/coral-xyz/anchor) | Source code — check constraint implementations, derive macros |
| [Anchor Documentation](https://www.anchor-lang.com/) | Official docs — constraint reference, account types, error codes |
| [Anchor Version Manager (AVM)](https://www.anchor-lang.com/docs/avm) | Version management — critical for reproducible builds in audits |

### Pinocchio (Performance-Critical Programs)

| Resource | Description |
|----------|-------------|
| [Pinocchio Repository](https://github.com/anza-xyz/pinocchio) | Source code — 84% more CU-efficient than Anchor |
| [pinocchio-system](https://crates.io/crates/pinocchio-system) | System program bindings |
| [pinocchio-token](https://crates.io/crates/pinocchio-token) | SPL Token bindings — check TryFrom validation behavior |
| [Pinocchio Guide](https://github.com/vict0rcarvalh0/pinocchio-guide) | Community guide with examples |
| [How to Build with Pinocchio (Helius)](https://www.helius.dev/blog/pinocchio) | Practical walkthrough — useful for understanding program structure |

## Testing Frameworks (PoC Writing)

| Framework | Repo | Crate/Package | Why Auditors Care |
|-----------|------|---------------|-------------------|
| **LiteSVM** | [GitHub](https://github.com/LiteSVM/litesvm) | [crate](https://crates.io/crates/litesvm) / [npm](https://www.npmjs.com/package/litesvm) | In-process SVM — fast PoC execution in seconds |
| **Mollusk** | [GitHub](https://github.com/buffalojoec/mollusk) | [crate](https://crates.io/crates/mollusk-svm) | Direct program execution — CU benchmarking, fine-grained state |
| **Surfpool** | [GitHub](https://github.com/txtx/surfpool) | [docs](https://docs.surfpool.dev/) | Integration testing with real mainnet state (Jupiter, Orca, etc.) |

## Token Standards

| Resource | Audit Relevance |
|----------|----------------|
| [SPL Token Documentation](https://spl.solana.com/token) | Standard token program — base for most DeFi |
| [Token-2022 Documentation](https://spl.solana.com/token-2022) | Extension-based tokens: transfer hooks, fees, confidential transfers |
| [Metaplex Documentation](https://developers.metaplex.com/) | NFT metadata standard — relevant for NFT lending/marketplace audits |

## IDLs and Codegen

| Resource | Audit Relevance |
|----------|----------------|
| [Codama Repository](https://github.com/codama-idl/codama) | IDL → typed client generation — verify IDL matches on-chain behavior |
| [Codama Generating Clients](https://solana.com/docs/programs/codama-generating-clients) | Official client generation docs |
| [Shank (Metaplex)](https://github.com/metaplex-foundation/shank) | IDL extraction from native Rust programs |

## Performance & Optimization Analysis

| Resource | Audit Relevance |
|----------|----------------|
| [Solana Optimized Programs](https://github.com/Laugharne/solana_optimized_programs) | Reference for understanding CU optimization patterns in production |
| [sBPF Assembly SDK](https://github.com/blueshift-gg/sbpf) | Ultra-low-level — for analyzing assembly-level exploits or gas griefing |
| [Doppler Oracle (21 CU)](https://github.com/blueshift-gg/doppler) | Minimal oracle implementation — useful reference for oracle audit comparisons |

## Core Documentation

| Resource | Description |
|----------|-------------|
| [Solana Documentation](https://solana.com/docs) | Core reference: runtime, accounts, transactions, programs |
| [RPC API Reference](https://solana.com/docs/rpc) | RPC methods — needed for testing and verification |
| [Solana Cookbook](https://solanacookbook.com/) | Recipes and patterns — good for understanding common approaches |

## Learning Platforms

| Resource | Description |
|----------|-------------|
| [Blueshift](https://learn.blueshift.gg/) | Free, open-source Solana learning — includes security courses |
| [@solana/kit Docs](https://solana.com/docs/clients/kit) | Modern TS SDK — relevant for client-side audit |

---

## Related Files

- [Solana Scanner SKILL.md](../SKILL.md) — Main scanner with 9 vulnerability categories
- [Solana Patterns](solana-patterns.md) — Comprehensive vulnerability patterns with code
- [Anchor Security](anchor-security.md) — Anchor constraint reference + common vulnerabilities
- [Pinocchio Security](pinocchio-security.md) — TryFrom, Token-2022, zero-copy safety
- [Solana Testing for Auditors](solana-testing-for-auditors.md) — LiteSVM, Mollusk, Surfpool PoC guide

---

*Source: Solana Foundation's official solana-dev-skill (January 2026)*
