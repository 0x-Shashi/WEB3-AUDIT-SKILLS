---
id: ROUTE-MAP
title: Audit Route Map - Decision Tree
category: navigation
type: index
triggers:
  - where do I start
  - which patterns for lending
  - which patterns for DEX
  - which patterns for bridge
  - which patterns for vault
  - which patterns for staking
  - which patterns for NFT
  - which patterns for governance
  - which patterns for perps
  - which patterns for intents
  - what should I read first
  - audit checklist by protocol
  - protocol-specific patterns
related_skills:
  - INDEX.md
  - MASTER_CHECKLIST.md
  - methodology/llm-audit-workflow.md
  - checklists/comprehensive-checklist.md
---

#  Audit Route Map

## Overview

This decision tree helps AI agents and auditors navigate the skills repository efficiently. Start with **what you're auditing**, then follow the recommended path.

---

## Quick Protocol Router

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT ARE YOU AUDITING?                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   LENDING   │  │     DEX     │  │   BRIDGE    │             │
│  │   PROTOCOL  │  │    / AMM    │  │             │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│    Section 1        Section 2        Section 3                  │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   VAULT /   │  │   STAKING   │  │    NFT      │             │
│  │    YIELD    │  │  RESTAKING  │  │ MARKETPLACE │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│    Section 4        Section 5        Section 6                  │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  GOVERNANCE │  │   PERP DEX  │  │   INTENT    │             │
│  │   / DAO     │  │  / OPTIONS  │  │   SYSTEM    │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│    Section 7        Section 8        Section 9                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Section 1: Lending Protocol

**You're auditing**: Aave-like, Compound-like, or any borrow/lend system

### Required Reading Path

```
START
  │
  ├─► patterns/lending-pool-patterns.md
  │     └─ Core lending mechanics, borrow/repay, utilization
  │
  ├─► patterns/oracle-patterns.md
  │     └─ Price feed attacks, stale prices, manipulation
  │
  ├─► patterns/liquidation-patterns.md
  │     └─ Health factor, bad debt, liquidation incentives
  │
  ├─► patterns/share-inflation-patterns.md
  │     └─ First depositor attack, share price manipulation
  │
  ├─► patterns/interest-rate-patterns.md
  │     └─ Rate model bugs, utilization gaming
  │
  └─► patterns/flash-loan-patterns.md
        └─ Flash loan callbacks, atomic arbitrage
```

### Also Check

| If Protocol Has... | Also Read |
|-------------------|-----------|
| Governance tokens | patterns/dao-patterns.md, patterns/vote-patterns.md |
| Isolated markets | methodology/composability-attacks.md |
| Cross-chain lending | patterns/bridge-patterns.md |
| NFT collateral | patterns/nft-patterns.md |

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Oracle manipulation → bad debt, price = 0 edge case |
| **High** | First depositor attack, liquidation DoS, interest accrual bugs |
| **Medium** | Stale oracle prices, utilization rate manipulation |

---

## Section 2: DEX / AMM

**You're auditing**: Uniswap-like, Curve-like, or any swap system

### Required Reading Path

```
START
  │
  ├─► patterns/amm-patterns.md
  │     └─ Constant product, liquidity math, LP tokens
  │
  ├─► patterns/swap-patterns.md
  │     └─ Token swap mechanics, routing, path validation
  │
  ├─► patterns/sandwich-attack-patterns.md
  │     └─ Front-running, back-running, MEV extraction
  │
  ├─► patterns/slippage-patterns.md
  │     └─ Minimum output, deadline, price impact
  │
  ├─► patterns/flash-loan-patterns.md
  │     └─ Reserve manipulation, atomic arbitrage
  │
  └─► patterns/reentrancy-patterns.md
        └─ Callback attacks, lock bypass
```

### Also Check

| If DEX Has... | Also Read |
|---------------|-----------|
| Concentrated liquidity | patterns/precision-loss-patterns.md, protocol-playbooks/uniswap-v3.md |
| Hooks (V4 style) | patterns/hook-attacks.md |
| Stable swaps | protocol-playbooks/curve.md |
| Limit orders | patterns/intent-based-attacks.md |

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | K value manipulation, price oracle as spot price |
| **High** | Missing slippage protection, callback reentrancy |
| **Medium** | Fee calculation errors, LP token inflation |

---

## Section 3: Bridge

**You're auditing**: Cross-chain bridge, message passing, token bridge

### Required Reading Path

```
START
  │
  ├─► patterns/bridge-patterns.md
  │     └─ Lock/mint, burn/unlock, message verification
  │
  ├─► patterns/signature-malleability-patterns.md
  │     └─ Multi-sig, threshold, signature malleability
  │
  ├─► patterns/eip-712-patterns.md
  │     └─ Typed data signing, domain separator, replay prevention
  │
  ├─► patterns/replay-attack-patterns.md
  │     └─ Cross-chain replay, nonce management
  │
  ├─► patterns/merkle-tree-patterns.md
  │     └─ Proof verification, leaf construction
  │
  └─► methodology/exploit-case-studies.md
        └─ Ronin ($625M), Wormhole ($320M), Nomad ($190M)
```

### Also Check

| If Bridge Has... | Also Read |
|-----------------|-----------|
| Optimistic verification | patterns/l2-security.md, chain-guides/optimism.md |
| ZK proofs | patterns/zk-proof-attacks.md |
| LayerZero/Axelar | protocol-playbooks/layerzero-v2.md |
| Token wrapping | patterns/erc20-patterns.md, patterns/weird-erc20-patterns.md |

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Signature bypass, message forgery, replay across chains |
| **High** | Validator collusion, merkle proof manipulation |
| **Medium** | Rate limiting bypass, stuck funds |

---

## Section 4: Vault / Yield Aggregator

**You're auditing**: ERC4626 vault, yield optimizer, auto-compounder

### Required Reading Path

```
START
  │
  ├─► patterns/erc4626-patterns.md
  │     └─ Share/asset math, deposit/withdraw, preview functions
  │
  ├─► patterns/share-inflation-patterns.md
  │     └─ First depositor, donation attack, rounding
  │
  ├─► patterns/first-depositor-issue-patterns.md
  │     └─ Donation attack, direct transfer manipulation, share price inflation
  │
  ├─► methodology/composability-attacks.md
  │     └─ Cross-protocol interactions, flash loan chains
  │
  └─► patterns/accounting-patterns.md
        └─ Balance vs internal accounting, fee calculation
```

### Also Check

| If Vault Has... | Also Read |
|-----------------|-----------|
| Strategies | patterns/vault-patterns.md |
| Multiple assets | patterns/decimals-patterns.md, patterns/erc20-patterns.md |
| Timelocks | patterns/timelock-patterns.md |
| Withdrawal queues | patterns/withdraw-pattern-patterns.md |

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Share price manipulation → fund theft |
| **High** | First depositor attack, strategy loss attribution |
| **Medium** | Rounding in favor of attacker, fee calculation |

---

## Section 5: Staking / Restaking

**You're auditing**: Staking pool, liquid staking, restaking (EigenLayer-like)

### Required Reading Path

```
START
  │
  ├─► patterns/staking-patterns.md
  │     └─ Stake/unstake, reward distribution, slashing
  │
  ├─► patterns/restaking-attacks.md
  │     └─ AVS risks, operator collusion, slashing cascade
  │
  ├─► patterns/reward-distribution-patterns.md
  │     └─ Reward calculation, claim timing, dust attacks
  │
  ├─► patterns/withdraw-pattern-patterns.md
  │     └─ Unbonding period, queue manipulation
  │
  └─► patterns/delegate-patterns.md
        └─ Operator selection, validator management
```

### Also Check

| If System Has... | Also Read |
|-----------------|-----------|
| Liquid staking tokens | protocol-playbooks/lido.md |
| Multiple validators | patterns/delegate-patterns.md |
| MEV sharing | patterns/front-running-patterns.md, patterns/sandwich-attack-patterns.md |
| Governance | patterns/dao-patterns.md, patterns/vote-patterns.md |

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Slashing amount manipulation, unbounded withdrawal |
| **High** | Reward calculation overflow, validator extraction |
| **Medium** | Unbonding period bypass, dust reward griefing |

---

## Section 6: NFT Marketplace

**You're auditing**: NFT trading, auction, royalty system

### Required Reading Path

```
START
  │
  ├─► patterns/nft-patterns.md
  │     └─ ERC721/1155, transfer hooks, metadata
  │
  ├─► patterns/auction-patterns.md
  │     └─ English, Dutch, sealed-bid, timing attacks
  │
  ├─► patterns/signature-malleability-patterns.md
  │     └─ Off-chain orders, signature replay, cancellation
  │
  ├─► patterns/eip-712-patterns.md
  │     └─ Typed data signing for off-chain orders
  │
  ├─► patterns/royalty-patterns.md
  │     └─ ERC2981, fee distribution, bypass prevention
  │
  └─► patterns/reentrancy-patterns.md
        └─ onERC721Received callback attacks
```

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Signature replay → free NFTs |
| **High** | Auction manipulation, royalty bypass |
| **Medium** | Metadata manipulation, callback reentrancy |

---

## Section 7: Governance / DAO

**You're auditing**: On-chain governance, voting, timelock

### Required Reading Path

```
START
  │
  ├─► patterns/dao-patterns.md
  │     └─ DAO mechanics, proposal creation, execution
  │
  ├─► patterns/vote-patterns.md
  │     └─ Voting systems, quorum, snapshot attacks
  │
  ├─► patterns/flash-loan-patterns.md
  │     └─ Flash loan voting, snapshot manipulation
  │
  ├─► patterns/timelock-patterns.md
  │     └─ Delay bypass, emergency functions
  │
  ├─► patterns/delegate-patterns.md
  │     └─ Vote delegation, snapshot attacks
  │
  └─► patterns/access-control-patterns.md
        └─ Role management, privilege escalation
```

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Governance takeover, timelock bypass |
| **High** | Flash loan voting, proposal spam |
| **Medium** | Quorum manipulation, execution ordering |

---

## Section 8: Perpetuals / Options

**You're auditing**: Perp DEX, options protocol, derivatives

### Required Reading Path

```
START
  │
  ├─► protocol-playbooks/hyperliquid.md
  │     └─ Orderbook, margin, funding rates
  │
  ├─► patterns/oracle-patterns.md
  │     └─ Mark price, index price, funding attacks
  │
  ├─► patterns/liquidation-patterns.md
  │     └─ Margin calls, cascade liquidations
  │
  ├─► patterns/funding-rate-patterns.md
  │     └─ Funding manipulation, rate arbitrage
  │
  └─► methodology/economic-attack-modeling.md
        └─ Game theory, position manipulation
```

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Oracle manipulation → liquidation cascade |
| **High** | Funding rate manipulation, ADL abuse |
| **Medium** | Mark price deviation, insurance fund drain |

---

## Section 9: Intent Systems

**You're auditing**: Intent-based protocol, solver network, CoW-style

### Required Reading Path

```
START
  │
  ├─► patterns/intent-based-attacks.md
  │     └─ Solver collusion, intent front-running
  │
  ├─► patterns/signature-malleability-patterns.md
  │     └─ Intent signing, signature replay, cancellation
  │
  ├─► patterns/eip-712-patterns.md
  │     └─ Typed data signing for intents
  │
  ├─► patterns/solver-patterns.md
  │     └─ Solver competition, MEV extraction
  │
  └─► patterns/sandwich-attack-patterns.md
        └─ Solver sandwich, batch manipulation
```

### Key Vulnerabilities by Severity

| Severity | Watch For |
|----------|-----------|
| **Critical** | Intent forgery, unauthorized execution |
| **High** | Solver collusion, preferential ordering |
| **Medium** | Intent expiry bypass, partial fill manipulation |

---

## Universal Checks (Always Apply)

Regardless of protocol type, **always check** these patterns:

```
┌─────────────────────────────────────────────────────────┐
│                  UNIVERSAL CHECKLIST                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  □ patterns/access-control-patterns.md                  │
│    └─ Owner privileges, role management                 │
│                                                         │
│  □ patterns/reentrancy-patterns.md                      │
│    └─ All external calls, callbacks                     │
│                                                         │
│  □ patterns/overflow-underflow-patterns.md              │
│    └─ Unchecked blocks, type casting                    │
│                                                         │
│  □ patterns/dos-patterns.md                             │
│    └─ Gas limits, unbounded loops                       │
│                                                         │
│  □ methodology/upgrade-migration-patterns.md            │
│    └─ Proxy patterns, storage layout                    │
│                                                         │
│  □ methodology/gas-optimization-security.md             │
│    └─ Dangerous optimizations                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Chain-Specific Considerations

| Chain | Guide | Key Differences |
|-------|-------|-----------------|
| **Ethereum** | Default patterns | EIP standards, gas model |
| **Arbitrum/Optimism** | chain-guides/arbitrum.md | L1→L2 messaging, sequencer |
| **Solana** | chain-guides/solana.md | Account model, PDA, CPI |
| **Move (Sui/Aptos)** | chain-guides/sui.md, aptos.md | Resources, abilities |
| **StarkNet** | chain-guides/starknet.md | Cairo, felt252, native AA |
| **TON** | ton-scanner/SKILL.md | Actor model, async |
| **Cosmos** | chain-guides/cosmos.md | IBC, modules |

---

## Quick Reference: File Location Guide

| Looking For... | File Location |
|----------------|---------------|
| Attack patterns | `patterns/*.md` |
| Protocol examples | `protocol-playbooks/*.md` |
| Audit methodology | `methodology/*.md` |
| Chain-specific | `chain-guides/*.md` |
| Severity classification | `severity/*.md` |
| Comprehensive checklist | `checklists/comprehensive-checklist.md` |
| PoC templates | `methodology/poc-writing-guide.md` |
| Secure implementations | `methodology/secure-pattern-reference.md` |

---

## How to Use This Map

### For AI Agents

1. Identify protocol type from codebase analysis
2. Navigate to relevant section
3. Load files in **Required Reading Path** order
4. Check **Also Check** table for additional patterns
5. Apply **Universal Checks** to all audits

### For Human Auditors

1. Start with protocol section for mental model
2. Use severity tables to prioritize
3. Cross-reference related patterns
4. Document findings using `methodology/audit-report-templates.md`
