# Languages Skill

## Quick Start

This folder contains language-specific security guidance. Different smart contract languages have different security characteristics and common vulnerability patterns.

## Supported Languages

| Language | Blockchain | Maturity | Security Tools |
|----------|------------|----------|----------------|
| [Solidity](solidity.md) | Ethereum, EVM chains | High | Slither, Foundry, Echidna |
| [Rust](rust.md) | Solana, Near, Cosmos | High | cargo-audit, clippy |
| [Cairo](cairo.md) | Starknet | Medium | Protostar |
| [Vyper](vyper.md) | Ethereum | Medium | Limited |
| [Move](move.md) | Aptos, Sui | Medium | Move Prover |

## Query by Language

### Single Language

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "languages": [{"value": "Solidity"}],
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Multiple Languages

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "languages": [{"value": "Rust"}, {"value": "Move"}],
      "impact": ["HIGH"]
    }
  }'
```

### Language + Category

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "languages": [{"value": "Solidity"}],
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH"]
    }
  }'
```

## Language Risk Profiles

### Solidity (EVM)
- **Reentrancy:** Major concern due to external calls
- **Integer overflow:** Pre-0.8 issue, now built-in checks
- **Gas limits:** DoS via unbounded operations
- **Assembly:** Low-level risks

### Rust (Solana/Near/Cosmos)
- **Memory safety:** Language handles this
- **Account confusion:** Major Solana issue
- **Arithmetic:** Must use checked operations
- **Cross-program invocation:** Trust boundaries

### Cairo (Starknet)
- **Felt type:** Limited integer range
- **Storage:** Unique storage model
- **Proofs:** ZK-specific considerations
- **Upgrades:** Different proxy patterns

### Vyper (EVM)
- **Simpler language:** Fewer footguns
- **Reentrancy lock:** Built-in decorator
- **Limited features:** By design
- **Compiler bugs:** Smaller community

### Move (Aptos/Sui)
- **Resource model:** Unique ownership
- **Formal verification:** Built-in prover
- **Abilities:** Restrict type capabilities
- **Modules:** Different than contracts

## Language Selection Guide

| Your Use Case | Recommended Language |
|---------------|---------------------|
| EVM DeFi | Solidity |
| Simple EVM contracts | Vyper |
| High performance | Rust (Solana) |
| Formal verification needed | Move |
| ZK applications | Cairo |

## Cross-Language Vulnerabilities

Some vulnerabilities exist across languages:

| Vulnerability | Solidity | Rust | Cairo | Move |
|---------------|----------|------|-------|------|
| Integer overflow | Yes* | Yes | Yes | Yes |
| Access control | Yes | Yes | Yes | Yes |
| Reentrancy | Yes | No | No | No |
| Oracle issues | Yes | Yes | Yes | Yes |
| Logic errors | Yes | Yes | Yes | Yes |

*Solidity 0.8+ has built-in overflow checks

## Test This Skill

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "languages": [{"value": "Solidity"}],
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, tags: [.issues_issuetagscore[]?.tags_tag.title] | unique}'
```

## Cross-Reference

- For vulnerability patterns → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For protocol specifics → See [../protocol-categories/SKILL.md](../protocol-categories/SKILL.md)
