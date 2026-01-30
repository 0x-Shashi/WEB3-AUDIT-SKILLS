---
name: context-detection
description: "Automatically detects the context of code being audited: chain, language, protocol type, and risk profile. Use this skill first to load appropriate scanners and patterns."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Context Detection Skill

## Purpose

Automatically analyze a codebase to determine:
1. **Chain/Language** - What blockchain and language
2. **Protocol Type** - What kind of protocol (DEX, lending, etc.)
3. **Risk Profile** - Complexity and attack surface

---

## When to Use

- **Always first** when starting an audit
- Before loading specific scanner skills
- When unsure what patterns to apply

---

## Detection Flow

```
┌─────────────────┐
│  Read Project   │
│  Structure      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐
│  Detect Chain   │───▶│  Load Scanner   │
└────────┬────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐
│ Detect Protocol │───▶│ Load Template   │
└────────┬────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐
│ Assess Risk     │───▶│ Prioritize      │
└─────────────────┘    └─────────────────┘
```

---

## Chain Detection

### Detection Patterns

| Files/Patterns | Chain | Scanner to Load |
|----------------|-------|-----------------|
| `*.sol`, `hardhat.config`, `foundry.toml` | EVM/Solidity | solidity-scanner |
| `Cargo.toml` + `anchor` | Solana | solana-scanner |
| `Move.toml` + `sui::` | Sui | sui-scanner |
| `Move.toml` + `aptos_framework` | Aptos | aptos-scanner |
| `Scarb.toml`, `*.cairo` | Starknet | starknet-scanner |
| `Nargo.toml`, `*.nr` | Aztec | aztec-scanner |
| `Forc.toml`, `*.sw` | Fuel | fuel-scanner |
| `*.fc`, `*.tact` | TON | ton-scanner |
| `Cargo.toml` + `cosmwasm` | Cosmos | cosmos-scanner |

### Detection Commands

```bash
# EVM
ls *.sol 2>/dev/null || ls contracts/*.sol 2>/dev/null

# Solana
grep -r "anchor" Cargo.toml 2>/dev/null

# Sui
grep -r "sui::" sources/*.move 2>/dev/null

# Aptos
grep -r "aptos_framework" sources/*.move 2>/dev/null

# Starknet
ls *.cairo 2>/dev/null || ls src/*.cairo 2>/dev/null

# Aztec
ls *.nr 2>/dev/null && cat Nargo.toml 2>/dev/null

# Fuel
ls *.sw 2>/dev/null && cat Forc.toml 2>/dev/null
```

---

## Protocol Detection

### Detection Patterns

| Code Patterns | Protocol Type | Template to Load |
|---------------|---------------|------------------|
| `swap`, `addLiquidity`, `pair`, `pool` | AMM/DEX | amm-dex-template |
| `borrow`, `lend`, `collateral`, `liquidate` | Lending | lending-template |
| `bridge`, `l1`, `l2`, `crossChain` | Bridge | bridge-template |
| `stake`, `unstake`, `delegate`, `validator` | Staking | staking-template |
| `mint`, `tokenURI`, `royalty`, `marketplace` | NFT | nft-marketplace-template |
| `propose`, `vote`, `execute`, `timelock` | Governance | governance-template |
| `vault`, `strategy`, `harvest`, `yield` | Yield/Vault | vault-template |
| `oracle`, `price`, `feed`, `twap` | Oracle | oracle-template |

### Detection Commands

```bash
# DEX patterns
grep -ri "swap\|addLiquidity\|removeLiquidity\|pair" . --include="*.sol"

# Lending patterns
grep -ri "borrow\|lend\|collateral\|liquidat" . --include="*.sol"

# Bridge patterns
grep -ri "bridge\|l1handler\|crosschain\|message" . --include="*.sol"

# Staking patterns
grep -ri "stake\|unstake\|delegate\|reward" . --include="*.sol"
```

---

## Risk Profiling

### Complexity Score

| Factor | Low (1) | Medium (2) | High (3) |
|--------|---------|------------|----------|
| Lines of Code | <500 | 500-2000 | >2000 |
| External Calls | 0-2 | 3-5 | >5 |
| Proxy Patterns | None | Single | Multiple |
| Token Standards | Standard | Modified | Custom |
| Oracle Usage | None | Single | Multiple |

### Attack Surface Score

| Factor | Points |
|--------|--------|
| Handles ETH/native tokens | +2 |
| Handles ERC20 | +1 |
| Flash loan capable | +3 |
| Cross-chain messaging | +3 |
| Upgradeable | +2 |
| Uses oracles | +2 |
| Governance controlled | +1 |
| Has timelock | -1 |

---

## Output Format

```yaml
context:
  chain: "ethereum"
  language: "solidity"
  version: "0.8.19"
  
protocol:
  type: "lending"
  similar_to: ["Aave", "Compound"]
  
risk:
  complexity: "high"
  attack_surface: 12
  priority_areas:
    - "liquidation logic"
    - "oracle integration"
    - "interest rate model"
    
recommended_skills:
  scanners:
    - solidity-scanner
  patterns:
    - defi-patterns
    - oracle-patterns
  templates:
    - lending-template
  attack_chains:
    - flash-loan-chains
    - oracle-chains
```

---

## Quick Detection Script

```bash
#!/bin/bash
echo "=== Chain Detection ==="

if ls *.sol 2>/dev/null || ls contracts/*.sol 2>/dev/null; then
    echo "Chain: EVM/Solidity"
    echo "Scanner: solidity-scanner"
elif grep -q "anchor" Cargo.toml 2>/dev/null; then
    echo "Chain: Solana"
    echo "Scanner: solana-scanner"
elif grep -q "sui::" sources/*.move 2>/dev/null; then
    echo "Chain: Sui"
    echo "Scanner: sui-scanner"
elif ls *.cairo 2>/dev/null; then
    echo "Chain: Starknet"
    echo "Scanner: starknet-scanner"
fi

echo ""
echo "=== Protocol Detection ==="

if grep -ri "swap\|liquidity" . --include="*.sol" -q 2>/dev/null; then
    echo "Type: DEX/AMM"
    echo "Template: amm-dex-template"
elif grep -ri "borrow\|lend" . --include="*.sol" -q 2>/dev/null; then
    echo "Type: Lending"
    echo "Template: lending-template"
elif grep -ri "bridge\|l1\|l2" . --include="*.sol" -q 2>/dev/null; then
    echo "Type: Bridge"
    echo "Template: bridge-template"
fi
```

---

## Next Steps After Detection

1. Load recommended scanner skill
2. Load protocol template
3. Load relevant attack chains
4. Begin systematic audit with context
