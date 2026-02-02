# Context Injection Files

Ultra-compressed security context for AI token efficiency. Load ONE file to get 80% of critical knowledge for a protocol type.

## Purpose

Instead of loading 10+ skill files (5000+ tokens), load one 200-line context file (~800 tokens) with the essential checks.

## Files

| File | Protocol Type | Critical Checks |
|------|--------------|-----------------|
| [lending-context.md](lending-context.md) | Lending/Borrowing | Oracle, liquidation, interest, collateral |
| [dex-context.md](dex-context.md) | DEX/AMM | Slippage, MEV, LP math, flash loans |
| [bridge-context.md](bridge-context.md) | Cross-chain bridges | Message validation, replay, finality |
| [staking-context.md](staking-context.md) | Staking/Rewards | Reward math, withdrawal, slashing |
| [governance-context.md](governance-context.md) | DAO/Governance | Vote manipulation, flash loans, timelock |
| [vault-context.md](vault-context.md) | Vaults/Yield | Share inflation, first depositor, ERC4626 |

## Usage

```
AI Prompt: "Audit this lending protocol"
→ Load: lending-context.md (200 lines, ~800 tokens)
→ Contains: All critical lending vulnerabilities in compressed format
```

## Format Convention

```markdown
## CATEGORY
1. Check: condition → impact | fix
2. Check: condition → impact | fix

### Code Pattern (if critical)
```solidity
// Vulnerable vs Safe pattern
```
```

## Token Comparison

| Approach | Files | Tokens | Coverage |
|----------|-------|--------|----------|
| Full skills | 10+ files | 5000+ | 100% |
| Context injection | 1 file | ~800 | 80% |
| Savings | - | **84%** | - |
