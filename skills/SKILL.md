# Web3 Audit Plugin - Core Skill Definition

## Purpose
This plugin provides AI-powered smart contract security auditing capabilities across multiple blockchain platforms.

## Capabilities
- Multi-chain smart contract analysis (EVM, Solana, Move, Cairo, CosmWasm, TON)
- Pattern-based vulnerability detection using 200+ known patterns
- Protocol-specific audit checklists (DeFi, NFT, Bridge, Governance)
- Attack chain analysis for multi-step exploit detection
- Automated severity classification
- Report generation with findings templates

## Usage
1. Load the target smart contract code
2. Identify the chain and protocol type
3. Run appropriate scanner skill
4. Apply relevant checklist
5. Check attack chain patterns
6. Generate audit report

## Skill Chain
```
Context Building → Scanner → Checklist → Attack Chains → Report
```

## Available Scanners
- Solidity Scanner (EVM chains)
- Solana Scanner (Rust/Anchor)
- Cairo Scanner (Starknet)
- Move Scanner (Aptos/Sui)
- Cosmos Scanner (CosmWasm/SDK)
- TON Scanner (FunC/Tact)
- Aptos Scanner (Move/Aptos)
- Sui Scanner (Sui Move)
- Starknet Scanner (Cairo)
- Aztec Scanner (Noir)
- Fuel Scanner (Sway)
