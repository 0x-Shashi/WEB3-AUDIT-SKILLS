# Attack Trees Index

Visual decision paths for systematically exploring attack surfaces in DeFi protocols.

---

## What Are Attack Trees?

Attack trees provide **visual decision paths** showing how an attacker would systematically explore a protocol for vulnerabilities. Each tree:

- **Starts at ROOT** - The attacker's ultimate goal (steal funds, DoS, etc.)
- **Branches into attack types** - Different vulnerability categories
- **Lists conditions** - What must be true for the attack to work
- **Shows actions** - Specific steps the attacker takes
- **Links to patterns** - Cross-references to detailed vulnerability patterns
- **Maps to real exploits** - Shows which attacks have happened in the wild

---

## How to Use Attack Trees

### During Audit Planning
1. Load the relevant attack tree for the protocol type
2. Use it as a **checklist** for coverage
3. Prioritize branches based on protocol architecture

### During Active Audit
1. Work through each branch **systematically**
2. Check if **conditions** exist in the codebase
3. Write PoC for vulnerable branches
4. Cross-reference linked pattern files for details

### During Reporting
1. Copy the markdown checklist
2. Paste into your audit report
3. Mark which vulnerabilities were found
4. Show coverage by marking tested branches

---

## Available Attack Trees

### [Lending Protocol](lending-attack-tree.md)
**ROOT: Steal Funds from Lending Pool**

**Main Attack Branches:**
- [A] Manipulate Oracle Price (stale, flash loan, zero/negative prices)
- [B] Exploit Liquidation Mechanism (self-liquidation, DoS, MEV)
- [C] Accounting Manipulation (first depositor, rounding, interest rate)
- [D] Reentrancy Attacks (withdraw, cross-function, read-only, ERC777)
- [E] Flash Loan Exploitation (governance, interest spike, pause)
- [F] Access Control Bypass (initialization, missing modifiers, tx.origin)
- [G] Economic Exploits (MEV sandwich, liquidation MEV, JIT liquidity)

**Real-World Exploits:**
- Euler Finance 2023 ($197M) - Liquidation DoS
- Radiant Capital 2024 ($4.5M) - Cross-function reentrancy
- Rari Fuse 2022 ($80M) - Flash loan price manipulation
- Cream Finance 2021 ($130M) - Oracle manipulation

**Use for:** Compound, Aave, Euler, Radiant, Venus, Benqi, etc.

---

### [DEX/AMM](dex-attack-tree.md)
**ROOT: Steal Funds from DEX/AMM**

**Main Attack Branches:**
- [A] Price Oracle Manipulation (spot price, TWAP, low liquidity)
- [B] Liquidity Pool Exploits (first LP inflation, reentrancy, imbalanced drain)
- [C] Swap Exploits (sandwich, k-value, fee-on-transfer, flash swap)
- [D] Arbitrage & MEV (cross-pool arb, JIT liquidity, backrunning)
- [E] Concentrated Liquidity (tick manipulation, NFT exploits, Uniswap V3)
- [F] Router Exploits (callback reentrancy, approval front-run, path validation)
- [G] Governance & Admin (fee manipulation, pause, flash loan voting)

**Real-World Exploits:**
- Uniswap V3 Oracle 2021 - Tick manipulation
- Warp Finance 2020 ($7.7M) - Flash loan oracle attack
- Cream Finance 2021 ($130M) - Spot price manipulation
- Harvest Finance 2020 ($24M) - Price manipulation + arbitrage

**Use for:** Uniswap, SushiSwap, Curve, Balancer, PancakeSwap, etc.

---

### [Cross-Chain Bridge](bridge-attack-tree.md)
**ROOT: Steal Funds from Bridge**

**Main Attack Branches:**
- [A] Signature/Validation Exploits (replay, malleability, validator compromise)
- [B] State Synchronization (race conditions, reorgs, nonce desync)
- [C] Token Handling (mint without lock, fee-on-transfer, decimal mismatch)
- [D] Oracle/Relayer Manipulation (malicious relayer, censorship)
- [E] Smart Contract Exploits (reentrancy, initialization, upgrade, delegatecall)
- [F] Economic Attacks (liquidity drain, fee manipulation, MEV)
- [G] Protocol-Specific (merkle proof, light client, validator set updates)

**Real-World Exploits:**
- Poly Network 2021 ($610M) - Access control bypass
- Wormhole 2022 ($326M) - Missing signature verification
- Ronin Bridge 2022 ($625M) - Validator key compromise
- Nomad Bridge 2022 ($190M) - Initialization attack
- Harmony Horizon 2022 ($100M) - Validator compromise

**Use for:** Wormhole, Axelar, LayerZero, Stargate, Synapse, etc.

---

### [Vault/Yield Aggregator](vault-attack-tree.md)
**ROOT: Steal Funds from Vault**

**Main Attack Branches:**
- [A] Share Price Manipulation (first depositor, donation, rounding, fees)
- [B] Strategy Exploits (reentrancy, malicious strategy, debt manipulation)
- [C] Withdrawal Exploits (fee avoidance, reentrancy, slippage)
- [D] Oracle/Price Manipulation (flash loan, stale price, LP pricing)
- [E] ERC4626 Violations (preview accuracy, conversion bugs, limits)
- [F] Access Control & Admin (initialization, governance, migration)
- [G] Token-Specific (fee-on-transfer, rebasing, ERC777, deflationary)
- [H] Reward Distribution (dilution, flash loan farming, reentrancy)

**Real-World Exploits:**
- Yearn Finance 2023 ($11M) - First depositor attack
- Rari Capital 2022 ($80M) - Malicious strategy
- Beefy Finance 2021 ($11M) - Strategy loss

**Use for:** Yearn, Beefy, Harvest, Convex, Pendle, etc.

---

## Attack Tree Format

Each attack tree follows this structure:

```
ROOT: Ultimate Attack Goal
│
├── [A] Attack Category
│   │
│   ├── [A1] Specific Attack Type
│   │   ├── Condition: What must be true for this attack
│   │   ├── Action: What the attacker does
│   │   ├── Result: What happens if successful
│   │   └── Check: Link to detailed pattern file
│   │
│   └── [A2] Another Attack Type
│       ├── Condition: ...
│       ├── Action: ...
│       ├── Result: ...
│       └── Check: ...
│
└── [B] Next Category
    └── ...
```

---

## Quick Start Guide

**For a Lending Protocol Audit:**
```bash
1. Load: attack-trees/lending-attack-tree.md
2. Check: [A] Oracle section - Most common critical
3. Test: First depositor attack [C1] - Easy to exploit
4. Verify: Liquidation DoS [B2] - Recent Euler exploit
5. Deep-dive: Load linked patterns for each vulnerability
```

**For a DEX Audit:**
```bash
1. Load: attack-trees/dex-attack-tree.md
2. Check: [A1] Spot price usage - Critical
3. Test: First LP inflation [B1] - Easy to exploit
4. Verify: Flash swap reentrancy [C5] - Common
5. For Uniswap V3: Focus on [E] Concentrated Liquidity
```

**For a Bridge Audit:**
```bash
1. Load: attack-trees/bridge-attack-tree.md
2. Check: [A] Signature section - Most exploited
3. Test: Signature replay [A1] - Easy to test
4. Verify: Decimal mismatch [C5] - Often missed
5. Deep-dive: Validator threshold [A4] - Architecture dependent
```

**For a Vault Audit:**
```bash
1. Load: attack-trees/vault-attack-tree.md
2. Check: [A1] First depositor - Critical, common
3. Test: Share price manipulation [A] - Entire section
4. Verify: Strategy exploits [B] - Each strategy separately
5. If ERC4626: Focus on [E] Standard violations
```

---

## Integration with Other Skills

Attack trees work best when combined with:

1. **Pattern Files** - Detailed vulnerability explanations
   - `patterns/lending-pool-patterns.md`
   - `patterns/dex-patterns.md`
   - `patterns/bridge-patterns.md`
   - `patterns/defi-vault-patterns.md`

2. **Exploit Forensics** - Real-world examples
   - `exploit-forensics/euler-2023.md`
   - `exploit-forensics/wormhole-2022.md`
   - `exploit-forensics/yearn-2023.md`

3. **Checklists** - Coverage verification
   - `checklists/comprehensive-checklist.md`
   - `checklists/roles/auditor-first-pass.md`

4. **ROUTE-MAP.md** - Overall audit methodology

---

## Creating Custom Attack Trees

When auditing novel protocols:

1. **Start with ROOT** - What's the ultimate attack goal?
2. **Identify categories** - Group by vulnerability type
3. **Branch systematically** - Cover all attack surfaces
4. **Add conditions** - When is this exploitable?
5. **Link to patterns** - Cross-reference existing knowledge
6. **Test thoroughly** - Write PoC for each branch

Example custom tree:
```
ROOT: Steal Funds from NFT Lending
├── [A] NFT Price Oracle
├── [B] NFT Liquidation
├── [C] Flash Loan + NFT
└── [D] NFT-Specific (ownership, metadata, approval)
```

---

## Contribution Guidelines

When adding new attack trees:

1. **Use consistent format** - Follow existing trees
2. **Link to patterns** - Cross-reference detailed files
3. **Include real exploits** - Map to actual incidents
4. **Provide checklist** - Copy-pasteable markdown
5. **Update this index** - Keep index.md current

---

## References

- **ROUTE-MAP.md** - Overall audit methodology
- **patterns/** - Detailed vulnerability patterns
- **exploit-forensics/** - Real-world exploit analysis
- **checklists/** - Coverage verification tools

---

**Last Updated:** 2024
**Version:** 1.0
