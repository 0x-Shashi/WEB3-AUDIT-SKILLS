---
id: NFT-LENDING-ATTACK-TREE
title: NFT Lending Attack Tree
category: attack-tree
protocol: nft-lending
triggers:
  - nft lending attack paths
  - how to attack nft collateral
  - nft oracle manipulation
  - nft lending exploit tree
related_skills:
  - patterns/nft-patterns.md
  - patterns/oracle-patterns.md
  - patterns/lending-pool-patterns.md
  - exploit-forensics/jpegd-2023.md
---

# NFT Lending Attack Tree

Visual decision path for attacking NFT lending protocols (peer-to-peer, peer-to-pool, CDP-style).

---

## ROOT: Steal Funds or Trap Collateral

```
ROOT: Steal Funds or Trap Collateral
│
├── [A] NFT Oracle Manipulation
│   │
│   ├── [A1] Floor Price Manipulation
│   │   ├── Condition: Oracle uses floor price from single marketplace
│   │   ├── Action: Buy all floor NFTs → Inflate floor
│   │   ├── Result: Borrow more than NFT worth
│   │   └── Check: patterns/oracle-patterns.md#nft-floor
│   │
│   ├── [A2] Wash Trading to Inflate Valuation
│   │   ├── Condition: Oracle uses recent sale prices
│   │   ├── Action: Sell NFT to self at high price
│   │   ├── Result: Oracle thinks NFT valuable → Over-borrow
│   │   └── Check: patterns/nft-patterns.md#wash-trading
│   │
│   ├── [A3] Rarity Score Manipulation
│   │   ├── Condition: Rarity score used for valuation
│   │   ├── Action: Manipulate traits → Inflate rarity
│   │   ├── Result: Borrow more against "rare" NFT
│   │   └── Check: patterns/nft-patterns.md#rarity-manipulation
│   │
│   ├── [A4] Cross-Marketplace Discrepancy
│   │   ├── Condition: Oracle uses single marketplace
│   │   ├── Action: Manipulate one marketplace while borrowing on another
│   │   ├── Result: Price arbitrage between venues
│   │   └── Check: patterns/oracle-patterns.md#cross-market
│   │
│   ├── [A5] Stale Oracle Data
│   │   ├── Condition: Oracle doesn't update frequently
│   │   ├── Action: Borrow after price crash, before oracle updates
│   │   ├── Result: Borrow more than current value
│   │   └── Check: patterns/oracle-patterns.md#stale-data
│   │
│   └── [A6] Oracle Front-Running
│       ├── Condition: Oracle update transaction visible
│       ├── Action: Front-run price decrease with borrow
│       ├── Result: Borrow at old (higher) price
│       └── Check: patterns/mev-patterns.md#oracle-frontrun
│
├── [B] NFT Trait/Metadata Manipulation
│   │
│   ├── [B1] Metadata Mutation
│   │   ├── Condition: NFT metadata mutable after deposit
│   │   ├── Action: Deposit valuable → Change to worthless → Keep loan
│   │   ├── Result: Collateral becomes worthless
│   │   └── Check: patterns/nft-patterns.md#metadata-mutation
│   │
│   ├── [B2] Reveal Timing Attack
│   │   ├── Condition: NFT reveal happens after lending
│   │   ├── Action: Deposit unrevealed → Reveal as garbage → Default
│   │   ├── Result: Protocol stuck with worthless NFT
│   │   └── Check: patterns/nft-patterns.md#reveal-timing
│   │
│   ├── [B3] Wrapped NFT Manipulation
│   │   ├── Condition: Wrapped version used as collateral
│   │   ├── Action: Deposit wrapped → Unwrap real → Wrapped becomes void
│   │   ├── Result: Collateral no longer backed
│   │   └── Check: patterns/nft-patterns.md#wrapped-nft
│   │
│   ├── [B4] Dynamic NFT Trait Change
│   │   ├── Condition: NFT traits change over time
│   │   ├── Action: Deposit when valuable → Traits degrade → Keep loan
│   │   ├── Result: Collateral loses value automatically
│   │   └── Check: patterns/nft-patterns.md#dynamic-traits
│   │
│   └── [B5] NFT Utility Removal
│       ├── Condition: NFT value tied to utility
│       ├── Action: Deposit → Project removes utility → Value crashes
│       ├── Result: Collateral worthless but loan outstanding
│       └── Check: patterns/nft-patterns.md#utility-removal
│
├── [C] Liquidation Exploits
│   │
│   ├── [C1] Liquidation Front-Running
│   │   ├── Condition: Liquidation calls publicly visible
│   │   ├── Action: Front-run liquidation to steal NFT
│   │   ├── Result: Liquidator profit at borrower expense
│   │   └── Check: patterns/mev-patterns.md#nft-liquidation
│   │
│   ├── [C2] Floor Crash to Trigger Liquidation
│   │   ├── Condition: Many similar NFTs collateralized
│   │   ├── Action: Dump floor → Mass liquidations
│   │   ├── Result: Acquire NFTs at discount via liquidation
│   │   └── Check: patterns/nft-patterns.md#floor-crash
│   │
│   ├── [C3] Liquidation DoS
│   │   ├── Condition: Liquidation can be blocked
│   │   ├── Action: Prevent liquidations during price crash
│   │   ├── Result: Protocol accumulates bad debt
│   │   └── Check: patterns/dos-patterns.md#liquidation
│   │
│   ├── [C4] Liquidation Bonus Exploitation
│   │   ├── Condition: High liquidation bonus
│   │   ├── Action: Self-liquidate or coordinate
│   │   ├── Result: Extract bonus unfairly
│   │   └── Check: patterns/lending-pool-patterns.md#liquidation-bonus
│   │
│   ├── [C5] Batch Liquidation Manipulation
│   │   ├── Condition: Multiple positions liquidatable
│   │   ├── Action: Cherry-pick best NFTs to liquidate
│   │   ├── Result: Protocol left with worst collateral
│   │   └── Check: patterns/nft-patterns.md#selective-liquidation
│   │
│   └── [C6] Re-entrancy During Liquidation
│       ├── Condition: Liquidation calls NFT contract
│       ├── Action: Re-enter during liquidation callback
│       ├── Result: Steal NFT without repaying debt
│       └── Check: patterns/reentrancy-patterns.md#erc721
│
├── [D] Fake/Malicious NFT Attacks
│   │
│   ├── [D1] Counterfeit NFT Deposit
│   │   ├── Condition: Protocol doesn't verify collection address
│   │   ├── Action: Deposit fake NFT from look-alike contract
│   │   ├── Result: Borrow funds with worthless collateral
│   │   └── Check: patterns/nft-patterns.md#counterfeit
│   │
│   ├── [D2] Malicious NFT Contract
│   │   ├── Condition: NFT contract can be malicious
│   │   ├── Action: Deploy NFT with DoS in transfer
│   │   ├── Result: NFT can't be liquidated/transferred
│   │   └── Check: patterns/nft-patterns.md#malicious-contract
│   │
│   ├── [D3] Rug Pull Collection
│   │   ├── Condition: Project team can rug
│   │   ├── Action: Deposit → Team rugs → Value gone
│   │   ├── Result: Protocol stuck with worthless NFTs
│   │   └── Check: patterns/nft-patterns.md#rug-pull
│   │
│   ├── [D4] Honeypot NFT
│   │   ├── Condition: NFT can be deposited but not withdrawn
│   │   ├── Action: Deposit NFT with withdrawal restrictions
│   │   ├── Result: Protocol can't seize collateral
│   │   └── Check: patterns/nft-patterns.md#honeypot
│   │
│   └── [D5] Operator Filter Manipulation
│       ├── Condition: NFT uses operator filter registry
│       ├── Action: Block protocol from operating NFT
│       ├── Result: Can't transfer/liquidate
│       └── Check: patterns/nft-patterns.md#operator-filter
│
├── [E] Peer-to-Peer Specific Attacks
│   │
│   ├── [E1] Offer Sniping
│   │   ├── Condition: Best offers visible publicly
│   │   ├── Action: Front-run to accept best offers
│   │   ├── Result: Steal favorable terms
│   │   └── Check: patterns/mev-patterns.md#offer-sniping
│   │
│   ├── [E2] Lender Griefing
│   │   ├── Condition: Lender funds locked in offer
│   │   ├── Action: Never accept → Lock funds indefinitely
│   │   ├── Result: DoS lender capital
│   │   └── Check: patterns/dos-patterns.md#p2p
│   │
│   ├── [E3] Repayment Front-Running
│   │   ├── Condition: Repayment publicly visible
│   │   ├── Action: Front-run repayment to seize collateral
│   │   ├── Result: Unfair liquidation
│   │   └── Check: patterns/mev-patterns.md#repayment-frontrun
│   │
│   ├── [E4] Signature Replay
│   │   ├── Condition: Offer signatures reusable
│   │   ├── Action: Reuse old favorable signature
│   │   ├── Result: Get terms no longer offered
│   │   └── Check: patterns/signature-patterns.md#replay
│   │
│   └── [E5] Offer Spam Attack
│       ├── Condition: Can flood with fake offers
│       ├── Action: Spam system with invalid offers
│       ├── Result: DoS real offer matching
│       └── Check: patterns/dos-patterns.md#spam
│
├── [F] Pool-Based Specific Attacks
│   │
│   ├── [F1] Pool Drain via Over-Valuation
│   │   ├── Condition: Pool uses optimistic pricing
│   │   ├── Action: Deposit overvalued NFTs
│   │   ├── Result: Drain pool with bad collateral
│   │   └── Check: patterns/nft-patterns.md#pool-drain
│   │
│   ├── [F2] First Depositor Attack
│   │   ├── Condition: New pool without liquidity
│   │   ├── Action: Deposit first with inflated valuation
│   │   ├── Result: Manipulate pool pricing model
│   │   └── Check: patterns/vault-patterns.md#first-depositor
│   │
│   ├── [F3] Interest Rate Manipulation
│   │   ├── Condition: Interest rate based on utilization
│   │   ├── Action: Flash borrow → Spike rate → Profit
│   │   ├── Result: Extract from other borrowers
│   │   └── Check: patterns/lending-pool-patterns.md#interest-rate
│   │
│   ├── [F4] Liquidity Extraction
│   │   ├── Condition: Lenders can withdraw anytime
│   │   ├── Action: Large borrow → Lenders panic → Pool drained
│   │   ├── Result: Borrower keeps funds, no liquidity to repay
│   │   └── Check: patterns/lending-pool-patterns.md#bank-run
│   │
│   └── [F5] Yield Farming Dump
│       ├── Condition: Pool offers token rewards
│       ├── Action: Farm rewards → Dump token
│       ├── Result: Devalue protocol token, economic attack
│       └── Check: patterns/tokenomics-patterns.md#farming-dump
│
└── [G] Cross-Protocol & Advanced Attacks
    │
    ├── [G1] Flash Loan Price Manipulation
    │   ├── Condition: Price oracle manipulatable via flash loan
    │   ├── Action: Flash loan → Manipulate → Borrow → Repay
    │   ├── Result: Borrow more than deserved
    │   └── Check: patterns/flash-loan-patterns.md#nft-oracle
    │
    ├── [G2] Collateral Fragmentation
    │   ├── Condition: NFT can be fractionalized
    │   ├── Action: Deposit → Fractionalize → Sell fractions
    │   ├── Result: Collateral ownership disputed
    │   └── Check: patterns/nft-patterns.md#fragmentation
    │
    ├── [G3] Governance Attack on Whitelist
    │   ├── Condition: Governance controls accepted NFTs
    │   ├── Action: Vote to whitelist own worthless NFTs
    │   ├── Result: Borrow against garbage
    │   └── Check: patterns/governance-patterns.md#whitelist
    │
    ├── [G4] Cross-Chain NFT Exploit
    │   ├── Condition: NFTs bridged across chains
    │   ├── Action: Exploit bridge to duplicate NFT
    │   ├── Result: Borrow on both chains with one NFT
    │   └── Check: patterns/bridge-patterns.md#nft
    │
    └── [G5] Rental Market Arbitrage
        ├── Condition: Can rent NFT cheaply
        ├── Action: Rent → Use as collateral → Default
        ├── Result: Profit from rent-vs-borrow arbitrage
        └── Check: patterns/nft-patterns.md#rental-arbitrage
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify lending model** - Peer-to-peer, Peer-to-pool, CDP-style
2. **Check NFT verification** - Collection whitelist, contract validation, metadata immutability
3. **Analyze oracle** - Floor price source, manipulation resistance, update frequency
4. **Test liquidation** - Fair ordering, DoS resistance, bonus exploitation
5. **Review NFT handling** - Transfer safety, re-entrancy, malicious contracts

---

## Quick Reference by Protocol Type

### Peer-to-Peer (P2P)
**Critical Vulnerabilities:**
- [E1] Offer Sniping (Medium)
- [E4] Signature Replay (High)
- [A2] Wash Trading (High)

**Examples:** NFTfi, Arcade, MetaStreet

### Peer-to-Pool
**Critical Vulnerabilities:**
- [F1] Pool Drain (Critical)
- [F2] First Depositor (High)
- [A1] Floor Manipulation (Critical)

**Examples:** BendDAO, JPEG'd, Drops

### CDP-Style
**Critical Vulnerabilities:**
- [A1] Floor Manipulation (Critical)
- [C2] Floor Crash Liquidation (High)
- [B1] Metadata Mutation (Critical)

**Examples:** JPEG'd (alt mode), Pine Loans

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| JPEG'd Exploit | 2023 | $11.6M | [A1] Floor Manipulation | Attacker inflated floor, over-borrowed |
| BendDAO Crisis | 2022 | Near-collapse | [C2] + [F4] | Floor crash + bank run |
| Wasabi Floor Manipulation | 2023 | Undisclosed | [A2] Wash Trading | Used to inflate valuations |

---

## Checklist (Copy for Audit)

```markdown
## NFT Lending Attack Surface

### Oracle [A]
- [ ] [A1] Floor price manipulation resistant
- [ ] [A2] Wash trading detection
- [ ] [A3] Rarity score validation
- [ ] [A4] Multi-marketplace aggregation
- [ ] [A5] Fresh data (<1hr old)
- [ ] [A6] Front-running protection

### NFT Integrity [B]
- [ ] [B1] Metadata immutability verified
- [ ] [B2] Reveal timing handled
- [ ] [B3] Wrapped NFT validation
- [ ] [B4] Dynamic traits accounted for
- [ ] [B5] Utility dependencies documented

### Liquidation [C]
- [ ] [C1] Liquidation MEV mitigation
- [ ] [C2] Floor crash circuit breakers
- [ ] [C3] Liquidation cannot be DoS'd
- [ ] [C4] Liquidation bonus reasonable
- [ ] [C5] Fair liquidation ordering
- [ ] [C6] ERC721 re-entrancy safe

### Fake NFTs [D]
- [ ] [D1] Collection address whitelist enforced
- [ ] [D2] Malicious contract detection
- [ ] [D3] Project rug risk documented
- [ ] [D4] Transfer/approve checks
- [ ] [D5] Operator filter compatibility

### P2P Specific [E]
- [ ] [E1] Offer front-running protection
- [ ] [E2] Lender griefing prevention
- [ ] [E3] Repayment timing safe
- [ ] [E4] Signature nonce/expiry
- [ ] [E5] Offer spam mitigation

### Pool Specific [F]
- [ ] [F1] Over-valuation protection
- [ ] [F2] First depositor handled
- [ ] [F3] Interest rate manipulation resistant
- [ ] [F4] Bank run protections
- [ ] [F5] Token dump mitigation

### Advanced [G]
- [ ] [G1] Flash loan oracle manipulation resistant
- [ ] [G2] Fractionalization handled
- [ ] [G3] Governance whitelist secure
- [ ] [G4] Cross-chain consistency
- [ ] [G5] Rental arbitrage prevented
```

---

## NFT-Specific Verification Steps

### Collection Verification
**Key Checks:**
- Correct contract address
- Collection authenticity (not fake)
- Metadata hosted reliably (IPFS/Arweave)
- Contract not upgradeable maliciously

### Valuation Model
**Key Checks:**
- Floor price from multiple sources
- Recent sale validation (not wash trades)
- Trait rarity correctly calculated
- Historical data considered

### Transfer Safety
**Key Checks:**
- ERC721 re-entrancy protection
- Approval/operator checks
- Transfer restrictions handled
- Royalty enforcement (if any)

### Liquidation Mechanics
**Key Checks:**
- Grace period reasonable
- Fair pricing for liquidation
- Cannot be front-run unfairly
- NFT can actually be transferred

---

## See Also

- **Patterns:** [nft-patterns.md](../patterns/nft-patterns.md)
- **Oracle Patterns:** [oracle-patterns.md](../patterns/oracle-patterns.md)
- **Lending Patterns:** [lending-pool-patterns.md](../patterns/lending-pool-patterns.md)
- **Exploits:** exploit-forensics/jpegd-2023.md, exploit-forensics/benddao-crisis-2022.md

---

**Last Updated:** 2025
**Version:** 1.0
