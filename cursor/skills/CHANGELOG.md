# Pattern Changelog

Tracks evolution of security patterns, attack vectors, and vulnerabilities over time.

---

## Why This Matters

DeFi security is constantly evolving:
- **New attack vectors** emerge from real exploits
- **Patterns evolve** based on lessons learned
- **Old patterns** may become deprecated as standards improve
- **Best practices** change with new tools and frameworks

This changelog helps you:
1. **Stay current** - Know what's new in security
2. **Understand evolution** - See how patterns were discovered
3. **Avoid outdated advice** - Know what's deprecated
4. **Learn from history** - See which exploits led to which patterns

---

## Version History

### v4.0 - January 2025 (Current)

**New Additions:**

**Attack Trees** (NEW)
- Added visual decision paths for systematic vulnerability discovery
- lending-attack-tree.md - Comprehensive lending protocol attack surface
- dex-attack-tree.md - DEX/AMM attack paths
- bridge-attack-tree.md - Cross-chain bridge vulnerabilities
- vault-attack-tree.md - Vault/yield aggregator attack surface
- attack-trees/INDEX.md - Navigation and usage guide

**Anti-Patterns** (NEW)
- Added "what NOT to do" examples with real exploit PoCs
- oracle-anti-patterns.md - 7 common oracle mistakes ($200M+ in losses)
- access-control-anti-patterns.md - 7 access control mistakes ($1.4B+ in losses)
- reentrancy-anti-patterns.md - 7 reentrancy mistakes ($115M+ in losses)
- anti-patterns/INDEX.md - Catalog of bad patterns

**Smart Checklists** (NEW)
- Added role-based context-aware checklists
- checklists/roles/developer-pre-deployment.md - Pre-deployment sanity checks
- checklists/roles/auditor-first-pass.md - 30-60 min initial scan
- checklists/roles/qa-integration-testing.md - Integration test scenarios
- checklists/roles/protocol-integration.md - External protocol integration guide

**Navigation Tools** (NEW)
- XREF.md - Cross-reference index mapping vulnerabilities → patterns → exploits → fixes
- TRIGGERS.md - AI trigger phrases for intelligent file loading
- CHANGELOG.md (this file) - Track pattern evolution

**Improvements:**
- Removed all emoji characters for professional appearance
- Enhanced cross-linking between patterns, anti-patterns, and attack trees
- Added real exploit mappings with dollar amounts and years
- Improved markdown formatting and link structure

**Statistics:**
- Total Files: 1,600+
- New Attack Trees: 5 files
- New Anti-Patterns: 4 files
- New Checklists: 4 files
- New Navigation: 3 files

---

### v3.0 - December 2024

**Focus:** Multi-chain expansion and real exploit forensics

**Major Additions:**

**Multi-Chain Scanners:**
- cairo-scanner/ - StarkNet/Cairo vulnerability patterns
- solana-scanner/ - Solana/Rust security patterns
- move-scanner/ - Aptos/Sui/Move security patterns
- cosmos-scanner/ - Cosmos/CosmWasm patterns
- ton-scanner/ - TON/Tact/Func security patterns

**Exploit Forensics:**
- exploit-forensics/ directory structure
- Real exploit analysis with timeline, root cause, PoC
- Post-mortem analysis of major hacks

**Pattern Additions:**
- ERC4626 vault standard patterns
- Uniswap V3 concentrated liquidity patterns
- Curve stableswap patterns
- Signature verification patterns (ECDSA, EIP-712)

**Improvements:**
- Added STATISTICS.md with exploit data
- Enhanced pattern cross-references
- Added vulnerability severity ratings
- Improved pattern organization

---

### v2.0 - November 2024

**Focus:** Comprehensive pattern library and methodology

**Major Additions:**

**Core Patterns:**
- lending-pool-patterns.md - Comprehensive lending security
- dex-patterns.md - AMM and DEX vulnerabilities
- bridge-patterns.md - Cross-chain bridge security
- defi-vault-patterns.md - Vault and yield aggregator patterns
- oracle-patterns.md - Price oracle security
- reentrancy-patterns.md - All reentrancy types
- access-control-patterns.md - Authorization patterns
- token-patterns.md - ERC20, ERC777, rebasing, fee-on-transfer

**Methodology:**
- ROUTE-MAP.md - Structured audit workflow
- llm-audit-workflow.md - AI-assisted auditing
- learning-path-attack-vectors.md - Educational progression

**Pattern Collections:**
- 1-64 common vulnerability patterns
- 51 attack patterns from 51% attack to zero-knowledge exploits
- Protocol-specific patterns (0x, Compound, Curve, Uniswap)

**Improvements:**
- Standardized pattern format (id, triggers, related_skills)
- Added code examples for each pattern
- Added "Exploited In" sections with real incidents
- Improved searchability with consistent tagging

---

### v1.0 - October 2024

**Focus:** Initial release - Foundation

**Initial Content:**
- MASTER_CHECKLIST.md - Comprehensive audit checklist
- comprehensive-checklist.md - Detailed vulnerability list
- Basic pattern files (20+ patterns)
- Static analysis tool configurations
- Command references for common tools

**Core Philosophy:**
- Pattern-based learning
- Real exploit analysis
- Practical code examples
- Tool-agnostic methodology

---

## Pattern Evolution Timeline

### 2024 Exploits That Changed Patterns

**Radiant Capital (January 2024, $4.5M)**
- **Vulnerability:** Cross-function reentrancy
- **Pattern Added:** Enhanced cross-function reentrancy in reentrancy-patterns.md
- **Anti-Pattern Added:** reentrancy-anti-patterns.md#2
- **Attack Tree:** lending-attack-tree.md#[D2]

**Implications:** Reinforced need for global reentrancy guards, not per-function

---

### 2023 Exploits

**Euler Finance (March 2023, $197M)**
- **Vulnerability:** Liquidation DoS via donation attack
- **Pattern Added:** dos-patterns.md#liquidation
- **Attack Tree:** lending-attack-tree.md#[B2]
- **Impact:** Major pattern addition for liquidation protection

**Yearn Finance (April 2023, $11M)**
- **Vulnerability:** First depositor attack on new vault
- **Pattern Enhanced:** defi-vault-patterns.md#first-depositor
- **Anti-Pattern:** Already covered, reinforced importance
- **Attack Tree:** vault-attack-tree.md#[A1]

**Sentiment (April 2023, $1M)**
- **Vulnerability:** Read-only reentrancy via Balancer
- **Pattern Added:** reentrancy-patterns.md#read-only
- **Anti-Pattern Added:** reentrancy-anti-patterns.md#3
- **Attack Tree:** lending-attack-tree.md#[D3]

---

### 2022 Exploits

**Ronin Bridge (March 2022, $625M)**
- **Vulnerability:** Validator private key compromise
- **Pattern Added:** bridge-patterns.md#validator-security
- **Anti-Pattern Added:** access-control-anti-patterns.md#5
- **Attack Tree:** bridge-attack-tree.md#[A5]
- **Impact:** Emphasized operational security, not just code

**Wormhole (February 2022, $326M)**
- **Vulnerability:** Missing signature verification
- **Pattern Added:** signature-patterns.md#verification
- **Attack Tree:** bridge-attack-tree.md#[A6]
- **Impact:** Reinforced signature validation patterns

**Nomad Bridge (August 2022, $190M)**
- **Vulnerability:** Unprotected initialize function
- **Pattern Enhanced:** access-control-patterns.md#initialization
- **Anti-Pattern Added:** access-control-anti-patterns.md#1
- **Attack Tree:** bridge-attack-tree.md#[E2]

**Harmony Horizon (June 2022, $100M)**
- **Vulnerability:** Validator key compromise (2-of-5 threshold too low)
- **Pattern Added:** bridge-patterns.md#validator-threshold
- **Attack Tree:** bridge-attack-tree.md#[A4]

**Rari Capital (April 2022, $80M)**
- **Vulnerability:** Malicious strategy in vault
- **Pattern Added:** strategy-patterns.md#validation
- **Attack Tree:** vault-attack-tree.md#[B2]

---

### 2021 Exploits

**Poly Network (August 2021, $610M)**
- **Vulnerability:** Missing access control on keeper role
- **Pattern Enhanced:** access-control-patterns.md#role-based
- **Anti-Pattern Added:** access-control-anti-patterns.md#2
- **Attack Tree:** bridge-attack-tree.md#[E5]
- **Impact:** Largest exploit at the time, major pattern overhaul

**Cream Finance (October 2021, $130M)**
- **Vulnerability:** Spot price oracle manipulation
- **Pattern Enhanced:** oracle-patterns.md#spot-price
- **Anti-Pattern Added:** oracle-anti-patterns.md#1
- **Attack Tree:** lending-attack-tree.md#[A2]

**THORChain (July 2021, $8M)**
- **Vulnerability:** tx.origin used for authentication
- **Pattern Added:** access-control-patterns.md#tx-origin
- **Anti-Pattern Added:** access-control-anti-patterns.md#3

**Grim Finance (December 2021, $30M)**
- **Vulnerability:** Classic reentrancy (state after external call)
- **Pattern Reinforced:** reentrancy-patterns.md#cei
- **Anti-Pattern:** reentrancy-anti-patterns.md#1
- **Impact:** Reminder that classic reentrancy still happens

**Beefy Finance (October 2021, $11M)**
- **Vulnerability:** Strategy loss not capped
- **Pattern Added:** strategy-patterns.md#loss-cap
- **Attack Tree:** vault-attack-tree.md#[B3]

---

### 2020 Exploits

**Harvest Finance (October 2020, $24M)**
- **Vulnerability:** Flash loan + spot price manipulation
- **Pattern Added:** oracle-patterns.md#flash-loan-resistance
- **Anti-Pattern Added:** oracle-anti-patterns.md#1
- **Attack Tree:** dex-attack-tree.md#[A1]
- **Impact:** Major awareness of flash loan oracle attacks

**Lendf.Me (April 2020, $25M)**
- **Vulnerability:** ERC777 reentrancy via tokensReceived callback
- **Pattern Added:** token-patterns.md#erc777-hooks
- **Anti-Pattern Added:** reentrancy-anti-patterns.md#4
- **Attack Tree:** lending-attack-tree.md#[D4]
- **Impact:** Widespread blocking of ERC777 tokens

**Warp Finance (December 2020, $7.7M)**
- **Vulnerability:** LP token pricing using balanceOf instead of reserves
- **Pattern Added:** defi-vault-patterns.md#lp-pricing
- **Anti-Pattern Added:** oracle-anti-patterns.md#5

**bZx (Multiple 2020, $8M)**
- **Vulnerability:** Oracle manipulation via on-chain price
- **Pattern Enhanced:** oracle-patterns.md
- **Impact:** Highlighted need for TWAP and multiple oracles

**Synthetix (June 2020, DoS)**
- **Vulnerability:** Oracle failure, no fallback
- **Pattern Added:** oracle-patterns.md#fallback
- **Anti-Pattern Added:** oracle-anti-patterns.md#4

---

### Historical (2016-2017)

**The DAO (June 2016, $60M)**
- **Vulnerability:** Classic reentrancy (state after external call)
- **Pattern Created:** reentrancy-patterns.md#cei (Checks-Effects-Interactions)
- **Anti-Pattern Created:** reentrancy-anti-patterns.md#1
- **Attack Tree:** lending-attack-tree.md#[D1]
- **Impact:** Birth of modern smart contract security

**Parity Wallet (November 2017, $150M frozen)**
- **Vulnerability:** Unprotected initialize function
- **Pattern Created:** access-control-patterns.md#initialization
- **Anti-Pattern Added:** access-control-anti-patterns.md#1
- **Impact:** Led to widespread use of initializer modifiers

---

## Deprecated Patterns

### Deprecated in v4.0
None yet. All patterns remain relevant.

### Watch List (May be deprecated in future)

**Single-chain patterns:**
- As multi-chain becomes standard, single-chain assumptions may need updates
- Cross-chain reentrancy patterns emerging

**Gas optimization patterns:**
- L2s and new chains change gas economics
- Some old gas tricks may be anti-patterns now

---

## Upcoming Patterns (Roadmap)

### Planned for v4.1 (Q1 2025)

**New Anti-Patterns:**
- Token Anti-Patterns (fee-on-transfer, rebasing, deflationary)
- DEX Anti-Patterns (AMM-specific mistakes)
- Bridge Anti-Patterns (cross-chain specific)
- Vault Anti-Patterns (share manipulation)
- Flash Loan Anti-Patterns (governance, yield farming)

**New Attack Trees:**
- Governance Attack Tree
- Stablecoin Attack Tree
- NFT Lending Attack Tree
- Liquid Staking Attack Tree

**Enhanced Coverage:**
- EIP-4337 (Account Abstraction) security patterns
- EIP-1967 (Proxy) upgrade patterns
- EIP-2535 (Diamond) multi-facet proxy patterns

### Planned for v5.0 (Q2 2025)

**Formal Verification:**
- Certora integration patterns
- Formal spec templates
- Invariant testing patterns

**Advanced MEV:**
- MEV attack trees
- Searcher protection patterns
- PBS (Proposer-Builder Separation) considerations

**Zero-Knowledge:**
- ZK circuit security patterns
- ZK proof verification patterns
- Privacy-preserving DeFi patterns

---

## How Patterns Are Created

### Discovery Process

1. **Real Exploit Occurs**
   - Exploit is analyzed
   - Root cause identified
   - Generalizable pattern extracted

2. **Pattern Documentation**
   - Added to relevant pattern file
   - Cross-referenced in XREF.md
   - Added to attack tree if applicable
   - Anti-pattern created if code example available

3. **Integration**
   - Triggers added to TRIGGERS.md
   - Checklist items updated
   - Related patterns cross-linked

4. **Validation**
   - Pattern tested against similar code
   - False positive rate checked
   - Community feedback incorporated

### Pattern Lifecycle

```
Real Exploit
    ↓
Analysis & Root Cause
    ↓
Pattern Extraction
    ↓
Documentation (Pattern File)
    ↓
Anti-Pattern (If applicable)
    ↓
Attack Tree Integration
    ↓
XREF Cross-Reference
    ↓
Trigger Phrases
    ↓
Checklist Items
    ↓
Continuous Refinement
```

---

## Pattern Quality Criteria

For a pattern to be included:

1. **Real-World Relevance** - Must be from actual exploits or audits
2. **Generalizable** - Applicable to multiple protocols
3. **Actionable** - Clear detection and mitigation
4. **Verifiable** - Can be tested with tools or manual review
5. **Documented** - Code examples, exploit references, fixes

---

## Contributing Pattern Updates

When suggesting pattern updates:

1. **Reference real exploits** - Link to incident reports
2. **Provide code examples** - Both vulnerable and fixed
3. **Cross-reference existing patterns** - Show relationships
4. **Update XREF.md** - Maintain cross-reference index
5. **Add triggers** - Help AI load relevant files
6. **Update this changelog** - Document the addition

---

## Statistics

### Pattern Growth

| Version | Total Patterns | Attack Trees | Anti-Patterns | Real Exploits Referenced |
|---------|---------------|--------------|---------------|-------------------------|
| v1.0 (Oct 2024) | 20+ | 0 | 0 | ~10 |
| v2.0 (Nov 2024) | 100+ | 0 | 0 | ~30 |
| v3.0 (Dec 2024) | 200+ | 0 | 0 | ~50 |
| v4.0 (Jan 2025) | 200+ | 5 | 4 | ~70 |

### Exploit Coverage

| Year | Exploits Analyzed | Total Loss | Patterns Created/Enhanced |
|------|------------------|------------|--------------------------|
| 2024 | 3+ | $212M+ | 5 |
| 2023 | 4+ | $209M+ | 8 |
| 2022 | 10+ | $1.3B+ | 20 |
| 2021 | 8+ | $800M+ | 15 |
| 2020 | 6+ | $65M+ | 12 |
| 2016-2017 | 2 | $210M | 5 (foundational) |

---

## See Also

- **XREF.md** - Cross-reference index
- **TRIGGERS.md** - AI trigger phrases
- **STATISTICS.md** - Detailed exploit statistics
- **ROUTE-MAP.md** - Audit methodology
- **attack-trees/INDEX.md** - Attack tree navigation
- **anti-patterns/INDEX.md** - Anti-pattern catalog

---

**Maintained By:** Web3 Audit Skills Contributors
**Last Updated:** January 2025
**Version:** 4.0
**Next Update:** v4.1 (Q1 2025)
