# Threat Model: [Protocol Name]

<!--
  WHAT: Document actors, trust assumptions, and attack surface BEFORE hunting bugs.
  WHY: A threat model focuses your audit on the highest-risk areas.
  WHEN: Fill this out during Phase 1 (Protocol Understanding).
-->

## Protocol Overview

### One-Sentence Description
<!--
  EXAMPLE: "A lending protocol where users deposit collateral to borrow other assets."
-->
[One sentence describing what this protocol does]

### Protocol Type
- [ ] Lending
- [ ] DEX/AMM
- [ ] Bridge
- [ ] Vault/Yield Aggregator
- [ ] Stablecoin
- [ ] Governance/DAO
- [ ] Perpetuals/Derivatives
- [ ] NFT Lending
- [ ] Liquid Staking
- [ ] Options
- [ ] Insurance
- [ ] Other: ________________

### Key Value Flows

```
┌─────────────┐     Deposit      ┌─────────────┐
│   User      │ ───────────────► │  Protocol   │
└─────────────┘                  └──────┬──────┘
       ▲                                │
       │         Rewards/Yield          │
       └────────────────────────────────┘
```

<!--
  Draw or describe how value flows through the protocol.
  Focus on: deposits, withdrawals, rewards, fees, liquidations.
-->

---

## Actors

### Trusted Actors
<!--
  Who can cause damage if they're malicious or compromised?
-->

| Actor | Trust Level | Capabilities | Risk if Compromised |
|-------|-------------|--------------|---------------------|
| Owner/Admin | High | Pause, upgrade, set params | Full fund loss |
| Oracle | High | Provide prices | Price manipulation |
| Keeper/Relayer | Medium | Execute liquidations | DoS, front-running |
| Multisig Signers | High | Execute proposals | Governance attack |

### Untrusted Actors
<!--
  Who can interact with the protocol without permission?
-->

| Actor | Capabilities | Potential Attacks |
|-------|--------------|-------------------|
| Any User | Deposit, borrow, repay | Flash loan, reentrancy |
| MEV Bot | Sandwich, front-run | Sandwich swaps, liquidation MEV |
| Attacker | Any public function | All attack tree branches |

---

## Trust Assumptions

<!--
  What MUST be true for the protocol to be secure?
  If any assumption fails, security breaks.
-->

### Critical Assumptions

| Assumption | What Breaks If False | Validation |
|------------|---------------------|------------|
| Oracle provides accurate prices | Infinite minting, bad debt | Check oracle source, TWAP |
| Admin is not malicious | Rug pull | Check multisig, timelock |
| Chainlink doesn't fail | Stale prices | Check staleness threshold |
| ETH price doesn't crash 90% in 1 block | Cascading liquidations | Check liquidation parameters |

### External Dependencies

| Dependency | Type | Failure Mode |
|------------|------|--------------|
| Chainlink | Oracle | Stale/wrong prices |
| Uniswap | AMM | Flash loan manipulation |
| USDC | Token | Blacklist, depeg |
| LayerZero | Bridge | Message spoofing |

---

## Attack Surface

### Entry Points (External/Public Functions)

<!--
  List all functions attackers can call.
  Focus on: deposit, withdraw, borrow, repay, liquidate, swap, claim.
-->

| Function | Contract | Risk Level | Attack Vectors |
|----------|----------|------------|----------------|
| `deposit()` | Vault.sol | High | Reentrancy, first depositor |
| `withdraw()` | Vault.sol | Critical | Reentrancy, rounding |
| `borrow()` | Lending.sol | Critical | Oracle manipulation |
| `liquidate()` | Lending.sol | Critical | Self-liquidation, DoS |
| `updatePrice()` | Oracle.sol | Critical | Access control |

### High-Value Targets

<!--
  Where is the money? What functions move the most value?
-->

| Target | TVL/Value | Attack Impact | Priority |
|--------|-----------|---------------|----------|
| Vault.sol | $XXX | Fund theft | P0 |
| Oracle.sol | Price source | Protocol-wide | P0 |
| Admin functions | Upgrade power | Full control | P1 |

### Token Interactions

<!--
  What tokens does the protocol handle? Any weird ones?
-->

| Token | Type | Special Behavior | Risk |
|-------|------|------------------|------|
| USDT | ERC20 | No return value | SafeTransfer needed |
| stETH | Rebasing | Balance changes | Accounting errors |
| USDC | Centralized | Blacklist | User funds frozen |
| Fee-on-transfer | Deflationary | Less received | Balance mismatch |

---

## Known Vulnerability Classes

<!--
  Based on protocol type, which vulnerabilities are most likely?
  Load from: anti-patterns/[type]-anti-patterns.md
-->

### High Priority (Check First)

| Vulnerability | Relevant Anti-Pattern | Status |
|---------------|----------------------|--------|
| Oracle manipulation | oracle-anti-patterns.md #1-#7 | [ ] Checked |
| Reentrancy | reentrancy-anti-patterns.md #1-#7 | [ ] Checked |
| Access control | access-control-anti-patterns.md #1-#7 | [ ] Checked |
| First depositor | vault-specific-anti-patterns.md #1 | [ ] Checked |

### Protocol-Specific

<!--
  Add vulnerabilities specific to this protocol type.
  Reference: attack-trees/[type]-attack-tree.md
-->

| Vulnerability | Attack Tree Branch | Status |
|---------------|-------------------|--------|
| | [ ] | [ ] Checked |

---

## Security Boundaries

### What the Protocol Protects

- User deposits (principal)
- Earned yield/rewards
- Protocol reserves
- Governance integrity

### What the Protocol Does NOT Protect

- MEV extraction (considered acceptable)
- Gas costs
- User mistakes (approving wrong amounts)
- External oracle failures

---

## Questions for Developers

<!--
  Questions to clarify with the protocol team.
-->

1. What oracle do you use? Is there a fallback?
2. What's the max admin privilege? Is there a timelock?
3. Are any tokens blacklisted or specially handled?
4. What's the expected TVL?
5. Have there been previous audits?

---

## Risk Assessment

### Overall Risk Level: [High/Medium/Low]

| Category | Risk | Justification |
|----------|------|---------------|
| Oracle | [H/M/L] | [Why] |
| Access Control | [H/M/L] | [Why] |
| Token Handling | [H/M/L] | [Why] |
| Flash Loan | [H/M/L] | [Why] |
| Upgrade Risk | [H/M/L] | [Why] |

---

## Related Resources

- **Attack Tree:** `attack-trees/[protocol-type]-attack-tree.md`
- **Anti-Patterns:** `anti-patterns/*.md`
- **Protocol Playbook:** `protocol-playbooks/[protocol].md`

---

*Fill this out during Phase 1 of your audit.*
*A good threat model = focused, efficient audit.*
