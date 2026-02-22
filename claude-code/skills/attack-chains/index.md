# Attack Chains Index

> Multi-step attack sequences combining multiple vulnerabilities for maximum impact.

---

## Available Attack Chains

| Chain | Complexity | Typical Severity | Protocols At Risk |
|-------|-----------|-----------------|-------------------|
| [Flash Loan + Oracle](flash-loan-oracle-chain.md) | Medium | CRITICAL | DEXs, Lending, Vaults |
| [Reentrancy + State Desync](reentrancy-desync-chain.md) | Medium | CRITICAL | Vaults, Lending, Staking |
| [Governance Takeover](governance-takeover-chain.md) | High | CRITICAL | DAOs, Governance tokens |
| [Bridge Exploit](bridge-exploit-chain.md) | High | CRITICAL | Bridges, Cross-chain |
| [Sandwich + MEV](sandwich-mev-chain.md) | Low-Medium | HIGH | DEXs, AMMs |
| [Cross-Contract](cross-contract-chain.md) | Medium-High | HIGH-CRITICAL | Multi-contract systems |

---

## How to Use Attack Chains

1. **Identify protocol type** from scope
2. **Load relevant chains** for that protocol
3. **Walk each step** checking if preconditions exist
4. **If Step N is possible**, check Step N+1
5. **Document the full chain** if all steps are viable

## When to Load

| Protocol Type | Load These Chains |
|--------------|-------------------|
| DEX/AMM | Flash Loan + Oracle, Sandwich + MEV |
| Lending | Flash Loan + Oracle, Reentrancy + Desync |
| Bridge | Bridge Exploit, Cross-Contract |
| DAO/Gov | Governance Takeover, Flash Loan + Oracle |
| Vault/Yield | Reentrancy + Desync, Flash Loan + Oracle |
| Multi-contract | Cross-Contract, any relevant chain |

---

## Chain Anatomy

Every attack chain follows this structure:

```
SETUP → TRIGGER → EXPLOIT → EXTRACT → COVER
```

- **SETUP**: Acquire resources, position tokens, prepare contracts
- **TRIGGER**: Initiate the vulnerable code path
- **EXPLOIT**: Execute the vulnerability in the manipulation window
- **EXTRACT**: Withdraw profits, repay loans, exit positions
- **COVER**: Remove traces, close positions, exit protocol
