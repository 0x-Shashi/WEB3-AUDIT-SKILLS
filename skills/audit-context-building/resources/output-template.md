---
id: AUDIT-CTX-OUTPUT
title: Audit Context Output Template
parent: audit-context-building
type: resource
last_updated: 2025-01-31
---

# Audit Context Output Template

Standardized format for documenting protocol understanding before code review begins. Fill out each section completely.

---

## 1. Protocol Overview

| Field | Value |
|-------|-------|
| **Name** | [Protocol Name] |
| **Version** | [v1.0 / commit hash] |
| **Chain(s)** | [Ethereum / Arbitrum / Base / Multichain] |
| **Category** | [DeFi Lending / DEX / Bridge / Yield / Stablecoin / NFT / DAO] |
| **SLOC** | [Total source lines of code, excluding tests] |
| **Contracts** | [Number of in-scope contracts] |
| **Solidity Version** | [e.g., 0.8.20] |
| **Framework** | [Foundry / Hardhat / Both] |
| **Previous Audits** | [None / Firm Name + Date] |
| **Bug Bounty** | [None / Immunefi $X / Custom $X] |

**One-Line Summary**: [Protocol Name] is a [category] protocol that enables [core value proposition] on [chain].

---

## 2. Contract Inventory

| Contract | Purpose | SLOC | Upgradeable | External Calls |
|----------|---------|------|-------------|----------------|
| `Core.sol` | [description] | [N] | YES/NO | [targets] |
| `Vault.sol` | [description] | [N] | YES/NO | [targets] |
| `Router.sol` | [description] | [N] | YES/NO | [targets] |

**Total SLOC**: [sum]

---

## 3. Architecture

### Contract Interaction Diagram

```
                    ┌─────────────┐
                    │   Router    │ ←── User entry point
                    └─────┬───────┘
                          │
              ┌─────────┼─────────┐
              │                   │
        ┌─────┴─────┐   ┌─────┴─────┐
        │   Vault    │   │   Pool     │
        └─────┬─────┘   └─────┬─────┘
              │                   │
        ┌─────┴─────┐   ┌─────┴─────┐
        │   Token    │   │   Oracle   │ ←── External
        └───────────┘   └───────────┘
```

[Replace with actual protocol architecture]

### Inheritance Hierarchy

```
Contract A
  ├── inherits: OpenZeppelin Ownable2Step
  ├── inherits: ReentrancyGuard
  └── uses: SafeERC20

Contract B (Upgradeable)
  ├── inherits: Initializable
  ├── inherits: UUPSUpgradeable
  ├── inherits: OwnableUpgradeable
  └── proxy: ERC1967Proxy
```

### Upgrade Pattern

| Contract | Pattern | Admin | Timelock |
|----------|---------|-------|----------|
| `Vault` | UUPS | Owner (EOA/Multisig) | None / 48h |
| `Token` | Non-upgradeable | N/A | N/A |

---

## 4. Roles and Permissions

| Role | Holder | Capabilities | Can Steal Funds? | Timelock? |
|------|--------|-------------|-----------------|----------|
| Owner | [EOA/Multisig/DAO] | Upgrade contracts, set fees, pause | [YES/NO + how] | [YES/NO] |
| Admin | [address] | Set parameters, whitelist tokens | [YES/NO + how] | [YES/NO] |
| Operator | [address] | Execute rebalances, harvest | [NO — limited to X] | [NO] |
| Guardian | [address] | Pause protocol | [NO] | [NO] |

### Centralization Risk Assessment

| Risk | Severity | Description |
|------|----------|-------------|
| Single owner can upgrade | HIGH | Owner can deploy malicious implementation |
| Admin can set fees to 100% | MEDIUM | Admin can extract all yield |
| No timelock on parameter changes | MEDIUM | Admin changes instant, no user exit window |

---

## 5. Token and Value Flows

### Token Entry Points

| Function | Contract | Token | From | Validation |
|----------|----------|-------|------|------------|
| `deposit(amount)` | Vault.sol | USDC | msg.sender | amount > 0, maxDeposit |
| `addLiquidity(a, b)` | Pool.sol | TokenA, TokenB | msg.sender | amounts > 0 |

### Token Exit Points

| Function | Contract | Token | To | Validation |
|----------|----------|-------|-----|------------|
| `withdraw(amount)` | Vault.sol | USDC | msg.sender | amount <= balance |
| `removeLiquidity(shares)` | Pool.sol | TokenA, TokenB | msg.sender | shares > 0 |

### Fee Flows

| Fee Type | Rate | Collected In | Collected By | Distributed To |
|----------|------|-------------|-------------|----------------|
| Swap fee | 0.3% | Pool.sol | Per-swap | LP holders (auto) |
| Management fee | 2% annual | Vault.sol | Per-harvest | Treasury |
| Performance fee | 20% | Vault.sol | On profit | Treasury |

### ETH Flows

| Contract | Receives ETH? | Sends ETH? | Can ETH Get Stuck? |
|----------|--------------|-----------|-------------------|
| Router | YES (payable) | YES (refund) | NO (refunds excess) |
| Vault | NO | NO | N/A |

---

## 6. External Dependencies

| Dependency | Type | Contract(s) | Trust Level | Failure Mode |
|-----------|------|------------|------------|-------------|
| Chainlink | Price oracle | Pool.sol | High (decentralized) | Stale price → wrong valuation |
| Uniswap V3 | DEX | Router.sol | High (immutable) | Low liquidity → slippage |
| OpenZeppelin 4.9 | Library | All | High (audited) | N/A (inherited code) |

### Oracle Details

| Oracle | Feed | Heartbeat | Deviation | Staleness Check? |
|--------|------|-----------|-----------|------------------|
| Chainlink ETH/USD | [address] | 3600s | 0.5% | [YES/NO] |
| Chainlink BTC/USD | [address] | 3600s | 0.5% | [YES/NO] |

---

## 7. Key Invariants

### Accounting Invariants
1. `sum(balanceOf[i]) == totalSupply` for all token contracts
2. `totalAssets() >= totalSupply * minShareValue` (vault solvency)
3. `reserve0 * reserve1 >= k` after every swap (constant product)

### Access Invariants
4. Only depositor (or approved) can withdraw their funds
5. Only owner can upgrade — and only through timelock
6. Paused state prevents all user-facing state-changing functions

### Ordering Invariants
7. Lockup period must elapse before withdrawal
8. Proposal must pass quorum before execution
9. Timelock delay must elapse before admin action takes effect

### External Assumptions
10. Oracle price is fresh (within heartbeat interval)
11. Underlying token does not have fee-on-transfer
12. Underlying token does not rebase

---

## 8. Risk Areas (Prioritized)

| # | Risk Area | Severity | Reason |
|---|-----------|----------|--------|
| 1 | [e.g., Oracle manipulation] | CRITICAL | [brief explanation] |
| 2 | [e.g., Access control on upgrade] | HIGH | [brief explanation] |
| 3 | [e.g., Reentrancy in withdraw] | HIGH | [brief explanation] |
| 4 | [e.g., First depositor attack] | MEDIUM | [brief explanation] |
| 5 | [e.g., Fee rounding] | LOW | [brief explanation] |

---

## 9. Test Coverage Assessment

| Area | Covered? | Gap |
|------|---------|-----|
| Core deposit/withdraw flow | YES/NO | [describe gap] |
| Edge cases (0 amount, max uint) | YES/NO | [describe gap] |
| Access control | YES/NO | [describe gap] |
| Oracle failure scenarios | YES/NO | [describe gap] |
| Reentrancy scenarios | YES/NO | [describe gap] |
| Upgrade safety | YES/NO | [describe gap] |
| Multi-user scenarios | YES/NO | [describe gap] |
| Invariant / fuzz tests | YES/NO | [describe gap] |
