---
id: AUDIT-CTX-CHECKLIST
title: Context Building Completeness Checklist
parent: audit-context-building
type: resource
last_updated: 2025-01-31
---

# Context Building Completeness Checklist

Use this checklist before and during audits to ensure systematic coverage. Do not begin line-by-line code review until all Phase 1 items are complete.

---

## Phase 1: Pre-Code-Review (Must complete before reading code)

### 1.1 Documentation & Scope

- [ ] Audit scope clearly defined (which contracts, which commit hash)
- [ ] README and project documentation reviewed
- [ ] Whitepaper or specification document reviewed (if exists)
- [ ] Protocol purpose understood and documented in one sentence
- [ ] Target chain(s) identified (Ethereum, L2, multichain)
- [ ] Known issues or out-of-scope items listed by team

### 1.2 Contract Inventory

- [ ] All in-scope `.sol` files listed with line counts
- [ ] Purpose of each contract documented (one line each)
- [ ] Total SLOC counted (use `cloc` or `scc`)
- [ ] Test files separated from source files
- [ ] Script/deployment files identified

```bash
# Quick inventory command
find src/ -name "*.sol" | xargs wc -l | sort -n
# Or with Foundry
forge inspect --sizes
```

### 1.3 Compilation & Environment

- [ ] Project compiles without errors (`forge build` / `npx hardhat compile`)
- [ ] Solidity version noted (check `pragma solidity`)
- [ ] Compiler optimizations settings noted (runs, via-ir, etc.)
- [ ] All dependency versions documented (OpenZeppelin, Solmate, etc.)
- [ ] Remappings file reviewed (`remappings.txt` or `foundry.toml`)

### 1.4 Previous Security Work

- [ ] Previous audit reports reviewed (if any)
- [ ] Known issues from previous audits — fixed or still present?
- [ ] Bug bounty program reviewed (if exists)
- [ ] Immunefi/code4rena/sherlock listings checked for disclosed issues

---

## Phase 2: Architecture Understanding

### 2.1 Contract Relationships

- [ ] Inheritance hierarchy mapped (every `is` relationship)
- [ ] Contract interaction diagram drawn (who calls whom)
- [ ] Proxy patterns identified (UUPS, Transparent, Diamond, Beacon)
- [ ] Storage layout documented for upgradeable contracts
- [ ] Library usage documented (internal vs external)

### 2.2 Key Design Patterns

- [ ] Entry points identified (user-facing external functions)
- [ ] Access control pattern identified (Ownable, AccessControl, custom)
- [ ] Reentrancy protection pattern identified (guards, CEI, locks)
- [ ] Pausability mechanism (if any) documented
- [ ] Emergency withdrawal / circuit breaker mechanisms noted

---

## Phase 3: Privilege & Trust Analysis

### 3.1 Role Inventory

- [ ] All privileged roles listed (owner, admin, operator, guardian, etc.)
- [ ] Each role's capabilities documented
- [ ] Role assignment/revocation mechanism documented
- [ ] Timelock requirements identified (or absence noted as risk)
- [ ] Multisig requirements identified (or absence noted as risk)

### 3.2 Centralization Assessment

| Role | Can Steal Funds? | Can Pause? | Can Upgrade? | Timelock? |
|------|-----------------|-----------|-------------|----------|
| Owner | | | | |
| Admin | | | | |
| Operator | | | | |

- [ ] Table completed for all roles
- [ ] Centralization risks documented

---

## Phase 4: Value Flow Analysis

### 4.1 Token Flows

- [ ] All token entry points mapped (deposit, stake, swap, mint)
- [ ] All token exit points mapped (withdraw, unstake, redeem, burn)
- [ ] Internal token movements documented (transfers between contracts)
- [ ] Fee collection mechanism documented (where fees go, how collected)
- [ ] Fee distribution mechanism documented (who receives, when)

### 4.2 ETH / Native Token Flows

- [ ] Which contracts receive ETH? (`receive()`, `fallback()`, `payable` functions)
- [ ] Which contracts send ETH? (`transfer`, `send`, `call{value: ...}`)
- [ ] Can ETH get stuck in any contract? (locked ether risk)

### 4.3 External Protocol Dependencies

- [ ] All oracle dependencies listed (Chainlink, TWAP, custom)
- [ ] All DEX integrations listed (Uniswap, Curve, etc.)
- [ ] All lending protocol integrations listed (Aave, Compound, etc.)
- [ ] All bridge integrations listed
- [ ] Trust assumptions about each external dependency documented

---

## Phase 5: Invariant Identification

- [ ] Protocol-level invariants identified and listed
- [ ] Math invariants documented (e.g., `totalShares * pricePerShare = totalAssets`)
- [ ] Accounting invariants documented (e.g., `sum(balances) = totalSupply`)
- [ ] Access invariants documented (e.g., `only depositor can withdraw their funds`)
- [ ] Ordering invariants documented (e.g., `can't withdraw before lockup expires`)
- [ ] External assumptions documented (e.g., `oracle always returns fresh price`)

---

## Phase 6: Understanding Verification

Before starting code review, verify you can answer all of these:

- [ ] Can explain the protocol purpose in one sentence
- [ ] Can describe a typical user flow end-to-end
- [ ] Can identify the top 3 risk areas
- [ ] Can name all external integrations and their trust level
- [ ] Know which functions handle the most value
- [ ] Know which functions have the most complex logic
- [ ] Understand the protocol's economic model (revenue, incentives)
- [ ] Can explain what happens if any single admin key is compromised

---

## Quick Reference: Common Misses

| What Gets Missed | Why It Matters |
|----|----|
| Initialization in upgradeable contracts | `initialize()` can be front-run, re-called if not guarded |
| Fee-on-transfer token support | Accounting mismatch if not handled |
| Rebasing token support | Balances change without transfers |
| Block timestamp dependency | Manipulable by validators |
| Gas griefing in loops | Unbounded arrays = DoS |
| Return value of low-level calls | Silently fails without check |
