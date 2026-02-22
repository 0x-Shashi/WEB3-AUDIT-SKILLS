---
id: AUDIT-CTX-WF-PRE
title: Pre-Audit Context Building Workflow
parent: audit-context-building
type: workflow
last_updated: 2025-01-31
---

# Pre-Audit Context Building Workflow

Complete this workflow BEFORE starting line-by-line code review. Typically takes 15-20% of total audit time. Each phase builds on the previous one.

---

## Phase 1: Documentation and Scope Review

### 1.1 Scope Definition

Before reading any code, establish what you're auditing:

```bash
# Confirm the exact commit
git log --oneline -1
# Output: abc1234 feat: final changes before audit

# List all in-scope files
find src/ -name "*.sol" | sort

# Count lines
find src/ -name "*.sol" | xargs wc -l | tail -1
```

| Item | Value |
|------|-------|
| Repository | [URL] |
| Commit hash | [hash] |
| Branch | [branch] |
| In-scope folder | `src/` |
| Out-of-scope | `test/`, `script/`, `lib/` |
| Total SLOC | [number] |
| Known issues | [list from team] |

### 1.2 Protocol Documentation

Read in order:
1. **README.md** — High-level purpose
2. **docs/** folder — Detailed specification
3. **Whitepaper** (if exists) — Economic model, token mechanics
4. **NatSpec comments** in contracts — Developer intent
5. **Previous audit reports** — Past findings and fixes

Answer these questions:
- What problem does this protocol solve?
- Who are the users? (depositors, borrowers, traders, governance participants)
- What is the protocol's revenue model?
- What assumptions does the protocol make about external systems?

### 1.3 Ecosystem Context

Identify the ecosystem and chain-specific considerations:

| Chain | Considerations |
|-------|---------------|
| Ethereum L1 | High gas costs, MEV, 12s block times |
| Arbitrum | Sequencer dependency, different `block.number` |
| Optimism | Sequencer dependency, L1 data availability |
| Base | Same as Optimism (OP Stack) |
| Polygon | 2s blocks, different gas token, frequent reorgs |
| BSC | Centralized validators, MEV less prominent |
| zkSync | Different CREATE2, no `EXTCODECOPY` |
| Solana | Account model, different trust assumptions |

---

## Phase 2: Architecture Mapping

Use the full [Architecture Analysis Workflow](architecture-analysis.md) to produce:

- [ ] Contract inventory with SLOC and purpose
- [ ] Inheritance hierarchy tree
- [ ] Contract interaction diagram
- [ ] Proxy/upgrade patterns documented
- [ ] External dependency audit table
- [ ] Storage layout for upgradeable contracts

### Quick Architecture Assessment

| Complexity | Indicator | Approach |
|-----------|-----------|----------|
| Low | 1-3 contracts, <500 SLOC, no proxies | Can proceed to code review quickly |
| Medium | 4-10 contracts, 500-2000 SLOC, simple proxy | Full architecture phase needed |
| High | 10+ contracts, 2000+ SLOC, diamond pattern | Dedicated day for architecture mapping |

---

## Phase 3: Role and Permission Analysis

### 3.1 Role Discovery

```bash
# Find all access control patterns
grep -rn "onlyOwner\|onlyRole\|onlyAdmin\|msg.sender ==\|require.*msg.sender" src/ --include="*.sol"

# Find role definitions
grep -rn "bytes32.*ROLE\|keccak256.*ROLE" src/ --include="*.sol"

# Find ownership
grep -rn "Ownable\|owner()\|_owner" src/ --include="*.sol"
```

### 3.2 Permission Matrix

For each privileged role, exhaustively list what it can do:

| Role | Function | Can It Steal Funds? | Can It DoS? | Timelock? |
|------|----------|--------------------|-----------|-----------|
| Owner | `setFeeRecipient(addr)` | YES — redirect all fees | NO | NO ⚠️ |
| Owner | `upgradeTo(impl)` | YES — arbitrary code | YES | NO ⚠️ |
| Owner | `pause()` | NO | YES — locks funds | NO |
| Keeper | `harvest()` | NO — constrained | NO | N/A |
| Guardian | `pause()` | NO | YES — locks funds | NO |

### 3.3 Centralization Risk Score

| Score | Meaning | Criteria |
|-------|---------|----------|
| 1 | Fully decentralized | No admin keys, no governance, immutable |
| 2 | Minimal trust | Timelock + multisig, limited admin power |
| 3 | Moderate trust | Multisig without timelock, or timelock with EOA |
| 4 | High trust | EOA owner with significant power, no timelock |
| 5 | Full trust | Single EOA can steal all funds |

---

## Phase 4: Token and Value Flow Mapping

### 4.1 Token Entry Points

Trace how tokens enter the protocol:

```
User → deposit(amount) → Vault.sol
  └── token.safeTransferFrom(user, vault, amount)
  └── _mint(user, shares)
  └── emit Deposit(user, amount, shares)
```

### 4.2 Token Exit Points

Trace how tokens leave the protocol:

```
User → withdraw(shares) → Vault.sol
  └── _burn(user, shares)
  └── amount = convertToAssets(shares)
  └── token.safeTransfer(user, amount)
  └── emit Withdraw(user, shares, amount)
```

### 4.3 Internal Flows

Trace token movement between protocol contracts:

```
Vault → Strategy.deposit(amount) → ExternalProtocol.deposit()
  └── Token moves: Vault → Strategy → ExternalProtocol
```

### 4.4 Fee Analysis

| Fee | Rate | Where Collected | Where Sent | Can Be Changed? |
|-----|------|----------------|-----------|----------------|
| Swap fee | 0.3% | Pool.swap() | LP holders | YES (owner) |
| Performance | 20% | Vault.harvest() | Treasury | YES (owner) |
| Withdrawal | 0.1% | Vault.withdraw() | Treasury | YES (owner) |

---

## Phase 5: Invariant Identification

### 5.1 Protocol-Level Invariants

Invariants are conditions that must ALWAYS hold true. If broken, the protocol is compromised.

| Category | Example Invariant | How to Test |
|----------|-------------------|------------|
| Accounting | `sum(userBalances) == totalSupply` | Fuzz test: do random operations, check invariant |
| Solvency | `vault.totalAssets() >= vault.totalSupply()` | After every deposit/withdraw/harvest |
| AMM | `reserveA * reserveB >= k` (after swap) | After every swap |
| Lending | `totalBorrowed <= totalDeposited * collateralFactor` | After every borrow |
| Access | `only owner can call adminFunction()` | Call from non-owner, should revert |
| Ordering | `cannot withdraw before lockupEnd` | Try to withdraw early |

### 5.2 Assumption Documentation

Document assumptions about things outside the protocol's control:

| Assumption | If Wrong, What Happens |
|-----------|------------------------|
| Chainlink oracle is live and accurate | Incorrect liquidations, bad swaps |
| Underlying token is standard ERC-20 | Accounting errors (fee-on-transfer, rebasing) |
| Users act rationally | May not matter — attackers don't |
| Block timestamp is roughly accurate | Validator manipulation of time-dependent logic |
| External protocol (Aave/Compound) is solvent | Strategy losses |

### 5.3 Writing Invariant Tests

```solidity
// Foundry invariant test example
function invariant_solvencyMaintained() public {
    uint256 totalAssets = vault.totalAssets();
    uint256 totalShares = vault.totalSupply();
    // Vault should never be underwater
    if (totalShares > 0) {
        assertGe(totalAssets, totalShares, "Vault is insolvent");
    }
}

function invariant_supplyConsistency() public {
    uint256 sumBalances = 0;
    for (uint i = 0; i < actors.length; i++) {
        sumBalances += token.balanceOf(actors[i]);
    }
    assertEq(sumBalances, token.totalSupply(), "Supply mismatch");
}
```

---

## Phase Summary Checklist

- [ ] Phase 1: Scope defined, docs read, ecosystem noted
- [ ] Phase 2: Architecture mapped (contracts, inheritance, dependencies)
- [ ] Phase 3: All roles documented with centralization score
- [ ] Phase 4: All token flows traced (in, out, internal, fees)
- [ ] Phase 5: Invariants identified and assumption documented
- [ ] Can explain protocol purpose in one sentence
- [ ] Top 3 risk areas identified
- [ ] Ready for deep code review → proceed to [Deep Code Review](deep-code-review.md)
