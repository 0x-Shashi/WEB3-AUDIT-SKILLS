---
id: AUDIT-CTX-WF-ARCH
title: Architecture Analysis Workflow
parent: audit-context-building
type: workflow
last_updated: 2025-01-31
---

# Architecture Analysis Workflow

Map the entire contract system architecture before reading individual functions. This workflow produces a complete structural understanding of how contracts relate to each other.

---

## Step 1: Contract Inventory

List all in-scope source files with line counts:

```bash
# Foundry project
find src/ -name "*.sol" -exec wc -l {} \; | sort -rn

# Hardhat project
find contracts/ -name "*.sol" -exec wc -l {} \; | sort -rn

# Get total SLOC (excluding comments/blanks)
npx cloc src/ --include-lang=Solidity
# or
scc src/ --include-ext sol
```

Produce an inventory table:

| File | Purpose | SLOC | Complexity |
|------|---------|------|------------|
| `src/Vault.sol` | User deposit/withdraw | 450 | High |
| `src/Strategy.sol` | Yield farming logic | 320 | High |
| `src/Token.sol` | Vault share token | 80 | Low |
| `src/Oracle.sol` | Price feed wrapper | 120 | Medium |

---

## Step 2: Inheritance Hierarchy

Map every `is` / `extends` / `inherits` relationship:

```bash
# Quick inheritance scan
grep -rn "contract .* is" src/ --include="*.sol"

# Or use Slither
slither . --print inheritance-graph
```

Document as a tree:

```
Vault
  ├── is Initializable (OZ)
  ├── is UUPSUpgradeable (OZ)
  ├── is OwnableUpgradeable (OZ)
  ├── is ReentrancyGuardUpgradeable (OZ)
  └── is ERC4626Upgradeable (OZ)
       ├── is ERC20Upgradeable
       └── is IERC4626

Strategy
  ├── is IStrategy (custom interface)
  └── is Ownable2Step (OZ)

Oracle
  └── is IOracle (custom interface)
```

### Red Flags in Inheritance

| Pattern | Risk |
|---------|------|
| Diamond inheritance (A → B, A → C, D → B + C) | Storage slot collision, function ambiguity |
| Missing Initializable in upgradeable contract | `initialize()` can be called multiple times |
| Ownable instead of Ownable2Step | Single-step ownership transfer risks loss |
| Custom access control (not OZ) | Likely to have bugs |
| Deep inheritance (>5 levels) | Hard to reason about behavior |

---

## Step 3: Interface Analysis

List all interfaces defined and implemented:

```bash
grep -rn "interface I" src/ --include="*.sol"
```

| Interface | Implemented By | Standard? | Complete? |
|-----------|---------------|-----------|----------|
| `IERC20` | Token.sol | ERC-20 | YES |
| `IERC4626` | Vault.sol | ERC-4626 | Check |
| `IStrategy` | Strategy.sol | Custom | N/A |
| `IOracle` | Oracle.sol | Custom | N/A |

For each standard interface, verify completeness (see [spec-compliance](../../spec-compliance/SKILL.md)).

---

## Step 4: Dependency Audit

Document all imported libraries with versions:

```bash
# Check installed versions
cat package.json | jq '.dependencies'
# Or for Foundry
cat foundry.toml
ls lib/
```

| Library | Version | Latest | Audit Status | Known Issues |
|---------|---------|--------|-------------|-------------|
| OpenZeppelin | 4.9.3 | 5.0.1 | Audited | None critical |
| Solmate | 6.2.0 | 6.7.0 | Audited | None |
| Chainlink | 0.8 | 1.1.1 | Audited | Stale price risk |

### Dependency Risks

- **Outdated version**: Check changelogs for security fixes between installed and latest
- **Unaudited dependency**: Custom libraries without audit history
- **Forked/modified OZ**: Protocol modified OpenZeppelin code (check diffs)

---

## Step 5: Storage Layout Analysis

Critical for upgradeable contracts:

```bash
# Slither storage layout
slither . --print variable-order

# Foundry storage layout  
forge inspect Vault storage-layout --pretty
```

Document storage slots:

| Slot | Variable | Type | Contract |
|------|----------|------|----------|
| 0 | _initialized | uint8 | Initializable |
| 1 | _initializing | bool | Initializable |
| 2 | _owner | address | OwnableUpgradeable |
| 3 | totalDeposited | uint256 | Vault |
| 4 | strategies | mapping | Vault |

### Storage Layout Red Flags

| Issue | Risk |
|-------|------|
| Gap variables missing between inherited contracts | Upgrade collision |
| New variables added before existing ones | Shifts all subsequent slots |
| Struct/mapping at beginning of contract storage | May overlap with parent slots |
| No `__gap` in base contracts | Can't add storage to base in future |

---

## Step 6: Event Analysis

List all events and where they're emitted:

```bash
grep -rn "event " src/ --include="*.sol" | grep -v "//"
grep -rn "emit " src/ --include="*.sol"
```

| Event | Contract | Emitted In | Indexed Params |
|-------|----------|-----------|----------------|
| `Deposit(address,uint256)` | Vault.sol | `deposit()` | address |
| `Withdraw(address,uint256)` | Vault.sol | `withdraw()` | address |
| `StrategyUpdated(address)` | Vault.sol | `setStrategy()` | address |

### Event Red Flags

- Missing events on privileged operations (admin parameter changes)
- Missing events on ownership transfer
- Events emitted but with wrong values (logging bugs)
- No events on state-changing external functions

---

## Step 7: External Call Map

Map every cross-contract call:

```bash
# Find external calls
grep -rn "\.call\|\.delegatecall\|\.staticcall\|\.transfer\|\.send" src/ --include="*.sol"
# Find interface calls
grep -rn "I[A-Z].*\." src/ --include="*.sol"
```

| Source Contract | Target | Function | Return Checked? | Trust Level |
|----------------|--------|----------|----------------|------------|
| Vault | Strategy | `harvest()` | YES | Medium (own contract) |
| Vault | IERC20 | `safeTransfer()` | YES (SafeERC20) | High |
| Strategy | IUniswap | `swap()` | YES | High (immutable) |
| Oracle | AggregatorV3 | `latestRoundData()` | PARTIAL | High |

### External Call Red Flags

| Pattern | Risk |
|---------|------|
| Unchecked return value | Silent failure |
| `delegatecall` to user input | Code injection |
| `call` with user-supplied data | Arbitrary execution |
| No reentrancy guard on function making external call | Reentrancy |
| Callback to untrusted contract (e.g., `onERC721Received`) | Reentrancy via callback |

---

## Step 8: Architecture Diagram Output

Produce a final architecture diagram:

```
┌──────────────────────────────────────────────────────────────┐
│                    PROTOCOL ARCHITECTURE                     │
├──────────────────────────────────────────────────────────────┤
│ User Entry Points                                           │
│   Router.sol (proxy: UUPS)                                   │
│     ├── deposit(asset, amount) → Vault.deposit()              │
│     ├── withdraw(asset, amount) → Vault.withdraw()            │
│     └── swap(tokenIn, tokenOut, amount) → Pool.swap()         │
├──────────────────────────────────────────────────────────────┤
│ Core Logic                                                   │
│   Vault.sol (ERC-4626, upgradeable)                          │
│     ├── Manages user deposits/withdrawals                    │
│     ├── Calls Strategy.harvest() for yield                   │
│     └── Calls Oracle.getPrice() for valuation                │
│   Pool.sol (immutable)                                       │
│     ├── AMM swap logic                                       │
│     └── Calls Oracle.getPrice() for TWAP                     │
├──────────────────────────────────────────────────────────────┤
│ External Dependencies                                       │
│   Chainlink (price feeds)                                    │
│   Uniswap V3 (liquidity / swaps)                             │
│   OpenZeppelin 4.9.3 (access, proxy, token)                  │
└──────────────────────────────────────────────────────────────┘
```

[Replace example with actual protocol architecture]
