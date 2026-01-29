# Architecture Analysis Workflow

Build context for complex, multi-contract systems by understanding architectural patterns and component interactions.

---

## Purpose

This workflow is designed for **large or complex codebases** where understanding the architecture is essential before diving into function-level analysis.

**When to Use:**
- Multi-contract systems (5+ contracts)
- Protocol with multiple modules/subsystems
- Complex inheritance hierarchies
- Diamond/proxy/modular patterns
- Cross-chain or multi-deployment systems

**Outcome:** Complete architectural understanding with component interaction maps

---

## Phase 1: System Decomposition

### Step 1.1: Identify Architectural Pattern

```markdown
## Architecture Pattern Identification

### Primary Pattern
- [ ] Monolithic (single contract)
- [ ] Modular (separate concerns)
- [ ] Diamond (EIP-2535)
- [ ] Proxy (Transparent/UUPS)
- [ ] Beacon Proxy
- [ ] Factory Pattern
- [ ] Hub-and-Spoke
- [ ] Plugin Architecture

### Secondary Patterns
- [ ] Access Control (RBAC/Ownable)
- [ ] Pausable
- [ ] Upgradeable
- [ ] Multicall
- [ ] Flash Loans
- [ ] Callback Pattern

### Pattern-Specific Concerns
Based on identified patterns:
1. [Pattern-specific risk]
2. [Another pattern-specific risk]
```

### Step 1.2: Component Inventory

```markdown
## System Components

### Core Components
| Component | Purpose | Trust Level | Upgradeable |
|-----------|---------|-------------|-------------|
| Router | Entry point | N/A | No |
| Pool | Liquidity | Critical | Yes |
| Oracle | Price data | High | No |

### Supporting Components
| Component | Purpose | Dependencies |
|-----------|---------|--------------|
| Math | Calculations | None |
| Events | Logging | All |
| Errors | Reverts | All |

### External Components
| Component | Provider | Integration Type |
|-----------|----------|------------------|
| PriceOracle | Chainlink | Read-only |
| SwapRouter | Uniswap | Bidirectional |
```

### Step 1.3: Layer Identification

```markdown
## System Layers

### Layer Diagram
```
┌─────────────────────────────────────────────┐
│ Layer 4: User Interface                     │
│   Frontend, SDK, Scripts                    │
├─────────────────────────────────────────────┤
│ Layer 3: Entry Points                       │
│   Router.sol, Periphery.sol                 │
├─────────────────────────────────────────────┤
│ Layer 2: Core Logic                         │
│   Pool.sol, Position.sol, Strategy.sol      │
├─────────────────────────────────────────────┤
│ Layer 1: Data & Storage                     │
│   State.sol, Storage.sol, Mappings          │
├─────────────────────────────────────────────┤
│ Layer 0: External Integrations              │
│   Oracles, Other Protocols, Bridges         │
└─────────────────────────────────────────────┘
```

### Layer Interactions
| From Layer | To Layer | Interaction Type |
|------------|----------|------------------|
| 3 → 2 | Entry → Core | Function calls |
| 2 → 1 | Core → Data | State access |
| 2 → 0 | Core → External | External calls |
```

---

## Phase 2: Component Deep Dive

### Step 2.1: Core Component Analysis

For each core component:

```markdown
## Component: [ComponentName]

### Responsibility
[What is this component responsible for?]

### Interface
**Exports (Public/External):**
- function1(): Purpose
- function2(): Purpose

**Imports (Dependencies):**
- OtherComponent.method(): Why needed

### State Ownership
| State Variable | Owned By | Shared With |
|----------------|----------|-------------|
| balances | This | None |
| config | This | Reader contracts |

### Invariants
1. [Component-level invariant]
2. [Another invariant]

### Trust Assumptions
- [What this component trusts]
- [What should not be trusted]
```

### Step 2.2: Interface Analysis

```markdown
## Interface Definitions

### IPool
```solidity
interface IPool {
    function deposit(uint256 amount) external returns (uint256 shares);
    function withdraw(uint256 shares) external returns (uint256 amount);
    function getBalance(address user) external view returns (uint256);
}
```

**Implementations:**
- Pool.sol (main)
- MockPool.sol (testing)

**Consumers:**
- Router.sol
- Periphery.sol

### IOracle
[Same format for each interface]
```

### Step 2.3: Dependency Graph

```markdown
## Dependency Graph

### Contract Dependencies
```
Router.sol
├── Pool.sol
│   ├── Oracle.sol
│   │   └── Chainlink
│   ├── Token.sol
│   └── Math.sol
└── Periphery.sol
    ├── Pool.sol (shared)
    └── WETH.sol
```

### Circular Dependency Check
- [ ] No circular dependencies found
- [ ] Circular: [A → B → C → A]

### Dependency Risks
| Dependency | If Fails | Impact |
|------------|----------|--------|
| Oracle | Wrong prices | Critical |
| Pool | No liquidity | High |
```

---

## Phase 3: Data Flow Analysis

### Step 3.1: State Machine Identification

```markdown
## State Machines

### System States
```
┌─────────┐    initialize()    ┌────────┐
│ CREATED ├───────────────────►│ ACTIVE │
└─────────┘                    └───┬────┘
                                   │
                    pause()        │ unpause()
                         ▼         │
                    ┌────────┐◄────┘
                    │ PAUSED │
                    └───┬────┘
                        │ shutdown()
                        ▼
                    ┌──────────┐
                    │ SHUTDOWN │
                    └──────────┘
```

### State Transitions
| From | To | Trigger | Who Can |
|------|-----|---------|---------|
| CREATED | ACTIVE | initialize() | Deployer |
| ACTIVE | PAUSED | pause() | Owner |
| PAUSED | ACTIVE | unpause() | Owner |
| PAUSED | SHUTDOWN | shutdown() | Owner |

### State Invariants
| State | Must Be True |
|-------|--------------|
| CREATED | No user funds |
| ACTIVE | Operations allowed |
| PAUSED | No deposits/withdraws |
| SHUTDOWN | Only emergency withdrawals |
```

### Step 3.2: Value Flow Tracing

```markdown
## Value Flows

### Primary Value Flow: User Deposit
```
User Wallet
    │
    │ approve(Router, amount)
    ▼
ERC20 Token ─────────────────────────────────┐
    │                                         │
    │ transferFrom(User, Pool, amount)       │
    ▼                                         │
Pool Contract                                 │
    │                                         │
    │ mint(User, shares)                     │
    ▼                                         │
Share Token                                   │
    │                                         │
    └────── Update: balances[User] ◄─────────┘
```

### Fee Flow
```
Transaction
    │
    │ calculate fee
    ▼
Fee Amount ──► Protocol Treasury
    │
    └──► LP Rewards (partial)
```

### External Value Flows
```
Protocol ──[collateral]──► External Lending
           ◄──[yield]────
```
```

### Step 3.3: Information Flow

```markdown
## Information Flows

### Oracle Data Flow
```
Chainlink ──[price]──► OracleWrapper ──[price]──► Pool
                           │
                           └── validate, transform
```

### Configuration Data Flow
```
Owner ──[setConfig]──► Config Contract ──[read]──► Core Contracts
```

### Event Data Flow
```
Core Contracts ──[emit]──► Events ──[index]──► Off-chain
```
```

---

## Phase 4: Security Architecture

### Step 4.1: Trust Boundary Mapping

```markdown
## Trust Boundaries

### Boundary Diagram
```
┌─────────────────────────────────────────────────────┐
│ EXTERNAL (Untrusted)                                │
│   Users, External Contracts, MEV Bots               │
├─────────────────────────────────────────────────────┤
│ BOUNDARY: Input Validation, Access Control          │
├─────────────────────────────────────────────────────┤
│ INTERNAL (Trusted after validation)                 │
│   Core Logic, State Changes, Calculations           │
├─────────────────────────────────────────────────────┤
│ BOUNDARY: Output Validation, Reentrancy Guards      │
├─────────────────────────────────────────────────────┤
│ EXTERNAL INTEGRATIONS (Semi-trusted)                │
│   Oracles, DEXes, Lending Protocols                 │
└─────────────────────────────────────────────────────┘
```

### Boundary Crossings
| Crossing Point | Protection | Verified |
|----------------|------------|----------|
| User → Router | Input validation | ⏳ |
| Pool → Oracle | Return validation | ⏳ |
| Core → External | Error handling | ⏳ |
```

### Step 4.2: Access Control Architecture

```markdown
## Access Control

### Role Hierarchy
```
DEFAULT_ADMIN_ROLE (Multisig)
├── OPERATOR_ROLE
│   └── harvest(), compound(), rebalance()
├── PAUSER_ROLE
│   └── pause(), unpause()
├── UPGRADER_ROLE
│   └── upgradeTo()
└── FEE_SETTER_ROLE
    └── setFee(), setTreasury()
```

### Role Assignment
| Role | Current Holder | Assignment Method |
|------|----------------|-------------------|
| ADMIN | Multisig | Constructor |
| OPERATOR | Bot wallet | grantRole() |

### Privilege Escalation Paths
- ⚠️ ADMIN can grant any role
- ⚠️ [Other escalation concern]

### Time Locks
| Action | Delay | Bypass Possible |
|--------|-------|-----------------|
| Upgrade | 48h | Emergency only |
| Fee change | 24h | No |
```

### Step 4.3: Upgrade Architecture

```markdown
## Upgrade Architecture

### Upgrade Pattern
- [ ] Immutable
- [x] Transparent Proxy
- [ ] UUPS
- [ ] Diamond

### Upgrade Flow
```
Owner ──[propose]──► Timelock ──[execute after delay]──► Proxy
                        │                                   │
                        │                                   │
                    48h delay                          upgradeTo()
```

### Upgrade Risks
| Risk | Mitigation | Status |
|------|------------|--------|
| Storage collision | Gap variables | ✅ |
| Function collision | Selector check | ✅ |
| Malicious upgrade | Timelock | ✅ |
| Initialization | initializer modifier | ⏳ |

### Storage Layout
```
Slot 0: owner
Slot 1: paused
Slot 2: balances mapping base
...
Slot 50-99: __gap (reserved)
```
```

---

## Phase 5: Synthesis

### Step 5.1: Architecture Summary

```markdown
## Architecture Summary

### System Overview
[3-5 sentences describing the complete system]

### Key Components
1. **Router:** Entry point for all user operations
2. **Pool:** Core liquidity and accounting
3. **Oracle:** Price data integration
4. [Other key components]

### Critical Paths
1. Deposit: Router → Pool → Token Transfer
2. Withdraw: Router → Pool → Share Burn → Token Transfer
3. Liquidation: Keeper → Pool → Oracle → Position Close

### Architecture Strengths
- [Positive architectural decision]
- [Another strength]

### Architecture Concerns
- ⚠️ [Architectural weakness]
- ⚠️ [Another concern]
```

### Step 5.2: Attack Surface Summary

```markdown
## Attack Surface Summary

### Entry Points by Risk
**Critical Risk:**
- deposit() - receives value
- withdraw() - releases value
- callback() - external caller controlled

**High Risk:**
- setOracle() - can change price source
- upgrade() - full control

**Medium Risk:**
- setFee() - economic impact
- pause() - operational impact

### Cross-Component Risks
| Component A | Component B | Risk |
|-------------|-------------|------|
| Pool | Oracle | Price manipulation |
| Router | Pool | Reentrancy |
```

### Step 5.3: Analysis Prioritization

```markdown
## Analysis Priorities

Based on architectural analysis:

### Priority 1 (Critical)
Functions/Components to analyze first:
1. [Most critical item] - Reason
2. [Next critical] - Reason

### Priority 2 (High)
1. [High priority item] - Reason
2. [Another] - Reason

### Priority 3 (Medium)
1. [Medium priority item]
2. [Another]

### Can Defer
- View-only functions
- Event emissions
- [Other low-risk items]
```

---

## Transition to Function Analysis

With architecture context complete:

### You Now Understand:
✅ System patterns and structure  
✅ Component responsibilities  
✅ Data and value flows  
✅ Trust boundaries  
✅ Access control model  
✅ Upgrade mechanics  

### Next Steps:
1. **deep-code-review** workflow for critical functions
2. **cyfrin-findings** to research pattern-specific vulnerabilities
3. **Chain-specific scanners** for blockchain-specific issues

### Architecture Informs:
- Which functions need deepest analysis
- What invariants to verify
- Where trust boundaries are crossed
- What external integrations need scrutiny
