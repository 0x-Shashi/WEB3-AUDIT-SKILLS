# Pre-Audit Context Building Workflow

## Phase 1: Documentation Review
- [ ] Read project README and documentation
- [ ] Understand protocol purpose and target users
- [ ] Identify the blockchain and ecosystem
- [ ] Note any previous audits

## Phase 2: Architecture Mapping
- [ ] List all contracts and their purposes
- [ ] Map inheritance hierarchies
- [ ] Identify external dependencies (OpenZeppelin, Chainlink, etc.)
- [ ] Draw contract interaction diagram
- [ ] Identify proxy/upgrade patterns

## Phase 3: Role and Permission Analysis
- [ ] List all privileged roles (owner, admin, operator)
- [ ] Map each role to its capabilities
- [ ] Identify centralization risks
- [ ] Check timelock/multisig requirements

## Phase 4: Token and Value Flow
- [ ] Map all token entry points (deposit, mint)
- [ ] Map all token exit points (withdraw, burn, transfer)
- [ ] Identify fee collection and distribution
- [ ] Trace ETH/native token flows

## Phase 5: Invariant Identification
- [ ] List protocol invariants (e.g., "total shares = total assets")
- [ ] Identify assumptions about external systems
- [ ] Note any documented constraints
- [ ] Verify invariants hold in edge cases
