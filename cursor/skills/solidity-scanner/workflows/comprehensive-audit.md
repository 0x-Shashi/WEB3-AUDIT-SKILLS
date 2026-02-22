# Comprehensive Audit Workflow

## Purpose
Full in-depth security audit for protocol launches, major upgrades, or client engagements.

## Phase 1: Context Building (Day 1)
- [ ] Read documentation and specification
- [ ] Understand protocol purpose and user flows
- [ ] Map contract architecture and inheritance
- [ ] Identify external dependencies and integrations
- [ ] List all privileged roles and their capabilities
- [ ] Document protocol invariants and assumptions

## Phase 2: Automated Analysis (Day 1-2)
- [ ] Run Slither with full detector suite
- [ ] Run Aderyn for additional patterns
- [ ] Run Mythril on core contracts
- [ ] Compile all tool findings
- [ ] Triage: mark true positives vs false positives

## Phase 3: Manual Review - Access Control (Day 2)
- [ ] Map all roles (owner, admin, operator, user)
- [ ] Verify each privileged function has correct modifier
- [ ] Check initialization and upgrade paths
- [ ] Review timelock and multisig requirements
- [ ] Assess centralization risks and admin powers

## Phase 4: Manual Review - Core Logic (Day 2-3)
- [ ] Trace all token/ETH flows end-to-end
- [ ] Verify mathematical formulas (interest, rewards, pricing)
- [ ] Check rounding direction in all division operations
- [ ] Validate state machine transitions
- [ ] Test boundary conditions (0, 1, max, overflow)

## Phase 5: Manual Review - External Interactions (Day 3)
- [ ] Audit oracle integration (staleness, manipulation)
- [ ] Review cross-contract calls (reentrancy, return values)
- [ ] Check token compatibility (fee-on-transfer, rebasing, etc.)
- [ ] Validate flash loan attack resistance
- [ ] Test MEV/front-running exposure

## Phase 6: Attack Chains (Day 3-4)
- [ ] Flash loan + oracle manipulation scenario
- [ ] Reentrancy + state desync scenario
- [ ] Governance takeover scenario (if applicable)
- [ ] Bridge exploit scenario (if cross-chain)
- [ ] Multi-step liquidation cascade

## Phase 7: Report Writing (Day 4)
- [ ] Write findings with severity, description, impact, PoC, fix
- [ ] Review and validate each finding
- [ ] Write executive summary
- [ ] Include recommendations beyond bugs
- [ ] Final quality review

## Deliverables
1. Audit report (PDF/MD)
2. Findings spreadsheet
3. Fix recommendations
4. Executive summary
