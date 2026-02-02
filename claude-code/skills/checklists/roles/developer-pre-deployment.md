---
id: DEVELOPER-PRE-DEPLOYMENT
title: Developer Pre-Deployment Checklist
category: checklist
role: developer
phase: pre-deployment
triggers:
  - about to deploy
  - deployment checklist
  - pre-deployment checks
  - ready to deploy
  - deployment sanity check
related_skills:
  - methodology/secure-pattern-reference.md
  - checklists/comprehensive-checklist.md
---

# Developer Pre-Deployment Checklist

Copy this into your deployment PR or issue. Check boxes as you verify each item.

---

## Initialization & Setup

- [ ] Constructor has `_disableInitializers()` if upgradeable
- [ ] `initialize()` function has `initializer` modifier
- [ ] Initial owner/admin set to multisig (not EOA)
- [ ] All roles properly assigned in initializer
- [ ] Immutable variables set correctly (can't change post-deploy)
- [ ] Contract verification parameters prepared (constructor args)

---

## Access Control

- [ ] Owner set to multisig/governance address
- [ ] Deployer EOA does NOT retain admin rights
- [ ] Timelock configured if required
- [ ] Emergency pause guardian set (if applicable)
- [ ] Role assignments match deployment plan
- [ ] No hardcoded addresses that should be configurable

---

## External Dependencies

- [ ] Oracle addresses verified on correct network
- [ ] Router addresses match official deployments
- [ ] Token addresses verified (not test tokens)
- [ ] External protocol addresses double-checked
- [ ] Chainlink feeds have correct decimals/heartbeat
- [ ] No placeholder addresses (0x123...456)

---

## Configuration Validation

- [ ] Fee parameters within expected ranges
- [ ] Slippage bounds set appropriately
- [ ] Timelock delays configured (if applicable)
- [ ] Max/min limits set and tested
- [ ] Decimal handling verified (18 vs 6 vs 8)
- [ ] Chain ID checks included (for signatures)

---

## Storage & Upgrades

- [ ] Storage gaps present (`uint256[50] __gap`)
- [ ] No storage layout changes from audited version
- [ ] Upgrade authorization properly restricted
- [ ] Implementation contract has disabled initializers
- [ ] Proxy admin set correctly
- [ ] Upgrade timelock configured

---

## Critical Safety Checks

- [ ] ReentrancyGuard on all value-transfer functions
- [ ] CEI pattern followed (Checks-Effects-Interactions)
- [ ] No unchecked external calls without validation
- [ ] SafeERC20 used for token transfers
- [ ] Zero address checks on critical parameters
- [ ] No floating pragmas (`^0.8.0` → `0.8.19`)

---

## Testing Evidence

- [ ] All tests passing on forked mainnet
- [ ] Integration tests with real protocol addresses
- [ ] Tested with realistic token amounts
- [ ] Tested with fee-on-transfer tokens (if accepting any ERC20)
- [ ] Gas profiling acceptable
- [ ] Edge cases tested (0 amount, max uint, etc.)

---

## Deployment Scripts

- [ ] Deployment script tested on testnet
- [ ] Deployment order documented
- [ ] Post-deployment verification steps listed
- [ ] Rollback plan prepared
- [ ] Block explorer verification ready
- [ ] Deployment addresses logged correctly

---

## Documentation

- [ ] README updated with deployment addresses
- [ ] Architecture diagrams current
- [ ] Deployment steps documented
- [ ] Known limitations/risks documented
- [ ] Emergency procedures documented
- [ ] Contact info for on-call engineer

---

## Pre-Flight Final

- [ ] Audit report recommendations implemented
- [ ] Code freeze - no last-minute changes
- [ ] Deployment wallet has sufficient gas
- [ ] Team notified of deployment timing
- [ ] Monitoring/alerts configured
- [ ] Incident response plan ready

---

## Network-Specific

### Mainnet
- [ ] Double-check all addresses (no testnet addresses)
- [ ] Verify gas price reasonable
- [ ] Confirm multisig has enough signers

### L2 (Arbitrum/Optimism)
- [ ] Sequencer uptime checks added
- [ ] L1→L2 message handling correct
- [ ] Gas estimation adjusted for L2

### Polygon/BSC
- [ ] Fast finality considered
- [ ] Bridge addresses verified
- [ ] Native token handling correct

---

## Post-Deployment Immediate

- [ ] Verify contract on block explorer
- [ ] Test basic functionality immediately
- [ ] Transfer ownership to multisig
- [ ] Announce deployment on Discord/Twitter
- [ ] Monitor first 10 transactions closely
- [ ] Check events are emitting correctly

---

## Red Flags (DO NOT DEPLOY IF)

- [ ] [!] Deployer retains admin/owner role
- [ ] [!] Hardcoded addresses not verified
- [ ] [!] Tests failing or skipped
- [ ] [!] Gas costs unexpectedly high
- [ ] [!] Last-minute code changes
- [ ] [!] Unclear about any configuration parameter
- [ ] [!] Team unavailable for monitoring
- [ ] [!] Audit findings not addressed

---

## Quick Reference

**Before You Hit Deploy:**
1. Run full test suite one more time
2. Verify all addresses in deployment script
3. Check deployer wallet balance
4. Have block explorer open
5. Have multisig ready for ownership transfer
6. Take a deep breath

**If Something Goes Wrong:**
1. DO NOT PANIC
2. Check if contract is paused (pause if possible)
3. Notify team immediately
4. Document the issue
5. Execute rollback if necessary
6. Post-mortem after resolution
