---
id: METH-DEPRECATED-INFRA-DETECTION
title: Deprecated Infrastructure Detection
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - deprecated
  - dead-infrastructure
  - legacy
  - migration
  - supply-chain
  - dependency-audit
  - clockwork
  - serum
  - outdated
last_updated: 2026-02-27
description: >-
  Use when auditing protocols that may depend on deprecated, dead, or
  replaced infrastructure — covers Solana dead ecosystem registry
  (Clockwork, Serum, Switchboard Functions), deprecated EVM infrastructure,
  "verify before use" methodology for unfamiliar APIs, placeholder test
  detection, outdated dependency flagging, and finding templates with
  severity guidance. Derived from solana-anchor-claude analysis and
  vulnhunter sharp-edges methodology.
---

# Deprecated Infrastructure Detection

## Overview

Deprecated infrastructure is a silent killer in audits. The code compiles,
the tests pass (often with placeholders), and the integration LOOKS correct.
But the upstream service is dead, unmaintained, or replaced — meaning the
protocol will fail in production or, worse, expose funds to abandoned code
with known unpatched vulnerabilities.

**Core principle**: If a dependency or integration target is deprecated,
it is a finding. The severity depends on what breaks when the deprecated
service stops working (or has already stopped).

### Why Deprecated Infrastructure Is a Security Issue

| Risk Level | Scenario | Example |
|-----------|---------|---------|
| Critical | Protocol funds locked in dead contract | Serum DEX market accounts frozen |
| High | Integration silently returns stale/wrong data | Abandoned oracle feed |
| Medium | Scheduled automation stops executing | Clockwork cron jobs |
| Low | Suboptimal performance due to legacy patterns | web3.js v1 instead of Solana Kit |

## Solana Dead Infrastructure Registry

### Confirmed Dead Projects

| Project | Status | Replacement | Date Deprecated | Risk If Used |
|---------|--------|-------------|-----------------|-------------|
| **Project Serum** | DEAD — collapsed (FTX connection) | OpenBook DEX | Nov 2022 | Critical: market accounts may be frozen |
| **Clockwork** | DEAD — team dissolved | TukTuk | 2024 | High: scheduled instructions will never fire |
| **Switchboard Functions** | DEPRECATED — product discontinued | Switchboard Oracle Quotes | 2025 | High: function callbacks will stop |
| **@solana/web3.js v1** | LEGACY — superseded | Solana Kit (web3.js v2) | 2024 | Low: works but missing features |
| **@coral-xyz/anchor (TS)** | LEGACY — being replaced | Codama-generated clients | 2025 | Low: works but adds unnecessary dependency |
| **Solana Labs docs** | DEAD — company replaced | Anza docs (docs.anza.xyz) | 2024 | Low: outdated documentation |
| **yarn** | DISCOURAGED in Solana ecosystem | npm | — | Low: unnecessary complexity |
| **bs58 npm package** | UNNECESSARY | `@solana/codecs` getBase58Decoder | — | Low: extra dependency |
| **ts-mocha** | UNNECESSARY | Node.js built-in test runner + tsx | — | Low: extra dependency |

### Detection Patterns for Solana

```bash
# Scan for Serum/OpenBook confusion
grep -rn "serum\|SerumMarket\|@project-serum" programs/ tests/ package.json

# Scan for Clockwork (dead scheduler)
grep -rn "clockwork\|ClockworkProvider\|clockwork-xyz" programs/ tests/ Cargo.toml

# Scan for deprecated Switchboard Functions
grep -rn "switchboard-functions\|FunctionAccount\|switchboard.*function" programs/

# Scan for web3.js v1 usage
grep -rn "@solana/web3.js" package.json
# If found: check if it's v1 (deprecated) or v2/Kit (current)

# Scan for old Anchor TS package
grep -rn "@coral-xyz/anchor" package.json tests/

# Scan for unnecessary bs58
grep -rn "bs58\|from.*'bs58'" package.json tests/ src/
```

## EVM Dead Infrastructure Registry

### Confirmed Dead/Deprecated Projects

| Project | Status | Replacement | Risk If Used |
|---------|--------|-------------|-------------|
| **Rinkeby testnet** | DEAD | Sepolia, Holesky | Test-only dependency; no production risk |
| **Ropsten testnet** | DEAD | Sepolia | Same as above |
| **Kovan testnet** | DEAD | Sepolia | Same as above |
| **OpenZeppelin v3** | OUTDATED | OpenZeppelin v5 | Medium: missing security fixes |
| **Solidity <0.8.0** | LEGACY | Solidity >=0.8.0 | High: no overflow protection |
| **Truffle** | DEPRECATED | Foundry, Hardhat | Low: works but unmaintained |
| **web3.js (EVM)** | LEGACY | ethers.js v6, viem | Low: works but larger footprint |
| **Chainlink Price Feed v2** | SUPERSEDED | Chainlink Price Feed v3 | Medium: missing features |

### Detection Patterns for EVM

```bash
# Scan for deprecated testnets in config
grep -rn "rinkeby\|ropsten\|kovan" hardhat.config.* foundry.toml .env

# Scan for old OpenZeppelin
grep -rn "openzeppelin.*3\.\|@openzeppelin/contracts@3" package.json

# Scan for Solidity version
grep -rn "pragma solidity" contracts/ | grep -v "0\.8\."

# Scan for Truffle
ls truffle-config.js truffle.js 2>/dev/null

# Scan for deprecated web3.js
grep -rn "web3.js\|Web3(" package.json src/
```

## Verify-Before-Use Methodology

### The "CRITICAL — Verify Before Use" Rule

From real-world experience auditing Solana programs:

> Before calling ANY function whose signature you don't know with certainty,
> read the actual source code/type definitions first. NEVER guess or assume
> what parameters a function accepts based on what seems logical.

**Why this matters for deprecated infrastructure**: Generated code,
third-party libraries, and unfamiliar codebases often have different APIs
than expected. If the library is deprecated, the API documentation may
be offline or outdated.

### Verification Process

```
1. IDENTIFY the dependency
   - Name, version, last update date
   - Is it still maintained? Check GitHub: last commit, open issues, archived?

2. CHECK for deprecation notices
   - README badges: "archived," "deprecated," "unmaintained"
   - NPM: check for deprecation warnings
   - Cargo: check for yanked versions
   - GitHub: is the repo archived?

3. VERIFY the API surface actually in use
   - Which functions/methods does the protocol call?
   - Do those functions still exist in the latest version?
   - Do the function signatures match what the code expects?

4. ASSESS replacement viability
   - Is there a maintained replacement?
   - How difficult is the migration?
   - Are there breaking changes?
```

## Placeholder Test Detection

### Why Placeholder Tests Are a Red Flag

Placeholder tests create false confidence. They pass in CI, showing green
checkmarks, but test NOTHING. In an audit context, placeholder tests suggest
the developer didn't fully understand the integration.

### Detection Patterns

```typescript
// ❌ PLACEHOLDER — tests nothing
test("should work", () => {
  assert.ok(true);
});

// ❌ PLACEHOLDER — never calls the program
test("deposit works", () => {
  const amount = 100;
  assert.equal(amount, 100); // tests a constant, not the program
});

// ❌ PLACEHOLDER — declares success without verification
test("transfer succeeds", async () => {
  await program.methods.transfer(amount).rpc();
  // No assertion! No balance check! No state verification!
});
```

### Placeholder Detection Script

```bash
# Find tests that only assert true/ok(true)
grep -rn "assert.*ok.*true\|assert.*equal.*true\|expect.*toBe.*true" tests/

# Find tests with no assertions at all
# (harder — requires AST analysis, but heuristic works)
grep -A5 "test\|it\|describe" tests/ | grep -L "assert\|expect\|should"

# Find tests that don't call any program instruction
grep -rn "test(" tests/ | while read line; do
  file=$(echo "$line" | cut -d: -f1)
  # Check if file contains any RPC call
  if ! grep -q "\.rpc()\|\.send()\|sendTransaction\|invoke" "$file"; then
    echo "NO RPC CALLS: $file"
  fi
done
```

### Severity Classification for Placeholder Tests

| Context | Severity | Rationale |
|---------|----------|-----------|
| Critical function has only placeholder tests | High | No verification of security-critical behavior |
| Non-critical utility has placeholder tests | Low | Informational — suggest improvement |
| ALL tests are placeholders | High | No test coverage at all |
| Placeholder tests alongside real tests | Informational | Incomplete coverage |

## Outdated Dependency Audit

### Automated Scanning

```bash
# NPM: Check for outdated packages
npm outdated

# NPM: Check for known vulnerabilities
npm audit

# Cargo: Check for outdated crates
cargo outdated

# Cargo: Check for known vulnerabilities
cargo audit

# Check for abandoned GitHub repos (> 1 year no commits)
# Manual: Visit each dependency's GitHub page
```

### Dependency Risk Matrix

| Factor | Low Risk | Medium Risk | High Risk |
|--------|---------|-------------|-----------|
| Last commit | < 3 months | 3-12 months | > 12 months |
| Open critical issues | 0 | 1-3 | > 3 or unresponsive |
| Maintainer count | 3+ active | 1-2 active | 0 or 1 inactive |
| Security advisories | None | Patched | Unpatched |
| Fork/replacement exists | N/A | Available | Widely adopted |
| Used by protocol for | Display/logging | Business logic | Fund management |

## Finding Templates

### Template 1: Dead Integration

```markdown
## [SEVERITY] — Protocol Depends on Dead Infrastructure: [PROJECT]

**Description**: The protocol integrates with [PROJECT], which was
discontinued on [DATE]. [Specific impact description].

**Impact**: [What breaks when the dead service fully stops responding]

**Location**: [File:Line — specific integration point]

**Recommendation**: Migrate to [REPLACEMENT]. Key migration steps:
1. [Step 1]
2. [Step 2]
3. [Step 3]
```

### Template 2: Outdated Dependency with Known Vulnerability

```markdown
## [SEVERITY] — Outdated Dependency: [PACKAGE] v[VERSION]

**Description**: The protocol uses [PACKAGE] version [VERSION], which
has known vulnerability [CVE/Advisory ID]. The patched version is
[NEW_VERSION].

**Impact**: [How the vulnerability could be exploited in this context]

**Location**: [package.json / Cargo.toml — line N]

**Recommendation**: Upgrade to [PACKAGE] v[NEW_VERSION]. Breaking
changes to be aware of: [list any].
```

### Template 3: Placeholder Tests Detected

```markdown
## [SEVERITY] — Placeholder Tests for [FUNCTION/MODULE]

**Description**: Tests for [FUNCTION/MODULE] contain placeholder
assertions that do not verify actual program behavior. Specifically:
- [test_name]: asserts `ok(true)` without calling any program instruction
- [test_name]: calls instruction but has no post-condition assertion

**Impact**: No automated verification of [CRITICAL BEHAVIOR]. Regressions
will not be caught by CI.

**Recommendation**: Replace placeholder tests with integration tests that:
1. Initialize accounts and state
2. Execute the program instruction
3. Verify state changes (balances, flags, counters)
4. Test error conditions (invalid inputs, unauthorized callers)
```

## Systematic Checklist

### Pre-Audit Dependency Scan

- [ ] List all dependencies (Cargo.toml, package.json, remappings)
- [ ] Check each dependency's GitHub: archived? Last commit?
- [ ] Run `npm audit` / `cargo audit` for known vulnerabilities
- [ ] Run `npm outdated` / `cargo outdated` for version currency
- [ ] Check for Solana-specific dead projects (Serum, Clockwork, etc.)
- [ ] Check for EVM-specific dead projects (Rinkeby, Truffle, etc.)

### Integration Point Audit

- [ ] For each external protocol integration: is the target still live?
- [ ] For each oracle feed: is the feed still being updated?
- [ ] For each keeper/automation: is the service still running?
- [ ] For each API endpoint: is the API still responding?
- [ ] For each testnet dependency: is the testnet still operating?

### Test Quality Assessment

- [ ] Are there tests for every critical function?
- [ ] Do tests actually call program instructions (not just assert true)?
- [ ] Do tests verify state changes after execution?
- [ ] Do tests cover error paths (unauthorized, invalid input)?
- [ ] Are there integration tests (not just unit tests)?

## Integration with Other Skills

| Skill | Relationship |
|-------|-------------|
| [Sharp Edges Detection](methodology/sharp-edges-detection.md) | Deprecated APIs are a category of sharp edges |
| [Codebase Recon](methodology/codebase-recon-methodology.md) | Phase 1 tech stack mapping reveals dependencies |
| [TDD Security Testing](methodology/tdd-security-testing.md) | Placeholder test detection feeds into TDD workflow |
| [Static Analysis](../static-analysis/) | Dependency scanners complement static analysis |
| [Audit Context Building](../audit-context-building/) | Deprecated deps are critical context |
