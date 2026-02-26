---
id: foundry-ci-cd
title: Foundry CI/CD for Automated Security Testing
category: solidity-scanner
difficulty: intermediate
triggers:
  - CI/CD Foundry
  - GitHub Actions Foundry
  - automated security testing
  - gas regression
  - deployment pipeline
related_skills:
  - solidity-scanner/SKILL.md
  - solidity-scanner/resources/foundry-security.md
  - solidity-scanner/resources/foundry-testing.md
tags:
  - foundry
  - ci-cd
  - github-actions
  - automation
  - deployment
last_updated: 2026-02-26
description: >-
  GitHub Actions workflows for automated Foundry security testing:
  build/test/gas/coverage/deploy pipelines, fork testing with secrets,
  gas snapshot tracking, matrix testing, CI-specific profiles.
  Sourced from claude-plugins foundry-solidity.
---

# Foundry CI/CD for Automated Security Testing

> **For Auditors**: Verify that protocol CI pipelines include fuzz testing, invariant testing, and gas regression detection. A project running only unit tests in CI is missing the majority of Foundry's security value.

---

## Basic GitHub Actions Workflow

```yaml
# .github/workflows/foundry.yml
name: Foundry CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  FOUNDRY_PROFILE: ci

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly

      - name: Build
        run: forge build --sizes

      - name: Run Tests
        run: forge test -vvv

      - name: Run Format Check
        run: forge fmt --check
```

---

## Optimized Workflow with Caching

```yaml
name: Foundry CI (Cached)

on:
  push:
    branches: [main]
  pull_request:

env:
  FOUNDRY_PROFILE: ci

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Cache Forge Build
        uses: actions/cache@v4
        with:
          path: |
            cache
            out
          key: forge-${{ runner.os }}-${{ hashFiles('foundry.toml', 'src/**/*.sol') }}
          restore-keys: |
            forge-${{ runner.os }}-

      - name: Build
        run: forge build

      - name: Test
        run: forge test -vvv
```

---

## Full Security Pipeline

```yaml
name: Security Pipeline

on:
  push:
    branches: [main]
  pull_request:

env:
  FOUNDRY_PROFILE: ci

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Build
        run: forge build --sizes
        id: build

      - name: Check Contract Sizes
        run: |
          forge build --sizes 2>&1 | tee sizes.txt
          # Fail if any contract exceeds 24KB limit
          if grep -E '\|\s+[0-9]+\.[0-9]+\s*\|' sizes.txt | awk -F'|' '{if ($3+0 > 24.576) exit 1}'; then
            echo "All contracts within size limit"
          else
            echo "::error::Contract exceeds 24KB deployment limit"
            exit 1
          fi

  test:
    runs-on: ubuntu-latest
    needs: build
    strategy:
      matrix:
        test-type: [unit, fuzz, invariant]
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Run Unit Tests
        if: matrix.test-type == 'unit'
        run: forge test --match-path "test/unit/**" -vvv

      - name: Run Fuzz Tests
        if: matrix.test-type == 'fuzz'
        run: forge test --match-path "test/fuzz/**" -vvv

      - name: Run Invariant Tests
        if: matrix.test-type == 'invariant'
        run: forge test --match-path "test/invariant/**" -vvv

  coverage:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Generate Coverage
        run: forge coverage --report lcov

      - name: Upload Coverage
        uses: codecov/codecov-action@v4
        with:
          file: ./lcov.info

  gas-report:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Gas Snapshot
        run: forge snapshot

      - name: Compare Gas Snapshot
        run: forge snapshot --check --tolerance 5
        continue-on-error: true
```

---

## Fork Testing in CI

```yaml
  fork-tests:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Run Fork Tests
        run: forge test --match-path "test/fork/**" -vvv
        env:
          # RPC URLs from GitHub Secrets
          ETH_RPC_URL: ${{ secrets.ETH_RPC_URL }}
          ARBITRUM_RPC_URL: ${{ secrets.ARBITRUM_RPC_URL }}
          OPTIMISM_RPC_URL: ${{ secrets.OPTIMISM_RPC_URL }}
          BASE_RPC_URL: ${{ secrets.BASE_RPC_URL }}
```

**⚠️ Security**: Always use GitHub Secrets for RPC URLs — testnet endpoints may expose API keys, and mainnet fork URLs expose provider credentials.

---

## Gas Snapshot Tracking

### PR Comment with Gas Diff

```yaml
  gas-comparison:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
          fetch-depth: 0

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Generate Gas Snapshot (PR)
        run: forge snapshot --snap .gas-snapshot-pr

      - name: Checkout base branch
        run: git checkout ${{ github.event.pull_request.base.sha }}

      - name: Generate Gas Snapshot (Base)
        run: forge snapshot --snap .gas-snapshot-base

      - name: Checkout PR branch
        run: git checkout ${{ github.event.pull_request.head.sha }}

      - name: Compare Snapshots
        id: gas_diff
        run: |
          forge snapshot --diff .gas-snapshot-base 2>&1 | head -100 > gas-diff.txt
          echo "gas_diff<<EOF" >> $GITHUB_OUTPUT
          cat gas-diff.txt >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Comment PR with Gas Diff
        uses: actions/github-script@v7
        with:
          script: |
            const diff = `${{ steps.gas_diff.outputs.gas_diff }}`;
            const body = `## ⛽ Gas Snapshot Diff\n\`\`\`\n${diff}\n\`\`\``;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body,
            });
```

---

## CI-Specific Foundry Profile

```toml
# foundry.toml

[profile.default]
src = "src"
out = "out"
libs = ["lib"]
optimizer = true
optimizer_runs = 200
solc_version = "0.8.30"

[profile.ci]
# Higher fuzz runs for CI (catches more edge cases)
fuzz.runs = 10000
fuzz.max_test_rejects = 100000

# Higher invariant runs
invariant.runs = 256
invariant.depth = 500

# Stricter settings
verbosity = 3
gas_reports = ["*"]

[profile.ci.fuzz]
seed = "0x1234"          # Reproducible fuzzing in CI
dictionary_weight = 80
include_storage = true
include_push_bytes = true

[profile.ci.invariant]
shrink_run_limit = 5000
```

Activate in CI with:
```yaml
env:
  FOUNDRY_PROFILE: ci
```

---

## Matrix Testing Across Solidity Versions

```yaml
  solidity-matrix:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        solc: ["0.8.24", "0.8.26", "0.8.28", "0.8.30"]
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
          cache: true

      - name: Test with Solidity ${{ matrix.solc }}
        run: forge test -vvv
        env:
          FOUNDRY_SOLC_VERSION: ${{ matrix.solc }}
```

---

## Deployment Workflow

```yaml
name: Deploy

on:
  workflow_dispatch:
    inputs:
      network:
        description: "Target network"
        required: true
        type: choice
        options:
          - sepolia
          - mainnet
      verify:
        description: "Verify on Etherscan"
        required: true
        type: boolean
        default: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: ${{ github.event.inputs.network }}
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly

      - name: Run Full Test Suite First
        run: forge test -vvv
        env:
          FOUNDRY_PROFILE: ci

      - name: Deploy
        run: |
          forge script script/Deploy.s.sol:DeployScript \
            --rpc-url ${{ secrets[format('{0}_RPC_URL', github.event.inputs.network)] }} \
            --private-key ${{ secrets.DEPLOYER_PRIVATE_KEY }} \
            --broadcast \
            ${{ github.event.inputs.verify && '--verify --etherscan-api-key' || '' }} \
            ${{ github.event.inputs.verify && secrets.ETHERSCAN_API_KEY || '' }}
        env:
          FOUNDRY_PROFILE: production

      - name: Save Deployment Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: deployment-${{ github.event.inputs.network }}-${{ github.sha }}
          path: broadcast/
```

---

## Secrets Management

### Required GitHub Secrets

| Secret | Purpose | Example |
|--------|---------|---------|
| `ETH_RPC_URL` | Mainnet fork testing | `https://eth-mainnet.g.alchemy.com/v2/KEY` |
| `DEPLOYER_PRIVATE_KEY` | Deployment signing | `0xabc...` (use hardware wallet for mainnet) |
| `ETHERSCAN_API_KEY` | Contract verification | `ABC123...` |
| `CODECOV_TOKEN` | Coverage upload | From codecov.io |

### GitHub Environments

```
Environments:
├── sepolia (no approval required)
│   ├── SEPOLIA_RPC_URL
│   ├── DEPLOYER_PRIVATE_KEY (testnet key)
│   └── ETHERSCAN_API_KEY
└── mainnet (requires approval from 2 reviewers)
    ├── MAINNET_RPC_URL
    ├── DEPLOYER_PRIVATE_KEY (production key)
    └── ETHERSCAN_API_KEY
```

**⚠️ Security**: Never use the same private key for testnet and mainnet deployments. Configure required reviewers for mainnet environment.

---

## Audit Checklist for CI Pipelines

When auditing a project's CI setup, verify:

- [ ] Fuzz tests run with sufficient iterations (≥1000 in CI)
- [ ] Invariant tests are included and run (not skipped)
- [ ] Fork tests use secrets for RPC URLs (not hardcoded)
- [ ] Gas snapshots are tracked and compared on PRs
- [ ] Coverage is measured and uploaded
- [ ] Contract size check is included (24KB limit)
- [ ] Deployment workflow requires test suite to pass first
- [ ] Mainnet deployment requires reviewer approval
- [ ] Private keys are in GitHub Secrets (never in code)
- [ ] Compiler settings match between CI and deployment

---

## Related Files

- [Foundry Security](foundry-security.md) — Vulnerability PoC testing patterns
- [Foundry Testing](foundry-testing.md) — Fuzz/invariant/fork testing
- [Foundry Cheatcodes](foundry-cheatcodes.md) — Complete cheatcode reference
- [Gas Security](gas-security.md) — Gas snapshot CI integration

---

*Source: claude-plugins foundry-solidity cicd.md, configuration.md (February 2026)*
