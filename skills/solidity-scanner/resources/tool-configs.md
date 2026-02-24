---
id: solidity-tool-configs
title: Static Analysis Tool Configurations
category: resource
parent_skill: solidity-scanner/SKILL.md
description: >
  Production-ready configurations for Slither, Aderyn, Mythril, Semgrep,
  4naly3er, and Foundry test integration. Includes detector explanations,
  custom rule examples, and a recommended multi-tool workflow.
tags:
  - solidity
  - tools
  - static-analysis
  - slither
  - aderyn
  - mythril
last_updated: 2026-02-24
---

# Static Analysis Tool Configurations

## Tool Selection Matrix

| Tool | Analysis Type | Speed | Depth | Best For |
|---|---|---|---|---|
| **Slither** | Static (AST + IR) | Fast (seconds) | Broad | First-pass sweep of all contracts |
| **Aderyn** (Cyfrin) | Static (AST) | Fast (seconds) | Broad | Cyfrin-pattern detection, reporting |
| **Mythril** | Symbolic execution | Slow (minutes–hours) | Deep | Complex state-dependent bugs |
| **Semgrep** | Pattern matching | Fast (seconds) | Custom | Custom rules, CI/CD integration |
| **4naly3er** | Static + gas | Fast (seconds) | Broad | Gas + low-severity automated report |
| **Foundry (forge test)** | Dynamic (fuzzing) | Variable | Deep | Invariant testing, PoC validation |

---

## Slither

### Installation

```bash
pip install slither-analyzer
# Or with specific Solidity version support
pip install slither-analyzer[solc]
```

### Configuration File

```json
// slither.config.json
{
  "detectors_to_exclude": "naming-convention,solc-version,pragma",
  "exclude_informational": false,
  "exclude_low": false,
  "exclude_medium": false,
  "exclude_high": false,
  "filter_paths": "node_modules|lib|test|script",
  "solc_remaps": [
    "@openzeppelin/=lib/openzeppelin-contracts/",
    "@chainlink/=lib/chainlink/",
    "solmate/=lib/solmate/src/"
  ],
  "solc_args": "--optimize --optimize-runs 200"
}
```

### Key Detectors Reference

| Detector | Severity | What It Finds | False Positive Rate |
|---|---|---|---|
| `reentrancy-eth` | High | Reentrancy with ETH transfer | Low |
| `reentrancy-no-eth` | Medium | Reentrancy without ETH | Medium |
| `reentrancy-benign` | Low | Reentrancy with no security impact | High |
| `reentrancy-events` | Low | Event emitted after external call | High |
| `uninitialized-state` | High | State variables never initialized | Low |
| `uninitialized-local` | Medium | Local variables never initialized | Medium |
| `arbitrary-send-eth` | High | ETH sent to arbitrary address | Medium |
| `arbitrary-send-erc20` | High | ERC20 sent to arbitrary address | Medium |
| `suicidal` | High | Unprotected selfdestruct | Low |
| `controlled-delegatecall` | High | Delegatecall to user-controlled target | Low |
| `unchecked-transfer` | High | Missing return value check on transfer | Low |
| `unchecked-lowlevel` | Medium | Missing return value on low-level call | Low |
| `locked-ether` | Medium | Contract locks ETH with no withdraw | Low |
| `shadowing-state` | High | State variable shadows parent | Low |
| `shadowing-local` | Low | Local variable shadows state | Medium |
| `controlled-array-length` | High | Array length controlled by user | Low |
| `costly-loop` | Medium | Expensive operations in loop | Medium |
| `calls-loop` | Low | External calls inside loop | Medium |
| `tx-origin` | Medium | `tx.origin` used for auth | Low |
| `unprotected-upgrade` | High | Missing auth on upgrade function | Low |
| `missing-zero-check` | Low | Missing zero-address validation | Medium |
| `dead-code` | Info | Unreachable code | Low |
| `unused-state` | Info | Unused state variables | Low |

### Running Slither

```bash
# Full analysis
slither . --config-file slither.config.json

# Target specific contract
slither src/Vault.sol --config-file slither.config.json

# Run specific detectors only
slither . --detect reentrancy-eth,unchecked-transfer,unprotected-upgrade

# Generate markdown report
slither . --checklist --markdown-root . > slither-report.md

# Print contract summary (useful for context building)
slither . --print contract-summary

# Print inheritance graph
slither . --print inheritance-graph

# Print function summary (visibility, modifiers, state changes)
slither . --print function-summary

# Print storage layout (critical for upgradeable contracts)
slither . --print variable-order
```

### Custom Slither Detector Template

```python
# custom_detectors/state_after_call.py
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import HighLevelCall, LowLevelCall

class StateAfterExternalCall(AbstractDetector):
    ARGUMENT = "state-after-external-call"
    HELP = "State variable written after external call (CEI violation)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://docs.soliditylang.org/en/latest/security-considerations.html"
    WIKI_TITLE = "CEI Violation"
    WIKI_DESCRIPTION = "State modification after external call enables reentrancy"
    WIKI_RECOMMENDATION = "Apply Check-Effects-Interactions pattern"

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or function.view or function.pure:
                    continue
                external_call_seen = False
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, (HighLevelCall, LowLevelCall)):
                            external_call_seen = True
                    if external_call_seen and node.state_variables_written:
                        info = [
                            "CEI violation in ", function, ":\n",
                            "\tState written after external call at ", node, "\n",
                        ]
                        results.append(self.generate_result(info))
        return results
```

Run: `slither . --detect state-after-external-call --plugin custom_detectors`

---

## Aderyn (Cyfrin)

### Installation

```bash
# Via cargo
cargo install aderyn

# Or download binary from GitHub releases
# https://github.com/Cyfrin/aderyn/releases
```

### Running Aderyn

```bash
# Full analysis with markdown output
aderyn . --output report.md

# Specify root directory
aderyn ./src --output report.md

# JSON output for programmatic processing
aderyn . --output report.json
```

### What Aderyn Detects

| Category | Detections |
|---|---|
| **High** | Uninitialized state, arbitrary ETH send, selfdestruct, delegatecall |
| **Medium** | Centralization risks, unsafe ERC20 operations, missing events |
| **Low** | Missing zero-address checks, unused imports, floating pragma |
| **Gas** | State variable caching, calldata vs memory, redundant checks |

### Aderyn vs Slither Comparison

| Feature | Aderyn | Slither |
|---|---|---|
| Language | Rust | Python |
| Speed | Very fast | Fast |
| Custom detectors | Limited | Extensive |
| Report format | Clean markdown/JSON | Verbose text or markdown |
| Solidity version support | Modern (0.8.x) | Broad (0.4.x–0.8.x) |
| Best use | Quick automated report | Deep custom analysis |

**Recommendation**: Run both. They have different detector sets and catch different patterns.

---

## Mythril

### Installation

```bash
pip install mythril

# Or Docker
docker pull mythril/myth
```

### Configuration

```bash
# Default analysis (30-second timeout per function)
myth analyze src/Vault.sol --solc-json mythril.config.json --execution-timeout 120

# Deep analysis (longer timeout, more states explored)
myth analyze src/Vault.sol --solc-json mythril.config.json \
  --execution-timeout 600 \
  --max-depth 50 \
  --transaction-count 3
```

```json
// mythril.config.json
{
  "remappings": [
    "@openzeppelin/=lib/openzeppelin-contracts/",
    "solmate/=lib/solmate/src/"
  ]
}
```

### What Mythril Excels At

| Vulnerability | Why Mythril Is Better |
|---|---|
| Integer overflow/underflow | Symbolic execution proves exact values |
| Unprotected selfdestruct | Explores all call paths to selfdestruct |
| Delegatecall injection | Traces data flow to delegatecall target |
| Ether extraction | Proves ETH can be extracted by attacker |
| State-dependent bugs | Multi-transaction analysis (2–3 txs deep) |

### What Mythril Is Weak At

| Area | Limitation |
|---|---|
| Speed | Much slower than Slither/Aderyn |
| Large codebases | State explosion problem |
| Cross-contract analysis | Limited multi-contract reasoning |
| Business logic | Cannot understand protocol intent |

**Use Mythril selectively**: Only on high-risk contracts (vaults, bridges, token contracts), not on the entire codebase.

---

## Semgrep

### Installation

```bash
pip install semgrep
```

### Custom Rules for Solidity

```yaml
# solidity-rules.yaml
rules:
  # Reentrancy: state write after external call
  - id: reentrancy-state-after-call
    languages: [solidity]
    severity: ERROR
    message: "State modification after external call — potential reentrancy"
    patterns:
      - pattern: |
          $TOKEN.safeTransfer(...);
          ...
          $MAP[$KEY] = $VALUE;
      - pattern: |
          $TOKEN.transfer(...);
          ...
          $MAP[$KEY] = $VALUE;

  # Unchecked return value
  - id: unchecked-erc20-transfer
    languages: [solidity]
    severity: WARNING
    message: "ERC20 transfer return value not checked — use SafeERC20"
    pattern: $TOKEN.transfer($TO, $AMOUNT);
    pattern-not-inside: |
      require($TOKEN.transfer($TO, $AMOUNT), ...);

  # Missing staleness check on Chainlink
  - id: chainlink-missing-staleness
    languages: [solidity]
    severity: WARNING
    message: "Chainlink latestRoundData() without staleness check"
    pattern: |
      (... , int256 $ANSWER, ... , ... , ...) = $FEED.latestRoundData();
    pattern-not-inside: |
      require(block.timestamp - $UPDATED <= ..., ...);

  # tx.origin authentication
  - id: tx-origin-auth
    languages: [solidity]
    severity: ERROR
    message: "tx.origin used for authentication — phishing vulnerability"
    pattern: require(tx.origin == $ADDR, ...);

  # Missing zero-address check
  - id: missing-zero-address-check
    languages: [solidity]
    severity: INFO
    message: "Address parameter not checked for zero address"
    pattern: |
      function $FUNC(address $ADDR, ...) ... {
        ...
        $VAR = $ADDR;
        ...
      }
    pattern-not-inside: |
      require($ADDR != address(0), ...);
```

Run: `semgrep --config solidity-rules.yaml src/`

---

## 4naly3er

### Usage

```bash
# Clone and run
git clone https://github.com/Picodes/4naly3er
cd 4naly3er
node analyze.js /path/to/contracts

# Or with npx
npx 4naly3er /path/to/contracts
```

### What 4naly3er Covers

Primarily low-severity and gas findings:
- Gas optimizations (storage caching, calldata usage, unchecked increments)
- Non-critical issues (missing events, floating pragma, imports order)
- Low issues (unsafe ERC20, missing zero checks)

**Best used as**: Automated baseline for QA/gas reports in contests. Run it, include relevant findings, focus your manual effort on High/Medium.

---

## Foundry Integration — Security Testing

### Invariant Testing Configuration

```toml
# foundry.toml
[invariant]
runs = 1000
depth = 50
fail_on_revert = false
call_override = false
dictionary_weight = 40
include_storage = true
include_push_bytes = true
```

### Security-Focused Fuzzing Template

```solidity
// test/invariants/VaultInvariant.t.sol
contract VaultInvariantTest is Test {
    Vault vault;
    MockERC20 token;

    function setUp() public {
        token = new MockERC20("Test", "TST", 18);
        vault = new Vault(address(token));
    }

    // INVARIANT: Vault balance >= sum of all user deposits
    function invariant_solvency() public view {
        uint256 vaultBalance = token.balanceOf(address(vault));
        assertGe(vaultBalance, vault.totalDeposited(), "Vault is insolvent!");
    }

    // INVARIANT: Total shares == sum of individual shares
    function invariant_shareAccounting() public view {
        // This should always hold
        assertEq(vault.totalSupply(), sumOfAllShares(), "Share accounting broken");
    }

    // INVARIANT: No user can withdraw more than they deposited
    function invariant_noExcessWithdrawal() public view {
        for (uint i = 0; i < actors.length; i++) {
            assertLe(
                vault.totalWithdrawn(actors[i]),
                vault.totalDeposited(actors[i]),
                "Excess withdrawal detected"
            );
        }
    }
}
```

### PoC Validation Template

```solidity
// test/PoC.t.sol
contract ReentrancyPoC is Test {
    Vault vault;
    AttackContract attacker;

    function setUp() public {
        vault = new Vault();
        attacker = new AttackContract(address(vault));

        // Fund the vault
        vm.deal(address(vault), 10 ether);
        vault.deposit{value: 10 ether}();

        // Fund the attacker
        vm.deal(address(attacker), 1 ether);
    }

    function test_reentrancyExploit() public {
        uint256 vaultBalanceBefore = address(vault).balance;

        // Execute attack
        attacker.attack{value: 1 ether}();

        uint256 vaultBalanceAfter = address(vault).balance;

        // Vault should be drained
        assertEq(vaultBalanceAfter, 0, "Vault not fully drained");
        // Attacker should have all the ETH
        assertGt(address(attacker).balance, vaultBalanceBefore, "Attacker did not profit");
    }
}
```

---

## Recommended Multi-Tool Workflow

```
1. SLITHER (2 min)
   ├── Run full detector suite
   ├── Generate contract-summary and function-summary
   ├── Print storage layout (if upgradeable)
   └── Triage findings: mark true/false positives
         ↓
2. ADERYN (1 min)
   ├── Run full analysis
   ├── Compare findings with Slither output
   └── New unique findings → add to triage list
         ↓
3. 4NALY3ER (1 min)
   ├── Generate gas/QA report
   └── Include relevant gas findings in report
         ↓
4. MYTHRIL — Selective (5–30 min per contract)
   ├── Run ONLY on high-risk contracts (vault, bridge, token)
   ├── Deep analysis: integer overflow, selfdestruct, delegatecall
   └── Validate or refute ambiguous Slither findings
         ↓
5. SEMGREP — Custom Rules (1 min)
   ├── Run custom rules for protocol-specific patterns
   └── Catch patterns that static tools miss
         ↓
6. FOUNDRY — Dynamic Validation (variable)
   ├── Write invariant tests for critical properties
   ├── Fuzz critical functions
   └── Build PoCs for confirmed findings
```

## Tool Limitations — What They Cannot Find

| Limitation | Example |
|---|---|
| Business logic errors | Incorrect interest rate formula |
| Design flaws | Missing functionality, wrong architecture |
| Economic attacks | Token incentive misalignment |
| Cross-protocol dependencies | Integration risk with external DeFi protocol |
| Off-chain component bugs | Backend/oracle/keeper failures |
| Social engineering | Governance manipulation via social media |

**Bottom line**: Static tools are a starting point, not a replacement for manual review. They catch ~20–30% of real bugs. The remaining 70–80% require human analysis.
