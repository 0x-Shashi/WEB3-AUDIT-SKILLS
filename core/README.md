# Web3 Audit Core Module

The functional core of the Web3 Security Audit System. This module provides the actual execution layer for security analysis.

## Features

- **Solodit API Client** - Query 50K+ real security findings from Cyfrin Solodit
- **Tool Runners** - Execute Slither, Mythril, and Aderyn with unified output
- **Finding Database** - SQLite/JSON storage for tracking findings
- **CLI Tool** - Command-line interface for all operations
- **Project Detection** - Auto-detect framework (Foundry, Hardhat, Anchor, etc.)

## Installation

```bash
cd core
npm install
npm link  # Makes 'web3audit' command globally available
```

## Prerequisites

Install security analysis tools:

```bash
# Slither (Python) - Most commonly used
pip install slither-analyzer

# Aderyn (Rust) - Fast, modern
cargo install aderyn

# Mythril (Python) - Symbolic execution
pip install mythril
```

## CLI Usage

### Check Tool Status

```bash
web3audit status
```

### Run Security Scan

```bash
# Basic scan
web3audit scan ./contracts

# Quick scan (faster)
web3audit scan ./contracts --quick

# Deep scan (thorough)
web3audit scan ./contracts --deep

# Specify tools
web3audit scan ./contracts --tools slither,aderyn

# Save to database
web3audit scan ./contracts --save

# Output to file
web3audit scan ./contracts -o report.md -f markdown
```

### Search Solodit Database

```bash
# Search by keyword
web3audit search "reentrancy"

# Search by protocol
web3audit search -p "uniswap" "swap vulnerability"

# Search by severity
web3audit search -s "high" "flash loan"

# Find similar to code file
web3audit similar ./contracts/Vault.sol
```

### Database Operations

```bash
# List projects
web3audit db list

# List findings
web3audit db findings --severity HIGH

# Mark as fixed
web3audit db fix 123 --notes "Fixed in commit abc123"

# Mark as false positive
web3audit db fp 123 --reason "Not applicable to our use case"
```

### Generate Reports

```bash
# Generate from database
web3audit report -o audit-report.md

# For specific project
web3audit report --project 1 -o report.md
```

## Programmatic Usage

```javascript
const { 
  SoloditClient, 
  ToolRunner, 
  FindingDatabase,
  ProjectDetector 
} = require('./src');

// Detect project type
const detector = new ProjectDetector();
const project = await detector.detect('./my-project');
console.log(`Framework: ${project.framework}`);  // foundry, hardhat, etc.

// Search Solodit
const client = new SoloditClient();
const findings = await client.searchFindings('reentrancy', { limit: 10 });
const similar = await client.findSimilar(contractCode);

// Run analysis
const runner = new ToolRunner();
const results = await runner.runAll('./contracts');
console.log(`Found ${results.combined.summary.total} issues`);

// Store findings
const db = new FindingDatabase();
await db.init();

const projectId = db.createProject({ name: 'MyDeFi', path: './contracts' });
const auditId = db.startAudit(projectId);

for (const finding of results.combined.findings) {
  db.addFinding({
    audit_id: auditId,
    project_id: projectId,
    title: finding.title,
    severity: finding.severity,
    description: finding.description,
    file_path: finding.elements?.[0]?.file,
    source: finding.source
  });
}

// Query findings
const highSeverity = db.queryFindings({ 
  severity: 'HIGH',
  excludeFalsePositives: true 
});

// Get statistics
const stats = db.getStats({ project_id: projectId });
console.log(`High: ${stats.bySeverity.high}, Medium: ${stats.bySeverity.medium}`);

db.close();
```

## Module Structure

```
core/
 package.json           # Node.js config
 bin/
    cli.js            # CLI entry point
 src/
    index.js          # Main exports
    api/
       solodit-client.js   # Solodit API
       solodit-parser.js   # Response parsing
    tools/
       slither-runner.js   # Slither integration
       mythril-runner.js   # Mythril integration
       aderyn-runner.js    # Aderyn integration
       tool-runner.js      # Unified runner
    db/
       finding-database.js # SQLite/JSON storage
    utils/
        project-detector.js # Framework detection
```

## Supported Frameworks

| Framework | Ecosystem | Detection |
|-----------|-----------|-----------|
| Foundry | Ethereum | `foundry.toml` |
| Hardhat | Ethereum | `hardhat.config.js/ts` |
| Truffle | Ethereum | `truffle-config.js` |
| Brownie | Ethereum | `brownie-config.yaml` |
| Anchor | Solana | `Anchor.toml` |
| Move | Aptos/Sui | `Move.toml` |
| CosmWasm | Cosmos | `Cargo.toml` + cosmwasm-std |

## Tool Comparison

| Tool | Speed | Depth | Install |
|------|-------|-------|---------|
| Slither |  Fast | Pattern-based | `pip install slither-analyzer` |
| Aderyn |  Very Fast | Pattern-based | `cargo install aderyn` |
| Mythril |  Slow | Symbolic exec | `pip install mythril` |

**Recommendation:** Use Slither + Aderyn for quick scans, add Mythril for deep analysis.

## Environment Variables

```bash
# Optional: Solodit API configuration
SOLODIT_API_URL=https://solodit.xyz/api

# Debug mode
DEBUG=true
```

## License

MIT

