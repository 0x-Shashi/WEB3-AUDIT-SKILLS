# Web3 Audit Skills - Core Module

## Overview
The core module provides the backend intelligence engine for the Web3 Audit Skills system. It includes pattern matching, severity scoring, vulnerability classification, and MCP server integration.

## Architecture
```
core/
├── package.json           # Node.js package configuration
├── bin/
│   └── cli.js             # Command-line interface
├── src/
│   ├── index.js           # Main exports
│   ├── api/               # Solodit API client
│   │   ├── index.js       # API exports
│   │   ├── solodit-client.js    # HTTP client for Solodit
│   │   └── solodit-parser.js    # Response parser
│   ├── db/                # Finding database
│   │   ├── index.js       # DB exports
│   │   └── finding-database.js  # Local finding storage
│   ├── intelligence/      # AI analysis modules
│   │   ├── index.js       # Intelligence exports
│   │   ├── pattern-matcher.js   # Vulnerability pattern matching
│   │   ├── severity-scorer.js   # CVSS-based severity scoring
│   │   ├── vulnerability-classifier.js  # Finding classification
│   │   └── semantic-search.js   # Pattern semantic search
│   ├── tools/             # Static analysis tool runners
│   │   ├── index.js       # Tool exports
│   │   ├── slither-runner.js    # Slither integration
│   │   ├── mythril-runner.js    # Mythril integration
│   │   ├── aderyn-runner.js     # Aderyn integration
│   │   └── tool-runner.js       # Base tool runner
│   └── utils/             # Utilities
│       ├── index.js       # Utility exports
│       └── project-detector.js  # Project type detection
└── tests/
    ├── core.test.js       # Core module tests
    └── intelligence.test.js     # Intelligence module tests
```

## Key Components

### Intelligence Module
- **PatternMatcher**: Matches Solidity code against 200+ known vulnerability patterns
- **SeverityScorer**: Calculates severity using impact, likelihood, and exploitability
- **VulnerabilityClassifier**: Categorizes findings into standard taxonomy
- **SemanticSearch**: Finds relevant patterns using semantic similarity

### API Module
- **SoloditClient**: Fetches historical audit findings from Solodit
- **SoloditParser**: Parses and normalizes API responses

### Tools Module
- **SlitherRunner**: Runs Slither static analysis
- **MythrilRunner**: Runs Mythril symbolic execution
- **AderynRunner**: Runs Aderyn Rust-based analysis

### Database Module
- **FindingDatabase**: Local storage for findings and patterns

## Setup
```bash
cd core
npm install
npm start
```

## MCP Server
The core module can run as an MCP (Model Context Protocol) server:
```bash
npm run mcp
```

## License
MIT
