---
name: Commands & Hooks
description: Plugin commands, keyboard shortcuts, and automation hooks
version: 1.0.0
author: Web3 Security Plugin
tags: [commands, hooks, automation, workflow, integration]
---

# Commands & Hooks

Register slash commands and event hooks for seamless plugin integration.

---

## Slash Commands

### Audit Commands

```yaml
commands:
  # Start a new audit
  - name: "/audit-start"
    description: "Initialize a new security audit"
    usage: "/audit-start <project-name>"
    action: |
      1. Create audit workspace structure
      2. Generate README with scope template
      3. Set up findings tracker
      4. Initialize static analysis config

  # Analyze current file
  - name: "/audit-scan"
    description: "Scan current file for vulnerabilities"
    usage: "/audit-scan [--deep]"
    action: |
      1. Identify file type/language
      2. Apply appropriate scanner skill
      3. Run static analysis
      4. Report findings inline

  # Search findings database
  - name: "/audit-search"
    description: "Search Cyfrin Solodit for similar patterns"
    usage: "/audit-search <pattern-or-keyword>"
    action: |
      1. Query Solodit API
      2. Filter by relevance
      3. Display matching findings
      4. Suggest applicable patterns

  # Generate report
  - name: "/audit-report"
    description: "Generate audit report from findings"
    usage: "/audit-report [format]"
    options:
      - "--format=md|pdf|html"
      - "--template=full|summary|findings-only"
    action: |
      1. Collect all documented findings
      2. Apply template
      3. Generate report file
```

### Quick Scan Commands

```yaml
commands:
  # Reentrancy check
  - name: "/check-reentrancy"
    description: "Check current function for reentrancy"
    usage: "/check-reentrancy"
    action: |
      1. Identify external calls
      2. Check state updates order
      3. Verify guards
      4. Report findings

  # Access control check
  - name: "/check-access"
    description: "Analyze access control patterns"
    usage: "/check-access [function-name]"
    action: |
      1. Map modifiers
      2. Identify privileged functions
      3. Check role hierarchies
      4. Report gaps

  # Token integration check
  - name: "/check-tokens"
    description: "Analyze token integration safety"
    usage: "/check-tokens"
    action: |
      1. Identify token interactions
      2. Check for weird token handling
      3. Verify safe transfer usage
      4. Report vulnerabilities

  # Oracle check
  - name: "/check-oracle"
    description: "Analyze oracle usage patterns"
    usage: "/check-oracle"
    action: |
      1. Identify price feeds
      2. Check staleness handling
      3. Verify manipulation resistance
      4. Report concerns
```

### Finding Commands

```yaml
commands:
  # Log new finding
  - name: "/finding"
    description: "Document a new security finding"
    usage: "/finding <severity> <title>"
    options:
      - "severity: critical|high|medium|low|info"
    action: |
      1. Create finding entry
      2. Auto-fill location
      3. Open finding template
      4. Add to tracker

  # List findings
  - name: "/findings"
    description: "List all documented findings"
    usage: "/findings [--severity=X]"
    action: |
      1. Read findings tracker
      2. Apply filters
      3. Display summary table

  # Export findings
  - name: "/findings-export"
    description: "Export findings to various formats"
    usage: "/findings-export <format>"
    options:
      - "format: md|csv|json"
```

### Static Analysis Commands

```yaml
commands:
  # Run Slither
  - name: "/slither"
    description: "Run Slither on current project"
    usage: "/slither [--detector=X]"
    action: |
      1. Detect project root
      2. Run slither command
      3. Parse results
      4. Display findings

  # Run Mythril
  - name: "/mythril"
    description: "Run Mythril symbolic execution"
    usage: "/mythril [file.sol]"
    action: |
      1. Run myth analyze
      2. Parse results
      3. Display findings

  # Triage results
  - name: "/triage"
    description: "Triage static analysis results"
    usage: "/triage"
    action: |
      1. Load analysis results
      2. Classify by severity
      3. Filter false positives
      4. Generate review list
```

### Comparison Commands

```yaml
commands:
  # Diff contracts
  - name: "/diff"
    description: "Compare two contract versions"
    usage: "/diff <v1-path> <v2-path>"
    action: |
      1. Generate code diff
      2. Classify changes
      3. Highlight security-relevant
      4. Generate review list

  # Storage layout check
  - name: "/storage-check"
    description: "Compare storage layouts for upgrade safety"
    usage: "/storage-check <v1> <v2>"
    action: |
      1. Extract storage layouts
      2. Compare slot assignments
      3. Check compatibility
      4. Report issues
```

---

## Event Hooks

### File Events

```yaml
hooks:
  # On file open
  onFileOpen:
    trigger: "File opened in editor"
    conditions:
      - extension: [".sol", ".rs", ".cairo", ".move", ".fc"]
    actions:
      - "Display security checklist for file type"
      - "Run quick static analysis"
      - "Load relevant skill context"

  # On file save
  onFileSave:
    trigger: "File saved"
    conditions:
      - extension: [".sol", ".rs", ".cairo", ".move", ".fc"]
    actions:
      - "Run incremental static analysis"
      - "Check for new vulnerabilities"
      - "Update findings if file modified"

  # On file change
  onFileChange:
    trigger: "File content changed"
    conditions:
      - inAuditMode: true
    actions:
      - "Mark file as modified in audit tracker"
      - "Queue for re-review"
```

### Project Events

```yaml
hooks:
  # On project open
  onProjectOpen:
    trigger: "Workspace opened"
    actions:
      - "Detect project type"
      - "Load appropriate skills"
      - "Initialize audit context"
      - "Run initial analysis"

  # On git commit
  onGitCommit:
    trigger: "Git commit in workspace"
    conditions:
      - inAuditMode: true
    actions:
      - "Log commit for audit trail"
      - "Check for fix commits"
      - "Update finding statuses"
```

### Cursor Events

```yaml
hooks:
  # On function hover
  onFunctionHover:
    trigger: "Cursor hovers over function"
    delay: 500ms
    actions:
      - "Show quick security summary"
      - "Display relevant checklist items"

  # On selection
  onCodeSelection:
    trigger: "Code selected"
    actions:
      - "Enable context menu with audit actions"
      - "Show 'Analyze Selection' option"
```

---

## Keyboard Shortcuts

```yaml
shortcuts:
  # Quick scan
  - key: "Ctrl+Shift+A"
    command: "/audit-scan"
    description: "Quick scan current file"

  # New finding
  - key: "Ctrl+Shift+F"
    command: "/finding"
    description: "Log new finding"

  # Search database
  - key: "Ctrl+Shift+S"
    command: "/audit-search"
    description: "Search vulnerability database"

  # Run Slither
  - key: "Ctrl+Shift+L"
    command: "/slither"
    description: "Run Slither analysis"

  # Show findings
  - key: "Ctrl+Shift+I"
    command: "/findings"
    description: "Show findings panel"
```

---

## Context Menus

### Right-Click Menu

```yaml
contextMenu:
  - label: " Analyze Selection"
    command: "audit.analyzeSelection"
    when: "editorHasSelection && resourceExtname == .sol"
    
  - label: " Report Finding Here"
    command: "audit.reportFinding"
    when: "editorHasSelection"
    
  - label: " Search Similar Vulnerabilities"
    command: "audit.searchSimilar"
    when: "editorHasSelection"
    
  - label: "---"
    
  - label: " Check Reentrancy"
    command: "audit.checkReentrancy"
    when: "editorLangId == solidity"
    
  - label: " Check Access Control"
    command: "audit.checkAccess"
    when: "editorLangId == solidity"
```

---

## Automation Workflows

### Pre-Audit Automation

```yaml
workflow:
  name: "Pre-Audit Setup"
  trigger: "/audit-start"
  steps:
    - name: "Create structure"
      action: |
        mkdir -p {project}/findings
        mkdir -p {project}/notes
        mkdir -p {project}/poc

    - name: "Initialize tracker"
      action: |
        Create findings.json with schema:
        {
          "project": "{name}",
          "startDate": "{date}",
          "status": "in-progress",
          "findings": []
        }

    - name: "Run initial analysis"
      action: |
        slither . --json findings/slither-initial.json
        
    - name: "Generate scope document"
      action: |
        Create SCOPE.md with:
        - Contract list
        - Line counts
        - Dependency list
```

### Continuous Audit Automation

```yaml
workflow:
  name: "Continuous Analysis"
  trigger: "onFileSave"
  conditions:
    - "file.extension in [.sol]"
    - "audit.active == true"
  steps:
    - name: "Quick scan"
      action: "Run targeted Slither detectors"
      
    - name: "Compare to baseline"
      action: "Diff against initial analysis"
      
    - name: "Alert new issues"
      action: "Notify if new vulnerabilities detected"
```

### Report Generation Automation

```yaml
workflow:
  name: "Generate Report"
  trigger: "/audit-report"
  steps:
    - name: "Collect findings"
      action: "Read all findings from tracker"
      
    - name: "Sort and number"
      action: "Order by severity, assign IDs"
      
    - name: "Apply template"
      action: "Use report-template.md"
      
    - name: "Generate summary tables"
      action: "Create severity and category tables"
      
    - name: "Output report"
      action: "Write to reports/AUDIT-REPORT.md"
```

---

## Integration Points

### IDE Integration

```yaml
integration:
  # Status bar
  statusBar:
    - position: "right"
      content: " Audit Mode: {status}"
      tooltip: "Click to toggle audit mode"
      
    - position: "right"
      content: "Findings: {count}"
      tooltip: "Click to show findings panel"

  # Side panel
  sidePanel:
    name: "Security Audit"
    sections:
      - "Active Findings"
      - "Checklist"
      - "Analysis Results"
      - "Quick Actions"

  # Problems panel
  problemsIntegration:
    enabled: true
    source: "Web3 Security"
    severityMapping:
      critical: "error"
      high: "error"
      medium: "warning"
      low: "information"
      info: "hint"
```

### External Tools

```yaml
externalTools:
  slither:
    command: "slither"
    args: ["{workspace}", "--json", "-"]
    parseOutput: "json"
    
  mythril:
    command: "myth"
    args: ["analyze", "{file}"]
    parseOutput: "text"
    
  foundry:
    command: "forge"
    args: ["test", "--match-path", "{file}"]
    parseOutput: "text"
```

---

## Command Reference

| Command | Description | Usage |
|---------|-------------|-------|
| `/audit-start` | Initialize audit | `/audit-start my-project` |
| `/audit-scan` | Scan current file | `/audit-scan --deep` |
| `/audit-search` | Search Solodit | `/audit-search reentrancy` |
| `/audit-report` | Generate report | `/audit-report --format=md` |
| `/finding` | Log finding | `/finding high Missing auth` |
| `/findings` | List findings | `/findings --severity=high` |
| `/slither` | Run Slither | `/slither --detector=reentrancy` |
| `/check-reentrancy` | Check reentrancy | `/check-reentrancy` |
| `/check-access` | Check access control | `/check-access` |
| `/check-tokens` | Check token safety | `/check-tokens` |
| `/diff` | Compare versions | `/diff v1/ v2/` |

