# Command Implementation Guide

Reference for implementing plugin commands and hooks in Cursor/IDE environments.

---

## Command Structure

### Basic Command Definition

```javascript
// commands/audit-scan.js
module.exports = {
  name: 'audit-scan',
  description: 'Scan current file for security vulnerabilities',
  aliases: ['scan', 'as'],
  
  // Command options
  options: [
    {
      name: 'deep',
      type: 'boolean',
      description: 'Perform deep analysis',
      default: false
    },
    {
      name: 'output',
      type: 'string',
      description: 'Output format',
      choices: ['inline', 'panel', 'file'],
      default: 'inline'
    }
  ],
  
  // Execution function
  async execute(context, options) {
    const { editor, workspace } = context;
    const file = editor.activeDocument;
    
    // Determine file type
    const fileType = getFileType(file.path);
    
    // Load appropriate skill
    const skill = await loadSkill(fileType);
    
    // Run analysis
    const results = await skill.analyze(file.content, options);
    
    // Display results
    return displayResults(results, options.output);
  }
};
```

### Command Registration

```javascript
// plugin.js
const commands = require('./commands');

function activate(context) {
  // Register all commands
  for (const command of commands) {
    context.registerCommand(`web3audit.${command.name}`, (args) => {
      return command.execute(context, parseArgs(args));
    });
  }
  
  // Register slash command handler
  context.registerSlashCommandHandler('audit', async (prompt) => {
    const [cmd, ...args] = prompt.split(' ');
    const command = commands.find(c => c.name === cmd || c.aliases?.includes(cmd));
    
    if (command) {
      return command.execute(context, parseArgs(args.join(' ')));
    }
    
    return `Unknown command: ${cmd}`;
  });
}
```

---

## Hook Implementation

### File Event Hooks

```javascript
// hooks/file-hooks.js
module.exports = {
  onFileOpen: {
    async handler(context, file) {
      // Check if it's a smart contract
      if (!isSmartContract(file.path)) return;
      
      // Load relevant context
      const fileType = getFileType(file.path);
      const skill = await loadSkill(fileType);
      
      // Show security checklist in panel
      await showSecurityChecklist(skill.checklist);
      
      // Run quick analysis
      const quickResults = await skill.quickScan(file.content);
      
      // Highlight issues inline
      await highlightIssues(context.editor, quickResults);
    },
    
    conditions: {
      extensions: ['.sol', '.rs', '.cairo', '.move', '.fc', '.tact']
    }
  },
  
  onFileSave: {
    async handler(context, file) {
      // Only in audit mode
      if (!context.isAuditMode) return;
      
      // Run incremental analysis
      const results = await runIncrementalAnalysis(file);
      
      // Compare to previous
      const newIssues = compareToBaseline(results, file.baseline);
      
      if (newIssues.length > 0) {
        await notifyNewIssues(newIssues);
      }
      
      // Update baseline
      file.baseline = results;
    },
    
    conditions: {
      auditMode: true,
      extensions: ['.sol', '.rs', '.cairo', '.move', '.fc', '.tact']
    }
  }
};
```

### Project Event Hooks

```javascript
// hooks/project-hooks.js
module.exports = {
  onProjectOpen: {
    async handler(context, workspace) {
      // Detect project type
      const projectType = await detectProjectType(workspace);
      
      // Store in context
      context.projectType = projectType;
      
      // Load skills for project type
      await loadSkillsForProject(projectType);
      
      // Initialize audit context
      if (await hasAuditConfig(workspace)) {
        await loadAuditContext(workspace);
        context.isAuditMode = true;
      }
      
      // Show welcome panel
      await showWelcomePanel(projectType);
    }
  }
};
```

---

## Context Menu Implementation

```javascript
// context-menu.js
module.exports = {
  menus: [
    {
      id: 'audit.analyzeSelection',
      label: '🔍 Analyze Selection',
      when: 'editorHasSelection && resourceExtname =~ /\\.(sol|rs|cairo|move|fc)$/',
      group: 'web3audit',
      
      async handler(context) {
        const selection = context.editor.selection;
        const code = context.editor.document.getText(selection);
        
        const results = await analyzeCodeSnippet(code);
        await showAnalysisResults(results);
      }
    },
    
    {
      id: 'audit.reportFinding',
      label: '🐛 Report Finding Here',
      when: 'editorHasSelection',
      group: 'web3audit',
      
      async handler(context) {
        const selection = context.editor.selection;
        const file = context.editor.document.uri.path;
        const line = selection.start.line + 1;
        
        // Open finding creation dialog
        await openFindingDialog({
          location: `${file}#L${line}`,
          codeSnippet: context.editor.document.getText(selection)
        });
      }
    },
    
    {
      id: 'audit.searchSimilar',
      label: '📚 Search Similar Vulnerabilities',
      when: 'editorHasSelection',
      group: 'web3audit',
      
      async handler(context) {
        const code = context.editor.document.getText(context.editor.selection);
        
        // Extract pattern from code
        const pattern = extractPattern(code);
        
        // Search Solodit
        const results = await searchSolodit(pattern);
        
        await showSearchResults(results);
      }
    }
  ]
};
```

---

## Keyboard Shortcut Bindings

```json
{
  "keybindings": [
    {
      "key": "ctrl+shift+a",
      "command": "web3audit.audit-scan",
      "when": "editorTextFocus && resourceExtname =~ /\\.(sol|rs|cairo|move|fc)$/"
    },
    {
      "key": "ctrl+shift+f",
      "command": "web3audit.finding",
      "when": "editorTextFocus"
    },
    {
      "key": "ctrl+shift+s",
      "command": "web3audit.audit-search",
      "when": "editorTextFocus"
    },
    {
      "key": "ctrl+shift+l",
      "command": "web3audit.slither",
      "when": "workspaceFolderCount > 0"
    },
    {
      "key": "ctrl+shift+i",
      "command": "web3audit.findings",
      "when": "workspaceFolderCount > 0"
    }
  ]
}
```

---

## Status Bar Integration

```javascript
// statusbar.js
module.exports = {
  items: [
    {
      id: 'auditMode',
      alignment: 'right',
      priority: 100,
      
      get text() {
        return context.isAuditMode ? '🔍 Audit Mode: ON' : '🔍 Audit Mode: OFF';
      },
      
      get tooltip() {
        return 'Click to toggle audit mode';
      },
      
      onClick() {
        context.isAuditMode = !context.isAuditMode;
        this.update();
      }
    },
    
    {
      id: 'findingsCount',
      alignment: 'right',
      priority: 99,
      
      get text() {
        const count = context.findings?.length || 0;
        return `📋 Findings: ${count}`;
      },
      
      get tooltip() {
        return 'Click to show findings panel';
      },
      
      onClick() {
        executeCommand('web3audit.findings');
      }
    }
  ]
};
```

---

## Side Panel Implementation

```javascript
// panel.js
module.exports = {
  id: 'web3audit.securityPanel',
  title: 'Security Audit',
  icon: 'shield',
  
  sections: [
    {
      id: 'findings',
      title: 'Active Findings',
      
      async getContent() {
        const findings = await getFindingsFromTracker();
        
        return findings.map(f => ({
          label: `[${f.id}] ${f.title}`,
          description: f.severity,
          icon: getSeverityIcon(f.severity),
          onClick: () => navigateToFinding(f)
        }));
      }
    },
    
    {
      id: 'checklist',
      title: 'Security Checklist',
      
      async getContent() {
        const fileType = getActiveFileType();
        const skill = await loadSkill(fileType);
        
        return skill.checklist.map(item => ({
          label: item.title,
          checked: item.completed,
          onToggle: (checked) => updateChecklistItem(item.id, checked)
        }));
      }
    },
    
    {
      id: 'quickActions',
      title: 'Quick Actions',
      
      getContent() {
        return [
          { label: 'Scan Current File', command: 'web3audit.audit-scan' },
          { label: 'Run Slither', command: 'web3audit.slither' },
          { label: 'Check Reentrancy', command: 'web3audit.check-reentrancy' },
          { label: 'Generate Report', command: 'web3audit.audit-report' }
        ];
      }
    }
  ]
};
```

---

## Problems Panel Integration

```javascript
// diagnostics.js
module.exports = {
  source: 'Web3 Security',
  
  async provideDiagnostics(document) {
    const results = await runQuickAnalysis(document);
    
    return results.map(issue => ({
      range: issue.range,
      message: issue.message,
      severity: mapSeverity(issue.severity),
      code: issue.id,
      source: 'Web3 Security'
    }));
  },
  
  mapSeverity(severity) {
    switch (severity) {
      case 'critical':
      case 'high':
        return DiagnosticSeverity.Error;
      case 'medium':
        return DiagnosticSeverity.Warning;
      case 'low':
        return DiagnosticSeverity.Information;
      default:
        return DiagnosticSeverity.Hint;
    }
  }
};
```

---

## Command Help Text

```javascript
// help.js
const helpText = `
# Web3 Security Audit Plugin

## Commands

### Audit Management
  /audit-start <name>     Initialize a new audit project
  /audit-scan [--deep]    Scan current file for vulnerabilities
  /audit-search <query>   Search vulnerability database
  /audit-report [format]  Generate audit report

### Security Checks
  /check-reentrancy       Check for reentrancy vulnerabilities
  /check-access           Analyze access control patterns
  /check-tokens           Check token integration safety
  /check-oracle           Analyze oracle usage patterns

### Findings
  /finding <sev> <title>  Log a new finding
  /findings [--filter]    List all findings
  /findings-export <fmt>  Export findings

### Static Analysis
  /slither [--detector]   Run Slither analysis
  /mythril [file]         Run Mythril analysis
  /triage                 Triage analysis results

### Comparison
  /diff <v1> <v2>         Compare contract versions
  /storage-check <v1> <v2> Check storage compatibility

## Keyboard Shortcuts
  Ctrl+Shift+A            Quick scan current file
  Ctrl+Shift+F            Log new finding
  Ctrl+Shift+S            Search vulnerability database
  Ctrl+Shift+L            Run Slither
  Ctrl+Shift+I            Show findings panel

## Tips
- Use /audit-start to begin a new audit
- Use /audit-scan frequently while reviewing
- Document findings immediately with /finding
- Generate reports with /audit-report

For more help, visit the documentation.
`;

module.exports = { helpText };
```

