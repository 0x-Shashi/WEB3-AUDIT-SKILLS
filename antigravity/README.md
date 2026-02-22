# WEB3-AUDIT-SKILLS for Antigravity

Antigravity CLI configuration for Web3 security auditing skills.

## Architecture

This folder contains **only platform-specific configuration** for Antigravity CLI. All skill content lives in the shared `skills/` directory at the repository root, which is the single source of truth for all platforms.

```
repo-root/
  skills/          <-- shared skill files (465 files)
  antigravity/     <-- this folder (config only)
    antigravity.yaml
    README.md
```

## Installation

1. Clone this repo to your Antigravity skills directory
2. Configure Antigravity to load the skills from `../skills/`

## Skills Available

- **Attack Trees** - Protocol-specific vulnerability decision trees
- **Anti-Patterns** - Bad code patterns with fixes
- **Patterns** - 155 vulnerability patterns from 50K+ real findings
- **Exploit Forensics** - 30 real hack forensic analyses
- **Protocol Playbooks** - 19 integration security guides
- **Templates** - Audit session templates
- **Methodology** - 16 advanced audit methodology guides

## Usage

Load skills based on protocol type:

```
/load ../skills/attack-trees/lending-attack-tree.md
/load ../skills/anti-patterns/oracle-anti-patterns.md
```

## Configuration

See `antigravity.yaml` for hooks, tool permissions, and custom commands.
