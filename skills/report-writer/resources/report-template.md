---
id: RPT-REPORT-TPL
title: Audit Report Template
parent: report-writer
type: resource
last_updated: 2025-01-31
---

# Audit Report Template

Full template for producing a professional smart contract security audit report. Based on industry standards from leading audit firms.

---

## Complete Report Template

````markdown
# Security Audit Report

## [Protocol Name]

### Report Information

| Field | Value |
|-------|-------|
| **Protocol** | [Protocol Name] |
| **Website** | [URL] |
| **Audit Date** | [Start Date] — [End Date] |
| **Auditor** | [Auditor Name / Firm] |
| **Repository** | [GitHub URL] |
| **Commit Hash** | [40-char commit] |
| **Report Version** | 1.0 |
| **Language** | Solidity [version] |
| **Framework** | Foundry / Hardhat |
| **Chain** | Ethereum / Arbitrum / etc. |

---

## Disclaimer

This audit report is not financial advice. The findings represent the
auditor's best effort to identify vulnerabilities within the reviewed
scope during the audit period. A security audit cannot guarantee the
absence of vulnerabilities. The protocol team is responsible for
addressing findings and maintaining security post-audit.

---

## Executive Summary

[Protocol Name] is a [type of protocol: DEX / lending / bridge / etc.]
that enables [core functionality in 1-2 sentences].

The audit reviewed [X] contracts comprising approximately [Y] lines of
Solidity code. The review identified [N] findings:

| Severity | Count |
|----------|-------|
| Critical | [N] |
| High | [N] |
| Medium | [N] |
| Low | [N] |
| Informational | [N] |
| Gas Optimization | [N] |
| **Total** | **[N]** |

**Overall Assessment:** [Brief 1-2 sentence assessment. E.g., "The codebase
demonstrates strong security practices with comprehensive access control.
However, critical findings in the vault logic should be addressed before
deployment."]

---

## Scope

### In Scope

| Contract | SLOC | Purpose |
|----------|------|----------|
| `src/Vault.sol` | 245 | Core vault logic |
| `src/Router.sol` | 180 | User-facing router |
| `src/Oracle.sol` | 95 | Price feed integration |
| **Total** | **520** | |

### Out of Scope

- Test files (`test/`)
- Deployment scripts (`script/`)
- Third-party libraries (`lib/`)
- Off-chain components

---

## Methodology

The audit was conducted using the following approach:

1. **Context building** — Review documentation, architecture, and previous audits
2. **Static analysis** — Automated scanning with Slither and Aderyn
3. **Manual review** — Line-by-line code review of all in-scope contracts
4. **Attack surface analysis** — Identify entry points and trust boundaries
5. **Vulnerability testing** — Write PoC tests for potential findings
6. **Report writing** — Document findings with severity classification

Tools used:
- Slither v0.10.x
- Foundry (forge, cast)
- Custom analysis scripts

---

## Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| C-01 | [Title] | Critical | [Open/Fixed/Acknowledged] |
| H-01 | [Title] | High | [Open/Fixed/Acknowledged] |
| H-02 | [Title] | High | [Open/Fixed/Acknowledged] |
| M-01 | [Title] | Medium | [Open/Fixed/Acknowledged] |
| L-01 | [Title] | Low | [Open/Fixed/Acknowledged] |
| I-01 | [Title] | Info | [Open/Fixed/Acknowledged] |

---

## Detailed Findings

### Critical

#### [C-01] [Finding Title]

[Use standard finding template from finding-templates.md]

---

### High

#### [H-01] [Finding Title]

[Use standard finding template]

---

### Medium

#### [M-01] [Finding Title]

[Use standard finding template]

---

### Low

#### [L-01] [Finding Title]

[Use standard finding template]

---

### Informational

#### [I-01] [Finding Title]

[Brief description and recommendation]

---

## Centralization Risks

| Risk | Description | Severity |
|------|-------------|----------|
| Owner can upgrade | Proxy upgrade authority held by EOA | High |
| Admin can pause | Emergency pause controlled by single key | Medium |
| Fee recipient | Protocol fees sent to hardcoded address | Low |

**Recommendation:** Transfer ownership to a multisig (e.g., Gnosis Safe)
with a timelock for critical operations.

---

## Gas Optimizations

| ID | Description | Savings |
|----|-------------|----------|
| G-01 | Use `unchecked` for safe arithmetic | ~100 gas/call |
| G-02 | Cache storage reads in local variables | ~200 gas/call |
| G-03 | Use `calldata` instead of `memory` for read-only arrays | ~60 gas/param |

---

## Appendix

### A. Severity Classification

[Include the Likelihood × Impact matrix]

### B. Tools Used

| Tool | Version | Purpose |
|------|---------|----------|
| Slither | 0.10.x | Static analysis |
| Foundry | 0.2.0 | Testing and PoC |
| Aderyn | 0.1.x | Additional static analysis |

### C. About [Auditor/Firm]

[Brief auditor/firm description]
````

---

## Finding Status Definitions

| Status | Meaning |
|--------|----------|
| **Open** | Not yet addressed by the team |
| **Fixed** | Fix verified by auditor in commit [hash] |
| **Acknowledged** | Team aware but chose not to fix (with reasoning) |
| **Disputed** | Team disagrees with finding (with reasoning) |
| **Partially Fixed** | Mitigation applied but doesn't fully resolve |

---

## Best Practices for Report Writing

1. **Version the report** — v1.0 for initial, v1.1 for fix review
2. **Link to specific commits** — Base commit and fix commit
3. **Be objective** — State facts, not opinions
4. **Be specific** — Exact lines, exact values, exact attack scenarios
5. **Be constructive** — Every finding should have a clear recommendation
