# Severity Classification Guide

## Critical
- Direct fund theft possible
- Complete protocol compromise
- Unbounded token minting
- Proxy upgrade to malicious implementation

**Criteria:** Exploitable with high probability, affects all users, no prerequisites

## High
- Conditional fund loss (specific scenarios)
- Significant protocol disruption
- Oracle manipulation leading to incorrect liquidations
- Governance takeover via flash loans

**Criteria:** Exploitable under specific conditions, significant financial impact

## Medium
- Limited fund loss (bounded)
- Protocol functionality impaired
- Centralization risks (admin can rug)
- Griefing attacks (DoS without profit)

**Criteria:** Requires specific conditions, limited scope, or bounded impact

## Low
- Best practice violations
- Minor gas inefficiencies
- Non-critical missing validations
- Informational issues

**Criteria:** No direct fund loss, minimal impact on protocol functionality

## Severity Matrix

| | Loss of Funds | Protocol Impact | Likelihood |
|---|---|---|---|
| **Critical** | Unbounded | Complete | High |
| **High** | Significant | Major | Medium-High |
| **Medium** | Limited/None | Moderate | Medium |
| **Low** | None | Minor | Low |

## False Positive Indicators
- Issue requires admin to be malicious (often accepted risk)
- Gas cost of attack exceeds profit
- Theoretical only, no practical exploit path
- Already mitigated by existing mechanism
