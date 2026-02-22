# Attack Chains Skill

## Purpose
Detect multi-step exploit sequences where individual steps may appear benign but combine into critical vulnerabilities. Real-world exploits rarely use a single vulnerability — they chain multiple issues together.

## Why Attack Chains Matter
- $624M Ronin Bridge: Social engineering → Key compromise → Validator threshold bypass → Fund drain
- $326M Wormhole: Signature verification bypass → Fake VAA → Unauthorized minting
- $182M Beanstalk: Flash loan → Governance vote → Proposal execution → Fund drain
- $130M Cream Finance: Flash loan → Oracle manipulation → Under-collateralized borrow → Drain

## Chain Types
| Chain | Description | File |
|-------|-------------|------|
| Flash Loan | Flash loan enables price/governance manipulation | [flash-loan-chains.md](flash-loan-chains.md) |
| Oracle | Oracle distortion enables economic exploits | [oracle-chains.md](oracle-chains.md) |
| Bridge | Cross-chain verification bypass chains | [bridge-chains.md](bridge-chains.md) |
| Governance | Vote manipulation and proposal hijacking | [governance-chains.md](governance-chains.md) |

## Detection Approach
1. **Identify entry points**: Flash loans, large token transfers, governance proposals
2. **Trace data flow**: Follow manipulated values through the system
3. **Check invariants**: Verify economic invariants hold under manipulation
4. **Simulate chains**: Walk through multi-step sequences mentally or in tests

## Severity
Attack chains are almost always **Critical** or **High** severity because they represent complete exploit paths.
