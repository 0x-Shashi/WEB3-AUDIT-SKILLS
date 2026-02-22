# Competitive Audit Workflow

## Purpose
Optimized for audit contests (Code4rena, Sherlock, CodeHawks) where speed and unique findings matter.

## Strategy: Time-Boxed Passes

### Pass 1: Quick Wins (2 hours)
- [ ] Run Slither + Aderyn automated tools
- [ ] Focus on critical/high automated findings
- [ ] Check all `external` functions for missing access control
- [ ] Look for classic patterns: reentrancy, unchecked returns, unsafe casting
- [ ] Submit obvious findings immediately

### Pass 2: Money Flows (3 hours)
- [ ] Map all deposit/withdrawal paths
- [ ] Trace token flows through the protocol
- [ ] Check for fee-on-transfer token incompatibility
- [ ] Look for rounding errors in share/token calculations
- [ ] First depositor / donation attack in vaults
- [ ] Oracle manipulation vectors

### Pass 3: Protocol Logic (3 hours)
- [ ] Read documentation to understand intended behavior
- [ ] Compare implementation vs specification
- [ ] Find edge cases: zero amounts, max values, empty arrays
- [ ] Check for off-by-one errors in loops/bounds
- [ ] Validate mathematical formulas manually
- [ ] State machine: can states be reached out of order?

### Pass 4: Deep Analysis (2 hours)
- [ ] Multi-step attack chains
- [ ] Flash loan scenarios
- [ ] Cross-contract reentrancy
- [ ] Integration risks with external protocols
- [ ] Governance/timelock bypass paths

## Finding Submission Strategy
1. Submit critical findings immediately (don't wait)
2. Quality over quantity for mediums
3. Include clear PoC code
4. Reference similar past exploits
5. Be specific about impact (dollar amount if possible)

## Common Contest-Winning Patterns
- Price manipulation via donation/inflation
- Cross-function reentrancy (not caught by simple tools)
- Incorrect accounting after fee-on-transfer tokens
- Missing slippage/deadline on protocol-initiated swaps
- Privilege escalation through initialization
- ERC-4626 vault inflation attack

## Time Allocation (8-hour contest day)
| Phase | Time | Focus |
|-------|------|-------|
| Quick wins | 2h | Automated + obvious |
| Money flows | 3h | Financial logic |
| Protocol logic | 2h | Spec compliance |
| Deep analysis | 1h | Complex attacks |
