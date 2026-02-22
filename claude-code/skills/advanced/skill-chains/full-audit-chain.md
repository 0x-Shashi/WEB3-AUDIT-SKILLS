# Full Audit Chain

## Duration: 1-2 Weeks
## Depth: Comprehensive

## Purpose
Complete protocol audit with maximum coverage. Includes all Quick Scan and Deep Dive steps plus economic analysis, invariant testing, and multi-pass review.

## Chain Steps (in order)

### Phase 1: Reconnaissance (Day 1)
1. **Documentation Review**
   - Read all specs, whitepapers, previous audit reports
   - Understand protocol economics and intended behavior
   - Document all assumptions and trust assumptions
   
2. **Architecture Mapping**
   - Full contract inheritance and dependency graph
   - External protocol integrations mapped
   - Deployment configuration and parameters documented
   - Access control roles and permissions matrix

3. **Scope Enumeration**
   - Lines of code per contract
   - Complexity score (cyclomatic complexity)
   - Risk-ranked function list
   - Test coverage analysis

### Phase 2: Automated Analysis (Day 2)
1. **Static Analysis**
   - Slither full scan + triage
   - Aderyn scan + triage
   - Semgrep custom rules (if applicable)
   - Mythril targeted symbolic execution on high-risk functions
   
2. **Test Review**
   - Run existing test suite
   - Identify missing test coverage
   - Review edge case testing
   - Check fuzzing/invariant tests exist

### Phase 3: Manual Review Pass 1 (Days 3-5)
1. **Critical Path Review**
   - User fund deposit/withdrawal flows
   - Admin/privileged functions
   - Oracle integration points
   - Cross-contract interactions
   
2. **Function-by-Function Review**
   - Every external/public function reviewed
   - Internal functions called by externals reviewed
   - Library functions verified
   
3. **Protocol-Specific Template**
   - Load and execute full template checklist
   - Document each check as Pass/Fail/N/A

### Phase 4: Attack Analysis (Days 6-7)
1. **Attack Chain Construction**
   - Flash loan chains (all variants)
   - Oracle manipulation chains
   - Governance attack chains
   - Bridge attack chains (if applicable)
   - Custom chains for unique protocol features
   
2. **Economic Attack Analysis**
   - Sandwich attack profitability
   - Liquidation cascades
   - Incentive misalignment
   - Game theory analysis

3. **Proof of Concept Development**
   - Write PoC for each High/Critical finding
   - Test on mainnet fork
   - Calculate maximum extractable value

### Phase 5: Manual Review Pass 2 (Days 8-9)
1. **Fresh Eyes Review**
   - Re-read all code with findings context
   - Look for issues missed in Pass 1
   - Cross-reference with historical exploits of similar protocols
   
2. **Variant Analysis**
   - Every finding → search for variants
   - Cross-contract pattern matching
   - Historical pattern database comparison (Cyfrin, Solodit)

3. **Integration Review**
   - Token compatibility analysis (weird ERC20s)
   - Upgrade safety review (if proxy)
   - Initializer safety (if upgradeable)

### Phase 6: Report (Days 10-12)
1. **Finding Documentation**
   - Each finding with full PoC
   - Severity justification
   - Remediation recommendations
   - Estimated fix effort
   
2. **Executive Summary**
   - Overall risk assessment
   - Critical/High finding summary
   - Architecture recommendations
   - Deployment readiness opinion

3. **Review and QA**
   - Peer review of all findings
   - Verify PoCs still work
   - Check severity assignments
   - Format and deliver report

## Exit Criteria
- Two full manual review passes completed
- All automated tool findings triaged
- Attack chains documented for all identifiable vectors
- PoCs for all High/Critical findings
- Variant analysis for all findings
- Protocol-specific template fully executed
- Peer-reviewed report delivered
- Fix review scheduled

## Post-Audit
- Fix review (after client applies fixes)
- Verify each finding addressed
- Check for regression/new issues from fixes
- Final sign-off report
