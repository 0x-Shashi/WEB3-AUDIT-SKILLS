# Gradient Template: Missed Oracle Manipulation

## Vulnerability Class
Price Oracle Manipulation (all variants)

---

## Detection Signals

### Spot Price Manipulation
```solidity
// Signal: Using AMM reserves directly for price
function getPrice() external view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();  // [SIGNAL]
    return reserve1 * 1e18 / reserve0;  // Manipulable via flash loan
}
```

### TWAP Insufficient Window
```solidity
// Signal: TWAP with short observation window
function getPrice() external view returns (uint256) {
    return oracle.consult(token, 600);  // [SIGNAL] 10 min = too short
}
```

### Single Oracle Source
```solidity
// Signal: No fallback oracle
function getPrice(address token) external view returns (uint256) {
    return chainlinkFeed.latestAnswer();  // [SIGNAL] What if stale/down?
}
```

### Stale Price Check Missing
```solidity
// Signal: No freshness validation
(, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
return uint256(price);  // [SIGNAL] No check on updatedAt
```

### L2 Sequencer Check Missing
```solidity
// Signal: Chainlink on L2 without sequencer check
function getPrice() external view returns (uint256) {
    // On Arbitrum/Optimism - no sequencer uptime check
    (, int256 price,,,) = priceFeed.latestRoundData();  // [SIGNAL]
    return uint256(price);
}
```

### Decimal Mismatch
```solidity
// Signal: Different oracle decimals not normalized
function getValue(uint256 amount) external view returns (uint256) {
    uint256 price = oracle.getPrice();  // 8 decimals
    return amount * price / 1e18;  // [SIGNAL] Assumes 18 decimals
}
```

---

## Common Miss Reasons

| Reason | Frequency | Fix |
|--------|-----------|-----|
| Assumed Chainlink is infallible | HIGH | Add stale/fallback checks |
| Didn't check TWAP window | HIGH | Verify window vs attack cost |
| Missed L2-specific requirements | HIGH | Add sequencer uptime check |
| Didn't trace price flow | MEDIUM | Map all oracle consumers |
| Assumed decimals are standard | MEDIUM | Verify decimal handling |
| Didn't consider flash loan context | MEDIUM | Check all price reads in tx |

---

## Critique Template

### Section 1: Identify the Miss
```markdown
**Vulnerability Missed:** [Describe the oracle manipulation]
**Contract:** [contract.sol]
**Function:** [function using oracle]
**Oracle Type:** [Chainlink/Uniswap/Custom]
**Severity:** [CRITICAL/HIGH/MEDIUM]
**Discovery Source:** [How was it found?]
```

### Section 2: Analyze Why
```markdown
**What pattern file should have caught this?**
- patterns/oracle-manipulation-patterns.md

**Was the attack vector documented?**
- [ ] Yes, fully documented
- [ ] Partially documented  
- [ ] No documentation exists

**What code signal was present?**
- [Describe the signal]

**Why was it missed?**
- [ ] Oracle validation not in checklist
- [ ] L2-specific check not known
- [ ] Decimal handling not verified
- [ ] Price flow not fully traced
- [ ] Flash loan context not considered
```

### Section 3: Root Cause
```markdown
**Root Cause Analysis:**
[Detailed explanation]

**Pattern Gap:**
[What oracle pattern was missing?]

**Process Gap:**
[What validation step was skipped?]
```

---

## Edit Targets

### If Stale Price Check Missed
```yaml
update_files:
  - patterns/oracle-manipulation-patterns.md:
      add: "## Stale Price Detection Checklist"
  - checklists/defi-checklist.md:
      add: "[ ] Chainlink updatedAt checked against threshold"
  - anti-patterns/oracle-anti-patterns.md:
      add: "Anti-Pattern: Missing Staleness Check"
```

### If L2 Sequencer Check Missed
```yaml
update_files:
  - patterns/oracle-manipulation-patterns.md:
      add: "## L2 Sequencer Uptime Check"
  - TRIGGERS.md:
      add: "| Arbitrum/Optimism | l2-oracle-patterns.md |"
  - checklists/defi-checklist.md:
      add: "[ ] L2 sequencer uptime feed checked"
```

### If Spot Price Used
```yaml
update_files:
  - patterns/oracle-manipulation-patterns.md:
      add: "## Spot Price vs TWAP"
  - anti-patterns/oracle-anti-patterns.md:
      add: "Anti-Pattern: Raw AMM Reserve Price"
```

---

## Edit Templates

### Checklist Addition
```markdown
## Oracle Security Checklist

**Price Source:**
- [ ] Using TWAP or reliable oracle (not spot)
- [ ] TWAP window sufficient (>30 min recommended)
- [ ] Fallback oracle configured

**Validation:**
- [ ] Stale price check implemented
- [ ] Negative/zero price handled
- [ ] Round completeness verified

**L2 Specific:**
- [ ] Sequencer uptime checked (Arbitrum/Optimism)
- [ ] Grace period after sequencer restart

**Decimal Handling:**
- [ ] Oracle decimals queried, not assumed
- [ ] Normalization correct
```

### Pattern Addition
```markdown
## [Oracle Issue] Pattern

### Vulnerable Code
```solidity
// [Show vulnerable oracle usage]
```

### Safe Code
```solidity
// [Show proper oracle usage]
```

### Detection Query
"Search for [specific oracle pattern]"

### Attack Scenario
1. [Step 1]
2. [Step 2]
3. [Step 3]
```

---

## Validation Query

```markdown
## Validation Test

### Test Case: Stale Price
```solidity
// Original vulnerable code
(, int256 price,,,) = priceFeed.latestRoundData();
return uint256(price);
```

### Expected Detection
- [ ] Flagged by: "Missing staleness check"
- [ ] Severity: MEDIUM/HIGH

### Test Case: L2 Sequencer
```solidity
// L2 code without sequencer check
```

### Expected Detection  
- [ ] Flagged by: "L2 sequencer uptime not checked"
- [ ] Trigger: "Arbitrum deployment"
```

---

## Example Gradient

### GRAD-002: L2 Sequencer Uptime Check Missing

**Miss Details:**
- Contract: PriceOracle.sol (deployed on Arbitrum)
- Function: `getLatestPrice()`
- Discovery: Sequencer outage caused stale prices, exploited

**Critique:**
The auditor verified Chainlink integration including staleness checks but did not add the L2-specific sequencer uptime check. When the Arbitrum sequencer went down and restarted, prices were stale but passed the staleness check because the round was "fresh" post-restart.

**Signal Present But Missed:**
```solidity
// On Arbitrum - should check sequencer feed
function getLatestPrice() external view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale");
    // [MISSING] Sequencer uptime check
    return uint256(price);
}
```

**Applied Edits:**
1. Added "L2 Sequencer Uptime" section to oracle patterns
2. Added trigger: "Arbitrum/Optimism → load l2-oracle.md"
3. Added checklist item for sequencer check
4. Added anti-pattern example

**Validation:**
Re-audited → detected at "L2 Specific" checklist section.

---

## Complete Oracle Checklist

After processing oracle-related gradients, ensure:

```markdown
## Master Oracle Checklist

### Source Validation
- [ ] Not using spot/reserve prices directly
- [ ] TWAP window >= 30 minutes
- [ ] Multiple oracle sources / fallback

### Chainlink Specific
- [ ] latestRoundData() used (not latestAnswer)
- [ ] updatedAt checked against threshold
- [ ] answeredInRound >= roundId verified
- [ ] Negative/zero price handled

### L2 Deployment
- [ ] Sequencer uptime feed checked
- [ ] Grace period after restart
- [ ] Sequencer feed address correct per chain

### Decimal Handling
- [ ] Oracle decimals() queried
- [ ] Proper normalization to 18 decimals
- [ ] Different token decimal handling

### Integration
- [ ] All price consumers identified
- [ ] Flash loan attack surface mapped
- [ ] Price update frequency sufficient
```

---

## Related Templates

- [Missed Reentrancy](missed-reentrancy.md)
- [Missed Access Control](missed-access-control.md)
- [Pattern Addition Template](../apply-edit-templates/pattern-addition.md)
