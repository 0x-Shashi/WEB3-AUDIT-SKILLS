# Apply Edit Template: Pattern Addition

## Purpose
Template for adding new vulnerability patterns, detection techniques, and secure code examples to pattern files.

---

## When to Use

Use this template when:
- A new vulnerability pattern is discovered
- An existing pattern has a new variant
- Detection techniques need improvement
- Secure code examples need to be added
- Cross-references between patterns need updating

---

## Pattern Structure Standard

Every pattern should follow this structure:

```markdown
## [Pattern Name]

### Overview
[1-2 sentence description]

### Vulnerable Code
```solidity
// [VULNERABLE] - Clearly marked
[code example]
```

### Why It's Vulnerable
[Explanation of the vulnerability]

### Secure Code
```solidity
// [SAFE] - Clearly marked
[fixed code example]
```

### Detection Query
[How to find this in a codebase]

### Severity
[Typical severity and impact]

### Related Patterns
- [Link to related pattern 1]
- [Link to related pattern 2]
```

---

## Addition Process

### Step 1: Identify Target File

```markdown
**Target Pattern File:** [e.g., patterns/reentrancy-patterns.md]
**Section:** [Existing section or new section needed]
**Pattern Type:** [Vulnerability/Detection/Secure Implementation]
```

### Step 2: Draft Pattern Content

```markdown
## [Pattern Name]

### Overview
[Description]

### Vulnerable Code
```solidity
[code]
```

### Why It's Vulnerable
[Explanation]

### Secure Code
```solidity
[code]
```

### Detection Query
[Search methodology]

### Severity
[Rating and rationale]
```

### Step 3: Add Cross-References

```markdown
**Links TO this pattern from:**
- [ ] checklists/comprehensive-checklist.md
- [ ] anti-patterns/[relevant].md
- [ ] Other relevant files

**Links FROM this pattern to:**
- [ ] Related vulnerability patterns
- [ ] Exploit forensics (if real-world example)
- [ ] Fix patterns
```

### Step 4: Update Index

```markdown
**INDEX.md Update:**
Add under appropriate category:
- [Pattern Name](patterns/[file].md#pattern-name)
```

---

## Pattern Examples by Category

### Reentrancy Pattern Addition
```markdown
## Read-Only Reentrancy

### Overview
View functions can return inconsistent state when called during another transaction's external call, allowing price manipulation in integrated protocols.

### Vulnerable Code
```solidity
// [VULNERABLE] - View function reads manipulable state
function convertToAssets(uint256 shares) public view returns (uint256) {
    uint256 supply = totalSupply();
    return supply == 0 ? shares : shares.mulDivDown(totalAssets(), supply);
}

// Attacker exploits via integrated protocol:
function attack() external {
    vault.withdraw(amount);  // During callback:
    // Another protocol reads vault.convertToAssets() - gets wrong value
}
```

### Why It's Vulnerable
During `withdraw()`, the vault makes an external call (ETH transfer). At this point, `totalSupply` has been reduced but `totalAssets` hasn't. Any external protocol calling `convertToAssets()` gets an inflated share price.

### Secure Code
```solidity
// [SAFE] - Use reentrancy lock for view functions OR
// Document that view functions are not safe during reentrant calls

// Option 1: Reentrancy protection
bool private _locked;
modifier noReentrantView() {
    require(!_locked, "Reentrant");
    _;
}

function convertToAssets(uint256 shares) public view noReentrantView returns (uint256) {
    // ...
}

// Option 2: CEI in all state-changing functions
function withdraw(uint256 assets) external nonReentrant {
    // Update ALL state first
    _burn(msg.sender, shares);
    // Then external call
    asset.transfer(msg.sender, assets);
}
```

### Detection Query
1. Find ERC4626 vaults or similar share-based systems
2. Identify view functions that read state
3. Check if external protocols integrate these view functions
4. Trace reentrancy windows in state-changing functions

### Severity
HIGH - Can lead to significant fund loss in integrated protocols

### Related Patterns
- [Classic Reentrancy](#classic-reentrancy)
- [Cross-Contract Reentrancy](#cross-contract-reentrancy)
- [ERC4626 Patterns](vault-patterns.md)
```

### Oracle Pattern Addition
```markdown
## L2 Sequencer Uptime Check

### Overview
On L2s (Arbitrum, Optimism), Chainlink prices can be stale after sequencer downtime without triggering standard staleness checks.

### Vulnerable Code
```solidity
// [VULNERABLE] - Missing sequencer check on L2
function getPrice() external view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
    return uint256(price);
}
```

### Why It's Vulnerable
When the L2 sequencer goes down, no new price updates are submitted. When it comes back up, the first update appears "fresh" (new `updatedAt`) even though it may reflect pre-outage prices. Attackers can exploit the grace period.

### Secure Code
```solidity
// [SAFE] - With sequencer uptime check
function getPrice() external view returns (uint256) {
    // Check sequencer status first
    (, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
    bool isSequencerUp = answer == 0;
    require(isSequencerUp, "Sequencer down");
    
    // Add grace period after restart
    uint256 timeSinceUp = block.timestamp - startedAt;
    require(timeSinceUp > GRACE_PERIOD, "Grace period not passed");
    
    // Then check price freshness
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
    return uint256(price);
}
```

### Detection Query
1. Identify L2 deployment (Arbitrum, Optimism, Base)
2. Find Chainlink price feed usage
3. Check for sequencer uptime feed integration
4. Verify grace period implementation

### Severity
HIGH - Can allow liquidations/trades at stale prices

### Related Patterns
- [Chainlink Staleness Check](#chainlink-staleness)
- [Oracle Fallback Pattern](#oracle-fallback)
```

### Access Control Pattern Addition
```markdown
## Unprotected Initializer

### Overview
Upgradeable contracts using `initialize()` instead of constructors must protect against re-initialization.

### Vulnerable Code
```solidity
// [VULNERABLE] - Can be called multiple times
function initialize(address _owner) external {
    owner = _owner;
}
```

### Why It's Vulnerable
Anyone can call `initialize()` after deployment, potentially resetting the owner or other critical state. Even if called legitimately first, an attacker can call again later.

### Secure Code
```solidity
// [SAFE] - Using OpenZeppelin's Initializable
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyContract is Initializable {
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
```

### Detection Query
1. Find contracts with `initialize` functions
2. Check if using proxy pattern
3. Verify `initializer` modifier present
4. Check implementation contract initialization (for UUPS)

### Severity
CRITICAL - Complete contract takeover possible

### Related Patterns
- [Proxy Upgrade Safety](proxy-patterns.md)
- [Access Control Modifiers](#access-modifiers)
```

---

## Anti-Pattern Integration

When adding a pattern, also add corresponding anti-pattern:

```markdown
## Anti-Pattern Addition

**Target File:** anti-patterns/[category]-anti-patterns.md

### Anti-Pattern: [Name]

[VULNERABLE]
```solidity
// Bad code
```

[SAFE]
```solidity
// Fixed code
```

**Why it's dangerous:** [Brief explanation]
**Detection:** [How to spot]
**Fix:** [How to remediate]
```

---

## Trigger Integration

If pattern should auto-load based on code signals:

```markdown
## TRIGGERS.md Addition

| Trigger Condition | Pattern Files to Load |
|-------------------|----------------------|
| [Code signal] | [pattern-file.md] |
```

---

## Validation Checklist

Before finalizing pattern addition:

- [ ] Vulnerable code is clearly marked `[VULNERABLE]`
- [ ] Safe code is clearly marked `[SAFE]`
- [ ] Explanation is clear and accurate
- [ ] Detection query is actionable
- [ ] Severity is appropriate
- [ ] Related patterns are linked
- [ ] Cross-references added to other files
- [ ] Anti-pattern added if applicable
- [ ] Trigger added if applicable
- [ ] INDEX.md updated

---

## Edit Commands

### Adding Pattern to File
```yaml
file: patterns/[category]-patterns.md
action: insert_after
marker: "## [Previous Pattern]"
content: |
  ## [New Pattern Name]
  
  ### Overview
  [content...]
```

### Updating INDEX.md
```yaml
file: INDEX.md
action: insert_after
marker: "### [Category]"
content: |
  - [New Pattern Name](patterns/[file].md#new-pattern-name)
```

### Adding Trigger
```yaml
file: TRIGGERS.md
action: insert_after
marker: "| [Last trigger] |"
content: |
  | [New trigger] | [files-to-load.md] |
```

---

## Template for Submission

```markdown
## Pattern Addition Request

**Source:** [Gradient ID or discovery reference]
**Target File:** [patterns/category-patterns.md]
**Section:** [New or existing section]

### Pattern Content
```markdown
## [Pattern Name]
[Full pattern following structure]
```

### Cross-References
- [ ] Checklist item added: [path]
- [ ] Anti-pattern added: [path]
- [ ] Trigger added: [yes/no]
- [ ] INDEX.md updated: [yes/no]

### Validation
- [ ] Tested vulnerable code compiles
- [ ] Safe code actually fixes the issue
- [ ] Detection query finds real examples
```

---

## Related Templates

- [Checklist Expansion](checklist-expansion.md)
- [Feedback Loop](../FEEDBACK_LOOP.md)
- [Gradient Templates](../gradient-templates/)
