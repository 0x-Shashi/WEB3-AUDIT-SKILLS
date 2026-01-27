# Governance Protocol Security

## Quick Start

Governance protocols enable decentralized decision-making through voting mechanisms. They control critical protocol parameters and treasury funds, making them high-value targets for manipulation.

**Risk Level:** MEDIUM to HIGH  
**Common Attacks:** Flash loan voting, proposal manipulation, timelock bypasses  
**Key Considerations:** Vote weight, timelocks, quorum, execution

## Governance Types

| Type | Examples | Primary Risks |
|------|----------|---------------|
| Token Voting | Compound Gov | Flash loan attacks |
| veToken | Curve | Lock manipulation |
| NFT Voting | Nouns | Concentration |
| Delegation | Compound | Delegation exploits |
| Optimistic | Optimism | Challenge period |

## Most Critical Governance Vulnerabilities

### 1. Flash Loan Vote Manipulation
Borrow tokens to meet quorum or sway votes.

### 2. Proposal Frontrunning
Submit malicious proposals when governance tokens are accessible.

### 3. Timelock Bypass
Execute proposals without proper delay.

### 4. Quorum Manipulation
Artificially meet or prevent quorum.

### 5. Delegation Exploits
Abuse delegation mechanics.

## API Query: Governance Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Governance"}],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

## API Query: Flash Loan Governance

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "governance flash loan vote",
      "impact": ["HIGH"]
    }
  }'
```

## Security Considerations by Feature

### Vote Weight Calculation
```solidity
// VULNERABLE - Current balance (flash loanable)
function getVotes(address account) public view returns (uint256) {
    return token.balanceOf(account);  // Can flash loan tokens
}

// SECURE - Historical snapshot
function getVotes(address account, uint256 blockNumber) public view returns (uint256) {
    return token.getPastVotes(account, blockNumber);  // Uses checkpoint
}
```

### Proposal Creation
```solidity
// VULNERABLE - No restrictions
function propose(bytes calldata action) external returns (uint256) {
    proposals.push(Proposal({proposer: msg.sender, action: action}));
    return proposals.length - 1;
}

// SECURE - Threshold required
function propose(bytes calldata action) external returns (uint256) {
    require(
        getVotes(msg.sender, block.number - 1) >= proposalThreshold,
        "Below threshold"
    );
    // Add proposal
}
```

### Timelock Implementation
```solidity
// SECURE - Proper timelock
uint256 public constant DELAY = 2 days;

function queue(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(proposal.passed, "Not passed");
    require(proposal.eta == 0, "Already queued");
    
    proposal.eta = block.timestamp + DELAY;
}

function execute(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(proposal.eta > 0, "Not queued");
    require(block.timestamp >= proposal.eta, "Timelock not passed");
    require(block.timestamp <= proposal.eta + GRACE_PERIOD, "Expired");
    
    proposal.executed = true;
    (bool success,) = proposal.target.call(proposal.callData);
    require(success, "Execution failed");
}
```

### Delegation Security
```solidity
// SECURE - Track delegation
mapping(address => address) public delegates;
mapping(address => uint256) public nonces;

function delegate(address delegatee) external {
    _delegate(msg.sender, delegatee);
}

function delegateBySig(
    address delegatee,
    uint256 nonce,
    uint256 expiry,
    uint8 v,
    bytes32 r,
    bytes32 s
) external {
    require(block.timestamp <= expiry, "Expired");
    
    bytes32 structHash = keccak256(
        abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry)
    );
    bytes32 digest = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(digest, v, r, s);
    
    require(nonces[signer]++ == nonce, "Invalid nonce");
    _delegate(signer, delegatee);
}
```

## Common Vulnerable Patterns

### 1. Instant Voting Power
```solidity
// VULNERABLE - Vote with current balance
function vote(uint256 proposalId, bool support) external {
    uint256 weight = token.balanceOf(msg.sender);  // Flash loanable
    // ...
}

// SECURE - Use snapshot at proposal creation
function vote(uint256 proposalId, bool support) external {
    uint256 weight = token.getPastVotes(msg.sender, proposals[proposalId].snapshot);
    // ...
}
```

### 2. No Voting Delay
```solidity
// VULNERABLE - Can vote immediately after proposal
// Attacker can:
// 1. Buy tokens
// 2. Create proposal
// 3. Vote immediately
// 4. Sell tokens

// SECURE - Delay before voting starts
uint256 public constant VOTING_DELAY = 1 days;

function vote(uint256 proposalId) external {
    require(block.timestamp >= proposals[proposalId].startTime + VOTING_DELAY);
    // ...
}
```

### 3. Missing Quorum Check
```solidity
// VULNERABLE
function execute(uint256 proposalId) external {
    require(proposals[proposalId].forVotes > proposals[proposalId].againstVotes);
    // Executes even with 1 vote
}

// SECURE
function execute(uint256 proposalId) external {
    require(proposals[proposalId].forVotes > proposals[proposalId].againstVotes);
    require(proposals[proposalId].forVotes >= quorum, "Quorum not reached");
    // ...
}
```

### 4. Proposal Spam
```solidity
// VULNERABLE - No cost to create proposals
function propose() external {
    proposals.push(...);
}

// SECURE - Require stake or threshold
function propose() external {
    require(getVotes(msg.sender) >= proposalThreshold, "Below threshold");
    // Or require deposit that's returned on success/slashed on spam
}
```

## Governance Security Checklist

### Vote Weight
- [ ] Snapshot-based voting power
- [ ] Historical balance used
- [ ] Flash loan resistance
- [ ] Delegation properly tracked

### Proposals
- [ ] Proposal threshold
- [ ] Voting delay period
- [ ] Anti-spam mechanisms
- [ ] Proposal expiration

### Execution
- [ ] Timelock delay
- [ ] Grace period
- [ ] Reentrancy protection
- [ ] Failed execution handling

### Quorum & Thresholds
- [ ] Reasonable quorum
- [ ] Dynamic quorum if needed
- [ ] Minimum participation
- [ ] Majority requirements

### Emergency Handling
- [ ] Guardian/emergency role
- [ ] Proposal cancellation
- [ ] Pause mechanism
- [ ] Recovery procedures

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "Governance"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, tags: [.issues_issuetagscore[]?.tags_tag.title]}'
```

## Cross-Reference

- For flash loan attacks → See [../vulnerability-tags/flash-loan.md](../vulnerability-tags/flash-loan.md)
- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
- For front-running → See [../vulnerability-tags/front-running.md](../vulnerability-tags/front-running.md)
