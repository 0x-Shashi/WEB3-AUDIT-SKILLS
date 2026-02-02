# DeFi Insurance Protocol Attack Tree

> Comprehensive attack surface analysis for DeFi insurance protocols.
> Covers Nexus Mutual, InsurAce, Unslashed, Risk Harbor, and similar coverage platforms.

## Attack Tree Visualization

```
DeFi Insurance Protocol Attacks
├── [A] Cover/Policy Attacks
│   ├── [A.1] Cover Purchase Exploits
│   │   ├── [A.1.1] Front-Run Exploit with Cover [$$$]
│   │   ├── [A.1.2] Cover Stacking Attack
│   │   ├── [A.1.3] Underpriced Cover Arbitrage
│   │   └── [A.1.4] Cover Parameter Manipulation
│   ├── [A.2] Coverage Scope Attacks
│   │   ├── [A.2.1] Ambiguous Coverage Exploitation
│   │   ├── [A.2.2] Coverage Gap Discovery
│   │   └── [A.2.3] Multi-Protocol Claim Stacking
│   ├── [A.3] Cover Timing Attacks
│   │   ├── [A.3.1] Immediate Coverage Exploit
│   │   ├── [A.3.2] Expiry Timing Attack
│   │   └── [A.3.3] Grace Period Exploitation
│   └── [A.4] Cover Transfer Attacks
│       ├── [A.4.1] Sell Cover Before Claim
│       ├── [A.4.2] Cover NFT Manipulation
│       └── [A.4.3] Double-Claim via Transfer
│
├── [B] Claims Assessment Attacks
│   ├── [B.1] Fraudulent Claims
│   │   ├── [B.1.1] Fake Loss Fabrication [$$$]
│   │   ├── [B.1.2] Inflated Loss Claims
│   │   ├── [B.1.3] Self-Inflicted Exploit Claims
│   │   └── [B.1.4] Claim Evidence Manipulation
│   ├── [B.2] Assessment Process Gaming
│   │   ├── [B.2.1] Assessor Bribery/Collusion
│   │   ├── [B.2.2] Vote Buying for Claims
│   │   ├── [B.2.3] Assessment Deadline Gaming
│   │   └── [B.2.4] Appeal Process Abuse
│   ├── [B.3] Oracle/Trigger Attacks
│   │   ├── [B.3.1] Parametric Trigger Manipulation
│   │   ├── [B.3.2] Price Oracle Gaming for Claims
│   │   └── [B.3.3] Event Oracle Manipulation
│   └── [B.4] Claim Timing Exploits
│       ├── [B.4.1] Race to Claim (Pool Drain)
│       ├── [B.4.2] Delayed Claim Attack
│       └── [B.4.3] Claim Before Pool Recognizes Loss
│
├── [C] Capital Pool Attacks
│   ├── [C.1] Pool Drain Attacks
│   │   ├── [C.1.1] Coordinated Mass Claims [$$$]
│   │   ├── [C.1.2] Correlated Risk Exploitation
│   │   ├── [C.1.3] Black Swan Event Drain
│   │   └── [C.1.4] Reinsurance Failure Chain
│   ├── [C.2] Pool Investment Attacks
│   │   ├── [C.2.1] Investment Strategy Manipulation
│   │   ├── [C.2.2] Yield Farming Risk Injection
│   │   └── [C.2.3] Pool Collateral Devaluation
│   ├── [C.3] Liquidity Attacks
│   │   ├── [C.3.1] Capital Provider Exit Run
│   │   ├── [C.3.2] Withdrawal Queue Gaming
│   │   └── [C.3.3] Redemption Timing Attack
│   └── [C.4] Pool Accounting
│       ├── [C.4.1] Reserve Calculation Errors
│       ├── [C.4.2] Pending Claims Undercount
│       └── [C.4.3] Active Cover Misaccounting
│
├── [D] Staking/Underwriting Attacks
│   ├── [D.1] Risk Assessment Gaming
│   │   ├── [D.1.1] Stake on About-to-Exploit Protocol
│   │   ├── [D.1.2] Risk Score Manipulation
│   │   └── [D.1.3] Insider Staking Before Event
│   ├── [D.2] Staker Collusion
│   │   ├── [D.2.1] Coordinated Unstaking Before Claim
│   │   ├── [D.2.2] Staker-Claimant Collusion
│   │   └── [D.2.3] Risk Pool Manipulation
│   ├── [D.3] Reward Gaming
│   │   ├── [D.3.1] Stake Mining (Stake/Unstake)
│   │   ├── [D.3.2] Premium Sniping
│   │   └── [D.3.3] NXM/Token Price Manipulation
│   └── [D.4] Underwriting Capacity Attacks
│       ├── [D.4.1] Capacity Exhaustion Attack
│       ├── [D.4.2] Concentration Risk Creation
│       └── [D.4.3] Cover Limit Manipulation
│
├── [E] Governance Attacks
│   ├── [E.1] Voting Power Exploits
│   │   ├── [E.1.1] Flash Loan Governance Attack
│   │   ├── [E.1.2] Vote Delegation Manipulation
│   │   └── [E.1.3] Quorum Gaming
│   ├── [E.2] Parameter Manipulation
│   │   ├── [E.2.1] Risk Parameter Changes
│   │   ├── [E.2.2] Premium Pricing Manipulation
│   │   └── [E.2.3] Claim Threshold Changes
│   ├── [E.3] Member Attacks (Nexus Mutual)
│   │   ├── [E.3.1] KYC/Membership Fraud
│   │   ├── [E.3.2] Member Exclusion Attacks
│   │   └── [E.3.3] Advisory Board Capture
│   └── [E.4] Protocol Upgrade Attacks
│       ├── [E.4.1] Malicious Contract Upgrade
│       ├── [E.4.2] Coverage Definition Changes
│       └── [E.4.3] Retroactive Rule Changes
│
├── [F] Token Economics Attacks
│   ├── [F.1] Native Token Attacks
│   │   ├── [F.1.1] NXM/Token Price Manipulation [$$$]
│   │   ├── [F.1.2] Bonding Curve Exploits
│   │   └── [F.1.3] Token Mint/Burn Gaming
│   ├── [F.2] Premium Token Attacks
│   │   ├── [F.2.1] Premium Currency Manipulation
│   │   ├── [F.2.2] Payout Currency Arbitrage
│   │   └── [F.2.3] Multi-Token Accounting Errors
│   ├── [F.3] Incentive Misalignment
│   │   ├── [F.3.1] Reward Token Farming
│   │   ├── [F.3.2] Liquidity Mining Abuse
│   │   └── [F.3.3] Referral System Gaming
│   └── [F.4] Treasury Attacks
│       ├── [F.4.1] Treasury Fund Extraction
│       ├── [F.4.2] Investment Return Manipulation
│       └── [F.4.3] Fee Distribution Exploits
│
└── [G] Integration/External Attacks
    ├── [G.1] Covered Protocol Attacks
    │   ├── [G.1.1] Intentional Exploit for Payout
    │   ├── [G.1.2] Covered Protocol Rug Pull
    │   └── [G.1.3] Dependency Chain Exploitation
    ├── [G.2] Oracle Dependencies
    │   ├── [G.2.1] Price Feed Manipulation
    │   ├── [G.2.2] Event Oracle Compromise
    │   └── [G.2.3] TVL Oracle Gaming
    ├── [G.3] Cross-Protocol Risks
    │   ├── [G.3.1] Cascading Protocol Failures
    │   ├── [G.3.2] Shared Infrastructure Risks
    │   └── [G.3.3] Bridge/Cross-Chain Coverage Issues
    └── [G.4] Regulatory/Legal Attacks
        ├── [G.4.1] Regulatory Arbitrage
        ├── [G.4.2] Jurisdiction Shopping
        └── [G.4.3] Legal Challenge to Claims
```

---

## Branch [A]: Cover/Policy Attacks

### [A.1] Cover Purchase Exploits

#### [A.1.1] Front-Run Exploit with Cover

**Attack Vector:** Purchase coverage immediately before exploiting the covered protocol.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// Attack sequence:
// Block N: Attacker discovers vulnerability in Protocol X
// Block N: Attacker buys max cover for Protocol X
// Block N+1: Attacker exploits Protocol X for $10M
// Block N+2: Attacker claims $10M from insurance

// VULNERABLE: No waiting period
contract VulnerableCoverPurchase {
    function buyCover(
        address protocol,
        uint256 amount,
        uint256 period
    ) external payable {
        require(msg.value >= calculatePremium(protocol, amount, period));
        
        // Cover active immediately!
        covers[nextCoverId] = Cover({
            holder: msg.sender,
            protocol: protocol,
            amount: amount,
            startTime: block.timestamp,  // Active now
            endTime: block.timestamp + period
        });
        
        emit CoverPurchased(nextCoverId++, msg.sender, protocol, amount);
    }
}
```

**Real Exploits:**
- **Insurance Protocol (2021):** Attacker bought cover minutes before known exploit
- **Cover Protocol (2020):** Front-running vulnerability in cover purchase

**Mitigation:**
```solidity
// SECURE: Waiting period + cover cap + anomaly detection
contract SecureCoverPurchase {
    uint256 public constant WAITING_PERIOD = 3 days;
    uint256 public constant MAX_SINGLE_COVER = 100_000e18; // $100k
    
    mapping(address => uint256) public recentCoverPurchased;
    
    function buyCover(
        address protocol,
        uint256 amount,
        uint256 period
    ) external payable {
        require(amount <= MAX_SINGLE_COVER, "Cover too large");
        
        // Rate limiting per user
        require(
            recentCoverPurchased[msg.sender] + amount <= MAX_SINGLE_COVER,
            "Rate limit exceeded"
        );
        recentCoverPurchased[msg.sender] += amount;
        
        covers[nextCoverId] = Cover({
            holder: msg.sender,
            protocol: protocol,
            amount: amount,
            startTime: block.timestamp + WAITING_PERIOD,  // Delayed start
            endTime: block.timestamp + WAITING_PERIOD + period,
            status: CoverStatus.PENDING
        });
        
        emit CoverPurchased(nextCoverId++);
    }
    
    // Waiting period must pass before cover is active
    function activateCover(uint256 coverId) external {
        Cover storage cover = covers[coverId];
        require(
            block.timestamp >= cover.startTime,
            "Waiting period not passed"
        );
        require(cover.status == CoverStatus.PENDING, "Invalid status");
        
        // Check no exploit occurred during waiting period
        require(
            !hasRecentExploit(cover.protocol, cover.startTime),
            "Exploit during waiting period"
        );
        
        cover.status = CoverStatus.ACTIVE;
    }
}
```

---

#### [A.1.2] Cover Stacking Attack

**Attack Vector:** Purchase coverage from multiple insurance protocols for same risk.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```
Cover Stacking Attack:
1. Deposit 100 ETH in Protocol X
2. Buy cover from Nexus Mutual for 100 ETH
3. Buy cover from InsurAce for 100 ETH
4. Buy cover from Risk Harbor for 100 ETH
5. Protocol X exploited, attacker loses 100 ETH
6. Claim from all 3 insurers = 300 ETH payout
7. Net profit: 200 ETH - premiums

Issue: No cross-protocol coordination
Each insurer pays full amount
Attacker profits from exploit
```

**Mitigation:**
```solidity
// SECURE: Registry for cover coordination
contract CoverRegistry {
    // Track all covers per user per protocol
    mapping(address => mapping(address => uint256)) public totalCover;
    
    function registerCover(
        address user,
        address protocol,
        uint256 amount
    ) external onlyInsuranceProtocol {
        totalCover[user][protocol] += amount;
    }
    
    function validateClaim(
        address user,
        address protocol,
        uint256 claimAmount,
        uint256 actualLoss
    ) external view returns (bool) {
        // Total payout across all insurers cannot exceed actual loss
        uint256 totalCoverage = totalCover[user][protocol];
        
        // Pro-rata distribution if over-covered
        if (totalCoverage > actualLoss) {
            uint256 ratio = actualLoss * 1e18 / totalCoverage;
            return claimAmount <= (claimAmount * ratio / 1e18);
        }
        
        return claimAmount <= actualLoss;
    }
}
```

---

### [A.3] Cover Timing Attacks

#### [A.3.1] Immediate Coverage Exploit

**Attack Vector:** Exploit zero waiting period to profit from known vulnerabilities.

**Severity:** Critical | **Likelihood:** High | **Impact:** Critical

**Technical Details:**
```solidity
// VULNERABLE: No waiting period, immediate claims
contract VulnerableInsurance {
    function buyCover(bytes32 productId, uint256 amount) external payable {
        // Cover starts immediately
        activeCover[msg.sender][productId] = amount;
    }
    
    function submitClaim(bytes32 productId, uint256 amount) external {
        require(activeCover[msg.sender][productId] >= amount);
        
        // Can claim immediately after purchase
        pendingClaims.push(Claim({
            claimant: msg.sender,
            productId: productId,
            amount: amount
        }));
    }
}

// Attack:
// 1. News breaks of hack on Protocol X (not public yet)
// 2. Attacker buys max cover
// 3. Hack becomes public
// 4. Attacker claims immediately
// 5. Insurance pays out for pre-known event
```

**Mitigation:**
```solidity
// SECURE: Multiple time-based protections
contract SecureInsuranceTiming {
    uint256 public constant COVER_WAITING_PERIOD = 14 days;
    uint256 public constant CLAIM_WAITING_PERIOD = 7 days;
    uint256 public constant MIN_COVER_DURATION = 30 days;
    
    function buyCover(
        bytes32 productId,
        uint256 amount,
        uint256 duration
    ) external payable {
        require(duration >= MIN_COVER_DURATION, "Duration too short");
        
        Cover memory cover = Cover({
            buyer: msg.sender,
            productId: productId,
            amount: amount,
            purchaseTime: block.timestamp,
            activeFrom: block.timestamp + COVER_WAITING_PERIOD,
            expiresAt: block.timestamp + COVER_WAITING_PERIOD + duration
        });
        
        covers.push(cover);
    }
    
    function submitClaim(uint256 coverId, uint256 amount) external {
        Cover storage cover = covers[coverId];
        
        // Cover must be active (past waiting period)
        require(block.timestamp >= cover.activeFrom, "Cover not active");
        require(block.timestamp <= cover.expiresAt, "Cover expired");
        
        // Event must occur after cover activation
        uint256 eventTime = getEventTime(cover.productId);
        require(
            eventTime >= cover.activeFrom,
            "Event before cover active"
        );
        
        // Claim submission waiting period
        require(
            block.timestamp >= eventTime + CLAIM_WAITING_PERIOD,
            "Claim period not started"
        );
    }
}
```

---

## Branch [B]: Claims Assessment Attacks

### [B.1] Fraudulent Claims

#### [B.1.1] Fake Loss Fabrication

**Attack Vector:** Submit fraudulent claim for losses that never occurred.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// Fraudulent claim patterns:

// 1. Fake deposit proof
// - Create transaction showing deposit to protocol
// - Never actually deposited (simulated/failed tx)
// - Claim loss from "deposited" funds

// 2. Wash trading for history
// - Create fake transaction history
// - Build artificial deposit record
// - Claim imaginary losses

// 3. Sybil attack
// - Multiple accounts claim for same event
// - Each account shows partial "loss"
// - Total claims exceed actual pool losses

// VULNERABLE: Trust user-provided loss proof
contract VulnerableClaimVerification {
    function submitClaim(
        uint256 coverId,
        uint256 lossAmount,
        bytes memory lossProof  // User provides proof
    ) external {
        // Simple signature verification - easily faked
        require(verifyProof(lossProof), "Invalid proof");
        
        claims.push(Claim({
            coverId: coverId,
            amount: lossAmount,
            status: ClaimStatus.PENDING
        }));
    }
}
```

**Mitigation:**
```solidity
// SECURE: On-chain verification + assessor review
contract SecureClaimVerification {
    function submitClaim(
        uint256 coverId,
        uint256 lossAmount
    ) external {
        Cover storage cover = covers[coverId];
        require(cover.holder == msg.sender, "Not cover holder");
        
        // Verify user had actual exposure
        uint256 verifiedExposure = verifyOnChainExposure(
            msg.sender,
            cover.protocol,
            cover.activeFrom
        );
        require(verifiedExposure > 0, "No verified exposure");
        
        // Claim cannot exceed verified exposure or cover
        uint256 maxClaim = min(verifiedExposure, cover.amount);
        require(lossAmount <= maxClaim, "Claim exceeds exposure");
        
        // Verify protocol actually had incident
        require(
            hasVerifiedIncident(cover.protocol, cover.activeFrom, block.timestamp),
            "No verified incident"
        );
        
        claims.push(Claim({
            coverId: coverId,
            amount: lossAmount,
            verifiedExposure: verifiedExposure,
            status: ClaimStatus.PENDING_ASSESSMENT
        }));
    }
    
    function verifyOnChainExposure(
        address user,
        address protocol,
        uint256 timestamp
    ) internal view returns (uint256) {
        // Query actual deposits/positions from protocol
        // Use historical state if available
        return IProtocol(protocol).getUserDeposit(user, timestamp);
    }
}
```

---

#### [B.1.3] Self-Inflicted Exploit Claims

**Attack Vector:** Attacker exploits protocol then claims insurance for their "loss".

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// Attack scenario:
// 1. Attacker holds 1000 tokens in Protocol X
// 2. Attacker buys cover for 1000 tokens
// 3. Attacker exploits Protocol X (different account)
// 4. Attacker's 1000 tokens "lost" in exploit
// 5. Attacker claims 1000 tokens from insurance
// 6. Attacker keeps exploit proceeds + insurance payout

// VULNERABLE: No attacker exclusion
contract VulnerableAttackerExclusion {
    function processClaim(uint256 claimId) external onlyAssessor {
        Claim storage claim = claims[claimId];
        
        // No check if claimant was the attacker
        if (claim.verified) {
            payout(claim.claimant, claim.amount);
        }
    }
}
```

**Mitigation:**
```solidity
// SECURE: Attacker exclusion analysis
contract SecureAttackerExclusion {
    function processClaim(uint256 claimId) external onlyAssessor {
        Claim storage claim = claims[claimId];
        
        // Check claimant is not suspected attacker
        address attacker = getExploitAttacker(claim.protocol, claim.incidentId);
        
        require(
            !isRelatedAddress(claim.claimant, attacker),
            "Suspected attacker"
        );
        
        // Check claim timing relative to exploit knowledge
        require(
            claim.coverPurchaseTime < getExploitDiscoveryTime(claim.incidentId),
            "Cover purchased after exploit known"
        );
        
        // Additional forensic analysis by assessors
        require(
            !claim.flaggedForReview,
            "Under investigation"
        );
        
        if (claim.verified) {
            payout(claim.claimant, claim.amount);
        }
    }
    
    function isRelatedAddress(address a, address b) internal view returns (bool) {
        // Check on-chain relationships
        // - Same funding source
        // - Interacted with each other
        // - Common contract deployments
        return addressRelationshipOracle.areRelated(a, b);
    }
}
```

---

### [B.2] Assessment Process Gaming

#### [B.2.1] Assessor Bribery/Collusion

**Attack Vector:** Bribe or collude with assessors to approve fraudulent claims.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```
Bribery Attack:
1. Attacker identifies claim assessors
2. Offers assessors 10% of claim value
3. Assessors approve fraudulent claim
4. Attacker gets 90% fraudulent payout
5. Assessors get 10% bribe

Collusion variants:
- Assessor submits claim, other assessors approve
- Coordinated voting among assessor cartel
- Assessors stake on claims they'll approve
```

**Mitigation:**
```solidity
// SECURE: Randomized assessor selection + slashing
contract SecureAssessment {
    uint256 public constant ASSESSOR_STAKE = 10 ether;
    uint256 public constant MIN_ASSESSORS = 5;
    
    function selectAssessors(uint256 claimId) internal returns (address[] memory) {
        // Random selection from staked assessors
        uint256 seed = uint256(keccak256(abi.encodePacked(
            claimId,
            block.prevrandao,
            block.timestamp
        )));
        
        address[] memory selected = new address[](MIN_ASSESSORS);
        for (uint i = 0; i < MIN_ASSESSORS; i++) {
            selected[i] = assessors[(seed + i) % assessors.length];
        }
        
        return selected;
    }
    
    function submitAssessment(
        uint256 claimId,
        bool approve,
        string memory rationale
    ) external {
        require(isSelectedAssessor(claimId, msg.sender), "Not selected");
        require(!hasVoted[claimId][msg.sender], "Already voted");
        
        assessments[claimId].push(Assessment({
            assessor: msg.sender,
            approve: approve,
            rationale: rationale
        }));
        
        hasVoted[claimId][msg.sender] = true;
    }
    
    function finalizeClaim(uint256 claimId) external {
        Assessment[] storage votes = assessments[claimId];
        require(votes.length >= MIN_ASSESSORS, "Insufficient votes");
        
        uint256 approvals = 0;
        for (uint i = 0; i < votes.length; i++) {
            if (votes[i].approve) approvals++;
        }
        
        bool approved = approvals > votes.length / 2;
        
        // Slash minority voters (incentivize honest assessment)
        for (uint i = 0; i < votes.length; i++) {
            if (votes[i].approve != approved) {
                slashAssessor(votes[i].assessor, claimId);
            }
        }
    }
}
```

---

### [B.3] Oracle/Trigger Attacks

#### [B.3.1] Parametric Trigger Manipulation

**Attack Vector:** Manipulate on-chain data to trigger parametric insurance payout.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// Parametric insurance: Automatic payout when condition met
// e.g., "Pay out if ETH drops 50% in 24h"

// VULNERABLE: Manipulatable trigger condition
contract VulnerableParametricInsurance {
    IPriceOracle public oracle;
    
    function checkTrigger(uint256 coverId) external {
        Cover storage cover = covers[coverId];
        
        // Get current and past price
        uint256 currentPrice = oracle.getPrice("ETH");
        uint256 pastPrice = oracle.getHistoricalPrice("ETH", block.timestamp - 24 hours);
        
        // If price dropped 50%, trigger payout
        if (currentPrice < pastPrice / 2) {
            // VULNERABLE: Oracle can be manipulated
            payout(cover.holder, cover.amount);
        }
    }
}

// Attack:
// 1. Buy parametric cover for 50% price drop
// 2. Manipulate oracle to show fake 50% drop
// 3. Trigger automatic payout
// 4. No human assessment needed
```

**Mitigation:**
```solidity
// SECURE: Multiple oracles + delay + sanity checks
contract SecureParametricInsurance {
    IPriceOracle[] public oracles;
    uint256 public constant MIN_ORACLE_AGREEMENT = 3;
    uint256 public constant TRIGGER_DELAY = 1 hours;
    uint256 public constant MAX_SINGLE_PAYOUT = 1_000_000e18;
    
    mapping(uint256 => TriggerEvent) public pendingTriggers;
    
    function checkTrigger(uint256 coverId) external {
        Cover storage cover = covers[coverId];
        
        // Get prices from multiple oracles
        uint256 triggerCount = 0;
        for (uint i = 0; i < oracles.length; i++) {
            if (checkOracleTrigger(oracles[i], cover.triggerCondition)) {
                triggerCount++;
            }
        }
        
        // Require majority oracle agreement
        require(triggerCount >= MIN_ORACLE_AGREEMENT, "Insufficient agreement");
        
        // Create pending trigger (not instant payout)
        pendingTriggers[coverId] = TriggerEvent({
            timestamp: block.timestamp,
            verified: false
        });
    }
    
    function executeTrigger(uint256 coverId) external {
        TriggerEvent storage trigger = pendingTriggers[coverId];
        
        // Delay allows for investigation
        require(
            block.timestamp >= trigger.timestamp + TRIGGER_DELAY,
            "Delay not passed"
        );
        
        // Re-verify condition still holds
        require(verifyConditionStillMet(coverId), "Condition no longer met");
        
        // Cap payout
        uint256 payoutAmount = min(covers[coverId].amount, MAX_SINGLE_PAYOUT);
        payout(covers[coverId].holder, payoutAmount);
    }
}
```

---

## Branch [C]: Capital Pool Attacks

### [C.1] Pool Drain Attacks

#### [C.1.1] Coordinated Mass Claims

**Attack Vector:** Multiple attackers coordinate to drain insurance pool simultaneously.

**Severity:** Critical | **Likelihood:** Low | **Impact:** Critical

**Technical Details:**
```
Coordinated Attack:
1. Insurance pool has $100M capacity
2. Pool insures 50 different protocols
3. Attackers buy max cover across all protocols
4. Attackers coordinate exploits on multiple protocols
5. All claims submitted simultaneously
6. Pool cannot pay all claims
7. First claimants drain pool
8. Later claimants receive nothing

Risk factors:
- Correlated risks (all use same oracle)
- Shared infrastructure (same bridge)
- Systemic events (chain halt)
```

**Mitigation:**
```solidity
// SECURE: Risk correlation management + claim queuing
contract SecurePoolManagement {
    uint256 public constant MAX_CORRELATED_EXPOSURE = 20; // 20% max
    uint256 public constant CLAIM_PROCESSING_WINDOW = 7 days;
    
    mapping(bytes32 => uint256) public riskCategoryExposure;
    
    function buyCover(
        address protocol,
        uint256 amount
    ) external payable {
        bytes32 riskCategory = getRiskCategory(protocol);
        
        // Check correlation limits
        uint256 categoryExposure = riskCategoryExposure[riskCategory] + amount;
        uint256 maxExposure = totalPoolCapital * MAX_CORRELATED_EXPOSURE / 100;
        require(categoryExposure <= maxExposure, "Risk category limit");
        
        riskCategoryExposure[riskCategory] = categoryExposure;
        
        // ... create cover
    }
    
    function processClaimQueue() external {
        // Process claims in order, up to available capital
        uint256 availableCapital = getAvailableCapital();
        
        for (uint i = 0; i < claimQueue.length; i++) {
            Claim storage claim = claims[claimQueue[i]];
            
            if (claim.amount <= availableCapital) {
                payout(claim);
                availableCapital -= claim.amount;
            } else {
                // Partial payout or wait for capital
                claim.status = ClaimStatus.PENDING_CAPITAL;
            }
        }
    }
    
    function getRiskCategory(address protocol) internal view returns (bytes32) {
        // Categorize protocols by shared risk factors
        // Same oracle, same chain, same audit firm, etc.
        return riskOracle.getCategory(protocol);
    }
}
```

---

### [C.2] Pool Investment Attacks

#### [C.2.1] Investment Strategy Manipulation

**Attack Vector:** Manipulate pool investments to create correlated risk or extract value.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```solidity
// VULNERABLE: Pool invests in same protocols it insures
contract VulnerablePoolInvestment {
    function investPoolFunds(address protocol, uint256 amount) external onlyManager {
        // Pool invests in Protocol X for yield
        IYieldProtocol(protocol).deposit(amount);
        
        // Problem: Pool also insures Protocol X
        // If Protocol X is exploited:
        // 1. Pool loses investment
        // 2. Pool must pay claims
        // 3. Double whammy = insolvency
    }
}

// Manipulation attack:
// 1. Attacker is pool investment manager
// 2. Invests pool in risky protocols
// 3. Buys cover for those protocols
// 4. Protocols fail/exploited
// 5. Claims exceed remaining pool
```

**Mitigation:**
```solidity
// SECURE: Investment restrictions + separation
contract SecurePoolInvestment {
    mapping(address => bool) public coveredProtocols;
    uint256 public constant MAX_SINGLE_INVESTMENT = 5; // 5% max per protocol
    
    function investPoolFunds(
        address protocol,
        uint256 amount
    ) external onlyManager {
        // Cannot invest in covered protocols
        require(!coveredProtocols[protocol], "Covered protocol");
        
        // Concentration limit
        uint256 currentInvestment = investments[protocol];
        uint256 maxInvestment = totalPoolCapital * MAX_SINGLE_INVESTMENT / 100;
        require(currentInvestment + amount <= maxInvestment, "Concentration limit");
        
        // Risk assessment
        require(
            riskOracle.getProtocolRisk(protocol) <= MAX_INVESTMENT_RISK,
            "Risk too high"
        );
        
        investments[protocol] += amount;
        IYieldProtocol(protocol).deposit(amount);
    }
    
    // Automatically flag if invested protocol becomes covered
    function onCoverCreated(address protocol) internal {
        if (investments[protocol] > 0) {
            // Trigger divestment process
            flagForDivestment(protocol);
        }
        coveredProtocols[protocol] = true;
    }
}
```

---

### [C.3] Liquidity Attacks

#### [C.3.1] Capital Provider Exit Run

**Attack Vector:** Large capital providers exit before major claims deplete pool.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```solidity
// VULNERABLE: Instant withdrawals allowed
contract VulnerableLiquidity {
    function withdraw(uint256 shares) external {
        uint256 amount = shares * poolBalance / totalShares;
        
        // Instant withdrawal - no delay
        totalShares -= shares;
        poolBalance -= amount;
        
        token.transfer(msg.sender, amount);
    }
}

// Attack scenario:
// 1. Major exploit news leaks (not public yet)
// 2. Insiders/large LPs rush to withdraw
// 3. Pool depleted before claims processed
// 4. Remaining LPs and claimants get nothing
```

**Mitigation:**
```solidity
// SECURE: Withdrawal queues + lockups
contract SecureLiquidity {
    uint256 public constant WITHDRAWAL_DELAY = 30 days;
    uint256 public constant MIN_LOCKUP = 90 days;
    
    struct WithdrawalRequest {
        uint256 shares;
        uint256 requestTime;
        bool processed;
    }
    
    mapping(address => WithdrawalRequest) public withdrawalRequests;
    mapping(address => uint256) public depositTime;
    
    function deposit(uint256 amount) external {
        // ... mint shares
        depositTime[msg.sender] = block.timestamp;
    }
    
    function requestWithdrawal(uint256 shares) external {
        require(
            block.timestamp >= depositTime[msg.sender] + MIN_LOCKUP,
            "Lockup period"
        );
        
        require(
            withdrawalRequests[msg.sender].shares == 0,
            "Pending request exists"
        );
        
        withdrawalRequests[msg.sender] = WithdrawalRequest({
            shares: shares,
            requestTime: block.timestamp,
            processed: false
        });
    }
    
    function processWithdrawal() external {
        WithdrawalRequest storage request = withdrawalRequests[msg.sender];
        
        require(request.shares > 0, "No request");
        require(
            block.timestamp >= request.requestTime + WITHDRAWAL_DELAY,
            "Delay not passed"
        );
        require(!request.processed, "Already processed");
        
        // Check pending claims don't exceed remaining capital
        uint256 pendingClaimValue = getTotalPendingClaims();
        uint256 postWithdrawalCapital = poolBalance - withdrawAmount;
        require(
            postWithdrawalCapital >= pendingClaimValue * 150 / 100,
            "Insufficient buffer"
        );
        
        request.processed = true;
        // ... process withdrawal
    }
}
```

---

## Branch [D]: Staking/Underwriting Attacks

### [D.1] Risk Assessment Gaming

#### [D.1.1] Stake on About-to-Exploit Protocol

**Attack Vector:** Stake on protocol before exploiting it to profit from own attack.

**Severity:** Critical | **Likelihood:** Low | **Impact:** Critical

**Technical Details:**
```solidity
// Nexus Mutual style staking:
// Stakers earn premium share but get slashed on claims

// VULNERABLE: Can unstake before claim
contract VulnerableStaking {
    function stake(address protocol, uint256 amount) external {
        stakes[msg.sender][protocol] += amount;
    }
    
    function unstake(address protocol, uint256 amount) external {
        // Instant unstake!
        stakes[msg.sender][protocol] -= amount;
        token.transfer(msg.sender, amount);
    }
    
    // Attack:
    // 1. Attacker stakes on Protocol X
    // 2. Collects premiums for months
    // 3. Plans exploit of Protocol X
    // 4. Unstakes day before exploit
    // 5. Exploits Protocol X
    // 6. No slashing - already unstaked!
}
```

**Mitigation:**
```solidity
// SECURE: Unstaking delay + burn on incident
contract SecureStaking {
    uint256 public constant UNSTAKE_DELAY = 90 days;
    
    struct UnstakeRequest {
        uint256 amount;
        uint256 requestTime;
    }
    
    mapping(address => mapping(address => UnstakeRequest)) public unstakeRequests;
    
    function requestUnstake(address protocol, uint256 amount) external {
        require(stakes[msg.sender][protocol] >= amount, "Insufficient stake");
        
        unstakeRequests[msg.sender][protocol] = UnstakeRequest({
            amount: amount,
            requestTime: block.timestamp
        });
        
        // Stake still at risk during delay period
    }
    
    function processUnstake(address protocol) external {
        UnstakeRequest storage request = unstakeRequests[msg.sender][protocol];
        
        require(
            block.timestamp >= request.requestTime + UNSTAKE_DELAY,
            "Delay not passed"
        );
        
        // Check no incidents during delay period
        require(
            !hasIncidentDuringPeriod(protocol, request.requestTime, block.timestamp),
            "Incident during unstake period"
        );
        
        stakes[msg.sender][protocol] -= request.amount;
        delete unstakeRequests[msg.sender][protocol];
        
        token.transfer(msg.sender, request.amount);
    }
    
    // On incident, slash all stakers (including those with pending unstake)
    function onIncident(address protocol) internal {
        uint256 totalStake = getTotalStake(protocol);
        uint256 claimAmount = getTotalClaims(protocol);
        
        uint256 slashRatio = min(claimAmount * 1e18 / totalStake, 1e18);
        
        // Slash including pending unstakes
        for (address staker : stakersOf[protocol]) {
            uint256 toSlash = stakes[staker][protocol] * slashRatio / 1e18;
            stakes[staker][protocol] -= toSlash;
        }
    }
}
```

---

## Branch [E]: Governance Attacks

### [E.1] Voting Power Exploits

#### [E.1.1] Flash Loan Governance Attack

**Attack Vector:** Borrow tokens to manipulate insurance protocol governance.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// VULNERABLE: Snapshot at vote time
contract VulnerableGovernance {
    function vote(uint256 proposalId, bool support) external {
        uint256 votingPower = token.balanceOf(msg.sender);
        
        // Flash loan tokens = instant voting power
        votes[proposalId][support] += votingPower;
    }
}

// Attack on insurance protocol:
// 1. Flash loan governance tokens
// 2. Vote to approve fraudulent claim
// 3. Vote to drain treasury
// 4. Vote to change coverage terms
// 5. Return flash loan
// Result: Governance manipulation without token ownership
```

**Mitigation:**
```solidity
// SECURE: Checkpointed voting + timelock
contract SecureGovernance {
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];
        
        // Use voting power from snapshot (before proposal)
        uint256 votingPower = token.getPastVotes(
            msg.sender,
            proposal.snapshotBlock
        );
        
        require(votingPower > 0, "No voting power at snapshot");
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        
        hasVoted[proposalId][msg.sender] = true;
        votes[proposalId][support] += votingPower;
    }
    
    function createProposal(bytes memory data) external returns (uint256) {
        // Proposer must have held tokens for minimum period
        require(
            token.getPastVotes(msg.sender, block.number - MIN_HOLDING_PERIOD) 
                >= proposalThreshold,
            "Insufficient holding history"
        );
        
        return _createProposal(data, block.number - 1); // Snapshot is past block
    }
}
```

---

## Branch [F]: Token Economics Attacks

### [F.1] Native Token Attacks

#### [F.1.1] NXM/Token Price Manipulation

**Attack Vector:** Manipulate insurance token price to profit or harm protocol.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```solidity
// Nexus Mutual NXM token has bonding curve:
// Price = f(Capital Pool, Minimum Capital Requirement)

// VULNERABLE: Manipulatable through capital flows
contract VulnerableBondingCurve {
    function getTokenPrice() public view returns (uint256) {
        uint256 capitalPool = address(this).balance;
        uint256 mcr = calculateMCR();
        
        // Price depends on capital ratio
        uint256 ratio = capitalPool * 100 / mcr;
        return calculatePriceFromRatio(ratio);
    }
    
    function buyNXM() external payable {
        uint256 price = getTokenPrice();
        uint256 tokens = msg.value * 1e18 / price;
        _mint(msg.sender, tokens);
    }
}

// Attack:
// 1. Large ETH deposit → raises MCR ratio → token price up
// 2. Attacker buys tokens before deposit
// 3. After price increase, attacker sells
// 4. Or: Trigger claims → capital down → price down → buy cheap
```

**Mitigation:**
```solidity
// SECURE: TWAP pricing + buy/sell limits
contract SecureBondingCurve {
    uint256 public constant PRICE_SMOOTHING_PERIOD = 24 hours;
    uint256 public constant MAX_PRICE_CHANGE = 10; // 10% max daily
    
    function getSmoothedPrice() public view returns (uint256) {
        uint256 spotPrice = calculateSpotPrice();
        uint256 twap = getTWAP(PRICE_SMOOTHING_PERIOD);
        
        // Use lower of spot and TWAP for buys
        // Use higher of spot and TWAP for sells
        return twap;
    }
    
    function buyNXM() external payable {
        uint256 price = getSmoothedPrice();
        
        // Rate limiting
        require(
            dailyVolume + msg.value <= maxDailyVolume,
            "Daily limit exceeded"
        );
        
        // Price change limit
        uint256 priceImpact = calculatePriceImpact(msg.value);
        require(priceImpact <= MAX_PRICE_CHANGE, "Price impact too high");
        
        dailyVolume += msg.value;
        
        uint256 tokens = msg.value * 1e18 / price;
        _mint(msg.sender, tokens);
    }
}
```

---

## Protocol-Specific Attack Patterns

### Nexus Mutual

| Attack | Vector | Mitigation |
|--------|--------|------------|
| NXM Price Manipulation | Capital pool changes | Bonding curve smoothing |
| Staker Collusion | Unstake before exploit | 90-day unstake period |
| Claim Voting Gaming | Vote buying | Random assessor selection |
| KYC Bypass | Fake identities | Multi-factor verification |

### InsurAce

| Attack | Vector | Mitigation |
|--------|--------|------------|
| Premium Pool Gaming | Stake manipulation | Minimum stake period |
| Cover Capacity Drain | Concentrated buying | Per-protocol limits |
| Cross-Chain Claims | Bridge verification | Multi-oracle verification |

### Risk Harbor

| Attack | Vector | Mitigation |
|--------|--------|------------|
| Parametric Trigger Gaming | Oracle manipulation | Multiple oracle consensus |
| LP Drain | Mass redemptions | Withdrawal queues |
| Protection Writer Collusion | Writer-claimer coordination | Randomized matching |

### Unslashed

| Attack | Vector | Mitigation |
|--------|--------|------------|
| USF Token Manipulation | Governance attacks | Timelock + multisig |
| Capital Pool Underwriting | Risk concentration | Diversification rules |
| Claim Arbitration Gaming | Arbitrator bribery | Stake + slash arbitrators |

---

## Audit Checklist

### Cover/Policy Security
- [ ] Is there waiting period before cover activates?
- [ ] Is cover stacking across protocols prevented?
- [ ] Are cover amounts capped per user/protocol?
- [ ] Is cover purchase rate-limited?
- [ ] Can cover be transferred to evade restrictions?

### Claims Assessment
- [ ] Is there on-chain loss verification?
- [ ] Are assessors randomly selected?
- [ ] Can assessors be bribed/collude?
- [ ] Is there appeal process?
- [ ] Are attackers excluded from claims?

### Capital Pool Security
- [ ] Is risk correlation managed?
- [ ] Are pool investments separated from covered protocols?
- [ ] Is there withdrawal delay/queue?
- [ ] Can pool handle mass claims?
- [ ] Is there reinsurance/backstop?

### Staking/Underwriting
- [ ] Is there unstaking delay?
- [ ] Can stakers front-run incidents?
- [ ] Are rewards manipulation-resistant?
- [ ] Is stake slash enforceable?

### Governance
- [ ] Is flash loan governance prevented?
- [ ] Are there timelocks on critical changes?
- [ ] Is voting power checkpointed?
- [ ] Can governance change claim rules retroactively?

### Token Economics
- [ ] Is token price manipulation-resistant?
- [ ] Are bonding curves stable?
- [ ] Is treasury extraction prevented?
- [ ] Are incentives aligned?

---

## References

- [Nexus Mutual Documentation](https://docs.nexusmutual.io/)
- [InsurAce Protocol](https://docs.insurace.io/)
- [Risk Harbor](https://docs.riskharbor.com/)
- [Cover Protocol Post-Mortem](https://coverprotocol.medium.com/)
- [DeFi Insurance: State of the Market](https://defillama.com/protocols/Insurance)

---

## Related Documents

- [governance-patterns.md](../patterns/governance-patterns.md)
- [staking-patterns.md](../patterns/staking-patterns.md)
- [oracle-patterns.md](../patterns/oracle-patterns.md)
- [token-anti-patterns.md](../anti-patterns/token-anti-patterns.md)
