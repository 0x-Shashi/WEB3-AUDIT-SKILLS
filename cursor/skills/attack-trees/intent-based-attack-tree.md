# Intent-Based Protocol Attack Tree

> Comprehensive attack surface analysis for intent-based DEXs, solvers, and order flow systems.
> Covers CoW Protocol, UniswapX, 1inch Fusion, Across+, and similar intent-centric architectures.

## Attack Tree Visualization

```
Intent-Based Protocol Attacks
├── [A] Solver/Filler Attacks
│   ├── [A.1] Malicious Solver Behavior
│   │   ├── [A.1.1] Sandwich User Intents [$$$]
│   │   ├── [A.1.2] Intent Front-Running
│   │   ├── [A.1.3] Partial Fill Exploitation
│   │   └── [A.1.4] Quote Manipulation
│   ├── [A.2] Solver Collusion
│   │   ├── [A.2.1] Solver Cartel Formation
│   │   ├── [A.2.2] MEV Extraction Ring
│   │   └── [A.2.3] Exclusive Order Flow Deals
│   ├── [A.3] Solver Competition Attacks
│   │   ├── [A.3.1] DoS Competing Solvers
│   │   ├── [A.3.2] Solver Score Manipulation
│   │   └── [A.3.3] Sybil Solver Network
│   └── [A.4] Solver Insolvency
│       ├── [A.4.1] Under-Collateralized Solver
│       ├── [A.4.2] Solver Bankruptcy Mid-Settlement
│       └── [A.4.3] Bond Slashing Evasion
│
├── [B] Intent Signature Attacks
│   ├── [B.1] Signature Replay
│   │   ├── [B.1.1] Cross-Chain Replay [$$$]
│   │   ├── [B.1.2] Same-Chain Duplicate Execution
│   │   └── [B.1.3] Fork Replay Attack
│   ├── [B.2] Signature Malleability
│   │   ├── [B.2.1] ECDSA s-Value Flip
│   │   ├── [B.2.2] EIP-712 Domain Separator Issues
│   │   └── [B.2.3] Compact Signature Decoding
│   ├── [B.3] Intent Modification
│   │   ├── [B.3.1] Partial Intent Extraction
│   │   ├── [B.3.2] Intent Parameter Tampering
│   │   └── [B.3.3] Deadline Extension Abuse
│   └── [B.4] Authorization Attacks
│       ├── [B.4.1] Permit2 Allowance Drain
│       ├── [B.4.2] Gasless Approval Abuse
│       └── [B.4.3] Signature Phishing
│
├── [C] Order/Intent Validation Attacks
│   ├── [C.1] Price Validation Failures
│   │   ├── [C.1.1] Stale Price Execution [$$$]
│   │   ├── [C.1.2] Oracle Manipulation Pre-Fill
│   │   └── [C.1.3] Price Impact Ignorance
│   ├── [C.2] Slippage Attacks
│   │   ├── [C.2.1] Missing Slippage Bounds
│   │   ├── [C.2.2] Dynamic Slippage Exploitation
│   │   └── [C.2.3] Multi-Hop Slippage Accumulation
│   ├── [C.3] Fill Validation Issues
│   │   ├── [C.3.1] Partial Fill Griefing
│   │   ├── [C.3.2] Dust Fill Attacks
│   │   └── [C.3.3] Fill Order Manipulation
│   └── [C.4] Intent Expiry Attacks
│       ├── [C.4.1] Last-Block Exploitation
│       ├── [C.4.2] Deadline Sniping
│       └── [C.4.3] Auction End Gaming
│
├── [D] Settlement Layer Attacks
│   ├── [D.1] Settlement Contract Exploits
│   │   ├── [D.1.1] Reentrancy in Settlement [$$$]
│   │   ├── [D.1.2] Settlement Callback Manipulation
│   │   └── [D.1.3] Flash Loan + Settlement
│   ├── [D.2] Batch Settlement Issues
│   │   ├── [D.2.1] Batch Ordering Manipulation
│   │   ├── [D.2.2] Cross-Intent MEV Extraction
│   │   └── [D.2.3] Batch Atomicity Failures
│   ├── [D.3] Token Transfer Attacks
│   │   ├── [D.3.1] Fee-on-Transfer Token Issues
│   │   ├── [D.3.2] Rebasing Token Settlement
│   │   └── [D.3.3] Token Blacklist Mid-Settlement
│   └── [D.4] Surplus Extraction
│       ├── [D.4.1] Solver Keeps Surplus
│       ├── [D.4.2] Surplus Calculation Errors
│       └── [D.4.3] Negative Surplus Exploitation
│
├── [E] Auction Mechanism Attacks
│   ├── [E.1] Dutch Auction Exploits
│   │   ├── [E.1.1] Last-Second Fill (UniswapX)
│   │   ├── [E.1.2] Price Decay Exploitation
│   │   └── [E.1.3] Auction Start Manipulation
│   ├── [E.2] Batch Auction Exploits
│   │   ├── [E.2.1] Uniform Clearing Price Gaming (CoW)
│   │   ├── [E.2.2] Solution Quality Manipulation
│   │   └── [E.2.3] Batch Inclusion Bribery
│   ├── [E.3] RFQ Attacks
│   │   ├── [E.3.1] Quote Staling
│   │   ├── [E.3.2] Market Maker Front-Running
│   │   └── [E.3.3] RFQ Response Manipulation
│   └── [E.4] Auction Timing
│       ├── [E.4.1] Block Timestamp Manipulation
│       ├── [E.4.2] Auction Window Gaming
│       └── [E.4.3] Cross-Block Arbitrage
│
├── [F] Cross-Chain Intent Attacks
│   ├── [F.1] Message Verification
│   │   ├── [F.1.1] Missing Source Chain Validation [$$$]
│   │   ├── [F.1.2] Relayer Collusion
│   │   └── [F.1.3] Optimistic Verification Gaming
│   ├── [F.2] Settlement Asymmetry
│   │   ├── [F.2.1] Source Settled, Dest Fails
│   │   ├── [F.2.2] Double-Spend Across Chains
│   │   └── [F.2.3] Reorg Exploitation
│   ├── [F.3] Liquidity Attacks
│   │   ├── [F.3.1] LP Drain via Intent Spam
│   │   ├── [F.3.2] Inventory Imbalance Exploitation
│   │   └── [F.3.3] Fast Lane Liquidity Attacks
│   └── [F.4] Fee Arbitrage
│       ├── [F.4.1] Gas Price Manipulation
│       ├── [F.4.2] Relay Fee Extraction
│       └── [F.4.3] Cross-Chain Fee Asymmetry
│
└── [G] Protocol Governance/Economic Attacks
    ├── [G.1] Tokenomics Attacks
    │   ├── [G.1.1] Solver Token Manipulation
    │   ├── [G.1.2] Fee Distribution Exploits
    │   └── [G.1.3] Staking Reward Gaming
    ├── [G.2] Protocol Parameters
    │   ├── [G.2.1] Malicious Parameter Updates
    │   ├── [G.2.2] Fee Tier Manipulation
    │   └── [G.2.3] Solver Whitelist Attacks
    ├── [G.3] Upgrade Attacks
    │   ├── [G.3.1] Settlement Contract Upgrade Exploits
    │   ├── [G.3.2] Intent Schema Migration Issues
    │   └── [G.3.3] Backward Compatibility Exploits
    └── [G.4] Censorship
        ├── [G.4.1] Solver Censorship
        ├── [G.4.2] Intent Blacklisting
        └── [G.4.3] Geographic Restrictions Bypass
```

---

## Branch [A]: Solver/Filler Attacks

### [A.1] Malicious Solver Behavior

#### [A.1.1] Sandwich User Intents

**Attack Vector:** Solver executes trades before and after user intent to extract value.

**Severity:** Critical | **Likelihood:** High | **Impact:** High

**Technical Details:**
```solidity
// VULNERABLE: Solver can see intent and sandwich
contract VulnerableSolver {
    function solve(Intent[] memory intents) external {
        // Solver sees all intents in batch
        // Can front-run by trading first on other venues
        for (uint i = 0; i < intents.length; i++) {
            executeIntent(intents[i]);
        }
    }
}

// Attack Flow:
// 1. Solver receives intent: Buy 100 ETH for USDC
// 2. Solver buys ETH on Uniswap (price increases)
// 3. Solver fills user intent at higher price
// 4. Solver sells ETH on Uniswap (profit)
```

**Real Exploits:**
- **CoW Protocol Solver Issues (2023):** Certain solvers extracted MEV from users
- **Intent Protocol X (2024):** Malicious solver sandwiched $2M in user orders

**Detection Methods:**
- [ ] Intent-level MEV analysis
- [ ] Solver execution path monitoring
- [ ] Cross-venue price comparison
- [ ] Surplus tracking per solver

**Mitigation:**
```solidity
// SECURE: Batch auction with uniform clearing price
contract SecureBatchAuction {
    function solveBatch(
        Intent[] memory intents,
        Solution memory solution
    ) external onlyApprovedSolver {
        // Uniform clearing price prevents sandwiching
        uint256 clearingPrice = solution.clearingPrice;
        
        // All intents execute at same price
        for (uint i = 0; i < intents.length; i++) {
            require(
                validateExecution(intents[i], clearingPrice),
                "Below limit price"
            );
        }
        
        // Track solver quality score
        updateSolverScore(msg.sender, solution.quality);
    }
}
```

---

#### [A.1.2] Intent Front-Running

**Attack Vector:** Solver or observer executes trade ahead of intent based on leaked information.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```solidity
// Intent lifecycle vulnerability:
// 1. User signs intent (off-chain)
// 2. Intent submitted to mempool/API ← Leak point
// 3. Solver/attacker sees intent
// 4. Attacker front-runs on external venue
// 5. User gets worse execution

// VULNERABLE: Public intent submission
contract VulnerableIntentPool {
    event IntentSubmitted(
        address user,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut  // Reveals intent details
    );
    
    function submitIntent(Intent memory intent) external {
        emit IntentSubmitted(...);  // MEV searchers monitor
        pendingIntents.push(intent);
    }
}
```

**Detection Methods:**
- [ ] Intent submission privacy analysis
- [ ] MEV extraction monitoring
- [ ] Execution quality metrics
- [ ] Time-to-fill analysis

**Mitigation:**
```solidity
// SECURE: Encrypted intent submission + commit-reveal
contract PrivateIntentPool {
    mapping(bytes32 => CommittedIntent) public commits;
    
    function commitIntent(bytes32 intentHash) external {
        commits[intentHash] = CommittedIntent({
            user: msg.sender,
            timestamp: block.timestamp,
            revealed: false
        });
    }
    
    function revealAndFill(
        Intent memory intent,
        bytes memory solverSolution
    ) external onlyApprovedSolver {
        bytes32 hash = hashIntent(intent);
        require(commits[hash].user != address(0), "Not committed");
        require(!commits[hash].revealed, "Already revealed");
        
        // Time-lock prevents front-running
        require(
            block.timestamp >= commits[hash].timestamp + MIN_DELAY,
            "Too early"
        );
        
        commits[hash].revealed = true;
        executeFill(intent, solverSolution);
    }
}
```

---

#### [A.1.3] Partial Fill Exploitation

**Attack Vector:** Solver partially fills intent to extract value or grief user.

**Severity:** Medium | **Likelihood:** Medium | **Impact:** Medium

**Technical Details:**
```solidity
// VULNERABLE: No minimum fill enforcement
contract VulnerablePartialFill {
    function fillIntent(
        Intent memory intent,
        uint256 fillAmount
    ) external onlySolver {
        require(fillAmount <= intent.amountIn, "Overfill");
        
        // No minimum fill size - allows dust fills
        executePartialFill(intent, fillAmount);
        
        // Attacker fills 0.1% repeatedly to grief
        // Or fills favorable portion, leaves unfavorable
    }
}

// Attack: Cherry-picking
// Intent: Swap 1000 USDC for ETH at market
// Market moves against user
// Solver fills only 10 USDC (when favorable)
// Leaves 990 USDC unfilled (when unfavorable)
```

**Mitigation:**
```solidity
// SECURE: Minimum fill + all-or-nothing option
contract SecurePartialFill {
    uint256 public constant MIN_FILL_RATIO = 1000; // 10%
    
    function fillIntent(
        Intent memory intent,
        uint256 fillAmount
    ) external onlySolver {
        if (intent.fillType == FillType.PARTIAL) {
            // Minimum fill enforcement
            uint256 minFill = intent.amountIn * MIN_FILL_RATIO / 10000;
            require(
                fillAmount >= minFill || fillAmount == remainingAmount(intent),
                "Fill too small"
            );
        } else {
            // All-or-nothing
            require(fillAmount == intent.amountIn, "Must fill completely");
        }
        
        executePartialFill(intent, fillAmount);
    }
}
```

---

### [A.2] Solver Collusion

#### [A.2.1] Solver Cartel Formation

**Attack Vector:** Solvers coordinate to reduce competition and extract more value from users.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```
Cartel Attack Pattern:
1. Top 3 solvers control 80% of order flow
2. Solvers agree to not compete on certain intents
3. Users receive worse execution (higher spread)
4. Cartel splits excess profit

Economic Impact:
- Competitive spread: 0.05%
- Cartel spread: 0.15%
- $1B monthly volume = $1M/month extracted
```

**Detection Methods:**
- [ ] Solver diversity metrics
- [ ] Execution quality variance analysis
- [ ] Bid pattern correlation detection
- [ ] Market share concentration (HHI index)

**Mitigation:**
```solidity
// SECURE: Force solver competition
contract AntiCollusionMeasures {
    uint256 public constant MAX_SOLVER_SHARE = 3000; // 30%
    uint256 public constant MIN_SOLVER_COUNT = 5;
    
    mapping(address => SolverStats) public solverStats;
    
    function validateSolverDiversity() internal view {
        uint256 activeSolvers = getActiveSolverCount();
        require(activeSolvers >= MIN_SOLVER_COUNT, "Insufficient competition");
        
        for (uint i = 0; i < solvers.length; i++) {
            uint256 share = solverStats[solvers[i]].volumeShare;
            require(share <= MAX_SOLVER_SHARE, "Solver too dominant");
        }
    }
    
    // Random solver selection for certain batches
    function selectRandomSolver(bytes32 intentHash) internal view returns (address) {
        uint256 random = uint256(keccak256(abi.encodePacked(
            intentHash,
            block.prevrandao
        )));
        return solvers[random % solvers.length];
    }
}
```

---

### [A.3] Solver Competition Attacks

#### [A.3.1] DoS Competing Solvers

**Attack Vector:** Malicious solver disrupts competitors to win more order flow.

**Severity:** Medium | **Likelihood:** Medium | **Impact:** Medium

**Technical Details:**
```solidity
// Attack vectors against competing solvers:

// 1. Block stuffing during auction
// Malicious solver fills blocks to prevent competitor submissions

// 2. API DoS
// Flood competitor's quote API with requests

// 3. Solution invalidation
// Submit transactions that make competitor's solution invalid
// (e.g., drain liquidity they planned to use)

contract CompetitorSabotage {
    function sabotageCompetitor(
        address competitorLiquiditySource,
        uint256 amount
    ) external {
        // Front-run to drain liquidity competitor needs
        IPool(competitorLiquiditySource).swap(amount);
        
        // Competitor's solution now fails
        // Malicious solver's solution wins by default
    }
}
```

**Mitigation:**
```solidity
// SECURE: Multiple solution acceptance + fallback
contract ResilientAuction {
    struct AuctionRound {
        Solution[] validSolutions;
        uint256 deadline;
    }
    
    function submitSolution(
        bytes32 batchId,
        Solution memory solution
    ) external onlySolver {
        AuctionRound storage round = rounds[batchId];
        
        // Accept multiple valid solutions
        if (validateSolution(solution)) {
            round.validSolutions.push(solution);
        }
    }
    
    function settleBatch(bytes32 batchId) external {
        AuctionRound storage round = rounds[batchId];
        require(block.timestamp >= round.deadline, "Auction ongoing");
        
        // Select best solution, fallback to others if execution fails
        Solution memory best = selectBestSolution(round.validSolutions);
        
        try this.executeSolution(best) {
            // Success
        } catch {
            // Fallback to next best
            executeFallbackSolution(round.validSolutions);
        }
    }
}
```

---

## Branch [B]: Intent Signature Attacks

### [B.1] Signature Replay

#### [B.1.1] Cross-Chain Replay

**Attack Vector:** Intent signed for one chain is replayed on another chain.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// VULNERABLE: No chain ID in signature
contract VulnerableIntent {
    struct Intent {
        address user;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 deadline;
        uint256 nonce;
        // Missing: chainId
    }
    
    function executeIntent(
        Intent memory intent,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(intent));
        address signer = ECDSA.recover(hash, signature);
        require(signer == intent.user, "Invalid signature");
        
        // Same signature valid on all chains!
        // Attacker replays on chain with better rates
    }
}

// Attack scenario:
// 1. User signs intent on Ethereum: Swap 100 USDC for ETH
// 2. Attacker replays on Arbitrum where same tokens exist
// 3. User's tokens drained on Arbitrum
```

**Real Exploits:**
- **Wintermute Signature Replay (2022):** Cross-chain signature vulnerability
- **Multiple Intent Protocols (2023-2024):** Missing chain ID in EIP-712 domain

**Mitigation:**
```solidity
// SECURE: EIP-712 with chain-specific domain separator
contract SecureIntent {
    bytes32 public immutable DOMAIN_SEPARATOR;
    
    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "Intent(address user,address tokenIn,address tokenOut,uint256 amountIn,uint256 minAmountOut,uint256 deadline,uint256 nonce)"
    );
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("IntentProtocol"),
            keccak256("1"),
            block.chainid,  // Chain-specific
            address(this)   // Contract-specific
        ));
    }
    
    function executeIntent(
        Intent memory intent,
        bytes memory signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            INTENT_TYPEHASH,
            intent.user,
            intent.tokenIn,
            intent.tokenOut,
            intent.amountIn,
            intent.minAmountOut,
            intent.deadline,
            intent.nonce
        ));
        
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            structHash
        ));
        
        address signer = ECDSA.recover(digest, signature);
        require(signer == intent.user, "Invalid signature");
        
        // Mark nonce as used
        require(!usedNonces[intent.user][intent.nonce], "Nonce used");
        usedNonces[intent.user][intent.nonce] = true;
    }
}
```

---

#### [B.1.2] Same-Chain Duplicate Execution

**Attack Vector:** Same intent executed multiple times on same chain.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// VULNERABLE: No nonce tracking
contract VulnerableNonce {
    function executeIntent(
        Intent memory intent,
        bytes memory signature
    ) external {
        require(block.timestamp < intent.deadline, "Expired");
        require(verifySignature(intent, signature), "Invalid sig");
        
        // No nonce check - can replay until deadline
        transferFrom(intent.user, intent.tokenIn, intent.amountIn);
        transfer(intent.user, intent.tokenOut, calculateOutput());
    }
}

// Attack:
// 1. User signs intent with 1 hour deadline
// 2. Solver executes intent
// 3. Attacker replays same intent multiple times
// 4. User's tokens drained repeatedly
```

**Mitigation:**
```solidity
// SECURE: Bitmap nonce for gas efficiency
contract SecureNonce {
    // Bitmap: nonces[user][wordIndex] contains 256 nonces
    mapping(address => mapping(uint256 => uint256)) public nonces;
    
    function executeIntent(
        Intent memory intent,
        bytes memory signature
    ) external {
        require(block.timestamp < intent.deadline, "Expired");
        require(verifySignature(intent, signature), "Invalid sig");
        
        // Check and set nonce atomically
        uint256 wordIndex = intent.nonce / 256;
        uint256 bitIndex = intent.nonce % 256;
        uint256 bit = 1 << bitIndex;
        
        uint256 word = nonces[intent.user][wordIndex];
        require(word & bit == 0, "Nonce already used");
        nonces[intent.user][wordIndex] = word | bit;
        
        // Execute
        executeTransfer(intent);
    }
    
    function invalidateNonces(uint256 wordIndex) external {
        // User can invalidate 256 nonces at once
        nonces[msg.sender][wordIndex] = type(uint256).max;
    }
}
```

---

### [B.4] Authorization Attacks

#### [B.4.1] Permit2 Allowance Drain

**Attack Vector:** Exploit Permit2 signature to drain more than intended.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// Permit2 allows gasless approvals, but introduces risks:

// VULNERABLE: Unlimited Permit2 allowance
contract VulnerablePermit2Usage {
    IPermit2 public immutable PERMIT2;
    
    function executeWithPermit(
        Intent memory intent,
        IPermit2.PermitSingle memory permit,
        bytes memory permitSignature
    ) external {
        // User signs permit with MAX_UINT256 amount
        // Trusting this contract forever
        PERMIT2.permit(intent.user, permit, permitSignature);
        
        // Malicious upgrade or bug = all tokens drainable
        PERMIT2.transferFrom(
            intent.user,
            address(this),
            intent.amountIn,
            intent.tokenIn
        );
    }
}

// Attack flow:
// 1. User signs Permit2 with high/unlimited allowance
// 2. Protocol is exploited or upgraded maliciously
// 3. Attacker drains all approved tokens
```

**Real Exploits:**
- **Socket Bridge Permit2 Exploit (2024):** $3.3M drained via Permit2 approvals

**Mitigation:**
```solidity
// SECURE: Exact amount permits + expiration
contract SecurePermit2Usage {
    IPermit2 public immutable PERMIT2;
    
    function executeWithPermit(
        Intent memory intent,
        IPermit2.PermitSingle memory permit,
        bytes memory permitSignature
    ) external {
        // Validate permit matches intent exactly
        require(permit.details.amount == intent.amountIn, "Amount mismatch");
        require(permit.details.token == intent.tokenIn, "Token mismatch");
        require(
            permit.details.expiration <= block.timestamp + 1 hours,
            "Expiration too long"
        );
        
        // Use permit
        PERMIT2.permit(intent.user, permit, permitSignature);
        
        // Transfer exact amount only
        PERMIT2.transferFrom(
            intent.user,
            address(this),
            intent.amountIn,  // Exact, not permit.amount
            intent.tokenIn
        );
    }
}

// User-side: Sign permit for exact trade amount with short expiry
```

---

## Branch [C]: Order/Intent Validation Attacks

### [C.1] Price Validation Failures

#### [C.1.1] Stale Price Execution

**Attack Vector:** Intent executed using outdated price data.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```solidity
// VULNERABLE: No price freshness check
contract VulnerablePriceValidation {
    function validateFill(
        Intent memory intent,
        uint256 fillPrice
    ) internal view returns (bool) {
        // User's limit price might be based on old market
        return fillPrice >= intent.minAmountOut;
        
        // If market moved 10% against user since signing,
        // solver still fills at user's stale limit
        // User loses 10%
    }
}

// Attack scenario:
// 1. User signs intent at 2000 USDC/ETH market price
// 2. Sets minAmountOut based on 1% slippage = 1980 USDC
// 3. Market moves to 2200 USDC/ETH
// 4. Solver fills at 1980 (user's limit), pockets 220 USDC
```

**Mitigation:**
```solidity
// SECURE: On-chain price reference + maximum deviation
contract SecurePriceValidation {
    IPriceOracle public oracle;
    uint256 public constant MAX_DEVIATION = 200; // 2%
    
    function validateFill(
        Intent memory intent,
        uint256 fillAmountOut
    ) internal view returns (bool) {
        // Get current market price
        uint256 currentPrice = oracle.getPrice(
            intent.tokenIn,
            intent.tokenOut
        );
        
        // Calculate fair output
        uint256 fairOutput = intent.amountIn * currentPrice / 1e18;
        
        // User must receive at least their limit
        require(fillAmountOut >= intent.minAmountOut, "Below limit");
        
        // But also close to current market
        uint256 minFairOutput = fairOutput * (10000 - MAX_DEVIATION) / 10000;
        require(fillAmountOut >= minFairOutput, "Too far from market");
        
        return true;
    }
}
```

---

### [C.3] Fill Validation Issues

#### [C.3.1] Partial Fill Griefing

**Attack Vector:** Attacker repeatedly partial fills to grief user with gas costs.

**Severity:** Low | **Likelihood:** Medium | **Impact:** Low

**Technical Details:**
```solidity
// VULNERABLE: Any partial fill allowed
contract VulnerablePartialFill {
    mapping(bytes32 => uint256) public filledAmounts;
    
    function partialFill(
        Intent memory intent,
        uint256 fillAmount
    ) external onlySolver {
        bytes32 intentHash = hashIntent(intent);
        uint256 remaining = intent.amountIn - filledAmounts[intentHash];
        require(fillAmount <= remaining, "Overfill");
        
        // Attacker fills 1 wei at a time
        // User pays gas for each fill event
        // Eventually cancels intent, wasting gas
        
        filledAmounts[intentHash] += fillAmount;
        executeFill(intent, fillAmount);
    }
}
```

**Mitigation:**
```solidity
// SECURE: Minimum fill size + user gas rebate
contract SecurePartialFill {
    uint256 public constant MIN_FILL_BPS = 500; // 5% minimum
    
    function partialFill(
        Intent memory intent,
        uint256 fillAmount
    ) external onlySolver {
        bytes32 intentHash = hashIntent(intent);
        uint256 remaining = intent.amountIn - filledAmounts[intentHash];
        
        uint256 minFill = intent.amountIn * MIN_FILL_BPS / 10000;
        
        // Must fill at least minimum OR complete the remaining
        require(
            fillAmount >= minFill || fillAmount == remaining,
            "Fill too small"
        );
        
        filledAmounts[intentHash] += fillAmount;
        executeFill(intent, fillAmount);
    }
}
```

---

## Branch [D]: Settlement Layer Attacks

### [D.1] Settlement Contract Exploits

#### [D.1.1] Reentrancy in Settlement

**Attack Vector:** Reenter settlement during callback to extract additional value.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// VULNERABLE: State update after external call
contract VulnerableSettlement {
    mapping(bytes32 => IntentState) public intentStates;
    
    function settle(
        Intent memory intent,
        address solver,
        bytes memory fillData
    ) external {
        bytes32 hash = hashIntent(intent);
        require(intentStates[hash] == IntentState.PENDING, "Invalid state");
        
        // Transfer tokens to solver
        IERC20(intent.tokenIn).transferFrom(
            intent.user,
            solver,
            intent.amountIn
        );
        
        // Solver fills (external call)
        ISolver(solver).fill(intent, fillData);
        
        // State update AFTER external call
        intentStates[hash] = IntentState.FILLED;  // TOO LATE
        
        // Malicious solver reenters and settles again
    }
}
```

**Mitigation:**
```solidity
// SECURE: CEI pattern + reentrancy guard
contract SecureSettlement is ReentrancyGuard {
    mapping(bytes32 => IntentState) public intentStates;
    
    function settle(
        Intent memory intent,
        address solver,
        bytes memory fillData
    ) external nonReentrant {
        bytes32 hash = hashIntent(intent);
        require(intentStates[hash] == IntentState.PENDING, "Invalid state");
        
        // State update FIRST (Checks-Effects-Interactions)
        intentStates[hash] = IntentState.FILLING;
        
        // Transfer tokens
        IERC20(intent.tokenIn).safeTransferFrom(
            intent.user,
            solver,
            intent.amountIn
        );
        
        // Solver fills
        ISolver(solver).fill(intent, fillData);
        
        // Final state
        intentStates[hash] = IntentState.FILLED;
    }
}
```

---

### [D.4] Surplus Extraction

#### [D.4.1] Solver Keeps Surplus

**Attack Vector:** Solver keeps price improvement instead of returning to user.

**Severity:** Medium | **Likelihood:** High | **Impact:** Medium

**Technical Details:**
```solidity
// VULNERABLE: No surplus return mechanism
contract VulnerableSurplus {
    function settle(
        Intent memory intent,
        uint256 actualOutput
    ) external onlySolver {
        require(actualOutput >= intent.minAmountOut, "Below limit");
        
        // User asked for min 1000 USDC
        // Solver got 1050 USDC from market
        // Solver returns 1000 USDC to user
        // Solver pockets 50 USDC surplus
        
        IERC20(intent.tokenOut).transfer(intent.user, intent.minAmountOut);
        // Surplus stays with solver
    }
}
```

**Mitigation:**
```solidity
// SECURE: Surplus sharing or full return
contract SecureSurplus {
    uint256 public constant PROTOCOL_SURPLUS_BPS = 1000; // 10% to protocol
    uint256 public constant SOLVER_SURPLUS_BPS = 4000;   // 40% to solver
    // Remaining 50% to user
    
    function settle(
        Intent memory intent,
        uint256 actualOutput
    ) external onlySolver {
        require(actualOutput >= intent.minAmountOut, "Below limit");
        
        uint256 surplus = actualOutput - intent.minAmountOut;
        
        if (surplus > 0) {
            uint256 protocolShare = surplus * PROTOCOL_SURPLUS_BPS / 10000;
            uint256 solverShare = surplus * SOLVER_SURPLUS_BPS / 10000;
            uint256 userShare = surplus - protocolShare - solverShare;
            
            IERC20(intent.tokenOut).transfer(treasury, protocolShare);
            IERC20(intent.tokenOut).transfer(msg.sender, solverShare);
            IERC20(intent.tokenOut).transfer(
                intent.user, 
                intent.minAmountOut + userShare
            );
        } else {
            IERC20(intent.tokenOut).transfer(intent.user, actualOutput);
        }
    }
}
```

---

## Branch [E]: Auction Mechanism Attacks

### [E.1] Dutch Auction Exploits

#### [E.1.1] Last-Second Fill (UniswapX Style)

**Attack Vector:** Wait until auction price decays to maximum then fill.

**Severity:** Medium | **Likelihood:** High | **Impact:** Medium

**Technical Details:**
```solidity
// UniswapX Dutch Auction mechanism:
// Price starts high, decays to user's limit over time

// VULNERABLE: Predictable decay exploited
contract VulnerableDutchAuction {
    function calculateOutput(
        DutchIntent memory intent,
        uint256 currentTime
    ) public view returns (uint256) {
        uint256 elapsed = currentTime - intent.startTime;
        uint256 duration = intent.endTime - intent.startTime;
        
        // Linear decay from startOutput to minOutput
        uint256 decay = (intent.startOutput - intent.minOutput) 
            * elapsed / duration;
        
        return intent.startOutput - decay;
    }
    
    // Solver strategy: Wait until output = minOutput
    // User gets worst possible price every time
    // No solver competition if all wait for floor
}
```

**Mitigation:**
```solidity
// SECURE: Non-linear decay + exclusivity period
contract SecureDutchAuction {
    function calculateOutput(
        DutchIntent memory intent,
        uint256 currentTime
    ) public view returns (uint256) {
        uint256 elapsed = currentTime - intent.startTime;
        uint256 duration = intent.endTime - intent.startTime;
        
        // Exponential decay incentivizes earlier fills
        // y = start * e^(-k*t) + min
        uint256 decayFactor = expDecay(elapsed, duration);
        uint256 range = intent.startOutput - intent.minOutput;
        
        return intent.minOutput + (range * decayFactor / 1e18);
    }
    
    function fill(
        DutchIntent memory intent,
        bytes memory signature
    ) external {
        // Exclusivity period - only designated filler
        if (block.timestamp < intent.exclusivityEnd) {
            require(
                msg.sender == intent.exclusiveFiller,
                "Exclusivity period"
            );
        }
        
        uint256 output = calculateOutput(intent, block.timestamp);
        executeFill(intent, output);
    }
}
```

---

### [E.2] Batch Auction Exploits

#### [E.2.1] Uniform Clearing Price Gaming (CoW Protocol Style)

**Attack Vector:** Manipulate batch composition to shift clearing price.

**Severity:** Medium | **Likelihood:** Medium | **Impact:** Medium

**Technical Details:**
```
CoW Protocol Batch Auction:
- All orders in batch settle at uniform clearing price
- Solver finds price that maximizes surplus

Attack:
1. Observe pending batch with 10 buy orders for ETH
2. Submit large sell order with aggressive limit
3. Shift clearing price in attacker's favor
4. Cancel or don't submit if unfavorable

Defense bypass:
- Orders are private until batch deadline
- But solver can inject their own orders
```

**Detection Methods:**
- [ ] Solver self-trading detection
- [ ] Last-minute order injection analysis
- [ ] Clearing price deviation monitoring
- [ ] Batch composition correlation

**Mitigation:**
```solidity
// SECURE: Solver cannot include own orders
contract SecureBatchAuction {
    mapping(address => bool) public solvers;
    
    function submitBatchSolution(
        bytes32 batchId,
        Order[] memory orders,
        uint256 clearingPrice
    ) external onlySolver {
        for (uint i = 0; i < orders.length; i++) {
            // Solver cannot fill their own orders
            require(orders[i].maker != msg.sender, "Self-trade");
            
            // Orders must be pre-committed
            require(
                committedOrders[batchId][hashOrder(orders[i])],
                "Order not in batch"
            );
        }
        
        validateAndExecute(orders, clearingPrice);
    }
}
```

---

## Branch [F]: Cross-Chain Intent Attacks

### [F.1] Message Verification

#### [F.1.1] Missing Source Chain Validation

**Attack Vector:** Forge intent fulfillment without actual source chain execution.

**Severity:** Critical | **Likelihood:** Medium | **Impact:** Critical

**Technical Details:**
```solidity
// VULNERABLE: Trust relayer without verification
contract VulnerableCrossChainIntent {
    mapping(address => bool) public relayers;
    
    function fulfillCrossChainIntent(
        CrossChainIntent memory intent,
        bytes memory relayerAttestation
    ) external {
        // Only checks relayer signature
        address relayer = recoverSigner(
            hashIntent(intent), 
            relayerAttestation
        );
        require(relayers[relayer], "Invalid relayer");
        
        // No verification that source chain locked tokens!
        // Malicious relayer attests without source execution
        
        mintOrTransfer(intent.user, intent.tokenOut, intent.amountOut);
    }
}
```

**Mitigation:**
```solidity
// SECURE: Verify source chain state
contract SecureCrossChainIntent {
    IMessageBridge public bridge;
    
    function fulfillCrossChainIntent(
        CrossChainIntent memory intent,
        bytes memory bridgeProof
    ) external {
        // Verify source chain lock via bridge
        bytes32 messageHash = keccak256(abi.encode(
            intent.sourceChain,
            intent.user,
            intent.tokenIn,
            intent.amountIn,
            intent.nonce
        ));
        
        require(
            bridge.verifyMessage(
                intent.sourceChain,
                messageHash,
                bridgeProof
            ),
            "Source not verified"
        );
        
        // Verify not already fulfilled
        require(!fulfilled[messageHash], "Already fulfilled");
        fulfilled[messageHash] = true;
        
        // Safe to fulfill
        transferToUser(intent);
    }
}
```

---

### [F.2] Settlement Asymmetry

#### [F.2.1] Source Settled, Destination Fails

**Attack Vector:** Lock funds on source chain but fail to deliver on destination.

**Severity:** High | **Likelihood:** Medium | **Impact:** High

**Technical Details:**
```solidity
// Cross-chain intent flow:
// Source Chain: User locks 1000 USDC
// Destination Chain: Solver should deliver 1 ETH

// VULNERABLE: No recourse if destination fails
contract VulnerableSourceLock {
    function lockForCrossChain(
        CrossChainIntent memory intent
    ) external {
        IERC20(intent.tokenIn).transferFrom(
            msg.sender,
            address(this),
            intent.amountIn
        );
        
        lockedIntents[hashIntent(intent)] = true;
        emit IntentLocked(intent);
        
        // If destination chain execution fails:
        // - User's funds stuck
        // - No automatic refund
        // - Solver might have extracted value elsewhere
    }
}
```

**Mitigation:**
```solidity
// SECURE: Timeout-based refund mechanism
contract SecureCrossChainLock {
    uint256 public constant LOCK_TIMEOUT = 24 hours;
    
    struct LockedIntent {
        uint256 amount;
        uint256 lockTime;
        bool fulfilled;
        bool refunded;
    }
    
    mapping(bytes32 => LockedIntent) public locks;
    
    function lockForCrossChain(
        CrossChainIntent memory intent
    ) external {
        bytes32 hash = hashIntent(intent);
        
        IERC20(intent.tokenIn).transferFrom(
            msg.sender,
            address(this),
            intent.amountIn
        );
        
        locks[hash] = LockedIntent({
            amount: intent.amountIn,
            lockTime: block.timestamp,
            fulfilled: false,
            refunded: false
        });
    }
    
    function confirmFulfillment(
        bytes32 intentHash,
        bytes memory fulfillmentProof
    ) external {
        require(
            bridge.verifyFulfillment(intentHash, fulfillmentProof),
            "Invalid proof"
        );
        locks[intentHash].fulfilled = true;
        // Release to solver
    }
    
    function refundTimedOut(bytes32 intentHash) external {
        LockedIntent storage lock = locks[intentHash];
        require(!lock.fulfilled, "Already fulfilled");
        require(!lock.refunded, "Already refunded");
        require(
            block.timestamp > lock.lockTime + LOCK_TIMEOUT,
            "Not timed out"
        );
        
        lock.refunded = true;
        // Return to user
    }
}
```

---

## Branch [G]: Protocol Governance/Economic Attacks

### [G.4] Censorship

#### [G.4.1] Solver Censorship

**Attack Vector:** Solvers refuse to fill certain users or token pairs.

**Severity:** Medium | **Likelihood:** Medium | **Impact:** Medium

**Technical Details:**
```
Censorship scenarios:
1. Solvers blacklist certain addresses (regulatory)
2. Solvers avoid low-profit intents
3. Solvers only fill large orders, ignore retail
4. Geographic solver restrictions

Impact:
- Users cannot execute intents
- Protocol becomes centralized gatekeeper
- Worse than traditional DEX for censorship resistance
```

**Mitigation:**
```solidity
// SECURE: Permissionless fallback + solver incentives
contract AntiCensorshipMeasures {
    uint256 public constant CENSORSHIP_TIMEOUT = 5 minutes;
    
    struct PendingIntent {
        uint256 submissionTime;
        bool filled;
    }
    
    mapping(bytes32 => PendingIntent) public pending;
    
    function submitIntent(Intent memory intent) external {
        bytes32 hash = hashIntent(intent);
        pending[hash] = PendingIntent({
            submissionTime: block.timestamp,
            filled: false
        });
    }
    
    // After timeout, anyone can fill (not just solvers)
    function permissionlessFill(
        Intent memory intent,
        uint256 amountOut
    ) external {
        bytes32 hash = hashIntent(intent);
        PendingIntent storage p = pending[hash];
        
        require(!p.filled, "Already filled");
        require(
            block.timestamp > p.submissionTime + CENSORSHIP_TIMEOUT,
            "Solver exclusivity active"
        );
        
        // Anyone can fill after timeout
        require(amountOut >= intent.minAmountOut, "Below limit");
        
        p.filled = true;
        executePermissionlessFill(intent, amountOut);
    }
}
```

---

## Protocol-Specific Attack Patterns

### CoW Protocol

| Attack | Vector | Mitigation |
|--------|--------|------------|
| Solver MEV | Sandwich within batch | Uniform clearing price, solver competition |
| Batch Manipulation | Inject orders to shift price | Order commitment before batch |
| Solution Gaming | Submit suboptimal then optimal | Solution quality scoring |

### UniswapX

| Attack | Vector | Mitigation |
|--------|--------|------------|
| Dutch Auction Gaming | Wait for floor price | Exclusivity periods, non-linear decay |
| Filler Collusion | Market makers coordinate | Multiple filler competition |
| Permit2 Drain | Unlimited approvals | Exact amount permits |

### 1inch Fusion

| Attack | Vector | Mitigation |
|--------|--------|------------|
| Resolver MEV | Front-run revealed orders | Auction mechanism, resolver staking |
| Quote Manipulation | Stale quotes in RFQ | Short quote validity, price bounds |
| Partial Fill Abuse | Cherry-pick profitable fills | Minimum fill requirements |

### Across Protocol (Cross-Chain)

| Attack | Vector | Mitigation |
|--------|--------|------------|
| Relayer Fraud | Attest without source lock | Optimistic verification + bonds |
| LP Drain | Inventory attacks | Rate limiting, LP caps |
| Reorg Exploitation | Claim on reorged txs | Sufficient confirmations |

---

## Audit Checklist

### Solver/Filler Security
- [ ] Can solver sandwich user intents?
- [ ] Is there protection against solver collusion?
- [ ] Are solvers properly bonded/collateralized?
- [ ] Can competing solvers be DoS'd?
- [ ] Is there permissionless fallback if solvers censor?

### Signature Security
- [ ] Does domain separator include chainId?
- [ ] Is contract address in domain separator?
- [ ] Are nonces properly tracked (no replay)?
- [ ] Is signature malleability prevented?
- [ ] Are Permit2 allowances bounded?

### Price/Fill Validation
- [ ] Is there staleness check on intent prices?
- [ ] Is slippage properly bounded?
- [ ] Are partial fills minimum enforced?
- [ ] Is fill order manipulation prevented?
- [ ] Is surplus properly distributed?

### Settlement Security
- [ ] Is reentrancy prevented in settlement?
- [ ] Are fee-on-transfer tokens handled?
- [ ] Is batch settlement atomic?
- [ ] Are callbacks safe?
- [ ] Is CEI pattern followed?

### Auction Mechanism
- [ ] Can auction timing be gamed?
- [ ] Is price decay manipulation-resistant?
- [ ] Are batch auctions protected from injection?
- [ ] Is exclusivity properly enforced?

### Cross-Chain (if applicable)
- [ ] Is source chain verification robust?
- [ ] Is there timeout-based refund?
- [ ] Are reorgs handled properly?
- [ ] Is relayer/validator set decentralized?

---

## References

- [CoW Protocol Docs](https://docs.cow.fi/)
- [UniswapX Whitepaper](https://uniswap.org/whitepaper-uniswapx.pdf)
- [1inch Fusion Mode](https://docs.1inch.io/docs/fusion-swap/introduction)
- [Across Protocol](https://docs.across.to/)
- [EIP-712: Typed Structured Data Hashing](https://eips.ethereum.org/EIPS/eip-712)
- [Permit2 by Uniswap](https://github.com/Uniswap/permit2)

---

## Related Documents

- [signature-patterns.md](../patterns/signature-patterns.md)
- [mev-patterns.md](../patterns/mev-patterns.md)
- [bridge-attack-tree.md](bridge-attack-tree.md)
- [dex-attack-tree.md](dex-attack-tree.md)
