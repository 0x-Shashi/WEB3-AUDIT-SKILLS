# BRIDGE SECURITY CONTEXT
> Ultra-compressed audit context. ~200 lines = 80% coverage.

## MESSAGE VALIDATION CRITICAL
1. No source validation: accept message from any chain → fake messages | whitelist source chains
2. No sender validation: accept from any address → impersonation | whitelist senders per chain
3. Payload tampering: message modified in transit → wrong execution | verify merkle proof/signature
4. Empty payload: `data.length == 0` not handled → revert or wrong behavior | validate payload
5. Wrong encoding: ABI decode fails silently → partial execution | try/catch with revert

## REPLAY ATTACKS
1. Same-chain replay: message executed twice → double mint | track processed messageIds
2. Cross-chain replay: message from chain A valid on chain B → double spend | include chainId in hash
3. Nonce reuse: same nonce different message → signature collision | sequential or random nonces
4. Block reorg: message executed, then chain reorgs → inconsistent state | wait for finality

## FINALITY ISSUES
1. Optimistic rollups: 7-day challenge period → message may be invalid | wait for finality
2. L1→L2 latency: message sent but not yet received → race conditions | handle pending state
3. L2→L1 latency: withdrawal may take days → liquidity lock | use fast bridges for speed
4. Reorg on source: source tx reverts after relay → ghost message | confirm source finality

## TOKEN HANDLING
1. Lock-and-mint: lock on source, mint on dest | must match amounts exactly
2. Burn-and-unlock: burn on source, unlock on dest | verify burn happened
3. Decimal mismatch: 18 decimals on ETH, 6 on Solana → 10^12 factor | normalize across chains
4. Native token wrapping: ETH↔WETH conversion → stuck funds if mishandled | auto-wrap logic

## SIGNATURE / MULTISIG
1. Threshold too low: 2/5 multisig → collude to drain | require >50% threshold
2. Key rotation: old keys still valid after rotation → compromise window | instant revocation
3. Single oracle: one oracle signs → single point of failure | N of M with diverse operators
4. Signature malleability: same message, different signature → replay | normalize signatures

## RATE LIMITING
1. No rate limit: drain entire bridge in one tx → unlimited loss | hourly/daily caps
2. Rate limit bypass: multiple small txs → exceed intended limit | cumulative tracking
3. Global vs per-user: global limit → DoS by one attacker | per-user with global cap

## ADMIN CONTROLS
1. Instant pause: no delay → can front-run users | time-delayed admin
2. No pause: can't stop exploit in progress → unlimited damage | emergency pause function
3. Upgrade without delay: instant malicious upgrade → drain | timelock upgrades
4. Blocklist bypass: blocked address transfers to new address → circumvent block | destination blocklist

## LIQUIDITY MANAGEMENT
1. Insufficient liquidity: more withdrawn than deposited → insolvency | track cross-chain totals
2. Liquidity fragmentation: liquidity split across chains → some chains stuck | rebalancing mechanism
3. Fast bridge liquidity: LP provides liquidity, gets slow-bridge funds later → LP risk | proper incentives

## RELAYER ISSUES
1. Relayer censorship: relayer refuses to relay → messages stuck | permissionless relay option
2. Relayer front-running: relayer extracts MEV → user loss | encrypt payload until execution
3. Gas estimation: relayer underpays gas → execution fails | user specifies gas, relayer tops up
4. Failed execution: relay succeeds but execution reverts → stuck state | retry mechanism

## CRITICAL CODE PATTERNS

### Bad Source Validation
```solidity
// [VULNERABLE]
function receiveMessage(bytes calldata message) external {
    // Accept from anyone
    _execute(message);
}

// [SAFE]
function receiveMessage(uint256 srcChain, address srcSender, bytes calldata message) external {
    require(msg.sender == trustedRelayer, "Invalid relayer");
    require(allowedSources[srcChain][srcSender], "Invalid source");
    require(!processed[messageId], "Already processed");
    processed[messageId] = true;
    _execute(message);
}
```

### Bad Replay Protection
```solidity
// [VULNERABLE] - No replay protection
function executeMessage(bytes32 messageHash, bytes calldata data) external {
    require(verifySignature(messageHash, signature), "Bad sig");
    _execute(data);
}

// [SAFE]
mapping(bytes32 => bool) public executed;

function executeMessage(bytes32 messageHash, bytes calldata data) external {
    require(!executed[messageHash], "Already executed");
    require(verifySignature(messageHash, signature), "Bad sig");
    executed[messageHash] = true;
    _execute(data);
}
```

### Bad Token Amount Handling
```solidity
// [VULNERABLE] - Decimal mismatch
function bridgeIn(uint256 amount) external {
    // Source has 18 decimals, dest has 6
    destToken.mint(msg.sender, amount);  // 10^12 too many!
}

// [SAFE]
function bridgeIn(uint256 amount, uint8 srcDecimals) external {
    uint256 normalizedAmount = amount * (10 ** destDecimals) / (10 ** srcDecimals);
    destToken.mint(msg.sender, normalizedAmount);
}
```

### Bad Finality Assumption
```solidity
// [VULNERABLE] - No finality wait
function receiveFromL2(bytes calldata message) external {
    // Execute immediately, but L2 might reorg
    _execute(message);
}

// [SAFE]
function receiveFromL2(bytes calldata message, uint256 l2Block) external {
    require(block.number >= l2Block + FINALITY_BLOCKS, "Not finalized");
    _execute(message);
}
```

## CHECKLIST (Quick Scan)
- [ ] Source chain validation: whitelist allowed chains
- [ ] Source sender validation: whitelist allowed senders
- [ ] Message integrity: signature/merkle verification
- [ ] Replay protection: unique messageId tracking
- [ ] Finality: wait for source chain finality
- [ ] Token decimals: normalize across chains
- [ ] Rate limits: per-user and global caps
- [ ] Admin controls: timelock, pause capability
- [ ] Relayer trust: minimize or permissionless
- [ ] Failed execution: retry mechanism

## BRIDGE-SPECIFIC VULNERABILITIES

### Optimistic Bridges
- Challenge period bypass → instant withdrawal | verify challenge mechanism
- Invalid state root → fake withdrawals | robust fraud proofs
- Data withholding → can't generate fraud proof | data availability

### ZK Bridges
- Prover manipulation → fake proof validates | circuit correctness audit
- Trusted setup compromise → fake proofs | multi-party ceremony
- Soundness bugs → false proofs accepted | formal verification

### MPC Bridges
- Threshold key leakage → complete compromise | HSM, diverse operators
- Key generation ceremony → backdoor insertion | audited ceremony
- Liveness failure → bridge halts | recovery mechanism

## COMMON FINDINGS BY SEVERITY
**Critical**: No source validation, replay possible, signature bypass
**High**: Finality ignored, decimal mismatch, relayer can censor
**Medium**: Rate limit bypass, admin instant actions, failed execution stuck
**Low**: Gas inefficiency, event emission, minor centralization
