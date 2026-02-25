# Pattern Summaries — Quick Reference & Detection Guide

> **Master index of all vulnerability categories.** Each section has a quick-reference table, detection code, audit checklist, and source file list. Load the individual pattern files for full details.

**Last updated**: 2026-02-25

---

## Table of Contents

1. [Token Security](#1-token-security)
2. [Reentrancy](#2-reentrancy)
3. [Access Control → see access-control-patterns.md](#3-access-control)
4. [Math & Precision](#4-math--precision)
5. [Validation](#5-validation)
6. [DoS & Gas](#6-dos--gas)
7. [Upgrade & Storage](#7-upgrade--storage)
8. [Signature & Cryptography](#8-signature--cryptography)
9. [NFT & Governance](#9-nft--governance)
10. [DeFi → see defi-patterns.md](#10-defi)
11. [Cross-Chain & L2 → see cross-chain-l2-patterns.md](#11-cross-chain--l2)
12. [Miscellaneous](#12-miscellaneous)

---

## 1. Token Security

### Quick Summary

| Token Issue | Description | Severity |
|-------------|-------------|----------|
| Fee-on-Transfer | Actual received < transferred amount | High |
| Rebasing Tokens | Balance changes without transfers | High |
| ERC777 Hooks | Reentrancy via token callbacks | Critical |
| Missing Return | USDT doesn't return bool on transfer | Medium |
| Blacklist Tokens | USDC/USDT can freeze addresses | Medium |
| Pausable Tokens | Token can halt all transfers | Medium |
| Decimals Variance | Not all tokens have 18 decimals | High |
| Approval Race | Double-spend via approve front-running | Medium |

### Token Compatibility Matrix

| Token | Decimals | Fee | Rebase | Blacklist | Pausable | Hook |
|-------|----------|-----|--------|-----------|----------|------|
| USDT | 6 | No | No | Yes | Yes | No |
| USDC | 6 | No | No | Yes | Yes | No |
| DAI | 18 | No | No | No | No | No |
| WETH | 18 | No | No | No | No | No |
| stETH | 18 | No | Yes | No | No | No |
| PAXG | 18 | Yes | No | Yes | Yes | No |
| AMPL | 9 | No | Yes | No | No | No |
| ERC777 | 18 | Varies | No | No | No | Yes |

### Detection Code

```solidity
// Fee-on-Transfer — VULNERABLE
function deposit(uint amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // Wrong! May receive less
}

// Fee-on-Transfer — SAFE
function deposit(uint amount) external {
    uint balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint received = token.balanceOf(address(this)) - balanceBefore;
    balances[msg.sender] += received;  // Correct
}

// SafeERC20 Usage — REQUIRED for USDT and others
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeTransfer(to, amount);
token.safeTransferFrom(from, to, amount);

// Approval Race — SAFE
token.safeApprove(spender, 0);
token.safeApprove(spender, newAmount);
// Or use increaseAllowance/decreaseAllowance or permit
```

### Audit Checklist
- [ ] Using SafeERC20 for all token operations?
- [ ] Checking actual balance received (fee-on-transfer)?
- [ ] Not assuming 18 decimals?
- [ ] Handling potential blacklist/pause?
- [ ] Protected against ERC777 reentrancy?
- [ ] Approval race condition mitigated?
- [ ] Rebasing token accounting correct?

### Source Files
> erc20-patterns.md, erc721-patterns.md, erc777-patterns.md, erc1155-patterns.md, fee-on-transfer-patterns.md, rebasing-tokens-patterns.md, weird-erc20-patterns.md, usdc-patterns.md, usdt-patterns.md, approve-patterns.md, approve-max-patterns.md, allowance-patterns.md, safeapprove-patterns.md, safetransfer-patterns.md, mint-vs-safemint-patterns.md, token-existence-patterns.md

---

## 2. Reentrancy

### Quick Summary

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| Classic Reentrancy | External call before state update allows re-entry | Critical |
| Cross-Function | Attacker re-enters different function sharing state | Critical |
| Cross-Contract | Reentrancy between multiple contracts | Critical |
| Read-Only Reentrancy | View function reads stale state during callback | High |
| ERC777 Callback | tokensReceived/tokensToSend hook exploitation | High |
| ERC721 Callback | onERC721Received hook exploitation | High |
| ERC1155 Callback | onERC1155Received hook exploitation | High |

### Real-World Exploits

| Protocol | Loss | Attack Type | Year |
|----------|------|-------------|------|
| The DAO | $60M | Classic reentrancy | 2016 |
| Uniswap/Lendf.Me | $25M | ERC777 reentrancy | 2020 |
| Cream Finance | $130M | Flash loan + reentrancy | 2021 |
| Rari Capital | $80M | Cross-contract reentrancy | 2022 |

### Detection Code

```solidity
// VULNERABLE: External call before state update
function withdraw() external {
    uint amount = balances[msg.sender];
    (bool success,) = msg.sender.call{value: amount}("");
    balances[msg.sender] = 0;  // State update AFTER call = VULNERABLE
}

// SAFE: Checks-Effects-Interactions (CEI)
function withdraw() external {
    uint amount = balances[msg.sender];
    require(amount > 0, "No balance");    // Check
    balances[msg.sender] = 0;              // Effect
    payable(msg.sender).transfer(amount);  // Interaction
}

// ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw() external nonReentrant { ... }
}
```

### Audit Checklist
- [ ] All external calls happen AFTER state updates (CEI pattern)
- [ ] ReentrancyGuard on ALL external functions, not just obvious ones
- [ ] Check for callbacks: ERC777, ERC721, ERC1155, flash loans
- [ ] Cross-function: Can re-entering function B affect function A's state?
- [ ] Cross-contract: Can external contract callback affect shared state?
- [ ] Read-only: Do view functions return stale data during reentrancy?

### Source Files
> reentrancy-patterns.md, read-only-reentrancy-patterns.md, cei-patterns.md, external-call-patterns.md, external-contract-patterns.md, call-vs-transfer-patterns.md, check-return-value-patterns.md, transfer-result-check-patterns.md, revert-inside-hook-patterns.md

---

## 3. Access Control

*See [access-control-patterns.md](access-control-patterns.md) for the full standalone guide (5 KB).*

### Source Files
> access-control-patterns.md, authorization-patterns.md, owner-patterns.md, role-patterns.md, tx-origin-patterns.md, pause-patterns.md

---

## 4. Math & Precision

### Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Division Before Multiply | Precision lost in intermediate calculation | High |
| Wrong Rounding Direction | Rounding favors attacker over protocol | High |
| Decimal Mismatch | Different token decimals not normalized | High |
| Unchecked Overflow | Arithmetic overflow in unchecked blocks | High |
| Truncation | Casting to smaller type loses data | Medium |
| 1/64 Gas Rule | Only 63/64 gas forwarded to subcalls | Medium |

### Detection Code

```solidity
// Division Before Multiplication — WRONG
uint result = (a / b) * c;  // a=5, b=3, c=6: (5/3)*6 = 1*6 = 6
// CORRECT
uint result = (a * c) / b;  // a=5, b=3, c=6: (5*6)/3 = 30/3 = 10

// Rounding Direction — Protocol should NEVER round in attacker's favor
// Deposits: Round DOWN (user gets fewer shares)
// Withdrawals: Round DOWN (user gets fewer assets)
// Fees: Round UP (protocol gets more)
import "@openzeppelin/contracts/utils/math/Math.sol";
shares = Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Down);

// Decimal Normalization
uint8 decimalsA = tokenA.decimals();
uint normalizedA = amountA * 10**(18 - decimalsA);
```

### Audit Checklist
- [ ] All divisions happen AFTER multiplications
- [ ] Rounding direction checked for every calculation
- [ ] Token decimals normalized before comparison
- [ ] No unchecked blocks with user input
- [ ] Type casting checked for truncation
- [ ] Large numbers checked for overflow potential

### Source Files
> precision-loss-patterns.md, rounding-patterns.md, time-rounding-patterns.md, overflow-underflow-patterns.md, truncation-patterns.md, type-casting-patterns.md, decimals-patterns.md, wrong-math-patterns.md, 1-64-rule-patterns.md

---

## 5. Validation

### Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Missing Zero Check | address(0) or amount=0 not validated | Medium-High |
| Unchecked Return | External call return value ignored | High |
| Array Length Mismatch | Two arrays expected same length | High |
| Bounds Check Missing | Array index out of bounds | High |
| from == to | Self-transfer breaks logic | Medium |
| Bypass Limit | User can exceed intended limits | High |

### Detection Code

```solidity
// Zero Address Check — SAFE
function setAdmin(address _admin) external onlyOwner {
    require(_admin != address(0), "Zero address");
    admin = _admin;
}

// Array Length Validation — SAFE
function batchTransfer(address[] calldata to, uint[] calldata amounts) external {
    require(to.length == amounts.length, "Length mismatch");
    for (uint i = 0; i < to.length; i++) {
        transfer(to[i], amounts[i]);
    }
}

// Return Value Check — SAFE
require(token.transfer(to, amount), "Transfer failed");
// OR use SafeERC20
token.safeTransfer(to, amount);
```

### Audit Checklist
- [ ] All address parameters checked for zero
- [ ] All amount parameters checked for zero (if relevant)
- [ ] Array lengths validated when multiple arrays used together
- [ ] External call return values checked
- [ ] from != to validated where relevant
- [ ] Bounds checks on all array accesses
- [ ] User input validated before use in calculations

### Source Files
> validation-patterns.md, data-validation-patterns.md, change-validation-patterns.md, missing-check-patterns.md, missing-logic-patterns.md, min-max-cap-validation-patterns.md, minout-maxin-validation-patterns.md, from-to-patterns.md, bypass-limit-patterns.md

---

## 6. DoS & Gas

### Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Unbounded Loop | Loop over user-controlled array | High |
| External Call in Loop | One failure reverts entire batch | High |
| Block Gas Limit | Transaction too large to execute | High |
| Griefing | Attacker makes operations expensive | Medium |
| Fund Lock | Funds become permanently stuck | Critical |
| Push Over Pop | Array grows unbounded | Medium |

### Detection Code

```solidity
// Unbounded Loop — SAFE: Paginated
function processBatch(uint start, uint count) external {
    uint end = min(start + count, users.length);
    for (uint i = start; i < end; i++) {
        process(users[i]);
    }
}

// External Call in Loop — SAFE: Pull pattern
function claimReward() external {
    uint reward = rewards[msg.sender];
    rewards[msg.sender] = 0;
    payable(msg.sender).transfer(reward);
}

// Fund Lock Prevention — Always have emergency withdraw
function emergencyWithdraw() external onlyOwner {
    token.transfer(owner, token.balanceOf(address(this)));
}
```

### Audit Checklist
- [ ] All loops have bounded iteration count
- [ ] No external calls inside loops (or handled with try/catch)
- [ ] Pull pattern used instead of push for distributions
- [ ] Emergency withdrawal mechanism exists
- [ ] No user can grief others' gas costs significantly
- [ ] Arrays that grow have corresponding cleanup mechanism

### Source Files
> dos-patterns.md, denial-of-service-patterns.md, gas-limit-patterns.md, gas-price-patterns.md, broken-loop-patterns.md, array-patterns.md, array-reorder-patterns.md, dust-patterns.md, revert-by-sending-dust-patterns.md, grief-attack-patterns.md, fund-lock-patterns.md, withdraw-0-patterns.md, withdraw-pattern-patterns.md

---

## 7. Upgrade & Storage

### Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Storage Collision | Proxy and impl storage slots overlap | Critical |
| Uninitialized Proxy | initialize() never called | Critical |
| Front-Run Initialize | Attacker initializes before owner | Critical |
| Missing Storage Gap | No __gap for future upgrades | High |
| Selfdestruct in Impl | Implementation can be destroyed | Critical |
| Immutable in Proxy | Immutables don't work in proxies | High |

### Proxy Patterns Reference

| Pattern | Pros | Cons |
|---------|------|------|
| Transparent Proxy | Simple, widely used | Gas overhead on every call |
| UUPS | Gas efficient | Risk if upgrade function broken |
| Beacon Proxy | Upgrade many proxies at once | More complex |
| Diamond (EIP-2535) | Modular, no size limit | Very complex |

### Detection Code

```solidity
// Storage Collision — SAFE: Use EIP-1967
bytes32 constant IMPL_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

// Initialize Protection — SAFE
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
function initialize(address _owner) external initializer {
    require(_owner != address(0), "Zero address");
    owner = _owner;
}

// Storage Gap — for upgradeable base contracts
abstract contract BaseContract {
    uint256 public value;
    uint256[49] private __gap;  // Reserve 50 slots
}
```

### Audit Checklist
- [ ] Using EIP-1967 storage slots for proxy state
- [ ] initialize() has initializer modifier
- [ ] initialize() checks for zero addresses
- [ ] All upgradeable base contracts have __gap
- [ ] No selfdestruct in implementation
- [ ] No immutable variables in upgradeable contracts
- [ ] Constructor only sets immutables or disables initializers
- [ ] Storage layout preserved between upgrades

### Source Files
> upgradable-patterns.md, initialization-patterns.md, initializer-patterns.md, storage-collision-patterns.md, storage-gap-patterns.md, immutable-patterns.md, hardcoded-address-patterns.md, hardcoded-setting-patterns.md, configuration-patterns.md

---

## 8. Signature & Cryptography

### Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Signature Malleability | Same sig can have multiple valid forms | High |
| Missing Nonce | Signature can be replayed | Critical |
| Cross-Chain Replay | Sig valid on multiple chains | High |
| Missing Deadline | Signature never expires | Medium |
| ecrecover Returns Zero | Invalid sig returns address(0) | High |
| Weak Domain Separator | Missing chainId or address in EIP-712 | High |

### Detection Code

```solidity
// Signature Malleability — SAFE: Use OpenZeppelin ECDSA
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
function verify(bytes32 hash, bytes memory signature) public returns (address) {
    return ECDSA.recover(hash, signature);  // Checks s value
}

// Replay Protection — SAFE: Use nonce
mapping(address => uint256) public nonces;
function execute(bytes memory sig, uint256 nonce) external {
    require(nonce == nonces[msg.sender]++, "Invalid nonce");
    bytes32 hash = keccak256(abi.encode(data, nonce, block.chainid));
    address signer = ECDSA.recover(hash, sig);
}

// EIP-712 Domain Separator — MUST include chainId and contract address
bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256(bytes("MyProtocol")),
    keccak256(bytes("1")),
    block.chainid,
    address(this)
));
```

### Audit Checklist
- [ ] Using ECDSA.recover() not raw ecrecover
- [ ] Checking recovered address != address(0)
- [ ] Nonce included in signed message
- [ ] Deadline/expiry included in signed message
- [ ] ChainId included in domain separator
- [ ] Contract address included in domain separator
- [ ] Signature marked as used after verification

### Source Files
> signature-malleability-patterns.md, replay-attack-patterns.md, nonce-patterns.md, deadline-patterns.md, eip-712-patterns.md, merkle-tree-patterns.md, abi-encoding-patterns.md

---

## 9. NFT & Governance

### Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Flash Loan Voting | Borrow tokens, vote, return same block | Critical |
| Checkpoint Missing | Historical balance not tracked | High |
| Vote Manipulation | Incorrect voting power calculation | High |
| Unsafe NFT Mint | mint() doesn't check receiver | Medium |
| Royalty Bypass | Marketplace avoids creator royalties | Medium |
| Proposal Frontrun | Attacker frontrun proposal execution | High |

### Detection Code

```solidity
// Flash Loan Governance — SAFE: Use checkpointed balance
function vote(uint proposalId, bool support) external {
    uint snapshotId = proposals[proposalId].snapshotId;
    uint votes = token.balanceOfAt(msg.sender, snapshotId);
    _vote(proposalId, support, votes);
}

// NFT Safe Minting — SAFE
function mint(address to, uint tokenId) external {
    _safeMint(to, tokenId);  // Calls onERC721Received
}

// Governance Timing Protections
contract SecureGovernor {
    uint public constant VOTING_DELAY = 1 days;
    uint public constant VOTING_PERIOD = 3 days;
    uint public constant TIMELOCK_DELAY = 2 days;
    uint public constant QUORUM = 4;  // 4% of supply
}
```

### Audit Checklist
- [ ] Voting power uses checkpointed/snapshot balance
- [ ] Snapshot taken at proposal creation time
- [ ] Voting delay prevents last-minute token acquisition
- [ ] Timelock on proposal execution
- [ ] Quorum requirements appropriate
- [ ] Using _safeMint for NFTs to contracts
- [ ] Royalty calculation in marketplace enforced

### Source Files
> nft-patterns.md, royalty-patterns.md, dao-patterns.md, vote-patterns.md, checkpoint-patterns.md, auction-patterns.md, cooldown-patterns.md

---

## 10. DeFi

*See [defi-patterns.md](defi-patterns.md) for the full standalone guide (6 KB) covering oracle manipulation, TWAP, donation attacks, flash loans, slippage, and liquidation.*

---

## 11. Cross-Chain & L2

*See [cross-chain-l2-patterns.md](cross-chain-l2-patterns.md) for the full standalone guide (6 KB) covering sequencer risks, message passing, finality differences, bridge security, and gas pricing.*

---

## 12. Miscellaneous

### Quick Summary

| Category | Key Issues |
|----------|------------|
| Timing | block.timestamp manipulation, deadline issues |
| Events | Missing events, incorrect event data |
| Code Quality | Typos, copy-paste errors, dead code |
| Account Abstraction | ERC-4337 specific vulnerabilities |
| Business Logic | Protocol-specific logic flaws |

### Detection Code

```solidity
// Timestamp Manipulation — miners can manipulate by ~15 seconds
if (block.timestamp >= unlockTime) { ... }  // OK for hours+
// Risky for short time windows (< 30 seconds)

// Event Emission — CORRECT
event PriceUpdated(uint oldPrice, uint newPrice);
function setPrice(uint _price) external onlyOwner {
    emit PriceUpdated(price, _price);
    price = _price;
}

// Pre/Post Balance Check — for accurate accounting
function deposit(address token, uint amount) external {
    uint balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    uint received = IERC20(token).balanceOf(address(this)) - balanceBefore;
    // Use 'received' not 'amount'
}
```

### Source Files
> account-abstraction-patterns.md, business-logic-patterns.md, timing-patterns.md, block-period-patterns.md, event-patterns.md, auditing-and-logging-patterns.md, code-quality-patterns.md, coding-bug-patterns.md, typo-copypaste-patterns.md, documentation-patterns.md, don-t-update-state-patterns.md, mapping-patterns.md, payable-patterns.md, refund-ether-patterns.md, pre-post-balance-patterns.md, sense-patterns.md, supportsinterface-patterns.md, eip-165-patterns.md, protocol-specific-patterns.md, vulnerability-patterns.md, vulnerability-taxonomy.md, severity-scoring.md, invariant-testing.md

---

## Quick Detection Checklist

```
REENTRANCY
[ ] External calls before state updates?         → Reentrancy risk
[ ] Callback functions (onERC721Received, etc.)?  → Check for reentrancy
[ ] ReentrancyGuard on all external functions?    → May have gaps

MATH
[ ] Division before multiplication?               → Precision loss
[ ] Unchecked blocks in Solidity 0.8+?            → Intentional overflow risk
[ ] Different token decimals?                     → Normalization needed
[ ] Rounding in share calculations?               → Check direction

ACCESS CONTROL
[ ] Critical function without modifier?           → Anyone can call
[ ] Using tx.origin?                              → Phishing vulnerability
[ ] initialize() without initializer modifier?    → Can reinitialize

VALIDATION
[ ] Unchecked external call return?               → Silent failures
[ ] Missing zero address check?                   → Permanent loss
[ ] Array iteration without bounds?               → DoS risk

ORACLE
[ ] Single price source?                          → Manipulation risk
[ ] No staleness check on Chainlink?              → Outdated price
[ ] Spot price from AMM?                          → Flash loan manipulation

TOKENS
[ ] Assuming 18 decimals?                         → Check actual decimals
[ ] Not using SafeERC20?                          → Missing return value
[ ] No fee-on-transfer handling?                  → Accounting mismatch
```
