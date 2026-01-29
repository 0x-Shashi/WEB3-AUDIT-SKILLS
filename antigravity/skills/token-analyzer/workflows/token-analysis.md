# Token Integration Analysis Workflow

Systematic workflow for auditing protocol token integrations. Identifies vulnerabilities from weird token behaviors.

---

## Prerequisites

- [ ] Token list to be integrated/supported
- [ ] Protocol smart contracts
- [ ] Protocol documentation on token handling
- [ ] Access to token contract sources or verified code

---

## Phase 1: Token Inventory

### 1.1 Identify All Token Interactions

```bash
# Find all token transfers
grep -rn "transfer\|transferFrom" contracts/
grep -rn "safeTransfer\|safeTransferFrom" contracts/

# Find all approvals
grep -rn "approve\|safeApprove\|forceApprove" contracts/

# Find balance checks
grep -rn "balanceOf" contracts/

# Find token interfaces
grep -rn "IERC20\|ERC20\|IERC721\|IERC1155" contracts/
```

### 1.2 Document Token Entry Points

```markdown
## Token Entry Points

| Function | Token Type | Direction | Location |
|----------|------------|-----------|----------|
| deposit() | Any ERC20 | In | Vault.sol:45 |
| withdraw() | Any ERC20 | Out | Vault.sol:78 |
| swap() | Pool tokens | Both | Pool.sol:123 |
| liquidate() | Collateral | Out | Lending.sol:200 |
```

### 1.3 Classify Token Support

```markdown
## Token Support Classification

| Category | Supported | Notes |
|----------|-----------|-------|
| Standard ERC20 | ✅ | Full support |
| Fee-on-Transfer | ⚠️ | See deposit() |
| Rebasing | ❌ | Will break accounting |
| ERC777 | ⚠️ | Reentrancy protected |
| Pausable | ⚠️ | May lock funds |
| Blacklistable | ⚠️ | Liquidation risk |
```

---

## Phase 2: Fee-on-Transfer Analysis

### 2.1 Check Deposit Patterns

```solidity
// ❌ VULNERABLE PATTERN
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // Credits amount sent, not received
}

// ✅ SAFE PATTERN
function deposit(uint256 amount) external {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;
    balances[msg.sender] += received;  // Credits actual received
}
```

### 2.2 Grep Patterns

```bash
# Find vulnerable deposit patterns
grep -Pzo "transferFrom.*\n.*\+= amount" contracts/

# Find safe patterns (good)
grep -n "balanceOf.*Before\|balanceBefore" contracts/
grep -n "balanceOf.*after\|balanceAfter" contracts/
```

### 2.3 Impact Assessment

```markdown
## Fee-on-Transfer Impact

### Vulnerable Functions
- [ ] deposit(): User credited more than received
- [ ] stake(): Stake accounting incorrect
- [ ] addLiquidity(): LP tokens miscalculated

### Financial Impact
- Users can drain contract by depositing fee tokens
- Last withdrawer can't withdraw (insufficient balance)
- Protocol becomes insolvent over time
```

---

## Phase 3: Rebasing Token Analysis

### 3.1 Check Balance Caching

```solidity
// ❌ VULNERABLE: Cached balance becomes stale
mapping(address => uint256) public stakedBalance;

function stake(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    stakedBalance[msg.sender] = amount;  // Stale after rebase
}

// ✅ SAFE: Use share-based accounting
mapping(address => uint256) public shares;
uint256 public totalShares;

function getBalance(address user) view returns (uint256) {
    return shares[user] * token.balanceOf(address(this)) / totalShares;
}
```

### 3.2 Check Balance References

```bash
# Find all places where balances are stored/compared
grep -n "userBalance\|userDeposit\|stakedAmount" contracts/

# Find share-based patterns (good)
grep -n "shares\[.*\]\|userShares" contracts/
```

### 3.3 Impact Assessment

```markdown
## Rebasing Token Impact

### Positive Rebase (stETH, aTokens)
- [ ] User loses yield (stolen by contract)
- [ ] Last user gets all accumulated yield
- [ ] Reward distribution unfair

### Negative Rebase (AMPL down)
- [ ] Withdrawal may fail (insufficient balance)
- [ ] Undercollateralization in lending
- [ ] User can withdraw more than deserved
```

---

## Phase 4: Return Value Analysis

### 4.1 Check SafeERC20 Usage

```bash
# Find raw transfer calls (vulnerable)
grep -n "\.transfer\(.*\)" contracts/ | grep -v "safeTransfer"
grep -n "\.approve\(.*\)" contracts/ | grep -v "safeApprove"

# Find SafeERC20 usage (good)
grep -n "using SafeERC20" contracts/
grep -n "safeTransfer\|safeTransferFrom\|safeApprove" contracts/
```

### 4.2 Check Return Value Handling

```solidity
// ❌ VULNERABLE: No return value check
token.transfer(to, amount);

// ❌ VULNERABLE: Assumes bool return
require(token.transfer(to, amount), "failed");  // USDT has no return

// ✅ SAFE: Uses SafeERC20
token.safeTransfer(to, amount);
```

### 4.3 Known Tokens Without Return

```markdown
## No-Return Tokens

| Token | Network | transfer() | approve() |
|-------|---------|------------|-----------|
| USDT | ETH | ❌ | ❌ |
| BNB | ETH | ❌ | ✅ |
| OMG | ETH | ❌ | ✅ |
| MKR | ETH | ❌ | ❌ |
```

---

## Phase 5: Approval Analysis

### 5.1 Check Approval Patterns

```bash
# Find direct approvals (may fail with USDT)
grep -n "\.approve\(" contracts/

# Find proper approval patterns
grep -n "safeApprove\|forceApprove" contracts/
grep -n "approve.*0\)" contracts/  # Reset to 0 first
```

### 5.2 USDT Compatibility

```solidity
// ❌ VULNERABLE: Fails if current allowance > 0
token.approve(spender, newAmount);

// ✅ SAFE: Reset first
token.safeApprove(spender, 0);
token.safeApprove(spender, newAmount);

// ✅ SAFE: Use forceApprove (OZ 5.x)
token.forceApprove(spender, newAmount);
```

### 5.3 Infinite Approval Risks

```markdown
## Approval Security

### Check Points
- [ ] Does protocol use infinite approvals?
- [ ] Can infinite approvals be drained if protocol is compromised?
- [ ] Is approval scope limited to necessary amount?
- [ ] Can users revoke approvals easily?
```

---

## Phase 6: Reentrancy from Hooks

### 6.1 ERC777 Detection

```solidity
// Check for ERC777 hook vulnerability
function vulnerableDeposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount); // Hook called here
    balances[msg.sender] += amount; // State updated after hook
}

// Attacker's tokensToSend hook:
function tokensToSend(...) external {
    // Re-enter vulnerableDeposit before balance updated
}
```

### 6.2 Protection Patterns

```bash
# Check for reentrancy guards
grep -n "nonReentrant\|ReentrancyGuard" contracts/

# Check for CEI pattern (effects before interactions)
grep -Pzo "\-= .*\n.*transfer" contracts/  # Good: effects then interact
```

### 6.3 Risk Assessment

```markdown
## ERC777/Hook Reentrancy

### Vulnerable Patterns
- [ ] State updated after transfer
- [ ] No reentrancy guard
- [ ] Multiple external calls in sequence

### Protected Patterns
- [ ] nonReentrant modifier
- [ ] CEI (Check-Effects-Interactions)
- [ ] State updates before external calls
```

---

## Phase 7: Blacklist/Pause Analysis

### 7.1 Identify Risk Points

```markdown
## Blacklist Risk Points

### Protocol Addresses
- [ ] Treasury address blacklisted = funds locked
- [ ] Pool address blacklisted = all LP funds locked
- [ ] Liquidator blacklisted = bad debt accumulation

### User Flows
- [ ] Borrower blacklisted during loan = can't repay
- [ ] LP blacklisted = can't withdraw
- [ ] Staker blacklisted = rewards locked
```

### 7.2 Mitigation Patterns

```solidity
// ✅ Graceful degradation for blacklisted users
function withdraw(address token, uint256 amount) external {
    balances[msg.sender] -= amount;
    
    try IERC20(token).transfer(msg.sender, amount) {
        // Success
    } catch {
        // Store for alternative withdrawal
        pendingWithdrawals[msg.sender][token] += amount;
        emit WithdrawalFailed(msg.sender, token, amount);
    }
}
```

### 7.3 Pause Impact

```markdown
## Token Pause Impact

### Affected Operations
- [ ] Deposits: Users can't add collateral
- [ ] Withdrawals: Funds locked
- [ ] Liquidations: Bad debt accumulates
- [ ] Swaps: Pool unusable

### Mitigation
- [ ] Emergency withdrawal mechanism
- [ ] Alternative collateral acceptance
- [ ] Grace period before liquidation
```

---

## Phase 8: Decimal Handling

### 8.1 Check Decimal Assumptions

```bash
# Find hardcoded decimal assumptions
grep -n "1e18\|10\*\*18\|10 \*\* 18" contracts/
grep -n "decimals()" contracts/

# Find division before multiplication (precision loss)
grep -n "/ .*\*" contracts/
```

### 8.2 Precision Analysis

```solidity
// ❌ VULNERABLE: Division before multiplication
uint256 share = amount / totalSupply * totalShares;  // Truncates to 0 for small amounts

// ✅ SAFE: Multiplication before division
uint256 share = amount * totalShares / totalSupply;

// ✅ SAFER: Use mulDiv for large numbers
uint256 share = Math.mulDiv(amount, totalShares, totalSupply);
```

### 8.3 Low Decimal Token Issues

```markdown
## Low Decimal Tokens (USDC: 6, WBTC: 8)

### Risk Areas
- [ ] Small amounts round to 0
- [ ] Fee calculations lose precision
- [ ] Price ratios incorrect
- [ ] Minimum viable amounts too large

### Mitigation
- [ ] Scale to common precision (18 decimals)
- [ ] Use mulDiv for safe math
- [ ] Add minimum amount checks
- [ ] Test with 6 decimal tokens
```

---

## Phase 9: Special Token Types

### 9.1 Upgradeable Tokens

```markdown
## Upgradeable Token Risks

### Concerns
- [ ] Token behavior may change
- [ ] New fees could be added
- [ ] Blacklist could be expanded
- [ ] Transfer logic could change

### Due Diligence
- [ ] Who controls upgrade keys?
- [ ] Is there a timelock?
- [ ] Is upgrade logic audited?
- [ ] What's the track record?
```

### 9.2 Permit (ERC2612) Tokens

```solidity
// Check permit usage for signature replay
function depositWithPermit(
    uint256 amount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    token.permit(msg.sender, address(this), amount, deadline, v, r, s);
    // permit uses nonce, so replay is prevented
    token.transferFrom(msg.sender, address(this), amount);
}
```

### 9.3 Flash Mintable Tokens

```markdown
## Flash Mint Risks

### Vulnerable Patterns
- [ ] Governance voting power from balanceOf
- [ ] Collateral ratios checked in same tx
- [ ] Price oracle manipulation

### Safe Patterns
- [ ] Use historical balance snapshots
- [ ] Check balances across multiple blocks
- [ ] Use time-weighted average prices
```

---

## Phase 10: Testing & Verification

### 10.1 Token Compatibility Tests

```javascript
describe("Token Compatibility", function() {
    it("should handle fee-on-transfer tokens", async function() {
        // Deploy mock fee token (1% fee)
        const FeeToken = await ethers.getContractFactory("MockFeeToken");
        const feeToken = await FeeToken.deploy(100); // 1% = 100 bps
        
        // Deposit 1000 tokens
        await feeToken.approve(vault.address, 1000);
        await vault.deposit(feeToken.address, 1000);
        
        // User should be credited 990 (after 1% fee)
        expect(await vault.balances(user.address, feeToken.address)).to.equal(990);
    });
    
    it("should handle rebasing tokens", async function() {
        // Deploy mock rebasing token
        const RebaseToken = await ethers.getContractFactory("MockRebaseToken");
        const rebaseToken = await RebaseToken.deploy();
        
        // Deposit
        await rebaseToken.approve(vault.address, 1000);
        await vault.deposit(rebaseToken.address, 1000);
        
        // Simulate rebase (+10%)
        await rebaseToken.rebase(110); // 110% of original
        
        // Withdraw should get rebased amount
        const balanceBefore = await rebaseToken.balanceOf(user.address);
        await vault.withdraw(rebaseToken.address);
        const balanceAfter = await rebaseToken.balanceOf(user.address);
        
        expect(balanceAfter - balanceBefore).to.equal(1100);
    });
    
    it("should handle USDT-style approvals", async function() {
        // Deploy mock USDT (no return value, blocks non-zero to non-zero)
        const MockUSDT = await ethers.getContractFactory("MockUSDT");
        const usdt = await MockUSDT.deploy();
        
        // Should not revert on approval
        await expect(vault.deposit(usdt.address, 1000)).to.not.be.reverted;
    });
});
```

### 10.2 Mainnet Fork Testing

```javascript
describe("Mainnet Fork Token Tests", function() {
    const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const STETH = "0xae7ab96520DE3A18E5e111B5EaijB0116A3b6CE9";
    
    beforeEach(async function() {
        await network.provider.request({
            method: "hardhat_reset",
            params: [{
                forking: {
                    jsonRpcUrl: process.env.ETH_RPC_URL,
                    blockNumber: 18000000
                }
            }]
        });
    });
    
    it("should work with real USDT", async function() {
        // Get USDT whale
        await hre.network.provider.request({
            method: "hardhat_impersonateAccount",
            params: ["0x...whale..."]
        });
        
        // Test actual integration
        // ...
    });
});
```

---

## Audit Report Template

```markdown
# Token Integration Findings

## Summary
| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

## Findings

### [C-01] Fee-on-Transfer Tokens Break Accounting

**Location**: Vault.sol:deposit()

**Description**: The deposit function credits users with the amount parameter rather than the actual received amount.

**Impact**: Users depositing fee-on-transfer tokens are credited more than the contract receives. Over time, this creates a deficit where the last users cannot withdraw.

**Proof of Concept**:
1. Deposit 1000 SAFEMOON (10% fee)
2. Contract receives 900, user credited 1000
3. Repeat until contract balance = 0
4. Last depositor cannot withdraw

**Recommendation**:
```solidity
uint256 balanceBefore = token.balanceOf(address(this));
token.safeTransferFrom(msg.sender, address(this), amount);
uint256 received = token.balanceOf(address(this)) - balanceBefore;
balances[msg.sender] += received;
```

---

### [H-01] Rebasing Token Yield Stolen

**Location**: Staking.sol

**Description**: The contract stores absolute balances for rebasing tokens instead of shares. When tokens rebase positively, the yield is trapped in the contract.

**Recommendation**: Use share-based accounting or explicitly disallow rebasing tokens.

---

### [M-01] Missing SafeERC20 for USDT

**Location**: Multiple files

**Description**: Several transfer and approve calls use the raw ERC20 interface. This will fail for USDT and similar tokens that don't return a boolean.

**Recommendation**: Use SafeERC20 from OpenZeppelin for all token interactions.
```

---

## Quick Reference Checklist

```markdown
## Token Integration Audit Checklist

### Transfers
- [ ] Using SafeERC20?
- [ ] Measuring actual received amounts?
- [ ] Handling zero transfer gracefully?
- [ ] Protected against reentrancy?

### Approvals
- [ ] Using safeApprove/forceApprove?
- [ ] Resetting to 0 for USDT?
- [ ] Avoiding infinite approvals?

### Balances
- [ ] Using shares for rebasing tokens?
- [ ] Not caching stale balances?
- [ ] Handling decimals correctly?

### Special Cases
- [ ] Blacklist failure handling?
- [ ] Pause resilience?
- [ ] Upgrade risk assessment?
- [ ] ERC777 reentrancy protection?

### Testing
- [ ] Tested with fee-on-transfer mock?
- [ ] Tested with rebasing mock?
- [ ] Tested with no-return mock?
- [ ] Tested with low decimal tokens?
- [ ] Mainnet fork tests?
```
