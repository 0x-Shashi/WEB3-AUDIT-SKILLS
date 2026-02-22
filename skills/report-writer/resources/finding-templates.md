---
id: RPT-FINDING-TPL
title: Finding Templates
parent: report-writer
type: resource
last_updated: 2025-01-31
---

# Finding Templates

Standardized templates for writing audit findings across all severity levels.

---

## Standard Finding Format

```markdown
### [S-01] Title That Describes the Vulnerability

**Severity:** Critical / High / Medium / Low / Informational

**Likelihood:** High / Medium / Low
**Impact:** High / Medium / Low

**Location:** `ContractName.sol#L123-L145`

**Description:**
[2-4 sentences explaining the vulnerability. What is wrong and why it's
a security issue. Include the root cause.]

**Impact:**
[1-3 sentences explaining the concrete consequences. What can an attacker
achieve? How much value is at risk? Who is affected?]

**Proof of Concept:**
[Working test case or step-by-step attack scenario]

**Recommended Mitigation:**
[Specific code change with before/after]
```

---

## Template: Critical Finding (Direct Fund Theft)

```markdown
### [C-01] Missing access control in `withdraw()` allows anyone to drain pool funds

**Severity:** Critical

**Likelihood:** High — No special conditions required, callable by any address
**Impact:** High — Complete loss of all deposited funds

**Location:** `LendingPool.sol#L189-L201`

**Description:**
The `withdraw()` function transfers tokens to `msg.sender` based on the
`amount` parameter without verifying that `msg.sender` has a corresponding
deposit balance. The function should check `balances[msg.sender] >= amount`
before transferring, but this check is missing.

**Impact:**
Any address can call `withdraw()` with an arbitrary `amount` and receive
tokens from the pool without having deposited. An attacker can drain the
entire pool balance in a single transaction.

**Proof of Concept:**
```solidity
function test_anyone_can_drain() public {
    // Setup: Alice deposits 100 ETH
    vm.prank(alice);
    pool.deposit{value: 100 ether}();
    
    // Attack: Bob (no deposit) withdraws everything
    vm.prank(bob);
    pool.withdraw(100 ether);  // Succeeds!
    
    assertEq(bob.balance, 100 ether);  // Bob has Alice's funds
    assertEq(address(pool).balance, 0); // Pool drained
}
```

**Recommended Mitigation:**
Add a balance check before the transfer:

```solidity
function withdraw(uint256 amount) external {
+   require(balances[msg.sender] >= amount, "Insufficient balance");
+   balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```
```

---

## Template: High Finding (Conditional Fund Loss)

```markdown
### [H-01] First depositor inflation attack on ERC4626 vault

**Severity:** High

**Likelihood:** Medium — Requires front-running the first deposit
**Impact:** High — Loss of first legitimate depositor's funds

**Location:** `Vault.sol#L45-L67` (inherited from ERC4626)

**Description:**
The vault uses the standard ERC4626 `convertToShares()` formula:
`shares = (assets * totalSupply) / totalAssets`. When `totalSupply` is 0,
the first depositor gets 1:1 shares. An attacker can front-run the first
deposit by:
1. Depositing 1 wei to get 1 share
2. Donating a large amount directly to the vault (inflating totalAssets)
3. When the victim deposits, they receive 0 shares due to rounding

**Impact:**
The first depositor can lose their entire deposit to the attacker. The
attacker profits from the donated amount being shared across (now
 inflated) shares.

**Proof of Concept:**
```solidity
function test_inflation_attack() public {
    // Attacker: deposit 1 wei, get 1 share
    vm.prank(attacker);
    vault.deposit(1, attacker);
    
    // Attacker: donate 10_000e18 directly
    token.transfer(address(vault), 10_000e18);
    
    // Victim: deposits 9_999e18, gets 0 shares!
    vm.prank(victim);
    vault.deposit(9_999e18, victim);
    
    assertEq(vault.balanceOf(victim), 0); // Victim got nothing
}
```

**Recommended Mitigation:**
Option A: Implement virtual offset (OpenZeppelin style):
```solidity
function _decimalsOffset() internal pure override returns (uint8) {
    return 3; // Adds virtual shares to prevent inflation
}
```

Option B: Require minimum initial deposit and burn dead shares.
```

---

## Template: Medium Finding (Logic Error)

```markdown
### [M-01] Fee calculation rounds in favor of user instead of protocol

**Severity:** Medium

**Likelihood:** High — Occurs on every transaction under 10,000 units
**Impact:** Low — Small fee leakage per transaction

**Location:** `FeeCollector.sol#L34`

**Description:**
The fee calculation `fee = amount * feeRate / 10000` rounds down due to
integer division, which is correct. However, for small amounts where
`amount * feeRate < 10000`, the fee is 0, allowing zero-fee transactions.

**Impact:**
Users can split large transactions into many small transactions to avoid
fees entirely. With a 0.3% fee rate (feeRate = 30), any transaction under
~333 units pays zero fees.

**Recommended Mitigation:**
Add a minimum fee or round up:
```solidity
function calculateFee(uint256 amount) internal view returns (uint256) {
    uint256 fee = (amount * feeRate + 9999) / 10000; // Round up
    return fee;
}
```
```

---

## Template: Low / Informational

```markdown
### [L-01] Missing zero-address check in constructor

**Severity:** Low

**Location:** `Vault.sol#L22`

**Description:**
The constructor accepts `_token` and `_admin` parameters without checking
for address(0). If deployed with a zero address, the contract would need
to be redeployed.

**Recommended Mitigation:**
```solidity
constructor(address _token, address _admin) {
+   require(_token != address(0), "zero token");
+   require(_admin != address(0), "zero admin");
    token = IERC20(_token);
    admin = _admin;
}
```
```

---

## Severity Justification Format

Always justify severity with the Likelihood × Impact matrix:

```
Likelihood: HIGH — [Why: exploitable by anyone, no prerequisites]
Impact: HIGH — [Why: direct loss of user funds]
→ Severity = Critical (High × High)

Likelihood: MEDIUM — [Why: requires specific market conditions]
Impact: HIGH — [Why: can drain the lending pool]
→ Severity = High (Medium × High)

Likelihood: HIGH — [Why: occurs on every small transaction]
Impact: LOW — [Why: small fee leakage per occurrence]
→ Severity = Medium (High × Low)
```

---

## Anti-Patterns: What NOT to Write

| Anti-Pattern | Problem |
|-------------|----------|
| "This function is vulnerable" | No specifics, not actionable |
| "Consider adding a check" | Too vague, no concrete fix |
| Impact without scenario | "Could lead to fund loss" — how? |
| PoC without assertions | Test that passes but proves nothing |
| Copy-pasted description | Same text for multiple findings |
| Wrong severity | Every finding marked Critical |
