# Attack Chain: Reentrancy + State Desynchronization

## Overview

Attacker exploits a reentrancy window to call back into the contract (or a related contract) while state variables are inconsistent, extracting value from the desynchronized state.

**Complexity:** Medium
**Typical Severity:** CRITICAL
**Protocols At Risk:** Vaults, Lending protocols, Staking, ERC4626, DEXs

---

## Attack Steps

```
ENTER FUNCTION → EXTERNAL CALL → RE-ENTER → READ STALE STATE → EXTRACT → STATE UPDATES
```

### Step 1: Identify Reentrancy Window
```
Find a function where:
- External call happens before state update (violates CEI)
- OR: State is partially updated between calls
- OR: View function reads state during external call
```

**What to check:**
- [ ] External calls before state updates?
- [ ] ETH transfers via .call{value:}()?
- [ ] Token transfers that could callback (ERC777, ERC1155)?
- [ ] View functions callable during state transition?

### Step 2: Identify Desync State
```
During reentrancy window, what state is inconsistent?
- Balance updated but totalSupply not
- Shares burned but assets not transferred
- Debt reduced but collateral not released
- Price stale due to partial state update
```

**What to check:**
- [ ] Which variables update BEFORE the external call?
- [ ] Which variables update AFTER?
- [ ] What reads from the inconsistent state?
- [ ] Can another function/contract read during the window?

### Step 3: Exploit the Desync
```
In the callback, exploit the inconsistent state:
- Deposit at favorable rate (stale price)
- Withdraw more than entitled
- Borrow with inflated collateral
- Liquidate at wrong price
```

### Step 4: Complete and Extract
```
- Original call completes, state finalizes
- Attacker has already extracted excess value
- May need to unwind positions to realize profit
```

---

## Variant Matrix

| Variant | What Re-enters | Where State is Stale | Typical Target |
|---------|---------------|---------------------|----------------|
| Classic | Same function | Same contract | withdraw() |
| Cross-function | Different function | Same contract | withdraw() → transfer() |
| Cross-contract | Different contract | Protocol A → B | Vault → Lending |
| Read-only | View function | Price/share calc | getPrice() |
| ERC777 | tokensReceived hook | Token balances | deposit() |
| ERC1155 | onERC1155Received | NFT state | mint/transfer |

---

## Code Signals

### Classic Reentrancy (CEI Violation)
```solidity
// [VULNERABLE] State update after external call
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");  // External call
    require(ok);
    balances[msg.sender] -= amount;  // State update AFTER call
}
```

### Cross-Function Reentrancy
```solidity
// [VULNERABLE] Callback can call transfer() with old balances
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}("");  // Callback here
    balances[msg.sender] = 0;
}

function transfer(address to, uint256 amt) external {
    // During callback, balances[msg.sender] is still old value
    require(balances[msg.sender] >= amt);
    balances[msg.sender] -= amt;
    balances[to] += amt;
}
```

### Read-Only Reentrancy
```solidity
// [VULNERABLE] Share price is wrong during withdraw
function convertToAssets(uint256 shares) public view returns (uint256) {
    return shares * totalAssets() / totalSupply();
    // During withdraw: totalSupply reduced but assets not yet sent
    // Price per share appears INFLATED
}
```

### ERC777 Callback Reentrancy
```solidity
// [VULNERABLE] ERC777 token calls tokensReceived on recipient
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);  // ERC777 callback
    shares[msg.sender] += computeShares(amount);
    totalDeposits += amount;
    // If token is ERC777, callback fires during transfer
    // Attacker can re-enter deposit() or call other functions
}
```

---

## Detection Checklist

- [ ] Any external call before state update
- [ ] CEI (Checks-Effects-Interactions) pattern violated
- [ ] No ReentrancyGuard on external/public functions
- [ ] ReentrancyGuard scope doesn't cover all related functions
- [ ] ERC777 tokens accepted (have transfer hooks)
- [ ] ERC1155 tokens (onERC1155Received callback)
- [ ] View functions read state that changes during external calls
- [ ] Cross-contract calls where state is shared
- [ ] ETH transfers via .call (not .transfer/.send)
- [ ] Multiple state variables updated non-atomically around external call

---

## Real-World Examples

| Protocol | Loss | Variant | Year |
|----------|------|---------|------|
| The DAO | $60M | Classic cross-function | 2016 |
| Curve/Vyper | $60M+ | Read-only via Vyper bug | 2023 |
| Rari/Fei | $80M | Cross-contract | 2022 |
| Cream Finance | $18.8M | ERC777 callback | 2021 |

---

## Mitigations

| Mitigation | Effectiveness |
|-----------|---------------|
| ReentrancyGuard (all external functions) | HIGH |
| CEI pattern strictly followed | HIGH |
| No ERC777 token support | MEDIUM |
| View function reentrancy lock | MEDIUM |
| Cross-contract reentrancy locks | HIGH |

---

## Related Patterns

- [Reentrancy Patterns](../patterns/reentrancy-patterns.md)
- [ERC4626 Patterns](../patterns/erc4626-patterns.md)
- [ERC20 Patterns](../patterns/erc20-patterns.md)
