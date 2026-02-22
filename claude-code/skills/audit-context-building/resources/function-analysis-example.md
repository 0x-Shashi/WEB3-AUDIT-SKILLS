# Function Analysis Example

## Template
```
### functionName(param1, param2)
- **Visibility**: external / public
- **Access**: onlyOwner / unrestricted
- **Modifiers**: nonReentrant, whenNotPaused
- **State Changes**: updates balances[msg.sender], totalSupply
- **External Calls**: token.transfer(to, amount)
- **Events**: Transfer(msg.sender, to, amount)
- **CEI Compliance**: YES/NO
- **Edge Cases**: amount=0 (no-op), amount=max (overflow?)
- **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL
- **Notes**: Fee-on-transfer tokens will cause accounting mismatch
```

## Example Analysis
```
### withdraw(uint256 amount)
- **Visibility**: external
- **Access**: unrestricted (any depositor)
- **Modifiers**: nonReentrant
- **State Changes**: balances[msg.sender] -= amount
- **External Calls**: IERC20(token).transfer(msg.sender, amount)
- **Events**: Withdrawal(msg.sender, amount)
- **CEI Compliance**: YES (state updated before transfer)
- **Edge Cases**: amount=0 succeeds (gas waste), amount > balance reverts
- **Risk Level**: MEDIUM
- **Notes**: Uses SafeERC20, but doesn't account for fee-on-transfer
```
