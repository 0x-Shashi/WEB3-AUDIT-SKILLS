# Token Analysis Workflow

## When to Use
Run this workflow whenever a protocol integrates external ERC20/ERC721/ERC1155 tokens.

## Step 1: Identify All External Token Interactions
Scan for:
- `IERC20`, `IERC721`, `IERC1155` imports
- `.transfer()`, `.transferFrom()`, `.approve()` calls
- `balanceOf()` reads used in accounting
- Token addresses passed as constructor/function parameters

## Step 2: Classify Each Token
For each token the protocol interacts with:
- Is it a known token (USDC, USDT, DAI, etc.)?
- Is it permissionless (any token allowed)?
- Check the weird tokens list for known quirks

## Step 3: Check Transfer Safety
For each transfer call:
- [ ] Uses SafeERC20? (Handles missing return values)
- [ ] Measures actual received amount? (Handles fee-on-transfer)
- [ ] CEI pattern followed? (Handles callback tokens)
- [ ] Reentrancy guard present? (Handles ERC777/hooks)

## Step 4: Check Approval Safety
For each approve call:
- [ ] Resets to 0 before setting new value? (Required by USDT)
- [ ] Uses safeApprove or safeIncreaseAllowance?
- [ ] No infinite approval on user behalf without consent?

## Step 5: Check Accounting
- [ ] Protocol tracks shares or actual balances?
- [ ] Rebasing token handling (if applicable)?
- [ ] Decimal normalization correct?
- [ ] No assumption that `decimals() == 18`?
- [ ] Handles zero amounts correctly?

## Step 6: Check Access/Admin Risks
- [ ] What happens if token is paused?
- [ ] What happens if user address is blacklisted?
- [ ] What happens if token is upgraded?
- [ ] Withdrawal still possible under adverse conditions?

## Step 7: Document Findings
For each token integration issue found:
```
Token: [name/address]
Issue: [description]
Severity: [H/M/L]
Pattern: [fee-on-transfer / missing-return / rebase / etc.]
Fix: [recommended fix]
```

## Step 8: Verify with Testing
- Test with actual tokens on mainnet fork
- Test with fee-on-transfer mock
- Test with rebasing mock
- Test with pausable mock
- Test with zero-amount transfers
