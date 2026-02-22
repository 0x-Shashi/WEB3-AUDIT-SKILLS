# Token Analyzer Skill

## Purpose
Analyze ERC20/ERC721/ERC1155 token implementations for non-standard behavior, fee-on-transfer mechanics, rebasing logic, and integration risks.

## Detection Capabilities
- Fee-on-transfer tokens (deflationary)
- Rebasing tokens (elastic supply)
- Tokens with blacklists/whitelists (USDC, USDT)
- Tokens with pausable transfers
- Tokens with max transaction limits
- Missing return values (USDT-style)
- Tokens with callback hooks (ERC777)
- Tokens returning false instead of reverting
- Approval race conditions
- Double-entry point tokens (tusd-style)
- Tokens with admin mint/burn

## Why This Matters
Over $500M has been lost due to protocol assumptions about "standard" ERC20 behavior. Most tokens deviate from the standard in subtle ways that break DeFi integrations.

## Resources
- [Integration Patterns](resources/integration-patterns.md)
- [Weird Tokens List](resources/weird-tokens-list.md)

## Workflows
- [Token Analysis](workflows/token-analysis.md)
