# ERC Standards Reference

## ERC-20 (Fungible Token)
Required: `totalSupply()`, `balanceOf()`, `transfer()`, `approve()`, `allowance()`, `transferFrom()`
Events: `Transfer`, `Approval`
Common issues: missing return values, approve race condition

## ERC-721 (Non-Fungible Token)
Required: `balanceOf()`, `ownerOf()`, `safeTransferFrom()`, `transferFrom()`, `approve()`, `getApproved()`, `setApprovalForAll()`, `isApprovedForAll()`
Events: `Transfer`, `Approval`, `ApprovalForAll`
Must implement: `onERC721Received` callback for safe transfers

## ERC-1155 (Multi-Token)
Required: `balanceOf()`, `balanceOfBatch()`, `safeTransferFrom()`, `safeBatchTransferFrom()`, `setApprovalForAll()`, `isApprovedForAll()`
Events: `TransferSingle`, `TransferBatch`, `ApprovalForAll`, `URI`

## ERC-4626 (Tokenized Vault)
Required: `asset()`, `totalAssets()`, `deposit()`, `mint()`, `withdraw()`, `redeem()`, `convertToShares()`, `convertToAssets()`, `maxDeposit()`, `maxMint()`, `maxWithdraw()`, `maxRedeem()`, `previewDeposit()`, `previewMint()`, `previewWithdraw()`, `previewRedeem()`
Key risk: first depositor inflation attack, rounding direction

## EIP-2612 (Permit)
Required: `permit()`, `nonces()`, `DOMAIN_SEPARATOR()`
Key risk: signature replay, frontrunning permit + transferFrom

## EIP-2981 (Royalty)
Required: `royaltyInfo(tokenId, salePrice)` returns (receiver, royaltyAmount)
Note: not enforceable on-chain (informational standard)
