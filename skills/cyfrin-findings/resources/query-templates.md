# Query Templates for Cyfrin/Solodit

## By Vulnerability Type
- `reentrancy cross-function` - Cross-function reentrancy findings
- `oracle manipulation flash loan` - Oracle + flash loan attacks
- `access control initialize` - Unprotected initializer findings
- `signature replay` - Signature replay vulnerabilities

## By Protocol Type
- `lending liquidation` - Lending protocol liquidation bugs
- `AMM slippage` - DEX slippage vulnerabilities
- `bridge message verification` - Bridge message validation issues
- `governance flash loan voting` - Governance flash loan attacks

## By Severity
- `severity:critical` - Critical findings only
- `severity:high oracle` - High severity oracle issues

## Combination Queries
- `lending oracle manipulation severity:critical` - Critical oracle bugs in lending
- `bridge replay chain:arbitrum` - Bridge replay on Arbitrum
- `vault inflation first depositor` - First depositor attacks on vaults
