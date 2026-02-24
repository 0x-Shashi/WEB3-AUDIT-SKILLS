#  Solodit Findings Statistics

*Comprehensive analysis of 50,530 security findings*

---

## Overview

| Metric | Value |
|--------|-------|
| Total Findings | 50,530 |
| Unique Tags | 207 |
| Audit Firms | 30 |
| Protocol Categories | 33 |
| Protocols Audited | 2844 |

---

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | 0 | 0.00% |
| HIGH | 8022 | 15.88% |
| MEDIUM | 13814 | 27.34% |
| LOW | 25272 | 50.01% |
| GAS | 3422 | 6.77% |

> **Data Integrity Notes:**
>
> 1. **CRITICAL: 0 is a labeling artifact.** The Solodit API supports `critical` as a severity filter (see [DATA/APIdocs.txt](../DATA/APIdocs.txt)), but the extracted dataset returned 0 findings under this label. This likely means: (a) Solodit maps Critical-severity findings into the HIGH bucket for most contest platforms (Code4rena, Sherlock), or (b) the extraction query did not include `severity=critical` as a separate pass. Real-world audit reports from Spearbit, Zokyo, and others in this repository do reference Critical-severity findings — they are aggregated under HIGH in this dataset.
>
> 2. **GAS vs INFO mapping.** The Solodit API lists `info` as a valid severity, not `gas`. The GAS category (3,422 findings, 6.77%) likely corresponds to Solodit's `info` severity bucket, which includes both informational findings and gas optimizations. The label was changed during data processing to better reflect the content, as the majority of info-severity findings on competitive audit platforms are gas optimization reports.
>
> 3. **Tag coverage is sparse.** The Top 50 vulnerability types sum to approximately 2,100 tagged findings — only ~4.2% of the 50,530 total. The remaining ~96% of findings either have no tag, have tags outside the top 50, or are tagged with the protocol name rather than a vulnerability category. The `finding_count` values in pattern files reflect only the tagged subset from this dataset.

---

## Top 50 Vulnerability Types

| Rank | Vulnerability | Count | % of Total |
|------|--------------|-------|------------|
| 1 | Business Logic | 234 | 0.463% |
| 2 | Validation | 127 | 0.251% |
| 3 | Wrong Math | 107 | 0.212% |
| 4 | Front-Running | 106 | 0.210% |
| 5 | Fee On Transfer | 66 | 0.131% |
| 6 | DOS | 66 | 0.131% |
| 7 | Oracle | 59 | 0.117% |
| 8 | Reentrancy | 59 | 0.117% |
| 9 | Access Control | 48 | 0.095% |
| 10 | Don't update state | 47 | 0.093% |
| 11 | Decimals | 45 | 0.089% |
| 12 | Overflow/Underflow | 43 | 0.085% |
| 13 | Liquidation | 42 | 0.083% |
| 14 | Slippage | 36 | 0.071% |
| 15 | Denial-Of-Service | 36 | 0.071% |
| 16 | Admin | 36 | 0.071% |
| 17 | Missing-Logic | 33 | 0.065% |
| 18 | Rounding | 32 | 0.063% |
| 19 | Stale Price | 31 | 0.061% |
| 20 | ERC4626 | 28 | 0.055% |
| 21 | ERC20 | 27 | 0.053% |
| 22 | First Depositor Issue | 26 | 0.051% |
| 23 | Weird ERC20 | 26 | 0.051% |
| 24 | Flash Loan | 25 | 0.049% |
| 25 | Chainlink | 25 | 0.049% |
| 26 | Configuration | 24 | 0.047% |
| 27 | Missing Check | 23 | 0.046% |
| 28 | Vote | 22 | 0.044% |
| 29 | Uniswap | 22 | 0.044% |
| 30 | Fund Lock | 22 | 0.044% |
| 31 | ERC721 | 21 | 0.042% |
| 32 | Coding-Bug | 20 | 0.040% |
| 33 | Sandwich Attack | 19 | 0.038% |
| 34 | NFT | 19 | 0.038% |
| 35 | Deposit/Reward tokens | 18 | 0.036% |
| 36 | Gas Limit | 18 | 0.036% |
| 37 | Chain Reorganization Attack | 18 | 0.036% |
| 38 | Approve | 18 | 0.036% |
| 39 | Swap | 18 | 0.036% |
| 40 | Lending Pool | 17 | 0.034% |
| 41 | ERC1155 | 17 | 0.034% |
| 42 | Blacklisted | 16 | 0.032% |
| 43 | Auction | 15 | 0.030% |
| 44 | Initialization | 15 | 0.030% |
| 45 | Allowance | 15 | 0.030% |
| 46 | call vs transfer | 15 | 0.030% |
| 47 | Bypass limit | 15 | 0.030% |
| 48 | Precision Loss | 14 | 0.028% |
| 49 | Replay Attack | 14 | 0.028% |
| 50 | transferFrom vs safeTransferFrom | 14 | 0.028% |


---

## Top 20 Audit Firms

| Rank | Firm | Findings | % of Total |
|------|------|----------|------------|
| 1 | Code4rena | 12292 | 24.33% |
| 2 | Pashov Audit Group | 3452 | 6.83% |
| 3 | Zokyo | 3376 | 6.68% |
| 4 | OpenZeppelin | 3237 | 6.41% |
| 5 | Sherlock | 3017 | 5.97% |
| 6 | Cantina | 2932 | 5.80% |
| 7 | Halborn | 2649 | 5.24% |
| 8 | Quantstamp | 2443 | 4.83% |
| 9 | MixBytes | 2437 | 4.82% |
| 10 | OtterSec | 2273 | 4.50% |
| 11 | Spearbit | 2224 | 4.40% |
| 12 | Cyfrin | 2133 | 4.22% |
| 13 | TrailOfBits | 2094 | 4.14% |
| 14 | ConsenSys | 1395 | 2.76% |
| 15 | Codehawks | 1234 | 2.44% |
| 16 | SigmaPrime | 982 | 1.94% |
| 17 | Shieldify | 622 | 1.23% |
| 18 | Immunefi | 376 | 0.74% |
| 19 | Trust Security | 262 | 0.52% |
| 20 | Hexens | 228 | 0.45% |


---

## Top 20 Protocol Categories

| Rank | Category | Findings | % of Total |
|------|----------|----------|------------|
| 1 | Dexes | 11376 | 22.51% |
| 2 | CDP | 10648 | 21.07% |
| 3 | Services | 8460 | 16.74% |
| 4 | Cross Chain | 7672 | 15.18% |
| 5 | Yield | 5633 | 11.15% |
| 6 | Liquid Staking | 4414 | 8.74% |
| 7 | Bridge | 2690 | 5.32% |
| 8 | Yield Aggregator | 2507 | 4.96% |
| 9 | Staking Pool | 2130 | 4.22% |
| 10 | Synthetics | 2048 | 4.05% |
| 11 | RWA | 1987 | 3.93% |
| 12 | Launchpad | 1701 | 3.37% |
| 13 | Leveraged Farming | 1207 | 2.39% |
| 14 | Liquidity manager | 1161 | 2.30% |
| 15 | NFT Marketplace | 910 | 1.80% |
| 16 | Payments | 828 | 1.64% |
| 17 | Derivatives | 721 | 1.43% |
| 18 | Options Vault | 689 | 1.36% |
| 19 | Indexes | 668 | 1.32% |
| 20 | Privacy | 591 | 1.17% |


---

## Data Source

- **Provider**: Cyfrin Solodit API
- **Extraction Date**: 2026-01-29
- **Total Records**: 50,530

### Known Limitations

1. **Tag-based counts are a small subset.** The `finding_count` values used in pattern files (e.g., reentrancy: 59, oracle: 59) represent the number of findings tagged with that specific vulnerability label in the Solodit dataset. Two different vulnerability types can have the same tag count — this is coincidence from the dataset, not a copy-paste error. For example, both Oracle and Reentrancy have exactly 59 tagged findings.

2. **Consolidated pattern files inherit single-pattern counts.** Files in `consolidated/` (e.g., `dos-gas-patterns.md`) currently show the `finding_count` from one constituent sub-pattern rather than the sum of all merged patterns. These counts are labeled `finding_count_source` to indicate they reference the primary constituent pattern, not the full consolidated scope.

3. **Extraction data files are empty.** The files in `EXTRACED SOLODIT DATA/` (JSON checkpoints) are 0-byte placeholders. The raw extracted data was processed into the statistics and pattern files but the raw JSON was not retained in the repository (likely due to file size constraints for Git).

