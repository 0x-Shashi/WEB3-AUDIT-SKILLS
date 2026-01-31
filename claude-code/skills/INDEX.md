#  Security Findings Index

*Searchable index of all security patterns and findings*

---

##  Quick Navigation

- [Pattern Files](#pattern-files) - By vulnerability type
- [Severity Files](#severity-files) - By impact level
- [Source Files](#source-files) - By audit firm
- [Master Checklist](MASTER_CHECKLIST.md) - Prioritized checklist
- [Statistics](STATISTICS.md) - Comprehensive stats

---

## Pattern Files

Organized by vulnerability type:

| Vulnerability Type | Findings | File |
|-------------------|----------|------|
| Business Logic | 234 | [business-logic-patterns.md](patterns/business-logic-patterns.md) |
| Validation | 127 | [validation-patterns.md](patterns/validation-patterns.md) |
| Wrong Math | 107 | [wrong-math-patterns.md](patterns/wrong-math-patterns.md) |
| Front-Running | 106 | [front-running-patterns.md](patterns/front-running-patterns.md) |
| Fee On Transfer | 66 | [fee-on-transfer-patterns.md](patterns/fee-on-transfer-patterns.md) |
| DOS | 66 | [dos-patterns.md](patterns/dos-patterns.md) |
| Oracle | 59 | [oracle-patterns.md](patterns/oracle-patterns.md) |
| Reentrancy | 59 | [reentrancy-patterns.md](patterns/reentrancy-patterns.md) |
| Access Control | 48 | [access-control-patterns.md](patterns/access-control-patterns.md) |
| Don't update state | 47 | [don-t-update-state-patterns.md](patterns/don-t-update-state-patterns.md) |
| Decimals | 45 | [decimals-patterns.md](patterns/decimals-patterns.md) |
| Overflow/Underflow | 43 | [overflow-underflow-patterns.md](patterns/overflow-underflow-patterns.md) |
| Liquidation | 42 | [liquidation-patterns.md](patterns/liquidation-patterns.md) |
| Slippage | 36 | [slippage-patterns.md](patterns/slippage-patterns.md) |
| Denial-Of-Service | 36 | [denial-of-service-patterns.md](patterns/denial-of-service-patterns.md) |
| Admin | 36 | [admin-patterns.md](patterns/admin-patterns.md) |
| Missing-Logic | 33 | [missing-logic-patterns.md](patterns/missing-logic-patterns.md) |
| Rounding | 32 | [rounding-patterns.md](patterns/rounding-patterns.md) |
| Stale Price | 31 | [stale-price-patterns.md](patterns/stale-price-patterns.md) |
| ERC4626 | 28 | [erc4626-patterns.md](patterns/erc4626-patterns.md) |
| ERC20 | 27 | [erc20-patterns.md](patterns/erc20-patterns.md) |
| First Depositor Issue | 26 | [first-depositor-issue-patterns.md](patterns/first-depositor-issue-patterns.md) |
| Weird ERC20 | 26 | [weird-erc20-patterns.md](patterns/weird-erc20-patterns.md) |
| Flash Loan | 25 | [flash-loan-patterns.md](patterns/flash-loan-patterns.md) |
| Chainlink | 25 | [chainlink-patterns.md](patterns/chainlink-patterns.md) |
| Configuration | 24 | [configuration-patterns.md](patterns/configuration-patterns.md) |
| Missing Check | 23 | [missing-check-patterns.md](patterns/missing-check-patterns.md) |
| Vote | 22 | [vote-patterns.md](patterns/vote-patterns.md) |
| Uniswap | 22 | [uniswap-patterns.md](patterns/uniswap-patterns.md) |
| Fund Lock | 22 | [fund-lock-patterns.md](patterns/fund-lock-patterns.md) |
| ERC721 | 21 | [erc721-patterns.md](patterns/erc721-patterns.md) |
| Coding-Bug | 20 | [coding-bug-patterns.md](patterns/coding-bug-patterns.md) |
| Sandwich Attack | 19 | [sandwich-attack-patterns.md](patterns/sandwich-attack-patterns.md) |
| NFT | 19 | [nft-patterns.md](patterns/nft-patterns.md) |
| Deposit/Reward tokens | 18 | [deposit-reward-tokens-patterns.md](patterns/deposit-reward-tokens-patterns.md) |
| Gas Limit | 18 | [gas-limit-patterns.md](patterns/gas-limit-patterns.md) |
| Chain Reorganization Attack | 18 | [chain-reorganization-attack-patterns.md](patterns/chain-reorganization-attack-patterns.md) |
| Approve | 18 | [approve-patterns.md](patterns/approve-patterns.md) |
| Swap | 18 | [swap-patterns.md](patterns/swap-patterns.md) |
| Lending Pool | 17 | [lending-pool-patterns.md](patterns/lending-pool-patterns.md) |
| ERC1155 | 17 | [erc1155-patterns.md](patterns/erc1155-patterns.md) |
| Blacklisted | 16 | [blacklisted-patterns.md](patterns/blacklisted-patterns.md) |
| Auction | 15 | [auction-patterns.md](patterns/auction-patterns.md) |
| Initialization | 15 | [initialization-patterns.md](patterns/initialization-patterns.md) |
| Allowance | 15 | [allowance-patterns.md](patterns/allowance-patterns.md) |
| call vs transfer | 15 | [call-vs-transfer-patterns.md](patterns/call-vs-transfer-patterns.md) |
| Bypass limit | 15 | [bypass-limit-patterns.md](patterns/bypass-limit-patterns.md) |
| Precision Loss | 14 | [precision-loss-patterns.md](patterns/precision-loss-patterns.md) |
| Replay Attack | 14 | [replay-attack-patterns.md](patterns/replay-attack-patterns.md) |
| transferFrom vs safeTransferFrom | 14 | [transferfrom-vs-safetransferfrom-patterns.md](patterns/transferfrom-vs-safetransferfrom-patterns.md) |
| Type casting | 14 | [type-casting-patterns.md](patterns/type-casting-patterns.md) |
| SafeTransfer | 14 | [safetransfer-patterns.md](patterns/safetransfer-patterns.md) |
| Ownership | 13 | [ownership-patterns.md](patterns/ownership-patterns.md) |
| Grief Attack | 12 | [grief-attack-patterns.md](patterns/grief-attack-patterns.md) |
| Share Inflation | 12 | [share-inflation-patterns.md](patterns/share-inflation-patterns.md) |
| Refund Ether | 12 | [refund-ether-patterns.md](patterns/refund-ether-patterns.md) |
| ERC777 | 11 | [erc777-patterns.md](patterns/erc777-patterns.md) |
| Upgradable | 10 | [upgradable-patterns.md](patterns/upgradable-patterns.md) |
| Code Quality | 10 | [code-quality-patterns.md](patterns/code-quality-patterns.md) |
| Pause | 10 | [pause-patterns.md](patterns/pause-patterns.md) |
| TWAP | 10 | [twap-patterns.md](patterns/twap-patterns.md) |
| Initial Deposit | 9 | [initial-deposit-patterns.md](patterns/initial-deposit-patterns.md) |
| Timing | 9 | [timing-patterns.md](patterns/timing-patterns.md) |
| Vault | 9 | [vault-patterns.md](patterns/vault-patterns.md) |
| Payable | 9 | [payable-patterns.md](patterns/payable-patterns.md) |
| EIP-4626 | 9 | [eip-4626-patterns.md](patterns/eip-4626-patterns.md) |
| Min/Max Cap Validation | 9 | [min-max-cap-validation-patterns.md](patterns/min-max-cap-validation-patterns.md) |
| External Call | 8 | [external-call-patterns.md](patterns/external-call-patterns.md) |
| Cross Chain | 8 | [cross-chain-patterns.md](patterns/cross-chain-patterns.md) |
| Delegate | 8 | [delegate-patterns.md](patterns/delegate-patterns.md) |
| Pre/Post Balance | 7 | [pre-post-balance-patterns.md](patterns/pre-post-balance-patterns.md) |
| 0x | 7 | [0x-patterns.md](patterns/0x-patterns.md) |
| Check Return Value | 7 | [check-return-value-patterns.md](patterns/check-return-value-patterns.md) |
| Whitelist/Blacklist Match | 7 | [whitelist-blacklist-match-patterns.md](patterns/whitelist-blacklist-match-patterns.md) |
| LayerZero | 7 | [layerzero-patterns.md](patterns/layerzero-patterns.md) |
| Data Validation | 7 | [data-validation-patterns.md](patterns/data-validation-patterns.md) |
| External Contract | 7 | [external-contract-patterns.md](patterns/external-contract-patterns.md) |
| Broken Loop | 7 | [broken-loop-patterns.md](patterns/broken-loop-patterns.md) |
| Revert By Sending Dust | 7 | [revert-by-sending-dust-patterns.md](patterns/revert-by-sending-dust-patterns.md) |
| Bridge | 7 | [bridge-patterns.md](patterns/bridge-patterns.md) |
| 1/64 Rule | 6 | [1-64-rule-patterns.md](patterns/1-64-rule-patterns.md) |
| Account Abstraction | 6 | [account-abstraction-patterns.md](patterns/account-abstraction-patterns.md) |
| L2 Sequencer | 6 | [l2-sequencer-patterns.md](patterns/l2-sequencer-patterns.md) |
| from=to | 6 | [from-to-patterns.md](patterns/from-to-patterns.md) |
| Typo / CopyPaste | 6 | [typo-copypaste-patterns.md](patterns/typo-copypaste-patterns.md) |
| Change Validation | 6 | [change-validation-patterns.md](patterns/change-validation-patterns.md) |
| EIP-712 | 6 | [eip-712-patterns.md](patterns/eip-712-patterns.md) |
| Deadline | 6 | [deadline-patterns.md](patterns/deadline-patterns.md) |
| USDC | 6 | [usdc-patterns.md](patterns/usdc-patterns.md) |
| USDT | 6 | [usdt-patterns.md](patterns/usdt-patterns.md) |
| Event | 6 | [event-patterns.md](patterns/event-patterns.md) |
| Withdraw Pattern | 6 | [withdraw-pattern-patterns.md](patterns/withdraw-pattern-patterns.md) |
| Array | 6 | [array-patterns.md](patterns/array-patterns.md) |
| Read-only Reentrancy | 6 | [read-only-reentrancy-patterns.md](patterns/read-only-reentrancy-patterns.md) |
| Royalty | 6 | [royalty-patterns.md](patterns/royalty-patterns.md) |
| ERC2981 | 6 | [erc2981-patterns.md](patterns/erc2981-patterns.md) |
| Hardcoded Address | 6 | [hardcoded-address-patterns.md](patterns/hardcoded-address-patterns.md) |
| Arbitrum | 5 | [arbitrum-patterns.md](patterns/arbitrum-patterns.md) |
| EIP-165 | 5 | [eip-165-patterns.md](patterns/eip-165-patterns.md) |
| supportsInterface | 5 | [supportsinterface-patterns.md](patterns/supportsinterface-patterns.md) |
| Signature Malleability | 5 | [signature-malleability-patterns.md](patterns/signature-malleability-patterns.md) |
| Gas Price | 5 | [gas-price-patterns.md](patterns/gas-price-patterns.md) |
| Revert On 0 Transfer | 5 | [revert-on-0-transfer-patterns.md](patterns/revert-on-0-transfer-patterns.md) |
| Hardcoded Setting | 5 | [hardcoded-setting-patterns.md](patterns/hardcoded-setting-patterns.md) |
| mint vs safeMint | 5 | [mint-vs-safemint-patterns.md](patterns/mint-vs-safemint-patterns.md) |
| Dust | 5 | [dust-patterns.md](patterns/dust-patterns.md) |
| Update State After Admin Action | 5 | [update-state-after-admin-action-patterns.md](patterns/update-state-after-admin-action-patterns.md) |
| 51% Attack | 4 | [51-attack-patterns.md](patterns/51-attack-patterns.md) |
| ABI Encoding | 4 | [abi-encoding-patterns.md](patterns/abi-encoding-patterns.md) |
| Storage Gap | 4 | [storage-gap-patterns.md](patterns/storage-gap-patterns.md) |
| Documentation | 4 | [documentation-patterns.md](patterns/documentation-patterns.md) |
| msgSender | 4 | [msgsender-patterns.md](patterns/msgsender-patterns.md) |
| Merkle Tree | 4 | [merkle-tree-patterns.md](patterns/merkle-tree-patterns.md) |
| Nonce | 4 | [nonce-patterns.md](patterns/nonce-patterns.md) |
| Rebasing Tokens | 4 | [rebasing-tokens-patterns.md](patterns/rebasing-tokens-patterns.md) |
| Initializer | 4 | [initializer-patterns.md](patterns/initializer-patterns.md) |
| CheckPoint | 4 | [checkpoint-patterns.md](patterns/checkpoint-patterns.md) |
| Array Reorder | 4 | [array-reorder-patterns.md](patterns/array-reorder-patterns.md) |
| Optimism | 4 | [optimism-patterns.md](patterns/optimism-patterns.md) |
| Token Existence | 4 | [token-existence-patterns.md](patterns/token-existence-patterns.md) |
| Pegged | 4 | [pegged-patterns.md](patterns/pegged-patterns.md) |
| DAO | 4 | [dao-patterns.md](patterns/dao-patterns.md) |
| Revert Inside Hook | 4 | [revert-inside-hook-patterns.md](patterns/revert-inside-hook-patterns.md) |
| MinOut/MaxIn Validation | 3 | [minout-maxin-validation-patterns.md](patterns/minout-maxin-validation-patterns.md) |
| Protocol Reserve | 3 | [protocol-reserve-patterns.md](patterns/protocol-reserve-patterns.md) |
| Sense | 3 | [sense-patterns.md](patterns/sense-patterns.md) |
| Auditing and Logging | 3 | [auditing-and-logging-patterns.md](patterns/auditing-and-logging-patterns.md) |
| Block Period | 3 | [block-period-patterns.md](patterns/block-period-patterns.md) |
| Storage Collision | 3 | [storage-collision-patterns.md](patterns/storage-collision-patterns.md) |
| Transfer Result Check | 3 | [transfer-result-check-patterns.md](patterns/transfer-result-check-patterns.md) |
| Withdraw 0 | 3 | [withdraw-0-patterns.md](patterns/withdraw-0-patterns.md) |
| Collateral Factor | 3 | [collateral-factor-patterns.md](patterns/collateral-factor-patterns.md) |
| Cooldown | 3 | [cooldown-patterns.md](patterns/cooldown-patterns.md) |
| CEI | 3 | [cei-patterns.md](patterns/cei-patterns.md) |
| SafeApprove | 3 | [safeapprove-patterns.md](patterns/safeapprove-patterns.md) |
| Mapping | 3 | [mapping-patterns.md](patterns/mapping-patterns.md) |
| Time Rounding | 3 | [time-rounding-patterns.md](patterns/time-rounding-patterns.md) |
| Truncation | 3 | [truncation-patterns.md](patterns/truncation-patterns.md) |
| Approve Max | 3 | [approve-max-patterns.md](patterns/approve-max-patterns.md) |
| Immutable | 3 | [immutable-patterns.md](patterns/immutable-patterns.md) |


## Fractal Pattern Expansions (Phase 2)

- [Reentrancy Fractal Map](patterns/reentrancy/index.md)
	- [Classic reentrancy](patterns/reentrancy/classic-reentrancy.md)
	- [Cross-function reentrancy](patterns/reentrancy/cross-function-reentrancy.md)
	- [Cross-contract reentrancy](patterns/reentrancy/cross-contract-reentrancy.md)
	- [Read-only reentrancy](patterns/reentrancy/read-only-reentrancy.md)
	- [Reentrancy via token receiver hooks](patterns/reentrancy/callback-hook-reentrancy.md)


---

## Severity Files

| Severity | Findings | File |
|----------|----------|------|
| HIGH | 8022 | [high-severity.md](severity/high-severity.md) |
| MEDIUM | 13814 | [medium-severity.md](severity/medium-severity.md) |
| LOW | 25272 | [low-severity.md](severity/low-severity.md) |
| GAS | 3422 | [gas-optimizations.md](severity/gas-optimizations.md) |

---

## Source Files

Top audit firms by findings:

| Audit Firm | Findings | File |
|-----------|----------|------|
| Code4rena | 12292 | [code4rena.md](sources/code4rena.md) |
| Pashov Audit Group | 3452 | [pashov-audit-group.md](sources/pashov-audit-group.md) |
| Zokyo | 3376 | [zokyo.md](sources/zokyo.md) |
| OpenZeppelin | 3237 | [openzeppelin.md](sources/openzeppelin.md) |
| Sherlock | 3017 | [sherlock.md](sources/sherlock.md) |
| Cantina | 2932 | [cantina.md](sources/cantina.md) |
| Halborn | 2649 | [halborn.md](sources/halborn.md) |
| Quantstamp | 2443 | [quantstamp.md](sources/quantstamp.md) |
| MixBytes | 2437 | [mixbytes.md](sources/mixbytes.md) |
| OtterSec | 2273 | [ottersec.md](sources/ottersec.md) |
| Spearbit | 2224 | [spearbit.md](sources/spearbit.md) |
| Cyfrin | 2133 | [cyfrin.md](sources/cyfrin.md) |
| TrailOfBits | 2094 | [trailofbits.md](sources/trailofbits.md) |
| ConsenSys | 1395 | [consensys.md](sources/consensys.md) |
| Codehawks | 1234 | [codehawks.md](sources/codehawks.md) |


---

## Usage

### For AI Assistants
Reference these files when performing security audits:
1. Start with [MASTER_CHECKLIST.md](MASTER_CHECKLIST.md) for prioritized checks
2. Deep-dive into specific [patterns/](patterns/) for vulnerability details
3. Check [severity/](severity/) for impact-based analysis

### For Developers
1. Use as a security review checklist
2. Learn from real-world examples
3. Understand common vulnerability patterns

---

*Generated from 207 vulnerability types and 50,530 findings*

