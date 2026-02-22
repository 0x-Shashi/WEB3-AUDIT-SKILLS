# Context Detection Skill

## Purpose
Automatically identify the type of protocol being audited to load appropriate checklists, templates, and vulnerability patterns without manual configuration.

## Detection Signals

### DeFi Lending Protocol
```
Signals:
- Functions: deposit, withdraw, borrow, repay, liquidate
- State: collateralFactor, borrowRate, totalBorrows, totalReserves
- Imports: InterestRateModel, PriceOracle
- Patterns: health factor calculations, LTV ratios
→ Load: lending-template, defi-lending-checklist, oracle-chains
```

### DEX / AMM
```
Signals:
- Functions: swap, addLiquidity, removeLiquidity, getAmountOut
- State: reserve0, reserve1, totalLiquidity, fee
- Imports: IUniswapV2Pair, IUniswapV3Pool
- Patterns: constant product (x*y=k), concentrated liquidity, tick math
→ Load: amm-dex-template, dex-amm-checklist, flash-loan-chains
```

### Bridge
```
Signals:
- Functions: sendMessage, receiveMessage, relayMessage, verifyProof
- State: nonce, messageHash, guardians, threshold
- Imports: MessageVerifier, CrossChainMessenger
- Patterns: lock-mint-burn-unlock, validator signatures
→ Load: bridge-template, bridge-checklist, bridge-chains
```

### Governance
```
Signals:
- Functions: propose, vote, execute, queue, cancel
- State: proposals, votingPower, quorum, timelock
- Imports: GovernorAlpha, GovernorBravo, TimelockController
- Patterns: proposal lifecycle, voting snapshots, delegation
→ Load: governance-checklist, governance-chains
```

### Staking
```
Signals:
- Functions: stake, unstake, claim, getReward
- State: rewardRate, rewardPerToken, totalStaked
- Imports: StakingRewards, MasterChef
- Patterns: reward accumulation per share, lock periods
→ Load: staking-template, staking-checklist
```

### NFT / Gaming
```
Signals:
- Functions: mint, burn, tokenURI, onERC721Received
- State: tokenId, baseURI, maxSupply, royaltyInfo
- Imports: ERC721, ERC1155, VRF
- Patterns: merkle proof minting, reveal mechanics, randomness
→ Load: nft-marketplace-template, nft-gaming-checklist
```

### Vault / Yield
```
Signals:
- Functions: deposit, withdraw, harvest, compound
- State: totalAssets, totalShares, strategy
- Imports: ERC4626, Strategy
- Patterns: share/asset conversion, yield strategies
→ Load: defi-patterns, staking-checklist
```

## Detection Algorithm
1. Scan all contract interfaces (function signatures)
2. Scan import statements
3. Scan state variable names
4. Match against known protocol type signatures
5. Return ranked list of protocol types with confidence scores
6. Load templates for highest-confidence match

## Multiple Protocol Types
Many protocols combine multiple types (e.g., lending + staking + governance). When multiple types detected:
1. Load ALL matching templates
2. Prioritize by detection confidence
3. Add cross-module interaction checks
4. Apply comprehensive checklist as baseline
