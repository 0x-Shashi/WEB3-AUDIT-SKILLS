/**
 * TriggerEngine — Programmatic enforcement of trigger-based file routing
 * 
 * Converts user queries and code patterns into resolved file paths.
 * This replaces the passive TRIGGERS.md approach with active enforcement.
 * 
 * Usage:
 *   const engine = new TriggerEngine(skillsDir);
 *   const result = engine.resolve("audit my lending protocol");
 *   // → { files: [...], triggers: [...], priority: 'high' }
 * 
 *   const codeResult = engine.detectCodePatterns(soliditySource);
 *   // → { files: [...], detections: [...] }
 */

import { access, readFile } from 'fs/promises';
import { join } from 'path';

// ─── Trigger Registry ──────────────────────────────────────────────────────────
// Each trigger maps keywords to file targets with priority and category.
// This is the enforceable, programmatic version of TRIGGERS.md.

const TRIGGERS = [
  // ── Audit Initiation ──────────────────────────────────────────
  {
    id: 'audit-start',
    keywords: ['audit this', 'start audit', 'begin audit', 'how do i audit', 'audit workflow', 'audit methodology'],
    files: ['ROUTE-MAP.md', 'MASTER_CHECKLIST.md', 'methodology/llm-audit-workflow.md', 'consolidated/PATTERN-SUMMARIES.md'],
    category: 'initiation',
    priority: 1,
  },
  {
    id: 'first-time',
    keywords: ['first time', 'first audit', 'learn auditing', 'how to become auditor', 'beginner'],
    files: ['ROUTE-MAP.md', 'methodology/llm-audit-workflow.md', 'methodology/learning-path-attack-vectors.md', 'checklists/roles/auditor-first-pass.md', 'attack-trees/INDEX.md'],
    category: 'learning',
    priority: 1,
  },
  {
    id: 'pattern-overview',
    keywords: ['all patterns', 'pattern summary', 'vulnerability overview', 'what patterns', 'pattern index', 'full checklist'],
    files: ['consolidated/PATTERN-SUMMARIES.md', 'consolidated/QUICK-REFERENCE.md', 'MASTER_CHECKLIST.md'],
    category: 'initiation',
    priority: 2,
  },

  // ── Protocol-Specific ─────────────────────────────────────────
  {
    id: 'lending',
    keywords: ['lending', 'borrow', 'compound fork', 'aave fork', 'lend', 'borrowing', 'interest rate'],
    files: ['attack-trees/lending-attack-tree.md', 'patterns/lending-pool-patterns.md', 'patterns/oracle-patterns.md', 'patterns/interest-rate-patterns.md', 'patterns/liquidation-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'liquidation',
    keywords: ['liquidation', 'liquidate', 'health factor', 'bad debt', 'undercollateralized'],
    files: ['attack-trees/lending-attack-tree.md', 'patterns/liquidation-patterns.md', 'patterns/oracle-patterns.md'],
    category: 'protocol',
    priority: 2,
  },
  {
    id: 'dex-amm',
    keywords: ['dex', 'amm', 'swap', 'uniswap', 'liquidity pool', 'lp token'],
    files: ['attack-trees/dex-attack-tree.md', 'patterns/amm-patterns.md', 'patterns/swap-patterns.md', 'patterns/slippage-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'uniswap-v3',
    keywords: ['uniswap v3', 'uniswap v4', 'concentrated liquidity', 'tick'],
    files: ['attack-trees/dex-attack-tree.md', 'patterns/uniswap-patterns.md', 'patterns/hook-attacks.md'],
    category: 'protocol',
    priority: 2,
  },
  {
    id: 'curve',
    keywords: ['curve', 'stableswap', 'curve pool'],
    files: ['attack-trees/dex-attack-tree.md', 'protocol-playbooks/curve.md'],
    category: 'protocol',
    priority: 2,
  },
  {
    id: 'bridge',
    keywords: ['bridge', 'cross-chain', 'cross chain', 'message passing', 'wormhole', 'layerzero'],
    files: ['attack-trees/bridge-attack-tree.md', 'patterns/bridge-patterns.md', 'patterns/signature-malleability-patterns.md', 'patterns/replay-attack-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'vault',
    keywords: ['vault', 'yield', 'aggregator', 'erc4626', 'auto-compound', 'yearn', 'beefy'],
    files: ['attack-trees/vault-attack-tree.md', 'patterns/vault-patterns.md', 'patterns/erc4626-patterns.md', 'patterns/share-inflation-patterns.md', 'patterns/accounting-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'staking',
    keywords: ['staking', 'restaking', 'unstake', 'stake', 'validator', 'slashing', 'eigenlayer'],
    files: ['patterns/staking-patterns.md', 'patterns/restaking-attacks.md', 'patterns/reward-distribution-patterns.md', 'patterns/withdraw-pattern-patterns.md', 'patterns/delegate-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'nft',
    keywords: ['nft', 'erc721', 'erc1155', 'marketplace', 'auction', 'royalty'],
    files: ['patterns/nft-patterns.md', 'patterns/auction-patterns.md', 'patterns/royalty-patterns.md', 'patterns/reentrancy-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'governance',
    keywords: ['governance', 'dao', 'voting', 'vote', 'proposal', 'timelock', 'governor'],
    files: ['attack-trees/governance-attack-tree.md', 'patterns/dao-patterns.md', 'patterns/vote-patterns.md', 'patterns/timelock-patterns.md', 'patterns/access-control-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'perpetuals',
    keywords: ['perpetual', 'perp', 'perps', 'futures', 'margin', 'funding rate', 'leverage'],
    files: ['attack-trees/perpetuals-attack-tree.md', 'protocol-playbooks/hyperliquid.md', 'patterns/oracle-patterns.md', 'patterns/liquidation-patterns.md', 'patterns/funding-rate-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'options',
    keywords: ['options', 'call option', 'put option', 'strike price', 'expiry'],
    files: ['attack-trees/options-attack-tree.md', 'patterns/oracle-patterns.md', 'methodology/economic-attack-modeling.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'intents',
    keywords: ['intent', 'solver', 'order flow', 'cow protocol', 'cow swap', 'uniswapx', 'batch auction'],
    files: ['attack-trees/intent-based-attack-tree.md', 'patterns/intent-based-attacks.md', 'patterns/solver-patterns.md', 'patterns/signature-malleability-patterns.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'stablecoin',
    keywords: ['stablecoin', 'cdp', 'peg', 'depeg', 'makerdao', 'dai'],
    files: ['attack-trees/stablecoin-attack-tree.md', 'patterns/pegged-patterns.md', 'protocol-playbooks/makerdao.md'],
    category: 'protocol',
    priority: 1,
  },
  {
    id: 'insurance',
    keywords: ['insurance', 'insurance fund', 'coverage', 'claims'],
    files: ['attack-trees/insurance-attack-tree.md'],
    category: 'protocol',
    priority: 2,
  },

  // ── Vulnerability-Specific ────────────────────────────────────
  {
    id: 'oracle',
    keywords: ['oracle', 'price feed', 'chainlink', 'price manipulation', 'stale price', 'twap'],
    files: ['patterns/oracle-patterns.md', 'anti-patterns/oracle-anti-patterns.md', 'patterns/chainlink-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'reentrancy',
    keywords: ['reentrancy', 'reenter', 'reentra', 'callback', 'read-only reentrancy', 'cross-function'],
    files: ['patterns/reentrancy-patterns.md', 'anti-patterns/reentrancy-anti-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'access-control',
    keywords: ['access control', 'authorization', 'onlyowner', 'modifier', 'role', 'privilege', 'tx.origin'],
    files: ['patterns/access-control-patterns.md', 'anti-patterns/access-control-anti-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'flash-loan',
    keywords: ['flash loan', 'flashloan', 'flash borrow', 'atomic'],
    files: ['patterns/flash-loan-patterns.md', 'anti-patterns/flash-loan-anti-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'first-depositor',
    keywords: ['first depositor', 'inflation attack', 'share inflation', 'donate to pool', 'share price manipulation'],
    files: ['patterns/share-inflation-patterns.md', 'patterns/first-depositor-issue-patterns.md', 'anti-patterns/vault-specific-anti-patterns.md', 'attack-trees/vault-attack-tree.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'signature',
    keywords: ['signature', 'ecrecover', 'ecdsa', 'eip712', 'eip-712', 'malleability', 'signed message'],
    files: ['patterns/signature-malleability-patterns.md', 'patterns/eip-712-patterns.md', 'anti-patterns/signature-anti-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'front-running',
    keywords: ['front-running', 'frontrunning', 'front run', 'sandwich', 'mev', 'back-running', 'mempool'],
    files: ['patterns/front-running-patterns.md', 'patterns/sandwich-attack-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'overflow',
    keywords: ['overflow', 'underflow', 'unchecked', 'integer overflow', 'type casting'],
    files: ['patterns/overflow-underflow-patterns.md', 'patterns/type-casting-patterns.md'],
    category: 'vulnerability',
    priority: 2,
  },
  {
    id: 'dos',
    keywords: ['denial of service', 'dos', 'gas limit', 'unbounded loop', 'out of gas'],
    files: ['patterns/dos-patterns.md', 'patterns/gas-limit-patterns.md'],
    category: 'vulnerability',
    priority: 2,
  },
  {
    id: 'precision',
    keywords: ['precision', 'rounding', 'precision loss', 'truncation', 'decimal'],
    files: ['patterns/precision-loss-patterns.md', 'patterns/rounding-patterns.md', 'patterns/decimals-patterns.md'],
    category: 'vulnerability',
    priority: 2,
  },
  {
    id: 'upgradeable',
    keywords: ['upgradeable', 'proxy', 'upgrade', 'storage collision', 'implementation', 'uups', 'transparent proxy'],
    files: ['patterns/upgradable-patterns.md', 'patterns/storage-collision-patterns.md', 'methodology/upgrade-migration-patterns.md'],
    category: 'vulnerability',
    priority: 1,
  },
  {
    id: 'initializer',
    keywords: ['initialize', 'initializer', 'uninitialized', 'init front-run'],
    files: ['patterns/initializer-patterns.md', 'patterns/initialization-patterns.md', 'anti-patterns/access-control-anti-patterns.md'],
    category: 'vulnerability',
    priority: 2,
  },
  {
    id: 'erc20-weird',
    keywords: ['fee on transfer', 'rebasing', 'weird erc20', 'usdt', 'usdc', 'non-standard'],
    files: ['patterns/weird-erc20-patterns.md', 'patterns/fee-on-transfer-patterns.md', 'patterns/usdt-patterns.md', 'patterns/usdc-patterns.md'],
    category: 'vulnerability',
    priority: 2,
  },

  // ── Exploit Research ──────────────────────────────────────────
  {
    id: 'euler-hack',
    keywords: ['euler hack', 'euler exploit'],
    files: ['XREF.md', 'attack-trees/lending-attack-tree.md'],
    category: 'research',
    priority: 2,
  },
  {
    id: 'wormhole-hack',
    keywords: ['wormhole hack', 'wormhole exploit'],
    files: ['XREF.md', 'attack-trees/bridge-attack-tree.md'],
    category: 'research',
    priority: 2,
  },
  {
    id: 'ronin-hack',
    keywords: ['ronin hack', 'ronin bridge', 'ronin exploit'],
    files: ['XREF.md', 'attack-trees/bridge-attack-tree.md'],
    category: 'research',
    priority: 2,
  },
  {
    id: 'dao-hack',
    keywords: ['the dao hack', 'dao reentrancy', 'dao exploit'],
    files: ['XREF.md', 'anti-patterns/reentrancy-anti-patterns.md'],
    category: 'research',
    priority: 2,
  },
  {
    id: 'recent-exploits',
    keywords: ['recent exploits', 'latest hacks', 'recent hacks'],
    files: ['XREF.md'],
    category: 'research',
    priority: 2,
  },

  // ── Checklists ────────────────────────────────────────────────
  {
    id: 'checklist',
    keywords: ['checklist', 'what should i check', 'audit checklist'],
    files: ['MASTER_CHECKLIST.md', 'checklists/comprehensive-checklist.md'],
    category: 'checklist',
    priority: 1,
  },
  {
    id: 'pre-deployment',
    keywords: ['pre-deployment', 'before deploy', 'deployment checklist'],
    files: ['checklists/roles/developer-pre-deployment.md'],
    category: 'checklist',
    priority: 2,
  },
  {
    id: 'first-pass',
    keywords: ['first pass', 'quick scan', 'quick audit'],
    files: ['checklists/roles/auditor-first-pass.md'],
    category: 'checklist',
    priority: 2,
  },

  // ── Chain-Specific ────────────────────────────────────────────
  {
    id: 'solana',
    keywords: ['solana', 'anchor', 'solana audit', 'rust audit'],
    files: ['solana-scanner/SKILL.md', 'chain-guides/solana.md'],
    category: 'chain',
    priority: 1,
  },
  {
    id: 'starknet',
    keywords: ['starknet', 'cairo', 'felt252', 'cairo audit'],
    files: ['starknet-scanner/SKILL.md', 'cairo-scanner/SKILL.md', 'chain-guides/starknet.md'],
    category: 'chain',
    priority: 1,
  },
  {
    id: 'move',
    keywords: ['move', 'aptos', 'sui', 'move audit'],
    files: ['move-scanner/SKILL.md', 'sui-scanner/SKILL.md', 'aptos-scanner/SKILL.md', 'chain-guides/sui.md', 'chain-guides/aptos.md'],
    category: 'chain',
    priority: 1,
  },
  {
    id: 'ton',
    keywords: ['ton', 'tact', 'func', 'ton audit'],
    files: ['ton-scanner/SKILL.md'],
    category: 'chain',
    priority: 1,
  },
  {
    id: 'cosmos',
    keywords: ['cosmos', 'cosmwasm', 'ibc', 'cosmos audit'],
    files: ['cosmos-scanner/SKILL.md', 'chain-guides/cosmos.md'],
    category: 'chain',
    priority: 1,
  },
  {
    id: 'l2',
    keywords: ['layer 2', 'l2', 'arbitrum', 'optimism', 'base', 'zksync', 'scroll', 'linea', 'sequencer'],
    files: ['patterns/l2-security.md', 'patterns/l2-sequencer-patterns.md', 'chain-guides/arbitrum.md', 'chain-guides/optimism.md'],
    category: 'chain',
    priority: 2,
  },

  // ── Tool Usage ────────────────────────────────────────────────
  {
    id: 'slither',
    keywords: ['slither', 'static analysis'],
    files: ['static-analysis/SKILL.md', 'commands/SKILL.md'],
    category: 'tool',
    priority: 2,
  },
  {
    id: 'foundry',
    keywords: ['foundry', 'forge', 'foundry test', 'poc', 'proof of concept'],
    files: ['commands/SKILL.md', 'methodology/poc-writing-guide.md'],
    category: 'tool',
    priority: 2,
  },
];

// ─── Code Pattern Detectors ──────────────────────────────────────────────────
// These detect patterns in Solidity source code and recommend relevant files.

const CODE_PATTERNS = [
  {
    id: 'chainlink-oracle',
    pattern: /latestRoundData\s*\(/,
    label: 'Chainlink price feed detected',
    files: ['patterns/oracle-patterns.md', 'patterns/chainlink-patterns.md', 'anti-patterns/oracle-anti-patterns.md', 'patterns/stale-price-patterns.md'],
  },
  {
    id: 'initializer',
    pattern: /function\s+initialize\s*\(|initializer\b/,
    label: 'Initializer function detected',
    files: ['patterns/initializer-patterns.md', 'patterns/initialization-patterns.md', 'anti-patterns/access-control-anti-patterns.md'],
  },
  {
    id: 'nonreentrant',
    pattern: /nonReentrant|ReentrancyGuard/,
    label: 'Reentrancy guard detected (verify coverage)',
    files: ['patterns/reentrancy-patterns.md', 'anti-patterns/reentrancy-anti-patterns.md'],
  },
  {
    id: 'erc4626',
    pattern: /ERC4626|IERC4626|ERC-4626/,
    label: 'ERC4626 vault standard detected',
    files: ['patterns/erc4626-patterns.md', 'patterns/share-inflation-patterns.md', 'attack-trees/vault-attack-tree.md', 'patterns/accounting-patterns.md'],
  },
  {
    id: 'flash-loan',
    pattern: /flashLoan|flash\s*loan|IFlashLoanReceiver|IERC3156/,
    label: 'Flash loan interface detected',
    files: ['patterns/flash-loan-patterns.md', 'anti-patterns/flash-loan-anti-patterns.md'],
  },
  {
    id: 'ecrecover',
    pattern: /ecrecover\s*\(|ECDSA\.recover|SignatureChecker/,
    label: 'Signature verification detected',
    files: ['patterns/signature-malleability-patterns.md', 'patterns/eip-712-patterns.md', 'patterns/replay-attack-patterns.md', 'anti-patterns/signature-anti-patterns.md'],
  },
  {
    id: 'liquidation',
    pattern: /liquidat(?:e|ion)|healthFactor|isLiquidatable/i,
    label: 'Liquidation logic detected',
    files: ['patterns/liquidation-patterns.md', 'attack-trees/lending-attack-tree.md', 'patterns/oracle-patterns.md'],
  },
  {
    id: 'uniswap-v2',
    pattern: /IUniswapV2(?:Pair|Router|Factory)|UniswapV2Library/,
    label: 'Uniswap V2 integration detected',
    files: ['patterns/amm-patterns.md', 'patterns/swap-patterns.md', 'attack-trees/dex-attack-tree.md'],
  },
  {
    id: 'uniswap-v3',
    pattern: /IUniswapV3|slot0|sqrtPriceX96|ISwapRouter/,
    label: 'Uniswap V3 integration detected (check slot0 usage)',
    files: ['patterns/uniswap-patterns.md', 'patterns/amm-patterns.md', 'patterns/oracle-patterns.md', 'attack-trees/dex-attack-tree.md'],
  },
  {
    id: 'proxy',
    pattern: /UUPSUpgradeable|TransparentUpgradeableProxy|_implementation\(\)|delegatecall/,
    label: 'Upgradeable proxy pattern detected',
    files: ['patterns/upgradable-patterns.md', 'patterns/storage-collision-patterns.md', 'methodology/upgrade-migration-patterns.md'],
  },
  {
    id: 'merkle-proof',
    pattern: /MerkleProof|merkleRoot|verifyProof/,
    label: 'Merkle proof verification detected',
    files: ['patterns/merkle-tree-patterns.md'],
  },
  {
    id: 'erc721',
    pattern: /ERC721|onERC721Received|safeTransferFrom.*tokenId/,
    label: 'ERC721 token detected',
    files: ['patterns/nft-patterns.md', 'patterns/erc721-patterns.md', 'patterns/reentrancy-patterns.md'],
  },
  {
    id: 'erc1155',
    pattern: /ERC1155|onERC1155Received|onERC1155BatchReceived/,
    label: 'ERC1155 token detected',
    files: ['patterns/erc1155-patterns.md', 'patterns/reentrancy-patterns.md'],
  },
  {
    id: 'governance',
    pattern: /Governor|propose\s*\(|castVote|quorum|TimelockController/,
    label: 'Governance system detected',
    files: ['patterns/dao-patterns.md', 'patterns/vote-patterns.md', 'patterns/timelock-patterns.md', 'attack-trees/governance-attack-tree.md'],
  },
  {
    id: 'staking-reward',
    pattern: /rewardPerToken|earned\(|stake\s*\(|notifyRewardAmount/,
    label: 'Staking rewards system detected',
    files: ['patterns/staking-patterns.md', 'patterns/reward-distribution-patterns.md'],
  },
  {
    id: 'fee-on-transfer',
    pattern: /balanceOf\([^)]*\)\s*-\s*balance|_feeOnTransfer|deflation/i,
    label: 'Possible fee-on-transfer handling',
    files: ['patterns/fee-on-transfer-patterns.md', 'patterns/weird-erc20-patterns.md'],
  },
  {
    id: 'cross-chain-msg',
    pattern: /lzReceive|_nonblockingLzReceive|onMessageReceived|xDomainMessageSender/,
    label: 'Cross-chain messaging detected',
    files: ['patterns/bridge-patterns.md', 'patterns/cross-chain-patterns.md', 'patterns/layerzero-patterns.md'],
  },
  {
    id: 'funding-rate',
    pattern: /fundingRate|cumulativeFunding|premiumFraction/i,
    label: 'Funding rate mechanism detected',
    files: ['patterns/funding-rate-patterns.md', 'patterns/oracle-patterns.md', 'attack-trees/perpetuals-attack-tree.md'],
  },
  {
    id: 'intent-solver',
    pattern: /intent|solver|fillOrder|executeIntent|settleBatch/i,
    label: 'Intent/solver system detected',
    files: ['patterns/intent-based-attacks.md', 'patterns/solver-patterns.md', 'attack-trees/intent-based-attack-tree.md'],
  },
  {
    id: 'permit',
    pattern: /permit\s*\(|IERC20Permit|EIP2612/,
    label: 'ERC20 Permit detected',
    files: ['patterns/eip-712-patterns.md', 'patterns/signature-malleability-patterns.md', 'patterns/allowance-patterns.md'],
  },
  {
    id: 'unchecked-block',
    pattern: /unchecked\s*\{/,
    label: 'Unchecked arithmetic block detected',
    files: ['patterns/overflow-underflow-patterns.md', 'patterns/type-casting-patterns.md'],
  },
];


export class TriggerEngine {
  constructor(skillsDir) {
    this.skillsDir = skillsDir;
    this.triggers = TRIGGERS;
    this.codePatterns = CODE_PATTERNS;
  }

  /**
   * Resolve a user query to a list of recommended files and matched triggers.
   * 
   * @param {string} query — The user's natural language input
   * @returns {{ files: string[], triggers: object[], category: string }}
   */
  resolve(query) {
    const normalized = query.toLowerCase().trim();
    const matched = [];

    for (const trigger of this.triggers) {
      for (const keyword of trigger.keywords) {
        if (normalized.includes(keyword.toLowerCase())) {
          matched.push({
            triggerId: trigger.id,
            keyword,
            files: trigger.files,
            category: trigger.category,
            priority: trigger.priority,
          });
          break; // One match per trigger is enough
        }
      }
    }

    // Sort by priority (1 = highest)
    matched.sort((a, b) => a.priority - b.priority);

    // Deduplicate files while preserving priority order
    const seen = new Set();
    const files = [];
    for (const m of matched) {
      for (const f of m.files) {
        // Strip fragment identifiers for file resolution
        const cleanPath = f.split('#')[0];
        if (!seen.has(cleanPath)) {
          seen.add(cleanPath);
          files.push(cleanPath);
        }
      }
    }

    // Determine dominant category
    const categories = matched.map(m => m.category);
    const category = categories.length > 0
      ? categories.sort((a, b) =>
          categories.filter(c => c === b).length - categories.filter(c => c === a).length
        )[0]
      : 'general';

    return { files, triggers: matched, category };
  }

  /**
   * Validate that resolved files actually exist on disk.
   * Returns only files that exist, plus warnings for missing ones.
   * 
   * @param {string[]} files — Array of file paths relative to skills dir
   * @returns {Promise<{ valid: string[], missing: string[] }>}
   */
  async validateFiles(files) {
    const valid = [];
    const missing = [];

    for (const file of files) {
      const fullPath = join(this.skillsDir, file);
      try {
        await access(fullPath);
        valid.push(file);
      } catch {
        missing.push(file);
      }
    }

    return { valid, missing };
  }

  /**
   * Resolve a query and validate that all returned files exist.
   * This is the primary API for MCP tools — guaranteed no broken references.
   * 
   * @param {string} query — The user's input
   * @returns {Promise<{ files: string[], missing: string[], triggers: object[], category: string }>}
   */
  async resolveAndValidate(query) {
    const result = this.resolve(query);
    const { valid, missing } = await this.validateFiles(result.files);
    return {
      files: valid,
      missing,
      triggers: result.triggers,
      category: result.category,
    };
  }

  /**
   * Detect security-relevant patterns in Solidity source code.
   * Returns recommended files based on what the code actually does.
   * 
   * @param {string} sourceCode — Solidity source code
   * @returns {{ detections: object[], files: string[] }}
   */
  detectCodePatterns(sourceCode) {
    const detections = [];

    for (const cp of this.codePatterns) {
      if (cp.pattern.test(sourceCode)) {
        detections.push({
          id: cp.id,
          label: cp.label,
          files: cp.files,
        });
      }
    }

    // Deduplicate files
    const seen = new Set();
    const files = [];
    for (const d of detections) {
      for (const f of d.files) {
        if (!seen.has(f)) {
          seen.add(f);
          files.push(f);
        }
      }
    }

    return { detections, files };
  }

  /**
   * Detect code patterns and validate files exist.
   * 
   * @param {string} sourceCode — Solidity source code
   * @returns {Promise<{ detections: object[], files: string[], missing: string[] }>}
   */
  async detectAndValidate(sourceCode) {
    const result = this.detectCodePatterns(sourceCode);
    const { valid, missing } = await this.validateFiles(result.files);
    return {
      detections: result.detections,
      files: valid,
      missing,
    };
  }

  /**
   * Read and return the contents of resolved files.
   * This is the key method — it actually loads the files so the AI has them in context.
   * 
   * @param {string[]} filePaths — Validated file paths relative to skills dir
   * @param {object} options — { maxFiles: number, maxSizePerFile: number }
   * @returns {Promise<object[]>}
   */
  async loadFiles(filePaths, options = {}) {
    const { maxFiles = 10, maxSizePerFile = 50000 } = options;
    const toLoad = filePaths.slice(0, maxFiles);
    const loaded = [];

    for (const fp of toLoad) {
      try {
        const fullPath = join(this.skillsDir, fp);
        let content = await readFile(fullPath, 'utf8');
        if (content.length > maxSizePerFile) {
          content = content.slice(0, maxSizePerFile) + '\n\n... [truncated at ' + maxSizePerFile + ' chars]';
        }
        loaded.push({ path: fp, content, size: content.length });
      } catch {
        loaded.push({ path: fp, content: null, error: 'Failed to read file' });
      }
    }

    return loaded;
  }

  /**
   * Full pipeline: resolve query → validate → load files → return everything.
   * This is what the MCP tool calls.
   * 
   * @param {string} query — User's natural language input
   * @param {object} options — { loadContent: boolean, maxFiles: number }
   * @returns {Promise<object>}
   */
  async process(query, options = {}) {
    const { loadContent = true, maxFiles = 8 } = options;

    const resolved = await this.resolveAndValidate(query);

    if (resolved.files.length === 0) {
      return {
        success: false,
        message: 'No triggers matched the query. Try being more specific (e.g., "audit lending protocol", "reentrancy", "oracle manipulation").',
        suggestions: this.getSuggestions(),
      };
    }

    const result = {
      success: true,
      query,
      category: resolved.category,
      matchedTriggers: resolved.triggers.map(t => t.triggerId),
      files: resolved.files,
      fileCount: resolved.files.length,
    };

    if (resolved.missing.length > 0) {
      result.missingFiles = resolved.missing;
    }

    if (loadContent) {
      result.loadedFiles = await this.loadFiles(resolved.files, { maxFiles });
    }

    return result;
  }

  /**
   * Full pipeline for code analysis: detect patterns → validate → load files.
   * 
   * @param {string} sourceCode — Solidity source
   * @param {object} options — { loadContent: boolean, maxFiles: number }
   * @returns {Promise<object>}
   */
  async processCode(sourceCode, options = {}) {
    const { loadContent = true, maxFiles = 8 } = options;

    const detected = await this.detectAndValidate(sourceCode);

    if (detected.detections.length === 0) {
      return {
        success: true,
        message: 'No specific security patterns detected in code. Apply universal checks.',
        files: ['MASTER_CHECKLIST.md'],
        detections: [],
      };
    }

    const result = {
      success: true,
      detections: detected.detections.map(d => ({ id: d.id, label: d.label })),
      files: detected.files,
      fileCount: detected.files.length,
    };

    if (detected.missing.length > 0) {
      result.missingFiles = detected.missing;
    }

    if (loadContent) {
      result.loadedFiles = await this.loadFiles(detected.files, { maxFiles });
    }

    return result;
  }

  /**
   * Get suggestion categories for when no triggers match.
   */
  getSuggestions() {
    return [
      { category: 'Protocol', examples: ['lending', 'dex', 'bridge', 'vault', 'staking', 'governance', 'perpetuals', 'intents'] },
      { category: 'Vulnerability', examples: ['reentrancy', 'oracle', 'flash loan', 'access control', 'overflow', 'signature'] },
      { category: 'Chain', examples: ['solana', 'starknet', 'move', 'ton', 'cosmos'] },
      { category: 'Action', examples: ['audit this', 'checklist', 'first pass', 'learn auditing'] },
    ];
  }

  /**
   * List all available triggers (for introspection / CLI info).
   */
  listTriggers() {
    return this.triggers.map(t => ({
      id: t.id,
      keywords: t.keywords,
      fileCount: t.files.length,
      category: t.category,
    }));
  }

  /**
   * List all code pattern detectors (for introspection).
   */
  listCodePatterns() {
    return this.codePatterns.map(cp => ({
      id: cp.id,
      label: cp.label,
      fileCount: cp.files.length,
    }));
  }
}
