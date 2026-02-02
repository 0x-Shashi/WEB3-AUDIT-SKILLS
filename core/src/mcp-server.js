#!/usr/bin/env node
/**
 * Web3 Audit Skills - MCP Server
 * 
 * Model Context Protocol server for real-time pattern matching.
 * Allows AI assistants to query vulnerability patterns during audits.
 * 
 * Usage:
 *   node src/mcp-server.js
 * 
 * Or add to Claude Desktop config:
 *   {
 *     "mcpServers": {
 *       "web3-audit": {
 *         "command": "node",
 *         "args": ["/path/to/core/src/mcp-server.js"]
 *       }
 *     }
 *   }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

import { PatternMatcher, matchPatternToCode } from './intelligence/pattern-matcher.js';
import { SeverityScorer, calculateSeverity } from './intelligence/severity-scorer.js';
import { VulnerabilityClassifier, classifyVulnerability } from './intelligence/vulnerability-classifier.js';
import { SemanticSearch, searchPatterns } from './intelligence/semantic-search.js';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKILLS_DIR = join(__dirname, '../../skills');

// Initialize components
const patternMatcher = new PatternMatcher(SKILLS_DIR);
const severityScorer = new SeverityScorer();
const classifier = new VulnerabilityClassifier();
const semanticSearch = new SemanticSearch(SKILLS_DIR);

/**
 * Create MCP Server
 */
const server = new Server(
  {
    name: 'web3-audit-skills',
    version: '1.0.0'
  },
  {
    capabilities: {
      tools: {},
      resources: {}
    }
  }
);

/**
 * List available tools
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'match_vulnerabilities',
        description: 'Analyze Solidity code for known vulnerability patterns. Returns matches with severity, line numbers, and recommended fixes.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'Solidity source code to analyze'
            },
            category: {
              type: 'string',
              description: 'Optional: Filter by category (reentrancy, oracle, accessControl, arithmetic, flashLoan, externalCalls, signatures)',
              enum: ['reentrancy', 'oracle', 'accessControl', 'arithmetic', 'flashLoan', 'externalCalls', 'signatures']
            }
          },
          required: ['code']
        }
      },
      {
        name: 'calculate_severity',
        description: 'Calculate CVSS-like severity score for a vulnerability based on its characteristics.',
        inputSchema: {
          type: 'object',
          properties: {
            vulnType: {
              type: 'string',
              description: 'Vulnerability type for quick estimation (reentrancy, oracle-manipulation, access-control, integer-overflow, front-running, dos)'
            },
            factors: {
              type: 'object',
              description: 'Detailed factors for precise calculation',
              properties: {
                attackComplexity: { type: 'string', enum: ['LOW', 'HIGH'] },
                privilegesRequired: { type: 'string', enum: ['NONE', 'LOW', 'HIGH'] },
                fundsAtRisk: { type: 'string', enum: ['NONE', 'LIMITED', 'SIGNIFICANT', 'TOTAL'] },
                reversibility: { type: 'string', enum: ['REVERSIBLE', 'IRREVERSIBLE'] }
              }
            }
          }
        }
      },
      {
        name: 'classify_vulnerability',
        description: 'Classify a vulnerability description or code snippet into categories with CWE/SWC mappings.',
        inputSchema: {
          type: 'object',
          properties: {
            input: {
              type: 'string',
              description: 'Vulnerability description or code snippet'
            },
            type: {
              type: 'string',
              description: 'Input type',
              enum: ['description', 'code'],
              default: 'description'
            }
          },
          required: ['input']
        }
      },
      {
        name: 'search_patterns',
        description: 'Search for relevant vulnerability patterns, attack trees, and methodology guides.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (e.g., "flash loan oracle manipulation", "reentrancy callback")'
            },
            category: {
              type: 'string',
              description: 'Optional: Limit search to category (patterns, attack-trees, methodology, fix-patterns)'
            },
            limit: {
              type: 'number',
              description: 'Maximum results to return',
              default: 5
            }
          },
          required: ['query']
        }
      },
      {
        name: 'get_attack_tree',
        description: 'Get full attack tree for a vulnerability category.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Attack tree category',
              enum: ['reentrancy', 'oracle', 'access-control', 'flash-loan', 'arithmetic', 'signature', 'governance', 'bridge', 'amm', 'lending', 'staking', 'nft']
            }
          },
          required: ['category']
        }
      },
      {
        name: 'get_fix_verification',
        description: 'Get fix verification guide for a vulnerability type.',
        inputSchema: {
          type: 'object',
          properties: {
            vulnType: {
              type: 'string',
              description: 'Vulnerability type',
              enum: ['reentrancy', 'oracle', 'access-control']
            }
          },
          required: ['vulnType']
        }
      },
      {
        name: 'get_protocol_playbook',
        description: 'Get audit playbook for a specific protocol type.',
        inputSchema: {
          type: 'object',
          properties: {
            protocol: {
              type: 'string',
              description: 'Protocol type',
              enum: ['amm', 'lending', 'staking', 'bridge', 'governance', 'vault', 'nft', 'oracle', 'perpetuals', 'options']
            }
          },
          required: ['protocol']
        }
      }
    ]
  };
});

/**
 * Handle tool calls
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'match_vulnerabilities': {
        const { code, category } = args;
        
        let matches;
        if (category) {
          matches = patternMatcher.matchCategory(code, category);
        } else {
          matches = patternMatcher.matchAll(code);
        }
        
        const summary = patternMatcher.getSummary(matches);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ matches, summary }, null, 2)
          }]
        };
      }

      case 'calculate_severity': {
        const { vulnType, factors } = args;
        
        let result;
        if (vulnType) {
          result = severityScorer.estimateFromType(vulnType);
        } else if (factors) {
          result = severityScorer.calculate(factors);
        } else {
          result = { error: 'Provide either vulnType or factors' };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        };
      }

      case 'classify_vulnerability': {
        const { input, type = 'description' } = args;
        const result = classifyVulnerability(input, type);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        };
      }

      case 'search_patterns': {
        const { query, category, limit = 5 } = args;
        const results = await semanticSearch.search(query, { category, limit });
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2)
          }]
        };
      }

      case 'get_attack_tree': {
        const { category } = args;
        const filePath = join(SKILLS_DIR, `attack-trees/${category}-attack-tree.md`);
        
        if (existsSync(filePath)) {
          const content = readFileSync(filePath, 'utf-8');
          return {
            content: [{
              type: 'text',
              text: content
            }]
          };
        } else {
          return {
            content: [{
              type: 'text',
              text: `Attack tree not found for category: ${category}`
            }]
          };
        }
      }

      case 'get_fix_verification': {
        const { vulnType } = args;
        const filePath = join(SKILLS_DIR, `fix-patterns/${vulnType}-fix-verification.md`);
        
        if (existsSync(filePath)) {
          const content = readFileSync(filePath, 'utf-8');
          return {
            content: [{
              type: 'text',
              text: content
            }]
          };
        } else {
          return {
            content: [{
              type: 'text',
              text: `Fix verification guide not found for: ${vulnType}`
            }]
          };
        }
      }

      case 'get_protocol_playbook': {
        const { protocol } = args;
        const filePath = join(SKILLS_DIR, `playbooks/${protocol}-playbook.md`);
        
        if (existsSync(filePath)) {
          const content = readFileSync(filePath, 'utf-8');
          return {
            content: [{
              type: 'text',
              text: content
            }]
          };
        } else {
          return {
            content: [{
              type: 'text',
              text: `Playbook not found for protocol: ${protocol}`
            }]
          };
        }
      }

      default:
        return {
          content: [{
            type: 'text',
            text: `Unknown tool: ${name}`
          }],
          isError: true
        };
    }
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: `Error: ${error.message}`
      }],
      isError: true
    };
  }
});

/**
 * List available resources
 */
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: 'skills://patterns',
        name: 'Vulnerability Patterns',
        description: 'All vulnerability pattern files',
        mimeType: 'text/markdown'
      },
      {
        uri: 'skills://attack-trees',
        name: 'Attack Trees',
        description: 'Systematic attack exploration guides',
        mimeType: 'text/markdown'
      },
      {
        uri: 'skills://methodology',
        name: 'Audit Methodology',
        description: 'Audit workflow and methodology guides',
        mimeType: 'text/markdown'
      },
      {
        uri: 'skills://fix-patterns',
        name: 'Fix Verification',
        description: 'Fix verification guides',
        mimeType: 'text/markdown'
      }
    ]
  };
});

/**
 * Read resource content
 */
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;
  
  // Parse URI: skills://category or skills://category/file
  const match = uri.match(/^skills:\/\/([^\/]+)(?:\/(.+))?$/);
  
  if (!match) {
    throw new Error(`Invalid resource URI: ${uri}`);
  }
  
  const [, category, file] = match;
  const categoryPath = join(SKILLS_DIR, category);
  
  if (file) {
    const filePath = join(categoryPath, file);
    if (existsSync(filePath)) {
      return {
        contents: [{
          uri,
          mimeType: 'text/markdown',
          text: readFileSync(filePath, 'utf-8')
        }]
      };
    }
  } else {
    // Return index of category
    const indexPath = join(categoryPath, 'INDEX.md');
    if (existsSync(indexPath)) {
      return {
        contents: [{
          uri,
          mimeType: 'text/markdown',
          text: readFileSync(indexPath, 'utf-8')
        }]
      };
    }
  }
  
  throw new Error(`Resource not found: ${uri}`);
});

/**
 * Start server
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Web3 Audit Skills MCP Server running...');
}

main().catch(console.error);
