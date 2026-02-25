/**
 * Adapters barrel export + factory
 */

import { ClaudeCodeAdapter } from './claude-adapter.js';
import { CursorAdapter } from './cursor-adapter.js';
import { GenericAdapter } from './generic-adapter.js';

export { BaseAdapter } from './base-adapter.js';
export { ClaudeCodeAdapter } from './claude-adapter.js';
export { CursorAdapter } from './cursor-adapter.js';
export { GenericAdapter } from './generic-adapter.js';

/**
 * Get the appropriate adapter for the detected platform
 * @param {string} platform - Platform name or 'auto'
 * @returns {BaseAdapter} Adapter instance
 */
export function createAdapter(platform = 'auto') {
  switch (platform.toLowerCase()) {
    case 'claude':
    case 'claude-code':
    case 'claude-desktop':
      return new ClaudeCodeAdapter();
    case 'cursor':
      return new CursorAdapter();
    case 'generic':
    case 'copilot':
    case 'chatgpt':
    case 'aider':
    case 'cli':
      return new GenericAdapter();
    case 'auto':
    default:
      return new GenericAdapter(); // Safe default
  }
}

/**
 * List all available adapters
 */
export function listAdapters() {
  return [
    { name: 'claude-code', label: 'Claude Code / Claude Desktop', features: ['MCP tools', 'direct execution', 'streaming'] },
    { name: 'cursor', label: 'Cursor IDE', features: ['.cursorrules generation', 'terminal commands'] },
    { name: 'generic', label: 'Generic (any AI)', features: ['markdown output', 'CLI commands', 'copy-paste prompts'] }
  ];
}
