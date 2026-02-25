/**
 * Base AI Adapter — Abstract interface for AI assistant integration
 * 
 * Defines the contract that any AI-platform adapter must implement.
 * This decouples the audit workflow from any specific AI assistant,
 * so the same scan → analyze → report pipeline works with Claude Code,
 * Cursor, Copilot, Aider, generic OpenAI, or CLI-only mode.
 * 
 * @module adapter-base
 */

/**
 * @abstract
 */
export class BaseAdapter {
  constructor(name, options = {}) {
    if (new.target === BaseAdapter) {
      throw new Error('BaseAdapter is abstract — use a concrete adapter');
    }
    this.name = name;
    this.options = options;
    this.skills = null;
    this.tools = null;
  }

  /**
   * Initialize the adapter with skills directory and tool runners
   * @param {Object} context - { skillsDir, rootDir, pluginJson }
   */
  async initialize(context) {
    this.context = context;
    this.skillsDir = context.skillsDir;
    this.rootDir = context.rootDir;
  }

  /**
   * Get the workflow prompt for a given phase
   * Must format appropriately for the target AI platform.
   * 
   * @abstract
   * @param {string} phase - Workflow phase name
   * @param {Object} context - Phase-specific context
   * @returns {string|Object} Formatted prompt/instruction
   */
  getPhasePrompt(phase, context) {
    throw new Error('getPhasePrompt() must be implemented');
  }

  /**
   * Feed scan results (Slither/Aderyn/Mythril) to the AI
   * Each adapter formats this differently.
   * 
   * @abstract
   * @param {Object} results - Scan results from tool runners
   * @returns {string|Object} Formatted for the AI platform
   */
  formatScanResults(results) {
    throw new Error('formatScanResults() must be implemented');
  }

  /**
   * Get the system prompt / instructions for this adapter
   * @abstract
   * @returns {string}
   */
  getSystemPrompt() {
    throw new Error('getSystemPrompt() must be implemented');
  }

  /**
   * Check if this adapter can execute tool commands directly
   * (e.g., MCP server can, Cursor rules file cannot)
   */
  canExecuteTools() {
    return false;
  }

  /**
   * Get adapter capabilities
   */
  getCapabilities() {
    return {
      name: this.name,
      canExecuteTools: this.canExecuteTools(),
      hasSystemPrompt: true,
      hasPhasePrompts: true,
      supportsStreaming: false,
      supportsMCP: false
    };
  }
}

export default BaseAdapter;
