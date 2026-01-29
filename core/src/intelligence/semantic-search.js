/**
 * Semantic Search Engine
 * 
 * Vector embeddings for code similarity and vulnerability search.
 * Uses local embeddings when possible, with OpenAI fallback.
 * 
 * Usage:
 *   const engine = new SemanticSearch();
 *   await engine.init();
 *   const similar = await engine.findSimilar(code, findings);
 */

const crypto = require('crypto');

class SemanticSearch {
  constructor(options = {}) {
    this.embeddingDimension = options.dimension || 384;
    this.useOpenAI = options.useOpenAI || false;
    this.openAIKey = options.openAIKey || process.env.OPENAI_API_KEY;
    this.cache = new Map();
    this.cacheMaxSize = options.cacheSize || 1000;
    
    // Token patterns for code analysis
    this.codePatterns = {
      solidity: {
        keywords: ['function', 'contract', 'modifier', 'event', 'mapping', 'struct', 'enum', 'require', 'assert', 'revert'],
        securityKeywords: ['transfer', 'call', 'delegatecall', 'selfdestruct', 'msg.sender', 'tx.origin', 'block.timestamp', 'balance'],
        operators: ['=', '==', '!=', '>', '<', '>=', '<=', '+', '-', '*', '/', '%'],
        types: ['uint256', 'address', 'bytes32', 'bool', 'string', 'bytes']
      },
      rust: {
        keywords: ['fn', 'pub', 'struct', 'impl', 'trait', 'mod', 'use', 'let', 'mut', 'match', 'if', 'else'],
        securityKeywords: ['invoke', 'invoke_signed', 'transfer', 'AccountInfo', 'ProgramResult', 'Pubkey'],
        operators: ['=', '==', '!=', '>', '<', '>=', '<=', '+', '-', '*', '/'],
        types: ['u64', 'u128', 'i64', 'bool', 'String', 'Vec']
      }
    };
  }

  /**
   * Initialize the semantic search engine
   */
  async init() {
    // Pre-compute common pattern embeddings
    this.patternEmbeddings = new Map();
    
    const commonPatterns = [
      'reentrancy vulnerability external call before state update',
      'access control missing authorization check',
      'integer overflow arithmetic without bounds check',
      'oracle manipulation flash loan price',
      'front running sandwich attack MEV',
      'signature replay attack validation',
      'delegate call proxy upgrade vulnerability',
      'selfdestruct unprotected destruction',
      'timestamp manipulation block.timestamp',
      'denial of service gas limit loop'
    ];

    for (const pattern of commonPatterns) {
      this.patternEmbeddings.set(pattern, await this._generateEmbedding(pattern));
    }

    return this;
  }

  /**
   * Generate embedding for text
   * 
   * @param {string} text - Text to embed
   * @returns {Promise<Array>} Embedding vector
   */
  async _generateEmbedding(text) {
    // Check cache first
    const cacheKey = this._hashText(text);
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    let embedding;

    if (this.useOpenAI && this.openAIKey) {
      embedding = await this._generateOpenAIEmbedding(text);
    } else {
      // Use local TF-IDF based embedding
      embedding = this._generateLocalEmbedding(text);
    }

    // Cache the result
    this._addToCache(cacheKey, embedding);

    return embedding;
  }

  /**
   * Generate embedding using OpenAI API
   * @private
   */
  async _generateOpenAIEmbedding(text) {
    try {
      const axios = require('axios');
      const response = await axios.post(
        'https://api.openai.com/v1/embeddings',
        {
          model: 'text-embedding-3-small',
          input: text.slice(0, 8000) // API limit
        },
        {
          headers: {
            'Authorization': `Bearer ${this.openAIKey}`,
            'Content-Type': 'application/json'
          }
        }
      );
      return response.data.data[0].embedding;
    } catch (error) {
      console.warn('OpenAI embedding failed, falling back to local:', error.message);
      return this._generateLocalEmbedding(text);
    }
  }

  /**
   * Generate local TF-IDF based embedding
   * Uses a custom approach optimized for code and security text
   * @private
   */
  _generateLocalEmbedding(text) {
    const normalized = text.toLowerCase();
    const tokens = this._tokenize(normalized);
    
    // Create embedding vector
    const embedding = new Array(this.embeddingDimension).fill(0);
    
    // Token frequency features (first half of embedding)
    const tokenFreq = this._getTokenFrequency(tokens);
    const freqDim = Math.floor(this.embeddingDimension / 2);
    
    let i = 0;
    for (const [token, freq] of Object.entries(tokenFreq).slice(0, freqDim)) {
      // Hash-based index assignment
      const idx = this._hashToIndex(token, freqDim);
      embedding[idx] += freq * this._getIDF(token);
      i++;
    }

    // N-gram features (second half)
    const ngrams = this._getNGrams(tokens, 2);
    const ngramDim = Math.floor(this.embeddingDimension / 2);
    
    for (const ngram of ngrams) {
      const idx = freqDim + this._hashToIndex(ngram, ngramDim);
      embedding[idx] += 1;
    }

    // Security keyword boost
    for (const keyword of this._getSecurityKeywords()) {
      if (normalized.includes(keyword)) {
        const idx = this._hashToIndex(`sec_${keyword}`, this.embeddingDimension);
        embedding[idx] += 2.0;
      }
    }

    // Normalize embedding
    return this._normalizeVector(embedding);
  }

  /**
   * Tokenize text for embedding
   * @private
   */
  _tokenize(text) {
    // Remove comments
    let cleaned = text.replace(/\/\/.*$/gm, '');
    cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '');
    
    // Split on non-alphanumeric characters
    const tokens = cleaned.split(/[^a-zA-Z0-9_]+/).filter(t => t.length > 1);
    
    // Also split camelCase
    const expanded = [];
    for (const token of tokens) {
      const parts = token.split(/(?=[A-Z])/);
      expanded.push(...parts.map(p => p.toLowerCase()));
    }
    
    return expanded.filter(t => t.length > 1);
  }

  /**
   * Get token frequency map
   * @private
   */
  _getTokenFrequency(tokens) {
    const freq = {};
    for (const token of tokens) {
      freq[token] = (freq[token] || 0) + 1;
    }
    return freq;
  }

  /**
   * Get IDF-like weight for token
   * @private
   */
  _getIDF(token) {
    // Common code keywords get lower weight
    const commonTokens = ['function', 'return', 'if', 'else', 'for', 'while', 'let', 'const', 'var', 'public', 'private', 'internal', 'external'];
    if (commonTokens.includes(token)) return 0.5;
    
    // Security keywords get higher weight
    const securityTokens = this._getSecurityKeywords();
    if (securityTokens.includes(token)) return 2.0;
    
    return 1.0;
  }

  /**
   * Get security-related keywords
   * @private
   */
  _getSecurityKeywords() {
    return [
      'reentrancy', 'overflow', 'underflow', 'access', 'control',
      'transfer', 'call', 'delegatecall', 'selfdestruct', 'suicide',
      'oracle', 'flash', 'loan', 'manipulation', 'front', 'running',
      'sandwich', 'mev', 'signature', 'replay', 'authorization',
      'owner', 'admin', 'permission', 'require', 'assert', 'revert',
      'balance', 'withdraw', 'deposit', 'mint', 'burn', 'approve',
      'allowance', 'vulnerable', 'attack', 'exploit', 'malicious'
    ];
  }

  /**
   * Get n-grams from tokens
   * @private
   */
  _getNGrams(tokens, n) {
    const ngrams = [];
    for (let i = 0; i <= tokens.length - n; i++) {
      ngrams.push(tokens.slice(i, i + n).join('_'));
    }
    return ngrams;
  }

  /**
   * Hash text to cache key
   * @private
   */
  _hashText(text) {
    return crypto.createHash('md5').update(text).digest('hex');
  }

  /**
   * Hash string to index in range
   * @private
   */
  _hashToIndex(str, range) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash) % range;
  }

  /**
   * Normalize vector to unit length
   * @private
   */
  _normalizeVector(vec) {
    const magnitude = Math.sqrt(vec.reduce((sum, v) => sum + v * v, 0));
    if (magnitude === 0) return vec;
    return vec.map(v => v / magnitude);
  }

  /**
   * Add to cache with size limit
   * @private
   */
  _addToCache(key, value) {
    if (this.cache.size >= this.cacheMaxSize) {
      // Remove oldest entry
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  /**
   * Calculate cosine similarity between two vectors
   * 
   * @param {Array} a - First vector
   * @param {Array} b - Second vector
   * @returns {number} Similarity score (0-1)
   */
  cosineSimilarity(a, b) {
    if (a.length !== b.length) {
      throw new Error('Vectors must have same length');
    }
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
    if (magnitude === 0) return 0;
    
    return dotProduct / magnitude;
  }

  /**
   * Find similar code snippets or findings
   * 
   * @param {string} query - Query code or text
   * @param {Array} candidates - Array of {id, text, ...} objects
   * @param {Object} options - Search options
   * @returns {Promise<Array>} Ranked results with similarity scores
   */
  async findSimilar(query, candidates, options = {}) {
    const limit = options.limit || 10;
    const threshold = options.threshold || 0.3;

    // Generate query embedding
    const queryEmbedding = await this._generateEmbedding(query);

    // Score all candidates
    const scored = await Promise.all(
      candidates.map(async (candidate) => {
        const text = candidate.text || candidate.description || candidate.code || '';
        const embedding = await this._generateEmbedding(text);
        const similarity = this.cosineSimilarity(queryEmbedding, embedding);
        
        return {
          ...candidate,
          similarity,
          relevanceScore: similarity
        };
      })
    );

    // Filter by threshold and sort by similarity
    return scored
      .filter(item => item.similarity >= threshold)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit);
  }

  /**
   * Find findings similar to code
   * 
   * @param {string} code - Source code
   * @param {Array} findings - Array of findings from database
   * @param {Object} options - Search options
   * @returns {Promise<Array>} Relevant findings
   */
  async findRelevantFindings(code, findings, options = {}) {
    // Extract key patterns from code
    const codePatterns = this._extractCodePatterns(code);
    
    // Create enriched query
    const enrichedQuery = `${code}\n\nPatterns: ${codePatterns.join(', ')}`;
    
    return this.findSimilar(enrichedQuery, findings, {
      limit: options.limit || 5,
      threshold: options.threshold || 0.25
    });
  }

  /**
   * Extract security-relevant patterns from code
   * @private
   */
  _extractCodePatterns(code) {
    const patterns = [];
    const normalized = code.toLowerCase();

    // Check for common vulnerability patterns
    const patternChecks = [
      { pattern: /\.call\{value:/i, label: 'external call with value' },
      { pattern: /\.delegatecall/i, label: 'delegatecall' },
      { pattern: /selfdestruct/i, label: 'selfdestruct' },
      { pattern: /tx\.origin/i, label: 'tx.origin usage' },
      { pattern: /block\.timestamp/i, label: 'timestamp dependence' },
      { pattern: /unchecked\s*\{/i, label: 'unchecked arithmetic' },
      { pattern: /\.transfer\s*\(/i, label: 'transfer call' },
      { pattern: /approve/i, label: 'token approval' },
      { pattern: /flashloan|flash.*loan/i, label: 'flash loan' },
      { pattern: /getReserves|getAmountOut/i, label: 'DEX interaction' },
      { pattern: /latestRoundData/i, label: 'Chainlink oracle' },
      { pattern: /onlyOwner|onlyAdmin/i, label: 'access control' }
    ];

    for (const check of patternChecks) {
      if (check.pattern.test(code)) {
        patterns.push(check.label);
      }
    }

    return patterns;
  }

  /**
   * Cluster similar findings together
   * 
   * @param {Array} findings - Array of findings
   * @param {Object} options - Clustering options
   * @returns {Promise<Array>} Clustered findings
   */
  async clusterFindings(findings, options = {}) {
    const threshold = options.threshold || 0.6;
    const clusters = [];
    const assigned = new Set();

    // Generate embeddings for all findings
    const embeddings = await Promise.all(
      findings.map(async (f) => ({
        finding: f,
        embedding: await this._generateEmbedding(f.description || f.title || '')
      }))
    );

    // Simple clustering algorithm
    for (let i = 0; i < embeddings.length; i++) {
      if (assigned.has(i)) continue;

      const cluster = {
        representative: findings[i],
        members: [findings[i]],
        indices: [i]
      };
      assigned.add(i);

      // Find similar findings
      for (let j = i + 1; j < embeddings.length; j++) {
        if (assigned.has(j)) continue;

        const similarity = this.cosineSimilarity(
          embeddings[i].embedding,
          embeddings[j].embedding
        );

        if (similarity >= threshold) {
          cluster.members.push(findings[j]);
          cluster.indices.push(j);
          assigned.add(j);
        }
      }

      clusters.push(cluster);
    }

    return clusters;
  }

  /**
   * Search with natural language query
   * 
   * @param {string} query - Natural language query
   * @param {Array} documents - Array of documents to search
   * @param {Object} options - Search options
   * @returns {Promise<Array>} Search results
   */
  async search(query, documents, options = {}) {
    // Expand query with related terms
    const expandedQuery = this._expandQuery(query);
    
    return this.findSimilar(expandedQuery, documents, options);
  }

  /**
   * Expand query with related security terms
   * @private
   */
  _expandQuery(query) {
    const normalized = query.toLowerCase();
    const expansions = [];

    // Add related terms based on query content
    const termMappings = {
      'reentrancy': ['external call', 'state update', 'callback', 'reentrant'],
      'overflow': ['arithmetic', 'unchecked', 'integer', 'underflow'],
      'access': ['authorization', 'permission', 'owner', 'admin', 'role'],
      'oracle': ['price', 'manipulation', 'flash loan', 'TWAP'],
      'front-running': ['MEV', 'sandwich', 'mempool', 'transaction ordering'],
      'signature': ['replay', 'ecrecover', 'EIP-712', 'nonce']
    };

    for (const [term, related] of Object.entries(termMappings)) {
      if (normalized.includes(term)) {
        expansions.push(...related);
      }
    }

    return `${query} ${expansions.join(' ')}`;
  }
}

module.exports = SemanticSearch;
