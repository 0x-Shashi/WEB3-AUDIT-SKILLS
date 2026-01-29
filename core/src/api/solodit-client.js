/**
 * Solodit API Client
 * 
 * Official client for querying Cyfrin Solodit's 50,000+ security findings.
 * API Documentation: https://solodit.cyfrin.io/api/docs
 * 
 * Usage:
 *   const client = new SoloditClient(apiKey);
 *   const findings = await client.searchFindings('reentrancy', { severity: 'high' });
 */

const axios = require('axios');

class SoloditClient {
  constructor(apiKey = null) {
    this.apiKey = apiKey || process.env.CYFRIN_API_KEY;
    this.baseUrl = 'https://solodit.cyfrin.io/api/v1/solodit';
    this.rateLimit = {
      requests: 20,
      windowMs: 60000, // 60 seconds
      remaining: 20,
      resetAt: Date.now() + 60000
    };
    
    // Create axios instance with defaults
    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        ...(this.apiKey && { 'X-Cyfrin-API-Key': this.apiKey })
      }
    });

    // Add response interceptor for rate limiting
    this.client.interceptors.response.use(
      (response) => {
        this._updateRateLimit(response.headers);
        return response;
      },
      (error) => {
        if (error.response?.status === 429) {
          console.warn('Rate limited. Waiting before retry...');
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Update rate limit tracking from response headers
   */
  _updateRateLimit(headers) {
    if (headers['x-ratelimit-remaining']) {
      this.rateLimit.remaining = parseInt(headers['x-ratelimit-remaining']);
    }
    if (headers['x-ratelimit-reset']) {
      this.rateLimit.resetAt = parseInt(headers['x-ratelimit-reset']) * 1000;
    }
  }

  /**
   * Wait for rate limit if necessary
   */
  async _checkRateLimit() {
    if (this.rateLimit.remaining <= 0) {
      const waitTime = this.rateLimit.resetAt - Date.now();
      if (waitTime > 0) {
        console.log(`Rate limit reached. Waiting ${Math.ceil(waitTime / 1000)}s...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        this.rateLimit.remaining = this.rateLimit.requests;
      }
    }
  }

  /**
   * Search findings in Solodit database
   * 
   * @param {Object} options - Search options
   * @param {string} options.query - Search query (keywords)
   * @param {number} options.page - Page number (default: 1)
   * @param {number} options.pageSize - Results per page (default: 20, max: 100)
   * @param {string} options.severity - Filter by severity (critical, high, medium, low, info)
   * @param {string} options.category - Filter by category (reentrancy, access-control, etc.)
   * @param {string} options.protocol - Filter by protocol type (lending, dex, staking, etc.)
   * @param {string} options.chain - Filter by blockchain (ethereum, solana, etc.)
   * @returns {Promise<Object>} Search results
   */
  async searchFindings(options = {}) {
    await this._checkRateLimit();

    const payload = {
      page: options.page || 1,
      pageSize: Math.min(options.pageSize || 20, 100),
      ...(options.query && { query: options.query }),
      ...(options.severity && { severity: options.severity }),
      ...(options.category && { category: options.category }),
      ...(options.protocol && { protocol: options.protocol }),
      ...(options.chain && { chain: options.chain })
    };

    try {
      const response = await this.client.post('/findings', payload);
      return {
        success: true,
        data: response.data,
        pagination: {
          page: payload.page,
          pageSize: payload.pageSize,
          total: response.data.total || 0,
          hasMore: response.data.hasMore || false
        },
        rateLimit: {
          remaining: this.rateLimit.remaining,
          resetAt: new Date(this.rateLimit.resetAt).toISOString()
        }
      };
    } catch (error) {
      return this._handleError(error);
    }
  }

  /**
   * Get finding by ID
   * 
   * @param {string} findingId - The finding ID
   * @returns {Promise<Object>} Finding details
   */
  async getFinding(findingId) {
    await this._checkRateLimit();

    try {
      const response = await this.client.get(`/findings/${findingId}`);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      return this._handleError(error);
    }
  }

  /**
   * Search by vulnerability pattern
   * 
   * @param {string} pattern - Vulnerability pattern name
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Matching findings
   */
  async searchByPattern(pattern, options = {}) {
    const patternQueries = {
      'reentrancy': 'reentrancy OR reentrant OR "external call before state"',
      'oracle-manipulation': 'oracle manipulation OR "price manipulation" OR "flash loan"',
      'access-control': '"access control" OR "missing modifier" OR unauthorized OR "only owner"',
      'integer-overflow': 'overflow OR underflow OR "integer overflow"',
      'front-running': 'frontrun OR "front-running" OR MEV OR sandwich',
      'flash-loan': '"flash loan" OR flashloan OR uncollateralized',
      'signature-replay': 'replay OR signature OR "nonce" OR EIP712',
      'dos': 'denial of service OR DoS OR "gas limit" OR "unbounded loop"',
      'initialization': 'uninitialized OR initializer OR "not initialized"',
      'upgrade': 'upgrade OR proxy OR "storage collision" OR UUPS'
    };

    const query = patternQueries[pattern.toLowerCase()] || pattern;
    return this.searchFindings({ ...options, query });
  }

  /**
   * Search by protocol type
   * 
   * @param {string} protocolType - Protocol type (lending, dex, staking, bridge, etc.)
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Matching findings
   */
  async searchByProtocol(protocolType, options = {}) {
    return this.searchFindings({ ...options, protocol: protocolType });
  }

  /**
   * Search by severity level
   * 
   * @param {string} severity - Severity level (critical, high, medium, low)
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Matching findings
   */
  async searchBySeverity(severity, options = {}) {
    return this.searchFindings({ ...options, severity: severity.toLowerCase() });
  }

  /**
   * Get trending/recent findings
   * 
   * @param {number} limit - Number of findings to return
   * @returns {Promise<Object>} Recent findings
   */
  async getRecentFindings(limit = 20) {
    return this.searchFindings({ 
      pageSize: limit,
      sort: 'date_desc'
    });
  }

  /**
   * Get findings similar to a code pattern
   * 
   * @param {string} codeSnippet - Code snippet to find similar vulnerabilities for
   * @returns {Promise<Object>} Similar findings
   */
  async findSimilar(codeSnippet) {
    // Extract potential vulnerability patterns from code
    const patterns = this._extractPatterns(codeSnippet);
    
    if (patterns.length === 0) {
      return { success: true, data: [], message: 'No vulnerability patterns detected' };
    }

    // Search for each pattern
    const results = [];
    for (const pattern of patterns.slice(0, 3)) { // Limit to 3 to avoid rate limits
      const searchResult = await this.searchByPattern(pattern, { pageSize: 10 });
      if (searchResult.success && searchResult.data.findings) {
        results.push(...searchResult.data.findings);
      }
    }

    return {
      success: true,
      data: results,
      detectedPatterns: patterns
    };
  }

  /**
   * Extract potential vulnerability patterns from code
   * @private
   */
  _extractPatterns(code) {
    const patterns = [];
    
    // Check for reentrancy indicators
    if (code.includes('.call{') || code.includes('.transfer(') || code.includes('.send(')) {
      patterns.push('reentrancy');
    }
    
    // Check for oracle patterns
    if (code.includes('getPrice') || code.includes('latestAnswer') || code.includes('oracle')) {
      patterns.push('oracle-manipulation');
    }
    
    // Check for access control
    if (code.includes('onlyOwner') || code.includes('require(msg.sender') || code.includes('modifier')) {
      patterns.push('access-control');
    }
    
    // Check for flash loan
    if (code.includes('flashLoan') || code.includes('FlashLoan') || code.includes('executeOperation')) {
      patterns.push('flash-loan');
    }
    
    // Check for signature
    if (code.includes('ecrecover') || code.includes('ECDSA') || code.includes('signature')) {
      patterns.push('signature-replay');
    }
    
    // Check for upgrade patterns
    if (code.includes('upgradeTo') || code.includes('_implementation') || code.includes('delegatecall')) {
      patterns.push('upgrade');
    }

    return patterns;
  }

  /**
   * Handle API errors
   * @private
   */
  _handleError(error) {
    if (error.response) {
      return {
        success: false,
        error: {
          status: error.response.status,
          message: error.response.data?.message || 'API request failed',
          code: error.response.data?.code || 'UNKNOWN_ERROR'
        }
      };
    } else if (error.request) {
      return {
        success: false,
        error: {
          status: 0,
          message: 'No response from server',
          code: 'NETWORK_ERROR'
        }
      };
    } else {
      return {
        success: false,
        error: {
          status: 0,
          message: error.message,
          code: 'REQUEST_ERROR'
        }
      };
    }
  }

  /**
   * Check API health
   * 
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    try {
      const response = await this.client.get('/health');
      return { healthy: true, ...response.data };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }

  /**
   * Get API usage stats
   * 
   * @returns {Object} Current rate limit status
   */
  getRateLimitStatus() {
    return {
      remaining: this.rateLimit.remaining,
      total: this.rateLimit.requests,
      resetAt: new Date(this.rateLimit.resetAt).toISOString(),
      resetIn: Math.max(0, Math.ceil((this.rateLimit.resetAt - Date.now()) / 1000))
    };
  }
}

module.exports = SoloditClient;
