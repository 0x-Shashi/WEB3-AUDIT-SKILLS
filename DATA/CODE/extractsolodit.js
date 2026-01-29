/**
 * Solodit Vulnerability Data Extraction Pipeline
 * 
 * This script extracts all ~50,000 vulnerability findings from the Solodit API
 * and saves them with proper structure for further processing.
 * 
 * Features:
 * - Checkpoint system (saves progress every 50 pages)
 * - Resume capability (can restart from last checkpoint)
 * - Rate limiting (respects 20 req/60s limit)
 * - Error handling and retries
 * - Progress tracking
 * - Data validation
 */

const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  API_KEY: 'sk_d1908a9593e45c5cdfed5c6b07a62f1247d079952846b16d29d14560ec793c5c',
  BASE_URL: 'https://solodit.cyfrin.io/api/v1/solodit/findings',
  PAGE_SIZE: 100, // Maximum allowed
  REQUEST_DELAY: 3500, // 3.5 seconds between requests (safe rate limiting)
  CHECKPOINT_INTERVAL: 50, // Save progress every 50 pages
  MAX_RETRIES: 3,
  // All paths relative to CODE folder, output to parent DATA folder
  DATA_DIR: path.join(__dirname, '..'),
  RAW_DATA_DIR: path.join(__dirname, '..', 'raw'),
  CHECKPOINTS_DIR: path.join(__dirname, '..', 'checkpoints'),
  LOGS_DIR: path.join(__dirname, '..', 'logs')
};

// Ensure directories exist
function setupDirectories() {
  const dirs = [
    CONFIG.DATA_DIR,
    CONFIG.RAW_DATA_DIR,
    CONFIG.CHECKPOINTS_DIR,
    CONFIG.LOGS_DIR
  ];
  
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
}

// Logging utility
class Logger {
  constructor() {
    this.logFile = path.join(CONFIG.LOGS_DIR, `extraction_${Date.now()}.log`);
    this.startTime = Date.now();
  }
  
  log(message, type = 'INFO') {
    const timestamp = new Date().toISOString();
    const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
    const logMessage = `[${timestamp}] [${type}] [+${elapsed}s] ${message}`;
    
    console.log(logMessage);
    fs.appendFileSync(this.logFile, logMessage + '\n');
  }
  
  info(message) { this.log(message, 'INFO'); }
  warn(message) { this.log(message, 'WARN'); }
  error(message) { this.log(message, 'ERROR'); }
  success(message) { this.log(message, '✓'); }
}

// Sleep utility
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Checkpoint management
class CheckpointManager {
  constructor(logger) {
    this.logger = logger;
  }
  
  save(data) {
    const checkpointFile = path.join(
      CONFIG.CHECKPOINTS_DIR, 
      `checkpoint_page_${data.lastPage}.json`
    );
    
    fs.writeFileSync(checkpointFile, JSON.stringify(data, null, 2));
    this.logger.info(`💾 Checkpoint saved: Page ${data.lastPage}, Total findings: ${data.totalFindings}`);
  }
  
  findLast() {
    if (!fs.existsSync(CONFIG.CHECKPOINTS_DIR)) {
      return null;
    }
    
    const files = fs.readdirSync(CONFIG.CHECKPOINTS_DIR)
      .filter(f => f.startsWith('checkpoint_page_'))
      .map(f => {
        const page = parseInt(f.match(/checkpoint_page_(\d+)\.json/)[1]);
        return { file: f, page };
      })
      .sort((a, b) => b.page - a.page);
    
    if (files.length === 0) return null;
    
    const lastCheckpoint = files[0];
    const data = JSON.parse(
      fs.readFileSync(path.join(CONFIG.CHECKPOINTS_DIR, lastCheckpoint.file))
    );
    
    this.logger.info(`📂 Found checkpoint at page ${data.lastPage}`);
    return data;
  }
  
  clear() {
    if (fs.existsSync(CONFIG.CHECKPOINTS_DIR)) {
      const files = fs.readdirSync(CONFIG.CHECKPOINTS_DIR);
      files.forEach(f => fs.unlinkSync(path.join(CONFIG.CHECKPOINTS_DIR, f)));
      this.logger.info('🗑️  Cleared all checkpoints');
    }
  }
}

// API Client
class SoloditAPIClient {
  constructor(logger) {
    this.logger = logger;
    this.requestCount = 0;
    this.errors = [];
  }
  
  async fetchPage(page, retryCount = 0) {
    try {
      const response = await fetch(CONFIG.BASE_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Cyfrin-API-Key': CONFIG.API_KEY
        },
        body: JSON.stringify({
          page,
          pageSize: CONFIG.PAGE_SIZE,
          filters: {} // No filters = get everything
        })
      });
      
      // Check rate limit headers
      const remaining = response.headers.get('X-RateLimit-Remaining');
      const limit = response.headers.get('X-RateLimit-Limit');
      
      if (remaining && limit) {
        this.logger.info(`⚡ Rate limit: ${remaining}/${limit} remaining`);
      }
      
      // Handle rate limiting
      if (response.status === 429) {
        const resetTime = response.headers.get('X-RateLimit-Reset');
        const waitTime = resetTime ? (parseInt(resetTime) * 1000 - Date.now()) : 60000;
        
        this.logger.warn(`⏸️  Rate limited! Waiting ${Math.ceil(waitTime / 1000)}s...`);
        await sleep(waitTime + 1000); // Add 1s buffer
        return this.fetchPage(page, retryCount); // Retry without counting
      }
      
      // Handle other errors
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      this.requestCount++;
      
      return data;
      
    } catch (error) {
      this.logger.error(`❌ Error fetching page ${page}: ${error.message}`);
      this.errors.push({ page, error: error.message, timestamp: new Date().toISOString() });
      
      // Retry logic
      if (retryCount < CONFIG.MAX_RETRIES) {
        const waitTime = (retryCount + 1) * 2000; // Exponential backoff
        this.logger.warn(`🔄 Retrying in ${waitTime / 1000}s... (Attempt ${retryCount + 1}/${CONFIG.MAX_RETRIES})`);
        await sleep(waitTime);
        return this.fetchPage(page, retryCount + 1);
      }
      
      throw error;
    }
  }
  
  getStats() {
    return {
      totalRequests: this.requestCount,
      totalErrors: this.errors.length,
      errors: this.errors
    };
  }
}

// Data Aggregator - Updated for actual Solodit API response structure
class DataAggregator {
  constructor(logger) {
    this.logger = logger;
    this.allFindings = [];
    this.seenIds = new Set(); // Track duplicates
    this.metadata = {
      tags: new Map(),
      firms: new Map(),        // audit firms (source in old code)
      impacts: new Map(),
      protocols: new Map(),
      categories: new Map(),
      finders: new Map()       // auditors/researchers
    };
    this.duplicateCount = 0;
  }
  
  addFindings(findings) {
    findings.forEach(finding => {
      // Check for duplicates
      if (this.seenIds.has(finding.id)) {
        this.duplicateCount++;
        return;
      }
      this.seenIds.add(finding.id);
      
      // Store full finding
      this.allFindings.push(finding);
      
      // Aggregate metadata from actual API response structure
      
      // Tags: issues_issuetagscore[].tags_tag.title
      if (finding.issues_issuetagscore && Array.isArray(finding.issues_issuetagscore)) {
        finding.issues_issuetagscore.forEach(tagScore => {
          const tagTitle = tagScore?.tags_tag?.title;
          if (tagTitle) {
            this.metadata.tags.set(tagTitle, (this.metadata.tags.get(tagTitle) || 0) + 1);
          }
        });
      }
      
      // Audit firm: firm_name or auditfirms_auditfirm.name
      const firmName = finding.firm_name || finding.auditfirms_auditfirm?.name;
      if (firmName) {
        this.metadata.firms.set(firmName, (this.metadata.firms.get(firmName) || 0) + 1);
      }
      
      // Impact: direct field
      if (finding.impact) {
        this.metadata.impacts.set(
          finding.impact,
          (this.metadata.impacts.get(finding.impact) || 0) + 1
        );
      }
      
      // Protocol: protocol_name or protocols_protocol.name
      const protocolName = finding.protocol_name || finding.protocols_protocol?.name;
      if (protocolName) {
        this.metadata.protocols.set(
          protocolName,
          (this.metadata.protocols.get(protocolName) || 0) + 1
        );
      }
      
      // Categories: protocols_protocol.protocols_protocolcategoryscore[].protocols_protocolcategory.title
      if (finding.protocols_protocol?.protocols_protocolcategoryscore) {
        finding.protocols_protocol.protocols_protocolcategoryscore.forEach(catScore => {
          const catTitle = catScore?.protocols_protocolcategory?.title;
          if (catTitle) {
            this.metadata.categories.set(catTitle, (this.metadata.categories.get(catTitle) || 0) + 1);
          }
        });
      }
      
      // Finders: issues_issue_finders[].wardens_warden.handle
      if (finding.issues_issue_finders && Array.isArray(finding.issues_issue_finders)) {
        finding.issues_issue_finders.forEach(finder => {
          const handle = finder?.wardens_warden?.handle;
          if (handle) {
            this.metadata.finders.set(handle, (this.metadata.finders.get(handle) || 0) + 1);
          }
        });
      }
    });
  }
  
  save() {
    // Save all findings
    const findingsFile = path.join(CONFIG.RAW_DATA_DIR, 'all_findings.json');
    fs.writeFileSync(findingsFile, JSON.stringify(this.allFindings, null, 2));
    this.logger.success(`💾 Saved ${this.allFindings.length} findings to ${findingsFile}`);
    
    // Save metadata - updated for actual API structure
    const metadataFile = path.join(CONFIG.RAW_DATA_DIR, 'metadata.json');
    const metadata = {
      totalFindings: this.allFindings.length,
      duplicatesSkipped: this.duplicateCount,
      tags: Object.fromEntries(
        Array.from(this.metadata.tags.entries()).sort((a, b) => b[1] - a[1])
      ),
      auditFirms: Object.fromEntries(
        Array.from(this.metadata.firms.entries()).sort((a, b) => b[1] - a[1])
      ),
      impacts: Object.fromEntries(
        Array.from(this.metadata.impacts.entries()).sort((a, b) => b[1] - a[1])
      ),
      protocols: Object.fromEntries(
        Array.from(this.metadata.protocols.entries()).sort((a, b) => b[1] - a[1])
      ),
      categories: Object.fromEntries(
        Array.from(this.metadata.categories.entries()).sort((a, b) => b[1] - a[1])
      ),
      topFinders: Object.fromEntries(
        Array.from(this.metadata.finders.entries()).sort((a, b) => b[1] - a[1]).slice(0, 100)
      ),
      extractedAt: new Date().toISOString()
    };
    
    fs.writeFileSync(metadataFile, JSON.stringify(metadata, null, 2));
    this.logger.success(`💾 Saved metadata to ${metadataFile}`);
    
    return metadata;
  }
}

// Main extraction pipeline
async function extractAllVulnerabilities(resumeFromCheckpoint = true) {
  const logger = new Logger();
  const checkpointManager = new CheckpointManager(logger);
  const apiClient = new SoloditAPIClient(logger);
  const aggregator = new DataAggregator(logger);
  
  logger.info('🚀 Starting Solodit vulnerability extraction...\n');
  setupDirectories();
  
  let startPage = 1;
  let previousFindings = [];
  
  // Check for existing checkpoint
  if (resumeFromCheckpoint) {
    const checkpoint = checkpointManager.findLast();
    if (checkpoint) {
      const answer = await new Promise(resolve => {
        const readline = require('readline').createInterface({
          input: process.stdin,
          output: process.stdout
        });
        readline.question(
          `\n📍 Resume from page ${checkpoint.lastPage}? (y/n): `,
          answer => {
            readline.close();
            resolve(answer.toLowerCase() === 'y');
          }
        );
      });
      
      if (answer) {
        startPage = checkpoint.lastPage + 1;
        previousFindings = checkpoint.findings || [];
        aggregator.allFindings = previousFindings;
        logger.info(`▶️  Resuming from page ${startPage}`);
      } else {
        checkpointManager.clear();
      }
    }
  }
  
  let page = startPage;
  let consecutiveEmptyPages = 0;
  const maxConsecutiveEmpty = 3;
  let totalPages = null; // Will be set from API response
  let totalResults = null;
  
  logger.info(`\n📊 Configuration:`);
  logger.info(`   - Starting page: ${startPage}`);
  logger.info(`   - Page size: ${CONFIG.PAGE_SIZE}`);
  logger.info(`   - Request delay: ${CONFIG.REQUEST_DELAY}ms`);
  logger.info(`   - Checkpoint interval: ${CONFIG.CHECKPOINT_INTERVAL} pages\n`);
  
  while (true) {
    try {
      const pageDisplay = totalPages ? `${page}/${totalPages}` : `${page}`;
      logger.info(`\n📄 Fetching page ${pageDisplay}...`);
      
      const data = await apiClient.fetchPage(page);
      
      // Get total from API metadata (first request)
      if (!totalPages && data.metadata) {
        totalPages = data.metadata.totalPages;
        totalResults = data.metadata.totalResults;
        logger.info(`📊 API reports: ${totalResults} total findings across ${totalPages} pages`);
      }
      
      if (!data.findings || data.findings.length === 0) {
        consecutiveEmptyPages++;
        logger.warn(`⚠️  Empty page received (${consecutiveEmptyPages}/${maxConsecutiveEmpty})`);
        
        if (consecutiveEmptyPages >= maxConsecutiveEmpty) {
          logger.info('✅ Reached end of data (multiple empty pages)');
          break;
        }
      } else {
        consecutiveEmptyPages = 0;
        aggregator.addFindings(data.findings);
        
        const progressPct = totalResults 
          ? ((aggregator.allFindings.length / totalResults) * 100).toFixed(1) 
          : '?';
        
        logger.success(`   ✓ Fetched ${data.findings.length} findings`);
        logger.info(`   📈 Total so far: ${aggregator.allFindings.length} (${progressPct}%)`);
        
        if (aggregator.duplicateCount > 0) {
          logger.warn(`   ⚠️  Duplicates skipped: ${aggregator.duplicateCount}`);
        }
      }
      
      // Check if we've reached the end
      if (totalPages && page >= totalPages) {
        logger.info('✅ Reached final page');
        break;
      }
      
      // Save checkpoint
      if (page % CONFIG.CHECKPOINT_INTERVAL === 0) {
        checkpointManager.save({
          lastPage: page,
          totalFindings: aggregator.allFindings.length,
          findings: aggregator.allFindings,
          timestamp: new Date().toISOString()
        });
      }
      
      page++;
      
      // Rate limiting delay
      await sleep(CONFIG.REQUEST_DELAY);
      
    } catch (error) {
      logger.error(`❌ Failed to fetch page ${page} after retries: ${error.message}`);
      
      // Save emergency checkpoint
      logger.warn('💾 Saving emergency checkpoint...');
      checkpointManager.save({
        lastPage: page - 1,
        totalFindings: aggregator.allFindings.length,
        findings: aggregator.allFindings,
        timestamp: new Date().toISOString(),
        error: error.message
      });
      
      throw error;
    }
  }
  
  // Final save
  logger.info('\n💾 Saving all data...');
  const metadata = aggregator.save();
  
  // Save API stats
  const statsFile = path.join(CONFIG.LOGS_DIR, 'extraction_stats.json');
  const stats = {
    ...apiClient.getStats(),
    pagesProcessed: page - startPage,
    totalFindings: aggregator.allFindings.length,
    metadata,
    duration: ((Date.now() - logger.startTime) / 1000 / 60).toFixed(2) + ' minutes'
  };
  
  fs.writeFileSync(statsFile, JSON.stringify(stats, null, 2));
  
  // Summary
  logger.info('\n' + '='.repeat(60));
  logger.success('🎉 EXTRACTION COMPLETE!');
  logger.info('='.repeat(60));
  logger.info(`📊 Summary:`);
  logger.info(`   - Total findings: ${stats.totalFindings}`);
  logger.info(`   - Pages processed: ${stats.pagesProcessed}`);
  logger.info(`   - API requests: ${stats.totalRequests}`);
  logger.info(`   - Errors: ${stats.totalErrors}`);
  logger.info(`   - Duplicates skipped: ${metadata.duplicatesSkipped || 0}`);
  logger.info(`   - Duration: ${stats.duration}`);
  logger.info(`   - Unique tags: ${Object.keys(metadata.tags).length}`);
  logger.info(`   - Audit firms: ${Object.keys(metadata.auditFirms).length}`);
  logger.info(`   - Protocols: ${Object.keys(metadata.protocols).length}`);
  logger.info('='.repeat(60) + '\n');
  
  // Top 10 vulnerability tags
  logger.info('🔝 Top 10 Vulnerability Types:');
  Object.entries(metadata.tags)
    .slice(0, 10)
    .forEach(([tag, count], i) => {
      const percentage = ((count / stats.totalFindings) * 100).toFixed(2);
      logger.info(`   ${i + 1}. ${tag}: ${count} (${percentage}%)`);
    });
  
  // Top 5 audit firms
  logger.info('\n🏢 Top 5 Audit Firms:');
  Object.entries(metadata.auditFirms)
    .slice(0, 5)
    .forEach(([firm, count], i) => {
      const percentage = ((count / stats.totalFindings) * 100).toFixed(2);
      logger.info(`   ${i + 1}. ${firm}: ${count} (${percentage}%)`);
    });
  
  // Impact distribution
  logger.info('\n⚠️  Impact Distribution:');
  Object.entries(metadata.impacts)
    .forEach(([impact, count]) => {
      const percentage = ((count / stats.totalFindings) * 100).toFixed(2);
      logger.info(`   ${impact}: ${count} (${percentage}%)`);
    });
  
  return {
    findings: aggregator.allFindings,
    metadata,
    stats
  };
}

// Run if called directly
if (require.main === module) {
  extractAllVulnerabilities()
    .then(() => {
      console.log('\n✅ Script completed successfully!');
      process.exit(0);
    })
    .catch(error => {
      console.error('\n❌ Script failed:', error);
      process.exit(1);
    });
}

module.exports = { extractAllVulnerabilities };