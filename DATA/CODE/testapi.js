/**
 * Solodit API Test Script
 * 
 * Tests API connectivity and inspects data structure
 * before running the full extraction.
 * 
 * Updated for actual Solodit API response structure.
 */

const fs = require('fs');
const path = require('path');

const CONFIG = {
  API_KEY: 'sk_d1908a9593e45c5cdfed5c6b07a62f1247d079952846b16d29d14560ec793c5c',
  BASE_URL: 'https://solodit.cyfrin.io/api/v1/solodit/findings',
  TEST_PAGES: 3,
  DATA_DIR: path.join(__dirname, '..', 'test')
};

async function testAPI() {
  console.log('🧪 Testing Solodit API...\n');
  
  // Ensure test directory exists
  if (!fs.existsSync(CONFIG.DATA_DIR)) {
    fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });
  }
  
  try {
    // Test 1: Basic connectivity
    console.log('Test 1: API Connectivity');
    console.log('-'.repeat(50));
    
    const response = await fetch(CONFIG.BASE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cyfrin-API-Key': CONFIG.API_KEY
      },
      body: JSON.stringify({
        page: 1,
        pageSize: 10,
        filters: {}
      })
    });
    
    console.log(`Status: ${response.status} ${response.statusText}`);
    console.log(`Rate Limit: ${response.headers.get('X-RateLimit-Remaining')}/${response.headers.get('X-RateLimit-Limit')}`);
    
    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`API returned ${response.status}: ${errorBody}`);
    }
    
    const data = await response.json();
    console.log(`✅ API connection successful`);
    console.log(`   Findings returned: ${data.findings?.length || 0}`);
    
    // Show API metadata
    if (data.metadata) {
      console.log(`\n📊 API Metadata:`);
      console.log(`   Total Results: ${data.metadata.totalResults}`);
      console.log(`   Total Pages: ${data.metadata.totalPages}`);
      console.log(`   Current Page: ${data.metadata.currentPage}`);
      console.log(`   Page Size: ${data.metadata.pageSize}`);
    }
    
    // Test 2: Data structure inspection
    console.log('\nTest 2: Data Structure Inspection');
    console.log('-'.repeat(50));
    
    if (data.findings && data.findings.length > 0) {
      const sampleFinding = data.findings[0];
      console.log('Sample finding fields:');
      Object.keys(sampleFinding).forEach(key => {
        const value = sampleFinding[key];
        const type = Array.isArray(value) ? 'array' : typeof value;
        const preview = type === 'string' && value.length > 50 
          ? value.substring(0, 50) + '...' 
          : type === 'array' 
            ? `[${value.length} items]` 
            : value;
        console.log(`   ${key}: (${type}) ${preview}`);
      });
      
      // Save sample
      fs.writeFileSync(
        path.join(CONFIG.DATA_DIR, 'sample_finding.json'),
        JSON.stringify(sampleFinding, null, 2)
      );
      console.log(`\n✅ Sample finding saved to ${CONFIG.DATA_DIR}/sample_finding.json\n`);
    }
    
    // Test 3: Fetch multiple pages
    console.log('Test 3: Multi-page Fetch');
    console.log('-'.repeat(50));
    
    const allTestFindings = [];
    const seenFields = new Set();
    
    for (let page = 1; page <= CONFIG.TEST_PAGES; page++) {
      const pageResponse = await fetch(CONFIG.BASE_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Cyfrin-API-Key': CONFIG.API_KEY
        },
        body: JSON.stringify({
          page,
          pageSize: 100,
          filters: {}
        })
      });
      
      const pageData = await pageResponse.json();
      
      if (pageData.findings) {
        allTestFindings.push(...pageData.findings);
        
        // Collect all unique fields
        pageData.findings.forEach(f => {
          Object.keys(f).forEach(key => seenFields.add(key));
        });
        
        console.log(`   Page ${page}: ${pageData.findings.length} findings`);
      }
      
      // Small delay
      await new Promise(resolve => setTimeout(resolve, 3500));
    }
    
    console.log(`✅ Fetched ${allTestFindings.length} total findings across ${CONFIG.TEST_PAGES} pages\n`);
    
    // Test 4: Field analysis
    console.log('Test 4: Field Analysis');
    console.log('-'.repeat(50));
    console.log('All unique fields found across test data:');
    Array.from(seenFields).sort().forEach(field => {
      console.log(`   - ${field}`);
    });
    
    // Test 5: Metadata extraction (using actual API field names)
    console.log('\nTest 5: Metadata Extraction');
    console.log('-'.repeat(50));
    
    const metadata = {
      tags: new Map(),
      firms: new Map(),
      impacts: new Map(),
      protocols: new Map()
    };
    
    allTestFindings.forEach(finding => {
      // Tags: issues_issuetagscore[].tags_tag.title
      if (finding.issues_issuetagscore && Array.isArray(finding.issues_issuetagscore)) {
        finding.issues_issuetagscore.forEach(tagScore => {
          const tagTitle = tagScore?.tags_tag?.title;
          if (tagTitle) {
            metadata.tags.set(tagTitle, (metadata.tags.get(tagTitle) || 0) + 1);
          }
        });
      }
      
      // Audit firm
      const firmName = finding.firm_name || finding.auditfirms_auditfirm?.name;
      if (firmName) {
        metadata.firms.set(firmName, (metadata.firms.get(firmName) || 0) + 1);
      }
      
      // Impact
      if (finding.impact) {
        metadata.impacts.set(finding.impact, (metadata.impacts.get(finding.impact) || 0) + 1);
      }
      
      // Protocol
      const protocolName = finding.protocol_name || finding.protocols_protocol?.name;
      if (protocolName) {
        metadata.protocols.set(protocolName, (metadata.protocols.get(protocolName) || 0) + 1);
      }
    });
    
    console.log('\nTags found:');
    Array.from(metadata.tags.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([tag, count]) => {
        console.log(`   ${tag}: ${count}`);
      });
    
    console.log('\nAudit Firms found:');
    Array.from(metadata.firms.entries())
      .sort((a, b) => b[1] - a[1])
      .forEach(([firm, count]) => {
        console.log(`   ${firm}: ${count}`);
      });
    
    console.log('\nProtocols found:');
    Array.from(metadata.protocols.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([protocol, count]) => {
        console.log(`   ${protocol}: ${count}`);
      });
    
    console.log('\nImpacts found:');
    Array.from(metadata.impacts.entries())
      .sort((a, b) => b[1] - a[1])
      .forEach(([impact, count]) => {
        console.log(`   ${impact}: ${count}`);
      });
    
    // Save test data
    fs.writeFileSync(
      path.join(CONFIG.DATA_DIR, 'test_findings.json'),
      JSON.stringify(allTestFindings, null, 2)
    );
    
    fs.writeFileSync(
      path.join(CONFIG.DATA_DIR, 'test_metadata.json'),
      JSON.stringify({
        totalFindings: allTestFindings.length,
        uniqueFields: Array.from(seenFields).sort(),
        tags: Object.fromEntries(metadata.tags),
        auditFirms: Object.fromEntries(metadata.firms),
        protocols: Object.fromEntries(metadata.protocols),
        impacts: Object.fromEntries(metadata.impacts)
      }, null, 2)
    );
    
    console.log('\n' + '='.repeat(50));
    console.log('✅ ALL TESTS PASSED');
    console.log('='.repeat(50));
    console.log(`\nTest data saved to: ${CONFIG.DATA_DIR}`);
    console.log('\n✨ Ready for full extraction! Run: npm run extract\n');
    
  } catch (error) {
    console.error('\n❌ TEST FAILED:', error.message);
    console.error('\nPlease check:');
    console.error('   1. API key is valid');
    console.error('   2. Internet connection is stable');
    console.error('   3. Solodit API is operational\n');
    process.exit(1);
  }
}

// Run tests
testAPI();