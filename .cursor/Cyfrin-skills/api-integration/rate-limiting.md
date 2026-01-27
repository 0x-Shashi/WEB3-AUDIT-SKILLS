# Rate Limiting

## Quick Start

The Cyfrin Solodit API enforces rate limiting to ensure fair usage. This guide covers rate limit specifics, monitoring strategies, backoff implementations, and caching to optimize your API usage.

## Rate Limit Specifications

| Parameter | Value |
|-----------|-------|
| **Requests per window** | 20 |
| **Window duration** | 60 seconds |
| **Reset behavior** | Rolling window |
| **Exceeded response** | HTTP 429 Too Many Requests |

## Response Headers

Every API response includes rate limit information:

```http
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 15
X-RateLimit-Reset: 1706400060
```

And in the JSON response body:

```json
{
  "rateLimit": {
    "limit": 20,
    "remaining": 15,
    "reset": 1706400060
  }
}
```

## Checking Remaining Requests

### JavaScript

```javascript
async function makeApiCall(payload) {
  const response = await fetch('https://solodit.cyfrin.io/api/v1/solodit/findings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Cyfrin-API-Key': process.env.CYFRIN_API_KEY
    },
    body: JSON.stringify(payload)
  });
  
  const data = await response.json();
  
  // Check rate limit
  const { remaining, reset, limit } = data.rateLimit;
  
  console.log(`Rate limit: ${remaining}/${limit} requests remaining`);
  
  if (remaining <= 5) {
    console.warn(`⚠️ Low rate limit: ${remaining} requests left`);
    console.warn(`Resets at: ${new Date(reset * 1000).toISOString()}`);
  }
  
  if (remaining === 0) {
    const waitMs = (reset * 1000) - Date.now();
    console.error(`Rate limit exhausted. Wait ${Math.ceil(waitMs/1000)}s`);
  }
  
  return data;
}
```

### Python

```python
import time
import requests

def make_api_call(payload):
    response = requests.post(
        'https://solodit.cyfrin.io/api/v1/solodit/findings',
        headers={
            'Content-Type': 'application/json',
            'X-Cyfrin-API-Key': os.environ['CYFRIN_API_KEY']
        },
        json=payload
    )
    
    data = response.json()
    rate_limit = data.get('rateLimit', {})
    
    remaining = rate_limit.get('remaining', 0)
    reset_time = rate_limit.get('reset', 0)
    limit = rate_limit.get('limit', 20)
    
    print(f"Rate limit: {remaining}/{limit} requests remaining")
    
    if remaining <= 5:
        print(f"⚠️ Low rate limit: {remaining} requests left")
        print(f"Resets at: {time.ctime(reset_time)}")
    
    return data, remaining
```

### Bash

```bash
# Make request and check rate limit
response=$(curl -s -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 10}')

remaining=$(echo $response | jq '.rateLimit.remaining')
limit=$(echo $response | jq '.rateLimit.limit')

echo "Rate limit: $remaining/$limit requests remaining"

if [ "$remaining" -le 5 ]; then
  echo "⚠️ Warning: Low rate limit!"
fi
```

## Implementing Backoff Strategies

### Exponential Backoff

```javascript
async function apiCallWithBackoff(payload, maxRetries = 3) {
  let retries = 0;
  let delay = 1000; // Start with 1 second
  
  while (retries < maxRetries) {
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Cyfrin-API-Key': process.env.CYFRIN_API_KEY
        },
        body: JSON.stringify(payload)
      });
      
      if (response.status === 429) {
        // Rate limited - wait and retry
        const data = await response.json();
        const resetTime = data.rateLimit?.reset || (Date.now() / 1000 + 60);
        const waitMs = Math.max((resetTime * 1000) - Date.now(), delay);
        
        console.log(`Rate limited. Waiting ${waitMs}ms before retry...`);
        await new Promise(r => setTimeout(r, waitMs));
        
        retries++;
        delay *= 2; // Exponential backoff
        continue;
      }
      
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
      
      return await response.json();
      
    } catch (error) {
      retries++;
      if (retries >= maxRetries) throw error;
      
      await new Promise(r => setTimeout(r, delay));
      delay *= 2;
    }
  }
  
  throw new Error('Max retries exceeded');
}
```

### Python with Retry

```python
import time
import requests
from functools import wraps

def retry_with_backoff(max_retries=3, initial_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            delay = initial_delay
            
            while retries < max_retries:
                try:
                    result = func(*args, **kwargs)
                    
                    # Check for rate limit in response
                    if hasattr(result, 'status_code') and result.status_code == 429:
                        data = result.json()
                        reset_time = data.get('rateLimit', {}).get('reset', time.time() + 60)
                        wait_time = max(reset_time - time.time(), delay)
                        
                        print(f"Rate limited. Waiting {wait_time:.1f}s...")
                        time.sleep(wait_time)
                        
                        retries += 1
                        delay *= 2
                        continue
                    
                    return result
                    
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        raise
                    
                    print(f"Error: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                    delay *= 2
            
            raise Exception("Max retries exceeded")
        return wrapper
    return decorator

@retry_with_backoff(max_retries=3)
def fetch_findings(payload):
    return requests.post(
        'https://solodit.cyfrin.io/api/v1/solodit/findings',
        headers={
            'Content-Type': 'application/json',
            'X-Cyfrin-API-Key': os.environ['CYFRIN_API_KEY']
        },
        json=payload
    )
```

## Caching Strategies

### In-Memory Cache (JavaScript)

```javascript
const cache = new Map();
const CACHE_TTL = {
  search: 5 * 60 * 1000,      // 5 minutes for search results
  finding: 60 * 60 * 1000,     // 1 hour for individual findings
  metadata: 24 * 60 * 60 * 1000 // 24 hours for metadata
};

function getCacheKey(payload) {
  return JSON.stringify(payload);
}

async function cachedApiCall(payload, cacheType = 'search') {
  const key = getCacheKey(payload);
  const cached = cache.get(key);
  
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL[cacheType]) {
    console.log('Cache hit');
    return cached.data;
  }
  
  console.log('Cache miss - fetching from API');
  const data = await makeApiCall(payload);
  
  cache.set(key, {
    data,
    timestamp: Date.now()
  });
  
  return data;
}

// Clear old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of cache.entries()) {
    if (now - value.timestamp > CACHE_TTL.metadata) {
      cache.delete(key);
    }
  }
}, 60 * 60 * 1000); // Clean every hour
```

### File-Based Cache (Python)

```python
import json
import os
import time
import hashlib

CACHE_DIR = '.solodit_cache'
CACHE_TTL = {
    'search': 5 * 60,      # 5 minutes
    'finding': 60 * 60,     # 1 hour
    'metadata': 24 * 60 * 60  # 24 hours
}

def get_cache_key(payload):
    return hashlib.md5(json.dumps(payload, sort_keys=True).encode()).hexdigest()

def get_cached(payload, cache_type='search'):
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    cache_file = os.path.join(CACHE_DIR, f"{get_cache_key(payload)}.json")
    
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cached = json.load(f)
        
        if time.time() - cached['timestamp'] < CACHE_TTL[cache_type]:
            print('Cache hit')
            return cached['data']
    
    return None

def set_cached(payload, data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    cache_file = os.path.join(CACHE_DIR, f"{get_cache_key(payload)}.json")
    
    with open(cache_file, 'w') as f:
        json.dump({
            'data': data,
            'timestamp': time.time()
        }, f)

def cached_api_call(payload, cache_type='search'):
    cached = get_cached(payload, cache_type)
    if cached:
        return cached
    
    print('Cache miss - fetching from API')
    response = make_api_call(payload)
    set_cached(payload, response)
    return response

def clear_cache():
    import shutil
    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)
    print('Cache cleared')
```

## Batch Query Optimization

### Combine Related Queries

Instead of making multiple separate queries:

```javascript
// ❌ Bad: 4 separate API calls
const reentrancy = await fetchFindings({filters: {tags: [{value: "Reentrancy"}]}});
const oracle = await fetchFindings({filters: {tags: [{value: "Oracle"}]}});
const access = await fetchFindings({filters: {tags: [{value: "Access Control"}]}});
const flash = await fetchFindings({filters: {tags: [{value: "Flash Loan"}]}});
```

Combine into one query when possible:

```javascript
// ✅ Good: 1 API call with broader filters
const allFindings = await fetchFindings({
  pageSize: 100,
  filters: {
    impact: ["HIGH"],
    qualityScore: 4
  }
});

// Filter client-side by tag
const byTag = {
  reentrancy: allFindings.filter(f => hasTag(f, 'Reentrancy')),
  oracle: allFindings.filter(f => hasTag(f, 'Oracle')),
  access: allFindings.filter(f => hasTag(f, 'Access Control')),
  flash: allFindings.filter(f => hasTag(f, 'Flash Loan'))
};
```

### Pagination with Rate Awareness

```javascript
async function fetchAllPages(filters, maxResults = 500) {
  const results = [];
  let page = 1;
  let remaining = 20;
  
  while (results.length < maxResults) {
    // Check rate limit before requesting
    if (remaining <= 2) {
      console.log('Rate limit low. Waiting 60s...');
      await new Promise(r => setTimeout(r, 60000));
    }
    
    const response = await makeApiCall({
      page,
      pageSize: 100,
      filters
    });
    
    results.push(...response.findings);
    remaining = response.rateLimit.remaining;
    
    console.log(`Page ${page}: Got ${response.findings.length} findings. Rate limit: ${remaining}`);
    
    if (page >= response.metadata.totalPages) break;
    if (response.findings.length < 100) break;
    
    page++;
    
    // Small delay between requests to be nice
    await new Promise(r => setTimeout(r, 500));
  }
  
  return results;
}
```

## Test Rate Limiting

```bash
# Test current rate limit status
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 1}' \
  | jq '.rateLimit'
```

**Expected Output:**
```json
{
  "limit": 20,
  "remaining": 19,
  "reset": 1706400060
}
```

### Stress Test (Use Carefully!)

```bash
# Make 5 rapid requests and watch rate limit decrease
for i in {1..5}; do
  echo "Request $i:"
  curl -s -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
    -H "Content-Type: application/json" \
    -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
    -d '{"page": 1, "pageSize": 1}' \
    | jq '.rateLimit.remaining'
done
```

## Rate Limit Best Practices

### Do's ✅

1. **Cache aggressively** - Most findings don't change frequently
2. **Batch queries** - Combine multiple filters instead of separate calls
3. **Monitor remaining** - Check rate limit before each call
4. **Use exponential backoff** - For 429 responses
5. **Fetch larger pages** - Use pageSize: 100 to minimize calls
6. **Plan pagination** - Calculate total pages before starting

### Don'ts ❌

1. **Don't ignore rate limits** - Always check remaining count
2. **Don't make parallel requests** - Risk exhausting limit quickly
3. **Don't retry immediately on 429** - Wait for reset
4. **Don't fetch small pages** - pageSize: 10 wastes 10x more calls
5. **Don't skip caching** - Identical queries waste limit

## Checklist for Rate Limit Management

- [ ] Check `rateLimit.remaining` after each response
- [ ] Implement exponential backoff for retries
- [ ] Cache search results for 5+ minutes
- [ ] Cache metadata for 24 hours
- [ ] Use pageSize: 100 for bulk fetches
- [ ] Monitor and log rate limit usage
- [ ] Implement request queuing for busy periods
- [ ] Add delay between sequential requests
- [ ] Handle 429 errors gracefully
- [ ] Plan queries to minimize API calls
