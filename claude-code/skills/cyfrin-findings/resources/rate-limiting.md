# Rate Limiting Guide

Best practices for handling Cyfrin Solodit API rate limits.

---

## Rate Limit Specifications

| Parameter | Value |
|-----------|-------|
| **Requests per window** | 20 |
| **Window duration** | 60 seconds |
| **Reset behavior** | Rolling window |
| **Exceeded response** | HTTP 429 Too Many Requests |

---

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

---

## Implementation Patterns

### JavaScript/Node.js

```javascript
class SoloditClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://solodit.cyfrin.io/api/v1/solodit';
    this.rateLimit = {
      limit: 20,
      remaining: 20,
      reset: null
    };
  }

  async query(params) {
    await this.waitIfRateLimited();
    
    const response = await fetch(`${this.baseUrl}/findings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cyfrin-API-Key': this.apiKey
      },
      body: JSON.stringify(params)
    });

    // Update rate limit info from response
    this.updateRateLimit(response);

    if (response.status === 429) {
      const retryAfter = parseInt(response.headers.get('Retry-After')) || 60;
      await this.sleep(retryAfter * 1000);
      return this.query(params); // Retry
    }

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    return response.json();
  }

  updateRateLimit(response) {
    this.rateLimit = {
      limit: parseInt(response.headers.get('X-RateLimit-Limit')) || 20,
      remaining: parseInt(response.headers.get('X-RateLimit-Remaining')) || 0,
      reset: parseInt(response.headers.get('X-RateLimit-Reset')) || null
    };
  }

  async waitIfRateLimited() {
    if (this.rateLimit.remaining > 0) return;

    const now = Math.floor(Date.now() / 1000);
    const waitSeconds = Math.max(0, this.rateLimit.reset - now) + 1;
    
    console.log(`Rate limited. Waiting ${waitSeconds} seconds...`);
    await this.sleep(waitSeconds * 1000);
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage
const client = new SoloditClient(process.env.CYFRIN_API_KEY);

const findings = await client.query({
  page: 1,
  pageSize: 100,
  filters: { impact: ['HIGH'] }
});
```

### Python

```python
import time
import requests
import os

class SoloditClient:
    def __init__(self):
        self.api_key = os.environ.get('CYFRIN_API_KEY')
        self.base_url = 'https://solodit.cyfrin.io/api/v1/solodit'
        self.rate_limit = {
            'limit': 20,
            'remaining': 20,
            'reset': None
        }
    
    def query(self, params):
        self._wait_if_rate_limited()
        
        response = requests.post(
            f'{self.base_url}/findings',
            headers={
                'Content-Type': 'application/json',
                'X-Cyfrin-API-Key': self.api_key
            },
            json=params
        )
        
        self._update_rate_limit(response)
        
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f'Rate limited. Waiting {retry_after} seconds...')
            time.sleep(retry_after)
            return self.query(params)  # Retry
        
        response.raise_for_status()
        return response.json()
    
    def _update_rate_limit(self, response):
        self.rate_limit = {
            'limit': int(response.headers.get('X-RateLimit-Limit', 20)),
            'remaining': int(response.headers.get('X-RateLimit-Remaining', 0)),
            'reset': int(response.headers.get('X-RateLimit-Reset', 0))
        }
    
    def _wait_if_rate_limited(self):
        if self.rate_limit['remaining'] > 0:
            return
        
        now = int(time.time())
        wait_seconds = max(0, self.rate_limit['reset'] - now) + 1
        
        print(f'Rate limited. Waiting {wait_seconds} seconds...')
        time.sleep(wait_seconds)


# Usage
client = SoloditClient()

findings = client.query({
    'page': 1,
    'pageSize': 100,
    'filters': {'impact': ['HIGH']}
})
```

### Bash with Retry

```bash
#!/bin/bash

query_solodit() {
  local payload="$1"
  local max_retries=3
  local retry_count=0
  
  while [ $retry_count -lt $max_retries ]; do
    response=$(curl -s -w "\n%{http_code}" -X POST \
      https://solodit.cyfrin.io/api/v1/solodit/findings \
      -H "Content-Type: application/json" \
      -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
      -d "$payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
      echo "$body"
      return 0
    elif [ "$http_code" = "429" ]; then
      echo "Rate limited. Waiting 60 seconds..." >&2
      sleep 60
      ((retry_count++))
    else
      echo "Error: HTTP $http_code" >&2
      return 1
    fi
  done
  
  echo "Max retries exceeded" >&2
  return 1
}

# Usage
query_solodit '{"page": 1, "pageSize": 10, "filters": {"impact": ["HIGH"]}}'
```

---

## Best Practices

### 1. Maximize Page Size

Reduce total requests by getting more per request:

```json
{
  "page": 1,
  "pageSize": 100,  // Maximum
  "filters": { ... }
}
```

### 2. Cache Results

Store results locally to avoid repeated queries:

```javascript
const cache = new Map();

async function getCachedOrFetch(cacheKey, queryFn) {
  if (cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }
  
  const result = await queryFn();
  cache.set(cacheKey, result);
  return result;
}
```

### 3. Batch Related Queries

Combine related queries when possible:

```javascript
// Instead of:
// Query 1: reentrancy findings
// Query 2: oracle findings
// Query 3: access control findings

// Do:
const findings = await client.query({
  pageSize: 100,
  filters: {
    tags: ['reentrancy', 'oracle', 'access-control'],
    impact: ['HIGH']
  }
});

// Then filter client-side
const reentrancyFindings = findings.filter(f => 
  f.tags.includes('reentrancy')
);
```

### 4. Implement Exponential Backoff

```javascript
async function queryWithBackoff(params, maxRetries = 5) {
  let delay = 1000; // Start with 1 second
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await client.query(params);
    } catch (error) {
      if (error.status !== 429) throw error;
      
      console.log(`Retry ${i + 1}/${maxRetries}, waiting ${delay}ms`);
      await sleep(delay);
      delay *= 2; // Double the delay each time
    }
  }
  
  throw new Error('Max retries exceeded');
}
```

### 5. Monitor Rate Limit Status

```javascript
function logRateLimitStatus(rateLimit) {
  const remaining = rateLimit.remaining;
  const total = rateLimit.limit;
  const pct = Math.round((remaining / total) * 100);
  
  if (remaining < 5) {
    console.warn(`⚠️ Low rate limit: ${remaining}/${total} (${pct}%)`);
  } else {
    console.log(`Rate limit: ${remaining}/${total} (${pct}%)`);
  }
}
```

---

## Handling 429 Responses

When rate limited, the API returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 45
Content-Type: application/json

{
  "error": "Rate limit exceeded",
  "retryAfter": 45
}
```

### Response Strategy

1. **Read `Retry-After` header** - Contains seconds to wait
2. **Wait the specified time** - Plus 1-2 second buffer
3. **Retry the request** - Same parameters
4. **Log the event** - For monitoring

---

## Pre-Request Checks

Before making requests, check if you have capacity:

```javascript
async function safeQuery(params) {
  // Check current status
  if (client.rateLimit.remaining <= 1) {
    // Wait for reset
    await client.waitForReset();
  }
  
  // Add buffer - don't use last few requests
  if (client.rateLimit.remaining <= 3) {
    console.log('Approaching rate limit, slowing down...');
    await sleep(2000);
  }
  
  return client.query(params);
}
```

---

## Rate Limit Calculator

For planning batch operations:

```javascript
function calculateBatchTime(totalResults, pageSize = 100) {
  const requests = Math.ceil(totalResults / pageSize);
  const windows = Math.ceil(requests / 20); // 20 requests per window
  const seconds = windows * 60;
  
  return {
    requests,
    windows,
    estimatedSeconds: seconds,
    estimatedMinutes: Math.ceil(seconds / 60)
  };
}

// Example: 500 findings to fetch
const estimate = calculateBatchTime(500);
// { requests: 5, windows: 1, estimatedSeconds: 60, estimatedMinutes: 1 }

// Example: 5000 findings to fetch
const estimate2 = calculateBatchTime(5000);
// { requests: 50, windows: 3, estimatedSeconds: 180, estimatedMinutes: 3 }
```

