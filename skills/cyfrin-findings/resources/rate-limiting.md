---
id: CYFRIN-RATE-LIMITING
title: Rate Limiting and Caching Strategy
parent: cyfrin-findings
type: resource
last_updated: 2025-01-31
---

# Rate Limiting

## API Rate Limits

| Limit | Value | Scope |
|-------|-------|-------|
| Requests per minute | 100 | Per API key |
| Requests per day | 10,000 | Per API key |
| Max page size | 100 results | Per request |
| Concurrent connections | 10 | Per API key |

When a rate limit is exceeded, the API returns HTTP `429 Too Many Requests` with a `retry_after` field indicating the number of seconds to wait.

**429 Response Example:**

```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded. Please wait 60 seconds before retrying.",
    "retry_after": 60
  }
}
```

---

## Exponential Backoff Implementation

When receiving a `429` response, implement exponential backoff with jitter to avoid thundering herd problems.

**Algorithm:**

```
wait_time = min(base_delay * 2^attempt + random_jitter, max_delay)
```

**Recommended Parameters:**

| Parameter | Value |
|-----------|-------|
| Base delay | 1 second |
| Max delay | 60 seconds |
| Max retries | 5 |
| Jitter range | 0–500ms (random) |

**JavaScript Implementation:**

```javascript
async function fetchWithBackoff(url, apiKey, maxRetries = 5) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const response = await fetch(url, {
      headers: { 'X-API-Key': apiKey }
    });

    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after') || 
                          Math.min(1000 * Math.pow(2, attempt) + Math.random() * 500, 60000);
      console.log(`Rate limited. Waiting ${retryAfter}ms (attempt ${attempt + 1}/${maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, retryAfter));
      continue;
    }

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }
  throw new Error(`Failed after ${maxRetries} retries due to rate limiting`);
}
```

---

## Caching Strategy

Since audit findings are historical data and rarely change, aggressive caching is both safe and recommended.

### Cache Tiers

| Tier | Data Type | TTL | Storage |
|------|-----------|-----|---------|
| L1 (Memory) | Current session queries | Session duration | In-memory map |
| L2 (Local file) | Downloaded finding sets | 7 days | JSON files in project `.cache/` |
| L3 (Checkpoint) | Bulk download progress | Indefinite | Checkpoint JSON files |

### Cache Key Strategy

Use a deterministic key based on the query parameters:

```javascript
function cacheKey(params) {
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  return `solodit_${crypto.createHash('md5').update(sorted).digest('hex')}`;
}
```

### Cache Invalidation

- **Finding data**: Rarely needs invalidation. New findings are added but existing ones don't change.
- **Protocol listing**: Refresh weekly — new protocols are added as new audits are published.
- **Category listing**: Refresh monthly — vulnerability categories are relatively stable.
- **Force refresh**: Add `?_nocache=1` parameter to bypass cache for specific queries.

---

## Bulk Download Strategy

When downloading large datasets (e.g., all findings for a vulnerability category), use checkpointing to resume on failure.

### Checkpoint Pattern

```javascript
async function bulkDownload(category, apiKey) {
  const checkpointDir = './checkpoints';
  const checkpointFile = `${checkpointDir}/checkpoint_${category}.json`;
  
  // Resume from checkpoint if exists
  let startPage = 1;
  let allFindings = [];
  
  if (fs.existsSync(checkpointFile)) {
    const checkpoint = JSON.parse(fs.readFileSync(checkpointFile));
    startPage = checkpoint.nextPage;
    allFindings = checkpoint.findings;
    console.log(`Resuming from page ${startPage} (${allFindings.length} findings loaded)`);
  }

  let page = startPage;
  let totalPages = Infinity;

  while (page <= totalPages) {
    const data = await fetchWithBackoff(
      `https://api.solodit.xyz/findings?category=${category}&page=${page}&per_page=50`,
      apiKey
    );
    
    totalPages = data.pagination.total_pages;
    allFindings.push(...data.data);
    
    // Save checkpoint every 50 pages
    if (page % 50 === 0) {
      fs.writeFileSync(checkpointFile, JSON.stringify({
        nextPage: page + 1,
        findings: allFindings,
        totalPages,
        timestamp: new Date().toISOString()
      }));
      console.log(`Checkpoint saved at page ${page}/${totalPages}`);
    }
    
    page++;
    // Small delay between requests to stay under rate limit
    await new Promise(resolve => setTimeout(resolve, 650)); // ~90 req/min
  }

  return allFindings;
}
```

---

## Request Budget Planning

Plan your API usage based on the research task:

| Task | Estimated Requests | Time at Rate Limit |
|------|-------------------|--------------------|
| Single vulnerability lookup | 1 | Instant |
| Category deep-dive (50 findings) | 1 | Instant |
| Protocol threat model | 5–10 | ~6 seconds |
| Full category download (500 findings) | 10 | ~6 seconds |
| Bulk research (5,000 findings) | 100 | ~1 minute |
| Full database download (50,530 findings) | 1,011 | ~11 minutes |

---

## Best Practices

1. **Batch queries during context-building phase**: Pre-fetch relevant findings at the start of an audit rather than making ad-hoc queries throughout
2. **Cache aggressively**: Historical findings don't change — cache for at least 7 days
3. **Use specific filters**: `?category=reentrancy&protocol_type=lending&severity=high` returns far fewer results than an unfiltered query
4. **Paginate with reasonable sizes**: `per_page=50` is the sweet spot between request count and payload size
5. **Implement checkpoints**: For any download spanning more than 10 pages, save checkpoints
6. **Add inter-request delay**: Even when not rate-limited, a 650ms delay between requests (~90 req/min) provides headroom
7. **Monitor daily quota**: Track your daily request count to avoid hitting the 10,000/day limit during bulk operations
