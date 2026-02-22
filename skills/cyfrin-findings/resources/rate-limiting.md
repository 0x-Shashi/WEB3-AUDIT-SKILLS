# Rate Limiting

## API Limits
- 100 requests per minute per API key
- 1000 requests per hour per API key
- Batch queries preferred over many single queries

## Best Practices
- Cache responses locally for repeated lookups
- Use specific queries to reduce result volume
- Paginate with reasonable page sizes (20-50)
- Implement exponential backoff on 429 responses
- Pre-fetch relevant findings during context building phase
