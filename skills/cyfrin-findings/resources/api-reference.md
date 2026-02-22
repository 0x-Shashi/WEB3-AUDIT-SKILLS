# Cyfrin/Solodit API Reference

## Base URL
`https://api.solodit.xyz/` (or equivalent endpoint)

## Endpoints
- `GET /findings` - Search findings
- `GET /findings/:id` - Get specific finding
- `GET /protocols` - List audited protocols
- `GET /auditors` - List audit firms

## Query Parameters
- `q` - Search query (vulnerability type, protocol name)
- `severity` - Filter by severity (critical, high, medium, low)
- `category` - Filter by category (reentrancy, oracle, access-control)
- `protocol_type` - Filter by protocol type (lending, dex, bridge)
- `page` / `limit` - Pagination

## Response Format
```json
{
  "findings": [
    {
      "id": "...",
      "title": "...",
      "severity": "HIGH",
      "category": "reentrancy",
      "description": "...",
      "impact": "...",
      "recommendation": "...",
      "protocol": "...",
      "auditor": "..."
    }
  ]
}
```
