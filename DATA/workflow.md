# Solodit Extraction Workflow

## 📊 Complete Pipeline Visualization

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: DATA EXTRACTION                     │
│                         (30-45 minutes)                         │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   1. Test API (2 min)   │
                    │   npm run test          │
                    └─────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │ 2. Run Extraction       │
                    │    npm run extract      │
                    │    (~500 requests)      │
                    └─────────────────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                 ▼
        [Page 1-50]       [Page 51-100]      [Page 101-500]
        Checkpoint 1      Checkpoint 2       Checkpoint N
                │                 │                 │
                └─────────────────┼─────────────────┘
                                  ▼
                        ┌─────────────────┐
                        │ 3. Save Output  │
                        │  - Raw JSON     │
                        │  - Metadata     │
                        │  - Statistics   │
                        └─────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    OUTPUT FILES CREATED                         │
├─────────────────────────────────────────────────────────────────┤
│  DATA/raw/all_findings.json           (~50K findings, 100+ MB) │
│  DATA/raw/metadata.json                (Aggregated statistics)  │
│  DATA/logs/extraction_TIMESTAMP.log    (Detailed execution log) │
│  DATA/logs/extraction_stats.json       (Summary statistics)     │
│  DATA/checkpoints/*.json               (Recovery points)        │
└─────────────────────────────────────────────────────────────────┘
```

## 🔄 Request Flow Diagram

```
┌──────────┐                                           ┌──────────┐
│          │    POST /api/v1/solodit/findings         │          │
│  Script  │──────────────────────────────────────────>│  Solodit │
│          │    Headers: X-Cyfrin-API-Key              │   API    │
│          │    Body: {page, pageSize, filters}        │          │
│          │                                           │          │
│          │<──────────────────────────────────────────│          │
│          │    Response: {findings: [...]}            │          │
│          │    Headers: X-RateLimit-*                 │          │
└──────────┘                                           └──────────┘
     │
     │  Wait 3.5s (rate limiting)
     │
     ▼
┌──────────┐
│  Store   │
│ Findings │
│    +     │
│ Metadata │
└──────────┘
     │
     │  Every 50 pages
     │
     ▼
┌──────────┐
│   Save   │
│Checkpoint│
└──────────┘
```

## 📈 Data Transformation Flow

```
Raw API Response                    Processed Data
─────────────────                   ──────────────

{                                   Aggregated:
  findings: [                       ├─ tags: Map<string, count>
    {                               ├─ sources: Map<string, count>
      id: "123",                    ├─ languages: Map<string, count>
      title: "...",                 ├─ impacts: Map<string, count>
      tags: ["reentrancy"],         └─ protocols: Map<string, count>
      source: "code4rena",
      language: "solidity",         Validated:
      impact: "HIGH",               ├─ Required fields present
      ...                           ├─ No duplicates
    },                              ├─ Correct data types
    ...                             └─ Reasonable values
  ]
}                                   
                                    Stored:
                                    ├─ all_findings.json (raw)
                                    └─ metadata.json (stats)
```

## ⚠️ Error Handling Flow

```
                  API Request
                       │
                       ▼
              ┌────────────────┐
              │  Network Call  │
              └────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
    ┌────────┐   ┌─────────┐   ┌─────────┐
    │ Success│   │ 429 Rate│   │  Error  │
    │        │   │  Limit  │   │         │
    └────────┘   └─────────┘   └─────────┘
         │             │             │
         │             ▼             ▼
         │      Wait X-RateLimit    Retry
         │         Reset            (3x max)
         │             │             │
         │             └──────┬──────┘
         │                    │
         └────────────────────┼─────────────┐
                              ▼             ▼
                        Store Data    Save Emergency
                        Continue      Checkpoint
                                           │
                                           ▼
                                      Log Error
                                           │
                                           ▼
                                     Exit Gracefully
```

## 📊 Progress Tracking Example

```
Extraction Progress:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Time: 15:23 elapsed
Page: 234 / ~500 (46.8%)
Findings: 23,400 total
Rate Limit: 17/20 remaining
Est. Remaining: ~18 minutes

Recent Activity:
✓ Page 234 → 100 findings
✓ Page 233 → 100 findings  
✓ Page 232 → 100 findings
💾 Checkpoint saved (page 200)

Top Tags So Far:
1. reentrancy: 1,234
2. access-control: 987
3. oracle: 765
```

## 🎯 Checkpoint System

```
Checkpoint File Structure:
──────────────────────────

checkpoint_page_50.json
{
  "lastPage": 50,
  "totalFindings": 5000,
  "findings": [...],  // All findings so far
  "timestamp": "2025-01-29T10:15:30Z"
}

On Restart:
───────────
1. Scan DATA/checkpoints/
2. Find highest page number
3. Load checkpoint data
4. Prompt: "Resume from page 51? (y/n)"
   │
   ├─ Yes → Continue from page 51
   │         Append new findings to existing array
   │
   └─ No  → Clear checkpoints
            Start fresh from page 1
```

## 📁 File Structure After Extraction

```
project-root/
│
├── extract_solodit.js        (Main extraction script)
├── test_api.js                (API connectivity test)
├── package.json               (Dependencies and scripts)
├── README.md                  (Documentation)
├── PROMPTS_GUIDE.md           (AI prompts reference)
│
└── DATA/
    ├── raw/
    │   ├── all_findings.json       (50K+ findings, 100-200MB)
    │   └── metadata.json           (Statistics, 5-10KB)
    │
    ├── checkpoints/
    │   ├── checkpoint_page_50.json
    │   ├── checkpoint_page_100.json
    │   └── ...
    │
    ├── logs/
    │   ├── extraction_1738156789.log
    │   └── extraction_stats.json
    │
    └── test/
        ├── sample_finding.json
        ├── test_findings.json
        └── test_metadata.json
```

## 🚦 Status Indicators Reference

```
Progress Indicators:
────────────────────
📄  Fetching page
✓   Success
⚡  Rate limit status
📈  Progress update
💾  Checkpoint saved
⏸️  Paused (rate limited)
🔄  Retrying
❌  Error
⚠️  Warning
🎉  Completion

Log Levels:
───────────
[INFO]    Normal operation
[WARN]    Warning condition
[ERROR]   Error occurred
[✓]       Success indicator
```

## 🎓 What Happens After Extraction

```
Phase 1: EXTRACTION (Current)
└─> 50K+ findings extracted to JSON

Phase 2: PROCESSING (Next)
├─> Parse and analyze all findings
├─> Count vulnerability frequencies
├─> Group by tags, severity, chain
├─> Extract top 500 patterns
└─> Generate statistical reports

Phase 3: SKILL GENERATION (Final)
├─> Create pattern library (500+ files)
│   ├─ patterns/reentrancy.md
│   ├─ patterns/oracle-manipulation.md
│   └─ ...
├─> Build master checklist
│   └─ MASTER_CHECKLIST.md (prioritized)
├─> Generate chain-specific guides
│   ├─ solidity/
│   ├─ rust/
│   └─ cairo/
└─> Format for AI consumption
    └─> Deploy to Cursor/Antigravity/Claude Code
```

## ⏱️ Timeline Overview

```
┌────────────────────────────────────────────────────────┐
│  Complete Project Timeline                             │
├────────────────────────────────────────────────────────┤
│  Phase 1: Extraction    [████████░░░░░░] 30-45 min    │
│  Phase 2: Processing    [░░░░░░░░░░░░░░] 15-30 min    │
│  Phase 3: Generation    [░░░░░░░░░░░░░░] 20-40 min    │
├────────────────────────────────────────────────────────┤
│  Total Project Time: ~1.5 - 2 hours                    │
└────────────────────────────────────────────────────────┘
```

---

## 🎯 Success Checklist

After running `npm run extract`, verify:

```
□ Script ran for ~30-45 minutes
□ Console shows "EXTRACTION COMPLETE"
□ DATA/raw/all_findings.json exists
□ File size is 100+ MB
□ Contains ~50,000 objects
□ metadata.json has tag counts
□ Top tags include: reentrancy, access control, oracle
□ Stats show 0-5 errors (not hundreds)
□ Logs directory has execution log
□ Can open JSON file without errors
```

If all checkboxes are ✅, you're ready for Phase 2!