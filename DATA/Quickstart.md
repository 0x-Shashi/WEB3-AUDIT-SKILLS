# 🚀 QUICK START GUIDE

## Get Up and Running in 5 Minutes

### Step 1: Setup (1 minute)

```bash
# Navigate to your DATA folder
cd DATA

# Copy all extraction files here
# (extract_solodit.js, test_api.js, package.json, etc.)

# No npm install needed - uses native Node.js fetch API
```

### Step 2: Test API (2 minutes)

```bash
node test_api.js
```

**Expected output:**
```
🧪 Testing Solodit API...

Test 1: API Connectivity
--------------------------------------------------
Status: 200 OK
Rate Limit: 20/20
✅ API connection successful
   Findings returned: 10

Test 2: Data Structure Inspection
--------------------------------------------------
Sample finding fields:
   id: (string) 12345
   title: (string) Reentrancy vulnerability in...
   description: (string) The contract allows reentrancy...
   impact: (string) HIGH
   tags: (array) [3 items]
   source: (string) code4rena
   ...

✅ Sample finding saved to DATA/test/sample_finding.json

[More test output...]

============================================================
✅ ALL TESTS PASSED
============================================================

✨ Ready for full extraction! Run: node extract_solodit.js
```

### Step 3: Run Full Extraction (30-45 minutes)

```bash
node extract_solodit.js
```

**What you'll see:**
```
🚀 Starting Solodit vulnerability extraction...

📊 Configuration:
   - Starting page: 1
   - Page size: 100
   - Request delay: 3500ms
   - Checkpoint interval: 50 pages

📄 Fetching page 1...
   ✓ Fetched 100 findings
   📈 Total so far: 100
   ⚡ Rate limit: 19/20 remaining

[... continues for ~30 minutes ...]

💾 Checkpoint saved: Page 50, Total findings: 5000

[... continues ...]

============================================================
🎉 EXTRACTION COMPLETE!
============================================================
📊 Summary:
   - Total findings: 50,234
   - Pages processed: 503
   - API requests: 503
   - Errors: 2
   - Duration: 32.5 minutes
   - Unique tags: 247
   - Unique sources: 23

🔝 Top 10 Vulnerability Types:
   1. reentrancy: 2,341 (4.66%)
   2. access control: 1,808 (3.60%)
   3. oracle: 1,502 (2.99%)
   [...]
```

### Step 4: Verify Success (1 minute)

```bash
# Check files were created
ls -lh DATA/raw/

# Should show:
# all_findings.json (100-200 MB)
# metadata.json (5-10 KB)

# Quick data check
node -e "const d=require('./DATA/raw/all_findings.json'); console.log('Total findings:', d.length)"

# Should output: Total findings: 50234 (or similar)
```

---

## ⚡ One-Line Commands

```bash
# Full pipeline (test + extract)
node test_api.js && node extract_solodit.js

# Just extract (skip test)
node extract_solodit.js

# Resume from checkpoint (if interrupted)
node extract_solodit.js
# Will prompt: "Resume from page X? (y/n)"

# Start fresh (clear checkpoints)
rm -rf DATA/checkpoints/* && node extract_solodit.js
```

---

## 🆘 Troubleshooting

### Issue: Rate Limited (429 Error)
**Solution:** Script automatically waits 60s. Just let it run.

### Issue: Network Timeout
**Solution:** Script retries 3 times automatically. Check internet.

### Issue: Script Crashes
**Solution:** Just run again - it will resume from last checkpoint.

### Issue: Empty Findings
**Solution:** Check API key is correct. Run test script first.

### Issue: Slow Extraction
**Solution:** Normal! 500 pages × 3.5s = ~29 minutes minimum.

---

## 📁 Output Files Location

After successful extraction:

```
DATA/
├── raw/
│   ├── all_findings.json          ← Your 50K findings (100+ MB)
│   └── metadata.json               ← Statistics and counts
│
├── logs/
│   ├── extraction_[timestamp].log  ← Detailed execution log
│   └── extraction_stats.json       ← Summary statistics
│
└── checkpoints/
    └── checkpoint_page_*.json      ← Recovery points
```

---

## ✅ Success Indicators

You'll know extraction was successful if:

1. ✅ Script runs for 30-45 minutes
2. ✅ Shows "EXTRACTION COMPLETE" at end
3. ✅ `all_findings.json` is 100+ MB
4. ✅ Contains ~50,000 objects
5. ✅ Metadata shows expected tag counts
6. ✅ Errors count is 0-5 (not hundreds)
7. ✅ Top tags include: reentrancy, access control, oracle

---

## 🎯 Next Steps

After extraction completes:

1. **Verify data quality:**
   ```bash
   node -e "const d=require('./DATA/raw/all_findings.json'); console.log('Findings:', d.length); console.log('Sample:', d[0].title);"
   ```

2. **Check metadata:**
   ```bash
   cat DATA/raw/metadata.json | head -50
   ```

3. **Review logs:**
   ```bash
   cat DATA/logs/extraction_stats.json
   ```

4. **Move to Phase 2:** Data processing and analysis

---

## 💡 Pro Tips

1. **Run overnight** if you want to start fresh without interruption
2. **Keep checkpoints** until you verify data quality
3. **Check logs** if anything seems off
4. **Don't interrupt** during checkpoint saves (every 50 pages)
5. **Monitor progress** - it should fetch ~100 findings every 3.5 seconds

---

## 🎓 Using with GitHub Copilot / VS Code

If you're implementing this in VS Code with GitHub Copilot:

1. Open `PROMPTS_GUIDE.md`
2. Copy the "Master Prompt" section
3. Paste in Copilot chat
4. Let it generate/improve the code
5. Test with `node test_api.js`
6. Run full extraction

The prompts are designed to give Copilot/Claude all the context needed
to generate production-quality extraction code.

---

## 📞 Questions?

**Q: How long does it take?**  
A: 30-45 minutes for ~50,000 findings

**Q: What if it crashes?**  
A: Just run again - resumes from last checkpoint

**Q: Can I run multiple times?**  
A: Yes, but data won't change unless Solodit updates

**Q: Is the API key free?**  
A: Yes, Solodit provides free API access

**Q: What's the rate limit?**  
A: 20 requests per 60 seconds (handled automatically)

**Q: Can I filter the data?**  
A: Not in Phase 1. Filtering happens in Phase 2 (processing)

---

**Ready? Let's extract 50K vulnerabilities! 🚀**

```bash
node extract_solodit.js
```