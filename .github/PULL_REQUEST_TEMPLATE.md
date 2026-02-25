## Description

<!-- Describe your changes in detail. What security patterns, skills, or improvements are you adding? -->

## Type of Change

<!-- Mark the relevant option with an "x" -->

- [ ] New vulnerability pattern
- [ ] New scanner skill (chain-specific)
- [ ] New audit workflow
- [ ] Pattern improvement / update
- [ ] Scanner skill improvement / update
- [ ] Bug fix (incorrect pattern, wrong severity, etc.)
- [ ] Documentation update
- [ ] Structural improvement (YAML frontmatter, references, cross-links)
- [ ] Other (please describe):

## Skill / Pattern Details

**File(s) changed:**
<!-- List the files you added or modified -->

**Category:** <!-- e.g., patterns, solidity-scanner, methodology, exploit-forensics -->
**Severity (if pattern):** <!-- Critical / High / Medium / Low / Informational -->

---

## Security Content Checklist

<!-- Mark completed items with an "x". Not all items apply to every PR. -->

### Pattern Quality

- [ ] Pattern includes **vulnerable code example** (Solidity, Rust, Move, Cairo, etc.)
- [ ] Pattern includes **fixed/correct code example** showing the mitigation
- [ ] **Detection method** described (manual review steps, grep patterns, or tool commands)
- [ ] **Severity classification** follows the project's severity guide (`severity/SKILL.md`)
- [ ] YAML frontmatter includes `id`, `title`, `category`, `tags`, and `last_updated`

### Accuracy & Integrity

- [ ] **No false information** about exploit amounts, dates, or affected protocols
- [ ] All real-world exploit references link to **verifiable sources** (audit reports, post-mortems, on-chain evidence)
- [ ] Code examples are **compilable/valid** for their target language and version
- [ ] Severity assessment is **justified** — not inflated or downplayed

### Cross-References & Integration

- [ ] Cross-references to `XREF.md` updated (if adding a new pattern)
- [ ] `ROUTE-MAP.md` updated (if adding new files or restructuring)
- [ ] Related skills linked in the `## Integration with Other Skills` section
- [ ] `TRIGGERS.md` updated with new trigger phrases (if adding a new skill)
- [ ] `CHANGELOG.md` entry added

### Structure & Format

- [ ] YAML frontmatter with `description: "Use when..."` field included (for scanner skills)
- [ ] Matches the existing file format in the target directory
- [ ] File size is reasonable (patterns < 20KB, scanner skills < 25KB)
- [ ] No duplicate content — checked existing patterns for overlap
- [ ] Markdown renders correctly (tables, code blocks, links)

---

## Real-World References (if applicable)

<!-- List any audit reports, exploit post-mortems, or on-chain references used -->

| Reference | Source | Link |
|-----------|--------|------|
| <!-- e.g., Euler Finance exploit --> | <!-- e.g., Rekt News --> | <!-- URL --> |

## Testing

<!-- Describe how you validated this contribution -->

- [ ] Verified pattern against real-world exploit(s)
- [ ] Tested with AI agent (Claude/Cursor) to confirm skill triggers correctly
- [ ] Ran existing test suite (`npm test`) with no regressions
- [ ] Manually verified all internal links resolve to existing files

## Security Review

<!-- For the reviewer — these are checked during PR review -->

- [ ] No secrets, private keys, API keys, or sensitive data included
- [ ] No copyrighted content copied verbatim (paraphrased with attribution)
- [ ] Pattern does not provide step-by-step exploit instructions without mitigation
- [ ] Changes don't break existing skill routing or pattern detection

## Additional Context

<!-- Add any other context, screenshots, or discussion links about this PR -->
