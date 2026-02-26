#!/usr/bin/env python3
"""
Quality checker for audit skills based on Anthropic best practices.
Scores any SKILL.md file on a 10-point scale.

Usage:
    python scripts/quality-check.py <path-to-SKILL.md>
    python scripts/quality-check.py skills/solidity-scanner/SKILL.md
    python scripts/quality-check.py --all    # Score all SKILL.md files

Exit codes:
    0 — Score >= 8.0 (passes quality threshold)
    1 — Score < 8.0 (needs improvement)

Source: Adapted from claude-plugins skill-factory/scripts/quality-check.py
"""

import sys
import re
import os
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def parse_frontmatter(content):
    """Extract YAML frontmatter from markdown content."""
    # Handle both --- and ````skill fenced frontmatter
    match = re.match(r'^(?:---|\`{3,4}skill)\s*\n(.*?)\n(?:---|\`{3,4})', content, re.DOTALL)
    if not match:
        return {}

    fm = {}
    current_key = None
    for line in match.group(1).split('\n'):
        line = line.rstrip()
        if not line or line.startswith('#'):
            continue
        if ':' in line and not line.startswith(' ') and not line.startswith('-'):
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if value == '>-' or value == '|' or value == '>':
                current_key = key
                fm[key] = ''
            elif value:
                fm[key] = value
                current_key = key
            else:
                fm[key] = ''
                current_key = key
        elif current_key and (line.startswith('  ') or line.startswith('-')):
            if line.strip().startswith('-'):
                if current_key not in fm or isinstance(fm[current_key], str):
                    fm[current_key] = []
                if isinstance(fm[current_key], list):
                    fm[current_key].append(line.strip().lstrip('- '))
            else:
                if isinstance(fm[current_key], str):
                    fm[current_key] += ' ' + line.strip()
                    fm[current_key] = fm[current_key].strip()
    return fm


def check_description(frontmatter):
    """Check description quality (2.0 points)."""
    desc = frontmatter.get('description', '')
    if isinstance(desc, list):
        desc = ' '.join(desc)

    score = 0.0
    issues = []

    if not desc:
        issues.append("Missing description")
        return score, issues

    # Length check
    if len(desc) < 50:
        issues.append(f"Description too short ({len(desc)} chars, need >= 50)")
    else:
        score += 0.5

    # Specificity check
    vague_words = ['helps with', 'tool for', 'useful for', 'handles things']
    if any(word in desc.lower() for word in vague_words):
        issues.append("Description contains vague phrases ('helps with', 'tool for')")
    else:
        score += 0.5

    # When-to-use / trigger guidance
    trigger_phrases = ['when ', 'use when', 'use for', 'trigger']
    if any(phrase in desc.lower() for phrase in trigger_phrases):
        score += 0.5
    else:
        issues.append("Description missing 'when to use' guidance")

    # Third-person check (use word boundaries to avoid false positives like 'CI' matching 'i')
    first_person_patterns = [r'\byou\b', r'\byour\b', r'\bi\b', r"\bi'm\b", r"\bi'll\b", r'\bwe\b']
    if not any(re.search(p, desc, re.IGNORECASE) for p in first_person_patterns):
        score += 0.5
    else:
        issues.append("Description should be third person (avoid 'you', 'I')")

    return min(score, 2.0), issues


def check_name(frontmatter):
    """Check name convention (0.5 points)."""
    name = frontmatter.get('name', '') or frontmatter.get('id', '')

    score = 0.0
    issues = []

    if not name:
        issues.append("Missing name/id field")
        return score, issues

    # Lowercase and hyphens
    if re.match(r'^[a-z0-9-]+$', name):
        score += 0.25
    else:
        issues.append(f"Name '{name}' should be lowercase-with-hyphens only")

    # Not too generic
    generic_names = {'helper', 'utils', 'tool', 'skill', 'misc', 'general'}
    if name not in generic_names:
        score += 0.25
    else:
        issues.append(f"Name '{name}' is too generic")

    return min(score, 0.5), issues


def check_conciseness(content):
    """Check length (1.5 points)."""
    lines = content.count('\n') + 1

    if lines < 300:
        return 1.5, []
    elif lines < 500:
        return 1.0, [f"SKILL.md is {lines} lines (< 300 ideal)"]
    elif lines < 800:
        return 0.5, [f"SKILL.md is {lines} lines (recommend < 500, apply progressive disclosure)"]
    else:
        return 0.0, [f"SKILL.md is {lines} lines (MUST split into reference files)"]


def check_progressive_disclosure(skill_path):
    """Check for progressive disclosure (1.0 points)."""
    skill_dir = Path(skill_path).parent
    score = 0.0
    issues = []

    # Check for references/ or resources/ directory
    has_refs = (skill_dir / 'references').is_dir() or (skill_dir / 'resources').is_dir()
    if has_refs:
        score += 0.5
    else:
        issues.append("No references/ or resources/ directory for progressive disclosure")

    # Check SKILL.md links to reference files
    with open(skill_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    ref_links = re.findall(r'\[.*?\]\(((?:references|resources|workflows)/.*?)\)', content)
    if ref_links:
        score += 0.5
    elif has_refs:
        issues.append("Has references/ directory but SKILL.md doesn't link to it")

    return min(score, 1.0), issues


def check_examples(content):
    """Check for code examples (1.0 points)."""
    code_blocks = len(re.findall(r'```[\w]*\n', content))

    if code_blocks >= 5:
        return 1.0, []
    elif code_blocks >= 3:
        return 0.75, [f"{code_blocks} code examples (5+ recommended)"]
    elif code_blocks >= 1:
        return 0.5, [f"Only {code_blocks} code example(s) (recommend 5+)"]
    else:
        return 0.0, ["No code examples found"]


def check_structure(content):
    """Check document structure (1.0 points)."""
    issues = []
    score = 1.0

    # Check for section headings
    headings = re.findall(r'^#{1,3} .+', content, re.MULTILINE)
    if len(headings) < 3:
        issues.append(f"Only {len(headings)} section headings (need organized structure)")
        score -= 0.5

    # Heading hierarchy — check for skips (## then #### without ###)
    heading_levels = [len(re.match(r'(#+)', h).group(1)) for h in headings]
    for i in range(1, len(heading_levels)):
        if heading_levels[i] > heading_levels[i-1] + 1:
            issues.append("Heading hierarchy skips levels (e.g., ## → ####)")
            score -= 0.3
            break

    # Windows paths check
    if re.search(r'[A-Z]:\\', content):
        issues.append("Contains Windows-style paths (use Unix / forward slashes)")
        score -= 0.4

    return max(score, 0.0), issues


def check_antipatterns(content):
    """Check for anti-patterns (1.0 points)."""
    issues = []
    score = 1.0

    # Time-sensitive information
    time_patterns = [
        r'as of \d{4}',
        r'before (?:january|february|march|april|may|june|july|august|september|october|november|december) \d{4}',
        r'after (?:january|february|march|april|may|june|july|august|september|october|november|december) \d{4}',
    ]
    for pattern in time_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append("Contains time-sensitive information")
            score -= 0.5
            break

    # Inconsistent terminology (skill vs plugin)
    has_skill = bool(re.search(r'\bskill\b', content, re.IGNORECASE))
    has_plugin = bool(re.search(r'\bplugin\b', content, re.IGNORECASE))
    if has_skill and has_plugin:
        # Allow if in a context-explaining line
        context_lines = len(re.findall(r'(?:skill|plugin).*(?:skill|plugin)', content, re.IGNORECASE))
        if context_lines == 0:
            issues.append("Inconsistent terminology: mixes 'skill' and 'plugin'")
            score -= 0.5

    return max(score, 0.0), issues


def check_degree_of_freedom(content):
    """Check degree of freedom appropriateness (0.5 points)."""
    # Heuristic: check for a mix of prescriptive and flexible language
    prescriptive = len(re.findall(r'\b(?:MUST|ALWAYS|NEVER|exactly|mandatory)\b', content, re.IGNORECASE))
    flexible = len(re.findall(r'\b(?:consider|may|could|optional|as needed)\b', content, re.IGNORECASE))

    if prescriptive > 0 or flexible > 0:
        return 0.5, []
    else:
        return 0.25, ["No clear guidance on required vs optional behavior"]


def check_dependencies(content, frontmatter):
    """Check dependency documentation (0.5 points)."""
    deps = frontmatter.get('dependencies', [])
    has_deps_section = bool(re.search(r'(?:dependencies|requirements|prerequisites)', content, re.IGNORECASE))

    if deps or has_deps_section:
        return 0.5, []
    else:
        return 0.25, ["No dependencies section (add if external tools are needed)"]


def check_error_handling(content, skill_path):
    """Check error handling in scripts (0.5 points)."""
    skill_dir = Path(skill_path).parent
    scripts_dir = skill_dir / 'scripts'

    if not scripts_dir.is_dir():
        # No scripts — give partial credit
        return 0.4, []

    score = 0.5
    issues = []

    for script in scripts_dir.iterdir():
        if script.suffix in ('.py', '.sh', '.ps1', '.js'):
            script_content = script.read_text(encoding='utf-8', errors='ignore')
            if 'try' not in script_content and 'except' not in script_content \
               and 'catch' not in script_content and 'trap' not in script_content:
                issues.append(f"Script {script.name} lacks error handling")
                score -= 0.25

    return max(score, 0.0), issues


def check_testing(content):
    """Check for testing evidence (0.5 points)."""
    test_indicators = [
        r'\btest\b', r'\bevaluat', r'\bverif', r'\bvalidat',
        r'troubleshoot', r'common (?:issue|error|problem)',
    ]
    matches = sum(1 for p in test_indicators if re.search(p, content, re.IGNORECASE))

    if matches >= 3:
        return 0.5, []
    elif matches >= 1:
        return 0.25, ["Limited testing/validation evidence"]
    else:
        return 0.0, ["No testing or validation evidence"]


def score_skill(skill_path):
    """Score a skill file against Anthropic best practices. Returns (score, issues)."""
    path = Path(skill_path)
    if not path.exists():
        print(f"Error: {skill_path} not found")
        return 0.0, [f"File not found: {skill_path}"]

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    frontmatter = parse_frontmatter(content)

    total_score = 0.0
    all_issues = []

    checks = [
        ('Description',          lambda: check_description(frontmatter)),
        ('Name',                 lambda: check_name(frontmatter)),
        ('Conciseness',          lambda: check_conciseness(content)),
        ('Progressive Disclosure', lambda: check_progressive_disclosure(str(path))),
        ('Examples',             lambda: check_examples(content)),
        ('Degree of Freedom',    lambda: check_degree_of_freedom(content)),
        ('Dependencies',         lambda: check_dependencies(content, frontmatter)),
        ('Structure',            lambda: check_structure(content)),
        ('Error Handling',       lambda: check_error_handling(content, str(path))),
        ('Anti-Patterns',        lambda: check_antipatterns(content)),
        ('Testing',              lambda: check_testing(content)),
    ]

    print(f"\n{'='*60}")
    print(f"  Quality Report: {path.name}")
    print(f"  Path: {path}")
    print(f"{'='*60}\n")

    for name, check_func in checks:
        score, issues = check_func()
        total_score += score

        status = "PASS" if not issues else "WARN"
        icon = "+" if not issues else "!"
        print(f"  [{icon}] {name:.<30} {score:.1f}")

        if issues:
            for issue in issues:
                all_issues.append(f"{name}: {issue}")
                print(f"      -> {issue}")

    total_score = round(min(total_score, 10.0), 1)

    print(f"\n{'-'*60}")
    tier = "Excellent" if total_score >= 8.0 else "Good" if total_score >= 6.0 else "Fair" if total_score >= 4.0 else "Poor"
    print(f"  TOTAL: {total_score}/10.0  ({tier})")
    print(f"{'-'*60}\n")

    return total_score, all_issues


def find_all_skills(root_dir):
    """Find all SKILL.md files in the workspace."""
    skills = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for f in filenames:
            if f == 'SKILL.md':
                skills.append(os.path.join(dirpath, f))
    return sorted(skills)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scripts/quality-check.py <path-to-SKILL.md>")
        print("  python scripts/quality-check.py --all")
        print("  python scripts/quality-check.py --all --min-score 7.0")
        sys.exit(1)

    min_score = 8.0
    if '--min-score' in sys.argv:
        idx = sys.argv.index('--min-score')
        if idx + 1 < len(sys.argv):
            min_score = float(sys.argv[idx + 1])

    if sys.argv[1] == '--all':
        # Find workspace root (assume script is in scripts/)
        script_dir = Path(__file__).parent
        root = script_dir.parent / 'skills'

        if not root.is_dir():
            print(f"Error: skills/ directory not found at {root}")
            sys.exit(1)

        skills = find_all_skills(str(root))
        print(f"Found {len(skills)} SKILL.md files\n")

        results = []
        for skill_path in skills:
            score, issues = score_skill(skill_path)
            rel_path = os.path.relpath(skill_path, str(root.parent))
            results.append((rel_path, score, issues))

        # Summary table
        print(f"\n{'='*60}")
        print(f"  SUMMARY")
        print(f"{'='*60}\n")

        passing = 0
        failing = 0
        for path, score, issues in sorted(results, key=lambda x: x[1], reverse=True):
            status = "PASS" if score >= min_score else "FAIL"
            print(f"  [{status}] {score:>4.1f}/10  {path}")
            if score >= min_score:
                passing += 1
            else:
                failing += 1

        print(f"\n  {passing} passing, {failing} failing (threshold: {min_score})")

        sys.exit(0 if failing == 0 else 1)

    else:
        score, issues = score_skill(sys.argv[1])
        sys.exit(0 if score >= min_score else 1)


if __name__ == '__main__':
    main()
