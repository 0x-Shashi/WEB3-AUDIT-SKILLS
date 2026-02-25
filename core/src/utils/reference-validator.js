/**
 * Reference Validator — Checks that all file references in navigation documents resolve
 * Prevents broken links in ROUTE-MAP.md, INDEX.md, XREF.md, etc.
 */

import { readFile, readdir, access } from 'fs/promises';
import { join, dirname, basename, relative } from 'path';

const NAVIGATION_FILES = [
  'ROUTE-MAP.md',
  'INDEX.md',
  'XREF.md',
  'MASTER_CHECKLIST.md',
  'TRIGGERS.md',
];

// Patterns to extract file references from markdown
const REFERENCE_PATTERNS = [
  // Tree-style: ├─► path/file.md or └─► path/file.md
  /[├└]─►\s+([a-zA-Z0-9_\-\/]+\.(?:md|sol|yaml|json))/g,
  // Checkbox-style: □ path/file.md
  /□\s+([a-zA-Z0-9_\-\/]+\.(?:md|sol|yaml|json))/g,
  // Table cell: | path/file.md | or | text | path/file.md |
  /\|\s*(?:[^|]*?\s)?([a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-\/]+\.(?:md|sol|yaml|json))/g,
  // YAML frontmatter list: - path/file.md
  /^\s*-\s+([a-zA-Z0-9_\-\/]+\.(?:md|sol|yaml|json))\s*$/gm,
  // Markdown link: [text](path/file.md)
  /\]\(([a-zA-Z0-9_\-\/]+\.(?:md|sol|yaml|json))\)/g,
  // Backtick-wrapped: `path/file.md`
  /`([a-zA-Z0-9_\-\/]+\.(?:md|sol|yaml|json))`/g,
];

// File references that are example-only (not meant to resolve)
const IGNORE_PATTERNS = [
  /example/i,
  /template/i,
  /your-/i,
  /\*\*/,
  /\*/,
];

export class ReferenceValidator {
  constructor(skillsDir) {
    this.skillsDir = skillsDir;
    this.results = [];
  }

  /**
   * Extract all file references from a markdown file
   */
  extractReferences(content, sourceFile) {
    const refs = new Map(); // path → Set of line numbers

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of REFERENCE_PATTERNS) {
        // Reset regex state
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(line)) !== null) {
          const ref = match[1].trim();
          // Skip example/template references
          if (IGNORE_PATTERNS.some(p => p.test(ref))) continue;
          // Skip bare filenames without directory (like "SKILL.md" — too ambiguous)
          if (!ref.includes('/') && !ref.startsWith('patterns/') && sourceFile !== ref) continue;
          
          if (!refs.has(ref)) refs.set(ref, new Set());
          refs.get(ref).add(i + 1);
        }
      }
    }

    return refs;
  }

  /**
   * Check if a file reference resolves relative to the skills directory
   */
  async resolves(ref) {
    const fullPath = join(this.skillsDir, ref);
    try {
      await access(fullPath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Find the closest matching file for a broken reference
   */
  async findClosestMatch(ref) {
    const dir = dirname(ref);
    const name = basename(ref, '.md').toLowerCase();
    const targetDir = join(this.skillsDir, dir);

    try {
      const files = await readdir(targetDir);
      const mdFiles = files.filter(f => f.endsWith('.md'));

      // Score each file by similarity to the broken reference
      const scored = mdFiles.map(f => {
        const fName = basename(f, '.md').toLowerCase();
        let score = 0;

        // Exact substring match
        if (fName.includes(name) || name.includes(fName)) score += 50;

        // Word overlap
        const refWords = new Set(name.split('-'));
        const fileWords = new Set(fName.split('-'));
        const overlap = [...refWords].filter(w => fileWords.has(w)).length;
        score += overlap * 20;

        return { file: `${dir}/${f}`, score };
      }).filter(s => s.score > 0)
        .sort((a, b) => b.score - a.score);

      return scored.length > 0 ? scored[0].file : null;
    } catch {
      return null;
    }
  }

  /**
   * Validate a single navigation file
   */
  async validateFile(filename) {
    const filePath = join(this.skillsDir, filename);
    let content;
    try {
      content = await readFile(filePath, 'utf8');
    } catch {
      return { file: filename, error: 'File not found', refs: [] };
    }

    const refs = this.extractReferences(content, filename);
    const results = [];

    for (const [ref, lineNumbers] of refs) {
      const exists = await this.resolves(ref);
      if (!exists) {
        const closest = await this.findClosestMatch(ref);
        results.push({
          reference: ref,
          lines: [...lineNumbers],
          exists: false,
          suggestion: closest,
        });
      }
    }

    return {
      file: filename,
      totalRefs: refs.size,
      broken: results.length,
      valid: refs.size - results.length,
      issues: results,
    };
  }

  /**
   * Validate all navigation files
   */
  async validateAll() {
    const results = [];

    for (const file of NAVIGATION_FILES) {
      const filePath = join(this.skillsDir, file);
      try {
        await access(filePath);
        const result = await this.validateFile(file);
        results.push(result);
      } catch {
        // File doesn't exist, skip
      }
    }

    return {
      files: results,
      summary: {
        totalFiles: results.length,
        totalRefs: results.reduce((sum, r) => sum + r.totalRefs, 0),
        totalBroken: results.reduce((sum, r) => sum + r.broken, 0),
        totalValid: results.reduce((sum, r) => sum + r.valid, 0),
      },
    };
  }
}
