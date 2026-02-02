/**
 * Semantic Search - Search patterns by meaning
 * 
 * @module semantic-search
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, dirname, relative } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_SKILLS_DIR = join(__dirname, '../../../skills');

/**
 * Simple TF-IDF-like search (no external dependencies)
 */
export class SemanticSearch {
  constructor(skillsDir = DEFAULT_SKILLS_DIR) {
    this.skillsDir = skillsDir;
    this.index = new Map();
    this.documents = new Map();
    this.initialized = false;
  }

  /**
   * Initialize the search index
   */
  async initialize() {
    if (this.initialized) return;
    
    const files = this._getAllMarkdownFiles(this.skillsDir);
    
    for (const file of files) {
      const content = readFileSync(file, 'utf-8');
      const relativePath = relative(this.skillsDir, file);
      
      this.documents.set(relativePath, {
        path: relativePath,
        fullPath: file,
        content,
        title: this._extractTitle(content),
        sections: this._extractSections(content)
      });
      
      // Index words
      const words = this._tokenize(content);
      for (const word of words) {
        if (!this.index.has(word)) {
          this.index.set(word, new Set());
        }
        this.index.get(word).add(relativePath);
      }
    }
    
    this.initialized = true;
  }

  /**
   * Search for patterns matching query
   * @param {string} query - Search query
   * @param {Object} options - Search options
   * @returns {Array} Search results
   */
  async search(query, options = {}) {
    await this.initialize();
    
    const {
      limit = 10,
      category = null,
      minScore = 0.1
    } = options;

    const queryWords = this._tokenize(query);
    const scores = new Map();

    // Calculate relevance scores
    for (const word of queryWords) {
      if (this.index.has(word)) {
        const docs = this.index.get(word);
        const idf = Math.log(this.documents.size / docs.size);
        
        for (const docPath of docs) {
          const doc = this.documents.get(docPath);
          const tf = this._countOccurrences(doc.content.toLowerCase(), word);
          const score = tf * idf;
          
          scores.set(docPath, (scores.get(docPath) || 0) + score);
        }
      }
    }

    // Filter and sort results
    let results = Array.from(scores.entries())
      .filter(([path, score]) => score >= minScore)
      .filter(([path]) => !category || path.includes(category))
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([path, score]) => {
        const doc = this.documents.get(path);
        return {
          path,
          title: doc.title,
          score: Math.round(score * 100) / 100,
          snippet: this._extractSnippet(doc.content, queryWords),
          sections: doc.sections.slice(0, 5)
        };
      });

    return results;
  }

  /**
   * Get document by path
   * @param {string} path - Document path
   * @returns {Object|null} Document content
   */
  async getDocument(path) {
    await this.initialize();
    return this.documents.get(path) || null;
  }

  /**
   * Search within specific categories
   * @param {string} query - Search query
   * @param {Array} categories - Categories to search
   * @returns {Array} Categorized results
   */
  async searchByCategory(query, categories = ['patterns', 'attack-trees', 'methodology']) {
    const results = {};
    
    for (const category of categories) {
      results[category] = await this.search(query, { category, limit: 5 });
    }
    
    return results;
  }

  /**
   * Get related documents
   * @param {string} docPath - Source document path
   * @param {number} limit - Max results
   * @returns {Array} Related documents
   */
  async getRelated(docPath, limit = 5) {
    await this.initialize();
    
    const doc = this.documents.get(docPath);
    if (!doc) return [];

    // Use title and first section as query
    const query = doc.title + ' ' + (doc.sections[0] || '');
    const results = await this.search(query, { limit: limit + 1 });
    
    // Remove self from results
    return results.filter(r => r.path !== docPath).slice(0, limit);
  }

  /**
   * Get all files in directory recursively
   * @private
   */
  _getAllMarkdownFiles(dir) {
    const files = [];
    
    if (!existsSync(dir)) return files;
    
    const items = readdirSync(dir);
    
    for (const item of items) {
      const fullPath = join(dir, item);
      const stat = statSync(fullPath);
      
      if (stat.isDirectory()) {
        files.push(...this._getAllMarkdownFiles(fullPath));
      } else if (item.endsWith('.md')) {
        files.push(fullPath);
      }
    }
    
    return files;
  }

  /**
   * Extract title from markdown
   * @private
   */
  _extractTitle(content) {
    const match = content.match(/^#\s+(.+)$/m);
    return match ? match[1] : 'Untitled';
  }

  /**
   * Extract section headings
   * @private
   */
  _extractSections(content) {
    const matches = content.matchAll(/^#{2,3}\s+(.+)$/gm);
    return Array.from(matches, m => m[1]);
  }

  /**
   * Tokenize text into words
   * @private
   */
  _tokenize(text) {
    return text.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2)
      .filter(w => !this._isStopWord(w));
  }

  /**
   * Check if word is a stop word
   * @private
   */
  _isStopWord(word) {
    const stopWords = new Set([
      'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all',
      'can', 'had', 'her', 'was', 'one', 'our', 'out', 'has',
      'have', 'been', 'were', 'being', 'this', 'that', 'with',
      'from', 'they', 'will', 'would', 'there', 'their', 'what',
      'about', 'which', 'when', 'make', 'like', 'just', 'over',
      'such', 'into', 'than', 'them', 'some', 'could', 'should'
    ]);
    return stopWords.has(word);
  }

  /**
   * Count word occurrences
   * @private
   */
  _countOccurrences(text, word) {
    const regex = new RegExp(`\\b${word}\\b`, 'gi');
    return (text.match(regex) || []).length;
  }

  /**
   * Extract relevant snippet
   * @private
   */
  _extractSnippet(content, queryWords, maxLength = 200) {
    const lines = content.split('\n');
    
    // Find line with most query words
    let bestLine = '';
    let bestScore = 0;
    
    for (const line of lines) {
      const lineLower = line.toLowerCase();
      let score = 0;
      for (const word of queryWords) {
        if (lineLower.includes(word)) score++;
      }
      if (score > bestScore) {
        bestScore = score;
        bestLine = line;
      }
    }
    
    if (bestLine.length > maxLength) {
      return bestLine.substring(0, maxLength) + '...';
    }
    
    return bestLine || content.substring(0, maxLength) + '...';
  }
}

/**
 * Convenience function for quick search
 * @param {string} query - Search query
 * @param {string} skillsDir - Skills directory path
 * @returns {Array} Search results
 */
export async function searchPatterns(query, skillsDir = DEFAULT_SKILLS_DIR) {
  const search = new SemanticSearch(skillsDir);
  return await search.search(query);
}

export default SemanticSearch;
