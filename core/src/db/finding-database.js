/**
 * Finding Database
 * 
 * Persistent storage for security findings using SQLite.
 * Tracks findings across audits, stores metadata, and enables queries.
 * 
 * Usage:
 *   const db = new FindingDatabase('./findings.db');
 *   await db.init();
 *   await db.addFinding({ ... });
 */

const path = require('path');
const fs = require('fs');

// Use better-sqlite3 for synchronous, faster SQLite
let Database;
try {
  Database = require('better-sqlite3');
} catch (e) {
  // Fallback to JSON storage if better-sqlite3 not available
  Database = null;
}

class FindingDatabase {
  constructor(dbPath = './web3audit-findings.db') {
    this.dbPath = path.resolve(dbPath);
    this.db = null;
    this.useJson = !Database;
    this.jsonPath = this.dbPath.replace('.db', '.json');
    this.data = null;
  }

  /**
   * Initialize the database
   * Creates tables if they don't exist
   * 
   * @returns {Promise<void>}
   */
  async init() {
    if (this.useJson) {
      return this._initJson();
    }

    this.db = new Database(this.dbPath);
    
    // Enable WAL mode for better performance
    this.db.pragma('journal_mode = WAL');

    // Create tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        path TEXT UNIQUE,
        type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER,
        name TEXT,
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        status TEXT DEFAULT 'in_progress',
        notes TEXT,
        FOREIGN KEY (project_id) REFERENCES projects(id)
      );

      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id INTEGER,
        project_id INTEGER,
        external_id TEXT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT,
        description TEXT,
        file_path TEXT,
        start_line INTEGER,
        end_line INTEGER,
        code_snippet TEXT,
        source TEXT,
        status TEXT DEFAULT 'open',
        false_positive INTEGER DEFAULT 0,
        notes TEXT,
        recommendation TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (audit_id) REFERENCES audits(id),
        FOREIGN KEY (project_id) REFERENCES projects(id)
      );

      CREATE TABLE IF NOT EXISTS finding_tags (
        finding_id INTEGER,
        tag TEXT,
        PRIMARY KEY (finding_id, tag),
        FOREIGN KEY (finding_id) REFERENCES findings(id)
      );

      CREATE TABLE IF NOT EXISTS solodit_references (
        finding_id INTEGER,
        solodit_id TEXT,
        similarity REAL,
        PRIMARY KEY (finding_id, solodit_id),
        FOREIGN KEY (finding_id) REFERENCES findings(id)
      );

      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
      CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
      CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
    `);
  }

  /**
   * Initialize JSON-based storage fallback
   * @private
   */
  _initJson() {
    if (fs.existsSync(this.jsonPath)) {
      this.data = JSON.parse(fs.readFileSync(this.jsonPath, 'utf-8'));
    } else {
      this.data = {
        projects: [],
        audits: [],
        findings: [],
        tags: [],
        soloditRefs: [],
        _autoIncrement: { projects: 1, audits: 1, findings: 1 }
      };
      this._saveJson();
    }
  }

  /**
   * Save JSON data to file
   * @private
   */
  _saveJson() {
    fs.writeFileSync(this.jsonPath, JSON.stringify(this.data, null, 2));
  }

  // ==================== Project Operations ====================

  /**
   * Create or get a project
   * 
   * @param {Object} project - Project data
   * @returns {number} Project ID
   */
  createProject(project) {
    if (this.useJson) {
      const existing = this.data.projects.find(p => p.path === project.path);
      if (existing) return existing.id;
      
      const id = this.data._autoIncrement.projects++;
      this.data.projects.push({
        id,
        ...project,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      this._saveJson();
      return id;
    }

    const existing = this.db.prepare('SELECT id FROM projects WHERE path = ?').get(project.path);
    if (existing) return existing.id;

    const result = this.db.prepare(`
      INSERT INTO projects (name, path, type) VALUES (?, ?, ?)
    `).run(project.name, project.path, project.type || 'unknown');

    return result.lastInsertRowid;
  }

  /**
   * Get project by ID or path
   * 
   * @param {number|string} idOrPath - Project ID or path
   * @returns {Object|null} Project data
   */
  getProject(idOrPath) {
    if (this.useJson) {
      if (typeof idOrPath === 'number') {
        return this.data.projects.find(p => p.id === idOrPath);
      }
      return this.data.projects.find(p => p.path === idOrPath);
    }

    if (typeof idOrPath === 'number') {
      return this.db.prepare('SELECT * FROM projects WHERE id = ?').get(idOrPath);
    }
    return this.db.prepare('SELECT * FROM projects WHERE path = ?').get(idOrPath);
  }

  /**
   * List all projects
   * 
   * @returns {Array} All projects
   */
  listProjects() {
    if (this.useJson) {
      return this.data.projects;
    }
    return this.db.prepare('SELECT * FROM projects ORDER BY updated_at DESC').all();
  }

  // ==================== Audit Operations ====================

  /**
   * Start a new audit
   * 
   * @param {number} projectId - Project ID
   * @param {string} name - Audit name
   * @returns {number} Audit ID
   */
  startAudit(projectId, name = null) {
    if (this.useJson) {
      const id = this.data._autoIncrement.audits++;
      this.data.audits.push({
        id,
        project_id: projectId,
        name: name || `Audit ${id}`,
        started_at: new Date().toISOString(),
        status: 'in_progress'
      });
      this._saveJson();
      return id;
    }

    const result = this.db.prepare(`
      INSERT INTO audits (project_id, name) VALUES (?, ?)
    `).run(projectId, name || `Audit ${Date.now()}`);

    return result.lastInsertRowid;
  }

  /**
   * Complete an audit
   * 
   * @param {number} auditId - Audit ID
   * @param {string} notes - Completion notes
   */
  completeAudit(auditId, notes = null) {
    if (this.useJson) {
      const audit = this.data.audits.find(a => a.id === auditId);
      if (audit) {
        audit.completed_at = new Date().toISOString();
        audit.status = 'completed';
        audit.notes = notes;
        this._saveJson();
      }
      return;
    }

    this.db.prepare(`
      UPDATE audits SET completed_at = CURRENT_TIMESTAMP, status = 'completed', notes = ?
      WHERE id = ?
    `).run(notes, auditId);
  }

  /**
   * Get audit with summary
   * 
   * @param {number} auditId - Audit ID
   * @returns {Object} Audit data with finding counts
   */
  getAudit(auditId) {
    if (this.useJson) {
      const audit = this.data.audits.find(a => a.id === auditId);
      if (!audit) return null;
      
      const findings = this.data.findings.filter(f => f.audit_id === auditId);
      return {
        ...audit,
        finding_count: findings.length,
        open_count: findings.filter(f => f.status === 'open').length
      };
    }

    const audit = this.db.prepare('SELECT * FROM audits WHERE id = ?').get(auditId);
    if (!audit) return null;

    const counts = this.db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count
      FROM findings WHERE audit_id = ?
    `).get(auditId);

    return { ...audit, ...counts };
  }

  // ==================== Finding Operations ====================

  /**
   * Add a finding
   * 
   * @param {Object} finding - Finding data
   * @returns {number} Finding ID
   */
  addFinding(finding) {
    if (this.useJson) {
      const id = this.data._autoIncrement.findings++;
      this.data.findings.push({
        id,
        ...finding,
        status: finding.status || 'open',
        false_positive: finding.false_positive || 0,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      this._saveJson();
      return id;
    }

    const result = this.db.prepare(`
      INSERT INTO findings (
        audit_id, project_id, external_id, title, severity, category,
        description, file_path, start_line, end_line, code_snippet,
        source, status, notes, recommendation
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      finding.audit_id,
      finding.project_id,
      finding.external_id,
      finding.title,
      finding.severity,
      finding.category,
      finding.description,
      finding.file_path,
      finding.start_line,
      finding.end_line,
      finding.code_snippet,
      finding.source,
      finding.status || 'open',
      finding.notes,
      finding.recommendation
    );

    return result.lastInsertRowid;
  }

  /**
   * Add multiple findings at once
   * 
   * @param {Array} findings - Array of findings
   * @returns {Array} Array of finding IDs
   */
  addFindings(findings) {
    return findings.map(f => this.addFinding(f));
  }

  /**
   * Get finding by ID
   * 
   * @param {number} findingId - Finding ID
   * @returns {Object} Finding data
   */
  getFinding(findingId) {
    if (this.useJson) {
      const finding = this.data.findings.find(f => f.id === findingId);
      if (!finding) return null;
      
      finding.tags = this.data.tags
        .filter(t => t.finding_id === findingId)
        .map(t => t.tag);
      
      finding.solodit_refs = this.data.soloditRefs
        .filter(r => r.finding_id === findingId);
      
      return finding;
    }

    const finding = this.db.prepare('SELECT * FROM findings WHERE id = ?').get(findingId);
    if (!finding) return null;

    finding.tags = this.db.prepare(
      'SELECT tag FROM finding_tags WHERE finding_id = ?'
    ).all(findingId).map(r => r.tag);

    finding.solodit_refs = this.db.prepare(
      'SELECT solodit_id, similarity FROM solodit_references WHERE finding_id = ?'
    ).all(findingId);

    return finding;
  }

  /**
   * Update finding
   * 
   * @param {number} findingId - Finding ID
   * @param {Object} updates - Fields to update
   */
  updateFinding(findingId, updates) {
    if (this.useJson) {
      const finding = this.data.findings.find(f => f.id === findingId);
      if (finding) {
        Object.assign(finding, updates, { updated_at: new Date().toISOString() });
        this._saveJson();
      }
      return;
    }

    const fields = Object.keys(updates)
      .filter(k => k !== 'id')
      .map(k => `${k} = ?`);
    
    if (fields.length === 0) return;

    fields.push('updated_at = CURRENT_TIMESTAMP');
    
    const values = Object.keys(updates)
      .filter(k => k !== 'id')
      .map(k => updates[k]);
    
    values.push(findingId);

    this.db.prepare(`
      UPDATE findings SET ${fields.join(', ')} WHERE id = ?
    `).run(...values);
  }

  /**
   * Mark finding as false positive
   * 
   * @param {number} findingId - Finding ID
   * @param {string} reason - Reason for marking as false positive
   */
  markFalsePositive(findingId, reason = null) {
    this.updateFinding(findingId, {
      false_positive: 1,
      status: 'closed',
      notes: reason
    });
  }

  /**
   * Mark finding as fixed
   * 
   * @param {number} findingId - Finding ID
   * @param {string} notes - Fix notes
   */
  markFixed(findingId, notes = null) {
    this.updateFinding(findingId, {
      status: 'fixed',
      notes
    });
  }

  /**
   * Query findings with filters
   * 
   * @param {Object} filters - Query filters
   * @returns {Array} Matching findings
   */
  queryFindings(filters = {}) {
    if (this.useJson) {
      let results = [...this.data.findings];
      
      if (filters.project_id) {
        results = results.filter(f => f.project_id === filters.project_id);
      }
      if (filters.audit_id) {
        results = results.filter(f => f.audit_id === filters.audit_id);
      }
      if (filters.severity) {
        const severities = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
        results = results.filter(f => severities.includes(f.severity));
      }
      if (filters.status) {
        results = results.filter(f => f.status === filters.status);
      }
      if (filters.source) {
        results = results.filter(f => f.source === filters.source);
      }
      if (filters.file_path) {
        results = results.filter(f => f.file_path?.includes(filters.file_path));
      }
      if (filters.excludeFalsePositives) {
        results = results.filter(f => !f.false_positive);
      }
      
      // Sort
      const sortField = filters.sortBy || 'created_at';
      const sortOrder = filters.sortOrder || 'desc';
      results.sort((a, b) => {
        const aVal = a[sortField];
        const bVal = b[sortField];
        return sortOrder === 'asc' ? 
          (aVal > bVal ? 1 : -1) : 
          (aVal < bVal ? 1 : -1);
      });
      
      // Pagination
      if (filters.limit) {
        const offset = filters.offset || 0;
        results = results.slice(offset, offset + filters.limit);
      }
      
      return results;
    }

    let sql = 'SELECT * FROM findings WHERE 1=1';
    const params = [];

    if (filters.project_id) {
      sql += ' AND project_id = ?';
      params.push(filters.project_id);
    }
    if (filters.audit_id) {
      sql += ' AND audit_id = ?';
      params.push(filters.audit_id);
    }
    if (filters.severity) {
      const severities = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
      sql += ` AND severity IN (${severities.map(() => '?').join(',')})`;
      params.push(...severities);
    }
    if (filters.status) {
      sql += ' AND status = ?';
      params.push(filters.status);
    }
    if (filters.source) {
      sql += ' AND source = ?';
      params.push(filters.source);
    }
    if (filters.file_path) {
      sql += ' AND file_path LIKE ?';
      params.push(`%${filters.file_path}%`);
    }
    if (filters.excludeFalsePositives) {
      sql += ' AND false_positive = 0';
    }

    sql += ` ORDER BY ${filters.sortBy || 'created_at'} ${filters.sortOrder || 'DESC'}`;

    if (filters.limit) {
      sql += ' LIMIT ?';
      params.push(filters.limit);
      if (filters.offset) {
        sql += ' OFFSET ?';
        params.push(filters.offset);
      }
    }

    return this.db.prepare(sql).all(...params);
  }

  /**
   * Get findings grouped by severity
   * 
   * @param {Object} filters - Optional filters
   * @returns {Object} Findings grouped by severity
   */
  getGroupedBySeverity(filters = {}) {
    const findings = this.queryFindings(filters);
    return {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: findings.filter(f => f.severity === 'INFO'),
      GAS: findings.filter(f => f.severity === 'GAS')
    };
  }

  /**
   * Get statistics for a project or audit
   * 
   * @param {Object} filters - Filters (project_id or audit_id)
   * @returns {Object} Statistics
   */
  getStats(filters = {}) {
    const findings = this.queryFindings({ ...filters, excludeFalsePositives: true });
    
    const stats = {
      total: findings.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        gas: 0
      },
      byStatus: {
        open: 0,
        fixed: 0,
        acknowledged: 0,
        closed: 0
      },
      bySource: {},
      byFile: {}
    };

    for (const finding of findings) {
      // By severity
      const sev = finding.severity?.toLowerCase();
      if (stats.bySeverity[sev] !== undefined) {
        stats.bySeverity[sev]++;
      }

      // By status
      const status = finding.status?.toLowerCase();
      if (stats.byStatus[status] !== undefined) {
        stats.byStatus[status]++;
      }

      // By source
      if (finding.source) {
        stats.bySource[finding.source] = (stats.bySource[finding.source] || 0) + 1;
      }

      // By file
      if (finding.file_path) {
        stats.byFile[finding.file_path] = (stats.byFile[finding.file_path] || 0) + 1;
      }
    }

    return stats;
  }

  // ==================== Tags ====================

  /**
   * Add tags to a finding
   * 
   * @param {number} findingId - Finding ID
   * @param {Array} tags - Tags to add
   */
  addTags(findingId, tags) {
    for (const tag of tags) {
      if (this.useJson) {
        if (!this.data.tags.find(t => t.finding_id === findingId && t.tag === tag)) {
          this.data.tags.push({ finding_id: findingId, tag });
        }
      } else {
        try {
          this.db.prepare(
            'INSERT OR IGNORE INTO finding_tags (finding_id, tag) VALUES (?, ?)'
          ).run(findingId, tag);
        } catch (e) {
          // Ignore duplicate errors
        }
      }
    }
    
    if (this.useJson) {
      this._saveJson();
    }
  }

  /**
   * Find findings by tag
   * 
   * @param {string} tag - Tag to search
   * @returns {Array} Findings with the tag
   */
  findByTag(tag) {
    if (this.useJson) {
      const findingIds = this.data.tags
        .filter(t => t.tag === tag)
        .map(t => t.finding_id);
      return this.data.findings.filter(f => findingIds.includes(f.id));
    }

    return this.db.prepare(`
      SELECT f.* FROM findings f
      JOIN finding_tags t ON f.id = t.finding_id
      WHERE t.tag = ?
    `).all(tag);
  }

  // ==================== Solodit References ====================

  /**
   * Link a finding to Solodit reference
   * 
   * @param {number} findingId - Finding ID
   * @param {string} soloditId - Solodit finding ID
   * @param {number} similarity - Similarity score (0-1)
   */
  addSoloditRef(findingId, soloditId, similarity = 1.0) {
    if (this.useJson) {
      if (!this.data.soloditRefs.find(r => 
        r.finding_id === findingId && r.solodit_id === soloditId
      )) {
        this.data.soloditRefs.push({ finding_id: findingId, solodit_id: soloditId, similarity });
        this._saveJson();
      }
      return;
    }

    try {
      this.db.prepare(`
        INSERT OR REPLACE INTO solodit_references (finding_id, solodit_id, similarity)
        VALUES (?, ?, ?)
      `).run(findingId, soloditId, similarity);
    } catch (e) {
      // Ignore errors
    }
  }

  /**
   * Get Solodit references for a finding
   * 
   * @param {number} findingId - Finding ID
   * @returns {Array} Solodit references
   */
  getSoloditRefs(findingId) {
    if (this.useJson) {
      return this.data.soloditRefs.filter(r => r.finding_id === findingId);
    }

    return this.db.prepare(
      'SELECT solodit_id, similarity FROM solodit_references WHERE finding_id = ?'
    ).all(findingId);
  }

  // ==================== Cleanup ====================

  /**
   * Close the database connection
   */
  close() {
    if (this.db) {
      this.db.close();
    }
  }

  /**
   * Delete all data (for testing)
   */
  reset() {
    if (this.useJson) {
      this.data = {
        projects: [],
        audits: [],
        findings: [],
        tags: [],
        soloditRefs: [],
        _autoIncrement: { projects: 1, audits: 1, findings: 1 }
      };
      this._saveJson();
      return;
    }

    this.db.exec(`
      DELETE FROM solodit_references;
      DELETE FROM finding_tags;
      DELETE FROM findings;
      DELETE FROM audits;
      DELETE FROM projects;
    `);
  }
}

module.exports = FindingDatabase;
