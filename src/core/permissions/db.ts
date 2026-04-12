import { Permission, PermissionRequest, PermissionType } from './types';
import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 10; // ~100ms on modern hardware — slow enough to resist brute force

/**
 * PermissionDB — Persistent database layer for the SecureAI platform.
 * Supports both real SQLite (via better-sqlite3) and an in-memory mock fallback.
 * API keys are stored as SHA-256 hashes for security.
 */
export class PermissionDB {
  private db: any;
  private isMock: boolean = false;
  private mockStore: any = {
    permissions: new Map(),
    approval_requests: new Map(),
    users: new Map(),
    api_keys: new Map(),
    user_policies: new Map()
  };

  constructor(dbPath: string = 'secureai.db') {
    try {
      const Database = require('better-sqlite3');
      this.db = new Database(dbPath);
      this.db.pragma('journal_mode = WAL'); // Better concurrent access
      this.initializeDatabase();
      console.log(`[Database] ✅ Using persistent SQLite at ${dbPath}`);
    } catch (err) {
      console.warn(`[Database] ⚠ Failed to load better-sqlite3. Falling back to IN-MEMORY MOCK MODE.`);
      console.warn(`[Database] Note: Data will NOT persist after server restart.`);
      this.isMock = true;
    }
  }

  private initializeDatabase() {
    if (this.isMock) return;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS permissions (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        resource TEXT NOT NULL,
        action TEXT NOT NULL,
        requiresApproval INTEGER DEFAULT 1,
        maxDataSize INTEGER,
        maxExecutionTime INTEGER,
        expiresAt TEXT,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        createdBy TEXT,
        organizationId TEXT
      );

      CREATE TABLE IF NOT EXISTS approval_requests (
        id TEXT PRIMARY KEY,
        executionId TEXT NOT NULL,
        permissions TEXT NOT NULL, -- JSON array
        status TEXT DEFAULT 'pending', -- pending, approved, rejected, expired
        requestedBy TEXT NOT NULL,
        approvedBy TEXT,
        reason TEXT,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        expiresAt TEXT,
        approvalTime TEXT,
        code TEXT,
        language TEXT,
        riskScore INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS user_policies (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        permissionId TEXT NOT NULL,
        organizationId TEXT,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(permissionId) REFERENCES permissions(id),
        UNIQUE(userId, permissionId)
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        organizationId TEXT,
        role TEXT DEFAULT 'executor', -- admin, executor, approver
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        keyHash TEXT NOT NULL,        -- SHA-256 of raw key (fast index lookup)
        keySecret TEXT,               -- bcrypt hash of raw key (brute-force resistant verification)
        keyPrefix TEXT NOT NULL,      -- first 12 chars shown in UI
        name TEXT,                    -- human-readable label
        userId TEXT NOT NULL,
        organizationId TEXT,
        status TEXT DEFAULT 'active', -- active, revoked, expired
        expiresAt TEXT,               -- ISO timestamp, NULL = never expires
        lastUsedAt TEXT,              -- updated on every successful auth
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(userId) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_perm_resource ON permissions(resource);
      CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
      CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(keyHash);
    `);

    // Migration: add new columns if they don't exist (non-destructive ALTER TABLE)
    try {
      const columns = this.db.pragma('table_info(api_keys)') as any[];
      const colNames = columns.map((c: any) => c.name);

      // Old plaintext 'key' column → migrate to hashed storage
      if (colNames.includes('key') && !colNames.includes('keyHash')) {
        console.log('[Database] 🔄 Migrating api_keys: plaintext → SHA-256 hash...');
        const rows = this.db.prepare('SELECT id, key, userId, organizationId, status FROM api_keys').all() as any[];
        this.db.exec('DROP TABLE IF EXISTS api_keys');
        this.db.exec(`
          CREATE TABLE api_keys (
            id TEXT PRIMARY KEY,
            keyHash TEXT NOT NULL,
            keySecret TEXT,
            keyPrefix TEXT NOT NULL,
            name TEXT,
            userId TEXT NOT NULL,
            organizationId TEXT,
            status TEXT DEFAULT 'active',
            expiresAt TEXT,
            lastUsedAt TEXT,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(userId) REFERENCES users(id)
          );
          CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(keyHash);
        `);
        const insertStmt = this.db.prepare(
          'INSERT INTO api_keys (id, keyHash, keyPrefix, userId, organizationId, status) VALUES (?, ?, ?, ?, ?, ?)'
        );
        for (const row of rows) {
          insertStmt.run(row.id, PermissionDB.hashApiKey(row.key), row.key.substring(0, 12), row.userId, row.organizationId, row.status);
        }
        console.log(`[Database] ✅ Migrated ${rows.length} API key(s) to hashed storage.`);
      }

      // Add new columns to existing hashed-key tables (safe to run repeatedly)
      const addColIfMissing = (col: string, def: string) => {
        if (!colNames.includes(col)) {
          this.db.exec(`ALTER TABLE api_keys ADD COLUMN ${col} ${def}`);
          console.log(`[Database] 🔄 Added column api_keys.${col}`);
        }
      };
      addColIfMissing('keySecret',  'TEXT');
      addColIfMissing('name',       'TEXT');
      addColIfMissing('expiresAt',  'TEXT');
      addColIfMissing('lastUsedAt', 'TEXT');

      // Migrate approval_requests to add riskScore if missing
      try {
        const approvalCols = this.db.pragma('table_info(approval_requests)') as any[];
        const approvalColNames = approvalCols.map((c: any) => c.name);
        if (!approvalColNames.includes('riskScore')) {
          this.db.exec('ALTER TABLE approval_requests ADD COLUMN riskScore INTEGER DEFAULT 0');
          console.log('[Database] 🔄 Added column approval_requests.riskScore');
        }
      } catch (_) { /* table may not exist yet */ }
    } catch (_) {
      // Table might not exist yet — that's fine, schema was just created
    }
  }

  // --- Static Helpers ---

  /** SHA-256 hash used as the DB index (fast equality lookup) */
  static hashApiKey(rawKey: string): string {
    return crypto.createHash('sha256').update(rawKey).digest('hex');
  }

  /** bcrypt hash used for slow, brute-force-resistant verification */
  static async bcryptApiKey(rawKey: string): Promise<string> {
    return bcrypt.hash(rawKey, BCRYPT_ROUNDS);
  }

  static async verifyApiKey(rawKey: string, bcryptHash: string): Promise<boolean> {
    return bcrypt.compare(rawKey, bcryptHash);
  }

  // --- Permission Methods ---

  addPermission(permission: any) {
    if (this.isMock) {
      this.mockStore.permissions.set(permission.id, { ...permission });
      return;
    }
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO permissions (
        id, type, resource, action, requiresApproval, 
        maxDataSize, maxExecutionTime, expiresAt, createdBy, organizationId
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      permission.id,
      permission.type,
      permission.resource,
      permission.action,
      permission.requiresApproval ? 1 : 0,
      permission.conditions?.maxDataSize || null,
      permission.conditions?.maxExecutionTime || null,
      permission.conditions?.expiresAt || null,
      permission.createdBy,
      permission.organizationId || null
    );
  }

  getPermission(id: string): Permission | null {
    if (this.isMock) {
      const p = this.mockStore.permissions.get(id);
      return p ? this.mapPermissionRow(p) : null;
    }
    const row = this.db.prepare('SELECT * FROM permissions WHERE id = ?').get(id) as any;
    return row ? this.mapPermissionRow(row) : null;
  }

  getAllPermissions(): Permission[] {
    if (this.isMock) {
      return Array.from(this.mockStore.permissions.values()).map((r: any) => this.mapPermissionRow(r));
    }
    const rows = this.db.prepare('SELECT * FROM permissions ORDER BY createdAt DESC').all() as any[];
    return rows.map(this.mapPermissionRow);
  }

  queryPermissions(filters: { type?: string; resource?: string; action?: string }): Permission[] {
    if (this.isMock) {
      let results = Array.from(this.mockStore.permissions.values());
      if (filters.type) results = results.filter((p: any) => p.type === filters.type);
      if (filters.resource) results = results.filter((p: any) => p.resource.includes(filters.resource));
      return results.map((r: any) => this.mapPermissionRow(r));
    }
    let sql = 'SELECT * FROM permissions WHERE 1=1';
    const params: any[] = [];
    if (filters.type) { sql += ' AND type = ?'; params.push(filters.type); }
    if (filters.resource) { sql += ' AND resource LIKE ?'; params.push(`%${filters.resource}%`); }
    const rows = this.db.prepare(sql).all(...params) as any[];
    return rows.map(this.mapPermissionRow);
  }

  // --- Approval Request Methods ---

  createApprovalRequest(req: PermissionRequest) {
    if (this.isMock) {
      this.mockStore.approval_requests.set(req.id, {
        ...req,
        permissions: JSON.stringify(req.requestedPermissions),
        createdAt: req.createdAt.toISOString(),
        expiresAt: req.expiresAt.toISOString()
      });
      return req.id;
    }
    const stmt = this.db.prepare(`
      INSERT INTO approval_requests (
        id, executionId, permissions, status, requestedBy, expiresAt, createdAt, code, language, riskScore
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(req.id, req.executionId, JSON.stringify(req.requestedPermissions), req.status, req.requestedBy, req.expiresAt.toISOString(), req.createdAt.toISOString(), req.code || null, req.language || null, req.riskScore ?? 0);
    return req.id;
  }

  getApprovalRequest(id: string): PermissionRequest | null {
    if (this.isMock) {
      const row = this.mockStore.approval_requests.get(id);
      if (!row) return null;
      return {
        ...row,
        requestedPermissions: typeof row.permissions === 'string' ? JSON.parse(row.permissions) : row.requestedPermissions,
        expiresAt: new Date(row.expiresAt),
        createdAt: new Date(row.createdAt),
        approvalTime: row.approvalTime ? new Date(row.approvalTime) : undefined
      };
    }
    const row = this.db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(id) as any;
    if (!row) return null;
    return {
      ...row,
      requestedPermissions: JSON.parse(row.permissions),
      expiresAt: new Date(row.expiresAt),
      createdAt: new Date(row.createdAt),
      approvalTime: row.approvalTime ? new Date(row.approvalTime) : undefined
    };
  }

  updateApprovalStatus(id: string, status: string, approverId: string, reason?: string) {
    if (this.isMock) {
      const req = this.mockStore.approval_requests.get(id);
      if (req) { Object.assign(req, { status, approvedBy: approverId, reason, approvalTime: new Date().toISOString() }); }
      return;
    }
    const stmt = this.db.prepare(`UPDATE approval_requests SET status = ?, approvedBy = ?, reason = ?, approvalTime = ? WHERE id = ?`);
    stmt.run(status, approverId, reason || null, new Date().toISOString(), id);
  }

  /**
   * List approval requests, optionally filtered by status.
   */
  listApprovalRequests(status?: string): any[] {
    if (this.isMock) {
      let results = Array.from(this.mockStore.approval_requests.values());
      if (status) results = results.filter((r: any) => r.status === status);
      return results.map((r: any) => ({
        id: r.id,
        executionId: r.executionId,
        status: r.status,
        requestedBy: r.requestedBy || r.requestedBy,
        createdAt: r.createdAt,
        expiresAt: r.expiresAt,
        code: r.code,
        language: r.language,
      }));
    }
    let sql = 'SELECT * FROM approval_requests';
    const params: any[] = [];
    if (status) { sql += ' WHERE status = ?'; params.push(status); }
    sql += ' ORDER BY createdAt DESC LIMIT 100';
    return this.db.prepare(sql).all(...params) as any[];
  }

  /**
   * Get all API keys for a specific user or organization.
   */
  getApiKeysByUser(userId: string): any[] {
    if (this.isMock) {
      return Array.from(this.mockStore.api_keys.values())
        .filter((k: any) => k.userId === userId)
        .map((k: any) => ({
          id: k.id,
          keyPrefix: k.keyPrefix,
          name: k.name || k.id,
          status: k.status,
          organizationId: k.organizationId,
          createdAt: k.createdAt || new Date().toISOString(),
        }));
    }
    return this.db.prepare(
      'SELECT id, keyPrefix, status, organizationId, createdAt FROM api_keys WHERE userId = ? ORDER BY createdAt DESC'
    ).all(userId) as any[];
  }

  getApiKeysByOrg(organizationId: string): any[] {
    if (this.isMock) {
      return Array.from(this.mockStore.api_keys.values())
        .filter((k: any) => k.organizationId === organizationId)
        .map((k: any) => ({
          id: k.id,
          keyPrefix: k.keyPrefix,
          name: k.name || k.id,
          status: k.status,
          organizationId: k.organizationId,
          createdAt: k.createdAt || new Date().toISOString(),
        }));
    }
    return this.db.prepare(
      'SELECT id, keyPrefix, status, organizationId, createdAt FROM api_keys WHERE organizationId = ? ORDER BY createdAt DESC'
    ).all(organizationId) as any[];
  }


  // --- Auth Methods (with hashed API keys) ---

  getUserByApiKey(rawKey: string) {
    const keyHash = PermissionDB.hashApiKey(rawKey);
    const now = new Date().toISOString();

    if (this.isMock) {
      const apiKey = Array.from(this.mockStore.api_keys.values()).find(
        (k: any) => k.keyHash === keyHash && k.status === 'active'
          && (!k.expiresAt || k.expiresAt > now)
      ) as any;
      if (!apiKey) return null;
      // Update lastUsedAt in mock
      apiKey.lastUsedAt = now;
      const user = this.mockStore.users.get(apiKey.userId);
      return user ? { ...user, keyOrgId: apiKey.organizationId } : null;
    }

    // Step 1: fast SHA-256 index lookup
    const row = this.db.prepare(
      `SELECT u.*, k.organizationId as keyOrgId, k.keySecret, k.id as keyId
       FROM users u JOIN api_keys k ON u.id = k.userId
       WHERE k.keyHash = ? AND k.status = 'active'
         AND (k.expiresAt IS NULL OR k.expiresAt > ?)`
    ).get(keyHash, now) as any;

    if (!row) return null;

    // Step 2: bcrypt verification (if keySecret exists on this key)
    // Note: synchronous bcrypt compare is acceptable here — it's intentionally slow
    // and the rate limiter already caps requests per key.
    if (row.keySecret) {
      const valid = bcrypt.compareSync(rawKey, row.keySecret);
      if (!valid) return null;
    }

    // Step 3: update lastUsedAt (non-blocking, best-effort)
    try {
      this.db.prepare('UPDATE api_keys SET lastUsedAt = ? WHERE id = ?').run(now, row.keyId);
    } catch { /* ignore */ }

    return row;
  }

  createUser(user: any) {
    if (this.isMock) { this.mockStore.users.set(user.id, { ...user }); return; }
    this.db.prepare(`INSERT OR IGNORE INTO users (id, email, organizationId, role) VALUES (?, ?, ?, ?)`).run(user.id, user.email, user.organizationId, user.role);
  }

  getUserById(id: string) {
    if (this.isMock) { return this.mockStore.users.get(id) || null; }
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
  }

  async createApiKey(
    id: string,
    userId: string,
    rawKey: string,
    organizationId: string,
    options: { name?: string; expiresAt?: string } = {}
  ): Promise<void> {
    const keyHash   = PermissionDB.hashApiKey(rawKey);
    const keySecret = await PermissionDB.bcryptApiKey(rawKey); // slow hash for verification
    const keyPrefix = rawKey.substring(0, 12);
    const name      = options.name || id;
    const expiresAt = options.expiresAt || null;

    if (this.isMock) {
      this.mockStore.api_keys.set(id, { id, userId, keyHash, keySecret, keyPrefix, name, organizationId, status: 'active', expiresAt, createdAt: new Date().toISOString() });
      return;
    }
    this.db.prepare(
      `INSERT OR IGNORE INTO api_keys (id, keyHash, keySecret, keyPrefix, name, userId, organizationId, expiresAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, keyHash, keySecret, keyPrefix, name, userId, organizationId, expiresAt);
  }

  revokeApiKey(id: string) {
    if (this.isMock) {
      const key = this.mockStore.api_keys.get(id);
      if (key) key.status = 'revoked';
      return;
    }
    this.db.prepare('UPDATE api_keys SET status = ? WHERE id = ?').run('revoked', id);
  }

  // --- Database Health ---

  isHealthy(): boolean {
    if (this.isMock) return true;
    try {
      this.db.prepare('SELECT 1').get();
      return true;
    } catch {
      return false;
    }
  }

  getStats() {
    if (this.isMock) {
      return {
        users: this.mockStore.users.size,
        apiKeys: this.mockStore.api_keys.size,
        permissions: this.mockStore.permissions.size,
        approvalRequests: this.mockStore.approval_requests.size,
        mode: 'mock'
      };
    }
    return {
      users: (this.db.prepare('SELECT COUNT(*) as count FROM users').get() as any).count,
      apiKeys: (this.db.prepare('SELECT COUNT(*) as count FROM api_keys').get() as any).count,
      permissions: (this.db.prepare('SELECT COUNT(*) as count FROM permissions').get() as any).count,
      approvalRequests: (this.db.prepare('SELECT COUNT(*) as count FROM approval_requests').get() as any).count,
      mode: 'sqlite'
    };
  }

  // Proxy method so PermissionEngine can call db.prepare() directly
  prepare(sql: string) {
    if (this.isMock) {
      return { all: (...args: any[]) => [] as any[] };
    }
    return this.db.prepare(sql);
  }

  close() {
    if (!this.isMock && this.db) {
      this.db.close();
    }
  }

  private mapPermissionRow(row: any): Permission {
    return {
      id: row.id,
      type: row.type as PermissionType,
      resource: row.resource,
      action: row.action as any,
      conditions: {
        maxDataSize: row.maxDataSize,
        maxExecutionTime: row.maxExecutionTime,
        expiresAt: row.expiresAt ? new Date(row.expiresAt) : undefined,
        requiresApproval: row.requiresApproval === 1
      },
      createdAt: new Date(row.createdAt),
      createdBy: row.createdBy
    };
  }
}
