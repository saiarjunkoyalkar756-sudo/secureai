import { Permission, PermissionRequest, PermissionType } from './types';

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
      this.initializeDatabase();
      console.log(`[Database] Using persistent SQLite at ${dbPath}`);
    } catch (err) {
      console.warn(`[Database] Failed to load better-sqlite3. Falling back to IN-MEMORY MOCK MODE.`);
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
        language TEXT
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
        key TEXT UNIQUE NOT NULL,
        userId TEXT NOT NULL,
        organizationId TEXT,
        status TEXT DEFAULT 'active', -- active, revoked
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(userId) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_perm_resource ON permissions(resource);
      CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
      CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key);
    `);
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

  queryPermissions(filters: { type?: string; resource?: string; action?: string }): Permission[] {
    if (this.isMock) {
      let results = Array.from(this.mockStore.permissions.values());
      if (filters.type) results = results.filter((p: any) => p.type === filters.type);
      if (filters.resource) results = results.filter((p: any) => p.resource.includes(filters.resource));
      return results.map(r => this.mapPermissionRow(r));
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
        id, executionId, permissions, status, requestedBy, expiresAt, createdAt, code, language
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(req.id, req.executionId, JSON.stringify(req.requestedPermissions), req.status, req.requestedBy, req.expiresAt.toISOString(), req.createdAt.toISOString(), req.code || null, req.language || null);
    return req.id;
  }

  getApprovalRequest(id: string): PermissionRequest | null {
    if (this.isMock) {
      const row = this.mockStore.approval_requests.get(id);
      if (!row) return null;
      return {
        ...row,
        requestedPermissions: JSON.parse(row.permissions),
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

  // --- Auth Methods ---

  getUserByApiKey(key: string) {
    if (this.isMock) {
      const apiKey = Array.from(this.mockStore.api_keys.values()).find((k: any) => k.key === key && k.status === 'active');
      if (!apiKey) return null;
      const user = this.mockStore.users.get((apiKey as any).userId);
      return user ? { ...user, keyOrgId: (apiKey as any).organizationId } : null;
    }
    return this.db.prepare(`SELECT u.*, k.organizationId as keyOrgId FROM users u JOIN api_keys k ON u.id = k.userId WHERE k.key = ? AND k.status = 'active'`).get(key) as any;
  }

  createUser(user: any) {
    if (this.isMock) { this.mockStore.users.set(user.id, { ...user }); return; }
    this.db.prepare(`INSERT INTO users (id, email, organizationId, role) VALUES (?, ?, ?, ?)`).run(user.id, user.email, user.organizationId, user.role);
  }

  createApiKey(id: string, userId: string, key: string, organizationId: string) {
    if (this.isMock) { this.mockStore.api_keys.set(id, { id, userId, key, organizationId, status: 'active' }); return; }
    this.db.prepare(`INSERT INTO api_keys (id, userId, key, organizationId) VALUES (?, ?, ?, ?)`).run(id, userId, key, organizationId);
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
