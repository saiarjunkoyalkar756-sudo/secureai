import Database from 'better-sqlite3';
import { Permission, PermissionRequest, PermissionType } from './types';

export class PermissionDB {
  private db: Database.Database;

  constructor(dbPath: string = 'secureai.db') {
    this.db = new Database(dbPath);
    this.initializeDatabase();
  }

  /**
   * Create tables and indexes if they don't exist
   */
  private initializeDatabase() {
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

      CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);
  }

  // --- Auth Methods ---

  getUserByApiKey(key: string) {
    return this.db.prepare(`
      SELECT u.*, k.organizationId as keyOrgId FROM users u
      JOIN api_keys k ON u.id = k.userId
      WHERE k.key = ? AND k.status = 'active'
    `).get(key) as any;
  }

  createUser(user: { id: string; email: string; organizationId: string; role: string }) {
    const stmt = this.db.prepare(`
      INSERT INTO users (id, email, organizationId, role)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(user.id, user.email, user.organizationId, user.role);
  }

  createApiKey(id: string, userId: string, key: string, organizationId: string) {
    const stmt = this.db.prepare(`
      INSERT INTO api_keys (id, userId, key, organizationId)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(id, userId, key, organizationId);
  }


  // --- Permission Methods ---

  addPermission(permission: any) {
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
    const row = this.db.prepare('SELECT * FROM permissions WHERE id = ?').get(id) as any;
    return row ? this.mapPermissionRow(row) : null;
  }

  queryPermissions(filters: { type?: string; resource?: string; action?: string }): Permission[] {
    let sql = 'SELECT * FROM permissions WHERE 1=1';
    const params: any[] = [];

    if (filters.type) {
      sql += ' AND type = ?';
      params.push(filters.type);
    }
    if (filters.resource) {
      sql += ' AND resource LIKE ?';
      params.push(`%${filters.resource}%`);
    }
    if (filters.action) {
      sql += ' AND action = ?';
      params.push(filters.action);
    }

    const rows = this.db.prepare(sql).all(...params) as any[];
    return rows.map(this.mapPermissionRow);
  }

  // --- Approval Request Methods ---

  createApprovalRequest(req: PermissionRequest) {
    const stmt = this.db.prepare(`
      INSERT INTO approval_requests (
        id, executionId, permissions, status, requestedBy, expiresAt, createdAt, code, language
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      req.id,
      req.executionId,
      JSON.stringify(req.requestedPermissions),
      req.status,
      req.requestedBy,
      req.expiresAt.toISOString(),
      req.createdAt.toISOString(),
      req.code || null,
      req.language || null
    );
    return req.id;
  }

  getApprovalRequest(id: string): PermissionRequest | null {
    const row = this.db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(id) as any;
    if (!row) return null;

    return {
      id: row.id,
      executionId: row.executionId,
      requestedPermissions: JSON.parse(row.permissions),
      status: row.status,
      requestedBy: row.requestedBy,
      approvedBy: row.approvedBy,
      approvalTime: row.approvalTime ? new Date(row.approvalTime) : undefined,
      expiresAt: new Date(row.expiresAt),
      createdAt: new Date(row.createdAt),
      reason: row.reason,
      code: row.code,
      language: row.language
    };
  }


  updateApprovalStatus(id: string, status: string, approverId: string, reason?: string) {
    const stmt = this.db.prepare(`
      UPDATE approval_requests 
      SET status = ?, approvedBy = ?, reason = ?, approvalTime = ?
      WHERE id = ?
    `);
    stmt.run(status, approverId, reason || null, new Date().toISOString(), id);
  }

  getPendingApprovals(userId?: string): PermissionRequest[] {
    let sql = 'SELECT * FROM approval_requests WHERE status = "pending"';
    const params: any[] = [];

    if (userId) {
      sql += ' AND requestedBy = ?';
      params.push(userId);
    }

    const rows = this.db.prepare(sql).all(...params) as any[];
    return rows.map(row => ({
      ...row,
      requestedPermissions: JSON.parse(row.permissions),
      expiresAt: new Date(row.expiresAt),
      createdAt: new Date(row.createdAt),
      approvalTime: row.approvalTime ? new Date(row.approvalTime) : undefined
    })) as any;
  }

  // --- User Policy Methods ---

  setUserPolicy(userId: string, permissionId: string, organizationId?: string) {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO user_policies (id, userId, permissionId, organizationId)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(`${userId}_${permissionId}`, userId, permissionId, organizationId || null);
  }

  getUserPolicies(userId: string): Permission[] {
    const rows = this.db.prepare(`
      SELECT p.* FROM permissions p
      JOIN user_policies up ON p.id = up.permissionId
      WHERE up.userId = ?
    `).all(userId) as any[];
    return rows.map(this.mapPermissionRow);
  }

  // --- Helpers ---

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
