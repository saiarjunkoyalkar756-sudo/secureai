import { Permission, PermissionRequest, PermissionType } from './types';
import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';
import { Pool } from 'pg';

const BCRYPT_ROUNDS = 10;

export class PermissionDB {
  private pool: Pool | null = null;
  private isMock: boolean = false;
  private mockStore: any = {
    permissions: new Map(),
    approval_requests: new Map(),
    users: new Map(),
    api_keys: new Map(),
    user_policies: new Map()
  };

  constructor(postgresUrl?: string) {
    if (postgresUrl) {
      try {
        this.pool = new Pool({
          connectionString: postgresUrl,
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
        });
        console.log(`[Database] ✅ Using persistent Postgres database`);
        this.initializeDatabase();
      } catch (err) {
        console.warn(`[Database] ⚠ Failed to connect to Postgres. Falling back to IN-MEMORY MOCK MODE.`);
        this.isMock = true;
        this.initMockStore();
      }
    } else {
      console.warn(`[Database] ⚠ No POSTGRES_URL provided. Falling back to IN-MEMORY MOCK MODE.`);
      this.isMock = true;
      this.initMockStore();
    }
  }

  private initMockStore() {
    const adminId = 'user_admin_static';
    const orgId = 'org_5977a082-1e0';
    const keyId = 'key_static_01';
    const keyPrefix = 'sk_live_3569';
    const keyHash = '8b843e028e54d214292a197f1d436ff1e84a341977e9d9c0f26fa950a864e947';
    const keySecret = '$2b$10$RjzXmUCkpmmq94D.nhlBM.YPzWWLRSdOUOhtv1r4RD2C9wAFggJgq';

    this.mockStore.users.set(adminId, {
      id: adminId, email: 'admin@secureai.io', organizationId: orgId, role: 'admin'
    });
    this.mockStore.api_keys.set(keyId, {
      id: keyId, keyHash, keySecret, keyPrefix, name: 'Vercel Permanent Admin Key',
      userId: adminId, organizationId: orgId, status: 'active'
    });
    console.log('[Database] ✅ Auto-seeded In-Memory Mock Admin API Key');
  }

  private async initializeDatabase() {
    if (this.isMock || !this.pool) return;
    try {
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS permissions (
          id TEXT PRIMARY KEY,
          type TEXT NOT NULL,
          resource TEXT NOT NULL,
          action TEXT NOT NULL,
          requiresApproval INTEGER DEFAULT 1,
          maxDataSize INTEGER,
          maxExecutionTime INTEGER,
          expiresAt TEXT,
          createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          createdBy TEXT,
          organizationId TEXT
        );

        CREATE TABLE IF NOT EXISTS approval_requests (
          id TEXT PRIMARY KEY,
          executionId TEXT NOT NULL,
          permissions TEXT NOT NULL,
          status TEXT DEFAULT 'pending',
          requestedBy TEXT NOT NULL,
          approvedBy TEXT,
          reason TEXT,
          createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
          createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(permissionId) REFERENCES permissions(id),
          UNIQUE(userId, permissionId)
        );

        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          organizationId TEXT,
          role TEXT DEFAULT 'executor',
          createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS api_keys (
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
          createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(userId) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_perm_resource ON permissions(resource);
        CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(keyHash);
      `);

      // Auto-seed for stateless environments
      const { rows } = await this.pool.query('SELECT COUNT(*) as count FROM api_keys');
      if (parseInt(rows[0].count) === 0) {
        console.log('[Database] ⚠️ Empty database detected. Auto-seeding static Admin...');
        const adminId = 'user_admin_static';
        const orgId = 'org_5977a082-1e0';
        const keyId = 'key_static_01';
        const keyPrefix = 'sk_live_3569';
        const keyHash = '8b843e028e54d214292a197f1d436ff1e84a341977e9d9c0f26fa950a864e947';
        const keySecret = '$2b$10$RjzXmUCkpmmq94D.nhlBM.YPzWWLRSdOUOhtv1r4RD2C9wAFggJgq';
        
        await this.pool.query(`
          INSERT INTO users (id, email, organizationId, role) 
          VALUES ($1, $2, $3, $4) 
          ON CONFLICT (id) DO NOTHING
        `, [adminId, 'admin@secureai.io', orgId, 'admin']);

        await this.pool.query(`
          INSERT INTO api_keys (id, keyHash, keySecret, keyPrefix, name, userId, organizationId) 
          VALUES ($1, $2, $3, $4, $5, $6, $7) 
          ON CONFLICT (id) DO NOTHING
        `, [keyId, keyHash, keySecret, keyPrefix, 'Permanent Admin Key', adminId, orgId]);
        
        console.log('[Database] ✅ Auto-seeded Admin API Key');
      }
    } catch (err) {
      console.error('[Database] Failed to initialize DB schema:', err);
    }
  }

  static hashApiKey(rawKey: string): string {
    return crypto.createHash('sha256').update(rawKey).digest('hex');
  }

  static async bcryptApiKey(rawKey: string): Promise<string> {
    return bcrypt.hash(rawKey, BCRYPT_ROUNDS);
  }

  static async verifyApiKey(rawKey: string, bcryptHash: string): Promise<boolean> {
    return bcrypt.compare(rawKey, bcryptHash);
  }

  async addPermission(permission: any): Promise<void> {
    if (this.isMock) {
      this.mockStore.permissions.set(permission.id, { ...permission });
      return;
    }
    await this.pool!.query(`
      INSERT INTO permissions (
        id, type, resource, action, requiresApproval, 
        maxDataSize, maxExecutionTime, expiresAt, createdBy, organizationId
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (id) DO UPDATE SET
        type = EXCLUDED.type, resource = EXCLUDED.resource, action = EXCLUDED.action,
        requiresApproval = EXCLUDED.requiresApproval, maxDataSize = EXCLUDED.maxDataSize,
        maxExecutionTime = EXCLUDED.maxExecutionTime, expiresAt = EXCLUDED.expiresAt
    `, [
      permission.id, permission.type, permission.resource, permission.action,
      permission.requiresApproval ? 1 : 0, permission.conditions?.maxDataSize || null,
      permission.conditions?.maxExecutionTime || null, permission.conditions?.expiresAt || null,
      permission.createdBy, permission.organizationId || null
    ]);
  }

  async getPermission(id: string): Promise<Permission | null> {
    if (this.isMock) {
      const p = this.mockStore.permissions.get(id);
      return p ? this.mapPermissionRow(p) : null;
    }
    const { rows } = await this.pool!.query('SELECT * FROM permissions WHERE id = $1', [id]);
    return Math.max(0, rows.length) ? this.mapPermissionRow(rows[0]) : null;
  }

  async getAllPermissions(): Promise<Permission[]> {
    if (this.isMock) {
      return Array.from(this.mockStore.permissions.values()).map((r: any) => this.mapPermissionRow(r));
    }
    const { rows } = await this.pool!.query('SELECT * FROM permissions ORDER BY createdAt DESC');
    return rows.map(r => this.mapPermissionRow(r));
  }

  async queryPermissions(filters: { type?: string; resource?: string; action?: string }): Promise<Permission[]> {
    if (this.isMock) {
      let results = Array.from(this.mockStore.permissions.values());
      if (filters.type) results = results.filter((p: any) => p.type === filters.type);
      if (filters.resource) results = results.filter((p: any) => p.resource.includes(filters.resource));
      return results.map((r: any) => this.mapPermissionRow(r));
    }
    
    let sql = 'SELECT * FROM permissions WHERE 1=1';
    const params: any[] = [];
    if (filters.type) { params.push(filters.type); sql += ` AND type = $${params.length}`; }
    if (filters.resource) { params.push(`%${filters.resource}%`); sql += ` AND resource LIKE $${params.length}`; }
    
    const { rows } = await this.pool!.query(sql, params);
    return rows.map(r => this.mapPermissionRow(r));
  }

  async createApprovalRequest(req: PermissionRequest): Promise<string> {
    if (this.isMock) {
      this.mockStore.approval_requests.set(req.id, {
        ...req,
        permissions: JSON.stringify(req.requestedPermissions),
        createdAt: req.createdAt.toISOString(),
        expiresAt: req.expiresAt.toISOString()
      });
      return req.id;
    }
    await this.pool!.query(`
      INSERT INTO approval_requests (
        id, executionId, permissions, status, requestedBy, expiresAt, createdAt, code, language, riskScore
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
      req.id, req.executionId, JSON.stringify(req.requestedPermissions), req.status, 
      req.requestedBy, req.expiresAt.toISOString(), req.createdAt.toISOString(), 
      req.code || null, req.language || null, req.riskScore ?? 0
    ]);
    return req.id;
  }

  async getApprovalRequest(id: string): Promise<PermissionRequest | null> {
    if (this.isMock) {
      const row = this.mockStore.approval_requests.get(id);
      if (!row) return null;
      return this.mapApprovalRow(row);
    }
    const { rows } = await this.pool!.query('SELECT * FROM approval_requests WHERE id = $1', [id]);
    if (!rows.length) return null;
    return this.mapApprovalRow(rows[0]);
  }

  async updateApprovalStatus(id: string, status: string, approverId: string, reason?: string): Promise<void> {
    if (this.isMock) {
      const req = this.mockStore.approval_requests.get(id);
      if (req) { Object.assign(req, { status, approvedBy: approverId, reason, approvalTime: new Date().toISOString() }); }
      return;
    }
    await this.pool!.query(`UPDATE approval_requests SET status = $1, approvedBy = $2, reason = $3, approvalTime = $4 WHERE id = $5`, 
      [status, approverId, reason || null, new Date().toISOString(), id]
    );
  }

  async listApprovalRequests(status?: string): Promise<any[]> {
    if (this.isMock) {
      let results = Array.from(this.mockStore.approval_requests.values());
      if (status) results = results.filter((r: any) => r.status === status);
      return results.map(this.mapApprovalRowLite);
    }
    
    let sql = 'SELECT * FROM approval_requests';
    const params: any[] = [];
    if (status) { params.push(status); sql += ' WHERE status = $1'; }
    sql += ' ORDER BY createdAt DESC LIMIT 100';
    
    const { rows } = await this.pool!.query(sql, params);
    return rows.map(r => this.mapApprovalRowLite(r));
  }

  async getApiKeysByUser(userId: string): Promise<any[]> {
    if (this.isMock) {
      return Array.from(this.mockStore.api_keys.values())
        .filter((k: any) => k.userId === userId)
        .map(this.mapApiKeyLite);
    }
    const { rows } = await this.pool!.query('SELECT id, keyPrefix, status, organizationId, createdAt FROM api_keys WHERE userId = $1 ORDER BY createdAt DESC', [userId]);
    return rows.map(r => this.mapApiKeyLite({ ...r, keyPrefix: r.keyprefix, organizationId: r.organizationid }));
  }

  async getApiKeysByOrg(organizationId: string): Promise<any[]> {
    if (this.isMock) {
      return Array.from(this.mockStore.api_keys.values())
        .filter((k: any) => k.organizationId === organizationId)
        .map(this.mapApiKeyLite);
    }
    const { rows } = await this.pool!.query('SELECT id, keyPrefix, status, organizationId, createdAt FROM api_keys WHERE organizationId = $1 ORDER BY createdAt DESC', [organizationId]);
    return rows.map(r => this.mapApiKeyLite({ ...r, keyPrefix: r.keyprefix, organizationId: r.organizationid }));
  }

  async getUserByApiKeyAsync(rawKey: string): Promise<any | 'expired' | null> {
    const keyHash = PermissionDB.hashApiKey(rawKey);
    const now = new Date().toISOString();

    if (this.isMock) {
      const apiKey = Array.from(this.mockStore.api_keys.values()).find(
        (k: any) => k.keyHash === keyHash && k.status === 'active'
      ) as any;
      if (!apiKey) return null;
      if (apiKey.expiresAt && apiKey.expiresAt < now) return 'expired';
      apiKey.lastUsedAt = now;
      const user = this.mockStore.users.get(apiKey.userId);
      return user ? { ...user, keyOrgId: apiKey.organizationId } : null;
    }

    const { rows } = await this.pool!.query(`
      SELECT u.*, k.organizationId as keyOrgId, k.keySecret, k.id as keyId, k.expiresAt as keyExpiresAt
      FROM users u JOIN api_keys k ON u.id = k.userId
      WHERE k.keyHash = $1 AND k.status = 'active'
    `, [keyHash]);

    if (!rows.length) return null;
    const row = rows[0];

    if (row.keyexpiresat && row.keyexpiresat < now) return 'expired';

    if (row.keysecret) {
      const valid = await bcrypt.compare(rawKey, row.keysecret);
      if (!valid) return null;
    }

    try {
      this.pool!.query('UPDATE api_keys SET lastUsedAt = $1 WHERE id = $2', [now, row.keyid]).catch(e => e);
    } catch { /* ignore */ }

    // Map Postgres lowercase keys to expected camelCase
    return { ...row, keyOrgId: row.keyorgid, organizationId: row.organizationid };
  }

  async createUser(user: any): Promise<void> {
    if (this.isMock) { this.mockStore.users.set(user.id, { ...user }); return; }
    await this.pool!.query(`INSERT INTO users (id, email, organizationId, role) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, 
      [user.id, user.email, user.organizationId, user.role]
    );
  }

  async getUserById(id: string): Promise<any> {
    if (this.isMock) { return this.mockStore.users.get(id) || null; }
    const { rows } = await this.pool!.query('SELECT * FROM users WHERE id = $1', [id]);
    if (!rows.length) return null;
    return { ...rows[0], organizationId: rows[0].organizationid };
  }

  async createApiKey(
    id: string,
    userId: string,
    rawKey: string,
    organizationId: string,
    options: { name?: string; expiresAt?: string } = {}
  ): Promise<void> {
    const keyHash   = PermissionDB.hashApiKey(rawKey);
    const keySecret = await PermissionDB.bcryptApiKey(rawKey); 
    const keyPrefix = rawKey.substring(0, 12);
    const name      = options.name || id;
    const expiresAt = options.expiresAt || null;

    if (this.isMock) {
      this.mockStore.api_keys.set(id, { id, userId, keyHash, keySecret, keyPrefix, name, organizationId, status: 'active', expiresAt, createdAt: new Date().toISOString() });
      return;
    }
    await this.pool!.query(
      `INSERT INTO api_keys (id, keyHash, keySecret, keyPrefix, name, userId, organizationId, expiresAt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`,
      [id, keyHash, keySecret, keyPrefix, name, userId, organizationId, expiresAt]
    );
  }

  async revokeApiKey(id: string): Promise<void> {
    if (this.isMock) {
      const key = this.mockStore.api_keys.get(id);
      if (key) key.status = 'revoked';
      return;
    }
    await this.pool!.query('UPDATE api_keys SET status = $1 WHERE id = $2', ['revoked', id]);
  }

  async isHealthy(): Promise<boolean> {
    if (this.isMock) return true;
    try {
      await this.pool!.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async getStats(): Promise<any> {
    if (this.isMock) {
      return {
        users: this.mockStore.users.size,
        apiKeys: this.mockStore.api_keys.size,
        permissions: this.mockStore.permissions.size,
        approvalRequests: this.mockStore.approval_requests.size,
        mode: 'mock'
      };
    }
    const [u, k, p, a] = await Promise.all([
      this.pool!.query('SELECT COUNT(*) FROM users'),
      this.pool!.query('SELECT COUNT(*) FROM api_keys'),
      this.pool!.query('SELECT COUNT(*) FROM permissions'),
      this.pool!.query('SELECT COUNT(*) FROM approval_requests')
    ]);
    return {
      users: parseInt(u.rows[0].count),
      apiKeys: parseInt(k.rows[0].count),
      permissions: parseInt(p.rows[0].count),
      approvalRequests: parseInt(a.rows[0].count),
      mode: 'postgres'
    };
  }

  async query(sql: string, params: any[] = []): Promise<any[]> {
    if (this.isMock) return [];
    return (await this.pool!.query(sql, params)).rows;
  }

  async close(): Promise<void> {
    if (!this.isMock && this.pool) {
      await this.pool.end();
    }
  }

  private mapPermissionRow(row: any): Permission {
    return {
      id: row.id,
      type: row.type as PermissionType,
      resource: row.resource,
      action: row.action as any,
      conditions: {
        maxDataSize: row.maxDataSize || row.maxdatasize,
        maxExecutionTime: row.maxExecutionTime || row.maxexecutiontime,
        expiresAt: (row.expiresAt || row.expiresat) ? new Date(row.expiresAt || row.expiresat) : undefined,
        requiresApproval: (row.requiresApproval !== undefined ? row.requiresApproval : row.requiresapproval) === 1
      },
      createdAt: new Date(row.createdAt || row.createdat),
      createdBy: row.createdBy || row.createdby
    };
  }

  private mapApprovalRow(row: any): PermissionRequest {
    return {
      ...row,
      executionId: row.executionId || row.executionid,
      requestedBy: row.requestedBy || row.requestedby,
      approvedBy: row.approvedBy || row.approvedby,
      requestedPermissions: typeof (row.permissions || row.requestedPermissions) === 'string' 
        ? JSON.parse(row.permissions || row.requestedPermissions) 
        : (row.permissions || row.requestedPermissions),
      expiresAt: new Date(row.expiresAt || row.expiresat),
      createdAt: new Date(row.createdAt || row.createdat),
      approvalTime: (row.approvalTime || row.approvaltime) ? new Date(row.approvalTime || row.approvaltime) : undefined,
      riskScore: row.riskScore || row.riskscore
    };
  }

  private mapApprovalRowLite(r: any) {
    return {
      id: r.id,
      executionId: r.executionId || r.executionid,
      status: r.status,
      requestedBy: r.requestedBy || r.requestedby,
      createdAt: r.createdAt || r.createdat,
      expiresAt: r.expiresAt || r.expiresat,
      code: r.code,
      language: r.language,
    };
  }

  private mapApiKeyLite(k: any) {
    return {
      id: k.id,
      keyPrefix: k.keyPrefix || k.keyprefix,
      name: k.name || k.id,
      status: k.status,
      organizationId: k.organizationId || k.organizationid,
      createdAt: k.createdAt || k.createdat || new Date().toISOString(),
    };
  }
}
