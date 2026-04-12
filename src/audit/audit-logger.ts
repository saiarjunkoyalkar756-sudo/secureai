import * as crypto from 'crypto';
import { Pool } from 'pg';

export interface AuditEntry {
  id: string;
  timestamp: Date;
  executionId: string;
  userId: string;
  action: string; 
  resourcesBefore: Record<string, any>;
  resourcesAfter: Record<string, any>;
  metadata: Record<string, any>;
  previousHash: string; 
  signature: string; 
}

export class AuditLogger {
  private pool: Pool | null = null;
  private signingKey: Buffer;
  private isMock: boolean = false;
  private mockLog: AuditEntry[] = [];

  constructor(postgresUrl: string | undefined, signingKey: Buffer) {
    this.signingKey = signingKey;
    if (postgresUrl) {
      try {
        this.pool = new Pool({
          connectionString: postgresUrl,
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
        });
        this.initializeSchema();
      } catch (err) {
        this.isMock = true;
        console.warn(`[AuditLogger] ⚠ Failed to connect. Falling back to IN-MEMORY MOCK MODE.`);
      }
    } else {
      this.isMock = true;
    }
  }

  private async initializeSchema() {
    if (this.isMock || !this.pool) return;
    try {
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS audit_log (
          id TEXT PRIMARY KEY,
          timestamp TIMESTAMP,
          executionId TEXT,
          userId TEXT,
          action TEXT,
          resourcesBefore TEXT,
          resourcesAfter TEXT,
          metadata TEXT,
          previousHash TEXT,
          signature TEXT,
          created_serial SERIAL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_log(executionId);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(userId);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
      `);
    } catch (err) {
      console.error('[AuditLogger] Failed to initialize schema:', err);
    }
  }

  async log(entry: Omit<AuditEntry, 'id' | 'previousHash' | 'signature'>): Promise<AuditEntry> {
    const lastEntry = await this.getLastEntry();
    const previousHash = lastEntry ? lastEntry.signature : '';

    const auditEntry: AuditEntry = {
      ...entry,
      id: crypto.randomUUID(),
      previousHash,
      signature: ''
    };

    const hash = this.computeHash(auditEntry);
    const signature = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
    auditEntry.signature = signature;

    if (this.isMock) {
      this.mockLog.push(auditEntry);
    } else {
      await this.pool!.query(`
        INSERT INTO audit_log (
          id, timestamp, executionId, userId, action, resourcesBefore, resourcesAfter, metadata, previousHash, signature
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        auditEntry.id, auditEntry.timestamp.toISOString(), auditEntry.executionId, auditEntry.userId, auditEntry.action,
        JSON.stringify(auditEntry.resourcesBefore), JSON.stringify(auditEntry.resourcesAfter), JSON.stringify(auditEntry.metadata),
        previousHash, signature
      ]);
    }

    return auditEntry;
  }

  // --- Convenience Methods ---

  async logExecution(executionId: string, userId: string, code: string, language: string, result: any) {
    return this.log({
      timestamp: new Date(),
      executionId,
      userId,
      action: 'code_execution',
      resourcesBefore: { code: code.substring(0, 500), language },
      resourcesAfter: {
        status: result.status,
        exitCode: result.exitCode,
        sandboxType: result.sandboxType,
        outputLength: result.stdout?.length || 0
      },
      metadata: {
        executionTime: result.executionTime,
        resourcesUsed: result.resourcesUsed
      }
    });
  }

  async logPermissionCheck(executionId: string, userId: string, result: any) {
    return this.log({
      timestamp: new Date(),
      executionId,
      userId,
      action: 'permission_check',
      resourcesBefore: {},
      resourcesAfter: {
        canExecute: result.canExecute,
        blockedCount: result.blockedBy?.length || 0,
        autoApprovedCount: result.autoApproved?.length || 0
      },
      metadata: {
        requiresApproval: result.requiresApprovalFor?.map((p: any) => `${p.type}:${p.resource}`) || []
      }
    });
  }

  async logApproval(approvalId: string, executionId: string, approverId: string) {
    return this.log({
      timestamp: new Date(),
      executionId,
      userId: approverId,
      action: 'approval_granted',
      resourcesBefore: { status: 'pending' },
      resourcesAfter: { status: 'approved' },
      metadata: { approvalId }
    });
  }

  async logRejection(approvalId: string, executionId: string, approverId: string, reason?: string) {
    return this.log({
      timestamp: new Date(),
      executionId,
      userId: approverId,
      action: 'approval_rejected',
      resourcesBefore: { status: 'pending' },
      resourcesAfter: { status: 'rejected' },
      metadata: { approvalId, reason }
    });
  }

  async logThreatBlocked(executionId: string, userId: string, threats: any[]) {
    return this.log({
      timestamp: new Date(),
      executionId,
      userId,
      action: 'threat_blocked',
      resourcesBefore: {},
      resourcesAfter: { blocked: true, threatCount: threats.length },
      metadata: { threats }
    });
  }

  // --- Integrity Verification ---

  async verifyIntegrity(): Promise<{ valid: boolean; tamperedIds: string[] }> {
    const entries = this.isMock
      ? this.mockLog
      : (await this.pool!.query('SELECT * FROM audit_log ORDER BY created_serial ASC')).rows;
    const tamperedIds: string[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      if (i > 0) {
        const prevSignature = entries[i - 1].signature;
        if ((entry.previousHash || entry.previoushash) !== prevSignature) tamperedIds.push(entry.id);
      }

      const hash = this.computeHash(entry);
      const expectedSig = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
      if (entry.signature !== expectedSig) tamperedIds.push(entry.id);
    }

    return { valid: tamperedIds.length === 0, tamperedIds };
  }

  async getEntryCount(): Promise<number> {
    if (this.isMock) return this.mockLog.length;
    const { rows } = await this.pool!.query('SELECT COUNT(*) as count FROM audit_log');
    return parseInt(rows[0].count);
  }

  async getRecentEntries(limit: number = 20): Promise<AuditEntry[]> {
    if (this.isMock) return this.mockLog.slice(-limit);
    const { rows } = await this.pool!.query('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT $1', [limit]);
    return rows as any[];
  }

  private computeHash(entry: any): string {
    return crypto.createHash('sha256').update(JSON.stringify({
      timestamp: entry.timestamp instanceof Date ? entry.timestamp.toISOString() : entry.timestamp,
      executionId: entry.executionId || entry.executionid,
      action: entry.action,
      previousHash: entry.previousHash || entry.previoushash
    })).digest('hex');
  }

  private async getLastEntry(): Promise<any | null> {
    if (this.isMock) return this.mockLog[this.mockLog.length - 1] || null;
    const { rows } = await this.pool!.query('SELECT * FROM audit_log ORDER BY created_serial DESC LIMIT 1');
    return rows.length ? rows[0] : null;
  }
}
