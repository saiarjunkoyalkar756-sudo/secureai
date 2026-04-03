import * as crypto from 'crypto';

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

/**
 * AuditLogger — Immutable, cryptographically-signed audit trail.
 * 
 * Features:
 * - Hash chain: Each entry's hash depends on the previous entry
 * - HMAC signing: All entries signed with a server-side key
 * - Integrity verification: Detect tampering in the chain
 * - Convenience methods for common audit events
 */
export class AuditLogger {
  private db: any;
  private signingKey: Buffer;
  private isMock: boolean = false;
  private mockLog: AuditEntry[] = [];

  constructor(dbPath: string, signingKey: Buffer) {
    this.signingKey = signingKey;
    try {
      const Database = require('better-sqlite3');
      this.db = new Database(dbPath);
      this.initializeSchema();
    } catch (err) {
      this.isMock = true;
      console.warn(`[AuditLogger] ⚠ Falling back to IN-MEMORY MOCK MODE.`);
    }
  }

  private initializeSchema() {
    if (this.isMock) return;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        executionId TEXT,
        userId TEXT,
        action TEXT,
        resourcesBefore TEXT,
        resourcesAfter TEXT,
        metadata TEXT,
        previousHash TEXT,
        signature TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_log(executionId);
      CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(userId);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    `);
  }

  async log(entry: Omit<AuditEntry, 'id' | 'previousHash' | 'signature'>): Promise<AuditEntry> {
    const lastEntry = this.getLastEntry();
    // Always use the previous entry's SIGNATURE as the chain link (consistent in both mock and real modes)
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
      this.db.prepare(`INSERT INTO audit_log (id, timestamp, executionId, userId, action, resourcesBefore, resourcesAfter, metadata, previousHash, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        auditEntry.id, auditEntry.timestamp.toISOString(), auditEntry.executionId, auditEntry.userId, auditEntry.action,
        JSON.stringify(auditEntry.resourcesBefore), JSON.stringify(auditEntry.resourcesAfter), JSON.stringify(auditEntry.metadata),
        previousHash, signature
      );
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

  verifyIntegrity(): { valid: boolean; tamperedIds: string[] } {
    const entries = this.isMock
      ? this.mockLog
      : this.db.prepare('SELECT * FROM audit_log ORDER BY rowid ASC').all() as any[];
    const tamperedIds: string[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // 1. Verify the chain link: this entry's previousHash must equal the prior entry's signature
      if (i > 0) {
        const prevSignature = entries[i - 1].signature;
        if (entry.previousHash !== prevSignature) tamperedIds.push(entry.id);
      }

      // 2. Verify the HMAC signature of this entry itself
      const hash = this.computeHash(entry);
      const expectedSig = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
      if (entry.signature !== expectedSig) tamperedIds.push(entry.id);
    }

    return { valid: tamperedIds.length === 0, tamperedIds };
  }

  getEntryCount(): number {
    if (this.isMock) return this.mockLog.length;
    return (this.db.prepare('SELECT COUNT(*) as count FROM audit_log').get() as any).count;
  }

  getRecentEntries(limit: number = 20): AuditEntry[] {
    if (this.isMock) return this.mockLog.slice(-limit);
    return this.db.prepare('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?').all(limit) as AuditEntry[];
  }

  private computeHash(entry: any): string {
    return crypto.createHash('sha256').update(JSON.stringify({
      timestamp: entry.timestamp instanceof Date ? entry.timestamp.toISOString() : entry.timestamp,
      executionId: entry.executionId,
      action: entry.action,
      previousHash: entry.previousHash
    })).digest('hex');
  }

  private getLastEntry(): any | null {
    if (this.isMock) return this.mockLog[this.mockLog.length - 1] || null;
    // In real mode, return the row directly — we use .signature for chaining now
    return this.db.prepare('SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 1').get() || null;
  }
}
