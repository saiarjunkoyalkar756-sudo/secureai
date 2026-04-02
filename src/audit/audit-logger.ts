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
      console.warn(`[AuditLogger] Falling back to IN-MEMORY MOCK MODE.`);
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
      )
    `);
  }

  async log(entry: Omit<AuditEntry, 'id' | 'previousHash' | 'signature'>): Promise<AuditEntry> {
    const lastEntry = this.getLastEntry();
    const previousHash = lastEntry ? (this.isMock ? lastEntry.signature : (lastEntry as any).hash) : '';

    const auditEntry: AuditEntry = {
      ...entry,
      id: Math.random().toString(36).substring(7),
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

  verifyIntegrity(): string[] {
    const entries = this.isMock ? this.mockLog : this.db.prepare('SELECT * FROM audit_log ORDER BY timestamp ASC').all() as any[];
    const tamperedIds: string[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (i > 0) {
        const prevEntry = entries[i - 1];
        const actualPrevHash = this.isMock ? prevEntry.signature : this.computeHash(prevEntry);
        if (entry.previousHash !== actualPrevHash) tamperedIds.push(entry.id);
      }
      const hash = this.computeHash(entry);
      const expectedSig = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
      if (entry.signature !== expectedSig) tamperedIds.push(entry.id);
    }
    return tamperedIds;
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
    return this.db.prepare('SELECT *, signature as hash FROM audit_log ORDER BY timestamp DESC LIMIT 1').get() || null;
  }
}
