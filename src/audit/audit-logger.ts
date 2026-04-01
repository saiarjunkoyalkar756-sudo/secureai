import * as crypto from 'crypto';
import Database from 'better-sqlite3';

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
  private db: Database.Database;
  private signingKey: Buffer;

  constructor(dbPath: string, signingKey: Buffer) {
    this.db = new Database(dbPath);
    this.signingKey = signingKey;
    this.initializeSchema();
  }

  private initializeSchema() {
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
    const previousHash = lastEntry?.hash || '';

    const auditEntry: AuditEntry = {
      ...entry,
      id: Math.random().toString(36).substring(7),
      previousHash,
      signature: '' 
    };

    const hash = this.computeHash(auditEntry);
    
    const signature = crypto
      .createHmac('sha256', this.signingKey)
      .update(hash)
      .digest('hex');

    auditEntry.signature = signature;

    this.db.prepare(`
      INSERT INTO audit_log (
        id, timestamp, executionId, userId, action,
        resourcesBefore, resourcesAfter, metadata,
        previousHash, signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditEntry.id,
      auditEntry.timestamp.toISOString(),
      auditEntry.executionId,
      auditEntry.userId,
      auditEntry.action,
      JSON.stringify(auditEntry.resourcesBefore),
      JSON.stringify(auditEntry.resourcesAfter),
      JSON.stringify(auditEntry.metadata),
      previousHash,
      signature
    );

    return auditEntry;
  }

  verifyIntegrity(): string[] {
    const entries = this.db.prepare('SELECT * FROM audit_log ORDER BY timestamp ASC').all() as any[];
    const tamperedIds: string[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      
      if (i > 0) {
        const prevEntry = entries[i - 1];
        if (entry.previousHash !== this.computeHash(prevEntry)) {
          tamperedIds.push(entry.id);
        }
      }

      const expectedSig = crypto
        .createHmac('sha256', this.signingKey)
        .update(this.computeHash(entry))
        .digest('hex');

      if (entry.signature !== expectedSig) {
        tamperedIds.push(entry.id);
      }
    }

    return tamperedIds;
  }

  private computeHash(entry: any): string {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify({
        timestamp: entry.timestamp,
        executionId: entry.executionId,
        action: entry.action,
        previousHash: entry.previousHash
      }))
      .digest('hex');
  }

  private getLastEntry(): any | null {
    return this.db.prepare(
      'SELECT *, signature as hash FROM audit_log ORDER BY timestamp DESC LIMIT 1'
    ).get() || null;
  }
}
