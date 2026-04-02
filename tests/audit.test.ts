import { AuditLogger } from '../src/audit/audit-logger';
import * as path from 'path';
import * as fs from 'fs';

describe('Audit Logger', () => {
  let logger: AuditLogger;
  const dbPath = path.join(__dirname, 'test-audit.db');
  const signingKey = Buffer.from('test-signing-key');

  beforeAll(() => {
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    logger = new AuditLogger(dbPath, signingKey);
  });

  afterAll(() => {
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  });

  it('should create and verify an audit log entry', async () => {
    const entry = await logger.log({
      timestamp: new Date(),
      executionId: 'exec-1',
      userId: 'user-1',
      action: 'file_read',
      resourcesBefore: {},
      resourcesAfter: { '/etc/passwd': 'read' },
      metadata: { ip: '127.0.0.1' }
    });

    expect(entry.id).toBeDefined();
    expect(entry.signature).toBeDefined();
    expect(entry.previousHash).toBe('');
  });

  it('should maintain a hash chain', async () => {
    const entry1 = await logger.log({
      timestamp: new Date(),
      executionId: 'exec-2',
      userId: 'user-1',
      action: 'file_read',
      resourcesBefore: {},
      resourcesAfter: {},
      metadata: {}
    });

    const entry2 = await logger.log({
      timestamp: new Date(),
      executionId: 'exec-3',
      userId: 'user-1',
      action: 'file_read',
      resourcesBefore: {},
      resourcesAfter: {},
      metadata: {}
    });

    // entry2.previousHash should match a hash of entry1's data (represented in entry1.signature or calculated)
    // In our implementation, previousHash is the hash of the last entry's JSON
    expect(entry2.previousHash).not.toBe('');
    expect(entry2.previousHash).not.toBe(entry1.previousHash);
  });

  it('should pass integrity verification if no tampering occurred', async () => {
    const tampered = logger.verifyIntegrity();
    expect(tampered.length).toBe(0);
  });

  it('should detect tampering if signature is invalid', async () => {
    // Manually tamper with the database to simulate an attacker
    const Database = require('better-sqlite3');
    const db = new Database(dbPath);
    
    // Change action of first entry
    db.prepare('UPDATE audit_log SET action = "malicious_action" WHERE id = (SELECT id FROM audit_log LIMIT 1)').run();
    
    const tampered = logger.verifyIntegrity();
    expect(tampered.length).toBeGreaterThan(0);
  });
});
