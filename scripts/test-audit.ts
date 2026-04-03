import { AuditLogger } from './src/audit/audit-logger';
import * as fs from 'fs';
import * as path from 'path';

async function testAuditLogger() {
  const dbPath = path.join(__dirname, 'test-audit.db');
  const signingKey = Buffer.from('my-secret-signing-key');

  // Clean up existing test DB
  if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
  }

  const logger = new AuditLogger(dbPath, signingKey);

  console.log('Logging first entry...');
  await logger.log({
    timestamp: new Date(),
    executionId: 'exec-1',
    userId: 'user-1',
    action: 'file_read',
    resourcesBefore: {},
    resourcesAfter: { 'file.txt': 'read' },
    metadata: { ip: '127.0.0.1' }
  });

  console.log('Logging second entry...');
  await logger.log({
    timestamp: new Date(),
    executionId: 'exec-2',
    userId: 'user-1',
    action: 'network_egress',
    resourcesBefore: {},
    resourcesAfter: { 'example.com': 'connected' },
    metadata: { ip: '127.0.0.1' }
  });

  console.log('Verifying integrity...');
  const tampered = logger.verifyIntegrity();
  if (tampered.length === 0) {
    console.log('Integrity check PASSED');
  } else {
    console.error('Integrity check FAILED. Tampered IDs:', tampered);
  }

  // Clean up
  if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
  }
}

testAuditLogger().catch(console.error);
