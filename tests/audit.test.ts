import { AuditLogger } from '../src/audit/audit-logger';
import * as crypto from 'crypto';

describe('AuditLogger', () => {
  let logger: AuditLogger;
  const signingKey = crypto.randomBytes(32);

  beforeEach(() => {
    // Use an in-memory SQLite database to ensure clean state and isolation for each test run
    logger = new AuditLogger(':memory:', signingKey);
  });

  describe('Logging', () => {
    it('creates an audit entry with correct fields', async () => {
      const entry = await logger.log({
        timestamp: new Date(),
        executionId: 'exec-1',
        userId: 'user-1',
        action: 'code_execution',
        resourcesBefore: {},
        resourcesAfter: { result: 'success' },
        metadata: { ip: '127.0.0.1' }
      });

      expect(entry.id).toBeDefined();
      expect(entry.signature).toBeDefined();
      expect(entry.signature.length).toBe(64); // SHA-256 hex
      expect(entry.executionId).toBe('exec-1');
      expect(entry.action).toBe('code_execution');
    });

    it('chains entries with previous hash', async () => {
      const entry1 = await logger.log({
        timestamp: new Date(),
        executionId: 'exec-1',
        userId: 'user-1',
        action: 'file_read',
        resourcesBefore: {},
        resourcesAfter: {},
        metadata: {}
      });

      const entry2 = await logger.log({
        timestamp: new Date(),
        executionId: 'exec-2',
        userId: 'user-1',
        action: 'network_egress',
        resourcesBefore: {},
        resourcesAfter: {},
        metadata: {}
      });

      expect(entry2.previousHash).toBe(entry1.signature);
    });

    it('first entry has empty previousHash', async () => {
      const entry = await logger.log({
        timestamp: new Date(),
        executionId: 'exec-1',
        userId: 'user-1',
        action: 'test',
        resourcesBefore: {},
        resourcesAfter: {},
        metadata: {}
      });

      expect(entry.previousHash).toBe('');
    });
  });

  describe('Convenience Methods', () => {
    it('logExecution works', async () => {
      const entry = await logger.logExecution('exec-1', 'user-1', 'print("hi")', 'python3.11', {
        status: 'success', exitCode: 0, sandboxType: 'process', stdout: 'hi', executionTime: 0.5,
        resourcesUsed: { cpu: 0, memory: 0, disk: 0 }
      });
      expect(entry.action).toBe('code_execution');
    });

    it('logApproval works', async () => {
      const entry = await logger.logApproval('approval-1', 'exec-1', 'admin-1');
      expect(entry.action).toBe('approval_granted');
    });

    it('logRejection works', async () => {
      const entry = await logger.logRejection('approval-1', 'exec-1', 'admin-1', 'Too risky');
      expect(entry.action).toBe('approval_rejected');
    });

    it('logThreatBlocked works', async () => {
      const entry = await logger.logThreatBlocked('exec-1', 'user-1', [{ pattern: 'rm -rf', severity: 'critical' }]);
      expect(entry.action).toBe('threat_blocked');
    });
  });

  describe('Integrity Verification', () => {
    it('verifies valid chain', async () => {
      await logger.log({ timestamp: new Date(), executionId: 'e1', userId: 'u1', action: 'a', resourcesBefore: {}, resourcesAfter: {}, metadata: {} });
      await logger.log({ timestamp: new Date(), executionId: 'e2', userId: 'u1', action: 'b', resourcesBefore: {}, resourcesAfter: {}, metadata: {} });
      await logger.log({ timestamp: new Date(), executionId: 'e3', userId: 'u1', action: 'c', resourcesBefore: {}, resourcesAfter: {}, metadata: {} });

      const result = logger.verifyIntegrity();
      expect(result.valid).toBe(true);
      expect(result.tamperedIds).toHaveLength(0);
    });

    it('returns entry count', async () => {
      await logger.log({ timestamp: new Date(), executionId: 'e1', userId: 'u1', action: 'a', resourcesBefore: {}, resourcesAfter: {}, metadata: {} });
      await logger.log({ timestamp: new Date(), executionId: 'e2', userId: 'u1', action: 'b', resourcesBefore: {}, resourcesAfter: {}, metadata: {} });
      
      expect(logger.getEntryCount()).toBe(2);
    });
  });
});
