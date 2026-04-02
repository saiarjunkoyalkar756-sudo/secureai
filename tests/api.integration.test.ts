import request from 'supertest';
import app from '../src/api/routes';
import { PermissionDB } from '../src/core/permissions/db';
import * as path from 'path';
import * as fs from 'fs';

describe('API Integration', () => {
  const dbPath = path.join(__dirname, '../../secureai.db');
  let db: PermissionDB;
  const apiKey = 'sk_test_12345';
  const adminKey = 'sk_admin_12345';

  beforeAll(() => {
    // Note: Since the app instantiates its own PermissionDB on require, 
    // we must ensure that the same DB is used or initialized for our tests.
    db = new PermissionDB(dbPath);
    
    // Seed test users
    db.createUser({ id: 'user_1', email: 'user@test.io', organizationId: 'org_1', role: 'executor' });
    db.createUser({ id: 'admin_1', email: 'admin@test.io', organizationId: 'org_1', role: 'admin' });
    
    // Seed API Keys
    db.createApiKey('k1', 'user_1', apiKey, 'org_1');
    db.createApiKey('k2', 'admin_1', adminKey, 'org_1');
  });

  afterAll(() => {
    // DB cleanup (be careful in multi-tenant environments)
  });

  it('should reject requests without a valid API key', async () => {
    const res = await request(app)
      .post('/v1/execute')
      .send({ code: 'print("hi")', language: 'python3.11' });

    expect(res.status).toBe(401);
  });

  it('should allow execution for simple, safe code', async () => {
    const res = await request(app)
      .post('/v1/execute')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ 
        code: 'print("hello world")', 
        language: 'python3.11' 
      });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
  });

  it('should return 202 Accepted and an approvalId for sensitive code', async () => {
    const res = await request(app)
      .post('/v1/execute')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ 
        code: 'open("/etc/passwd", "r")', 
        language: 'python3.11' 
      });

    expect(res.status).toBe(202);
    expect(res.body.status).toBe('pending_approval');
    expect(res.body.approvalId).toBeDefined();
  });

  it('should allow an admin to approve a pending request', async () => {
    // 1. Create a request
    const postRes = await request(app)
      .post('/v1/execute')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ code: 'fetch("https://google.com")', language: 'node20' });
    
    const approvalId = postRes.body.approvalId;

    // 2. Approve it
    const approveRes = await request(app)
      .post(`/v1/approvals/${approvalId}/approve`)
      .set('Authorization', `Bearer ${adminKey}`);

    expect(approveRes.status).toBe(200);
    expect(approveRes.body.status).toBe('granted');
  });

  it('should reject non-admin users from approving requests', async () => {
    const res = await request(app)
      .post('/v1/approvals/any-id/approve')
      .set('Authorization', `Bearer ${apiKey}`); // Normal user key

    expect(res.status).toBe(403);
  });
});
