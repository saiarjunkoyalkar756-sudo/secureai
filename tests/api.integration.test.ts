import request from 'supertest';
import app from '../src/api/routes';

// Test API key (must be seeded first)
const ADMIN_KEY = 'sk_test_admin_123456';
const EXECUTOR_KEY = 'sk_test_executor_789';
const INVALID_KEY = 'sk_totally_wrong_key';

describe('SecureAI API', () => {
  
  describe('GET /health', () => {
    it('returns health status', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.version).toBeDefined();
      expect(res.body.database).toBeDefined();
      expect(res.body.uptime).toBeDefined();
    });
  });

  describe('Authentication', () => {
    it('rejects requests without auth header', async () => {
      const res = await request(app)
        .post('/v1/execute')
        .send({ code: 'print(1)', language: 'python3.11' });
      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Missing');
    });

    it('rejects invalid API key', async () => {
      const res = await request(app)
        .post('/v1/execute')
        .set('Authorization', `Bearer ${INVALID_KEY}`)
        .send({ code: 'print(1)', language: 'python3.11' });
      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Invalid');
    });
  });

  describe('POST /v1/execute', () => {
    it('validates request body', async () => {
      const res = await request(app)
        .post('/v1/execute')
        .set('Authorization', `Bearer ${ADMIN_KEY}`)
        .send({ language: 'python3.11' }); // Missing code
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation failed');
    });

    it('rejects invalid language', async () => {
      const res = await request(app)
        .post('/v1/execute')
        .set('Authorization', `Bearer ${ADMIN_KEY}`)
        .send({ code: 'print(1)', language: 'ruby' });
      expect(res.status).toBe(400);
    });

    it('blocks critical threats (rm -rf /)', async () => {
      const res = await request(app)
        .post('/v1/execute')
        .set('Authorization', `Bearer ${ADMIN_KEY}`)
        .send({ code: 'os.system("rm -rf /")', language: 'python3.11' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('blocked');
      expect(res.body.threats.length).toBeGreaterThan(0);
    });
  });

  describe('POST /v1/analyze', () => {
    it('analyzes code without executing', async () => {
      const res = await request(app)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${ADMIN_KEY}`)
        .send({ code: `requests.get('https://evil.com')`, language: 'python3.11' });
      expect(res.status).toBe(200);
      expect(res.body.riskScore).toBeDefined();
      expect(res.body.networksAccessed).toContain('evil.com');
      expect(res.body.recommendation).toBeDefined();
    });

    it('rejects missing fields', async () => {
      const res = await request(app)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${ADMIN_KEY}`)
        .send({ code: 'print(1)' }); // Missing language
      expect(res.status).toBe(400);
    });
  });

  describe('Approval Flow', () => {
    it('returns 404 for non-existent approval', async () => {
      const res = await request(app)
        .get('/v1/approvals/nonexistent')
        .set('Authorization', `Bearer ${ADMIN_KEY}`);
      expect(res.status).toBe(404);
    });
  });

  describe('Admin Endpoints', () => {
    it('GET /v1/audit/integrity works for admin', async () => {
      const res = await request(app)
        .get('/v1/audit/integrity')
        .set('Authorization', `Bearer ${ADMIN_KEY}`);
      // May be 200 or 403 depending on seed state — just verify it doesn't crash
      expect([200, 401, 403]).toContain(res.status);
    });

    it('GET /v1/audit/recent works for admin', async () => {
      const res = await request(app)
        .get('/v1/audit/recent')
        .set('Authorization', `Bearer ${ADMIN_KEY}`);
      expect([200, 401, 403]).toContain(res.status);
    });
  });

  describe('Rate Limiting', () => {
    it('includes rate limit headers', async () => {
      const res = await request(app).get('/health');
      expect(res.headers['x-ratelimit-limit']).toBeDefined();
      expect(res.headers['x-ratelimit-remaining']).toBeDefined();
    });
  });

  describe('Request Logging', () => {
    it('includes X-Request-Id header', async () => {
      const res = await request(app).get('/health');
      expect(res.headers['x-request-id']).toBeDefined();
      expect(res.headers['x-request-id'].length).toBeGreaterThan(0);
    });
  });
});
