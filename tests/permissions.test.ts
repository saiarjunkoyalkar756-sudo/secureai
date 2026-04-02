import { PermissionEngine } from '../src/core/permissions/engine';
import { PermissionDB } from '../src/core/permissions/db';
import * as path from 'path';
import * as fs from 'fs';

describe('Permission Engine', () => {
  let engine: PermissionEngine;
  let db: PermissionDB;
  const dbPath = path.join(__dirname, 'test-permissions.db');

  beforeAll(() => {
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    db = new PermissionDB(dbPath);
    engine = new PermissionEngine(db as any);
  });

  afterAll(() => {
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  });

  it('should detect file operations in Python', async () => {
    const code = 'with open("/etc/passwd", "r") as f: data = f.read()';
    const analysis = await engine.analyzeCodeStatically(code, 'python3.11');
    expect(analysis.filesAccessed).toContain('/etc/passwd');
  });

  it('should detect network egress in JS', async () => {
    const code = 'fetch("https://api.example.com/data")';
    const analysis = await engine.analyzeCodeStatically(code, 'node20');
    expect(analysis.networksAccessed).toContain('api.example.com');
  });

  it('should detect subprocess execution in Bash', async () => {
    const code = 'ls -la; cat /tmp/secret.txt';
    const analysis = await engine.analyzeCodeStatically(code, 'bash');
    expect(analysis.filesAccessed).toContain('/tmp/secret.txt');
  });

  it('should flag critical suspicious patterns', async () => {
    const code = 'os.system("rm -rf /")';
    const analysis = await engine.analyzeCodeStatically(code, 'python3.11');
    const critical = analysis.suspiciousPatterns.find(p => p.severity === 'critical');
    expect(critical).toBeDefined();
    expect(critical?.pattern).toBe('destructive_command');
  });

  it('should infer permissions correctly from analysis', async () => {
    const analysis = {
      filesAccessed: ['/app/data.json'],
      networksAccessed: ['google.com'],
      subprocesses: ['ls'],
      envVarsAccessed: ['API_KEY'],
      suspiciousPatterns: []
    };
    const permissions = engine.inferPermissions(analysis as any);
    
    expect(permissions.some(p => p.type === 'file_read' && p.resource === '/app/data.json')).toBe(true);
    expect(permissions.some(p => p.type === 'network_egress' && p.resource === 'google.com')).toBe(true);
    expect(permissions.some(p => p.type === 'subprocess_exec' && p.resource === 'ls')).toBe(true);
    expect(permissions.some(p => p.type === 'env_read' && p.resource === 'API_KEY')).toBe(true);
  });

  it('should block execution if permissions are missing in DB', async () => {
    const execution = {
      id: 'exec-1',
      userId: 'user-1',
      code: 'open("/secret.txt")',
      language: 'python3.11'
    };
    const result = await engine.checkPermissions(execution, 'executor');
    expect(result.canExecute).toBe(false);
    expect(result.requiresApprovalFor.length).toBeGreaterThan(0);
  });
});
