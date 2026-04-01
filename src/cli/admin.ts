import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:3000';

/**
 * Simple Admin CLI tool for SecureAI
 */
async function run() {
  const [,, command, id] = process.argv;

  if (!command || !id) {
    console.log('Usage: node dist/src/cli/admin.js <approve|deny> <id>');
    process.exit(1);
  }

  if (command === 'approve') {
    const resp = await fetch(`${BASE_URL}/v1/approvals/${id}/approve`, { method: 'POST' });
    const data = await resp.json() as any;
    console.log(`[Admin] Approval result:`, data.status === 'granted' ? 'SUCCESS ✅' : 'FAILED ❌');
  } else {
    console.log('[Admin] Denial logic not yet implemented in mock.');
  }
}

run().catch(console.error);
