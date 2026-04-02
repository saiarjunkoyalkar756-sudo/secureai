import { PermissionDB } from './src/core/permissions/db';
import * as path from 'path';

async function testAuthSystem() {
  const dbPath = path.join(__dirname, 'secureai.db');
  const db = new PermissionDB(dbPath);

  console.log('--- Setting up Test Data ---');
  
  const testUser = {
    id: 'user_test_1',
    email: 'test@secureai.io',
    organizationId: 'org_acme',
    role: 'admin'
  };

  try {
    db.createUser(testUser);
    console.log('User created:', testUser.email);
  } catch (e) {
    console.log('User already exists (skipping)');
  }

  const apiKeyId = 'key_test_1';
  const apiKeyValue = 'sk_test_123456789';
  
  try {
    db.createApiKey(apiKeyId, testUser.id, apiKeyValue, testUser.organizationId);
    console.log('API Key created:', apiKeyValue);
  } catch (e) {
    console.log('API Key already exists (skipping)');
  }

  console.log('\n--- Verifying Auth Retrieval ---');
  const user = db.getUserByApiKey(apiKeyValue);
  
  if (user && user.email === testUser.email) {
    console.log('✅ Auth retrieval PASSED');
    console.log('User Role:', user.role);
    console.log('Key Org ID:', user.keyOrgId);
  } else {
    console.error('❌ Auth retrieval FAILED');
    process.exit(1);
  }

  console.log('\n--- Verifying Invalid Key ---');
  const invalidUser = db.getUserByApiKey('wrong_key');
  if (!invalidUser) {
    console.log('✅ Invalid key check PASSED');
  } else {
    console.error('❌ Invalid key check FAILED');
    process.exit(1);
  }
}

testAuthSystem().catch(console.error);
