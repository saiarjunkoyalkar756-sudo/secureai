"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const db_1 = require("./src/core/permissions/db");
const path = __importStar(require("path"));
/**
 * Seeds the database with test users, API keys, and sample permissions.
 */
async function seedDatabase() {
    const dbPath = path.resolve(process.cwd(), process.env.DATABASE_PATH || 'secureai.db');
    const db = new db_1.PermissionDB(dbPath);
    console.log('');
    console.log('🌱 Seeding SecureAI Database...');
    console.log('');
    // --- Admin User ---
    const adminUser = {
        id: 'user_admin_1',
        email: 'admin@secureai.io',
        organizationId: 'org_secureai',
        role: 'admin'
    };
    try {
        db.createUser(adminUser);
        console.log(`  👤 Created admin user: ${adminUser.email}`);
    }
    catch (e) {
        console.log(`  👤 Admin user already exists: ${adminUser.email}`);
    }
    // --- Executor User ---
    const executorUser = {
        id: 'user_executor_1',
        email: 'developer@secureai.io',
        organizationId: 'org_secureai',
        role: 'executor'
    };
    try {
        db.createUser(executorUser);
        console.log(`  👤 Created executor user: ${executorUser.email}`);
    }
    catch (e) {
        console.log(`  👤 Executor user already exists: ${executorUser.email}`);
    }
    // --- API Keys (stored as hashed) ---
    const adminKeyRaw = 'sk_test_admin_123456';
    try {
        db.createApiKey('key_admin_1', adminUser.id, adminKeyRaw, adminUser.organizationId);
        console.log(`  🔑 Created admin API key: ${adminKeyRaw}`);
    }
    catch (e) {
        console.log(`  🔑 Admin API key already exists`);
    }
    const executorKeyRaw = 'sk_test_executor_789';
    try {
        db.createApiKey('key_executor_1', executorUser.id, executorKeyRaw, executorUser.organizationId);
        console.log(`  🔑 Created executor API key: ${executorKeyRaw}`);
    }
    catch (e) {
        console.log(`  🔑 Executor API key already exists`);
    }
    // --- Sample Permissions ---
    const samplePermissions = [
        {
            id: 'perm_1',
            type: 'file_read',
            resource: '/tmp/*',
            action: 'allow',
            requiresApproval: false,
            createdBy: 'system',
            organizationId: 'org_secureai'
        },
        {
            id: 'perm_2',
            type: 'network_egress',
            resource: 'api.github.com',
            action: 'allow',
            requiresApproval: true,
            createdBy: 'system',
            organizationId: 'org_secureai'
        },
        {
            id: 'perm_3',
            type: 'file_write',
            resource: '/tmp/*',
            action: 'allow',
            requiresApproval: false,
            createdBy: 'system',
            organizationId: 'org_secureai'
        }
    ];
    for (const perm of samplePermissions) {
        try {
            db.addPermission(perm);
            console.log(`  📋 Created permission: ${perm.type} → ${perm.resource} (${perm.action})`);
        }
        catch (e) {
            console.log(`  📋 Permission already exists: ${perm.id}`);
        }
    }
    // --- Verify ---
    console.log('');
    console.log('🔍 Verifying...');
    const adminAuth = db.getUserByApiKey(adminKeyRaw);
    if (adminAuth && adminAuth.email === adminUser.email) {
        console.log(`  ✅ Admin key auth: PASSED (role: ${adminAuth.role})`);
    }
    else {
        console.error('  ❌ Admin key auth: FAILED');
    }
    const executorAuth = db.getUserByApiKey(executorKeyRaw);
    if (executorAuth && executorAuth.email === executorUser.email) {
        console.log(`  ✅ Executor key auth: PASSED (role: ${executorAuth.role})`);
    }
    else {
        console.error('  ❌ Executor key auth: FAILED');
    }
    const invalidAuth = db.getUserByApiKey('totally_wrong_key');
    if (!invalidAuth) {
        console.log('  ✅ Invalid key rejection: PASSED');
    }
    else {
        console.error('  ❌ Invalid key rejection: FAILED');
    }
    const stats = db.getStats();
    console.log('');
    console.log('📊 Database Stats:', JSON.stringify(stats, null, 2));
    console.log('');
    console.log('🎉 Seed complete! Use these keys to authenticate:');
    console.log(`   Admin:    ${adminKeyRaw}`);
    console.log(`   Executor: ${executorKeyRaw}`);
    console.log('');
}
seedDatabase().catch(console.error);
