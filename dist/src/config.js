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
exports.config = void 0;
const crypto = __importStar(require("crypto"));
function loadConfig() {
    const errors = [];
    const port = parseInt(process.env.PORT || '3000', 10);
    const nodeEnv = process.env.NODE_ENV || 'development';
    const postgresUrl = process.env.POSTGRES_URL;
    if (nodeEnv === 'production' && !postgresUrl) {
        console.warn('[Config] ⚠️ POSTGRES_URL is not set in production. Database will fall back to In-Memory Mock Mode.');
    }
    // Audit signing key - generate a default for dev, warn loudly in production
    let auditSigningKey;
    if (process.env.AUDIT_SIGNING_KEY && process.env.AUDIT_SIGNING_KEY !== 'your_secure_audit_signing_key_here') {
        auditSigningKey = Buffer.from(process.env.AUDIT_SIGNING_KEY);
        console.log('[Config] ✅ AUDIT_SIGNING_KEY loaded from environment');
    }
    else {
        // Auto-generate so server starts — strongly recommended to set this in production
        auditSigningKey = crypto.randomBytes(32);
        if (nodeEnv === 'production') {
            console.warn('[Config] ⚠️  AUDIT_SIGNING_KEY not set in production!');
            console.warn('[Config] ⚠️  Audit log signatures will change on every restart.');
            console.warn('[Config] ⚠️  Set AUDIT_SIGNING_KEY in Railway Variables immediately.');
        }
        else {
            console.warn('[Config] ⚠  Using auto-generated AUDIT_SIGNING_KEY (dev mode)');
        }
    }
    const sendgridApiKey = process.env.SENDGRID_API_KEY;
    if (sendgridApiKey?.startsWith('SG.your_')) {
        // Placeholder value from .env.example
        console.warn('[Config] ⚠ SENDGRID_API_KEY is a placeholder — emails will be mocked');
    }
    const memoryLimit = parseInt(process.env.SANDBOX_MEMORY_LIMIT || '512', 10);
    const timeout = parseInt(process.env.SANDBOX_TIMEOUT || '30', 10);
    const rateLimitWindow = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
    const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);
    const hipaaMode = process.env.HIPAA_MODE === 'true';
    if (errors.length > 0) {
        console.error('❌ Configuration errors:');
        errors.forEach(e => console.error(`   - ${e}`));
        process.exit(1);
    }
    return {
        port,
        nodeEnv,
        postgresUrl,
        auditSigningKey,
        sendgridApiKey: sendgridApiKey?.startsWith('SG.your_') ? undefined : sendgridApiKey,
        sandbox: { memoryLimit, timeout },
        rateLimiting: { windowMs: rateLimitWindow, maxRequests: rateLimitMax },
        hipaaMode,
        allowPublicDemo: process.env.ALLOW_PUBLIC_DEMO === 'true' || nodeEnv === 'development',
        version: '1.0.0'
    };
}
exports.config = loadConfig();
