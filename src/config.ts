import * as path from 'path';
import * as crypto from 'crypto';

/**
 * SecureAI Configuration Module
 * Single source of truth for all application settings.
 * Validates required environment variables on startup.
 */

export interface AppConfig {
  port: number;
  nodeEnv: string;
  databasePath: string;
  auditSigningKey: Buffer;
  sendgridApiKey: string | undefined;
  sandbox: {
    memoryLimit: number;  // MB
    timeout: number;      // seconds
  };
  rateLimiting: {
    windowMs: number;     // milliseconds
    maxRequests: number;
  };
  hipaaMode: boolean;
  allowPublicDemo: boolean;
  version: string;
}

function loadConfig(): AppConfig {
  const errors: string[] = [];

  const port = parseInt(process.env.PORT || '3000', 10);
  const nodeEnv = process.env.NODE_ENV || 'development';

  // Database path - resolve relative to project root
  const databasePath = path.resolve(
    process.cwd(),
    process.env.DATABASE_PATH || 'secureai.db'
  );

  // Audit signing key - generate a default for dev, require in production
  let auditSigningKey: Buffer;
  if (process.env.AUDIT_SIGNING_KEY && process.env.AUDIT_SIGNING_KEY !== 'your_secure_audit_signing_key_here') {
    auditSigningKey = Buffer.from(process.env.AUDIT_SIGNING_KEY);
  } else if (nodeEnv === 'production') {
    errors.push('AUDIT_SIGNING_KEY is required in production');
    auditSigningKey = Buffer.alloc(0);
  } else {
    auditSigningKey = crypto.randomBytes(32);
    console.warn('[Config] ⚠ Using auto-generated AUDIT_SIGNING_KEY (dev mode only)');
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
    databasePath,
    auditSigningKey,
    sendgridApiKey: sendgridApiKey?.startsWith('SG.your_') ? undefined : sendgridApiKey,
    sandbox: { memoryLimit, timeout },
    rateLimiting: { windowMs: rateLimitWindow, maxRequests: rateLimitMax },
    hipaaMode,
    allowPublicDemo: process.env.ALLOW_PUBLIC_DEMO === 'true' || nodeEnv === 'development',
    version: '1.0.0'
  };
}

export const config = loadConfig();
