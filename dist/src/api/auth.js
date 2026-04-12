"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireRole = exports.authenticateApiKey = exports.authDb = void 0;
const db_1 = require("../core/permissions/db");
const config_1 = require("../config");
// Shared database instance
const db = new db_1.PermissionDB(config_1.config.databasePath);
exports.authDb = db;
/**
 * Middleware to authenticate via API Key in Bearer token.
 *
 * Flow:
 *   1. Extract Bearer token from Authorization header.
 *   2. SHA-256 hash for fast DB index lookup (avoids full-table scan).
 *   3. bcrypt.compare() for brute-force-resistant verification (async — non-blocking).
 *   4. Check key status (active) and expiry (expiresAt).
 *   5. Populate req.user for downstream middleware (rate limiter, handlers).
 *
 * Errors always include WWW-Authenticate per RFC 6750 §3.1.
 */
const authenticateApiKey = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        if (config_1.config.allowPublicDemo) {
            req.user = {
                id: 'user_guest',
                email: 'guest@secureai.io',
                organizationId: 'org_public_demo',
                role: 'executor'
            };
            return next();
        }
        res.set('WWW-Authenticate', 'Bearer realm="SecureAI", error="missing_token"');
        res.status(401).json({
            error: 'Unauthorized',
            code: 'MISSING_TOKEN',
            details: 'Provide a valid Bearer token in the Authorization header'
        });
        return;
    }
    const rawKey = authHeader.split(' ')[1];
    try {
        // getUserByApiKey returns null for revoked/non-existent keys,
        // and throws an ExpiredKeyError for valid-but-expired keys.
        const result = await db.getUserByApiKeyAsync(rawKey);
        if (result === 'expired') {
            res.set('WWW-Authenticate', 'Bearer realm="SecureAI", error="invalid_token", error_description="API key has expired"');
            res.status(401).json({
                error: 'Unauthorized',
                code: 'KEY_EXPIRED',
                details: 'This API key has expired. Please create a new key from the dashboard.'
            });
            return;
        }
        if (!result) {
            res.set('WWW-Authenticate', 'Bearer realm="SecureAI", error="invalid_token", error_description="API key is invalid or revoked"');
            res.status(401).json({
                error: 'Unauthorized',
                code: 'INVALID_KEY',
                details: 'The provided API key does not exist or has been revoked.'
            });
            return;
        }
        // Populate req.user — organizationId falls back to userId so the rate
        // limiter never collapses everyone without an org into a single bucket.
        req.user = {
            id: result.id,
            email: result.email,
            organizationId: result.organizationId ?? result.keyOrgId ?? result.id,
            role: result.role
        };
        next();
    }
    catch (err) {
        console.error('[Auth] Database error:', err);
        res.status(500).json({ error: 'Internal server error during authentication' });
    }
};
exports.authenticateApiKey = authenticateApiKey;
/**
 * Middleware to require specific roles
 */
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({
                error: 'Forbidden',
                details: `Access denied. Required roles: ${roles.join(', ')}`
            });
        }
        next();
    };
};
exports.requireRole = requireRole;
