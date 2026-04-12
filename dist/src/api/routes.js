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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const engine_1 = require("../core/permissions/engine");
const sandbox_engine_1 = require("../sandbox/sandbox-engine");
const validation_1 = require("../utils/validation");
const auth_1 = require("./auth");
const email_1 = require("../services/email");
const audit_logger_1 = require("../audit/audit-logger");
const rate_limiter_1 = require("../middleware/rate-limiter");
const request_logger_1 = require("../middleware/request-logger");
const hipaa_mode_1 = require("../compliance/hipaa-mode");
const soc2_controls_1 = require("../compliance/soc2-controls");
const config_1 = require("../config");
const crypto = __importStar(require("crypto"));
// --- SERVICES ---
const db = auth_1.authDb;
const emailService = new email_1.EmailService();
const auditLogger = new audit_logger_1.AuditLogger(config_1.config.postgresUrl, config_1.config.auditSigningKey);
const rateLimiter = new rate_limiter_1.RateLimiter(config_1.config.rateLimiting.windowMs, config_1.config.rateLimiting.maxRequests);
// Fine-grained per-route limits (applied per org once auth runs)
rateLimiter
    .addRouteLimit('/v1/execute', { windowMs: 60_000, maxRequests: 20 }) // 20 executions / min / org
    .addRouteLimit('/v1/analyze', { windowMs: 60_000, maxRequests: 30 }) // 30 analyses / min / org
    .addRouteLimit('/v1/auth/login', { windowMs: 60_000, maxRequests: 10 }) // 10 login attempts / min / ip
    .addRouteLimit('/v1/keys', { windowMs: 60_000, maxRequests: 30 }) // 30 key ops / min / org
    .addRouteLimit('/v1/audit-logs', { windowMs: 60_000, maxRequests: 60 }) // 60 log reads / min / org
    .addRouteLimit('/v1/org/stats', { windowMs: 30_000, maxRequests: 30 }) // dashboard polling
    .addRouteLimit('/v1/permissions', { windowMs: 60_000, maxRequests: 30 })
    .addRouteLimit('/v1/audit/recent', { windowMs: 60_000, maxRequests: 30 })
    .addRouteLimit('/v1/audit/integrity', { windowMs: 60_000, maxRequests: 10 }) // expensive chain scan
    .addRouteLimit('/v1/compliance/soc2-report', { windowMs: 300_000, maxRequests: 5 }); // 5 / 5 min — report is heavy
// --- UTILS ---
const generateId = () => crypto.randomUUID().substring(0, 12);
const app = (0, express_1.default)();
// --- MIDDLEWARE ---
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: '1mb' }));
app.use((0, request_logger_1.requestLogger)());
// NOTE: rateLimiter is applied PER-ROUTE after authenticateApiKey so that
// req.user.organizationId is available for org-level keying.
// Unauthenticated endpoints (/health, /v1/auth/login) use the global middleware below.
app.use('/health', rateLimiter.middleware());
app.use('/v1/auth', rateLimiter.middleware());
app.use((0, hipaa_mode_1.hipaaMiddleware)());
// --- HEALTH CHECK ---
app.get('/health', async (_req, res) => {
    const uptime = process.uptime();
    res.json({
        status: 'healthy',
        version: config_1.config.version,
        uptime: `${Math.floor(uptime / 60)}m ${Math.floor(uptime % 60)}s`,
        environment: config_1.config.nodeEnv,
        database: (await db.isHealthy()) ? 'connected' : 'disconnected',
        stats: await db.getStats(),
        audit: { entries: await auditLogger.getEntryCount() },
        hipaaMode: (0, hipaa_mode_1.isHIPAAEnabled)()
    });
});
/**
 * POST /v1/execute
 * Submit code for security analysis and sandboxed execution.
 */
app.post('/v1/execute', auth_1.authenticateApiKey, rateLimiter.middleware(), async (req, res) => {
    try {
        const validation = (0, validation_1.validateExecutionRequest)(req.body);
        if (!validation.isValid) {
            return res.status(400).json({ error: 'Validation failed', details: validation.errors });
        }
        const { code, language } = req.body;
        const executionId = generateId();
        console.log(`[Server] 📥 Execution request ${executionId} from ${req.user.email}`);
        const permissionEngine = new engine_1.PermissionEngine(db);
        const permissionCheck = await permissionEngine.checkPermissions({ code, userId: req.user.id, id: executionId, language }, req.user.role);
        // Log permission check
        await auditLogger.logPermissionCheck(executionId, req.user.id, permissionCheck);
        // Critical threat — blocked entirely
        if (permissionCheck.blocked) {
            await auditLogger.logThreatBlocked(executionId, req.user.id, permissionCheck.analysis.suspiciousPatterns);
            return res.status(403).json({
                status: 'blocked',
                message: 'Code execution blocked due to critical security threats',
                threats: permissionCheck.analysis.suspiciousPatterns.filter(p => p.severity === 'critical'),
                riskScore: permissionCheck.analysis.riskScore
            });
        }
        // Needs approval
        if (!permissionCheck.canExecute) {
            const approvalId = generateId();
            console.log(`[Security] 🔒 Approval required: ${approvalId}`);
            const approvalReq = {
                id: approvalId,
                executionId,
                requestedPermissions: permissionCheck.requiresApprovalFor,
                status: 'pending',
                requestedBy: req.user.id,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                createdAt: new Date(),
                code,
                language,
                riskScore: permissionCheck.analysis.riskScore, // store real score
            };
            await db.createApprovalRequest(approvalReq);
            await emailService.sendApprovalRequest(approvalReq, 'admin@secureai.io');
            return res.status(202).json({
                status: 'pending_approval',
                approvalId,
                permissions: permissionCheck.requiresApprovalFor,
                analysis: {
                    riskScore: permissionCheck.analysis.riskScore,
                    threats: permissionCheck.analysis.suspiciousPatterns
                },
                pollUrl: `/v1/approvals/${approvalId}`
            });
        }
        // Auto-approved — execute
        console.log(`[Server] ✅ Auto-approved. Executing in sandbox...`);
        const sandbox = new sandbox_engine_1.SandboxEngine();
        const result = await sandbox.execute(code, {
            language,
            timeout: req.body.timeout || config_1.config.sandbox.timeout,
            memory: config_1.config.sandbox.memoryLimit,
            cpuShares: 1,
            networkEnabled: permissionCheck.autoApproved.some((p) => p.type === 'network_egress'),
            permissions: permissionCheck.autoApproved
        }, []);
        // Log execution
        await auditLogger.logExecution(executionId, req.user.id, code, language, result);
        // Apply HIPAA sanitization if enabled
        const output = (0, hipaa_mode_1.isHIPAAEnabled)() ? (0, hipaa_mode_1.sanitizeExecutionResult)(result) : result;
        res.json({
            status: result.status,
            executionId,
            output: output.stdout,
            error: output.stderr,
            executionTime: result.executionTime,
            sandboxType: result.sandboxType,
            riskScore: permissionCheck.analysis.riskScore
        });
    }
    catch (err) {
        console.error('[Server] ❌ Execution error:', err);
        res.status(500).json({ error: 'Internal server error', details: String(err) });
    }
});
/**
 * GET /v1/approvals/:id
 * Poll the status of a pending approval request.
 */
app.get('/v1/approvals/:id', auth_1.authenticateApiKey, rateLimiter.middleware(), async (req, res) => {
    try {
        const approval = await db.getApprovalRequest(req.params.id);
        if (!approval)
            return res.status(404).json({ error: 'Not found' });
        if (approval.requestedBy !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        if (approval.status === 'approved') {
            return res.json({
                status: 'approved',
                executionId: approval.executionId,
                message: 'Execution approved and triggered.'
            });
        }
        res.json({ status: approval.status, createdAt: approval.createdAt, expiresAt: approval.expiresAt });
    }
    catch (err) {
        console.error('[Server] ❌ Approval check error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/approvals/:id/approve
 * Grant permission for a pending execution (admin/approver only).
 */
app.post('/v1/approvals/:id/approve', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin', 'approver']), async (req, res) => {
    try {
        const approval = await db.getApprovalRequest(req.params.id);
        if (!approval)
            return res.status(404).json({ error: 'Not found' });
        if (approval.status !== 'pending') {
            return res.status(400).json({ error: `Request is already ${approval.status}` });
        }
        console.log(`[Admin] ✅ Approval granted: ${req.params.id} by ${req.user.email}`);
        await db.updateApprovalStatus(req.params.id, 'approved', req.user.id);
        await auditLogger.logApproval(req.params.id, approval.executionId, req.user.id);
        // Notify requester
        const requester = await db.getUserById(approval.requestedBy);
        if (requester) {
            await emailService.notifyExecutionStatus((await db.getApprovalRequest(req.params.id)), requester.email);
        }
        // Trigger execution
        const sandbox = new sandbox_engine_1.SandboxEngine();
        const result = await sandbox.execute(approval.code, {
            language: approval.language,
            timeout: config_1.config.sandbox.timeout,
            memory: config_1.config.sandbox.memoryLimit,
            cpuShares: 1,
            networkEnabled: approval.requestedPermissions.some(p => p.type === 'network_egress'),
            permissions: approval.requestedPermissions
        }, []);
        await auditLogger.logExecution(approval.executionId, approval.requestedBy, approval.code, approval.language, result);
        const output = (0, hipaa_mode_1.isHIPAAEnabled)() ? (0, hipaa_mode_1.sanitizeExecutionResult)(result) : result;
        res.json({
            status: 'granted',
            message: 'Execution completed',
            output: output.stdout,
            error: output.stderr,
            executionTime: result.executionTime,
            sandboxType: result.sandboxType
        });
    }
    catch (err) {
        console.error('[Server] ❌ Approval error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/approvals/:id/reject
 * Reject a pending execution (admin/approver only).
 */
app.post('/v1/approvals/:id/reject', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin', 'approver']), async (req, res) => {
    try {
        const approval = await db.getApprovalRequest(req.params.id);
        if (!approval)
            return res.status(404).json({ error: 'Not found' });
        if (approval.status !== 'pending') {
            return res.status(400).json({ error: `Request is already ${approval.status}` });
        }
        const reason = req.body.reason || 'No reason provided';
        console.log(`[Admin] ❌ Rejection for: ${req.params.id} by ${req.user.email}. Reason: ${reason}`);
        await db.updateApprovalStatus(req.params.id, 'rejected', req.user.id, reason);
        await auditLogger.logRejection(req.params.id, approval.executionId, req.user.id, reason);
        // Notify requester
        const requester = await db.getUserById(approval.requestedBy);
        if (requester) {
            await emailService.notifyExecutionStatus((await db.getApprovalRequest(req.params.id)), requester.email);
        }
        res.json({
            status: 'rejected',
            message: 'Execution request rejected',
            reason
        });
    }
    catch (err) {
        console.error('[Server] ❌ Rejection error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/permissions
 * List all configured permissions.
 */
app.get('/v1/permissions', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (_req, res) => {
    try {
        const permissions = await db.getAllPermissions();
        res.json({ permissions, count: permissions.length });
    }
    catch (err) {
        console.error('[Server] ❌ Permissions list error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/audit/integrity
 * Verify the integrity of the audit log chain.
 */
app.get('/v1/audit/integrity', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (_req, res) => {
    try {
        const result = await auditLogger.verifyIntegrity();
        res.json({
            status: result.valid ? 'verified' : 'tampered',
            totalEntries: await auditLogger.getEntryCount(),
            tamperedEntries: result.tamperedIds.length,
            tamperedIds: result.tamperedIds
        });
    }
    catch (err) {
        console.error('[Server] ❌ Audit integrity error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/audit/recent
 * Get recent audit log entries.
 */
app.get('/v1/audit/recent', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const entries = await auditLogger.getRecentEntries(Math.min(limit, 100));
        res.json({ entries, count: entries.length });
    }
    catch (err) {
        console.error('[Server] ❌ Audit recent error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/compliance/soc2-report
 * Generate a SOC2 compliance report.
 */
app.get('/v1/compliance/soc2-report', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (_req, res) => {
    try {
        const report = await (0, soc2_controls_1.generateSOC2Report)([], []);
        res.json({ report });
    }
    catch (err) {
        console.error('[Server] ❌ SOC2 report error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/analyze
 * Analyze code without executing it.
 */
app.post('/v1/analyze', auth_1.authenticateApiKey, rateLimiter.middleware(), async (req, res) => {
    try {
        const { code, language } = req.body;
        if (!code || !language) {
            return res.status(400).json({ error: 'Missing "code" or "language" field' });
        }
        const engine = new engine_1.PermissionEngine(db);
        const analysis = await engine.analyzeCodeStatically(code, language);
        res.json({
            riskScore: analysis.riskScore,
            threats: analysis.suspiciousPatterns,
            filesAccessed: analysis.filesAccessed,
            networksAccessed: analysis.networksAccessed,
            subprocesses: analysis.subprocesses,
            envVarsAccessed: analysis.envVarsAccessed,
            recommendation: analysis.riskScore >= 50 ? 'BLOCK' : analysis.riskScore >= 20 ? 'REVIEW' : 'ALLOW'
        });
    }
    catch (err) {
        console.error('[Server] ❌ Analysis error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// ============================================================================
// DASHBOARD API ENDPOINTS
// ============================================================================
/**
 * POST /v1/auth/login
 * Validate an API key and return the user info for the frontend dashboard.
 */
app.post('/v1/auth/login', async (req, res) => {
    try {
        const { apiKey } = req.body;
        if (!apiKey) {
            return res.status(400).json({ error: 'Missing apiKey field' });
        }
        const user = await db.getUserByApiKeyAsync(apiKey);
        if (!user) {
            return res.status(401).json({ error: 'Invalid or revoked API key' });
        }
        // Log the login event
        await auditLogger.log({
            timestamp: new Date(),
            executionId: 'login_' + generateId(),
            userId: user.id,
            action: 'dashboard_login',
            resourcesBefore: {},
            resourcesAfter: { email: user.email, role: user.role },
            metadata: { ip: req.ip || 'unknown' }
        });
        res.json({
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                organizationId: user.organizationId || user.keyOrgId,
            }
        });
    }
    catch (err) {
        console.error('[Server] ❌ Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/approvals
 * List all approval requests (pending by default).
 */
app.get('/v1/approvals', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin', 'approver']), async (req, res) => {
    try {
        const status = req.query.status || undefined;
        const approvals = await db.listApprovalRequests(status);
        // Transform to frontend-friendly format
        const data = approvals.map((a) => ({
            id: a.id,
            codeHash: 'sha256:' + (a.executionId || a.id).substring(0, 8) + '...',
            language: a.language || 'node20',
            submittedBy: a.requestedBy || 'unknown',
            riskScore: a.riskScore ?? 50, // use real stored score
            submittedAt: a.createdAt,
            snippet: a.code ? a.code.substring(0, 80) : '(no preview)',
            status: a.status,
        }));
        res.json({ data, count: data.length });
    }
    catch (err) {
        console.error('[Server] ❌ List approvals error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/approvals/:id/deny
 * Alias for /reject — used by the frontend dashboard.
 */
app.post('/v1/approvals/:id/deny', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin', 'approver']), async (req, res) => {
    try {
        const approval = await db.getApprovalRequest(req.params.id);
        if (!approval)
            return res.status(404).json({ error: 'Not found' });
        if (approval.status !== 'pending') {
            return res.status(400).json({ error: `Request is already ${approval.status}` });
        }
        const reason = req.body.reason || 'Denied via dashboard';
        await db.updateApprovalStatus(req.params.id, 'rejected', req.user.id, reason);
        await auditLogger.logRejection(req.params.id, approval.executionId, req.user.id, reason);
        res.json({ status: 'denied', message: 'Execution request denied', reason });
    }
    catch (err) {
        console.error('[Server] ❌ Deny error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/keys
 * List API keys for the authenticated user's organization.
 */
app.get('/v1/keys', auth_1.authenticateApiKey, rateLimiter.middleware(), async (req, res) => {
    try {
        const keys = await db.getApiKeysByOrg(req.user.organizationId);
        const data = keys.map((k) => ({
            id: k.id,
            name: k.name || k.id,
            prefix: k.keyPrefix,
            createdAt: k.createdAt,
            lastUsed: null,
            status: k.status,
            expiresAt: null,
        }));
        res.json({ data, count: data.length });
    }
    catch (err) {
        console.error('[Server] ❌ List keys error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/keys
 * Create a new API key for the authenticated user.
 */
app.post('/v1/keys', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (req, res) => {
    try {
        const { name, expiresAt } = req.body;
        if (!name)
            return res.status(400).json({ error: 'Missing "name" field' });
        const keyId = 'key_' + generateId();
        const rawKey = 'sk_live_' + crypto.randomUUID().replace(/-/g, '').slice(0, 24);
        // createApiKey is now async (bcrypt hashing)
        await db.createApiKey(keyId, req.user.id, rawKey, req.user.organizationId, { name, expiresAt });
        await auditLogger.log({
            timestamp: new Date(),
            executionId: keyId,
            userId: req.user.id,
            action: 'api_key_created',
            resourcesBefore: {},
            resourcesAfter: { keyPrefix: rawKey.substring(0, 12) },
            metadata: { name, expiresAt: expiresAt || null }
        });
        res.json({
            data: {
                id: keyId,
                name,
                prefix: rawKey.substring(0, 12),
                secret: rawKey, // shown ONCE — never stored in plaintext
                createdAt: new Date().toISOString(),
                lastUsed: null,
                status: 'active',
                expiresAt: expiresAt || null,
            }
        });
    }
    catch (err) {
        console.error('[Server] ❌ Create key error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/keys/:id/revoke
 * Revoke an API key.
 */
app.post('/v1/keys/:id/revoke', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (req, res) => {
    try {
        await db.revokeApiKey(req.params.id);
        await auditLogger.log({
            timestamp: new Date(),
            executionId: req.params.id,
            userId: req.user.id,
            action: 'api_key_revoked',
            resourcesBefore: { status: 'active' },
            resourcesAfter: { status: 'revoked' },
            metadata: {}
        });
        res.json({ status: 'revoked', message: 'API key revoked successfully' });
    }
    catch (err) {
        console.error('[Server] ❌ Revoke key error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/org/stats
 * Get organization overview statistics for the dashboard.
 */
app.get('/v1/org/stats', auth_1.authenticateApiKey, rateLimiter.middleware(), async (req, res) => {
    try {
        const dbStats = await db.getStats();
        const auditCount = await auditLogger.getEntryCount();
        const allEntries = await auditLogger.getRecentEntries(1000); // scan for aggregates
        const executions = allEntries.filter((e) => e.action?.includes('execution') || e.action?.includes('sandboxed')).length;
        const blocked = allEntries.filter((e) => e.action?.includes('blocked') || e.action?.includes('threat')).length;
        const keys = await db.getApiKeysByOrg(req.user.organizationId);
        const activeKeys = keys.filter((k) => k.status === 'active').length;
        const pendingApprovals = await db.listApprovalRequests('pending');
        res.json({
            data: {
                totalExecutions: executions || dbStats.approvalRequests || 0,
                blockedThreats: blocked,
                activeApiKeys: activeKeys || dbStats.apiKeys,
                auditEvents: auditCount,
                executionQuota: 20000,
                executionUsed: executions || dbStats.approvalRequests || 0,
                executionDelta: 0,
                blockedDelta: 0,
                pendingApprovals: pendingApprovals.length,
            }
        });
    }
    catch (err) {
        console.error('[Server] ❌ Org stats error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /v1/audit-logs
 * Alias for /v1/audit/recent — used by the frontend dashboard.
 */
app.get('/v1/audit-logs', auth_1.authenticateApiKey, rateLimiter.middleware(), (0, auth_1.requireRole)(['admin']), async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const entries = await auditLogger.getRecentEntries(Math.min(limit, 100));
        // Transform audit entries to frontend-friendly format
        const data = entries.map((e) => {
            const action = e.action || '';
            let eventType = 'EXECUTION';
            if (action.includes('blocked') || action.includes('threat'))
                eventType = 'BLOCKED';
            else if (action.includes('key_created'))
                eventType = 'KEY_CREATED';
            else if (action.includes('key_revoked'))
                eventType = 'KEY_REVOKED';
            else if (action.includes('login'))
                eventType = 'LOGIN';
            else if (action.includes('rejected') || action.includes('denied'))
                eventType = 'DENIED';
            const metadata = typeof e.metadata === 'string' ? JSON.parse(e.metadata) : (e.metadata || {});
            return {
                id: e.id,
                timestamp: typeof e.timestamp === 'string' ? e.timestamp : e.timestamp?.toISOString?.() || new Date().toISOString(),
                eventType,
                actor: e.userId || 'system',
                resource: e.executionId || 'unknown',
                ip: metadata.ip || '0.0.0.0',
                orgId: req.user.organizationId,
            };
        });
        res.json({ data, count: data.length });
    }
    catch (err) {
        console.error('[Server] ❌ Audit logs error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /v1/setup
 * First-run database seed. Creates an admin user + API key if the DB is empty.
 *
 * Safety rules:
 *   - Refuses if any users already exist (truly one-time)
 *   - Optionally protected by SETUP_TOKEN env var
 *   - Returns the generated API key ONCE — copy it immediately
 */
app.post('/v1/setup', async (req, res) => {
    try {
        // Optional token protection — set SETUP_TOKEN in Railway env vars
        const setupToken = process.env.SETUP_TOKEN;
        if (setupToken && req.headers['x-setup-token'] !== setupToken) {
            return res.status(401).json({ error: 'Invalid or missing X-Setup-Token header' });
        }
        // Refuse if DB already has users — this is a one-time operation
        const stats = await db.getStats();
        if (stats.users > 0) {
            return res.status(409).json({
                error: 'Database already seeded',
                message: `Found ${stats.users} existing user(s). Setup can only run on an empty database.`,
                hint: 'Use the dashboard to create additional users and API keys.'
            });
        }
        const orgId = 'org_' + generateId();
        const userId = 'user_' + generateId();
        const keyId = 'key_' + generateId();
        const rawKey = 'sk_live_' + crypto.randomUUID().replace(/-/g, '').slice(0, 24);
        const email = req.body.email || 'admin@secureai.io';
        // Create org admin user
        await db.createUser({ id: userId, email, organizationId: orgId, role: 'admin' });
        // Create API key (bcrypt-hashed, takes ~100ms)
        await db.createApiKey(keyId, userId, rawKey, orgId, { name: 'Admin Key (Production)' });
        await auditLogger.log({
            timestamp: new Date(),
            executionId: 'setup_' + generateId(),
            userId,
            action: 'initial_setup',
            resourcesBefore: {},
            resourcesAfter: { email, organizationId: orgId },
            metadata: { ip: req.ip || 'unknown', note: 'First-run database seed' }
        });
        console.log(`[Setup] ✅ Production DB seeded. Admin: ${email} | Org: ${orgId}`);
        res.status(201).json({
            success: true,
            message: 'Database seeded. Save your API key — it will not be shown again.',
            credentials: {
                email,
                apiKey: rawKey, // ← copy this immediately
                keyPrefix: rawKey.substring(0, 12),
                organizationId: orgId,
                role: 'admin'
            }
        });
    }
    catch (err) {
        console.error('[Setup] ❌ Seed error:', err);
        res.status(500).json({ error: 'Internal server error during setup', details: String(err) });
    }
});
exports.default = app;
