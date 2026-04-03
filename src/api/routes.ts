import express, { Response } from 'express';
import cors from 'cors';
import { PermissionEngine } from '../core/permissions/engine';
import { SandboxEngine } from '../sandbox/sandbox-engine';
import { PermissionDB } from '../core/permissions/db';
import { validateExecutionRequest } from '../utils/validation';
import { authenticateApiKey, AuthRequest, requireRole, authDb } from './auth';
import { EmailService } from '../services/email';
import { AuditLogger } from '../audit/audit-logger';
import { RateLimiter } from '../middleware/rate-limiter';
import { requestLogger } from '../middleware/request-logger';
import { hipaaMiddleware, sanitizeExecutionResult, isHIPAAEnabled } from '../compliance/hipaa-mode';
import { generateSOC2Report } from '../compliance/soc2-controls';
import { config } from '../config';
import * as crypto from 'crypto';

// --- SERVICES ---
const db = authDb;
const emailService = new EmailService();
const auditLogger = new AuditLogger(config.databasePath.replace('.db', '-audit.db'), config.auditSigningKey);
const rateLimiter = new RateLimiter(config.rateLimiting.windowMs, config.rateLimiting.maxRequests);

// --- UTILS ---
const generateId = () => crypto.randomUUID().substring(0, 12);

const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(requestLogger());
app.use(rateLimiter.middleware());
app.use(hipaaMiddleware());

// --- HEALTH CHECK ---
app.get('/health', (_req, res) => {
  const uptime = process.uptime();
  res.json({
    status: 'healthy',
    version: config.version,
    uptime: `${Math.floor(uptime / 60)}m ${Math.floor(uptime % 60)}s`,
    environment: config.nodeEnv,
    database: db.isHealthy() ? 'connected' : 'disconnected',
    stats: db.getStats(),
    audit: { entries: auditLogger.getEntryCount() },
    hipaaMode: isHIPAAEnabled()
  });
});

/**
 * POST /v1/execute
 * Submit code for security analysis and sandboxed execution.
 */
app.post('/v1/execute', authenticateApiKey, async (req: AuthRequest, res: Response) => {
  try {
    const validation = validateExecutionRequest(req.body);
    if (!validation.isValid) {
      return res.status(400).json({ error: 'Validation failed', details: validation.errors });
    }

    const { code, language } = req.body;
    const executionId = generateId();

    console.log(`[Server] 📥 Execution request ${executionId} from ${req.user!.email}`);

    const permissionEngine = new PermissionEngine(db as any);
    const permissionCheck = await permissionEngine.checkPermissions(
      { code, userId: req.user!.id, id: executionId, language },
      req.user!.role
    );

    // Log permission check
    await auditLogger.logPermissionCheck(executionId, req.user!.id, permissionCheck);

    // Critical threat — blocked entirely
    if (permissionCheck.blocked) {
      await auditLogger.logThreatBlocked(executionId, req.user!.id, permissionCheck.analysis.suspiciousPatterns);

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
        status: 'pending' as const,
        requestedBy: req.user!.id,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        code,
        language
      };

      db.createApprovalRequest(approvalReq);
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
    const sandbox = new SandboxEngine();
    const result = await sandbox.execute(code, {
      language,
      timeout: req.body.timeout || config.sandbox.timeout,
      memory: config.sandbox.memoryLimit,
      cpuShares: 1,
      networkEnabled: permissionCheck.autoApproved.some((p: any) => p.type === 'network_egress'),
      permissions: permissionCheck.autoApproved
    }, []);

    // Log execution
    await auditLogger.logExecution(executionId, req.user!.id, code, language, result);

    // Apply HIPAA sanitization if enabled
    const output = isHIPAAEnabled() ? sanitizeExecutionResult(result) : result;

    res.json({
      status: result.status,
      executionId,
      output: output.stdout,
      error: output.stderr,
      executionTime: result.executionTime,
      sandboxType: result.sandboxType,
      riskScore: permissionCheck.analysis.riskScore
    });
  } catch (err) {
    console.error('[Server] ❌ Execution error:', err);
    res.status(500).json({ error: 'Internal server error', details: String(err) });
  }
});

/**
 * GET /v1/approvals/:id
 * Poll the status of a pending approval request.
 */
app.get('/v1/approvals/:id', authenticateApiKey, (req: AuthRequest, res: Response) => {
  try {
    const approval = db.getApprovalRequest(req.params.id);
    if (!approval) return res.status(404).json({ error: 'Not found' });

    if (approval.requestedBy !== req.user!.id && req.user!.role !== 'admin') {
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
  } catch (err) {
    console.error('[Server] ❌ Approval check error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /v1/approvals/:id/approve
 * Grant permission for a pending execution (admin/approver only).
 */
app.post('/v1/approvals/:id/approve', authenticateApiKey, requireRole(['admin', 'approver']), async (req: AuthRequest, res: Response) => {
  try {
    const approval = db.getApprovalRequest(req.params.id);
    if (!approval) return res.status(404).json({ error: 'Not found' });

    if (approval.status !== 'pending') {
      return res.status(400).json({ error: `Request is already ${approval.status}` });
    }

    console.log(`[Admin] ✅ Approval granted: ${req.params.id} by ${req.user!.email}`);

    db.updateApprovalStatus(req.params.id, 'approved', req.user!.id);
    await auditLogger.logApproval(req.params.id, approval.executionId, req.user!.id);

    // Notify requester
    const requester = db.getUserById(approval.requestedBy);
    if (requester) {
      await emailService.notifyExecutionStatus(
        db.getApprovalRequest(req.params.id)!,
        requester.email
      );
    }

    // Trigger execution
    const sandbox = new SandboxEngine();
    const result = await sandbox.execute(approval.code!, {
      language: approval.language as any,
      timeout: config.sandbox.timeout,
      memory: config.sandbox.memoryLimit,
      cpuShares: 1,
      networkEnabled: approval.requestedPermissions.some(p => p.type === 'network_egress'),
      permissions: approval.requestedPermissions
    }, []);

    await auditLogger.logExecution(approval.executionId, approval.requestedBy, approval.code!, approval.language!, result);

    const output = isHIPAAEnabled() ? sanitizeExecutionResult(result) : result;

    res.json({ 
      status: 'granted', 
      message: 'Execution completed', 
      output: output.stdout, 
      error: output.stderr,
      executionTime: result.executionTime,
      sandboxType: result.sandboxType
    });
  } catch (err) {
    console.error('[Server] ❌ Approval error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /v1/approvals/:id/reject
 * Reject a pending execution (admin/approver only).
 */
app.post('/v1/approvals/:id/reject', authenticateApiKey, requireRole(['admin', 'approver']), async (req: AuthRequest, res: Response) => {
  try {
    const approval = db.getApprovalRequest(req.params.id);
    if (!approval) return res.status(404).json({ error: 'Not found' });

    if (approval.status !== 'pending') {
      return res.status(400).json({ error: `Request is already ${approval.status}` });
    }

    const reason = req.body.reason || 'No reason provided';
    console.log(`[Admin] ❌ Rejection for: ${req.params.id} by ${req.user!.email}. Reason: ${reason}`);

    db.updateApprovalStatus(req.params.id, 'rejected', req.user!.id, reason);
    await auditLogger.logRejection(req.params.id, approval.executionId, req.user!.id, reason);

    // Notify requester
    const requester = db.getUserById(approval.requestedBy);
    if (requester) {
      await emailService.notifyExecutionStatus(
        db.getApprovalRequest(req.params.id)!,
        requester.email
      );
    }

    res.json({ 
      status: 'rejected', 
      message: 'Execution request rejected',
      reason 
    });
  } catch (err) {
    console.error('[Server] ❌ Rejection error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/permissions
 * List all configured permissions.
 */
app.get('/v1/permissions', authenticateApiKey, requireRole(['admin']), (_req: AuthRequest, res: Response) => {
  try {
    const permissions = db.getAllPermissions();
    res.json({ permissions, count: permissions.length });
  } catch (err) {
    console.error('[Server] ❌ Permissions list error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/audit/integrity
 * Verify the integrity of the audit log chain.
 */
app.get('/v1/audit/integrity', authenticateApiKey, requireRole(['admin']), (_req: AuthRequest, res: Response) => {
  try {
    const result = auditLogger.verifyIntegrity();
    res.json({
      status: result.valid ? 'verified' : 'tampered',
      totalEntries: auditLogger.getEntryCount(),
      tamperedEntries: result.tamperedIds.length,
      tamperedIds: result.tamperedIds
    });
  } catch (err) {
    console.error('[Server] ❌ Audit integrity error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/audit/recent
 * Get recent audit log entries.
 */
app.get('/v1/audit/recent', authenticateApiKey, requireRole(['admin']), (req: AuthRequest, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 20;
    const entries = auditLogger.getRecentEntries(Math.min(limit, 100));
    res.json({ entries, count: entries.length });
  } catch (err) {
    console.error('[Server] ❌ Audit recent error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/compliance/soc2-report
 * Generate a SOC2 compliance report.
 */
app.get('/v1/compliance/soc2-report', authenticateApiKey, requireRole(['admin']), async (_req: AuthRequest, res: Response) => {
  try {
    const report = await generateSOC2Report([], []);
    res.json({ report });
  } catch (err) {
    console.error('[Server] ❌ SOC2 report error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /v1/analyze
 * Analyze code without executing it.
 */
app.post('/v1/analyze', authenticateApiKey, async (req: AuthRequest, res: Response) => {
  try {
    const { code, language } = req.body;
    if (!code || !language) {
      return res.status(400).json({ error: 'Missing "code" or "language" field' });
    }

    const engine = new PermissionEngine(db as any);
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
  } catch (err) {
    console.error('[Server] ❌ Analysis error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default app;
