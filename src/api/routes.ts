import express, { Response } from 'express';
import cors from 'cors';
import { PermissionEngine } from '../core/permissions/engine';
import { SandboxEngine } from '../sandbox/sandbox-engine';
import { PermissionDB } from '../core/permissions/db';
import { validateExecutionRequest } from '../utils/validation';
import { authenticateApiKey, AuthRequest, requireRole } from './auth';
import { EmailService } from '../services/email';
import * as path from 'path';

// --- DATABASE SETUP ---
const dbPath = path.join(__dirname, '../../../../secureai.db');
const db = new PermissionDB(dbPath);

// --- SERVICES ---
const emailService = new EmailService();

// --- UTILS ---
const generateId = () => Math.random().toString(36).substring(7);

const app = express();
app.use(cors());
app.use(express.json());

/**
 * POST /v1/execute
 */
app.post('/v1/execute', authenticateApiKey, async (req: AuthRequest, res: Response) => {
  const validation = validateExecutionRequest(req.body);
  if (!validation.isValid) {
    return res.status(400).json({ error: 'Validation failed', details: validation.errors });
  }

  const { code, language, permissions, requiresApproval } = req.body;
  const executionId = generateId();

  console.log(`[Server] Received execution request ${executionId} from ${req.user!.email}`);

  const permissionEngine = new PermissionEngine(db as any);
  const permissionCheck = await permissionEngine.checkPermissions(
    { code, userId: req.user!.id, id: executionId, language },
    req.user!.role
  );

  if (!permissionCheck.canExecute) {
    const approvalId = generateId();
    console.log(`[Security] Permission denied. Created approval request: ${approvalId}`);
    
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

    // Send email to admin
    await emailService.sendApprovalRequest(approvalReq, 'admin@secureai.io');

    return res.status(202).json({
      status: 'pending_approval',
      approvalId,
      permissions: permissionCheck.requiresApprovalFor,
      pollUrl: `/v1/approvals/${approvalId}`
    });
  }

  // Auto-approved path
  const sandbox = new SandboxEngine();
  const result = await sandbox.execute(code, {
    language,
    timeout: req.body.timeout || 30,
    memory: 512,
    cpuShares: 1,
    networkEnabled: permissionCheck.autoApproved.some(p => p.type === 'network_egress'),
    permissions: permissionCheck.autoApproved
  }, []);

  res.json({ status: 'success', executionId, output: result.stdout, error: result.stderr });
});

/**
 * GET /v1/approvals/:id
 */
app.get('/v1/approvals/:id', authenticateApiKey, (req: AuthRequest, res: Response) => {
  const approval = db.getApprovalRequest(req.params.id);
  if (!approval) return res.status(404).json({ error: 'Not found' });

  // Only the requester or an admin can poll the status
  if (approval.requestedBy !== req.user!.id && req.user!.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  if (approval.status === 'approved') {
    return res.json({ 
      status: 'approved', 
      executionId: approval.executionId,
      // In a real app, we might store result in DB or a cache
      message: 'Execution approved and triggered.' 
    });
  }

  res.json({ status: approval.status });
});

/**
 * POST /v1/approvals/:id/approve
 */
app.post('/v1/approvals/:id/approve', authenticateApiKey, requireRole(['admin', 'approver']), async (req: AuthRequest, res: Response) => {
  const approval = db.getApprovalRequest(req.params.id);
  if (!approval) return res.status(404).json({ error: 'Not found' });

  if (approval.status !== 'pending') {
    return res.status(400).json({ error: `Request is already ${approval.status}` });
  }

  console.log(`[Admin] Granting approval for request: ${req.params.id} by ${req.user!.email}`);

  // Update status in DB
  db.updateApprovalStatus(req.params.id, 'approved', req.user!.id);

  // Notify requester
  const updatedApproval = db.getApprovalRequest(req.params.id);
  if (updatedApproval) {
    // In a real app, we'd fetch the user's email from the DB
    await emailService.notifyExecutionStatus(updatedApproval, 'user@example.com');
  }

  // Trigger execution
  const sandbox = new SandboxEngine();
  const result = await sandbox.execute(approval.code!, {
    language: approval.language as any,
    timeout: 30,
    memory: 512,
    cpuShares: 1,
    networkEnabled: approval.requestedPermissions.some(p => p.type === 'network_egress'),
    permissions: approval.requestedPermissions
  }, []);

  res.json({ 
    status: 'granted', 
    message: 'Execution completed', 
    output: result.stdout, 
    error: result.stderr 
  });
});



export default app;

