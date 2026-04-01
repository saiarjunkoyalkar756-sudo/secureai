import express, { Request, Response } from 'express';
import cors from 'cors';
import { PermissionEngine } from '../core/permissions/engine';
import { SandboxEngine } from '../sandbox/sandbox-engine';
import { validateExecutionRequest } from '../utils/validation';

// --- IN-MEMORY MOCK STORE ---
const db = {
  prepare: (sql: string) => ({
    all: (...args: any[]) => [] 
  })
};

const pendingApprovals = new Map<string, any>();
const completedExecutions = new Map<string, any>();

// --- UTILS ---
const generateId = () => Math.random().toString(36).substring(7);
const authenticate = () => (req: Request, res: Response, next: any) => {
  (req as any).user = { id: 'user_1', role: 'admin' };
  next();
};

const app = express();
app.use(cors()); // Reviewer feedback: Enable CORS for dashboard communication
app.use(express.json());

/**
 * POST /v1/execute
 */
app.post('/v1/execute', authenticate(), async (req: Request, res: Response) => {
  const validation = validateExecutionRequest(req.body);
  if (!validation.isValid) {
    return res.status(400).json({ error: 'Validation failed', details: validation.errors });
  }

  const { code, language, permissions, requiresApproval } = req.body;

  console.log(`[Server] Received execution request for ${language}`);

  const permissionEngine = new PermissionEngine(db);
  const permissionCheck = await permissionEngine.checkPermissions(
    { code, userId: (req as any).user.id, id: generateId() },
    (req as any).user.role
  );

  if (!permissionCheck.canExecute) {
    const approvalId = generateId();
    console.log(`[Security] Permission denied. Created approval request: ${approvalId}`);
    
    pendingApprovals.set(approvalId, { 
      code, language, permissions, status: 'pending' 
    });

    return res.status(202).json({
      status: 'pending_approval',
      approvalId,
      permissions: permissionCheck.blockedBy,
      pollUrl: `/v1/approvals/${approvalId}`
    });
  }

  res.json({ status: 'success', output: 'Auto-approved output' });
});

/**
 * GET /v1/approvals/:id
 */
app.get('/v1/approvals/:id', (req: Request, res: Response) => {
  const approval = pendingApprovals.get(req.params.id);
  if (!approval) return res.status(404).json({ error: 'Not found' });

  if (approval.status === 'approved') {
    return res.json({ 
      status: 'approved', 
      executionResult: completedExecutions.get(req.params.id) 
    });
  }

  res.json({ status: 'pending' });
});

/**
 * POST /v1/approvals/:id/approve
 */
app.post('/v1/approvals/:id/approve', async (req: Request, res: Response) => {
  const approval = pendingApprovals.get(req.params.id);
  if (!approval) return res.status(404).json({ error: 'Not found' });

  console.log(`[Admin] Granting approval for request: ${req.params.id}`);

  const sandbox = new SandboxEngine();
  const result = await sandbox.execute(approval.code, {
    language: approval.language,
    timeout: 30,
    memory: 512,
    cpuShares: 1,
    networkEnabled: approval.permissions?.some((p: any) => p.type === 'network_egress') || false,
    permissions: approval.permissions || []
  }, []);

  approval.status = 'approved';
  completedExecutions.set(req.params.id, result);

  res.json({ status: 'granted', message: 'Execution completed' });
});

export default app;
