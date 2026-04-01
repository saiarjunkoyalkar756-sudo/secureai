import express, { Request, Response } from 'express';
import { PermissionEngine } from '../core/permissions/engine';
import { SandboxEngine } from '../sandbox/sandbox-engine';

// --- IN-MEMORY MOCK STORE ---
const db = {
  prepare: (sql: string) => ({
    all: (...args: any[]) => [] // Always return empty (trigger approval)
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
app.use(express.json());

/**
 * POST /v1/execute
 * Step 1: Request execution. Returns 202 if approval is needed.
 */
app.post('/v1/execute', authenticate(), async (req: Request, res: Response) => {
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
    
    // Store the request for later execution
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

  // Auto-approved path (not triggered in this mock)
  res.json({ status: 'success', output: 'Auto-approved output' });
});

/**
 * GET /v1/approvals/:id
 * Step 2: Agent polls this to check if admin approved.
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
 * Step 3: Admin calls this to grant permission.
 */
app.post('/v1/approvals/:id/approve', async (req: Request, res: Response) => {
  const approval = pendingApprovals.get(req.params.id);
  if (!approval) return res.status(404).json({ error: 'Not found' });

  console.log(`[Admin] Granting approval for request: ${req.params.id}`);

  // Simulate Sandbox Execution
  const sandbox = new SandboxEngine();
  // In this mock, we skip real Docker call to avoid errors in Termux
  const result = {
    status: 'success',
    stdout: `Successfully executed ${approval.language} code after admin approval!`,
    stderr: '',
    executionTime: 1.2,
    resourcesUsed: { cpu: 0.1, memory: 64, disk: 0 }
  };

  approval.status = 'approved';
  completedExecutions.set(req.params.id, result);

  res.json({ status: 'granted', message: 'Execution completed' });
});

export default app;
