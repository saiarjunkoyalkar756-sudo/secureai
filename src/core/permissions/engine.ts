import { Permission, PermissionRequest, PermissionType } from './types';

export interface CodeAnalysisResult {
  filesAccessed: string[];
  networksAccessed: string[];
  subprocesses: string[];
  envVarsAccessed: string[];
  suspiciousPatterns: {
    pattern: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    recommendation: string;
  }[];
}

export interface PermissionCheckResult {
  canExecute: boolean;
  blockedBy: Permission[];
  autoApproved: any[];
  requiresApprovalFor: Permission[];
}

interface ExecutionRequest { id: string; userId: string; code: string; language: string; }

// Minimal database interface
interface IDatabase {
  prepare(sql: string): { all(...args: any[]): any[] };
}

export class PermissionEngine {
  private permissionsDb: IDatabase;
  private auditLog: any; // Mock AuditLogger
  private mlAnomalyDetector: any; // Mock ML detector
  private slackClient: any; // Mock Slack client
  private emailClient: any; // Mock Email client

  constructor(db: IDatabase) {
    this.permissionsDb = db;
    // Instantiate mocks...
    this.auditLog = { log: (msg: any) => console.log('Audit:', msg) };
    this.mlAnomalyDetector = { score: async () => 0.1 };
    this.slackClient = { sendMessage: async (id: string, msg: string) => console.log(`[Slack -> ${id}]: ${msg}`) };
    this.emailClient = { send: async (opts: any) => console.log(`[Email -> ${opts.to}]: ${opts.subject}`) };
  }

  /**
   * Pre-flight check: Can this execution proceed?
   */
  async checkPermissions(
    execution: ExecutionRequest,
    userRole: 'admin' | 'executor' | 'approver'
  ): Promise<PermissionCheckResult> {
    const analysis = await this.analyzeCodeStatically(execution.code, execution.language);
    const requiredPermissions = this.inferPermissions(analysis);

    const results = await Promise.all(
      requiredPermissions.map(async (perm) => {
        const allowed = this.permissionsDb.prepare(
          'SELECT * FROM permissions WHERE resource = ? AND type = ? AND action = "allow"'
        ).all(perm.resource, perm.type) as any[];

        if (allowed.length === 0) {
          return {
            permission: perm,
            status: 'needs_approval',
            approvalRequired: true
          };
        }

        const rule = allowed[0];
        if (rule.requiresApproval) {
          return {
            permission: perm,
            status: 'needs_approval',
            approvalRequired: true,
            rule
          };
        }

        return {
          permission: perm,
          status: 'auto_approved',
          approvalRequired: false
        };
      })
    );

    const needsApproval = results.filter(r => r.approvalRequired).map(r => r.permission);
    
    if (needsApproval.length > 0) {
      await this.sendApprovalRequest({
        id: Math.random().toString(36).substring(7),
        executionId: execution.id,
        requestedPermissions: needsApproval,
        requestedBy: execution.userId,
        status: 'pending',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        createdAt: new Date()
      });

      this.auditLog.log({
        type: 'permission_request_sent',
        executionId: execution.id,
        permissionsNeeded: needsApproval.length
      });
    }

    return {
      canExecute: needsApproval.length === 0,
      blockedBy: needsApproval,
      autoApproved: results.filter(r => !r.approvalRequired).map(r => r.permission),
      requiresApprovalFor: needsApproval
    };
  }

  /**
   * Performs static analysis using regex for the MVP
   */
  async analyzeCodeStatically(code: string, language: string): Promise<CodeAnalysisResult> {
    const analysis: CodeAnalysisResult = {
      filesAccessed: [],
      networksAccessed: [],
      subprocesses: [],
      envVarsAccessed: [],
      suspiciousPatterns: []
    };

    // 1. Extract File Paths
    const filePatterns = [
      /open\(['"](.+?)['"]/g,             // Python/JS open
      /read_file\(['"](.+?)['"]/g,        // General
      /fs\.\w+Sync\(['"](.+?)['"]/g,      // Node.js fs
      /cat\s+([^\s;&|<>]+)/g,             // Bash cat
    ];
    this.extractMatches(code, filePatterns, analysis.filesAccessed);

    // 2. Extract Network Domains
    const networkPatterns = [
      /https?:\/\/([a-zA-Z0-9.-]+)/g,     // URLs
      /requests\.\w+\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g, // Python requests
      /fetch\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g,        // JS fetch
      /curl\s+.*?https?:\/\/([a-zA-Z0-9.-]+)/g,         // Bash curl
    ];
    this.extractMatches(code, networkPatterns, analysis.networksAccessed);

    // 3. Extract Subprocesses
    const subprocessPatterns = [
      /os\.system\(['"](.+?)['"]/g,        // Python os.system
      /subprocess\.\w+\(\[(.+?)\]/g,      // Python subprocess
      /exec\(['"](.+?)['"]/g,             // JS/Bash exec
      /child_process\.\w+\(['"](.+?)['"]/g // Node.js child_process
    ];
    this.extractMatches(code, subprocessPatterns, analysis.subprocesses);

    // 4. Extract Env Vars
    const envPatterns = [
      /os\.environ\[['"](.+?)['"]\]/g,    // Python
      /process\.env\.(\w+)/g,             // JS
      /getenv\(['"](.+?)['"]/g,           // General
      /\$(\w+)/g                          // Bash
    ];
    this.extractMatches(code, envPatterns, analysis.envVarsAccessed);

    // 5. Threat Detection
    if (code.includes('rm -rf /')) {
      analysis.suspiciousPatterns.push({
        pattern: 'destructive_command',
        severity: 'critical',
        recommendation: 'Block execution. Code contains recursive deletion of root directory.'
      });
    }

    if (code.match(/chmod\s+777/)) {
      analysis.suspiciousPatterns.push({
        pattern: 'insecure_permissions',
        severity: 'high',
        recommendation: 'Audit required. Code is setting world-writable permissions.'
      });
    }

    const mlScore = await this.mlAnomalyDetector.score(code);
    if (mlScore > 0.7) {
      analysis.suspiciousPatterns.push({
        pattern: 'high_anomaly_score',
        score: mlScore,
        reason: 'Code structure unusual compared to known safe code'
      } as any);
    }

    return analysis;
  }

  private extractMatches(code: string, patterns: RegExp[], target: string[]) {
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        if (match[1] && !target.includes(match[1])) {
          target.push(match[1]);
        }
      }
    }
  }

  /**
   * Converts analysis results to Permission objects
   */
  inferPermissions(analysis: CodeAnalysisResult): Permission[] {
    const permissions: Permission[] = [];

    const now = new Date();
    const createdBy = 'system_analysis';

    analysis.filesAccessed.forEach(file => {
      permissions.push({
        id: `file_${Math.random().toString(36).substring(7)}`,
        type: 'file_read',
        resource: file,
        action: 'audit_only',
        createdAt: now,
        createdBy
      });
    });

    analysis.networksAccessed.forEach(domain => {
      permissions.push({
        id: `net_${Math.random().toString(36).substring(7)}`,
        type: 'network_egress',
        resource: domain,
        action: 'audit_only',
        createdAt: now,
        createdBy
      });
    });

    analysis.subprocesses.forEach(cmd => {
      permissions.push({
        id: `proc_${Math.random().toString(36).substring(7)}`,
        type: 'subprocess_exec',
        resource: cmd,
        action: 'audit_only',
        createdAt: now,
        createdBy
      });
    });

    analysis.envVarsAccessed.forEach(env => {
      permissions.push({
        id: `env_${Math.random().toString(36).substring(7)}`,
        type: 'env_read',
        resource: env,
        action: 'audit_only',
        createdAt: now,
        createdBy
      });
    });

    return permissions;
  }

  private async sendApprovalRequest(request: PermissionRequest) {
    const approvers = await this.getApproversForPermissions(request.requestedPermissions);

    for (const approver of approvers) {
      const channel = approver.preferredChannel || 'email';
      
      const approvalUrl = `https://your-domain.com/approvals/${request.id}`;
      const message = `
        [SecureAI] Approval Required for ${request.requestedBy}
        
        Execution ID: ${request.executionId}
        Requested Permissions:
        ${request.requestedPermissions.map(p => `- ${p.type}: ${p.resource}`).join('\n')}
        
        Approve/Reject: ${approvalUrl}
        Expires: ${request.expiresAt.toISOString()}
      `;

      if (channel === 'slack') {
        await this.slackClient.sendMessage(approver.slackId, message);
      } else {
        await this.emailClient.send({
          to: approver.email,
          subject: `[SecureAI] Execution Approval Needed`,
          body: message
        });
      }
    }
  }

  private async getApproversForPermissions(perms: Permission[]) { 
    return [{ email: 'admin@acme.com', slackId: 'U1234', preferredChannel: 'slack' }]; 
  }
}

