"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailService = void 0;
class EmailService {
    apiKey;
    constructor(apiKey) {
        this.apiKey = apiKey || process.env.SENDGRID_API_KEY;
    }
    /**
     * Send an approval request email to an administrator
     */
    async sendApprovalRequest(request, adminEmail) {
        const subject = `[SecureAI] Approval Required: ${request.executionId}`;
        const body = `
      Hi Admin,

      A user has requested to execute code that requires elevated permissions.

      Execution ID: ${request.executionId}
      Requested By: ${request.requestedBy}
      
      Permissions Needed:
      ${request.requestedPermissions.map(p => `- ${p.type}: ${p.resource}`).join('\n')}

      Approve/Reject here: https://your-domain.com/approvals/${request.id}

      Expires at: ${request.expiresAt.toISOString()}
    `;
        return this.send({ to: adminEmail, subject, body });
    }
    /**
     * Notify the requester when their execution is approved/rejected
     */
    async notifyExecutionStatus(request, userEmail) {
        const subject = `[SecureAI] Execution ${request.status.toUpperCase()}: ${request.executionId}`;
        const body = `
      Hi,

      Your execution request has been ${request.status}.
      
      Execution ID: ${request.executionId}
      ${request.reason ? `Reason: ${request.reason}` : ''}

      View Audit Trail: https://your-domain.com/executions/${request.executionId}
    `;
        return this.send({ to: userEmail, subject, body });
    }
    /**
     * Core send method (Mocks SendGrid integration)
     */
    async send(options) {
        console.log(`[EmailService] --- OUTBOUND EMAIL ---`);
        console.log(`To: ${options.to}`);
        console.log(`Subject: ${options.subject}`);
        console.log(`Body: ${options.body.trim()}`);
        console.log(`--------------------------------------`);
        if (!this.apiKey) {
            // Mock success if no API key is provided
            return { status: 'mock_sent', id: Math.random().toString(36).substring(7) };
        }
        // REAL INTEGRATION (Placeholder for @sendgrid/mail)
        /*
        const sgMail = require('@sendgrid/mail');
        sgMail.setApiKey(this.apiKey);
        await sgMail.send({
          to: options.to,
          from: 'alerts@secureai.io',
          subject: options.subject,
          text: options.body,
          html: options.html || options.body.replace(/\n/g, '<br>')
        });
        */
        return { status: 'success' };
    }
}
exports.EmailService = EmailService;
