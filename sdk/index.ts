import fetch from 'node-fetch';

export interface Permission {
  type: string;
  resource: string;
}

export class SecureAIClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey: string, baseUrl = 'https://api.secureai.io') {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  /**
   * Execute code in secure sandbox
   */
  async execute(options: {
    code: string;
    language: 'python3.11' | 'node20' | 'go1.21' | 'bash';
    permissions?: Permission[];
    timeout?: number;
    requiresApproval?: boolean;
  }) {
    const response = await fetch(`${this.baseUrl}/v1/execute`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(options)
    });

    if (response.status === 202) {
      // Pending approval
      const data = await response.json() as { approvalId: string };
      return this.pollApproval(data.approvalId);
    }

    return response.json();
  }

  /**
   * Poll for execution approval status
   */
  private async pollApproval(approvalId: string, maxRetries = 120) {
    for (let i = 0; i < maxRetries; i++) {
      const response = await fetch(
        `${this.baseUrl}/v1/approvals/${approvalId}`,
        { headers: { 'Authorization': `Bearer ${this.apiKey}` } }
      );

      const data = await response.json() as any;

      if (data.status === 'approved') {
        return data.executionResult;
      }

      if (data.status === 'rejected') {
        throw new Error(`Execution rejected: ${data.reason}`);
      }

      // Wait 5 seconds before next poll
      await new Promise(r => setTimeout(r, 5000));
    }

    throw new Error('Approval timeout');
  }

  /**
   * Analyze code for security threats before execution
   */
  async analyzeCode(code: string, language: string) {
    const response = await fetch(`${this.baseUrl}/v1/analyze`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ code, language })
    });

    return response.json();
  }

  /**
   * Get execution history + audit trail
   */
  async getExecution(executionId: string) {
    const response = await fetch(
      `${this.baseUrl}/v1/executions/${executionId}`,
      { headers: { 'Authorization': `Bearer ${this.apiKey}` } }
    );

    return response.json();
  }
}
