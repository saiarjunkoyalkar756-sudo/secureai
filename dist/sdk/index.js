"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureAIClient = void 0;
const node_fetch_1 = __importDefault(require("node-fetch"));
class SecureAIClient {
    apiKey;
    baseUrl;
    constructor(apiKey, baseUrl = 'https://api.secureai.io') {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
    }
    /**
     * Execute code in secure sandbox
     */
    async execute(options) {
        const response = await (0, node_fetch_1.default)(`${this.baseUrl}/v1/execute`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(options)
        });
        if (response.status === 202) {
            // Pending approval
            const data = await response.json();
            return this.pollApproval(data.approvalId);
        }
        return response.json();
    }
    /**
     * Poll for execution approval status
     */
    async pollApproval(approvalId, maxRetries = 120) {
        for (let i = 0; i < maxRetries; i++) {
            const response = await (0, node_fetch_1.default)(`${this.baseUrl}/v1/approvals/${approvalId}`, { headers: { 'Authorization': `Bearer ${this.apiKey}` } });
            const data = await response.json();
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
    async analyzeCode(code, language) {
        const response = await (0, node_fetch_1.default)(`${this.baseUrl}/v1/analyze`, {
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
    async getExecution(executionId) {
        const response = await (0, node_fetch_1.default)(`${this.baseUrl}/v1/executions/${executionId}`, { headers: { 'Authorization': `Bearer ${this.apiKey}` } });
        return response.json();
    }
}
exports.SecureAIClient = SecureAIClient;
