"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_fetch_1 = __importDefault(require("node-fetch"));
const BASE_URL = 'http://localhost:3000';
/**
 * Simple Admin CLI tool for SecureAI
 */
async function run() {
    const [, , command, id] = process.argv;
    if (!command || !id) {
        console.log('Usage: node dist/src/cli/admin.js <approve|deny> <id>');
        process.exit(1);
    }
    if (command === 'approve') {
        const resp = await (0, node_fetch_1.default)(`${BASE_URL}/v1/approvals/${id}/approve`, { method: 'POST' });
        const data = await resp.json();
        console.log(`[Admin] Approval result:`, data.status === 'granted' ? 'SUCCESS ✅' : 'FAILED ❌');
    }
    else {
        console.log('[Admin] Denial logic not yet implemented in mock.');
    }
}
run().catch(console.error);
