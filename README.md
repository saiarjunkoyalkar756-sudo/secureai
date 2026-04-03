SecureAI is a high-security sandbox middleware designed to bridge the gap between untrusted LLM-generated code and sensitive enterprise infrastructure. It provides a robust "Safety Layer" that allows AI agents to execute code with granular permissions, human-in-the-loop approvals, and immutable audit trails.

---

### 🌐 [Live App](https://secureai-platform.vercel.app) | 📡 [API Endpoints](https://secureai-production-bf5b.up.railway.app) | 📚 [Docs](API_SPEC.md)

---

## 🎯 Current Status: v0.1.0-beta
✅ **Core Features Fully Implemented:**
- **Sandbox Engine:** Multi-layered isolation using Docker with resource limits.
- **Permission Engine:** Real-time static code analysis (Regex-based) for Python, JS, and Bash.
- **Persistent Database:** SQLite-backed storage for permissions, requests, and identities.
- **Audit Logger:** Cryptographically signed hash chain for tamper-proof forensics.
- **RBAC Authentication:** API Key + Bearer token authentication with Role-Based Access Control.
- **Email Service:** SendGrid-ready notification system for approval workflows.
- **TypeScript SDK:** Ready-to-use client library for seamless integration.

---

## 🏗️ Core Architecture

### 1. Permission Engine (Policy Enforcement)
Analyzes code before execution to identify required capabilities.
- **Static Analysis:** Detects file access, network egress, subprocesses, and env vars.
- **Threat Detection:** Automatically blocks critical threats (e.g., `rm -rf /`).
- **HITL Approvals:** Triggers human-in-the-loop flows for sensitive requests.

### 2. Sandbox Engine (Process Isolation)
Executes code in a multi-layered isolated environment.
- **Containerization:** Runs code inside hardened Docker containers.
- **Resource Limits:** Strict CPU/RAM caps to prevent resource exhaustion attacks.

### 3. Audit Logger (Immutable Forensics)
Maintains a tamper-proof record of every AI action.
- **Hash Chaining:** Blockchain-style integrity verification for all logs.
- **HMAC Signing:** All entries signed with a secure server-side key.

---

## 🚀 Getting Started

### 1. Installation
```bash
npm install --no-bin-links
npm run build
```

### 2. Configuration
Copy the `.env.example` to `.env` and fill in your keys:
```bash
cp .env.example .env
```

### 3. Setup Test Data
Run the auth test script to create a test user and admin API key:
```bash
npx ts-node test-auth.ts
```

### 4. Running the Server
```bash
node dist/src/index.js
```

### 🧪 Testing
Run the comprehensive test suite (requires Jest setup):
```bash
npm test
```

---

## 📡 API Usage Example

Integrate SecureAI into your AI agent's workflow using a simple REST request:

```javascript
const API_URL = "https://secureai-production-bf5b.up.railway.app/v1/execute";

const response = await fetch(API_URL, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "Bearer sk_test_admin_123456" 
  },
  body: JSON.stringify({
    language: "python",
    code: "print('Hello from SecureAI and my live backend!')"
  })
});

const data = await response.json();
console.log(data);
```

---

## 🗺️ Roadmap
- [x] Core Architecture & MVP Prototype
- [x] Immutable Audit Logging
- [x] Persistent DB & RBAC Authentication
- [x] Real Static Code Analysis
- [ ] Production eBPF Isolation
- [ ] Slack & Microsoft Teams Approval Integration
- [ ] Managed SaaS Dashboard
- [ ] SOC2 / HIPAA Compliance Certification

## ⚖️ License
MIT License. See [LICENSE](LICENSE) for details.

---
**SecureAI** — *Deploying AI Agents with Confidence.*
