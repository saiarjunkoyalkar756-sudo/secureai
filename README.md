# 🛡️ SecureAI: Enterprise-Grade AI Code Execution Platform

SecureAI is a high-security sandbox middleware designed to bridge the gap between untrusted LLM-generated code and sensitive enterprise infrastructure. It provides a robust "Safety Layer" that allows AI agents to execute code with granular permissions, human-in-the-loop approvals, and immutable audit trails.

---

## 🎯 The Problem: "The Execution Gap"
Enterprises want to deploy autonomous AI agents (like software engineers or data analysts), but they fear:
1. **Malicious Code:** AI accidentally (or via prompt injection) deleting production data.
2. **Data Exfiltration:** AI scripts uploading private data to the internet.
3. **Compliance Risks:** Lack of audit trails for HIPAA, SOC2, or PCI-DSS.

**SecureAI solves this by trapping AI code in a "Digital Cage."**

---

## 🏗️ Core Architecture

### 1. Permission Engine (Policy Enforcement)
Analyzes code before execution to identify required capabilities (file access, network egress, etc.).
- **Automatic Blocking:** Blocks high-risk actions based on organization policy.
- **Human-in-the-Loop:** Triggers approval workflows (Slack/Email) for sensitive requests.

### 2. Sandbox Engine (Process Isolation)
Executes code in a multi-layered isolated environment.
- **Containerization:** Runs code inside hardened Docker containers.
- **Syscall Filtering (Seccomp):** Kernel-level restriction of dangerous system calls.
- **Resource Limits:** Strict CPU/RAM caps to prevent "Fork Bomb" or infinite loop attacks.

### 3. Audit Logger (Immutable Forensics)
Maintains a tamper-proof record of every AI action.
- **Cryptographic Hash Chain:** Blockchain-style integrity verification for all logs.
- **Compliance Ready:** Generates automated SOC2 and HIPAA evidence reports.

---

## 🚀 Getting Started

### Installation
```bash
npm install --no-bin-links --ignore-scripts
npm run build
```

### Running the Server
```bash
node dist/src/index.js
```

### Example Usage (The "Request -> Approval" Flow)

**1. AI Agent requests execution:**
```bash
curl -X POST http://localhost:3000/v1/execute \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import pandas as pd; print(pd.read_csv(\"salaries.csv\").mean())",
    "language": "python3.11",
    "permissions": [{"type": "file_read", "resource": "salaries.csv"}]
  }'
```

**2. Admin approves the request:**
```bash
curl -X POST http://localhost:3000/v1/approvals/YOUR_ID/approve
```

**3. Agent retrieves the result:**
```bash
curl http://localhost:3000/v1/approvals/YOUR_ID
```

---

## 🗺️ Roadmap
- [x] Core Architecture & MVP Prototype
- [x] Immutable Audit Logging
- [ ] Production Docker/eBPF Isolation
- [ ] Slack & Microsoft Teams Approval Integration
- [ ] Managed SaaS Dashboard
- [ ] FedRAMP & ISO27001 Certification Framework

## ⚖️ License
Proprietary / Enterprise Startup Draft. 

---
**SecureAI** — *Deploying AI Agents with Confidence.*
