# 📖 SecureAI Usage Guide

This guide provides everything you need to interact with the SecureAI API, including authentication, execution requests, and administrative approvals.

---

## 🔑 1. Authentication

SecureAI uses **API Keys** via the `Authorization` header.

*   **Header Format:** `Authorization: Bearer <YOUR_API_KEY>`
*   **Test API Key:** `sk_test_123456789` (Created via `test-auth.ts`)

---

## 📡 2. API Endpoints

### **A. Execute Code**
Submit code for security analysis and isolated execution.

*   **Endpoint:** `POST /v1/execute`
*   **Body:**
    ```json
    {
      "code": "print('hello world')",
      "language": "python3.11",
      "timeout": 30
    }
    ```
*   **Languages Supported:** `python3.11`, `node20`, `go1.21`, `bash`
*   **Behaviors:**
    *   **Safe Code:** Returns `200 OK` with the execution output.
    *   **Risky Code:** Returns `202 Accepted` with an `approvalId`.

### **B. Check Approval Status**
Poll the status of a request that was flagged for review.

*   **Endpoint:** `GET /v1/approvals/:id`
*   **Response:**
    *   `{"status": "pending"}`: Admin has not reviewed yet.
    *   `{"status": "approved", "executionId": "..."}`: Ready/Executed.

### **C. Admin: Approve Request**
Grant permission for a pending execution (Requires `admin` or `approver` role).

*   **Endpoint:** `POST /v1/approvals/:id/approve`
*   **Behavior:** Triggers the Sandbox Engine and returns the code output.

---

## 💻 3. Practical Examples (`curl`)

### **Example 1: Basic Python Execution**
```bash
curl -X POST http://localhost:3000/v1/execute \
  -H "Authorization: Bearer sk_test_123456789" \
  -H "Content-Type: application/json" \
  -d '{"code": "print(2 + 2)", "language": "python3.11"}'
```

### **Example 2: Triggering the Approval Flow**
Code that tries to read `/etc/passwd` will be automatically blocked and queued for approval.
```bash
curl -X POST http://localhost:3000/v1/execute \
  -H "Authorization: Bearer sk_test_123456789" \
  -H "Content-Type: application/json" \
  -d '{"code": "open(\"/etc/passwd\").read()", "language": "python3.11"}'
```

---

## 📦 4. SDK Usage

Integrate SecureAI into your own TypeScript/JavaScript projects.

```typescript
import { SecureAIClient } from './sdk/index';

const client = new SecureAIClient('sk_test_123456789', 'http://localhost:3000');

async function runCode() {
  try {
    const result = await client.execute({
      code: 'print("Secure Execution")',
      language: 'python3.11'
    });
    console.log('Output:', result.output);
  } catch (err) {
    console.error('Security Block:', err.message);
  }
}
```

---

## 🛡️ 5. Security Features

1.  **Static Analysis:** Every request is scanned for `rm -rf`, `chmod 777`, and data exfiltration patterns.
2.  **Immutable Audit Log:** Every action creates a cryptographically signed entry in a hash chain.
3.  **Sandbox Isolation:** Code runs in Docker containers with limited CPU, RAM, and no network access by default.

---
**SecureAI** — *Deploying AI Agents with Confidence.*
