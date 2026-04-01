# 📖 SecureAI API Specification (v1)

This document defines the REST API for the SecureAI Platform.

## 1. Execute Code
Submit code for execution with a specific permission set.

- **Endpoint:** `POST /v1/execute`
- **Auth:** Bearer Token (Mocked)
- **Payload:**
```json
{
  "code": "string",
  "language": "python3.11 | node20 | go1.21 | bash",
  "permissions": [
    { "type": "file_read | network_egress", "resource": "string" }
  ],
  "requiresApproval": true
}
```
- **Responses:**
  - `200 OK`: Auto-approved and executed.
  - `202 Accepted`: Requires human approval (returns `approvalId`).
  - `400 Bad Request`: Validation error (schema mismatch).

## 2. Check Approval Status
Poll the status of a pending execution request.

- **Endpoint:** `GET /v1/approvals/:id`
- **Responses:**
  - `200 OK (status: pending)`: Admin has not yet reviewed.
  - `200 OK (status: approved)`: Includes the `executionResult` (stdout/stderr).

## 3. Approve Request (Admin Only)
Grant permission for a pending request.

- **Endpoint:** `POST /v1/approvals/:id/approve`
- **Responses:**
  - `200 OK`: Triggers the Sandbox Engine and executes code.
