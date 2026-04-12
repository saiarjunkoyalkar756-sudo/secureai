const API_BASE = import.meta.env.VITE_API_URL || 'https://secureai-production-bf5b.up.railway.app';

/** Get the stored API key from localStorage if available */
function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  try {
    const stored = localStorage.getItem('secureai_auth');
    if (stored) {
      const auth = JSON.parse(stored);
      if (auth.apiKey) {
        headers['Authorization'] = `Bearer ${auth.apiKey}`;
      }
    }
  } catch { /* ignore */ }
  return headers;
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<{ data: T }> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...getAuthHeaders(), ...(options?.headers || {}) },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  const json = await res.json();
  return { data: json.data ?? json };
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Approval {
  id: string;
  codeHash: string;
  language: string;
  submittedBy: string;
  riskScore: number;
  submittedAt: string;
  snippet: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  eventType: 'EXECUTION' | 'BLOCKED' | 'KEY_CREATED' | 'KEY_REVOKED' | 'LOGIN' | 'DENIED';
  actor: string;
  resource: string;
  ip: string;
  orgId: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsed: string | null;
  status: 'active' | 'expired' | 'revoked';
  expiresAt: string | null;
}

export interface OrgStats {
  totalExecutions: number;
  blockedThreats: number;
  activeApiKeys: number;
  auditEvents: number;
  executionQuota: number;
  executionUsed: number;
  executionDelta: number;
  blockedDelta: number;
}

export interface ExecResult {
  status: 'success' | 'blocked' | 'error';
  stdout?: string;
  stderr?: string;
  message?: string;
  riskScore?: number;
  executionTime?: number;
  memoryUsed?: number;
}

// ─── API Functions ────────────────────────────────────────────────────────────

export async function getApprovals(): Promise<{ data: Approval[] }> {
  return await apiFetch<Approval[]>('/v1/approvals');
}

export async function approveRequest(id: string): Promise<void> {
  await apiFetch(`/v1/approvals/${id}/approve`, { method: 'POST' });
}

export async function denyRequest(id: string): Promise<void> {
  await apiFetch(`/v1/approvals/${id}/deny`, { method: 'POST' });
}

export async function getAuditLogs(): Promise<{ data: AuditEvent[] }> {
  return await apiFetch<AuditEvent[]>('/v1/audit-logs');
}

export async function getApiKeys(): Promise<{ data: ApiKey[] }> {
  return await apiFetch<ApiKey[]>('/v1/keys');
}

export async function createApiKey(name: string): Promise<{ data: ApiKey & { secret?: string } }> {
  return await apiFetch<ApiKey & { secret?: string }>('/v1/keys', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}

export async function revokeApiKey(id: string): Promise<void> {
  await apiFetch(`/v1/keys/${id}/revoke`, { method: 'POST' });
}

export async function getOrgStats(): Promise<{ data: OrgStats }> {
  return await apiFetch<OrgStats>('/v1/org/stats');
}

export async function executeCode(code: string, language: string): Promise<{ data: ExecResult }> {
  const API_BASE = import.meta.env.VITE_API_URL || 'https://secureai-production-bf5b.up.railway.app';
  const stored = localStorage.getItem('secureai_auth');
  const auth = stored ? JSON.parse(stored) : null;

  const res = await fetch(`${API_BASE}/v1/execute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(auth?.apiKey ? { Authorization: `Bearer ${auth.apiKey}` } : {}),
    },
    body: JSON.stringify({ code, language }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  const json = await res.json();

  // Backend returns { status, output, error, executionTime, riskScore, sandboxType }
  // Normalize to ExecResult shape { stdout, stderr, ... }
  const mapped: ExecResult = {
    status: json.status === 'success' ? 'success' : json.status === 'blocked' ? 'blocked' : 'error',
    stdout: json.output ?? json.stdout,
    stderr: json.error ?? json.stderr,
    message: json.message,
    riskScore: json.riskScore,
    executionTime: json.executionTime,
  };
  return { data: mapped };
}
