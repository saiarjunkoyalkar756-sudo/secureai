import { config } from '../config';

export interface HIPAAConfig {
  enabled: boolean;
  encryptionAtRest: 'AES-256';
  encryptionInTransit: 'TLS1.3';
  dataMinimization: boolean;
  auditLogging: boolean;
  accessControls: 'MFA_Required';
  dataResidency: 'US-East-1';
}

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  [key: string]: any;
}

/**
 * Check if HIPAA mode is enabled via config.
 */
export function isHIPAAEnabled(): boolean {
  return config.hipaaMode;
}

/**
 * Masks Protected Health Information (PHI) in text strings.
 * Detects and redacts: SSNs, medical record numbers, dates of birth, phone numbers, emails in output.
 */
export function maskPHI(text: string): string {
  if (!text) return text;
  return text
    .replace(/\d{3}-\d{2}-\d{4}/g, 'XXX-XX-XXXX')                     // SSN
    .replace(/MRN:\s*\d+/gi, 'MRN: XXXXX')                            // Medical record number
    .replace(/DOB:\s*\d{2}\/\d{2}\/\d{4}/gi, 'DOB: XX/XX/XXXX')     // Date of birth
    .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, 'XXX-XXX-XXXX')      // Phone numbers
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL REDACTED]') // Emails
    .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX-XXXX'); // Credit cards
}

/**
 * Sanitizes execution results by masking any PHI in stdout/stderr.
 */
export function sanitizeExecutionResult(result: ExecutionResult): ExecutionResult {
  return {
    ...result,
    stdout: maskPHI(result.stdout),
    stderr: maskPHI(result.stderr)
  };
}

/**
 * Express middleware that masks PHI in JSON responses when HIPAA mode is enabled.
 */
export function hipaaMiddleware() {
  return (_req: any, res: any, next: any) => {
    if (!isHIPAAEnabled()) {
      return next();
    }

    const originalJson = res.json.bind(res);
    res.json = (body: any) => {
      if (body && typeof body === 'object') {
        const sanitized = JSON.parse(JSON.stringify(body), (_key, value) => {
          if (typeof value === 'string') {
            return maskPHI(value);
          }
          return value;
        });
        return originalJson(sanitized);
      }
      return originalJson(body);
    };

    next();
  };
}
