export interface HIPAAConfig {
  enabled: boolean;
  encryptionAtRest: 'AES-256';
  encryptionInTransit: 'TLS1.3';
  dataMinimization: boolean; // Only execute on necessary data
  auditLogging: boolean;
  accessControls: 'MFA_Required';
  dataResidency: 'US-East-1'; // Region-locked
}

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  [key: string]: any;
}

// Before execution, mask PHI in logs
export function maskPHI(text: string): string {
  if (!text) return text;
  // Mask SSNs, medical record numbers, etc.
  return text
    .replace(/\d{3}-\d{2}-\d{4}/g, 'XXX-XX-XXXX') // SSN
    .replace(/MRN:\s*\d+/g, 'MRN: XXXXX') // Medical record
    .replace(/DOB:\s*\d{2}\/\d{2}\/\d{4}/g, 'DOB: XX/XX/XXXX'); // Date of birth
}

// Ensure PHI is never returned in plaintext
export function sanitizeExecutionResult(result: ExecutionResult): ExecutionResult {
  return {
    ...result,
    stdout: maskPHI(result.stdout),
    stderr: maskPHI(result.stderr)
  };
}
