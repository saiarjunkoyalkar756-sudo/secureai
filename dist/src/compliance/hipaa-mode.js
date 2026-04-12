"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isHIPAAEnabled = isHIPAAEnabled;
exports.maskPHI = maskPHI;
exports.sanitizeExecutionResult = sanitizeExecutionResult;
exports.hipaaMiddleware = hipaaMiddleware;
const config_1 = require("../config");
/**
 * Check if HIPAA mode is enabled via config.
 */
function isHIPAAEnabled() {
    return config_1.config.hipaaMode;
}
/**
 * Masks Protected Health Information (PHI) in text strings.
 * Detects and redacts: SSNs, medical record numbers, dates of birth, phone numbers, emails in output.
 */
function maskPHI(text) {
    if (!text)
        return text;
    return text
        .replace(/\d{3}-\d{2}-\d{4}/g, 'XXX-XX-XXXX') // SSN
        .replace(/MRN:\s*\d+/gi, 'MRN: XXXXX') // Medical record number
        .replace(/DOB:\s*\d{2}\/\d{2}\/\d{4}/gi, 'DOB: XX/XX/XXXX') // Date of birth
        .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, 'XXX-XXX-XXXX') // Phone numbers
        .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL REDACTED]') // Emails
        .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX-XXXX'); // Credit cards
}
/**
 * Sanitizes execution results by masking any PHI in stdout/stderr.
 */
function sanitizeExecutionResult(result) {
    return {
        ...result,
        stdout: maskPHI(result.stdout),
        stderr: maskPHI(result.stderr)
    };
}
/**
 * Express middleware that masks PHI in JSON responses when HIPAA mode is enabled.
 */
function hipaaMiddleware() {
    return (_req, res, next) => {
        if (!isHIPAAEnabled()) {
            return next();
        }
        const originalJson = res.json.bind(res);
        res.json = (body) => {
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
