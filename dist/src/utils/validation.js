"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateExecutionRequest = validateExecutionRequest;
/**
 * Validates the execution request payload
 */
function validateExecutionRequest(body) {
    const errors = [];
    if (!body.code || typeof body.code !== 'string') {
        errors.push('Missing or invalid "code" field');
    }
    if (!body.language || !['python3.11', 'node20', 'go1.21', 'bash'].includes(body.language)) {
        errors.push(`Invalid "language": ${body.language}. Supported: python3.11, node20, go1.21, bash`);
    }
    if (body.permissions && !Array.isArray(body.permissions)) {
        errors.push('"permissions" must be an array');
    }
    else if (body.permissions) {
        body.permissions.forEach((p, i) => {
            if (!p.type || !['file_read', 'file_write', 'network_egress', 'subprocess_exec'].includes(p.type)) {
                errors.push(`Permission at index ${i} has invalid type: ${p.type}`);
            }
            if (!p.resource || typeof p.resource !== 'string') {
                errors.push(`Permission at index ${i} is missing a "resource" string`);
            }
        });
    }
    return {
        isValid: errors.length === 0,
        errors
    };
}
