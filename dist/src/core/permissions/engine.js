"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PermissionEngine = void 0;
/**
 * PermissionEngine — Static analysis and permission checking for code execution.
 *
 * Features:
 * - Regex-based static analysis for Python, Node.js, Bash, and Go
 * - Enhanced threat detection (eval, reverse shells, crypto miners, etc.)
 * - Aggregate risk scoring
 * - Critical threat auto-blocking (no approval possible)
 * - Code size limit enforcement
 */
class PermissionEngine {
    permissionsDb;
    static MAX_CODE_SIZE = 100 * 1024; // 100KB
    constructor(db) {
        this.permissionsDb = db;
    }
    /**
     * Pre-flight check: Can this execution proceed?
     */
    async checkPermissions(execution, userRole) {
        // Code size check
        if (execution.code.length > PermissionEngine.MAX_CODE_SIZE) {
            return {
                canExecute: false,
                blockedBy: [],
                autoApproved: [],
                requiresApprovalFor: [],
                analysis: {
                    filesAccessed: [], networksAccessed: [], subprocesses: [],
                    envVarsAccessed: [], suspiciousPatterns: [{
                            pattern: 'code_size_exceeded',
                            severity: 'high',
                            recommendation: `Code exceeds maximum size of ${PermissionEngine.MAX_CODE_SIZE / 1024}KB`
                        }],
                    riskScore: 80
                },
                blocked: true
            };
        }
        const analysis = await this.analyzeCodeStatically(execution.code, execution.language);
        // Block critical threats immediately
        const criticalThreats = analysis.suspiciousPatterns.filter(p => p.severity === 'critical');
        if (criticalThreats.length > 0) {
            return {
                canExecute: false,
                blockedBy: [],
                autoApproved: [],
                requiresApprovalFor: [],
                analysis,
                blocked: true
            };
        }
        const requiredPermissions = this.inferPermissions(analysis);
        const results = await Promise.all(requiredPermissions.map(async (perm) => {
            try {
                const allowed = this.permissionsDb.prepare(`SELECT * FROM permissions WHERE resource = ? AND type = ? AND action = 'allow'`).all(perm.resource, perm.type);
                if (allowed.length === 0) {
                    return {
                        permission: perm,
                        status: 'needs_approval',
                        approvalRequired: true
                    };
                }
                const rule = allowed[0];
                if (rule.requiresApproval) {
                    return {
                        permission: perm,
                        status: 'needs_approval',
                        approvalRequired: true,
                        rule
                    };
                }
                return {
                    permission: perm,
                    status: 'auto_approved',
                    approvalRequired: false
                };
            }
            catch {
                // DB query failed, default to requiring approval
                return {
                    permission: perm,
                    status: 'needs_approval',
                    approvalRequired: true
                };
            }
        }));
        const needsApproval = results.filter(r => r.approvalRequired).map(r => r.permission);
        return {
            canExecute: needsApproval.length === 0,
            blockedBy: needsApproval,
            autoApproved: results.filter(r => !r.approvalRequired).map(r => r.permission),
            requiresApprovalFor: needsApproval,
            analysis,
            blocked: false
        };
    }
    /**
     * Performs static analysis using regex patterns for multiple languages.
     */
    async analyzeCodeStatically(code, language) {
        const analysis = {
            filesAccessed: [],
            networksAccessed: [],
            subprocesses: [],
            envVarsAccessed: [],
            suspiciousPatterns: [],
            riskScore: 0
        };
        // 1. Extract File Paths
        const filePatterns = [
            /open\(['"](.+?)['"]/g, // Python/JS open
            /read_file\(['"](.+?)['"]/g, // General
            /fs\.\w+Sync\(['"](.+?)['"]/g, // Node.js fs sync
            /fs\.\w+\(['"](.+?)['"]/g, // Node.js fs async
            /readFileSync\(['"](.+?)['"]/g, // Node.js readFileSync
            /writeFileSync\(['"](.+?)['"]/g, // Node.js writeFileSync
            /cat\s+([^\s;&|<>]+)/g, // Bash cat
            /os\.Open\(['"](.+?)['"]/g, // Go file open
        ];
        this.extractMatches(code, filePatterns, analysis.filesAccessed);
        // 2. Extract Network Domains
        const networkPatterns = [
            /https?:\/\/([a-zA-Z0-9.-]+)/g, // URLs
            /requests\.\w+\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g, // Python requests
            /fetch\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g, // JS fetch
            /curl\s+.*?https?:\/\/([a-zA-Z0-9.-]+)/g, // Bash curl
            /axios\.\w+\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g, // Axios
            /http\.Get\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g, // Go http
            /urllib\.request\.urlopen\(['"]https?:\/\/([a-zA-Z0-9.-]+)/g, // Python urllib
            /socket\.connect\(\(['"]([a-zA-Z0-9.-]+)['"]/g, // Python socket
        ];
        this.extractMatches(code, networkPatterns, analysis.networksAccessed);
        // 3. Extract Subprocesses
        const subprocessPatterns = [
            /os\.system\(['"](.+?)['"]/g, // Python os.system
            /subprocess\.\w+\(\[(.+?)\]/g, // Python subprocess
            /exec\(['"](.+?)['"]/g, // JS/Bash exec
            /child_process\.\w+\(['"](.+?)['"]/g, // Node.js child_process
            /execSync\(['"](.+?)['"]/g, // Node.js execSync
            /spawnSync\(['"](.+?)['"]/g, // Node.js spawnSync
            /Popen\(\[(.+?)\]/g, // Python Popen
        ];
        this.extractMatches(code, subprocessPatterns, analysis.subprocesses);
        // 4. Extract Env Vars
        const envPatterns = [
            /os\.environ\[['"](.+?)['"]\]/g, // Python
            /os\.getenv\(['"](.+?)['"]\)/g, // Python getenv
            /process\.env\.(\w+)/g, // JS
            /getenv\(['"](.+?)['"]/g, // General
            /\$\{?(\w+)\}?/g // Bash (but filter common ones)
        ];
        this.extractMatches(code, envPatterns, analysis.envVarsAccessed);
        // 5. Enhanced Threat Detection
        this.detectThreats(code, language, analysis);
        // 6. Calculate aggregate risk score
        analysis.riskScore = this.calculateRiskScore(analysis);
        return analysis;
    }
    /**
     * Enhanced threat detection with categorized patterns.
     */
    detectThreats(code, language, analysis) {
        const threats = [
            // CRITICAL — Auto-block, no approval possible
            {
                pattern: /rm\s+-rf\s+\//,
                name: 'destructive_command',
                severity: 'critical',
                recommendation: 'Block execution. Code contains recursive deletion of root directory.'
            },
            {
                pattern: /mkfs\./,
                name: 'disk_format',
                severity: 'critical',
                recommendation: 'Block execution. Code attempts to format a disk.'
            },
            {
                pattern: /dd\s+if=.*of=\/dev\//,
                name: 'disk_overwrite',
                severity: 'critical',
                recommendation: 'Block execution. Code attempts to overwrite a disk device.'
            },
            {
                pattern: /:(){ :|:& };:/,
                name: 'fork_bomb',
                severity: 'critical',
                recommendation: 'Block execution. Code contains a fork bomb.'
            },
            {
                pattern: /\/dev\/(tcp|udp)\//,
                name: 'reverse_shell',
                severity: 'critical',
                recommendation: 'Block execution. Code appears to open a reverse shell.'
            },
            {
                pattern: /bash\s+-i\s+>&\s*\/dev\/(tcp|udp)/,
                name: 'reverse_shell_bash',
                severity: 'critical',
                recommendation: 'Block execution. Code contains a bash reverse shell.'
            },
            {
                pattern: /nc\s+-[ev]/,
                name: 'netcat_shell',
                severity: 'critical',
                recommendation: 'Block execution. Netcat being used to establish a backdoor.'
            },
            // HIGH — Requires approval
            {
                pattern: /chmod\s+777/,
                name: 'insecure_permissions',
                severity: 'high',
                recommendation: 'Audit required. Code is setting world-writable permissions.'
            },
            {
                pattern: /eval\s*\(/,
                name: 'dynamic_code_execution',
                severity: 'high',
                recommendation: 'Audit required. Dynamic code execution via eval() detected.'
            },
            {
                pattern: /exec\s*\(/,
                name: 'dynamic_exec',
                severity: 'high',
                recommendation: 'Audit required. Dynamic execution detected.'
            },
            {
                pattern: /base64.*decode|atob\s*\(/,
                name: 'base64_decode',
                severity: 'high',
                recommendation: 'Audit required. Base64 decoding may be used to obfuscate malicious code.'
            },
            {
                pattern: /stratum\+tcp|cryptonight|xmrig|minerd/i,
                name: 'crypto_miner',
                severity: 'high',
                recommendation: 'Block execution. Code appears to be a cryptocurrency miner.'
            },
            {
                pattern: /keylog|keystroke|keyboard.*listen/i,
                name: 'keylogger',
                severity: 'high',
                recommendation: 'Block execution. Code appears to implement keylogging.'
            },
            // MEDIUM — Warning
            {
                pattern: /chmod\s+[0-7]+/,
                name: 'permission_change',
                severity: 'medium',
                recommendation: 'Review: Code modifies file permissions.'
            },
            {
                pattern: /sudo\s/,
                name: 'privilege_escalation',
                severity: 'medium',
                recommendation: 'Review: Code attempts to use sudo for privilege escalation.'
            },
            {
                pattern: /\.ssh\//,
                name: 'ssh_access',
                severity: 'medium',
                recommendation: 'Review: Code accesses SSH configuration or keys.'
            },
            {
                pattern: /\/etc\/(passwd|shadow|hosts)/,
                name: 'sensitive_file_access',
                severity: 'medium',
                recommendation: 'Review: Code accesses sensitive system files.'
            },
            {
                pattern: /AWS_SECRET|PRIVATE_KEY|API_KEY|PASSWORD|TOKEN/i,
                name: 'credential_access',
                severity: 'medium',
                recommendation: 'Review: Code may access or exfiltrate credentials.'
            },
            // LOW — Informational
            {
                pattern: /import\s+os|require\(['"]os['"]\)/,
                name: 'os_module',
                severity: 'low',
                recommendation: 'Note: Code imports OS module for system interaction.'
            },
        ];
        for (const threat of threats) {
            const regex = typeof threat.pattern === 'string' ? new RegExp(threat.pattern) : threat.pattern;
            if (regex.test(code)) {
                analysis.suspiciousPatterns.push({
                    pattern: threat.name,
                    severity: threat.severity,
                    recommendation: threat.recommendation
                });
            }
        }
    }
    /**
     * Calculates an aggregate risk score from 0-100 based on detected patterns.
     */
    calculateRiskScore(analysis) {
        let score = 0;
        const severityWeights = { critical: 50, high: 20, medium: 10, low: 2 };
        for (const pattern of analysis.suspiciousPatterns) {
            score += severityWeights[pattern.severity] || 0;
        }
        // Resource access adds to risk
        score += analysis.filesAccessed.length * 5;
        score += analysis.networksAccessed.length * 8;
        score += analysis.subprocesses.length * 10;
        score += analysis.envVarsAccessed.length * 3;
        return Math.min(100, score);
    }
    extractMatches(code, patterns, target) {
        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(code)) !== null) {
                if (match[1] && !target.includes(match[1])) {
                    target.push(match[1]);
                }
            }
        }
    }
    /**
     * Converts analysis results to Permission objects
     */
    inferPermissions(analysis) {
        const permissions = [];
        const now = new Date();
        const createdBy = 'system_analysis';
        analysis.filesAccessed.forEach(file => {
            permissions.push({
                id: `file_${Math.random().toString(36).substring(7)}`,
                type: 'file_read',
                resource: file,
                action: 'audit_only',
                createdAt: now,
                createdBy
            });
        });
        analysis.networksAccessed.forEach(domain => {
            permissions.push({
                id: `net_${Math.random().toString(36).substring(7)}`,
                type: 'network_egress',
                resource: domain,
                action: 'audit_only',
                createdAt: now,
                createdBy
            });
        });
        analysis.subprocesses.forEach(cmd => {
            permissions.push({
                id: `proc_${Math.random().toString(36).substring(7)}`,
                type: 'subprocess_exec',
                resource: cmd,
                action: 'audit_only',
                createdAt: now,
                createdBy
            });
        });
        analysis.envVarsAccessed.forEach(env => {
            permissions.push({
                id: `env_${Math.random().toString(36).substring(7)}`,
                type: 'env_read',
                resource: env,
                action: 'audit_only',
                createdAt: now,
                createdBy
            });
        });
        return permissions;
    }
}
exports.PermissionEngine = PermissionEngine;
