"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLogger = void 0;
const crypto = __importStar(require("crypto"));
/**
 * AuditLogger — Immutable, cryptographically-signed audit trail.
 *
 * Features:
 * - Hash chain: Each entry's hash depends on the previous entry
 * - HMAC signing: All entries signed with a server-side key
 * - Integrity verification: Detect tampering in the chain
 * - Convenience methods for common audit events
 */
class AuditLogger {
    db;
    signingKey;
    isMock = false;
    mockLog = [];
    constructor(dbPath, signingKey) {
        this.signingKey = signingKey;
        try {
            const Database = require('better-sqlite3');
            this.db = new Database(dbPath);
            this.initializeSchema();
        }
        catch (err) {
            this.isMock = true;
            console.warn(`[AuditLogger] ⚠ Falling back to IN-MEMORY MOCK MODE.`);
        }
    }
    initializeSchema() {
        if (this.isMock)
            return;
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        executionId TEXT,
        userId TEXT,
        action TEXT,
        resourcesBefore TEXT,
        resourcesAfter TEXT,
        metadata TEXT,
        previousHash TEXT,
        signature TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_log(executionId);
      CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(userId);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    `);
    }
    async log(entry) {
        const lastEntry = this.getLastEntry();
        // Always use the previous entry's SIGNATURE as the chain link (consistent in both mock and real modes)
        const previousHash = lastEntry ? lastEntry.signature : '';
        const auditEntry = {
            ...entry,
            id: crypto.randomUUID(),
            previousHash,
            signature: ''
        };
        const hash = this.computeHash(auditEntry);
        const signature = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
        auditEntry.signature = signature;
        if (this.isMock) {
            this.mockLog.push(auditEntry);
        }
        else {
            this.db.prepare(`INSERT INTO audit_log (id, timestamp, executionId, userId, action, resourcesBefore, resourcesAfter, metadata, previousHash, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(auditEntry.id, auditEntry.timestamp.toISOString(), auditEntry.executionId, auditEntry.userId, auditEntry.action, JSON.stringify(auditEntry.resourcesBefore), JSON.stringify(auditEntry.resourcesAfter), JSON.stringify(auditEntry.metadata), previousHash, signature);
        }
        return auditEntry;
    }
    // --- Convenience Methods ---
    async logExecution(executionId, userId, code, language, result) {
        return this.log({
            timestamp: new Date(),
            executionId,
            userId,
            action: 'code_execution',
            resourcesBefore: { code: code.substring(0, 500), language },
            resourcesAfter: {
                status: result.status,
                exitCode: result.exitCode,
                sandboxType: result.sandboxType,
                outputLength: result.stdout?.length || 0
            },
            metadata: {
                executionTime: result.executionTime,
                resourcesUsed: result.resourcesUsed
            }
        });
    }
    async logPermissionCheck(executionId, userId, result) {
        return this.log({
            timestamp: new Date(),
            executionId,
            userId,
            action: 'permission_check',
            resourcesBefore: {},
            resourcesAfter: {
                canExecute: result.canExecute,
                blockedCount: result.blockedBy?.length || 0,
                autoApprovedCount: result.autoApproved?.length || 0
            },
            metadata: {
                requiresApproval: result.requiresApprovalFor?.map((p) => `${p.type}:${p.resource}`) || []
            }
        });
    }
    async logApproval(approvalId, executionId, approverId) {
        return this.log({
            timestamp: new Date(),
            executionId,
            userId: approverId,
            action: 'approval_granted',
            resourcesBefore: { status: 'pending' },
            resourcesAfter: { status: 'approved' },
            metadata: { approvalId }
        });
    }
    async logRejection(approvalId, executionId, approverId, reason) {
        return this.log({
            timestamp: new Date(),
            executionId,
            userId: approverId,
            action: 'approval_rejected',
            resourcesBefore: { status: 'pending' },
            resourcesAfter: { status: 'rejected' },
            metadata: { approvalId, reason }
        });
    }
    async logThreatBlocked(executionId, userId, threats) {
        return this.log({
            timestamp: new Date(),
            executionId,
            userId,
            action: 'threat_blocked',
            resourcesBefore: {},
            resourcesAfter: { blocked: true, threatCount: threats.length },
            metadata: { threats }
        });
    }
    // --- Integrity Verification ---
    verifyIntegrity() {
        const entries = this.isMock
            ? this.mockLog
            : this.db.prepare('SELECT * FROM audit_log ORDER BY rowid ASC').all();
        const tamperedIds = [];
        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i];
            // 1. Verify the chain link: this entry's previousHash must equal the prior entry's signature
            if (i > 0) {
                const prevSignature = entries[i - 1].signature;
                if (entry.previousHash !== prevSignature)
                    tamperedIds.push(entry.id);
            }
            // 2. Verify the HMAC signature of this entry itself
            const hash = this.computeHash(entry);
            const expectedSig = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
            if (entry.signature !== expectedSig)
                tamperedIds.push(entry.id);
        }
        return { valid: tamperedIds.length === 0, tamperedIds };
    }
    getEntryCount() {
        if (this.isMock)
            return this.mockLog.length;
        return this.db.prepare('SELECT COUNT(*) as count FROM audit_log').get().count;
    }
    getRecentEntries(limit = 20) {
        if (this.isMock)
            return this.mockLog.slice(-limit);
        return this.db.prepare('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?').all(limit);
    }
    computeHash(entry) {
        return crypto.createHash('sha256').update(JSON.stringify({
            timestamp: entry.timestamp instanceof Date ? entry.timestamp.toISOString() : entry.timestamp,
            executionId: entry.executionId,
            action: entry.action,
            previousHash: entry.previousHash
        })).digest('hex');
    }
    getLastEntry() {
        if (this.isMock)
            return this.mockLog[this.mockLog.length - 1] || null;
        // In real mode, return the row directly — we use .signature for chaining now
        return this.db.prepare('SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 1').get() || null;
    }
}
exports.AuditLogger = AuditLogger;
