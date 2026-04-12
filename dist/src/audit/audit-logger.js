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
const pg_1 = require("pg");
class AuditLogger {
    pool = null;
    signingKey;
    isMock = false;
    mockLog = [];
    constructor(postgresUrl, signingKey) {
        this.signingKey = signingKey;
        if (postgresUrl) {
            try {
                this.pool = new pg_1.Pool({
                    connectionString: postgresUrl,
                    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
                });
                this.initializeSchema();
            }
            catch (err) {
                this.isMock = true;
                console.warn(`[AuditLogger] ⚠ Failed to connect. Falling back to IN-MEMORY MOCK MODE.`);
            }
        }
        else {
            this.isMock = true;
        }
    }
    async initializeSchema() {
        if (this.isMock || !this.pool)
            return;
        try {
            await this.pool.query(`
        CREATE TABLE IF NOT EXISTS audit_log (
          id TEXT PRIMARY KEY,
          timestamp TIMESTAMP,
          executionId TEXT,
          userId TEXT,
          action TEXT,
          resourcesBefore TEXT,
          resourcesAfter TEXT,
          metadata TEXT,
          previousHash TEXT,
          signature TEXT,
          created_serial SERIAL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_log(executionId);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(userId);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
      `);
        }
        catch (err) {
            console.error('[AuditLogger] Failed to initialize schema:', err);
        }
    }
    async log(entry) {
        const lastEntry = await this.getLastEntry();
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
            await this.pool.query(`
        INSERT INTO audit_log (
          id, timestamp, executionId, userId, action, resourcesBefore, resourcesAfter, metadata, previousHash, signature
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
                auditEntry.id, auditEntry.timestamp.toISOString(), auditEntry.executionId, auditEntry.userId, auditEntry.action,
                JSON.stringify(auditEntry.resourcesBefore), JSON.stringify(auditEntry.resourcesAfter), JSON.stringify(auditEntry.metadata),
                previousHash, signature
            ]);
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
    async verifyIntegrity() {
        const entries = this.isMock
            ? this.mockLog
            : (await this.pool.query('SELECT * FROM audit_log ORDER BY created_serial ASC')).rows;
        const tamperedIds = [];
        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i];
            if (i > 0) {
                const prevSignature = entries[i - 1].signature;
                if ((entry.previousHash || entry.previoushash) !== prevSignature)
                    tamperedIds.push(entry.id);
            }
            const hash = this.computeHash(entry);
            const expectedSig = crypto.createHmac('sha256', this.signingKey).update(hash).digest('hex');
            if (entry.signature !== expectedSig)
                tamperedIds.push(entry.id);
        }
        return { valid: tamperedIds.length === 0, tamperedIds };
    }
    async getEntryCount() {
        if (this.isMock)
            return this.mockLog.length;
        const { rows } = await this.pool.query('SELECT COUNT(*) as count FROM audit_log');
        return parseInt(rows[0].count);
    }
    async getRecentEntries(limit = 20) {
        if (this.isMock)
            return this.mockLog.slice(-limit);
        const { rows } = await this.pool.query('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT $1', [limit]);
        return rows;
    }
    computeHash(entry) {
        return crypto.createHash('sha256').update(JSON.stringify({
            timestamp: entry.timestamp instanceof Date ? entry.timestamp.toISOString() : entry.timestamp,
            executionId: entry.executionId || entry.executionid,
            action: entry.action,
            previousHash: entry.previousHash || entry.previoushash
        })).digest('hex');
    }
    async getLastEntry() {
        if (this.isMock)
            return this.mockLog[this.mockLog.length - 1] || null;
        const { rows } = await this.pool.query('SELECT * FROM audit_log ORDER BY created_serial DESC LIMIT 1');
        return rows.length ? rows[0] : null;
    }
}
exports.AuditLogger = AuditLogger;
