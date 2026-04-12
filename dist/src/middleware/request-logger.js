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
exports.requestLogger = requestLogger;
const crypto = __importStar(require("crypto"));
/**
 * Request logging middleware.
 * Assigns a unique X-Request-Id to each request and logs method, path, status, and timing.
 */
function requestLogger() {
    return (req, res, next) => {
        const requestId = crypto.randomUUID();
        const startTime = Date.now();
        // Attach request ID to headers
        req.headers['x-request-id'] = requestId;
        res.set('X-Request-Id', requestId);
        // Capture the original end method
        const originalEnd = res.end;
        res.end = function (...args) {
            const duration = Date.now() - startTime;
            const statusCode = res.statusCode;
            const statusIcon = statusCode >= 500 ? '🔴' : statusCode >= 400 ? '🟡' : '🟢';
            console.log(`${statusIcon} ${req.method} ${req.path} → ${statusCode} (${duration}ms) [${requestId.substring(0, 8)}]`);
            return originalEnd.apply(this, args);
        };
        next();
    };
}
