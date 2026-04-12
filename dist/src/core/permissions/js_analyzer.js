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
exports.analyzeJavascriptAST = analyzeJavascriptAST;
const acorn = __importStar(require("acorn"));
const DANGEROUS_MODULES = new Set([
    'child_process', 'fs', 'os', 'path', 'crypto', 'cluster',
    'net', 'tls', 'http', 'https', 'dns', 'dgram', 'zlib',
    'v8', 'vm', 'worker_threads', 'repl'
]);
const DANGEROUS_CALLS = new Set([
    'eval', 'setTimeout', 'setInterval', 'Function',
    'exec', 'execSync', 'spawn', 'spawnSync', 'fork',
    'execFile', 'execFileSync'
]);
function analyzeJavascriptAST(code) {
    try {
        const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
        const results = {
            imports: [],
            calls: [],
            attributes: [],
            suspicious: [],
            args: []
        };
        function walk(node) {
            if (!node)
                return;
            // Handle ImportDeclarations (ES Modules)
            if (node.type === 'ImportDeclaration') {
                const source = node.source.value;
                results.imports.push(source);
                if (DANGEROUS_MODULES.has(source) || source.startsWith('node:')) {
                    results.suspicious.push(`Import of dangerous module: ${source}`);
                }
            }
            // Handle CallExpressions
            if (node.type === 'CallExpression') {
                // CommonJS require('...')
                if (node.callee.type === 'Identifier' && node.callee.name === 'require') {
                    if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
                        const source = node.arguments[0].value;
                        results.imports.push(source);
                        if (DANGEROUS_MODULES.has(source) || source.startsWith('node:')) {
                            results.suspicious.push(`Require of dangerous module: ${source}`);
                        }
                    }
                }
                // Direct calls like eval()
                if (node.callee.type === 'Identifier') {
                    const funcName = node.callee.name;
                    results.calls.push(funcName);
                    if (DANGEROUS_CALLS.has(funcName)) {
                        results.suspicious.push(`Dangerous function call: ${funcName}`);
                    }
                    node.arguments.forEach((arg) => {
                        if (arg.type === 'Literal' && typeof arg.value === 'string')
                            results.args.push(arg.value);
                    });
                }
                // Attribute calls like fs.readFileSync()
                if (node.callee.type === 'MemberExpression') {
                    const object = node.callee.object;
                    const property = node.callee.property;
                    if (object.type === 'Identifier' && property.type === 'Identifier') {
                        const funcName = `${object.name}.${property.name}`;
                        results.calls.push(funcName);
                        if (DANGEROUS_CALLS.has(property.name) || DANGEROUS_MODULES.has(object.name)) {
                            results.suspicious.push(`Dangerous attribute call: ${funcName}`);
                        }
                    }
                    node.arguments.forEach((arg) => {
                        if (arg.type === 'Literal' && typeof arg.value === 'string')
                            results.args.push(arg.value);
                    });
                }
            }
            // Handle standard MemberExpressions without calls
            if (node.type === 'MemberExpression') {
                if (node.object.type === 'Identifier' && node.property.type === 'Identifier') {
                    results.attributes.push(`${node.object.name}.${node.property.name}`);
                }
            }
            // Recursive traversal
            for (const key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    walk(node[key]);
                }
            }
        }
        walk(ast);
        return { status: 'success', analysis: results };
    }
    catch (err) {
        return {
            status: 'error',
            message: `Syntax Error: ${err.message}`
        };
    }
}
