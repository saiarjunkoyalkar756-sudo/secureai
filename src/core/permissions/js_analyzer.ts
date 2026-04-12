import * as acorn from 'acorn';

export interface ASTAnalysisResult {
    imports: string[];
    calls: string[];
    attributes: string[];
    suspicious: string[];
    args: string[];
}

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

export function analyzeJavascriptAST(code: string): { status: string; analysis?: ASTAnalysisResult; message?: string } {
    try {
        const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
        
        const results: ASTAnalysisResult = {
            imports: [],
            calls: [],
            attributes: [],
            suspicious: [],
            args: []
        };

        function walk(node: any) {
            if (!node) return;

            // Handle ImportDeclarations (ES Modules)
            if (node.type === 'ImportDeclaration') {
                const source = node.source.value as string;
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
                        const source = node.arguments[0].value as string;
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
                    node.arguments.forEach((arg: any) => {
                        if (arg.type === 'Literal' && typeof arg.value === 'string') results.args.push(arg.value);
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
                    node.arguments.forEach((arg: any) => {
                        if (arg.type === 'Literal' && typeof arg.value === 'string') results.args.push(arg.value);
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

    } catch (err: any) {
         return {
            status: 'error',
            message: `Syntax Error: ${err.message}`
         };
    }
}
