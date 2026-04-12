import re

with open('src/core/permissions/engine.ts', 'r', encoding='utf-8') as f:
    code = f.read()

# Add import for JS analyzer
import_str = "import { analyzeJavascriptAST } from './js_analyzer';\nimport { spawnSync } from 'child_process';\nimport * as path from 'path';\n"
code = code.replace("import { Permission", import_str + "import { Permission")

# Rewrite analyzeCodeStatically
analyze_func = """
  async analyzeCodeStatically(code: string, language: string): Promise<CodeAnalysisResult> {
    const analysis: CodeAnalysisResult = {
      filesAccessed: [],
      networksAccessed: [],
      subprocesses: [],
      envVarsAccessed: [],
      suspiciousPatterns: [],
      riskScore: 0
    };

    // --- AST Parsing (Tier 1) ---
    if (language === 'node20') {
      const astResult = analyzeJavascriptAST(code);
      if (astResult.status === 'error') {
         analysis.suspiciousPatterns.push({
           pattern: 'compile_error', severity: 'critical', recommendation: `Syntax error: ${astResult.message}`
         });
      } else if (astResult.analysis) {
         astResult.analysis.suspicious.forEach(s => {
           analysis.suspiciousPatterns.push({ pattern: 'ast_detected', severity: 'high', recommendation: s });
         });
         
         // Route literal AST arguments to permissions
         astResult.analysis.args.forEach(arg => {
           if (arg.startsWith('http')) analysis.networksAccessed.push(arg);
           else if (arg.includes('/')) analysis.filesAccessed.push(arg);
           else if (astResult.analysis!.calls.some(c => c.includes('exec') || c.includes('spawn'))) {
               analysis.subprocesses.push(arg);
           }
         });
      }
    } else if (language === 'python3.11') {
      try {
        const pyAnalyzerPath = path.join(__dirname, 'python_analyzer.py');
        const proc = spawnSync(process.platform === 'win32' ? 'python' : 'python3', [pyAnalyzerPath], { input: code, encoding: 'utf-8' });
        if (proc.status === 0 && proc.stdout) {
           const parsed = JSON.parse(proc.stdout);
           if (parsed.status === 'success' && parsed.analysis) {
               // Map python AST results to engine
               parsed.analysis.suspicious.forEach((s: string) => {
                 analysis.suspiciousPatterns.push({ pattern: 'ast_detected', severity: 'high', recommendation: s });
               });
               parsed.analysis.calls.forEach((cmd: string) => {
                 if (cmd === 'os.system' || cmd.includes('subprocess')) analysis.subprocesses.push(cmd);
               });
           } else if (parsed.status === 'error') {
               analysis.suspiciousPatterns.push({
                 pattern: 'compile_error', severity: 'critical', recommendation: `Syntax error: ${parsed.message}`
               });
           }
        }
      } catch (e) {} // Fallback gracefully if python is not installed locally
    }

    // --- Regex Fallbacks (Tier 2) ---
    // We retain regex to catch obfucated patterns embedded in strings that AST might miscategorize
"""

# We replace the beginning of analyzeCodeStatically up to filePatterns
# We find:
#   async analyzeCodeStatically(code: string, language: string): Promise<CodeAnalysisResult> {
#     const analysis: CodeAnalysisResult = { ... };

old_analyze_start = """  async analyzeCodeStatically(code: string, language: string): Promise<CodeAnalysisResult> {
    const analysis: CodeAnalysisResult = {
      filesAccessed: [],
      networksAccessed: [],
      subprocesses: [],
      envVarsAccessed: [],
      suspiciousPatterns: [],
      riskScore: 0
    };"""

code = code.replace(old_analyze_start, old_analyze_start.replace("    const analysis: CodeAnalysisResult = {", analyze_func.split("    const analysis: CodeAnalysisResult = {")[1]))

with open('src/core/permissions/engine.ts', 'w', encoding='utf-8') as f:
    f.write(code)
