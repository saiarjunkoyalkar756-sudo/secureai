const fs = require('fs');
let code = fs.readFileSync('src/api/routes.ts', 'utf-8');

// Update auditLogger constructor
code = code.replace("const auditLogger = new AuditLogger(config.databasePath.replace('.db', '-audit.db'), config.auditSigningKey);", "const auditLogger = new AuditLogger(config.postgresUrl, config.auditSigningKey);");

// Await auditLogger usages
code = code.replace(/auditLogger\.verifyIntegrity\(\)/g, "await auditLogger.verifyIntegrity()");
code = code.replace(/auditLogger\.getEntryCount\(\)/g, "await auditLogger.getEntryCount()");
code = code.replace(/auditLogger\.getRecentEntries\(/g, "await auditLogger.getRecentEntries(");
code = code.replace(/(?<!await )auditLogger\.log\(/g, "await auditLogger.log(");

// Make health endpoint properly async for the new auditLogger methods
code = code.replace(/audit: \{ entries: await auditLogger\.getEntryCount\(\) \},/g, "audit: { entries: await auditLogger.getEntryCount() },");

// Fix db.getUserByApiKey
code = code.replace(/const user = db\.getUserByApiKey\(apiKey\);/g, "const user = await db.getUserByApiKeyAsync(apiKey);");
code = code.replace(/const user = await db\.getUserByApiKey\(apiKey\);/g, "const user = await db.getUserByApiKeyAsync(apiKey);");

// Fix remaining missing asyncs using literal replace
code = code.replace("app.get('/v1/audit/integrity', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), (_req: AuthRequest, res: Response) => {", "app.get('/v1/audit/integrity', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), async (_req: AuthRequest, res: Response) => {");

code = code.replace("app.get('/v1/audit/recent', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), (req: AuthRequest, res: Response) => {", "app.get('/v1/audit/recent', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), async (req: AuthRequest, res: Response) => {");

code = code.replace("app.get('/v1/audit-logs', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), (req: AuthRequest, res: Response) => {", "app.get('/v1/audit-logs', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), async (req: AuthRequest, res: Response) => {");

code = code.replace("app.post('/v1/auth/login', (req: AuthRequest, res: Response) => {", "app.post('/v1/auth/login', async (req: AuthRequest, res: Response) => {");

code = code.replace("app.post('/v1/setup', async (req: AuthRequest, res: Response) => {", "app.post('/v1/setup', async (req: AuthRequest, res: Response) => {"); // already async

// Fix the typescript error line 220, 277 (Argument of type 'PermissionRequest | null' is not assignable...)
code = code.replace("db.getApprovalRequest(req.params.id)!,", "(await db.getApprovalRequest(req.params.id))!,");

fs.writeFileSync('src/api/routes.ts', code);
