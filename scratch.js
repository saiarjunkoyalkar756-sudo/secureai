const fs = require('fs');
let code = fs.readFileSync('src/api/routes.ts', 'utf-8');

// Fix specific route async signatures
code = code.replace("app.get('/v1/approvals/:id', authenticateApiKey, rateLimiter.middleware(), (req: AuthRequest, res: Response) => {", "app.get('/v1/approvals/:id', authenticateApiKey, rateLimiter.middleware(), async (req: AuthRequest, res: Response) => {");

code = code.replace("app.get('/v1/keys', authenticateApiKey, rateLimiter.middleware(), (req: AuthRequest, res: Response) => {", "app.get('/v1/keys', authenticateApiKey, rateLimiter.middleware(), async (req: AuthRequest, res: Response) => {");

code = code.replace("app.post('/v1/keys/:id/revoke', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), (req: AuthRequest, res: Response) => {", "app.post('/v1/keys/:id/revoke', authenticateApiKey, rateLimiter.middleware(), requireRole(['admin']), async (req: AuthRequest, res: Response) => {");

code = code.replace("app.get('/v1/org/stats', authenticateApiKey, rateLimiter.middleware(), (req: AuthRequest, res: Response) => {", "app.get('/v1/org/stats', authenticateApiKey, rateLimiter.middleware(), async (req: AuthRequest, res: Response) => {");

// Fix db.getUserByApiKey => await db.getUserByApiKeyAsync
code = code.replace("const user = await db.getUserByApiKey(apiKey);", "const user = await db.getUserByApiKeyAsync(apiKey);");
code = code.replace("const user = db.getUserByApiKey(apiKey);", "const user = await db.getUserByApiKeyAsync(apiKey);");

fs.writeFileSync('src/api/routes.ts', code);
