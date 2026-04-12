# Project Rules

## Stack
- **Runtime**: Node.js + TypeScript (strict mode)
- **Framework**: Express.js (`src/api/`)
- **Database**: SQLite via `better-sqlite3` — files: `secureai.db`, `secureai-audit.db`
- **Frontend**: React + Vite (`frontend/`)
- **Testing**: Jest + Supertest (`tests/`)

## Code Rules
- All new backend code goes in `src/` — TypeScript only, no plain `.js`
- All API responses must follow this structure:
  ```json
  { "success": true|false, "data": {}, "error": "message or null" }
  ```
- All routes must go through `src/api/routes.ts` — do not create standalone route files
- Middleware (auth, rate-limit, logging) lives in `src/middleware/`
- All DB access uses `better-sqlite3` synchronous API — no async DB calls
- Security events must be logged via `src/audit/audit-logger.ts`

## Context — Use DB, Not File Scans
- **Do not scan the entire codebase**
- Use `secureai.db` for schema/data context before reading source files
  ```bash
  sqlite3 secureai.db ".tables"
  sqlite3 secureai.db ".schema <table>"
  ```
- Directory map:
  - `src/api/` — routes & controllers
  - `src/core/` — auth, permissions, AST analysis
  - `src/sandbox/` — execution engine
  - `src/audit/` — compliance logging
  - `src/middleware/` — rate limiting, request logging
  - `src/compliance/` — SOC2/HIPAA modules
  - `frontend/src/components/` — UI components

## Ignore Always
- `node_modules/`, `dist/`, `temp_src/`, `*.db-shm`, `*.db-wal`, `package-lock.json`, `.git/`

## Progress Tracking
- Always update `docs/roadmap.md` with completed work and next steps after every implementation
- Log security-relevant changes in `audit_results.txt`

## Before Writing Code
1. Query the DB to confirm schema
2. Ask clarifying questions one by one (multiple choice where possible)
3. Confirm existing structure before creating new files
