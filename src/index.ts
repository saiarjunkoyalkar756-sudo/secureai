import app from './api/routes';
import { config } from './config';

// Log the PORT Railway assigns — critical for diagnosing proxy routing issues
console.log(`[Startup] PORT env = ${process.env.PORT ?? 'not set'}, binding to ${config.port}`);

const server = app.listen(config.port, '0.0.0.0', () => {

  console.log('');
  console.log('  ╔═══════════════════════════════════════════════╗');
  console.log('  ║     🛡️  SecureAI Platform API v' + config.version + '          ║');
  console.log('  ╠═══════════════════════════════════════════════╣');
  console.log(`  ║  🌐 Server:     http://localhost:${config.port}          ║`);
  console.log(`  ║  🏗️  Environment: ${config.nodeEnv.padEnd(25)}  ║`);
  console.log(`  ║  💾 Database:    ${(config.postgresUrl ? 'PostgreSQL' : 'In-Memory Mock').padEnd(25)}  ║`);
  console.log(`  ║  🏥 HIPAA Mode:  ${(config.hipaaMode ? 'ENABLED' : 'disabled').padEnd(25)}  ║`);
  console.log('  ╠═══════════════════════════════════════════════╣');
  console.log('  ║  Endpoints:                                   ║');
  console.log('  ║   GET  /health                                ║');
  console.log('  ║   POST /v1/execute                            ║');
  console.log('  ║   POST /v1/analyze                            ║');
  console.log('  ║   GET  /v1/approvals/:id                      ║');
  console.log('  ║   POST /v1/approvals/:id/approve              ║');
  console.log('  ║   POST /v1/approvals/:id/reject               ║');
  console.log('  ║   GET  /v1/permissions                        ║');
  console.log('  ║   GET  /v1/audit/integrity                    ║');
  console.log('  ║   GET  /v1/audit/recent                       ║');
  console.log('  ║   GET  /v1/compliance/soc2-report             ║');
  console.log('  ╚═══════════════════════════════════════════════╝');
  console.log('');
});

// --- Graceful Shutdown ---
function shutdown(signal: string) {
  console.log(`\n[Server] ${signal} received. Shutting down gracefully...`);
  server.close(() => {
    console.log('[Server] ✅ All connections closed. Goodbye.');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('[Server] ⚠ Forceful shutdown after timeout.');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Catch unhandled errors
process.on('uncaughtException', (err) => {
  console.error('[Server] ❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason) => {
  console.error('[Server] ❌ Unhandled Rejection:', reason);
});
