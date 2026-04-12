// Vercel serverless entry point for the SecureAI Express backend.
// Vercel pre-buffers the request body — we must NOT let express.json() try
// to re-read the already-consumed stream. Instead we inject req.body manually.

const { default: app } = require('../dist/src/api/routes');

module.exports = async (req, res) => {
  // Vercel passes the raw body as a Buffer in req.body for POST/PUT/PATCH.
  // express.json() will reject it if the stream is already consumed, so we
  // parse it here and let Express pick it up via the pre-populated req.body.
  if (req.body && Buffer.isBuffer(req.body)) {
    try {
      req.body = JSON.parse(req.body.toString('utf8'));
    } catch {
      req.body = {};
    }
  }
  return app(req, res);
};
