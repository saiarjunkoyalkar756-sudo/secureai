import { Request, Response, NextFunction } from 'express';

/**
 * Production-grade in-memory sliding window rate limiter.
 *
 * Keying strategy (priority order):
 *   1. org:<organizationId>  — if the request has already been authenticated
 *                              and req.user is populated (post-auth middleware)
 *   2. key:<apiKeyPrefix>    — if a Bearer token is present but auth hasn't run yet
 *   3. ip:<address>          — unauthenticated fallback
 *
 * Per-org limits ensure that a single org with 10 API keys cannot multiply
 * its quota by 10x. Per-route overrides allow tighter caps on expensive
 * endpoints regardless of org.
 *
 * Headers emitted (IETF draft-ietf-httpapi-ratelimit-headers-07):
 *   RateLimit-Limit       — max requests in window
 *   RateLimit-Remaining   — requests left in current window
 *   RateLimit-Reset       — ISO-8601 timestamp when window resets
 *   RateLimit-Policy      — "{max};w={seconds}"
 *   RateLimit-Scope       — "org" | "key" | "ip"
 *   Retry-After           — seconds to wait on 429
 */

interface RateLimitEntry {
  timestamps: number[];
}

export interface RouteLimit {
  windowMs: number;
  maxRequests: number;
}

/** Extend Express Request to allow downstream auth to inject org context */
interface AugmentedRequest extends Request {
  user?: { organizationId?: string; id?: string };
}

export class RateLimiter {
  private store: Map<string, RateLimitEntry> = new Map();
  private windowMs: number;
  private maxRequests: number;
  private routeLimits: Map<string, RouteLimit> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor(windowMs: number = 60_000, maxRequests: number = 100) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;

    // Cleanup stale entries every 5 minutes — keeps memory bounded
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    if (this.cleanupInterval.unref) this.cleanupInterval.unref();
  }

  /**
   * Register a tighter per-route cap.
   * Chainable: rateLimiter.addRouteLimit(…).addRouteLimit(…)
   */
  addRouteLimit(path: string, limit: RouteLimit): this {
    this.routeLimits.set(path, limit);
    return this;
  }

  middleware() {
    return (req: AugmentedRequest, res: Response, next: NextFunction) => {
      const now = Date.now();

      // --- Determine client key and scope ---
      const { key: clientKey, scope } = this.getClientKey(req);

      // --- Determine which limit applies (route-specific > global) ---
      const routeLimit  = this.routeLimits.get(req.path);
      const windowMs    = routeLimit?.windowMs    ?? this.windowMs;
      const maxRequests = routeLimit?.maxRequests  ?? this.maxRequests;

      // Per-route limits use a compound key so they're isolated from global quota
      const storeKey = routeLimit ? `${clientKey}:${req.path}` : clientKey;

      let entry = this.store.get(storeKey);
      if (!entry) {
        entry = { timestamps: [] };
        this.store.set(storeKey, entry);
      }

      // Slide the window: drop timestamps outside the current window
      const windowStart = now - windowMs;
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);

      const resetAt = entry.timestamps.length > 0
        ? new Date(entry.timestamps[0] + windowMs).toISOString()
        : new Date(now + windowMs).toISOString();

      const remaining = maxRequests - entry.timestamps.length;

      // --- Rate limit exceeded ---
      if (remaining <= 0) {
        const oldestInWindow = entry.timestamps[0];
        const retryAfter = Math.ceil((oldestInWindow + windowMs - now) / 1000);

        res.set('RateLimit-Limit',     String(maxRequests));
        res.set('RateLimit-Remaining', '0');
        res.set('RateLimit-Reset',     resetAt);
        res.set('RateLimit-Policy',    `${maxRequests};w=${windowMs / 1000}`);
        res.set('RateLimit-Scope',     scope);
        res.set('Retry-After',         String(retryAfter));

        // Legacy headers for older clients (nginx, curl, Postman)
        res.set('X-RateLimit-Limit',     String(maxRequests));
        res.set('X-RateLimit-Remaining', '0');
        res.set('X-RateLimit-Reset',     resetAt);

        return res.status(429).json({
          error: 'Too Many Requests',
          message: `Rate limit exceeded. Max ${maxRequests} requests per ${windowMs / 1000}s window.`,
          scope,
          retryAfter,
          resetAt,
        });
      }

      // --- Request allowed — consume a slot ---
      entry.timestamps.push(now);

      // Set rate limit headers on all successful responses
      res.set('RateLimit-Limit',     String(maxRequests));
      res.set('RateLimit-Remaining', String(remaining - 1));
      res.set('RateLimit-Reset',     resetAt);
      res.set('RateLimit-Policy',    `${maxRequests};w=${windowMs / 1000}`);
      res.set('RateLimit-Scope',     scope);

      // Legacy headers
      res.set('X-RateLimit-Limit',     String(maxRequests));
      res.set('X-RateLimit-Remaining', String(remaining - 1));
      res.set('X-RateLimit-Reset',     resetAt);

      next();
    };
  }

  /**
   * Derive a stable client key and human-readable scope.
   *
   * Priority:
   *   1. org:<id>   if req.user has been set by auth middleware
   *   2. key:<pfx>  if a Bearer token is present
   *   3. ip:<addr>  fallback for unauthenticated endpoints
   */
  private getClientKey(req: AugmentedRequest): { key: string; scope: string } {
    // Auth middleware runs BEFORE rate limiting on authenticated routes, so
    // req.user may already be populated.
    const orgId = req.user?.organizationId;
    if (orgId) {
      return { key: `org:${orgId}`, scope: 'org' };
    }

    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      // Use first 16 chars of token as bucket — not the full secret
      const prefix = authHeader.split(' ')[1].substring(0, 16);
      return { key: `key:${prefix}`, scope: 'key' };
    }

    // Normalise IPv6-mapped IPv4 addresses (::ffff:1.2.3.4 → 1.2.3.4)
    const raw = req.ip || req.socket?.remoteAddress || 'unknown';
    const ip  = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
    return { key: `ip:${ip}`, scope: 'ip' };
  }

  private cleanup() {
    const now = Date.now();
    // Use 2× the global window so per-route entries aren't evicted too early
    const maxWindow = Math.max(this.windowMs * 2, ...Array.from(this.routeLimits.values()).map(r => r.windowMs * 2));
    for (const [key, entry] of this.store.entries()) {
      entry.timestamps = entry.timestamps.filter(t => t > now - maxWindow);
      if (entry.timestamps.length === 0) this.store.delete(key);
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }

  /** Expose current store size for monitoring/tests */
  get storeSize(): number {
    return this.store.size;
  }
}
