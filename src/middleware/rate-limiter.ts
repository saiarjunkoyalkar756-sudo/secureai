import { Request, Response, NextFunction } from 'express';

/**
 * In-memory sliding window rate limiter.
 * Tracks request timestamps per client key and enforces a max request count per window.
 *
 * Supports per-route limit overrides via routeLimits map.
 * Client key is: API key prefix (if Bearer token present) → IP address fallback.
 */

interface RateLimitEntry {
  timestamps: number[];
}

export interface RouteLimit {
  windowMs: number;
  maxRequests: number;
}

export class RateLimiter {
  private store: Map<string, RateLimitEntry> = new Map();
  private windowMs: number;
  private maxRequests: number;
  private routeLimits: Map<string, RouteLimit> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor(windowMs: number = 60000, maxRequests: number = 100) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;

    // Cleanup stale entries every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  /**
   * Register a tighter limit for a specific route path.
   * Example: rateLimiter.addRouteLimit('/v1/execute', { windowMs: 60000, maxRequests: 20 })
   */
  addRouteLimit(path: string, limit: RouteLimit): this {
    this.routeLimits.set(path, limit);
    return this;
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const key = this.getClientKey(req);
      const routeKey = `${key}:${req.path}`;
      const now = Date.now();

      // Determine which limits apply: route-specific > global
      const routeLimit = this.routeLimits.get(req.path);
      const windowMs    = routeLimit?.windowMs    ?? this.windowMs;
      const maxRequests = routeLimit?.maxRequests  ?? this.maxRequests;

      // Use per-route store key so route limits don't consume global quota
      const storeKey = routeLimit ? routeKey : key;

      let entry = this.store.get(storeKey);
      if (!entry) {
        entry = { timestamps: [] };
        this.store.set(storeKey, entry);
      }

      // Slide the window
      const windowStart = now - windowMs;
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);

      const resetAt = entry.timestamps.length > 0
        ? new Date(entry.timestamps[0] + windowMs).toISOString()
        : new Date(now + windowMs).toISOString();

      if (entry.timestamps.length >= maxRequests) {
        const oldestInWindow = entry.timestamps[0];
        const retryAfter = Math.ceil((oldestInWindow + windowMs - now) / 1000);

        res.set('Retry-After', String(retryAfter));
        res.set('X-RateLimit-Limit', String(maxRequests));
        res.set('X-RateLimit-Remaining', '0');
        res.set('X-RateLimit-Reset', resetAt);
        res.set('X-RateLimit-Policy', `${maxRequests};w=${windowMs / 1000}`);

        return res.status(429).json({
          error: 'Too Many Requests',
          message: `Rate limit exceeded. Max ${maxRequests} requests per ${windowMs / 1000}s window.`,
          retryAfter,
          resetAt
        });
      }

      entry.timestamps.push(now);

      // Always set headers on successful responses too
      res.set('X-RateLimit-Limit', String(maxRequests));
      res.set('X-RateLimit-Remaining', String(maxRequests - entry.timestamps.length));
      res.set('X-RateLimit-Reset', resetAt);
      res.set('X-RateLimit-Policy', `${maxRequests};w=${windowMs / 1000}`);

      next();
    };
  }

  private getClientKey(req: Request): string {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      // Use first 12 chars of key as bucket identifier (not the full key)
      return `key:${authHeader.split(' ')[1].substring(0, 12)}`;
    }
    // Normalise IPv6-mapped IPv4 addresses (::ffff:1.2.3.4 → 1.2.3.4)
    const raw = req.ip || req.socket.remoteAddress || 'unknown';
    const ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
    return `ip:${ip}`;
  }

  private cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      // Use the longest possible window to avoid premature eviction
      const windowStart = now - this.windowMs * 2;
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);
      if (entry.timestamps.length === 0) {
        this.store.delete(key);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}
