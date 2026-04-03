import { Request, Response, NextFunction } from 'express';

/**
 * In-memory sliding window rate limiter.
 * Tracks request timestamps per client key and enforces a max request count per window.
 */

interface RateLimitEntry {
  timestamps: number[];
}

export class RateLimiter {
  private store: Map<string, RateLimitEntry> = new Map();
  private windowMs: number;
  private maxRequests: number;
  private cleanupInterval: NodeJS.Timeout;

  constructor(windowMs: number = 60000, maxRequests: number = 100) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;

    // Cleanup stale entries every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref(); // Don't block process exit
    }
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const key = this.getClientKey(req);
      const now = Date.now();

      let entry = this.store.get(key);
      if (!entry) {
        entry = { timestamps: [] };
        this.store.set(key, entry);
      }

      // Remove timestamps outside the window
      const windowStart = now - this.windowMs;
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);

      if (entry.timestamps.length >= this.maxRequests) {
        const oldestInWindow = entry.timestamps[0];
        const retryAfter = Math.ceil((oldestInWindow + this.windowMs - now) / 1000);

        res.set('Retry-After', String(retryAfter));
        res.set('X-RateLimit-Limit', String(this.maxRequests));
        res.set('X-RateLimit-Remaining', '0');
        res.set('X-RateLimit-Reset', new Date(oldestInWindow + this.windowMs).toISOString());

        return res.status(429).json({
          error: 'Too Many Requests',
          message: `Rate limit exceeded. Max ${this.maxRequests} requests per ${this.windowMs / 1000}s window.`,
          retryAfter
        });
      }

      entry.timestamps.push(now);

      // Set rate limit headers
      res.set('X-RateLimit-Limit', String(this.maxRequests));
      res.set('X-RateLimit-Remaining', String(this.maxRequests - entry.timestamps.length));

      next();
    };
  }

  private getClientKey(req: Request): string {
    // Use API key if present, otherwise fall back to IP
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return `key:${authHeader.split(' ')[1].substring(0, 8)}`;
    }
    return `ip:${req.ip || req.socket.remoteAddress || 'unknown'}`;
  }

  private cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    for (const [key, entry] of this.store.entries()) {
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
