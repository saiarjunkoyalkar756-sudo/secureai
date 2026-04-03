import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

/**
 * Request logging middleware.
 * Assigns a unique X-Request-Id to each request and logs method, path, status, and timing.
 */
export function requestLogger() {
  return (req: Request, res: Response, next: NextFunction) => {
    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    // Attach request ID to headers
    req.headers['x-request-id'] = requestId;
    res.set('X-Request-Id', requestId);

    // Capture the original end method
    const originalEnd = res.end;
    res.end = function (this: Response, ...args: any[]): Response {
      const duration = Date.now() - startTime;
      const statusCode = res.statusCode;
      const statusIcon = statusCode >= 500 ? '🔴' : statusCode >= 400 ? '🟡' : '🟢';

      console.log(
        `${statusIcon} ${req.method} ${req.path} → ${statusCode} (${duration}ms) [${requestId.substring(0, 8)}]`
      );

      return originalEnd.apply(this, args as any);
    } as any;

    next();
  };
}
