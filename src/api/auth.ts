import { Request, Response, NextFunction } from 'express';
import { PermissionDB } from '../core/permissions/db';
import { config } from '../config';

export interface User {
  id: string;
  email: string;
  organizationId: string;
  role: 'admin' | 'executor' | 'approver';
}

export interface AuthRequest extends Request {
  user?: User;
  requestId?: string;
}

// Shared database instance
const db = new PermissionDB(config.databasePath);
export { db as authDb };

/**
 * Middleware to authenticate via API Key in Bearer token.
 * API keys are hashed with SHA-256 before lookup.
 */
export const authenticateApiKey = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    if (config.allowPublicDemo) {
      // Allow guest access for the public demo
      req.user = {
        id: 'user_guest',
        email: 'guest@secureai.io',
        organizationId: 'org_public_demo',
        role: 'executor'
      };
      return next();
    }

    return res.status(401).json({ 
      error: 'Missing or invalid Authorization header',
      details: 'Please provide a valid Bearer token'
    });
  }

  const apiKey = authHeader.split(' ')[1];
  
  try {
    const user = db.getUserByApiKey(apiKey);

    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid or revoked API key',
        details: 'The provided API key does not exist or has been deactivated'
      });
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      organizationId: user.organizationId,
      role: user.role
    };

    next();
  } catch (err) {
    console.error('[Auth] Database error:', err);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
};

/**
 * Middleware to require specific roles
 */
export const requireRole = (roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Forbidden', 
        details: `Access denied. Required roles: ${roles.join(', ')}` 
      });
    }
    next();
  };
};
