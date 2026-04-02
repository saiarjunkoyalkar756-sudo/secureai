import { Request, Response, NextFunction } from 'express';
import { PermissionDB } from '../core/permissions/db';
import * as path from 'path';

export interface User {
  id: string;
  email: string;
  organizationId: string;
  role: 'admin' | 'executor' | 'approver';
}

export interface AuthRequest extends Request {
  user?: User;
}

const dbPath = path.join(__dirname, '../../secureai.db');
const db = new PermissionDB(dbPath);

/**
 * Middleware to authenticate via API Key in Bearer token
 */
export const authenticateApiKey = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
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
