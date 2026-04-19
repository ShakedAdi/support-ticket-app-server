import { Request, Response, NextFunction } from 'express';

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if ((req.user as { role?: string } | undefined)?.role !== 'admin') {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  next();
}
