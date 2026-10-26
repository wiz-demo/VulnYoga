import { Request, Response } from 'express';
import { config } from '../utils/config';
import { logger, securityLogger } from '../utils/logger';
import { AuthenticatedRequest } from '../types';
import * as fs from 'fs';
import * as path from 'path';

export const readFile = async (req: Request, res: Response): Promise<void> => {
  try {
    const { file } = req.query as any;
    const requestingUser = (req as AuthenticatedRequest).user;

    if (!file) {
      res.status(400).json({ error: 'File parameter required' });
      return;
    }

    // Secure: Restrict to public directory only
    try {
      // Resolve and normalize the path
      const requestedPath = path.normalize(file);
      
      // Ensure path is within public directory
      const publicDir = path.resolve(process.cwd(), 'public');
      const filePath = path.resolve(publicDir, requestedPath);
      
      // Verify the resolved path is still within public directory
      if (!filePath.startsWith(publicDir)) {
        res.status(403).json({ error: 'Access denied: Path traversal detected' });
        return;
      }

      if (!fs.existsSync(filePath)) {
        res.status(404).json({ error: 'File not found' });
        return;
      }

      const stats = fs.statSync(filePath);
      if (stats.isDirectory()) {
        res.status(400).json({ error: 'Cannot read directory' });
        return;
      }

      const fileContent = fs.readFileSync(filePath, 'utf-8');
      
      const ext = path.extname(filePath).toLowerCase();
      let contentType = 'text/plain';
      if (ext === '.json') contentType = 'application/json';
      else if (ext === '.html' || ext === '.htm') contentType = 'text/html';
      else if (ext === '.css') contentType = 'text/css';
      else if (ext === '.js') contentType = 'application/javascript';
      else if (ext === '.xml') contentType = 'application/xml';
      else if (ext === '.yaml' || ext === '.yml') contentType = 'text/yaml';

      res.setHeader('Content-Type', contentType);
      res.send(fileContent);
    } catch (error) {
      logger.error('File read error', { error, file });
      res.status(500).json({ error: 'Failed to read file' });
    }
  } catch (error) {
    logger.error('LFI endpoint error', { error });
    res.status(500).json({ error: 'File read failed' });
  }
};

