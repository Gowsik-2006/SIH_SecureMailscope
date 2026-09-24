import type { Request, Response } from 'express';
import express from 'express';
import { apiRouter } from '../server/api/routes.ts';
import { CaseRepository } from '../server/storage/repository.ts';

const app = express();

app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));
app.use(express.raw({ limit: '60mb', type: ['application/octet-stream', 'application/vnd.tcpdump.pcap'] }));

// Initialize demo repository
CaseRepository.initializeWithDemo();

// Mount directly under both /api and root to handle any proxy rewrite style
app.use('/api', apiRouter);
app.use(apiRouter);

export default function handler(req: Request, res: Response) {
  return app(req, res);
}
