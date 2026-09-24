import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { apiRouter } from './server/api/routes.ts';
import { CaseRepository } from './server/storage/repository.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Body parsing middleware
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));
app.use(express.raw({ limit: '60mb', type: ['application/octet-stream', 'application/vnd.tcpdump.pcap'] }));

// Initialize demo case repository
CaseRepository.initializeWithDemo();

// Mount API routes under /api
app.use('/api', apiRouter);

// Set up Vite dev middleware in development mode
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Serve static files in production
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`[SIH26159 Server] Running on http://0.0.0.0:${PORT} (${isProd ? 'production' : 'development'})`);
  });
}

startServer().catch((err) => {
  console.error('[SIH26159 Server] Failed to start:', err);
  process.exit(1);
});
