// =============================================================================
// MTUCI Labs — runtime сервер
// =============================================================================
// Один процесс Node.js, который:
//   1. Стартует Python HTTP server (api/index.py) на 127.0.0.1:8000
//   2. Раздаёт собранную статику из dist/
//   3. Подключает TypeScript handlers /api/* из dist-api/*.cjs
//   4. Проксирует /labs/* в Python
// =============================================================================
const express = require('express');
const path    = require('path');
const fs      = require('fs');
const { spawn } = require('child_process');
const { createProxyMiddleware } = require('http-proxy-middleware');

const PORT        = parseInt(process.env.PORT || '3000', 10);
const PYTHON_PORT = 8000;

// -----------------------------------------------------------------------------
// 1) Python HTTP server для лабораторий
// -----------------------------------------------------------------------------
const pyCode = `
import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), 'api'))
from index import handler
from http.server import HTTPServer
print('[python] listening on 0.0.0.0:${PYTHON_PORT}', flush=True)
HTTPServer(('0.0.0.0', ${PYTHON_PORT}), handler).serve_forever()
`;
const python = spawn('python3', ['-c', pyCode], { stdio: 'inherit' });
python.on('exit', (code) => {
  console.error('[python] exited with code', code);
  process.exit(code || 1);
});

const shutdown = (sig) => () => {
  console.log(`[server] caught ${sig}, shutting down...`);
  try { python.kill(); } catch {}
  process.exit(0);
};
process.on('SIGINT',  shutdown('SIGINT'));
process.on('SIGTERM', shutdown('SIGTERM'));

// -----------------------------------------------------------------------------
// 2) Express
// -----------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// -----------------------------------------------------------------------------
// 3) TS API handlers (предсобранные esbuild'ом в dist-api/*.cjs)
// -----------------------------------------------------------------------------
const apiDir = path.join(__dirname, 'dist-api');
if (fs.existsSync(apiDir)) {
  for (const file of fs.readdirSync(apiDir)) {
    if (!file.endsWith('.cjs')) continue;
    const name = file.replace(/\.cjs$/, '');
    try {
      const mod = require(path.join(apiDir, file));
      const h   = mod.default || mod;
      if (typeof h !== 'function') {
        console.warn(`[server] /api/${name}: no default export`);
        continue;
      }
      app.all(`/api/${name}`, async (req, res) => {
        try {
          await h(req, res);
        } catch (e) {
          console.error(`[/api/${name}]`, e);
          if (!res.headersSent) {
            res.status(500).json({ error: e.message || String(e) });
          }
        }
      });
      console.log(`[server] mounted /api/${name}`);
    } catch (e) {
      console.error(`[server] failed loading /api/${name}:`, e.message);
    }
  }
} else {
  console.warn('[server] dist-api/ not found — TS handlers will be unavailable');
}

// -----------------------------------------------------------------------------
// 4) Прокси /labs/* → Python
// -----------------------------------------------------------------------------
app.use('/labs', createProxyMiddleware({
  target: `http://127.0.0.1:${PYTHON_PORT}`,
  changeOrigin: false,
  logLevel: 'warn',
}));

// -----------------------------------------------------------------------------
// 5) Статика собранного фронта + SPA fallback
// -----------------------------------------------------------------------------
const distPath = path.join(__dirname, 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/labs')) return next();
    const idx = path.join(distPath, 'index.html');
    if (fs.existsSync(idx)) return res.sendFile(idx);
    next();
  });
  console.log('[server] serving static from dist/');
} else {
  console.warn('[server] dist/ not found — frontend will be unavailable');
  app.get('/', (_req, res) => {
    res.status(503).send('<h1>dist/ not built</h1><p>Run <code>npm run build</code>.</p>');
  });
}

// -----------------------------------------------------------------------------
// 6) Слушаем
// -----------------------------------------------------------------------------
// Небольшая задержка, чтобы Python успел подняться раньше первого запроса
setTimeout(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] listening on http://0.0.0.0:${PORT}`);
  });
}, 800);
