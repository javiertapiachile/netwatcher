// src/server.js — Fase 2
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const { ready }          = require('./db/database');
const apiRouter          = require('./routes/api');
const { startBlocklistJob } = require('./jobs/blocklist.job');

const app  = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

app.use(cors({ origin: [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`], methods: ['GET','POST','DELETE'] }));
app.use(express.json());
app.use((req, _res, next) => { console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`); next(); });

app.use('/api/v1', apiRouter);
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.stack);
  res.status(500).json({ ok: false, error: 'Error interno' });
});

ready.then(() => {
  // Iniciar job de blocklists antes de aceptar conexiones
  startBlocklistJob();

  app.listen(PORT, HOST, () => {
    console.log(`
+==========================================+
|       NetWatch v2.0 -- Fase 2            |
+==========================================+
|  URL:  http://${HOST}:${PORT}
|  ENV:  ${process.env.NODE_ENV || 'development'}
|  DB:   ${process.env.DB_PATH || './data/netwatch.db'}
|  Geo:  ip-api.com (sin API key)
|  Rep:  Feodo Tracker + Emerging Threats
+==========================================+
    `);
  });
});

process.on('SIGTERM', () => { console.log('[server] Cerrando...'); process.exit(0); });
