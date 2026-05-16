// src/server.js — Fase 3: HTTPS + Auth + Helmet

require('dotenv').config();
const https        = require('https');
const http         = require('http');
const fs           = require('fs');
const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const path         = require('path');
const crypto       = require('crypto');

const { ready }           = require('./db/database');
const apiRouter           = require('./routes/api');
const authRouter          = require('./routes/auth');
const { requireAuth }     = require('./middleware/auth.middleware');
const { startBlocklistJob } = require('./jobs/blocklist.job');
const tlsSvc              = require('./services/tls.service');
const authSvc             = require('./services/auth.service');
const systemRulesSvc      = require('./services/system-rules.service');

const app      = express();
const PORT     = parseInt(process.env.PORT  || '3000');
const HOST     = process.env.HOST           || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV       || 'development';

// ── Seguridad HTTP headers (Helmet) ───────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com', 'fonts.googleapis.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com', 'fonts.googleapis.com', 'fonts.gstatic.com'],
      fontSrc:     ["'self'", 'fonts.googleapis.com', 'fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:', '*.tile.openstreetmap.org', '*.basemaps.cartocdn.com'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// ── Middlewares base ──────────────────────────────────────────
app.use(cors({
  origin: (origin, cb) => {
    // Permitir desde LAN y localhost
    if (!origin || /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/
        .test(origin)) cb(null, true);
    else cb(new Error('CORS no permitido'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'PUT'],
}));

app.use(express.json());
app.use(cookieParser());

// ── Logger de requests ────────────────────────────────────────
app.use((req, _res, next) => {
  const user = req.cookies?.nw_token ? '(auth)' : '(anon)';
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${user} ${req.ip}`);
  next();
});

// ── Redirigir HTTP → HTTPS ────────────────────────────────────
app.use((req, res, next) => {
  if (!req.secure && NODE_ENV === 'production') {
    return res.redirect(301, `https://${req.hostname}:${PORT}${req.url}`);
  }
  next();
});

// ── Rutas públicas (sin auth) ─────────────────────────────────
app.use('/auth', authRouter);
app.get('/login', (req, res) => res.redirect('/auth/login'));

// ── Rutas protegidas ──────────────────────────────────────────
app.use('/api/v1', requireAuth, apiRouter);

// ── Archivos estáticos del dashboard (protegidos) ─────────────
app.use('/auth', express.static(path.join(__dirname, '../public/auth')));
app.use('/', requireAuth, express.static(path.join(__dirname, '../public')));

// ── SPA fallback (protegido) ──────────────────────────────────
app.get('*', requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── Error handler global ──────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ ok: false, error: 'Error interno del servidor' });
});

// ── Inicializar usuario maestro si no existe ──────────────────
async function ensureMasterUser() {
  const exists = await authSvc.hasMasterUser();
  if (exists) return;

  const masterUser = process.env.MASTER_USER || 'admin';
  const masterPass = process.env.MASTER_PASS || crypto.randomBytes(12).toString('hex');

  await authSvc.createUser({
    username: masterUser,
    password: masterPass,
    role:     'admin',
    isMaster: true,
  });

  if (!process.env.MASTER_PASS) {
    console.log('\n' + '='.repeat(50));
    console.log('  USUARIO MAESTRO CREADO — GUARDA ESTAS CREDENCIALES');
    console.log('='.repeat(50));
    console.log(`  Usuario:    ${masterUser}`);
    console.log(`  Contraseña: ${masterPass}`);
    console.log('='.repeat(50));
    console.log('  Puedes cambiarla en .env con MASTER_USER y MASTER_PASS\n');
  }
}

// ── Arrancar servidor HTTPS ───────────────────────────────────
ready.then(async () => {
  startBlocklistJob();
  await ensureMasterUser();

  const { certPath, keyPath } = tlsSvc.loadOrGenerateCert();
  const certInfo = tlsSvc.getCertInfo();

  const serverPort = parseInt(process.env.PORT || '3000');
  await systemRulesSvc.initSystemRules(serverPort);

  const httpsOptions = {
    cert: fs.readFileSync(certPath),
    key:  fs.readFileSync(keyPath),
    // TLS 1.2+ únicamente
    minVersion: 'TLSv1.2',
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
    ].join(':'),
  };

  https.createServer(httpsOptions, app).listen(PORT, HOST, () => {
    console.log(`
+================================================+
|         NetWatch v3.0 -- Fase 3                |
+================================================+
|  URL:   https://${HOST}:${PORT}
|  ENV:   ${NODE_ENV}
|  DB:    ${process.env.DB_PATH || './data/netwatch.db'}
|  TLS:   ${certInfo ? `válido hasta ${new Date(certInfo.validUntil).toLocaleDateString()}` : 'generando...'}
|  Auth:  JWT + bcrypt + httpOnly cookies
+================================================+
|  NOTA: Primera vez? Acepta el certificado      |
|  autofirmado en el navegador                   |
+================================================+
    `);
  });

  // Servidor HTTP solo para redirigir a HTTPS (puerto 80 opcional)
  if (process.env.HTTP_REDIRECT === 'true') {
    http.createServer((req, res) => {
      res.writeHead(301, { Location: `https://${req.headers.host}:${PORT}${req.url}` });
      res.end();
    }).listen(80, HOST, () => console.log('[server] HTTP→HTTPS redirect activo en puerto 80'));
  }
});

process.on('SIGTERM', () => { console.log('[server] Cerrando...'); process.exit(0); });
