// src/middleware/auth.middleware.js
const rateLimit   = require('express-rate-limit');
const authService = require('../services/auth.service');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { ok: false, error: 'Demasiados intentos. Espera 15 minutos.', retryAfter: 15 },
  handler: (req, res, next, options) => {
    authService.auditLog({
      username: req.body?.username,
      action: 'login_rate_limited',
      ipAddr: req.ip,
      success: false,
      details: 'Rate limit alcanzado',
    });
    res.status(429).json(options.message);
  },
});

async function requireAuth(req, res, next) {
  const token = req.cookies?.nw_token || req.headers?.authorization?.replace('Bearer ', '');
  if (!token) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'No autenticado', redirect: '/login' });
    return res.redirect('/auth/login');
  }
  const payload = await authService.verifyToken(token);
  if (!payload) {
    res.clearCookie('nw_token');
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Sesión expirada', redirect: '/login' });
    return res.redirect('/auth/login');
  }
  req.user  = payload;
  req.token = token;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ ok: false, error: 'Se requiere rol admin' });
  next();
}

async function requireMasterPassword(req, res, next) {
  const { masterPassword } = req.body;
  if (!masterPassword) {
    return res.status(403).json({ ok: false, error: 'Se requiere contraseña maestra', requiresMasterPassword: true });
  }
  const valid = await authService.validateMasterPassword(masterPassword);
  if (!valid) {
    await authService.auditLog({
      userId: req.user?.userId, username: req.user?.username,
      action: 'master_password_failed', ipAddr: req.ip,
      success: false, details: `Intento fallido en: ${req.path}`,
    });
    return res.status(403).json({ ok: false, error: 'Contraseña maestra incorrecta' });
  }
  next();
}

module.exports = { loginLimiter, requireAuth, requireAdmin, requireMasterPassword };
