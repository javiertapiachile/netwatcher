// src/routes/auth.js — Endpoints de autenticación

const express    = require('express');
const router     = express.Router();
const authSvc    = require('../services/auth.service');
const systemSvc  = require('../services/system-rules.service');
const { loginLimiter, requireAuth, requireAdmin, requireMasterPassword } = require('../middleware/auth.middleware');

const COOKIE_OPTS = {
  httpOnly: true,
  secure:   true,        // Solo HTTPS
  sameSite: 'strict',
  maxAge:   8 * 60 * 60 * 1000, // 8 horas
};

// GET /auth/login — página de login
router.get('/login', (req, res) => {
  // Si ya está autenticado, redirigir al dashboard
  const token = req.cookies?.nw_token;
  if (token) return res.redirect('/');
  res.sendFile(require('path').join(__dirname, '../../public/auth/login.html'));
});

// POST /auth/login — procesar login
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Usuario y contraseña requeridos' });
  }
  const result = await authSvc.login({
    username,
    password,
    ipAddr:    req.ip,
    userAgent: req.headers['user-agent'],
  });
  if (!result.ok) return res.status(401).json(result);
  res.cookie('nw_token', result.token, COOKIE_OPTS);
  res.json({ ok: true, user: result.user, redirect: '/' });
});

// POST /auth/logout
router.post('/logout', requireAuth, async (req, res) => {
  await authSvc.logout(req.token, req.user.userId);
  res.clearCookie('nw_token');
  res.json({ ok: true, redirect: '/login' });
});

// GET /auth/me — info del usuario actual
router.get('/me', requireAuth, async (req, res) => {
  res.json({ ok: true, user: req.user });
});

// GET /auth/audit — log de auditoría (solo admin)
router.get('/audit', requireAuth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '100'), 500);
    const logs  = await authSvc.getAuditLog({ limit });
    res.json({ ok: true, count: logs.length, logs });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /auth/system-rules — reglas de sistema protegidas
router.get('/system-rules', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rules = await systemSvc.getSystemRules();
    res.json({ ok: true, rules });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /auth/system-rules/:id — modificar regla de sistema (requiere contraseña maestra)
router.post('/system-rules/:id', requireAuth, requireAdmin, requireMasterPassword, async (req, res) => {
  try {
    const { action } = req.body; // 'enable' | 'disable'
    const result = await systemSvc.modifySystemRule({
      ruleId:   parseInt(req.params.id),
      action,
      userId:   req.user.userId,
      username: req.user.username,
      ipAddr:   req.ip,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
