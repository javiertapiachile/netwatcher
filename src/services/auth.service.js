// src/services/auth.service.js
// Autenticación: bcrypt + JWT + httpOnly cookies + rate limiting

const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { db } = require('../db/database');

const JWT_SECRET  = process.env.JWT_SECRET  || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES = process.env.JWT_EXPIRES || '8h';
const BCRYPT_ROUNDS = 12;

// ── Gestión de usuarios ───────────────────────────────────────

async function createUser({ username, password, role = 'admin', isMaster = false }) {
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const result = await db.runAsync(
    `INSERT INTO users (username, password_hash, role, is_master)
     VALUES (?, ?, ?, ?)`,
    [username, hash, role, isMaster ? 1 : 0]
  );
  return result.lastID;
}

async function getUserByUsername(username) {
  return db.getAsync('SELECT * FROM users WHERE username = ? AND is_active = 1', [username]);
}

async function updateLastLogin(userId) {
  await db.runAsync(
    "UPDATE users SET last_login = datetime('now') WHERE id = ?",
    [userId]
  );
}

// ── Validación de contraseña maestra ─────────────────────────
async function validateMasterPassword(password) {
  const master = await db.getAsync(
    'SELECT * FROM users WHERE is_master = 1 AND is_active = 1'
  );
  if (!master) return false;
  return bcrypt.compare(password, master.password_hash);
}

// ── Login ─────────────────────────────────────────────────────
async function login({ username, password, ipAddr, userAgent }) {
  const user = await getUserByUsername(username);

  if (!user) {
    await auditLog({ username, action: 'login_failed', ipAddr, success: false, details: 'Usuario no encontrado' });
    return { ok: false, error: 'Credenciales incorrectas' };
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    await auditLog({ userId: user.id, username, action: 'login_failed', ipAddr, success: false, details: 'Contraseña incorrecta' });
    return { ok: false, error: 'Credenciales incorrectas' };
  }

  // Generar JWT
  const payload = { userId: user.id, username: user.username, role: user.role };
  const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });

  // Hash del token para guardarlo en DB (nunca el token raw)
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();

  await db.runAsync(
    'INSERT INTO sessions (user_id, token_hash, ip_addr, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)',
    [user.id, tokenHash, ipAddr, userAgent, expiresAt]
  );

  await updateLastLogin(user.id);
  await auditLog({ userId: user.id, username, action: 'login_success', ipAddr, success: true });

  return { ok: true, token, user: { id: user.id, username: user.username, role: user.role, isMaster: Boolean(user.is_master) } };
}

// ── Verificar JWT ─────────────────────────────────────────────
async function verifyToken(token) {
  try {
    const payload   = jwt.verify(token, JWT_SECRET);
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const session = await db.getAsync(
      `SELECT * FROM sessions WHERE token_hash = ? AND revoked = 0
       AND expires_at > datetime('now')`,
      [tokenHash]
    );

    if (!session) return null;
    return payload;
  } catch { return null; }
}

// ── Logout ────────────────────────────────────────────────────
async function logout(token, userId) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await db.runAsync('UPDATE sessions SET revoked = 1 WHERE token_hash = ?', [tokenHash]);
  await auditLog({ userId, action: 'logout', success: true });
}

// ── Revocar todas las sesiones (cambio de contraseña) ─────────
async function revokeAllSessions(userId) {
  await db.runAsync('UPDATE sessions SET revoked = 1 WHERE user_id = ?', [userId]);
}

// ── Audit log ─────────────────────────────────────────────────
async function auditLog({ userId = null, username = null, action, resource = null, ipAddr = null, success = true, details = null }) {
  await db.runAsync(
    'INSERT INTO audit_log (user_id, username, action, resource, ip_addr, success, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [userId, username, action, resource, ipAddr, success ? 1 : 0, details]
  );
}

async function getAuditLog({ limit = 100 } = {}) {
  return db.allAsync('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?', [limit]);
}

// ── Verificar si existe usuario maestro ──────────────────────
async function hasMasterUser() {
  const row = await db.getAsync('SELECT id FROM users WHERE is_master = 1');
  return Boolean(row);
}

module.exports = {
  createUser, getUserByUsername, login, verifyToken,
  logout, revokeAllSessions, validateMasterPassword,
  auditLog, getAuditLog, hasMasterUser,
};
