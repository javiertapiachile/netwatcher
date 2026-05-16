// src/services/firewall.service.js — Fase 3: con protección de reglas de sistema

const { execSync } = require('child_process');
const os   = require('os');
const { db } = require('../db/database');
const systemRulesSvc = require('./system-rules.service');

const RULE_PREFIX = 'NETWATCH_BLOCK_';
const IS_WINDOWS  = os.platform() === 'win32';

const initBlockedTable = async () => {
  await db.execAsync(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      ip           TEXT NOT NULL,
      port         INTEGER,
      pid          INTEGER,
      rule_name    TEXT,
      is_system    INTEGER NOT NULL DEFAULT 0,
      blocked_at   TEXT NOT NULL DEFAULT (datetime('now')),
      unblocked_at TEXT,
      status       TEXT NOT NULL DEFAULT 'active',
      notes        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_blocked_ips_status ON blocked_ips(status);
    CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
  `);
};
initBlockedTable().catch(console.error);

function checkAdminPrivileges() {
  if (!IS_WINDOWS) return true;
  try { execSync('net session', { stdio: 'ignore' }); return true; }
  catch { return false; }
}

function killProcess(pid) {
  if (!pid) return { ok: false, msg: 'Sin PID' };
  try {
    IS_WINDOWS
      ? execSync(`taskkill /PID ${pid} /F`, { stdio: 'ignore' })
      : execSync(`kill -9 ${pid}`, { stdio: 'ignore' });
    return { ok: true, msg: `Proceso ${pid} terminado` };
  } catch (err) {
    return { ok: false, msg: err.message };
  }
}

function blockIPFirewall(ip) {
  const ruleName = `${RULE_PREFIX}${ip.replace(/\./g, '_').replace(/:/g, '_')}`;
  if (!IS_WINDOWS) {
    try { execSync(`iptables -A OUTPUT -d ${ip} -j DROP`, { stdio: 'ignore' }); return { ok: true, ruleName }; }
    catch (err) { return { ok: false, msg: err.message }; }
  }
  try {
    execSync(`netsh advfirewall firewall add rule name="${ruleName}" dir=out action=block remoteip=${ip} enable=yes`, { stdio: 'ignore' });
    execSync(`netsh advfirewall firewall add rule name="${ruleName}_IN" dir=in action=block remoteip=${ip} enable=yes`, { stdio: 'ignore' });
    return { ok: true, ruleName };
  } catch (err) {
    return { ok: false, msg: err.message };
  }
}

function unblockIPFirewall(ip, ruleName) {
  const name = ruleName || `${RULE_PREFIX}${ip.replace(/\./g, '_').replace(/:/g, '_')}`;
  if (!IS_WINDOWS) {
    try { execSync(`iptables -D OUTPUT -d ${ip} -j DROP`, { stdio: 'ignore' }); return { ok: true }; }
    catch (err) { return { ok: false, msg: err.message }; }
  }
  try {
    execSync(`netsh advfirewall firewall delete rule name="${name}"`,      { stdio: 'ignore' });
    execSync(`netsh advfirewall firewall delete rule name="${name}_IN"`,   { stdio: 'ignore' });
    return { ok: true };
  } catch (err) {
    return { ok: false, msg: err.message };
  }
}

async function blockConnection({ ip, port, pid }) {
  if (!checkAdminPrivileges()) {
    return { ok: false, error: 'Se requieren privilegios de Administrador.' };
  }

  // ── PROTECCIÓN: verificar si es regla de sistema ──────────
  const isSystem = await systemRulesSvc.isSystemRule(ip, port);
  if (isSystem) {
    return {
      ok: false,
      error: 'Esta conexión corresponde al servicio NetWatch y no puede bloquearse.',
      isSystemRule: true,
    };
  }

  const existing = await db.getAsync(
    "SELECT id FROM blocked_ips WHERE ip = ? AND status = 'active'", [ip]
  );
  if (existing) return { ok: false, error: `La IP ${ip} ya está bloqueada.` };

  const killResult     = pid ? killProcess(pid) : null;
  const firewallResult = blockIPFirewall(ip);

  if (!firewallResult.ok) return { ok: false, error: firewallResult.msg };

  const row = await db.runAsync(
    'INSERT INTO blocked_ips (ip, port, pid, rule_name, is_system, notes) VALUES (?, ?, ?, ?, 0, ?)',
    [ip, port || null, pid || null, firewallResult.ruleName, 'Bloqueado manualmente desde NetWatch']
  );

  return { ok: true, blockId: row.lastID, ip, ruleName: firewallResult.ruleName, killResult };
}

async function unblockConnection(blockId) {
  const record = await db.getAsync('SELECT * FROM blocked_ips WHERE id = ?', [blockId]);
  if (!record) return { ok: false, error: 'Registro no encontrado' };
  if (record.status !== 'active') return { ok: false, error: 'Esta IP ya fue desbloqueada' };

  // ── PROTECCIÓN: no permitir desbloquear reglas de sistema ─
  if (record.is_system) {
    return {
      ok: false,
      error: 'Las reglas de sistema no pueden modificarse desde este panel.',
      isSystemRule: true,
    };
  }

  const result = unblockIPFirewall(record.ip, record.rule_name);
  await db.runAsync(
    "UPDATE blocked_ips SET status='reverted', unblocked_at=datetime('now') WHERE id=?",
    [blockId]
  );
  return { ok: result.ok, message: result.ok ? `IP ${record.ip} desbloqueada` : `Advertencia: ${result.msg}`, ip: record.ip };
}

async function getBlockedIPs({ status = null } = {}) {
  let q = 'SELECT * FROM blocked_ips WHERE is_system = 0';
  const p = [];
  if (status) { q += ' AND status = ?'; p.push(status); }
  q += ' ORDER BY blocked_at DESC';
  return db.allAsync(q, p);
}

async function isBlocked(ip) {
  const row = await db.getAsync("SELECT id FROM blocked_ips WHERE ip=? AND status='active'", [ip]);
  return Boolean(row);
}

module.exports = { blockConnection, unblockConnection, getBlockedIPs, isBlocked, checkAdminPrivileges };
