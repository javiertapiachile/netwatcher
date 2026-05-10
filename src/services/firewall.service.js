// src/services/firewall.service.js
// Gestión de bloqueo de conexiones: taskkill + firewall Windows + rollback

const { execSync, exec } = require('child_process');
const os   = require('os');
const { db } = require('../db/database');

const RULE_PREFIX = 'NETWATCH_BLOCK_';
const IS_WINDOWS  = os.platform() === 'win32';

// ── Schema para tabla de bloqueos ─────────────────────────────
const initBlockedTable = async () => {
  await db.execAsync(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      ip           TEXT NOT NULL,
      port         INTEGER,
      pid          INTEGER,
      rule_name    TEXT,
      blocked_at   TEXT NOT NULL DEFAULT (datetime('now')),
      unblocked_at TEXT,
      status       TEXT NOT NULL DEFAULT 'active',
      notes        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_blocked_ips_status ON blocked_ips(status);
    CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip     ON blocked_ips(ip);
  `);
};
initBlockedTable().catch(console.error);

// ── Verificar si corremos como administrador ──────────────────
function checkAdminPrivileges() {
  if (!IS_WINDOWS) return true;
  try {
    execSync('net session', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// ── Matar proceso por PID ─────────────────────────────────────
function killProcess(pid) {
  if (!pid) return { ok: false, msg: 'Sin PID disponible' };
  try {
    if (IS_WINDOWS) {
      execSync(`taskkill /PID ${pid} /F`, { stdio: 'ignore' });
    } else {
      execSync(`kill -9 ${pid}`, { stdio: 'ignore' });
    }
    return { ok: true, msg: `Proceso ${pid} terminado` };
  } catch (err) {
    return { ok: false, msg: `No se pudo terminar PID ${pid}: ${err.message}` };
  }
}

// ── Crear regla en firewall de Windows ───────────────────────
function blockIPFirewall(ip) {
  if (!IS_WINDOWS) {
    // En Linux usar iptables como alternativa
    try {
      execSync(`iptables -A OUTPUT -d ${ip} -j DROP`, { stdio: 'ignore' });
      return { ok: true, ruleName: `${RULE_PREFIX}${ip.replace(/\./g, '_')}` };
    } catch (err) {
      return { ok: false, msg: err.message };
    }
  }

  const ruleName = `${RULE_PREFIX}${ip.replace(/\./g, '_')}`;
  try {
    // Bloquear tráfico saliente hacia la IP
    execSync(
      `netsh advfirewall firewall add rule name="${ruleName}" dir=out action=block remoteip=${ip} enable=yes`,
      { stdio: 'ignore' }
    );
    // Bloquear tráfico entrante desde la IP
    execSync(
      `netsh advfirewall firewall add rule name="${ruleName}_IN" dir=in action=block remoteip=${ip} enable=yes`,
      { stdio: 'ignore' }
    );
    return { ok: true, ruleName };
  } catch (err) {
    return { ok: false, msg: `Error creando regla firewall: ${err.message}` };
  }
}

// ── Eliminar regla del firewall (rollback) ────────────────────
function unblockIPFirewall(ip, ruleName) {
  if (!IS_WINDOWS) {
    try {
      execSync(`iptables -D OUTPUT -d ${ip} -j DROP`, { stdio: 'ignore' });
      return { ok: true };
    } catch (err) {
      return { ok: false, msg: err.message };
    }
  }

  const name = ruleName || `${RULE_PREFIX}${ip.replace(/\./g, '_')}`;
  try {
    execSync(`netsh advfirewall firewall delete rule name="${name}"`,         { stdio: 'ignore' });
    execSync(`netsh advfirewall firewall delete rule name="${name}_IN"`,      { stdio: 'ignore' });
    return { ok: true };
  } catch (err) {
    return { ok: false, msg: `Error eliminando regla: ${err.message}` };
  }
}

// ── Acción principal: bloquear conexión completa ──────────────
async function blockConnection({ ip, port, pid }) {
  if (!checkAdminPrivileges()) {
    return {
      ok: false,
      error: 'Se requieren privilegios de Administrador. Reinicia PowerShell como Administrador y ejecuta npm start.',
    };
  }

  // Verificar si ya está bloqueada
  const existing = await db.getAsync(
    "SELECT id FROM blocked_ips WHERE ip = ? AND status = 'active'", [ip]
  );
  if (existing) {
    return { ok: false, error: `La IP ${ip} ya está bloqueada activamente.` };
  }

  const results = { killResult: null, firewallResult: null };

  // 1. Matar proceso si hay PID
  if (pid) {
    results.killResult = killProcess(pid);
  }

  // 2. Bloquear en firewall
  results.firewallResult = blockIPFirewall(ip);

  if (!results.firewallResult.ok) {
    return { ok: false, error: results.firewallResult.msg, results };
  }

  // 3. Registrar en DB
  const row = await db.runAsync(
    `INSERT INTO blocked_ips (ip, port, pid, rule_name, notes)
     VALUES (?, ?, ?, ?, ?)`,
    [ip, port || null, pid || null, results.firewallResult.ruleName,
     `Bloqueado manualmente desde NetWatch`]
  );

  return {
    ok:      true,
    blockId: row.lastID,
    ip,
    ruleName: results.firewallResult.ruleName,
    killResult: results.killResult,
    message: `IP ${ip} bloqueada correctamente en firewall de Windows`,
  };
}

// ── Rollback: desbloquear IP ──────────────────────────────────
async function unblockConnection(blockId) {
  const record = await db.getAsync('SELECT * FROM blocked_ips WHERE id = ?', [blockId]);
  if (!record) return { ok: false, error: 'Registro de bloqueo no encontrado' };
  if (record.status !== 'active') return { ok: false, error: 'Esta IP ya fue desbloqueada' };

  const result = unblockIPFirewall(record.ip, record.rule_name);

  // Actualizar DB aunque el firewall falle (para mantener consistencia)
  await db.runAsync(
    `UPDATE blocked_ips SET status = 'reverted', unblocked_at = datetime('now') WHERE id = ?`,
    [blockId]
  );

  return {
    ok:      result.ok,
    message: result.ok
      ? `IP ${record.ip} desbloqueada — regla de firewall eliminada`
      : `Advertencia: ${result.msg} — registro actualizado en DB`,
    ip: record.ip,
  };
}

// ── Consultas ─────────────────────────────────────────────────
async function getBlockedIPs({ status = null } = {}) {
  let query  = 'SELECT * FROM blocked_ips';
  const params = [];
  if (status) { query += ' WHERE status = ?'; params.push(status); }
  query += ' ORDER BY blocked_at DESC';
  return db.allAsync(query, params);
}

async function isBlocked(ip) {
  const row = await db.getAsync(
    "SELECT id FROM blocked_ips WHERE ip = ? AND status = 'active'", [ip]
  );
  return Boolean(row);
}

module.exports = {
  blockConnection, unblockConnection,
  getBlockedIPs, isBlocked, checkAdminPrivileges,
};
