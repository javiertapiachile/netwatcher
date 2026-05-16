// src/services/system-rules.service.js
// Gestión de reglas de sistema protegidas (no bloqueables sin contraseña maestra)

const { execSync } = require('child_process');
const os   = require('os');
const { db } = require('../db/database');

const IS_WINDOWS   = os.platform() === 'win32';
const SYSTEM_PREFIX = 'NETWATCH_SYSTEM_';

// ── Inicializar reglas de sistema al arrancar ─────────────────
async function initSystemRules(port = 3000) {
  const existing = await db.getAsync(
    "SELECT id FROM system_rules WHERE rule_name = ?",
    [`${SYSTEM_PREFIX}INBOUND_${port}`]
  );
  if (existing) {
    console.log('[system-rules] Reglas de sistema ya existen');
    return;
  }

  console.log(`[system-rules] Creando reglas protegidas para puerto ${port}...`);

  const rules = [
    {
      name:      `${SYSTEM_PREFIX}INBOUND_${port}`,
      desc:      `NetWatch dashboard - tráfico entrante puerto ${port}`,
      direction: 'in',
      port,
    },
    {
      name:      `${SYSTEM_PREFIX}OUTBOUND_${port}`,
      desc:      `NetWatch dashboard - tráfico saliente puerto ${port}`,
      direction: 'out',
      port,
    },
  ];

  for (const rule of rules) {
    // Crear regla en firewall de Windows
    if (IS_WINDOWS) {
      try {
        execSync(
          `netsh advfirewall firewall add rule name="${rule.name}" ` +
          `dir=${rule.direction} action=allow protocol=TCP localport=${rule.port} enable=yes`,
          { stdio: 'ignore' }
        );
      } catch (err) {
        console.warn(`[system-rules] No se pudo crear regla ${rule.name}: ${err.message}`);
      }
    }

    // Registrar en DB como regla de sistema
    await db.runAsync(
      `INSERT OR IGNORE INTO system_rules (rule_name, description, port, direction)
       VALUES (?, ?, ?, ?)`,
      [rule.name, rule.desc, rule.port, rule.direction]
    );

    // Registrar en blocked_ips como regla activa de sistema
    await db.runAsync(
      `INSERT OR IGNORE INTO blocked_ips (ip, port, rule_name, is_system, notes, status)
       VALUES ('0.0.0.0', ?, ?, 1, 'Regla de sistema — no modificar', 'system')`,
      [rule.port, rule.name]
    );
  }

  console.log('[system-rules] Reglas de sistema creadas correctamente');
}

// ── Verificar si una IP/puerto es regla de sistema ────────────
async function isSystemRule(ip, port) {
  // Verificar por puerto del servicio
  const byPort = await db.getAsync(
    "SELECT id FROM system_rules WHERE port = ? AND is_active = 1",
    [port]
  );
  if (byPort) return true;

  // Verificar si la IP es local (nunca bloquear localhost)
  const localIPs = ['127.0.0.1', '::1', '0.0.0.0', 'localhost'];
  if (localIPs.includes(ip)) return true;

  return false;
}

// ── Obtener reglas de sistema ─────────────────────────────────
async function getSystemRules() {
  return db.allAsync('SELECT * FROM system_rules ORDER BY created_at ASC');
}

// ── Modificar regla de sistema (requiere contraseña maestra) ──
async function modifySystemRule({ ruleId, action, userId, username, ipAddr }) {
  const rule = await db.getAsync('SELECT * FROM system_rules WHERE id = ?', [ruleId]);
  if (!rule) return { ok: false, error: 'Regla no encontrada' };

  // Registrar intento en audit log
  await db.runAsync(
    'INSERT INTO audit_log (user_id, username, action, resource, ip_addr, success, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [userId, username, `system_rule_${action}`, rule.rule_name, ipAddr, 1,
     `Modificación de regla de sistema: ${rule.rule_name}`]
  );

  if (action === 'disable') {
    if (IS_WINDOWS) {
      try {
        execSync(`netsh advfirewall firewall set rule name="${rule.rule_name}" new enable=no`, { stdio: 'ignore' });
      } catch {}
    }
    await db.runAsync('UPDATE system_rules SET is_active = 0 WHERE id = ?', [ruleId]);
    return { ok: true, message: `Regla ${rule.rule_name} desactivada` };
  }

  if (action === 'enable') {
    if (IS_WINDOWS) {
      try {
        execSync(`netsh advfirewall firewall set rule name="${rule.rule_name}" new enable=yes`, { stdio: 'ignore' });
      } catch {}
    }
    await db.runAsync('UPDATE system_rules SET is_active = 1 WHERE id = ?', [ruleId]);
    return { ok: true, message: `Regla ${rule.rule_name} reactivada` };
  }

  return { ok: false, error: 'Acción no válida' };
}

module.exports = { initSystemRules, isSystemRule, getSystemRules, modifySystemRule };
