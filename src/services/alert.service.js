// src/services/alert.service.js
// Motor de alertas: evalúa reglas y persiste en SQLite

const { db } = require('../db/database');

// IPs ya alertadas en esta sesión (evita duplicados en el mismo ciclo)
const alertedThisSession = new Set();

// Reglas de alerta configurables
const ALERT_RULES = [
  {
    id:       'malicious_ip',
    severity: 'critical',
    label:    'IP Maliciosa Detectada',
    check:    (conn, rep) => rep?.score === 'MALICIOUS',
    detail:   (conn, rep) => `IP ${conn.remoteAddr} encontrada en blocklist: ${rep?.reasons}`,
  },
  {
    id:       'suspicious_ip',
    severity: 'high',
    label:    'IP Sospechosa',
    check:    (conn, rep) => rep?.score === 'SUSPICIOUS' && rep?.blocklist_hits,
    detail:   (conn, rep) => `IP ${conn.remoteAddr} marcada como sospechosa: ${rep?.reasons}`,
  },
  {
    id:       'proxy_vpn',
    severity: 'medium',
    label:    'Conexión via Proxy/VPN',
    check:    (conn, rep, geo) => geo?.is_proxy === 1,
    detail:   (conn, rep, geo) => `Conexión a ${conn.remoteAddr} via proxy/VPN detectado (${geo?.country || 'país desconocido'})`,
  },
  {
    id:       'unusual_port',
    severity: 'medium',
    label:    'Puerto Inusual',
    check:    (conn) => [4444, 1337, 31337, 6666, 6667, 8888, 9999, 12345].includes(conn.remotePort),
    detail:   (conn) => `Conexión al puerto inusual ${conn.remotePort} en ${conn.remoteAddr}`,
  },
  {
    id:       'tor_exit',
    severity: 'high',
    label:    'Nodo Tor Detectado',
    check:    (conn, rep) => rep?.service_type === 'anonymizer',
    detail:   (conn) => `Conexión detectada a nodo Tor: ${conn.remoteAddr}`,
  },
];

/**
 * Evalúa todas las reglas para una conexión y crea alertas si aplica
 */
async function evaluateConnection(conn, repData, geoData) {
  const sessionKey = `${conn.remoteAddr}:${conn.remotePort}`;
  if (alertedThisSession.has(sessionKey)) return [];

  const triggered = [];

  for (const rule of ALERT_RULES) {
    try {
      if (rule.check(conn, repData, geoData)) {
        const detail = rule.detail(conn, repData, geoData);

        // Verificar si ya existe alerta reciente (< 1h) para esta IP + regla
        const existing = await db.getAsync(`
          SELECT id FROM alerts
          WHERE ip = ? AND rule = ? AND created_at > datetime('now', '-1 hour')
          AND acknowledged = 0
        `, [conn.remoteAddr, rule.id]);

        if (!existing) {
          await db.runAsync(
            'INSERT INTO alerts (ip, rule, severity, details) VALUES (?, ?, ?, ?)',
            [conn.remoteAddr, rule.id, rule.severity, detail]
          );
          triggered.push({ rule: rule.id, severity: rule.severity, label: rule.label, detail });
        }
      }
    } catch (err) {
      console.error(`[alert.service] Error en regla ${rule.id}:`, err.message);
    }
  }

  if (triggered.length > 0) alertedThisSession.add(sessionKey);
  return triggered;
}

/**
 * Obtiene alertas del log
 */
async function getAlerts({ limit = 100, onlyUnacknowledged = false } = {}) {
  let query  = 'SELECT * FROM alerts';
  const params = [];
  if (onlyUnacknowledged) { query += ' WHERE acknowledged = 0'; }
  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);
  return db.allAsync(query, params);
}

/**
 * Cuenta alertas sin reconocer por severidad
 */
async function getAlertSummary() {
  return db.getAsync(`
    SELECT
      COUNT(*)                                                        AS total,
      SUM(CASE WHEN severity='critical' AND acknowledged=0 THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN severity='high'     AND acknowledged=0 THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN severity='medium'   AND acknowledged=0 THEN 1 ELSE 0 END) AS medium,
      SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END)                AS unread
    FROM alerts
  `);
}

/**
 * Marcar alertas como reconocidas
 */
async function acknowledgeAlert(id) {
  return db.runAsync('UPDATE alerts SET acknowledged = 1 WHERE id = ?', [id]);
}

async function acknowledgeAll() {
  return db.runAsync('UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0');
}

module.exports = { evaluateConnection, getAlerts, getAlertSummary, acknowledgeAlert, acknowledgeAll };
