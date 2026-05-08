// src/services/logger.service.js
// Persiste snapshots de conexiones en SQLite (versión async con sqlite3)

const { db } = require('../db/database');

async function saveSnapshot(connections) {
  if (!connections?.length) return 0;
  try {
    const stmt = `
      INSERT INTO connections
        (protocol, local_addr, local_port, remote_addr, remote_port, state, pid, process_name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    await Promise.all(connections.map(c =>
      db.runAsync(stmt, [
        c.protocol    || 'UNKNOWN',
        c.localAddr   || '',
        c.localPort   || 0,
        c.remoteAddr  || '',
        c.remotePort  || 0,
        c.state       || null,
        c.pid         || null,
        c.processName || null,
      ])
    ));
    return connections.length;
  } catch (err) {
    console.error('[logger.service] Error guardando snapshot:', err.message);
    return 0;
  }
}

async function getHistory({ limit = 100, offset = 0, remoteAddr = null, since = null } = {}) {
  let query = `
    SELECT id, captured_at, protocol, local_addr, local_port,
           remote_addr, remote_port, state, pid, process_name
    FROM connections WHERE 1=1
  `;
  const params = [];

  if (remoteAddr) { query += ' AND remote_addr = ?'; params.push(remoteAddr); }
  if (since)      { query += ' AND captured_at >= ?'; params.push(since); }

  query += ' ORDER BY captured_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  return db.allAsync(query, params);
}

async function getUniqueRemoteIPs({ limit = 50 } = {}) {
  return db.allAsync(`
    SELECT remote_addr, COUNT(*) as seen_count, MAX(captured_at) as last_seen
    FROM connections
    GROUP BY remote_addr
    ORDER BY last_seen DESC
    LIMIT ?
  `, [limit]);
}

async function getStats() {
  return db.getAsync(`
    SELECT
      COUNT(*)                    AS total_records,
      COUNT(DISTINCT remote_addr) AS unique_remote_ips,
      MIN(captured_at)            AS first_capture,
      MAX(captured_at)            AS last_capture
    FROM connections
  `);
}

async function purgeOlderThan(days = 30) {
  const result = await db.runAsync(
    `DELETE FROM connections WHERE captured_at < datetime('now', '-' || ? || ' days')`,
    [days]
  );
  return result.changes;
}

module.exports = { saveSnapshot, getHistory, getUniqueRemoteIPs, getStats, purgeOlderThan };
