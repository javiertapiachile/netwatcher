// src/services/dns.service.js
// Resolución DNS con caché en SQLite (versión async con sqlite3)

const dns = require('dns').promises;
const { db } = require('../db/database');

const TTL = parseInt(process.env.DNS_CACHE_TTL || '300', 10);

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^::1$/,
  /^fe80:/i,
  /^fc00:/i,
  /^fd/i,
];

function isPrivateIP(ip) {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

async function resolveIP(ip) {
  if (!ip) return { ip, fqdn: null, fromCache: false, isPrivate: false };

  const isPrivate = isPrivateIP(ip);

  // 1. Buscar en caché
  const cached = await db.getAsync(
    'SELECT fqdn, resolved_at, ttl_seconds, is_private FROM dns_cache WHERE ip = ?',
    [ip]
  );

  if (cached) {
    const resolvedAt = new Date(cached.resolved_at + 'Z');
    const ageSeconds = (Date.now() - resolvedAt.getTime()) / 1000;
    if (ageSeconds < cached.ttl_seconds) {
      return {
        ip,
        fqdn:      cached.fqdn,
        fromCache: true,
        isPrivate: Boolean(cached.is_private),
        ageSeconds: Math.round(ageSeconds),
      };
    }
  }

  // 2. Resolver via DNS
  let fqdn = null;
  try {
    const hostnames = await dns.reverse(ip);
    fqdn = hostnames?.[0] || null;
  } catch { fqdn = null; }

  // 3. Guardar en caché (UPSERT)
  await db.runAsync(
    `INSERT INTO dns_cache (ip, fqdn, ttl_seconds, is_private)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(ip) DO UPDATE SET
       fqdn        = excluded.fqdn,
       resolved_at = datetime('now'),
       ttl_seconds = excluded.ttl_seconds`,
    [ip, fqdn, TTL, isPrivate ? 1 : 0]
  );

  return { ip, fqdn, fromCache: false, isPrivate, ageSeconds: 0 };
}

async function resolveMany(ips, concurrency = 10) {
  const results = {};
  const unique  = [...new Set(ips.filter(Boolean))];

  for (let i = 0; i < unique.length; i += concurrency) {
    const chunk   = unique.slice(i, i + concurrency);
    const resolved = await Promise.all(chunk.map(ip => resolveIP(ip)));
    resolved.forEach(r => { results[r.ip] = r; });
  }
  return results;
}

async function invalidateCache(ip) {
  await db.runAsync('DELETE FROM dns_cache WHERE ip = ?', [ip]);
}

async function getCacheStats() {
  return db.getAsync(`
    SELECT
      COUNT(*)                                          AS total,
      SUM(CASE WHEN fqdn IS NOT NULL THEN 1 ELSE 0 END) AS resolved,
      SUM(is_private)                                   AS private_ips
    FROM dns_cache
  `);
}

module.exports = { resolveIP, resolveMany, invalidateCache, getCacheStats, isPrivateIP };
