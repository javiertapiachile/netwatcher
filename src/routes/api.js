// src/routes/api.js — Fase 1 + Fase 2

const express   = require('express');
const router    = express.Router();

const netstatSvc    = require('../services/netstat.service');
const dnsSvc        = require('../services/dns.service');
const loggerSvc     = require('../services/logger.service');
const geoSvc        = require('../services/geo.service');
const repSvc        = require('../services/reputation.service');
const alertSvc      = require('../services/alert.service');

// ── GET /api/v1/connections ───────────────────────────────────
router.get('/connections', async (req, res) => {
  try {
    const connections = netstatSvc.getConnections();
    setImmediate(() => loggerSvc.saveSnapshot(connections));

    const remoteIPs = connections.map(c => c.remoteAddr).filter(Boolean);

    // Resolver DNS, geo y reputación en paralelo
    const [dnsMap, geoMap] = await Promise.all([
      dnsSvc.resolveMany(remoteIPs),
      geoSvc.getGeoMany(remoteIPs),
    ]);

    const repMap = await repSvc.checkReputationMany(remoteIPs, geoMap);

    // Evaluar alertas en background
    setImmediate(async () => {
      for (const conn of connections) {
        await alertSvc.evaluateConnection(conn, repMap[conn.remoteAddr], geoMap[conn.remoteAddr]);
      }
    });

    const enriched = connections.map(c => ({
      ...c,
      dns:        dnsMap[c.remoteAddr] || { fqdn: null, isPrivate: dnsSvc.isPrivateIP(c.remoteAddr) },
      geo:        geoMap[c.remoteAddr] || null,
      reputation: repMap[c.remoteAddr] || null,
    }));

    res.json({ ok: true, count: enriched.length, capturedAt: new Date().toISOString(), connections: enriched });
  } catch (err) {
    console.error('[GET /connections]', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/resolve/:ip ───────────────────────────────────
router.get('/resolve/:ip', async (req, res) => {
  const { ip } = req.params;
  const force   = req.query.force === '1';
  const ipv4    = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6    = /^[0-9a-fA-F:]+$/;
  if (!ipv4.test(ip) && !ipv6.test(ip)) {
    return res.status(400).json({ ok: false, error: 'Formato de IP inválido' });
  }
  try {
    if (force) dnsSvc.invalidateCache(ip);
    const [dns, geo, rep] = await Promise.all([
      dnsSvc.resolveIP(ip),
      geoSvc.getGeo(ip),
      repSvc.checkReputation(ip),
    ]);
    res.json({ ok: true, ip, dns, geo, reputation: rep });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/geo/:ip ───────────────────────────────────────
router.get('/geo/:ip', async (req, res) => {
  try {
    const data = await geoSvc.getGeo(req.params.ip);
    res.json({ ok: true, ...data });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/reputation/:ip ────────────────────────────────
router.get('/reputation/:ip', async (req, res) => {
  try {
    const geo = await geoSvc.getGeo(req.params.ip);
    const rep = await repSvc.checkReputation(req.params.ip, geo);
    res.json({ ok: true, ...rep });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/alerts ────────────────────────────────────────
router.get('/alerts', async (req, res) => {
  try {
    const onlyUnread = req.query.unread === '1';
    const limit      = Math.min(parseInt(req.query.limit || '100'), 500);
    const [alerts, summary] = await Promise.all([
      alertSvc.getAlerts({ limit, onlyUnacknowledged: onlyUnread }),
      alertSvc.getAlertSummary(),
    ]);
    res.json({ ok: true, summary, alerts });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── POST /api/v1/alerts/:id/acknowledge ──────────────────────
router.post('/alerts/:id/acknowledge', async (req, res) => {
  try {
    await alertSvc.acknowledgeAlert(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── POST /api/v1/alerts/acknowledge-all ──────────────────────
router.post('/alerts/acknowledge-all', async (req, res) => {
  try {
    await alertSvc.acknowledgeAll();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/history ───────────────────────────────────────
router.get('/history', async (req, res) => {
  try {
    const limit      = Math.min(parseInt(req.query.limit  || '100'), 500);
    const offset     = parseInt(req.query.offset || '0');
    const remoteAddr = req.query.ip    || null;
    const since      = req.query.since || null;
    const records    = await loggerSvc.getHistory({ limit, offset, remoteAddr, since });
    const stats      = await loggerSvc.getStats();
    res.json({ ok: true, count: records.length, stats, records });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/history/ips ───────────────────────────────────
router.get('/history/ips', async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit || '50'), 200);
    const ips    = await loggerSvc.getUniqueRemoteIPs({ limit });
    const ipList = ips.map(r => r.remote_addr);
    const [dnsMap, geoMap, repMap] = await Promise.all([
      dnsSvc.resolveMany(ipList),
      geoSvc.getGeoMany(ipList),
      repSvc.checkReputationMany(ipList),
    ]);
    const enriched = ips.map(r => ({
      ...r,
      fqdn:       dnsMap[r.remote_addr]?.fqdn       || null,
      isPrivate:  dnsMap[r.remote_addr]?.isPrivate  || geoSvc.isPrivate(r.remote_addr),
      geo:        geoMap[r.remote_addr]              || null,
      reputation: repMap[r.remote_addr]              || null,
    }));
    res.json({ ok: true, count: enriched.length, ips: enriched });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/stats ─────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const [connStats, dnsStats, alertSummary] = await Promise.all([
      loggerSvc.getStats(),
      dnsSvc.getCacheStats(),
      alertSvc.getAlertSummary(),
    ]);
    res.json({ ok: true, connections: connStats, dnsCache: dnsStats, alerts: alertSummary });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── DELETE /api/v1/cache/dns/:ip ──────────────────────────────
router.delete('/cache/dns/:ip', async (req, res) => {
  try {
    await dnsSvc.invalidateCache(req.params.ip);
    res.json({ ok: true, message: `Caché DNS invalidada para ${req.params.ip}` });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/v1/map/data ──────────────────────────────────────
// Datos para el mapa de geolocalización
router.get('/map/data', async (req, res) => {
  try {
    const rows = await require('../db/database').db.allAsync(`
      SELECT g.ip, g.country, g.country_code, g.city, g.lat, g.lon, g.isp, g.org,
             g.is_proxy, g.is_hosting,
             r.score, r.service_name, r.service_type,
             COUNT(c.id) as connection_count,
             MAX(c.captured_at) as last_seen
      FROM geo_cache g
      LEFT JOIN connections c ON c.remote_addr = g.ip
      LEFT JOIN reputation_cache r ON r.ip = g.ip
      WHERE g.lat IS NOT NULL AND g.lon IS NOT NULL
        AND g.country_code != 'XX'
      GROUP BY g.ip
      ORDER BY last_seen DESC
      LIMIT 200
    `);
    res.json({ ok: true, count: rows.length, points: rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;

// ── Firewall / Bloqueo ────────────────────────────────────────
const firewallSvc = require('../services/firewall.service');

// GET /api/v1/blocked — lista de IPs bloqueadas
router.get('/blocked', async (req, res) => {
  try {
    const status  = req.query.status || null; // 'active' | 'reverted' | null
    const records = await firewallSvc.getBlockedIPs({ status });
    res.json({ ok: true, count: records.length, records });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/v1/block — bloquear una conexión
router.post('/block', async (req, res) => {
  const { ip, port, pid } = req.body;
  if (!ip) return res.status(400).json({ ok: false, error: 'IP requerida' });
  try {
    const result = await firewallSvc.blockConnection({ ip, port, pid });
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/v1/unblock/:id — rollback de bloqueo
router.post('/unblock/:id', async (req, res) => {
  try {
    const result = await firewallSvc.unblockConnection(parseInt(req.params.id));
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /api/v1/admin-check — verifica privilegios de administrador
router.get('/admin-check', (_req, res) => {
  const isAdmin = firewallSvc.checkAdminPrivileges();
  res.json({ ok: true, isAdmin });
});
