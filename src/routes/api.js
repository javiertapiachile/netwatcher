// src/routes/api.js
// Definición de todos los endpoints REST v1

const express = require('express');
const router  = express.Router();

const netstatSvc = require('../services/netstat.service');
const dnsSvc     = require('../services/dns.service');
const loggerSvc  = require('../services/logger.service');

// ─── GET /api/v1/connections ─────────────────────────────────────────────────
// Devuelve las conexiones activas + resolución DNS en batch
router.get('/connections', async (req, res) => {
  try {
    const connections = netstatSvc.getConnections();

    // Guardar snapshot en historial (en background, no bloquea respuesta)
    setImmediate(() => loggerSvc.saveSnapshot(connections));

    // Resolver todas las IPs remotas únicas en paralelo
    const remoteIPs = connections.map(c => c.remoteAddr).filter(Boolean);
    const dnsMap    = await dnsSvc.resolveMany(remoteIPs);

    // Enriquecer cada conexión con datos DNS
    const enriched = connections.map(c => ({
      ...c,
      dns: dnsMap[c.remoteAddr] || { fqdn: null, fromCache: false, isPrivate: dnsSvc.isPrivateIP(c.remoteAddr) },
    }));

    res.json({
      ok:          true,
      count:       enriched.length,
      capturedAt:  new Date().toISOString(),
      connections: enriched,
    });
  } catch (err) {
    console.error('[GET /connections]', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── GET /api/v1/resolve/:ip ─────────────────────────────────────────────────
// Resuelve una IP puntual (con opción ?force=1 para ignorar caché)
router.get('/resolve/:ip', async (req, res) => {
  const { ip } = req.params;
  const force   = req.query.force === '1';

  // Validación básica de formato IP
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  if (!ipv4.test(ip) && !ipv6.test(ip)) {
    return res.status(400).json({ ok: false, error: 'Formato de IP inválido' });
  }

  try {
    if (force) dnsSvc.invalidateCache(ip);
    const result = await dnsSvc.resolveIP(ip);
    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── GET /api/v1/history ─────────────────────────────────────────────────────
// Historial de conexiones almacenadas en SQLite
router.get('/history', (req, res) => {
  try {
    const limit      = Math.min(parseInt(req.query.limit  || '100', 10), 500);
    const offset     = parseInt(req.query.offset || '0',   10);
    const remoteAddr = req.query.ip   || null;
    const since      = req.query.since || null; // ISO datetime

    const records = loggerSvc.getHistory({ limit, offset, remoteAddr, since });
    const stats   = loggerSvc.getStats();

    res.json({ ok: true, count: records.length, stats, records });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── GET /api/v1/history/ips ─────────────────────────────────────────────────
// IPs remotas únicas vistas históricamente
router.get('/history/ips', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const ips   = loggerSvc.getUniqueRemoteIPs({ limit });

    // Enriquecer con DNS
    const ipList = ips.map(r => r.remote_addr);
    const dnsMap = await dnsSvc.resolveMany(ipList);

    const enriched = ips.map(r => ({
      ...r,
      fqdn:      dnsMap[r.remote_addr]?.fqdn      || null,
      isPrivate: dnsMap[r.remote_addr]?.isPrivate || dnsSvc.isPrivateIP(r.remote_addr),
    }));

    res.json({ ok: true, count: enriched.length, ips: enriched });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── GET /api/v1/stats ───────────────────────────────────────────────────────
// Estadísticas generales del sistema
router.get('/stats', (req, res) => {
  try {
    const connStats = loggerSvc.getStats();
    const dnsStats  = dnsSvc.getCacheStats();
    res.json({ ok: true, connections: connStats, dnsCache: dnsStats });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── DELETE /api/v1/cache/dns/:ip ────────────────────────────────────────────
// Invalida la caché DNS de una IP
router.delete('/cache/dns/:ip', (req, res) => {
  try {
    dnsSvc.invalidateCache(req.params.ip);
    res.json({ ok: true, message: `Caché invalidada para ${req.params.ip}` });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
