// src/services/geo.service.js
// Geolocalización con HTTPS, fallback automático y filtro IPv6 completo

const fetch  = require('node-fetch');
const { db } = require('../db/database');

const GEO_TTL = 60 * 60 * 24;

// ── Detección de IPs privadas (IPv4 + IPv6 completo) ──────────
const PRIVATE_V4 = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1([01]\d|2[0-7]))\./,  // RFC 6598 CGNAT
];

function isPrivate(ip) {
  if (!ip || ip === '0.0.0.0' || ip === '*') return true;

  // Limpiar IPv4-mapped IPv6 (::ffff:192.168.1.1 → 192.168.1.1)
  const mapped = ip.replace(/^::ffff:/i, '');
  if (mapped !== ip) return isPrivate(mapped);

  // IPv6 privadas / especiales
  if (ip === '::1') return true;                          // loopback
  if (ip === '::')  return true;                          // unspecified
  if (/^fe80:/i.test(ip)) return true;                   // link-local
  if (/^fc/i.test(ip) || /^fd/i.test(ip)) return true;  // unique local
  if (/^2001:db8/i.test(ip)) return true;                // documentación
  if (/^64:ff9b/i.test(ip)) return true;                 // NAT64

  // IPv4 privadas
  return PRIVATE_V4.some(r => r.test(ip));
}

// ── Proveedor 1: ipwho.is ─────────────────────────────────────
async function fetchIpwho(ip) {
  const res  = await fetch(`https://ipwho.is/${ip}`, { timeout: 8000 });
  const data = await res.json();
  if (!data.success) throw new Error('ipwho: ' + (data.message || 'failed'));
  return {
    country:      data.country            || null,
    country_code: data.country_code       || null,
    region:       data.region             || null,
    city:         data.city               || null,
    isp:          data.connection?.isp    || null,
    org:          data.connection?.org    || null,
    as_number:    data.connection?.asn    ? `AS${data.connection.asn}` : null,
    lat:          data.latitude           || null,
    lon:          data.longitude          || null,
    is_proxy:     data.security?.proxy    ? 1 : 0,
    is_hosting:   data.security?.hosting  ? 1 : 0,
  };
}

// ── Proveedor 2: freeipapi.com ────────────────────────────────
async function fetchFreeipapi(ip) {
  const res  = await fetch(`https://freeipapi.com/api/json/${ip}`, { timeout: 8000 });
  const data = await res.json();
  if (!data.ipAddress) throw new Error('freeipapi: no data');
  return {
    country:      data.countryName  || null,
    country_code: data.countryCode  || null,
    region:       data.regionName   || null,
    city:         data.cityName     || null,
    isp:          null,
    org:          null,
    as_number:    null,
    lat:          data.latitude     || null,
    lon:          data.longitude    || null,
    is_proxy:     0,
    is_hosting:   0,
  };
}

// ── Fetch con fallback ────────────────────────────────────────
async function fetchGeoData(ip) {
  const providers = [
    { name: 'ipwho.is',  fn: () => fetchIpwho(ip) },
    { name: 'freeipapi', fn: () => fetchFreeipapi(ip) },
  ];
  for (const p of providers) {
    try {
      const data = await p.fn();
      console.log(`[geo] ${ip} resuelto via ${p.name}`);
      return data;
    } catch (err) {
      console.warn(`[geo] ${p.name} falló para ${ip}: ${err.message}`);
    }
  }
  return null;
}

// ── Guardar en caché ──────────────────────────────────────────
async function saveGeoCache(ip, row) {
  await db.runAsync(`
    INSERT INTO geo_cache
      (ip, country, country_code, region, city, isp, org, as_number, lat, lon, is_proxy, is_hosting)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      country=excluded.country, country_code=excluded.country_code,
      region=excluded.region,   city=excluded.city,
      isp=excluded.isp,         org=excluded.org,
      as_number=excluded.as_number,
      lat=excluded.lat,         lon=excluded.lon,
      is_proxy=excluded.is_proxy, is_hosting=excluded.is_hosting,
      cached_at=datetime('now')
  `, [ip, row.country, row.country_code, row.region, row.city,
      row.isp, row.org, row.as_number, row.lat, row.lon,
      row.is_proxy, row.is_hosting]);
}

// ── API pública ───────────────────────────────────────────────
async function getGeo(ip) {
  if (!ip || isPrivate(ip)) {
    return { ip, country:'Red local', country_code:'XX', city:'Privada', is_private:true };
  }

  // Caché
  const cached = await db.getAsync('SELECT * FROM geo_cache WHERE ip = ?', [ip]);
  if (cached) {
    const age = (Date.now() - new Date(cached.cached_at + 'Z').getTime()) / 1000;
    if (age < GEO_TTL) return { ...cached, fromCache: true };
  }

  const data = await fetchGeoData(ip);
  if (!data) return { ip, country:'Sin datos', country_code:null, fromCache:false };

  await saveGeoCache(ip, data);
  return { ip, ...data, fromCache: false };
}

async function getGeoMany(ips, concurrency = 5) {
  const results = {};
  const unique  = [...new Set(ips.filter(ip => ip && !isPrivate(ip)))];

  // Resolver desde caché primero
  const toFetch = [];
  for (const ip of unique) {
    const cached = await db.getAsync('SELECT * FROM geo_cache WHERE ip = ?', [ip]);
    if (cached) {
      const age = (Date.now() - new Date(cached.cached_at + 'Z').getTime()) / 1000;
      if (age < GEO_TTL) { results[ip] = { ...cached, fromCache: true }; continue; }
    }
    toFetch.push(ip);
  }

  // Fetch en paralelo con límite
  for (let i = 0; i < toFetch.length; i += concurrency) {
    const chunk = toFetch.slice(i, i + concurrency);
    const resolved = await Promise.all(chunk.map(ip => getGeo(ip)));
    resolved.forEach(r => { if (r) results[r.ip] = r; });
    if (i + concurrency < toFetch.length) await new Promise(r => setTimeout(r, 300));
  }

  // Respuestas para IPs privadas o no resueltas
  for (const ip of ips) {
    if (!results[ip]) {
      results[ip] = isPrivate(ip)
        ? { ip, country:'Red local', country_code:'XX', is_private:true }
        : { ip, country:'Sin datos' };
    }
  }

  return results;
}

module.exports = { getGeo, getGeoMany, isPrivate };
