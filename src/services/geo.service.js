// src/services/geo.service.js
// Geolocalización de IPs via ip-api.com (gratis, sin API key)
// Límite: 45 req/min — manejado con caché SQLite

const fetch  = require('node-fetch');
const { db } = require('../db/database');

const GEO_TTL    = 60 * 60 * 24; // 24 horas en caché
const BATCH_SIZE = 100;           // ip-api soporta batch de hasta 100 IPs
const API_URL    = 'http://ip-api.com/batch';

const PRIVATE_RANGES = [
  /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^127\./, /^169\.254\./, /^::1$/, /^fe80:/i,
];

function isPrivate(ip) {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

/**
 * Obtiene geolocalización de una IP (con caché)
 */
async function getGeo(ip) {
  if (!ip || isPrivate(ip)) {
    return { ip, country: 'Privada', country_code: 'XX', city: 'Red local', isp: '', is_private: true };
  }

  // 1. Buscar en caché
  const cached = await db.getAsync('SELECT * FROM geo_cache WHERE ip = ?', [ip]);
  if (cached) {
    const ageSeconds = (Date.now() - new Date(cached.cached_at + 'Z').getTime()) / 1000;
    if (ageSeconds < GEO_TTL) return { ...cached, fromCache: true };
  }

  // 2. Consultar ip-api.com
  try {
    const res  = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,proxy,hosting`);
    const data = await res.json();

    if (data.status !== 'success') return { ip, country: 'Desconocido', fromCache: false };

    const row = {
      ip,
      country:      data.country      || null,
      country_code: data.countryCode  || null,
      region:       data.regionName   || null,
      city:         data.city         || null,
      isp:          data.isp          || null,
      org:          data.org          || null,
      as_number:    data.as           || null,
      lat:          data.lat          || null,
      lon:          data.lon          || null,
      is_proxy:     data.proxy  ? 1 : 0,
      is_hosting:   data.hosting ? 1 : 0,
    };

    await db.runAsync(`
      INSERT INTO geo_cache (ip, country, country_code, region, city, isp, org, as_number, lat, lon, is_proxy, is_hosting)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET
        country=excluded.country, country_code=excluded.country_code,
        region=excluded.region, city=excluded.city, isp=excluded.isp,
        org=excluded.org, as_number=excluded.as_number,
        lat=excluded.lat, lon=excluded.lon,
        is_proxy=excluded.is_proxy, is_hosting=excluded.is_hosting,
        cached_at=datetime('now')
    `, [row.ip, row.country, row.country_code, row.region, row.city,
        row.isp, row.org, row.as_number, row.lat, row.lon, row.is_proxy, row.is_hosting]);

    return { ...row, fromCache: false };
  } catch (err) {
    console.error('[geo.service] Error:', err.message);
    return { ip, country: 'Error', fromCache: false };
  }
}

/**
 * Geolocaliza múltiples IPs en batch (respeta límite de 45/min)
 */
async function getGeoMany(ips) {
  const results  = {};
  const unique   = [...new Set(ips.filter(ip => ip && !isPrivate(ip)))];
  const toFetch  = [];

  // Verificar caché para cada IP
  for (const ip of unique) {
    const cached = await db.getAsync('SELECT * FROM geo_cache WHERE ip = ?', [ip]);
    if (cached) {
      const age = (Date.now() - new Date(cached.cached_at + 'Z').getTime()) / 1000;
      if (age < GEO_TTL) { results[ip] = { ...cached, fromCache: true }; continue; }
    }
    toFetch.push(ip);
  }

  // Batch fetch para las que no están en caché
  for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
    const chunk = toFetch.slice(i, i + BATCH_SIZE);
    try {
      const res  = await fetch(API_URL + '?fields=status,query,country,countryCode,regionName,city,isp,org,as,lat,lon,proxy,hosting', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(chunk.map(ip => ({ query: ip }))),
      });
      const data = await res.json();

      for (const item of data) {
        if (item.status !== 'success') continue;
        const row = {
          ip:           item.query,
          country:      item.country     || null,
          country_code: item.countryCode || null,
          region:       item.regionName  || null,
          city:         item.city        || null,
          isp:          item.isp         || null,
          org:          item.org         || null,
          as_number:    item.as          || null,
          lat:          item.lat         || null,
          lon:          item.lon         || null,
          is_proxy:     item.proxy  ? 1 : 0,
          is_hosting:   item.hosting ? 1 : 0,
        };

        await db.runAsync(`
          INSERT INTO geo_cache (ip, country, country_code, region, city, isp, org, as_number, lat, lon, is_proxy, is_hosting)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(ip) DO UPDATE SET
            country=excluded.country, country_code=excluded.country_code,
            region=excluded.region, city=excluded.city, isp=excluded.isp,
            org=excluded.org, as_number=excluded.as_number,
            lat=excluded.lat, lon=excluded.lon,
            is_proxy=excluded.is_proxy, is_hosting=excluded.is_hosting,
            cached_at=datetime('now')
        `, [row.ip, row.country, row.country_code, row.region, row.city,
            row.isp, row.org, row.as_number, row.lat, row.lon, row.is_proxy, row.is_hosting]);

        results[row.ip] = { ...row, fromCache: false };
      }

      // Respetar límite de 45 req/min si hay más chunks
      if (i + BATCH_SIZE < toFetch.length) await new Promise(r => setTimeout(r, 1400));

    } catch (err) {
      console.error('[geo.service] Batch error:', err.message);
    }
  }

  // Agregar IPs privadas
  for (const ip of ips) {
    if (!results[ip]) {
      results[ip] = isPrivate(ip)
        ? { ip, country: 'Red local', country_code: 'XX', is_private: true }
        : { ip, country: 'Desconocido' };
    }
  }

  return results;
}

module.exports = { getGeo, getGeoMany, isPrivate };
