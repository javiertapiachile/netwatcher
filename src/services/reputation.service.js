// src/services/reputation.service.js
// Reputación de IPs usando blocklists públicas gratuitas + datos de ip-api
// Sin API keys requeridas

const fetch  = require('node-fetch');
const { db } = require('../db/database');
const path   = require('path');
const fs     = require('fs');

const BLOCKLIST_DIR = process.env.BLOCKLIST_DIR || './data/blocklists';
const REP_TTL       = 60 * 60 * 6; // Re-chequear cada 6 horas

// Blocklists públicas gratuitas
const BLOCKLIST_SOURCES = [
  {
    name:   'feodo_tracker',
    label:  'Feodo Tracker (Botnets bancarias)',
    url:    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    parser: parseLineByLine,
  },
  {
    name:   'emerging_threats',
    label:  'Emerging Threats (Comprometidas)',
    url:    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    parser: parseLineByLine,
  },
];

// Rangos de proveedores conocidos para identificar servicios
const KNOWN_SERVICES = [
  { pattern: /microsoft|azure|msn|hotmail|live\.com|onedrive|teams|outlook/i, name: 'Microsoft',  type: 'cloud',     icon: '🪟' },
  { pattern: /google|gmail|youtube|gstatic|googlevideo/i,                     name: 'Google',     type: 'cloud',     icon: '🔵' },
  { pattern: /amazon|aws|cloudfront/i,                                         name: 'Amazon AWS', type: 'cloud',     icon: '🟠' },
  { pattern: /cloudflare/i,                                                    name: 'Cloudflare', type: 'cdn',       icon: '🟡' },
  { pattern: /akamai/i,                                                        name: 'Akamai',     type: 'cdn',       icon: '🔷' },
  { pattern: /fastly/i,                                                        name: 'Fastly',     type: 'cdn',       icon: '🔷' },
  { pattern: /meta|facebook|instagram|whatsapp/i,                             name: 'Meta',       type: 'social',    icon: '🔵' },
  { pattern: /apple|icloud/i,                                                  name: 'Apple',      type: 'cloud',     icon: '🍎' },
  { pattern: /netflix/i,                                                       name: 'Netflix',    type: 'streaming', icon: '🎬' },
  { pattern: /spotify/i,                                                       name: 'Spotify',    type: 'streaming', icon: '🎵' },
  { pattern: /dropbox/i,                                                       name: 'Dropbox',    type: 'cloud',     icon: '📦' },
  { pattern: /github/i,                                                        name: 'GitHub',     type: 'dev',       icon: '🐙' },
  { pattern: /zoom/i,                                                          name: 'Zoom',       type: 'comms',     icon: '📹' },
  { pattern: /slack/i,                                                         name: 'Slack',      type: 'comms',     icon: '💬' },
  { pattern: /twitch/i,                                                        name: 'Twitch',     type: 'streaming', icon: '🎮' },
  { pattern: /tor-exit|torproject/i,                                          name: 'Tor',        type: 'anonymizer',icon: '🧅' },
];

// ── Parser de blocklists ──────────────────────────────────────
function parseLineByLine(text) {
  const ips = new Set();
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const ip = trimmed.split(/\s+/)[0];
    if (ipv4.test(ip)) ips.add(ip);
  }
  return ips;
}

// ── Carga/descarga de blocklists ──────────────────────────────
let blocklistCache = new Map(); // name -> Set de IPs

async function loadBlocklists() {
  if (!fs.existsSync(BLOCKLIST_DIR)) fs.mkdirSync(BLOCKLIST_DIR, { recursive: true });

  for (const source of BLOCKLIST_SOURCES) {
    const filePath  = path.join(BLOCKLIST_DIR, `${source.name}.txt`);
    const metaPath  = path.join(BLOCKLIST_DIR, `${source.name}.meta.json`);
    let   needFetch = true;

    // Verificar si el archivo local está vigente (< 24h)
    if (fs.existsSync(metaPath)) {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      const age  = (Date.now() - new Date(meta.fetchedAt).getTime()) / 1000;
      if (age < 86400 && fs.existsSync(filePath)) needFetch = false;
    }

    if (needFetch) {
      console.log(`[reputation] Descargando blocklist: ${source.label}...`);
      try {
        const res  = await fetch(source.url, { timeout: 15000 });
        const text = await res.text();
        fs.writeFileSync(filePath, text, 'utf8');
        fs.writeFileSync(metaPath, JSON.stringify({ fetchedAt: new Date().toISOString(), source: source.url }));
        console.log(`[reputation] Blocklist ${source.name} actualizada.`);
      } catch (err) {
        console.warn(`[reputation] No se pudo descargar ${source.name}: ${err.message}`);
        if (!fs.existsSync(filePath)) continue;
      }
    }

    // Cargar en memoria
    try {
      const text = fs.readFileSync(filePath, 'utf8');
      blocklistCache.set(source.name, source.parser(text));
      console.log(`[reputation] ${source.name}: ${blocklistCache.get(source.name).size} IPs cargadas`);
    } catch (err) {
      console.warn(`[reputation] Error cargando ${source.name}:`, err.message);
    }
  }
}

/**
 * Identifica el servicio conocido por nombre de org/ISP
 */
function identifyService(org, isp) {
  const text = `${org || ''} ${isp || ''}`;
  for (const svc of KNOWN_SERVICES) {
    if (svc.pattern.test(text)) return { service_name: svc.name, service_type: svc.type, icon: svc.icon };
  }
  return { service_name: null, service_type: null, icon: null };
}

/**
 * Evalúa la reputación de una IP
 */
async function checkReputation(ip, geoData = null) {
  if (!ip) return null;

  // Verificar caché
  const cached = await db.getAsync('SELECT * FROM reputation_cache WHERE ip = ?', [ip]);
  if (cached) {
    const age = (Date.now() - new Date(cached.checked_at + 'Z').getTime()) / 1000;
    if (age < REP_TTL) return { ...cached, fromCache: true };
  }

  const hits    = [];
  let   score   = 'CLEAN';
  const reasons = [];

  // 1. Verificar blocklists en memoria
  for (const [name, ipSet] of blocklistCache.entries()) {
    if (ipSet.has(ip)) {
      const source = BLOCKLIST_SOURCES.find(s => s.name === name);
      hits.push(name);
      reasons.push(`Encontrada en ${source?.label || name}`);
      score = 'MALICIOUS';
    }
  }

  // 2. Verificar flags de ip-api (proxy/hosting)
  if (geoData) {
    if (geoData.is_proxy) {
      reasons.push('IP identificada como proxy/VPN');
      if (score === 'CLEAN') score = 'SUSPICIOUS';
    }
    if (geoData.is_hosting && score === 'CLEAN') {
      reasons.push('IP de datacenter/hosting');
      score = 'SUSPICIOUS';
    }
  }

  // 3. Identificar servicio
  const serviceInfo = identifyService(geoData?.org, geoData?.isp);

  // Si es un servicio conocido y confiable, limpiar flag de hosting
  if (serviceInfo.service_name && ['Microsoft','Google','Amazon AWS','Apple','Cloudflare','Akamai','Fastly'].includes(serviceInfo.service_name)) {
    if (score === 'SUSPICIOUS' && reasons.includes('IP de datacenter/hosting')) {
      score = 'CLEAN';
      reasons.length = 0;
      reasons.push(`Servicio conocido: ${serviceInfo.service_name}`);
    }
  }

  const result = {
    ip,
    score,
    reasons:        reasons.join('; ') || null,
    blocklist_hits: hits.join(',')     || null,
    service_name:   serviceInfo.service_name,
    service_type:   serviceInfo.service_type,
    icon:           serviceInfo.icon,
  };

  // Guardar en caché
  await db.runAsync(`
    INSERT INTO reputation_cache (ip, score, reasons, blocklist_hits, service_name, service_type)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      score=excluded.score, reasons=excluded.reasons,
      blocklist_hits=excluded.blocklist_hits,
      service_name=excluded.service_name, service_type=excluded.service_type,
      checked_at=datetime('now')
  `, [ip, score, result.reasons, result.blocklist_hits, result.service_name, result.service_type]);

  return { ...result, fromCache: false };
}

async function checkReputationMany(ips, geoMap = {}) {
  const results = {};
  for (const ip of [...new Set(ips.filter(Boolean))]) {
    results[ip] = await checkReputation(ip, geoMap[ip] || null);
  }
  return results;
}

module.exports = { loadBlocklists, checkReputation, checkReputationMany, identifyService };
