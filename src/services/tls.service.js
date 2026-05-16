// src/services/tls.service.js
const forge = require('node-forge');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

const CERT_DIR  = process.env.CERT_DIR  || './certs';
const CERT_FILE = path.join(CERT_DIR, 'netwatch.crt');
const KEY_FILE  = path.join(CERT_DIR, 'netwatch.key');
const CERT_DAYS = 730;

// Regex IPv4 e IPv6 válidos (excluye 'localhost' y hostnames)
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function isValidIP(str) {
  return IPV4_RE.test(str) || IPV6_RE.test(str);
}

function getLocalIPs() {
  const ifaces = os.networkInterfaces();
  const ips = new Set(['127.0.0.1']);
  for (const iface of Object.values(ifaces)) {
    for (const addr of iface) {
      if (addr.family === 'IPv4' && !addr.internal) ips.add(addr.address);
      if (addr.family === 'IPv6' && !addr.internal) ips.add(addr.address);
    }
  }
  return [...ips].filter(isValidIP); // Solo IPs válidas, nunca hostnames
}

function generateCertificate() {
  console.log('[tls] Generando certificado autofirmado...');
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey    = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + CERT_DAYS);

  const hostname = os.hostname();
  const attrs = [
    { name: 'commonName',             value: hostname },
    { name: 'organizationName',       value: 'NetWatch' },
    { name: 'organizationalUnitName', value: 'Network Monitor' },
    { name: 'countryName',            value: 'CL' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  const localIPs = getLocalIPs();

  // SANs: DNS entries para hostnames, IP entries solo para IPs válidas
  const altNames = [
    { type: 2, value: hostname },    // DNS — hostname del equipo
    { type: 2, value: 'localhost' }, // DNS — localhost como nombre
    ...localIPs.map(ip => ({ type: 7, ip })), // IP — solo IPs válidas
  ];

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  fs.writeFileSync(CERT_FILE, forge.pki.certificateToPem(cert));
  fs.writeFileSync(KEY_FILE,  forge.pki.privateKeyToPem(keys.privateKey));
  try { fs.chmodSync(KEY_FILE, 0o600); } catch {}

  console.log(`[tls] Certificado generado — válido hasta ${cert.validity.notAfter.toLocaleDateString()}`);
  console.log(`[tls] SANs IP: ${localIPs.join(', ')}`);

  return { certPath: CERT_FILE, keyPath: KEY_FILE };
}

function loadOrGenerateCert() {
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
    try {
      const cert     = forge.pki.certificateFromPem(fs.readFileSync(CERT_FILE, 'utf8'));
      const daysLeft = (cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24);
      if (daysLeft > 30) {
        console.log(`[tls] Certificado existente válido (${Math.round(daysLeft)} días restantes)`);
        return { certPath: CERT_FILE, keyPath: KEY_FILE };
      }
      console.log('[tls] Certificado próximo a expirar, regenerando...');
    } catch {
      console.log('[tls] Certificado inválido, regenerando...');
    }
  }
  return generateCertificate();
}

function getCertInfo() {
  if (!fs.existsSync(CERT_FILE)) return null;
  try {
    const cert     = forge.pki.certificateFromPem(fs.readFileSync(CERT_FILE, 'utf8'));
    const daysLeft = Math.round((cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24));
    return {
      validFrom:  cert.validity.notBefore.toISOString(),
      validUntil: cert.validity.notAfter.toISOString(),
      daysLeft,
      subject:    cert.subject.getField('CN')?.value,
    };
  } catch { return null; }
}

module.exports = { loadOrGenerateCert, getCertInfo, generateCertificate };
