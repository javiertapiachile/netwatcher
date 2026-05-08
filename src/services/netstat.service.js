// src/services/netstat.service.js
// Lee las conexiones de red activas del sistema operativo

const { execSync } = require('child_process');
const os = require('os');

/**
 * Detecta el sistema operativo y ejecuta el comando adecuado
 * para obtener conexiones de red activas.
 * @returns {Array} Lista de objetos de conexión normalizados
 */
function getConnections() {
  const platform = os.platform();

  try {
    if (platform === 'win32') {
      return parseWindows();
    } else if (platform === 'linux') {
      return parseLinux();
    } else if (platform === 'darwin') {
      return parseMacOS();
    } else {
      throw new Error(`Plataforma no soportada: ${platform}`);
    }
  } catch (err) {
    console.error('[netstat.service] Error leyendo conexiones:', err.message);
    return [];
  }
}

// ─── Windows ─────────────────────────────────────────────────────────────────

function parseWindows() {
  // netstat -ano: muestra TCP/UDP, IPs, puertos, estado y PID
  const output = execSync('netstat -ano', { encoding: 'utf8', timeout: 10000 });
  const connections = [];

  const lines = output.split('\n').slice(4); // Saltar encabezados

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;

    const protocol = parts[0]?.toUpperCase();
    if (!['TCP', 'UDP'].includes(protocol)) continue;

    const localFull  = parts[1] || '';
    const remoteFull = parts[2] || '';
    const stateOrPid = parts[3] || '';
    const pidRaw     = parts[4] || parts[3] || '0';

    const [localAddr,  localPortStr]  = splitAddrPort(localFull);
    const [remoteAddr, remotePortStr] = splitAddrPort(remoteFull);

    const state = protocol === 'TCP' ? stateOrPid : 'STATELESS';
    const pid   = parseInt(pidRaw, 10) || 0;

    if (!localAddr || !remoteAddr) continue;
    // Ignorar conexiones sin IP remota definida
    if (remoteAddr === '0.0.0.0' || remoteAddr === '*' || remoteAddr === '[::]') continue;

    connections.push({
      protocol,
      localAddr,
      localPort:  parseInt(localPortStr,  10) || 0,
      remoteAddr,
      remotePort: parseInt(remotePortStr, 10) || 0,
      state,
      pid,
      processName: null, // se enriquece si se necesita (tasklist)
    });
  }

  return deduplicateConnections(connections);
}

// ─── Linux ───────────────────────────────────────────────────────────────────

function parseLinux() {
  // ss es más moderno que netstat en Linux
  let output;
  try {
    output = execSync('ss -tunp', { encoding: 'utf8', timeout: 10000 });
  } catch {
    // fallback a netstat si ss no está disponible
    output = execSync('netstat -tunp 2>/dev/null || netstat -tun', { encoding: 'utf8', timeout: 10000 });
    return parseLinuxNetstat(output);
  }

  const connections = [];
  const lines = output.split('\n').slice(1);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;

    const protocol   = parts[0]?.toUpperCase().replace('TCP', 'TCP').replace('UDP', 'UDP');
    const state      = parts[1] === 'ESTAB' ? 'ESTABLISHED' : (parts[1] || 'UNKNOWN');
    const localFull  = parts[4] || '';
    const remoteFull = parts[5] || '';

    const [localAddr,  localPortStr]  = splitAddrPort(localFull);
    const [remoteAddr, remotePortStr] = splitAddrPort(remoteFull);

    if (!remoteAddr || remoteAddr === '0.0.0.0' || remoteAddr === '*') continue;

    connections.push({
      protocol: protocol.includes('TCP') ? 'TCP' : 'UDP',
      localAddr,
      localPort:  parseInt(localPortStr,  10) || 0,
      remoteAddr,
      remotePort: parseInt(remotePortStr, 10) || 0,
      state,
      pid:         null,
      processName: null,
    });
  }

  return deduplicateConnections(connections);
}

function parseLinuxNetstat(output) {
  const connections = [];
  const lines = output.split('\n').slice(2);

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6) continue;

    const protocol   = parts[0]?.toUpperCase();
    const localFull  = parts[3] || '';
    const remoteFull = parts[4] || '';
    const state      = parts[5] || 'UNKNOWN';

    const [localAddr,  localPortStr]  = splitAddrPort(localFull);
    const [remoteAddr, remotePortStr] = splitAddrPort(remoteFull);

    if (!remoteAddr || remoteAddr === '0.0.0.0') continue;

    connections.push({
      protocol,
      localAddr,
      localPort:  parseInt(localPortStr,  10) || 0,
      remoteAddr,
      remotePort: parseInt(remotePortStr, 10) || 0,
      state,
      pid:         null,
      processName: null,
    });
  }

  return deduplicateConnections(connections);
}

// ─── macOS ───────────────────────────────────────────────────────────────────

function parseMacOS() {
  const output = execSync('netstat -an -p tcp', { encoding: 'utf8', timeout: 10000 });
  const connections = [];
  const lines = output.split('\n').slice(2);

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6) continue;

    const protocol   = parts[0]?.toUpperCase();
    const localFull  = parts[3] || '';
    const remoteFull = parts[4] || '';
    const state      = parts[5] || 'UNKNOWN';

    const [localAddr,  localPortStr]  = splitAddrPort(localFull);
    const [remoteAddr, remotePortStr] = splitAddrPort(remoteFull);

    if (!remoteAddr || remoteAddr === '*') continue;

    connections.push({
      protocol,
      localAddr,
      localPort:  parseInt(localPortStr,  10) || 0,
      remoteAddr,
      remotePort: parseInt(remotePortStr, 10) || 0,
      state,
      pid:         null,
      processName: null,
    });
  }

  return deduplicateConnections(connections);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Separa "192.168.1.1:443" o "[::1]:443" en [addr, port]
 */
function splitAddrPort(full) {
  if (!full) return ['', ''];

  // IPv6 format: [::1]:443
  const ipv6Match = full.match(/^\[(.+)\]:(\d+)$/);
  if (ipv6Match) return [ipv6Match[1], ipv6Match[2]];

  // IPv4 format: 192.168.1.1:443
  const lastColon = full.lastIndexOf(':');
  if (lastColon === -1) return [full, '0'];

  return [full.substring(0, lastColon), full.substring(lastColon + 1)];
}

/**
 * Elimina conexiones duplicadas (misma IP remota + puerto remoto)
 */
function deduplicateConnections(connections) {
  const seen = new Set();
  return connections.filter(c => {
    const key = `${c.protocol}|${c.remoteAddr}|${c.remotePort}|${c.localAddr}|${c.localPort}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { getConnections };
