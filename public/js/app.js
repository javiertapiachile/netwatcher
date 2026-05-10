// public/js/app.js — NetWatch Fase 2

const API = '/api/v1';

const state = {
  connections:   [],
  refreshTimer:  null,
  isLoading:     false,
  sortKey:       'remoteAddr',
  sortDir:       'asc',
  activeTab:     'live',
  map:           null,
  mapMarkers:    [],
};

const $ = id => document.getElementById(id);

// ── Utils ─────────────────────────────────────────────────────
function formatTime(iso)     { if (!iso) return '—'; return new Date(iso).toLocaleTimeString('es-CL', { hour:'2-digit', minute:'2-digit', second:'2-digit' }); }
function formatDateTime(iso) { if (!iso) return '—'; return new Date(iso).toLocaleString('es-CL'); }

function showToast(msg, type = 'info', ms = 3500) {
  const t = $('toast');
  t.textContent = msg;
  t.className   = `toast ${type}`;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), ms);
}

function setStatus(s, text) {
  $('statusDot').className  = `status-dot ${s}`;
  $('statusText').textContent = text;
}

function apiFetch(path) {
  return fetch(`${API}${path}`).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
}

// ── Badge builders ────────────────────────────────────────────
function protoBadge(p) {
  const c = p === 'TCP' ? 'proto-TCP' : p === 'UDP' ? 'proto-UDP' : '';
  return `<span class="proto-badge ${c}">${p||'?'}</span>`;
}

function stateBadge(s) {
  const map = { ESTABLISHED:'state-ESTABLISHED', TIME_WAIT:'state-TIME_WAIT',
                CLOSE_WAIT:'state-CLOSE_WAIT', LISTEN:'state-LISTEN',
                SYN_SENT:'state-SYN_SENT', STATELESS:'state-STATELESS' };
  return `<span class="state-badge ${map[s]||'state-default'}">${s||'UNKNOWN'}</span>`;
}

function repBadge(rep) {
  if (!rep) return `<span class="rep-badge rep-unknown">—</span>`;
  const icons = { CLEAN:'✓', SUSPICIOUS:'⚠', MALICIOUS:'✕' };
  return `<span class="rep-badge rep-${rep.score}" title="${rep.reasons||''}">${icons[rep.score]||'?'} ${rep.score}</span>`;
}

function svcBadge(rep) {
  if (!rep?.service_name) return '';
  return `<span class="svc-badge">${rep.icon||''} ${rep.service_name}</span>`;
}

function countryCell(geo) {
  if (!geo || geo.is_private || geo.country_code === 'XX') return '<span style="color:var(--text3)">Local</span>';
  const flag = geo.country_code ? String.fromCodePoint(...[...geo.country_code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '';
  return `<span class="cell-country"><span class="flag">${flag}</span> ${geo.city ? geo.city + ', ' : ''}${geo.country||'?'}</span>`;
}

function dnsDot(dns) {
  if (!dns) return '<span class="dns-dot empty"></span>';
  if (dns.isPrivate) return '<span class="dns-dot private"></span>';
  if (!dns.fqdn)     return '<span class="dns-dot empty"></span>';
  return dns.fromCache
    ? '<span class="dns-dot cached" title="Desde caché"></span>'
    : '<span class="dns-dot resolved" title="Resuelto en vivo"></span>';
}

// ── Conexiones activas ────────────────────────────────────────
async function loadConnections() {
  if (state.isLoading) return;
  state.isLoading = true;
  setStatus('loading', 'Escaneando...');
  $('btnRefresh').classList.add('loading');

  try {
    const data = await apiFetch('/connections');
    state.connections = data.connections || [];

    const uniqueIPs = new Set(state.connections.map(c => c.remoteAddr)).size;
    $('connCount').textContent = data.count;
    $('ipCount').textContent   = uniqueIPs;
    $('lastScan').textContent  = formatTime(data.capturedAt);

    setStatus('online', `Online · ${data.count} conexiones`);
    renderConnectionsTable(applyFilters(state.connections));
    refreshAlertBadge();
  } catch (err) {
    setStatus('offline', 'Error de conexión');
    showToast('Error al obtener conexiones: ' + err.message, 'error');
  } finally {
    state.isLoading = false;
    $('btnRefresh').classList.remove('loading');
  }
}

function applyFilters(connections) {
  const search  = $('searchInput').value.trim().toLowerCase();
  const stateF  = $('filterState').value;
  const repF    = $('filterRep').value;

  return connections.filter(c => {
    if (stateF && c.state !== stateF) return false;
    if (repF   && c.reputation?.score !== repF) return false;
    if (search) {
      const hay = [
        c.remoteAddr, c.localAddr, c.state, c.protocol,
        c.dns?.fqdn, c.geo?.country, c.geo?.city, c.geo?.org,
        c.reputation?.service_name, String(c.remotePort),
      ].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });
}

function renderConnectionsTable(connections) {
  const body = $('connBody');
  if (!connections.length) {
    body.innerHTML = `<tr class="placeholder-row"><td colspan="10"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Sin conexiones que coincidan</div></div></td></tr>`;
    return;
  }
  body.innerHTML = connections.map(c => {
    const isPrivate = c.dns?.isPrivate;
    const fqdnCell  = c.dns?.fqdn
      ? `${dnsDot(c.dns)}<span class="cell-fqdn">${c.dns.fqdn}</span>`
      : `${dnsDot(c.dns)}<span class="cell-fqdn empty">${isPrivate ? 'IP privada' : 'Sin PTR'}</span>`;
    return `<tr class="new-row">
      <td>${protoBadge(c.protocol)}</td>
      <td class="cell-local">${c.localAddr}<span class="cell-port">:${c.localPort}</span></td>
      <td class="${isPrivate ? 'cell-ip private' : 'cell-ip'}">${c.remoteAddr}</td>
      <td>${fqdnCell}</td>
      <td>${svcBadge(c.reputation)}</td>
      <td>${countryCell(c.geo)}</td>
      <td>${repBadge(c.reputation)}</td>
      <td>${stateBadge(c.state)}</td>
      <td class="cell-port">${c.remotePort}</td>
      <td><button class="btn-action" onclick="openDetail('${c.remoteAddr}')">+ INFO</button></td>
    </tr>`;
  }).join('');
}

// ── Mapa ──────────────────────────────────────────────────────
function initMap() {
  if (state.map) return;
  state.map = L.map('geoMap', { zoomControl: true }).setView([20, 0], 2);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors',
    maxZoom: 18,
  }).addTo(state.map);
}

async function loadMapData() {
  initMap();
  try {
    const data = await apiFetch('/map/data');

    // Limpiar marcadores anteriores
    state.mapMarkers.forEach(m => m.remove());
    state.mapMarkers = [];

    const scoreColors = { MALICIOUS: '#ff4d6a', SUSPICIOUS: '#ffd166', CLEAN: '#39ff8f', default: '#718096' };

    for (const p of data.points) {
      if (!p.lat || !p.lon) continue;
      const color = scoreColors[p.score] || scoreColors.default;

      const marker = L.circleMarker([p.lat, p.lon], {
        radius: Math.min(6 + (p.connection_count || 1), 14),
        fillColor: color, color: color,
        weight: 1, opacity: 0.9, fillOpacity: 0.7,
      });

      marker.bindPopup(`
        <div style="min-width:200px">
          <div style="color:${color};font-weight:700;margin-bottom:8px">${p.ip}</div>
          <div><b>País:</b> ${p.city ? p.city + ', ' : ''}${p.country || '?'}</div>
          <div><b>ISP:</b> ${p.isp || p.org || '—'}</div>
          ${p.service_name ? `<div><b>Servicio:</b> ${p.service_name}</div>` : ''}
          <div><b>Reputación:</b> <span style="color:${color}">${p.score || 'DESCONOCIDA'}</span></div>
          <div><b>Conexiones:</b> ${p.connection_count || 0}</div>
          <div><b>Última vez:</b> ${formatDateTime(p.last_seen)}</div>
          <div style="margin-top:8px">
            <button onclick="openDetail('${p.ip}')" style="background:none;border:1px solid #4a6272;color:#c9d8e8;font-size:.7rem;padding:3px 8px;border-radius:3px;cursor:pointer">+ Detalle</button>
          </div>
        </div>
      `);

      marker.addTo(state.map);
      state.mapMarkers.push(marker);
    }

    showToast(`Mapa actualizado: ${data.count} IPs geolocalizadas`, 'success');
  } catch (err) {
    showToast('Error cargando mapa: ' + err.message, 'error');
  }
}

// ── Alertas ───────────────────────────────────────────────────
async function loadAlerts() {
  const onlyUnread = $('filterUnread').checked;
  try {
    const data = await apiFetch(`/alerts${onlyUnread ? '?unread=1' : ''}`);
    renderAlerts(data.alerts, data.summary);
  } catch (err) {
    showToast('Error cargando alertas: ' + err.message, 'error');
  }
}

function renderAlerts(alerts, summary) {
  if (summary) {
    $('alertSummaryText').textContent =
      `Total: ${summary.total} | Sin leer: ${summary.unread} | Critical: ${summary.critical} | High: ${summary.high}`;
  }

  if (!alerts?.length) {
    $('alertsBody').innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>Sin alertas registradas</div></div></td></tr>`;
    return;
  }

  $('alertsBody').innerHTML = alerts.map(a => {
    const sevCls = `sev-${a.severity}`;
    const rowCls = a.acknowledged ? '' : 'alert-row-unread';
    return `<tr class="${rowCls}">
      <td style="color:var(--text3);font-size:.7rem">${formatDateTime(a.created_at)}</td>
      <td><span class="severity-badge ${sevCls}">${a.severity.toUpperCase()}</span></td>
      <td class="cell-ip">${a.ip}</td>
      <td style="color:var(--text2);font-size:.72rem">${a.rule}</td>
      <td style="font-size:.72rem;color:var(--text)">${a.details || '—'}</td>
      <td>
        ${!a.acknowledged
          ? `<button class="btn-action" onclick="acknowledgeAlert(${a.id})">✓ Leída</button>`
          : `<span style="color:var(--text3);font-size:.65rem">leída</span>`}
      </td>
    </tr>`;
  }).join('');
}

async function refreshAlertBadge() {
  try {
    const data    = await apiFetch('/stats');
    const unread  = data.alerts?.unread || 0;
    const badge   = $('alertBadge');
    const pill    = $('alertPill');
    $('alertCount').textContent = unread;

    if (unread > 0) {
      badge.textContent = unread > 99 ? '99+' : unread;
      badge.classList.remove('hidden');
      pill.classList.add('has-alerts');
    } else {
      badge.classList.add('hidden');
      pill.classList.remove('has-alerts');
    }
  } catch {}
}

async function acknowledgeAlert(id) {
  try {
    await fetch(`${API}/alerts/${id}/acknowledge`, { method: 'POST' });
    loadAlerts();
    refreshAlertBadge();
    showToast('Alerta marcada como leída', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function acknowledgeAll() {
  try {
    await fetch(`${API}/alerts/acknowledge-all`, { method: 'POST' });
    loadAlerts();
    refreshAlertBadge();
    showToast('Todas las alertas marcadas como leídas', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

// ── Modal detalle IP ──────────────────────────────────────────
async function openDetail(ip) {
  $('modalBody').innerHTML = `<div class="placeholder" style="padding:20px 0"><div class="placeholder-icon">◈</div><div>Consultando ${ip}...</div></div>`;
  $('dnsModal').classList.remove('hidden');

  try {
    const d = await apiFetch(`/resolve/${encodeURIComponent(ip)}`);
    const g = d.geo;
    const r = d.reputation;
    const flag = g?.country_code
      ? String.fromCodePoint(...[...g.country_code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65))
      : '';

    $('modalBody').innerHTML = `
      <div style="display:grid;gap:0">
        <div class="dns-row"><span class="dns-key">IP</span>           <span class="dns-value highlight">${ip}</span></div>
        <div class="dns-row"><span class="dns-key">FQDN</span>         <span class="dns-value ${d.dns?.fqdn ? 'green' : ''}">${d.dns?.fqdn || '— Sin PTR —'}</span></div>
        <div class="dns-row"><span class="dns-key">IP Privada</span>   <span class="dns-value">${d.dns?.isPrivate ? '✔ Sí (RFC 1918)' : '✘ No'}</span></div>
        ${g && !g.is_private ? `
        <div class="dns-row"><span class="dns-key">País</span>         <span class="dns-value">${flag} ${g.country || '?'}</span></div>
        <div class="dns-row"><span class="dns-key">Ciudad</span>        <span class="dns-value">${g.city || '?'}, ${g.region || ''}</span></div>
        <div class="dns-row"><span class="dns-key">ISP</span>          <span class="dns-value">${g.isp || '?'}</span></div>
        <div class="dns-row"><span class="dns-key">Organización</span> <span class="dns-value">${g.org || '?'}</span></div>
        <div class="dns-row"><span class="dns-key">ASN</span>          <span class="dns-value">${g.as_number || '?'}</span></div>
        <div class="dns-row"><span class="dns-key">Proxy/VPN</span>    <span class="dns-value">${g.is_proxy ? '⚠ Sí' : '✓ No'}</span></div>
        <div class="dns-row"><span class="dns-key">Hosting/DC</span>   <span class="dns-value">${g.is_hosting ? '⚠ Sí' : '✓ No'}</span></div>
        ` : ''}
        ${r ? `
        <div class="dns-row"><span class="dns-key">Reputación</span>   <span class="dns-value">${repBadge(r)}</span></div>
        <div class="dns-row"><span class="dns-key">Servicio</span>     <span class="dns-value">${r.service_name ? `${r.icon || ''} ${r.service_name} (${r.service_type})` : '— Desconocido —'}</span></div>
        ${r.reasons ? `<div class="dns-row"><span class="dns-key">Razones</span> <span class="dns-value" style="color:var(--yellow)">${r.reasons}</span></div>` : ''}
        ` : ''}
      </div>
      <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-action" onclick="forceRefresh('${ip}')">↻ Forzar re-consulta</button>
        <button class="btn-action" onclick="navigator.clipboard.writeText('${ip}').then(()=>showToast('IP copiada','info'))">⎘ Copiar IP</button>
      </div>`;
  } catch (err) {
    $('modalBody').innerHTML = `<div style="color:var(--red);padding:12px 0;font-size:.78rem">Error: ${err.message}</div>`;
  }
}

async function forceRefresh(ip) {
  $('modalBody').innerHTML = `<div class="placeholder" style="padding:20px 0"><div>Re-consultando...</div></div>`;
  await fetch(`${API}/cache/dns/${encodeURIComponent(ip)}`, { method: 'DELETE' });
  await openDetail(ip);
  showToast('Caché invalidada y actualizada', 'success');
}

// ── Historial ─────────────────────────────────────────────────
async function loadHistory() {
  const ip    = $('historyIP').value.trim() || null;
  const since = $('historySince').value ? new Date($('historySince').value).toISOString() : null;
  let   url   = '/history?limit=200';
  if (ip)    url += `&ip=${encodeURIComponent(ip)}`;
  if (since) url += `&since=${encodeURIComponent(since)}`;

  $('histBody').innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Cargando...</div></div></td></tr>`;
  try {
    const data = await apiFetch(url);
    if (!data.records?.length) {
      $('histBody').innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>Sin registros</div></div></td></tr>`;
      return;
    }
    $('histBody').innerHTML = data.records.map(r => `
      <tr>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.captured_at)}</td>
        <td>${protoBadge(r.protocol)}</td>
        <td class="cell-local">${r.local_addr}:${r.local_port}</td>
        <td class="cell-ip">${r.remote_addr}<span class="cell-port">:${r.remote_port}</span></td>
        <td>${stateBadge(r.state)}</td>
        <td style="color:var(--text3)">${r.pid||'—'}</td>
      </tr>`).join('');
    showToast(`${data.records.length} registros cargados`, 'success');
  } catch (err) { showToast('Error: ' + err.message, 'error'); }
}

// ── IPs únicas ────────────────────────────────────────────────
async function loadUniqueIPs() {
  $('ipsBody').innerHTML = `<tr class="placeholder-row"><td colspan="8"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Cargando...</div></div></td></tr>`;
  try {
    const data = await apiFetch('/history/ips');
    if (!data.ips?.length) {
      $('ipsBody').innerHTML = `<tr class="placeholder-row"><td colspan="8"><div class="placeholder"><div>Sin IPs en historial</div></div></td></tr>`;
      return;
    }
    $('ipsBody').innerHTML = data.ips.map(r => `
      <tr>
        <td class="${r.isPrivate ? 'cell-ip private' : 'cell-ip'}">${r.remote_addr}</td>
        <td>${r.fqdn ? `<span class="cell-fqdn">${r.fqdn}</span>` : '<span class="cell-fqdn empty">—</span>'}</td>
        <td>${svcBadge(r.reputation)}</td>
        <td>${countryCell(r.geo)}</td>
        <td>${repBadge(r.reputation)}</td>
        <td style="color:var(--yellow);text-align:center">${r.seen_count}</td>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.last_seen)}</td>
        <td><button class="btn-action" onclick="openDetail('${r.remote_addr}')">+ INFO</button></td>
      </tr>`).join('');
  } catch (err) { showToast('Error: ' + err.message, 'error'); }
}

// ── Tabs ──────────────────────────────────────────────────────
function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.tab[data-tab="${tabName}"]`)?.classList.add('active');
  document.getElementById(`tab-${tabName}`)?.classList.add('active');
  if (tabName === 'map')     loadMapData();
  if (tabName === 'alerts')  loadAlerts();
  if (tabName === 'history') {}
  if (tabName === 'ips')     loadUniqueIPs();
}

// ── Auto-refresh ──────────────────────────────────────────────
function startAutoRefresh() {
  clearInterval(state.refreshTimer);
  if (!$('autoRefresh').checked) return;
  const ms = parseInt($('refreshInterval').value, 10);
  state.refreshTimer = setInterval(loadConnections, ms);
}

// ── Init ──────────────────────────────────────────────────────
function init() {
  // Tabs
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Filtros
  $('searchInput').addEventListener('input',   () => renderConnectionsTable(applyFilters(state.connections)));
  $('filterState').addEventListener('change',  () => renderConnectionsTable(applyFilters(state.connections)));
  $('filterRep').addEventListener('change',    () => renderConnectionsTable(applyFilters(state.connections)));
  $('autoRefresh').addEventListener('change',  startAutoRefresh);
  $('refreshInterval').addEventListener('change', startAutoRefresh);
  $('btnRefresh').addEventListener('click',    loadConnections);
  $('btnHistory').addEventListener('click',    loadHistory);
  $('btnAckAll').addEventListener('click',     acknowledgeAll);
  $('filterUnread').addEventListener('change', loadAlerts);

  // Modal
  $('modalClose').addEventListener('click', () => $('dnsModal').classList.add('hidden'));
  $('dnsModal').addEventListener('click',   e => { if (e.target === $('dnsModal')) $('dnsModal').classList.add('hidden'); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') $('dnsModal').classList.add('hidden');
    if (e.key === 'F5') { e.preventDefault(); loadConnections(); }
  });

  loadConnections();
  startAutoRefresh();
  console.log('[NetWatch] v2.0 iniciado');
}

document.addEventListener('DOMContentLoaded', init);
