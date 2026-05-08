// public/js/app.js
// NetWatch Frontend — Lógica completa de la interfaz

const API = '/api/v1';

// ── Estado de la app ──────────────────────────────────────────
const state = {
  connections:     [],
  filteredConns:   [],
  refreshTimer:    null,
  isLoading:       false,
  sortKey:         'remoteAddr',
  sortDir:         'asc',
  activeTab:       'live',
};

// ── Elementos del DOM ─────────────────────────────────────────
const $ = id => document.getElementById(id);
const el = {
  statusDot:     $('statusDot'),
  statusText:    $('statusText'),
  connCount:     $('connCount'),
  ipCount:       $('ipCount'),
  lastScan:      $('lastScan'),
  connBody:      $('connBody'),
  histBody:      $('histBody'),
  ipsBody:       $('ipsBody'),
  searchInput:   $('searchInput'),
  filterState:   $('filterState'),
  filterProto:   $('filterProto'),
  autoRefresh:   $('autoRefresh'),
  refreshInterval: $('refreshInterval'),
  btnRefresh:    $('btnRefresh'),
  refreshIcon:   $('refreshIcon'),
  btnHistory:    $('btnHistory'),
  historyIP:     $('historyIP'),
  historySince:  $('historySince'),
  dnsModal:      $('dnsModal'),
  modalBody:     $('modalBody'),
  modalClose:    $('modalClose'),
  toast:         $('toast'),
};

// ── Utilidades ────────────────────────────────────────────────

function formatTime(isoStr) {
  if (!isoStr) return '—';
  const d = new Date(isoStr);
  return d.toLocaleTimeString('es-CL', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDateTime(isoStr) {
  if (!isoStr) return '—';
  const d = new Date(isoStr);
  return d.toLocaleString('es-CL');
}

function showToast(msg, type = 'info', duration = 3000) {
  el.toast.textContent = msg;
  el.toast.className   = `toast ${type}`;
  clearTimeout(el.toast._timer);
  el.toast._timer = setTimeout(() => el.toast.classList.add('hidden'), duration);
}

function setStatus(state, text) {
  el.statusDot.className  = `status-dot ${state}`;
  el.statusText.textContent = text;
}

function stateBadge(state) {
  const cls = [
    'ESTABLISHED','TIME_WAIT','CLOSE_WAIT','LISTEN','SYN_SENT','STATELESS'
  ].includes(state) ? `state-${state}` : 'state-default';
  return `<span class="state-badge ${cls}">${state || 'UNKNOWN'}</span>`;
}

function protoBadge(proto) {
  const cls = ['TCP','UDP'].includes(proto) ? `proto-${proto}` : '';
  return `<span class="proto-badge ${cls}">${proto || '?'}</span>`;
}

function dnsDot(dns) {
  if (!dns) return '<span class="dns-dot empty"></span>';
  if (dns.isPrivate)  return '<span class="dns-dot private"></span>';
  if (!dns.fqdn)      return '<span class="dns-dot empty"></span>';
  if (dns.fromCache)  return '<span class="dns-dot cached" title="Desde caché"></span>';
  return '<span class="dns-dot resolved" title="Resuelto en vivo"></span>';
}

function getNestedValue(obj, key) {
  return key.split('.').reduce((o, k) => o?.[k], obj);
}

// ── Fetch helpers ─────────────────────────────────────────────

async function apiFetch(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Carga de conexiones activas ───────────────────────────────

async function loadConnections() {
  if (state.isLoading) return;
  state.isLoading = true;

  setStatus('loading', 'Escaneando...');
  el.btnRefresh.classList.add('loading');

  try {
    const data = await apiFetch('/connections');

    state.connections = data.connections || [];
    setStatus('online', `Online · ${data.count} conexiones`);

    // Stats header
    const uniqueIPs = new Set(state.connections.map(c => c.remoteAddr)).size;
    el.connCount.textContent = data.count;
    el.ipCount.textContent   = uniqueIPs;
    el.lastScan.textContent  = formatTime(data.capturedAt);

    applyFiltersAndRender();

  } catch (err) {
    setStatus('offline', 'Error de conexión');
    showToast('Error al obtener conexiones: ' + err.message, 'error');
    console.error(err);
  } finally {
    state.isLoading = false;
    el.btnRefresh.classList.remove('loading');
  }
}

// ── Filtros y orden ───────────────────────────────────────────

function applyFiltersAndRender() {
  const search    = el.searchInput.value.trim().toLowerCase();
  const stateF    = el.filterState.value;
  const protoF    = el.filterProto.value;

  let filtered = state.connections.filter(c => {
    if (stateF && c.state !== stateF)        return false;
    if (protoF && c.protocol !== protoF)     return false;
    if (search) {
      const haystack = [
        c.remoteAddr, c.localAddr, c.state,
        c.protocol, c.processName,
        c.dns?.fqdn,
        String(c.remotePort), String(c.localPort),
      ].filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  // Ordenar
  filtered.sort((a, b) => {
    const av = getNestedValue(a, state.sortKey) ?? '';
    const bv = getNestedValue(b, state.sortKey) ?? '';
    const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
    return state.sortDir === 'asc' ? cmp : -cmp;
  });

  state.filteredConns = filtered;
  renderConnectionsTable(filtered);
}

// ── Render: tabla de conexiones ───────────────────────────────

function renderConnectionsTable(connections) {
  if (!connections.length) {
    el.connBody.innerHTML = `
      <tr class="placeholder-row">
        <td colspan="7">
          <div class="placeholder">
            <div class="placeholder-icon">◈</div>
            <div>Sin conexiones que coincidan con los filtros</div>
          </div>
        </td>
      </tr>`;
    return;
  }

  el.connBody.innerHTML = connections.map(c => {
    const isPrivate = c.dns?.isPrivate;
    const fqdnText  = c.dns?.fqdn
      ? `${dnsDot(c.dns)}<span class="cell-fqdn">${c.dns.fqdn}</span>`
      : `${dnsDot(c.dns)}<span class="cell-fqdn empty">${isPrivate ? 'IP privada' : 'Sin PTR'}</span>`;

    return `
      <tr class="new-row">
        <td>${protoBadge(c.protocol)}</td>
        <td class="cell-local">${c.localAddr}<span class="cell-port">:${c.localPort}</span></td>
        <td class="${isPrivate ? 'cell-ip private' : 'cell-ip'}">${c.remoteAddr}</td>
        <td>${fqdnText}</td>
        <td>${stateBadge(c.state)}</td>
        <td class="cell-port">${c.remotePort}</td>
        <td>
          <button class="btn-action" onclick="openDnsDetail('${c.remoteAddr}')">DNS ↗</button>
        </td>
      </tr>`;
  }).join('');
}

// ── Modal de detalle DNS ──────────────────────────────────────

async function openDnsDetail(ip) {
  el.modalBody.innerHTML = `<div class="placeholder" style="padding:20px 0"><div class="placeholder-icon">◈</div><div>Resolviendo ${ip}...</div></div>`;
  el.dnsModal.classList.remove('hidden');

  try {
    const data = await apiFetch(`/resolve/${encodeURIComponent(ip)}`);
    el.modalBody.innerHTML = `
      <div class="dns-row"><span class="dns-key">IP</span>        <span class="dns-value highlight">${data.ip}</span></div>
      <div class="dns-row"><span class="dns-key">FQDN</span>      <span class="dns-value ${data.fqdn ? 'green' : ''}">${data.fqdn || '— Sin registro PTR —'}</span></div>
      <div class="dns-row"><span class="dns-key">IP Privada</span><span class="dns-value">${data.isPrivate ? '✔ Sí (RFC 1918)' : '✘ No (pública)'}</span></div>
      <div class="dns-row"><span class="dns-key">Desde caché</span><span class="dns-value">${data.fromCache ? `✔ Sí (hace ${data.ageSeconds}s)` : '✘ Consultado ahora'}</span></div>
      <div style="margin-top:14px; display:flex; gap:8px;">
        <button class="btn-action" onclick="forceRefreshDns('${ip}')">↻ Forzar re-consulta</button>
        <button class="btn-action" onclick="copyToClipboard('${ip}')">⎘ Copiar IP</button>
      </div>
    `;
  } catch (err) {
    el.modalBody.innerHTML = `<div style="color:var(--red);font-size:.78rem;padding:12px 0">Error: ${err.message}</div>`;
  }
}

async function forceRefreshDns(ip) {
  el.modalBody.innerHTML = `<div class="placeholder" style="padding:20px 0"><div>Re-consultando DNS...</div></div>`;
  try {
    await apiFetch(`/resolve/${encodeURIComponent(ip)}?force=1`);
    await openDnsDetail(ip);
    showToast('Caché DNS invalidada y actualizada', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => showToast('IP copiada al portapapeles', 'info'));
}

// ── Tab: Historial ────────────────────────────────────────────

async function loadHistory() {
  const ip    = el.historyIP.value.trim() || null;
  const since = el.historySince.value ? new Date(el.historySince.value).toISOString() : null;

  let url = `/history?limit=200`;
  if (ip)    url += `&ip=${encodeURIComponent(ip)}`;
  if (since) url += `&since=${encodeURIComponent(since)}`;

  el.histBody.innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Cargando...</div></div></td></tr>`;

  try {
    const data = await apiFetch(url);

    if (!data.records?.length) {
      el.histBody.innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>Sin registros encontrados</div></div></td></tr>`;
      return;
    }

    el.histBody.innerHTML = data.records.map(r => `
      <tr>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.captured_at)}</td>
        <td>${protoBadge(r.protocol)}</td>
        <td class="cell-local">${r.local_addr}:${r.local_port}</td>
        <td class="cell-ip">${r.remote_addr}<span class="cell-port">:${r.remote_port}</span></td>
        <td>${stateBadge(r.state)}</td>
        <td style="color:var(--text3)">${r.pid || '—'}</td>
      </tr>`).join('');

    showToast(`${data.records.length} registros cargados`, 'success');
  } catch (err) {
    showToast('Error cargando historial: ' + err.message, 'error');
  }
}

// ── Tab: IPs únicas ───────────────────────────────────────────

async function loadUniqueIPs() {
  el.ipsBody.innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Cargando IPs únicas...</div></div></td></tr>`;

  try {
    const data = await apiFetch('/history/ips');

    if (!data.ips?.length) {
      el.ipsBody.innerHTML = `<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>Sin IPs en historial aún</div></div></td></tr>`;
      return;
    }

    el.ipsBody.innerHTML = data.ips.map(r => `
      <tr>
        <td class="${r.isPrivate ? 'cell-ip private' : 'cell-ip'}">${r.remote_addr}</td>
        <td>${r.fqdn ? `<span class="cell-fqdn">${r.fqdn}</span>` : '<span class="cell-fqdn empty">—</span>'}</td>
        <td style="color:var(--yellow);text-align:center">${r.seen_count}</td>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.last_seen)}</td>
        <td><span class="state-badge ${r.isPrivate ? 'state-LISTEN' : 'state-default'}">${r.isPrivate ? 'PRIVADA' : 'PÚBLICA'}</span></td>
        <td><button class="btn-action" onclick="openDnsDetail('${r.remote_addr}')">DNS ↗</button></td>
      </tr>`).join('');
  } catch (err) {
    showToast('Error cargando IPs: ' + err.message, 'error');
  }
}

// ── Auto-refresh ──────────────────────────────────────────────

function startAutoRefresh() {
  stopAutoRefresh();
  if (!el.autoRefresh.checked) return;
  const interval = parseInt(el.refreshInterval.value, 10);
  state.refreshTimer = setInterval(loadConnections, interval);
}

function stopAutoRefresh() {
  clearInterval(state.refreshTimer);
  state.refreshTimer = null;
}

// ── Sorting en headers ────────────────────────────────────────

function setupSorting() {
  document.querySelectorAll('.conn-table thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        state.sortKey = key;
        state.sortDir = 'asc';
      }
      document.querySelectorAll('.conn-table thead th').forEach(h => h.classList.remove('sorted'));
      th.classList.add('sorted');
      applyFiltersAndRender();
    });
  });
}

// ── Tabs ──────────────────────────────────────────────────────

function setupTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      state.activeTab = tab;

      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      $(`tab-${tab}`).classList.add('active');

      // Cargar datos al cambiar de tab
      if (tab === 'history') loadHistory();
      if (tab === 'ips')     loadUniqueIPs();
    });
  });
}

// ── Event listeners ───────────────────────────────────────────

function setupListeners() {
  el.btnRefresh.addEventListener('click', loadConnections);
  el.btnHistory.addEventListener('click', loadHistory);

  el.searchInput.addEventListener('input', applyFiltersAndRender);
  el.filterState.addEventListener('change', applyFiltersAndRender);
  el.filterProto.addEventListener('change', applyFiltersAndRender);

  el.autoRefresh.addEventListener('change', () => {
    if (el.autoRefresh.checked) startAutoRefresh();
    else stopAutoRefresh();
  });
  el.refreshInterval.addEventListener('change', startAutoRefresh);

  el.modalClose.addEventListener('click', () => el.dnsModal.classList.add('hidden'));
  el.dnsModal.addEventListener('click', e => {
    if (e.target === el.dnsModal) el.dnsModal.classList.add('hidden');
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') el.dnsModal.classList.add('hidden');
    if (e.key === 'F5') { e.preventDefault(); loadConnections(); }
  });
}

// ── Init ──────────────────────────────────────────────────────

function init() {
  setupTabs();
  setupSorting();
  setupListeners();
  loadConnections();
  startAutoRefresh();
  console.log('[NetWatch] Frontend iniciado ✓');
}

document.addEventListener('DOMContentLoaded', init);
