// public/js/app.js — NetWatch v2.1

const API = '/api/v1';

const state = {
  connections:      [],
  refreshTimer:     null,
  isLoading:        false,
  activeTab:        'live',
  activeBlockedTab: 'active',
  map:              null,
  mapMarkers:       [],
  isAdmin:          false,
  blockedIPs:       new Set(),
  pendingBlock:     null,
};

const $ = id => document.getElementById(id);

// ── Utils ─────────────────────────────────────────────────────
function formatTime(iso)     { if (!iso) return '—'; return new Date(iso).toLocaleTimeString('es-CL',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
function formatDateTime(iso) { if (!iso) return '—'; return new Date(iso).toLocaleString('es-CL'); }

function showToast(msg, type='info', ms=3500) {
  const t = $('toast');
  t.textContent = msg; t.className = `toast ${type}`;
  clearTimeout(t._t); t._t = setTimeout(()=>t.classList.add('hidden'), ms);
}
function setStatus(s,text) { $('statusDot').className=`status-dot ${s}`; $('statusText').textContent=text; }
async function apiFetch(path, opts={}) {
  const r = await fetch(`${API}${path}`, opts);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── Badges ────────────────────────────────────────────────────
function protoBadge(p)  { const c=p==='TCP'?'proto-TCP':p==='UDP'?'proto-UDP':''; return `<span class="proto-badge ${c}">${p||'?'}</span>`; }
function stateBadge(s)  {
  const m={ESTABLISHED:'state-ESTABLISHED',TIME_WAIT:'state-TIME_WAIT',CLOSE_WAIT:'state-CLOSE_WAIT',LISTEN:'state-LISTEN',SYN_SENT:'state-SYN_SENT',STATELESS:'state-STATELESS'};
  return `<span class="state-badge ${m[s]||'state-default'}">${s||'UNKNOWN'}</span>`;
}
function repBadge(rep)  {
  if (!rep) return `<span class="rep-badge rep-unknown">—</span>`;
  const i={CLEAN:'✓',SUSPICIOUS:'⚠',MALICIOUS:'✕'};
  return `<span class="rep-badge rep-${rep.score}" title="${rep.reasons||''}">${i[rep.score]||'?'} ${rep.score}</span>`;
}
function svcBadge(rep)  { if (!rep?.service_name) return ''; return `<span class="svc-badge">${rep.icon||''} ${rep.service_name}</span>`; }
function dnsDot(dns)    {
  if (!dns) return '<span class="dns-dot empty"></span>';
  if (dns.isPrivate) return '<span class="dns-dot private"></span>';
  if (!dns.fqdn) return '<span class="dns-dot empty"></span>';
  return dns.fromCache?'<span class="dns-dot cached"></span>':'<span class="dns-dot resolved"></span>';
}
function countryCell(geo) {
  if (!geo||geo.is_private||geo.country_code==='XX') return '<span style="color:var(--text3)">Local</span>';
  const f = geo.country_code ? String.fromCodePoint(...[...geo.country_code.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65)) : '';
  return `<span class="cell-country"><span class="flag">${f}</span> ${geo.city?geo.city+', ':''}${geo.country||'?'}</span>`;
}
function blockBtn(conn) {
  const isBlocked = state.blockedIPs.has(conn.remoteAddr);
  if (isBlocked) return `<button class="btn-block already-blocked" disabled>✕ BLOQUEADA</button>`;
  return `<button class="btn-block" onclick="confirmBlock(${JSON.stringify({ip:conn.remoteAddr,port:conn.remotePort,pid:conn.pid}).replace(/"/g,'&quot;')})">⊘ BLOQUEAR</button>`;
}

// ── Verificar admin ───────────────────────────────────────────
async function checkAdmin() {
  try {
    const d = await apiFetch('/admin-check');
    state.isAdmin = d.isAdmin;
    if (!d.isAdmin) $('adminWarning').classList.remove('hidden');
    else $('adminWarning').classList.add('hidden');
  } catch {}
}

// ── Cargar IPs bloqueadas activas ─────────────────────────────
async function refreshBlockedSet() {
  try {
    const d = await apiFetch('/blocked?status=active');
    state.blockedIPs = new Set(d.records.map(r => r.ip));
    const count = d.records.length;
    $('blockedCount').textContent = count;
    $('blockedBadge').textContent = count;
    $('blockedBadge').style.display = count > 0 ? 'inline-block' : 'none';
  } catch {}
}

// ── Conexiones activas ────────────────────────────────────────
async function loadConnections() {
  if (state.isLoading) return;
  state.isLoading = true;
  setStatus('loading','Escaneando...');
  $('btnRefresh').classList.add('loading');
  try {
    const data = await apiFetch('/connections');
    state.connections = data.connections||[];
    $('connCount').textContent = data.count;
    $('ipCount').textContent   = new Set(state.connections.map(c=>c.remoteAddr)).size;
    $('lastScan').textContent  = formatTime(data.capturedAt);
    setStatus('online',`Online · ${data.count} conexiones`);
    await refreshBlockedSet();
    renderConnectionsTable(applyFilters(state.connections));
    refreshAlertBadge();
  } catch(err) {
    setStatus('offline','Error de conexión');
    showToast('Error: '+err.message,'error');
  } finally {
    state.isLoading=false;
    $('btnRefresh').classList.remove('loading');
  }
}

function applyFilters(conns) {
  const s=$('searchInput').value.trim().toLowerCase();
  const sf=$('filterState').value;
  const rf=$('filterRep').value;
  return conns.filter(c=>{
    if (sf&&c.state!==sf) return false;
    if (rf&&c.reputation?.score!==rf) return false;
    if (s) {
      const h=[c.remoteAddr,c.localAddr,c.state,c.protocol,c.dns?.fqdn,
               c.geo?.country,c.geo?.city,c.geo?.org,c.reputation?.service_name,
               String(c.remotePort)].filter(Boolean).join(' ').toLowerCase();
      if (!h.includes(s)) return false;
    }
    return true;
  });
}

function renderConnectionsTable(conns) {
  const body=$('connBody');
  if (!conns.length) {
    body.innerHTML=`<tr class="placeholder-row"><td colspan="10"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Sin conexiones que coincidan</div></div></td></tr>`;
    return;
  }
  body.innerHTML=conns.map(c=>{
    const isPriv=c.dns?.isPrivate;
    const fqdn=c.dns?.fqdn
      ?`${dnsDot(c.dns)}<span class="cell-fqdn">${c.dns.fqdn}</span>`
      :`${dnsDot(c.dns)}<span class="cell-fqdn empty">${isPriv?'IP privada':'Sin PTR'}</span>`;
    return `<tr class="new-row">
      <td>${protoBadge(c.protocol)}</td>
      <td class="cell-local">${c.localAddr}<span class="cell-port">:${c.localPort}</span></td>
      <td class="${isPriv?'cell-ip private':'cell-ip'}">${c.remoteAddr}</td>
      <td>${fqdn}</td>
      <td>${svcBadge(c.reputation)}</td>
      <td>${countryCell(c.geo)}</td>
      <td>${repBadge(c.reputation)}</td>
      <td>${stateBadge(c.state)}</td>
      <td class="cell-port">${c.remotePort}</td>
      <td style="display:flex;gap:4px;align-items:center">
        <button class="btn-action" onclick="openDetail('${c.remoteAddr}')">+ INFO</button>
        ${blockBtn(c)}
      </td>
    </tr>`;
  }).join('');
}

// ── Confirmar bloqueo ─────────────────────────────────────────
function confirmBlock({ip, port, pid}) {
  state.pendingBlock = {ip, port, pid};
  $('blockModalBody').innerHTML = `
    <div class="block-confirm-grid">
      <div class="dns-row"><span class="dns-key">IP a bloquear</span><span class="dns-value highlight">${ip}</span></div>
      <div class="dns-row"><span class="dns-key">Puerto remoto</span><span class="dns-value">${port||'—'}</span></div>
      <div class="dns-row"><span class="dns-key">PID proceso</span><span class="dns-value">${pid||'No disponible'}</span></div>
      <div class="dns-row"><span class="dns-key">Acción</span><span class="dns-value" style="color:var(--red)">Terminar proceso + Regla firewall Windows (entrada + salida)</span></div>
      ${!state.isAdmin?`<div style="color:var(--orange);font-size:.72rem;margin-top:8px;padding:8px;background:rgba(255,159,64,0.08);border-radius:4px;border:1px solid rgba(255,159,64,0.3)">⚠ Sin privilegios de Administrador — el bloqueo de firewall puede fallar</div>`:''}
    </div>
    <div class="block-confirm-actions">
      <button class="btn-cancel" onclick="$('blockModal').classList.add('hidden')">Cancelar</button>
      <button class="btn-confirm-block" onclick="executeBlock()">⊘ Confirmar Bloqueo</button>
    </div>`;
  $('blockModal').classList.remove('hidden');
}

async function executeBlock() {
  const {ip, port, pid} = state.pendingBlock;
  $('blockModal').classList.add('hidden');
  showToast(`Bloqueando ${ip}...`, 'info', 8000);
  try {
    const data = await apiFetch('/block', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ip, port, pid}),
    });
    if (!data.ok) { showToast('Error: '+data.error,'error',6000); return; }
    showToast(`✓ ${ip} bloqueada — regla firewall creada`,'success',5000);
    await refreshBlockedSet();
    renderConnectionsTable(applyFilters(state.connections));
  } catch(err) {
    showToast('Error de red: '+err.message,'error');
  }
}

// ── Panel de bloqueadas ───────────────────────────────────────
function switchBlockedTab(tab) {
  state.activeBlockedTab = tab;
  document.querySelectorAll('.blocked-tab').forEach(b=>b.classList.toggle('active', b.dataset.btab===tab));
  loadBlockedIPs();
}

async function loadBlockedIPs() {
  const status = state.activeBlockedTab;
  try {
    const data = await apiFetch(`/blocked?status=${status}`);
    renderBlockedTable(data.records, status);
  } catch(err) { showToast('Error: '+err.message,'error'); }
}

function renderBlockedTable(records, status) {
  const body = $('blockedBody');
  const head = $('blockedHead');

  if (status === 'active') {
    head.innerHTML = `<tr><th>IP</th><th>PUERTO</th><th>PID</th><th>REGLA FIREWALL</th><th>BLOQUEADA</th><th>ROLLBACK</th></tr>`;
  } else {
    head.innerHTML = `<tr><th>IP</th><th>PUERTO</th><th>REGLA FIREWALL</th><th>BLOQUEADA</th><th>DESBLOQUEADA</th><th>ESTADO</th></tr>`;
  }

  if (!records?.length) {
    body.innerHTML=`<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>${status==='active'?'Sin IPs bloqueadas actualmente':'Sin historial de bloqueos'}</div></div></td></tr>`;
    return;
  }

  body.innerHTML = records.map(r => {
    if (status === 'active') {
      return `<tr>
        <td class="cell-ip">${r.ip}</td>
        <td class="cell-port">${r.port||'—'}</td>
        <td style="color:var(--text3)">${r.pid||'—'}</td>
        <td style="color:var(--text2);font-size:.7rem">${r.rule_name||'—'}</td>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.blocked_at)}</td>
        <td><button class="btn-unblock" onclick="executeUnblock(${r.id},'${r.ip}')">↩ REVERTIR</button></td>
      </tr>`;
    } else {
      return `<tr>
        <td class="${r.status==='active'?'cell-ip':'cell-ip private'}">${r.ip}</td>
        <td class="cell-port">${r.port||'—'}</td>
        <td style="color:var(--text2);font-size:.7rem">${r.rule_name||'—'}</td>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.blocked_at)}</td>
        <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.unblocked_at)||'—'}</td>
        <td><span class="status-${r.status}">${r.status==='active'?'ACTIVO':'REVERTIDO'}</span></td>
      </tr>`;
    }
  }).join('');
}

async function executeUnblock(id, ip) {
  if (!confirm(`¿Revertir el bloqueo de ${ip}?\nEsto eliminará la regla del firewall de Windows.`)) return;
  showToast(`Revirtiendo bloqueo de ${ip}...`,'info',5000);
  try {
    const data = await apiFetch(`/unblock/${id}`, { method:'POST' });
    showToast(data.ok ? `✓ ${ip} desbloqueada — regla firewall eliminada` : `Advertencia: ${data.message}`, data.ok?'success':'error', 5000);
    await refreshBlockedSet();
    loadBlockedIPs();
    renderConnectionsTable(applyFilters(state.connections));
  } catch(err) { showToast('Error: '+err.message,'error'); }
}

// ── Mapa (CartoDB Dark Matter, noWrap) ────────────────────────
function initMap() {
  if (state.map) return;
  state.map = L.map('geoMap', { zoomControl:true, worldCopyJump:false }).setView([20,0],2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap contributors, © CARTO',
    subdomains: 'abcd', maxZoom: 19,
    noWrap: true,        // ← evita la repetición infinita
    bounds: [[-90,-180],[90,180]],
  }).addTo(state.map);
  // Limitar el pan al mundo
  state.map.setMaxBounds([[-90,-180],[90,180]]);
}

async function loadMapData() {
  initMap();
  try {
    const data = await apiFetch('/map/data');
    state.mapMarkers.forEach(m=>m.remove());
    state.mapMarkers=[];
    const colors={MALICIOUS:'#ff4d6a',SUSPICIOUS:'#ffd166',CLEAN:'#39ff8f',default:'#718096'};
    for (const p of data.points) {
      if (!p.lat||!p.lon) continue;
      const color=colors[p.score]||colors.default;
      const m=L.circleMarker([p.lat,p.lon],{
        radius: Math.min(5+(p.connection_count||1)*0.5,14),
        fillColor:color,color:color,weight:1,opacity:0.9,fillOpacity:0.75,
      });
      const flag=p.country_code?String.fromCodePoint(...[...p.country_code.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65)):'';
      m.bindPopup(`
        <div style="min-width:190px;font-family:monospace;font-size:.75rem">
          <div style="color:${color};font-weight:700;margin-bottom:6px;font-size:.82rem">${p.ip}</div>
          <div><b>Ubicación:</b> ${flag} ${p.city?p.city+', ':''}${p.country||'?'}</div>
          <div><b>ISP:</b> ${p.isp||p.org||'—'}</div>
          ${p.service_name?`<div><b>Servicio:</b> ${p.service_name}</div>`:''}
          <div><b>Reputación:</b> <span style="color:${color}">${p.score||'—'}</span></div>
          <div><b>Conexiones:</b> ${p.connection_count||0}</div>
          <div style="margin-top:8px;display:flex;gap:6px">
            <button onclick="openDetail('${p.ip}')" style="background:none;border:1px solid #4a6272;color:#c9d8e8;font-size:.68rem;padding:3px 7px;border-radius:3px;cursor:pointer">+ Info</button>
            ${!state.blockedIPs.has(p.ip)?`<button onclick="confirmBlock({ip:'${p.ip}',port:null,pid:null})" style="background:rgba(255,77,106,.1);border:1px solid rgba(255,77,106,.4);color:#ff4d6a;font-size:.68rem;padding:3px 7px;border-radius:3px;cursor:pointer">⊘ Bloquear</button>`:'<span style="color:var(--text3);font-size:.68rem">Bloqueada</span>'}
          </div>
        </div>`);
      m.addTo(state.map);
      state.mapMarkers.push(m);
    }
    showToast(`Mapa: ${data.count} IPs geolocalizadas`,'success');
  } catch(err) { showToast('Error mapa: '+err.message,'error'); }
}

// ── Alertas ───────────────────────────────────────────────────
async function loadAlerts() {
  const unread=$('filterUnread').checked;
  try {
    const data=await apiFetch(`/alerts${unread?'?unread=1':''}`);
    renderAlerts(data.alerts,data.summary);
  } catch(err) { showToast('Error alertas: '+err.message,'error'); }
}

function renderAlerts(alerts,summary) {
  if (summary) $('alertSummaryText').textContent=`Total: ${summary.total} | Sin leer: ${summary.unread} | Critical: ${summary.critical} | High: ${summary.high}`;
  if (!alerts?.length) {
    $('alertsBody').innerHTML=`<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>Sin alertas</div></div></td></tr>`;
    return;
  }
  $('alertsBody').innerHTML=alerts.map(a=>`
    <tr class="${a.acknowledged?'':'alert-row-unread'}">
      <td style="color:var(--text3);font-size:.7rem">${formatDateTime(a.created_at)}</td>
      <td><span class="severity-badge sev-${a.severity}">${a.severity.toUpperCase()}</span></td>
      <td class="cell-ip">${a.ip}</td>
      <td style="color:var(--text2);font-size:.72rem">${a.rule}</td>
      <td style="font-size:.72rem">${a.details||'—'}</td>
      <td>${!a.acknowledged?`<button class="btn-action" onclick="acknowledgeAlert(${a.id})">✓ Leída</button>`:'<span style="color:var(--text3);font-size:.65rem">leída</span>'}</td>
    </tr>`).join('');
}

async function refreshAlertBadge() {
  try {
    const d=await apiFetch('/stats');
    const u=d.alerts?.unread||0;
    $('alertCount').textContent=u;
    if (u>0){$('alertBadge').textContent=u>99?'99+':u;$('alertBadge').classList.remove('hidden');$('alertPill').classList.add('has-alerts');}
    else{$('alertBadge').classList.add('hidden');$('alertPill').classList.remove('has-alerts');}
  } catch{}
}

async function acknowledgeAlert(id) {
  try { await fetch(`${API}/alerts/${id}/acknowledge`,{method:'POST'}); loadAlerts(); refreshAlertBadge(); showToast('Alerta marcada','success'); }
  catch(err){ showToast('Error: '+err.message,'error'); }
}
async function acknowledgeAll() {
  try { await fetch(`${API}/alerts/acknowledge-all`,{method:'POST'}); loadAlerts(); refreshAlertBadge(); showToast('Todas leídas','success'); }
  catch(err){ showToast('Error: '+err.message,'error'); }
}

// ── Modal detalle ─────────────────────────────────────────────
async function openDetail(ip) {
  $('modalBody').innerHTML=`<div class="placeholder" style="padding:20px 0"><div class="placeholder-icon">◈</div><div>Consultando ${ip}...</div></div>`;
  $('dnsModal').classList.remove('hidden');
  try {
    const d=await apiFetch(`/resolve/${encodeURIComponent(ip)}`);
    const g=d.geo, r=d.reputation;
    const flag=g?.country_code?String.fromCodePoint(...[...g.country_code.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65)):'';
    $('modalBody').innerHTML=`
      <div>
        <div class="dns-row"><span class="dns-key">IP</span><span class="dns-value highlight">${ip}</span></div>
        <div class="dns-row"><span class="dns-key">FQDN</span><span class="dns-value ${d.dns?.fqdn?'green':''}">${d.dns?.fqdn||'— Sin PTR —'}</span></div>
        <div class="dns-row"><span class="dns-key">IP Privada</span><span class="dns-value">${d.dns?.isPrivate?'✔ Sí':'✘ No'}</span></div>
        ${g&&!g.is_private?`
        <div class="dns-row"><span class="dns-key">País</span><span class="dns-value">${flag} ${g.country||'?'}</span></div>
        <div class="dns-row"><span class="dns-key">Ciudad</span><span class="dns-value">${g.city||'?'}, ${g.region||''}</span></div>
        <div class="dns-row"><span class="dns-key">ISP</span><span class="dns-value">${g.isp||'?'}</span></div>
        <div class="dns-row"><span class="dns-key">ASN</span><span class="dns-value">${g.as_number||'?'}</span></div>
        <div class="dns-row"><span class="dns-key">Proxy/VPN</span><span class="dns-value">${g.is_proxy?'⚠ Sí':'✓ No'}</span></div>
        <div class="dns-row"><span class="dns-key">Datacenter</span><span class="dns-value">${g.is_hosting?'⚠ Sí':'✓ No'}</span></div>`:''}
        ${r?`
        <div class="dns-row"><span class="dns-key">Reputación</span><span class="dns-value">${repBadge(r)}</span></div>
        <div class="dns-row"><span class="dns-key">Servicio</span><span class="dns-value">${r.service_name?`${r.icon||''} ${r.service_name} (${r.service_type})`:'— Desconocido —'}</span></div>
        ${r.reasons?`<div class="dns-row"><span class="dns-key">Razones</span><span class="dns-value" style="color:var(--yellow)">${r.reasons}</span></div>`:''}`:'' }
      </div>
      <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-action" onclick="forceRefresh('${ip}')">↻ Re-consultar</button>
        <button class="btn-action" onclick="navigator.clipboard.writeText('${ip}').then(()=>showToast('Copiada','info'))">⎘ Copiar IP</button>
        ${!state.blockedIPs.has(ip)?`<button class="btn-block" onclick="$('dnsModal').classList.add('hidden');confirmBlock({ip:'${ip}',port:null,pid:null})">⊘ Bloquear IP</button>`:'<span style="color:var(--red);font-size:.72rem;font-weight:700">✕ IP BLOQUEADA</span>'}
      </div>`;
  } catch(err) { $('modalBody').innerHTML=`<div style="color:var(--red);padding:12px 0">Error: ${err.message}</div>`; }
}

async function forceRefresh(ip) {
  $('modalBody').innerHTML=`<div class="placeholder" style="padding:20px 0"><div>Re-consultando...</div></div>`;
  await fetch(`${API}/cache/dns/${encodeURIComponent(ip)}`,{method:'DELETE'});
  await openDetail(ip);
  showToast('Caché invalidada','success');
}

// ── Historial ─────────────────────────────────────────────────
async function loadHistory() {
  const ip=$('historyIP').value.trim()||null;
  const since=$('historySince').value?new Date($('historySince').value).toISOString():null;
  let url='/history?limit=200';
  if (ip) url+=`&ip=${encodeURIComponent(ip)}`;
  if (since) url+=`&since=${encodeURIComponent(since)}`;
  $('histBody').innerHTML=`<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Cargando...</div></div></td></tr>`;
  try {
    const d=await apiFetch(url);
    if (!d.records?.length){$('histBody').innerHTML=`<tr class="placeholder-row"><td colspan="6"><div class="placeholder"><div>Sin registros</div></div></td></tr>`;return;}
    $('histBody').innerHTML=d.records.map(r=>`<tr>
      <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.captured_at)}</td>
      <td>${protoBadge(r.protocol)}</td>
      <td class="cell-local">${r.local_addr}:${r.local_port}</td>
      <td class="cell-ip">${r.remote_addr}<span class="cell-port">:${r.remote_port}</span></td>
      <td>${stateBadge(r.state)}</td>
      <td style="color:var(--text3)">${r.pid||'—'}</td>
    </tr>`).join('');
    showToast(`${d.records.length} registros`,'success');
  } catch(err){showToast('Error: '+err.message,'error');}
}

// ── IPs únicas ────────────────────────────────────────────────
async function loadUniqueIPs() {
  $('ipsBody').innerHTML=`<tr class="placeholder-row"><td colspan="8"><div class="placeholder"><div class="placeholder-icon">◈</div><div>Cargando...</div></div></td></tr>`;
  try {
    const d=await apiFetch('/history/ips');
    if (!d.ips?.length){$('ipsBody').innerHTML=`<tr class="placeholder-row"><td colspan="8"><div class="placeholder"><div>Sin IPs en historial</div></div></td></tr>`;return;}
    $('ipsBody').innerHTML=d.ips.map(r=>`<tr>
      <td class="${r.isPrivate?'cell-ip private':'cell-ip'}">${r.remote_addr}</td>
      <td>${r.fqdn?`<span class="cell-fqdn">${r.fqdn}</span>`:'<span class="cell-fqdn empty">—</span>'}</td>
      <td>${svcBadge(r.reputation)}</td>
      <td>${countryCell(r.geo)}</td>
      <td>${repBadge(r.reputation)}</td>
      <td style="color:var(--yellow);text-align:center">${r.seen_count}</td>
      <td style="color:var(--text3);font-size:.7rem">${formatDateTime(r.last_seen)}</td>
      <td style="display:flex;gap:4px">
        <button class="btn-action" onclick="openDetail('${r.remote_addr}')">+ INFO</button>
        ${!state.blockedIPs.has(r.remote_addr)?`<button class="btn-block" onclick="confirmBlock({ip:'${r.remote_addr}',port:null,pid:null})">⊘</button>`:'<span style="color:var(--red);font-size:.65rem;font-weight:700">BLOQ.</span>'}
      </td>
    </tr>`).join('');
  } catch(err){showToast('Error: '+err.message,'error');}
}

// ── Tabs ──────────────────────────────────────────────────────
function switchTab(tab) {
  state.activeTab=tab;
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  $(`tab-${tab}`)?.classList.add('active');
  if (tab==='map')     loadMapData();
  if (tab==='alerts')  loadAlerts();
  if (tab==='blocked') loadBlockedIPs();
  if (tab==='ips')     loadUniqueIPs();
}

// ── Auto-refresh ──────────────────────────────────────────────
function startAutoRefresh() {
  clearInterval(state.refreshTimer);
  if (!$('autoRefresh').checked) return;
  state.refreshTimer=setInterval(loadConnections,parseInt($('refreshInterval').value,10));
}

// ── Init ──────────────────────────────────────────────────────
function init() {
  document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>switchTab(b.dataset.tab)));
  $('searchInput').addEventListener('input',  ()=>renderConnectionsTable(applyFilters(state.connections)));
  $('filterState').addEventListener('change', ()=>renderConnectionsTable(applyFilters(state.connections)));
  $('filterRep').addEventListener('change',   ()=>renderConnectionsTable(applyFilters(state.connections)));
  $('autoRefresh').addEventListener('change', startAutoRefresh);
  $('refreshInterval').addEventListener('change', startAutoRefresh);
  $('btnRefresh').addEventListener('click',   loadConnections);
  $('btnHistory').addEventListener('click',   loadHistory);
  $('btnAckAll').addEventListener('click',    acknowledgeAll);
  $('filterUnread').addEventListener('change',loadAlerts);
  $('modalClose').addEventListener('click',   ()=>$('dnsModal').classList.add('hidden'));
  $('dnsModal').addEventListener('click',     e=>{if(e.target===$('dnsModal'))$('dnsModal').classList.add('hidden');});
  document.addEventListener('keydown', e=>{
    if (e.key==='Escape'){$('dnsModal').classList.add('hidden');$('blockModal').classList.add('hidden');}
    if (e.key==='F5'){e.preventDefault();loadConnections();}
  });

  checkAdmin();
  loadConnections();
  startAutoRefresh();
  console.log('[NetWatch] v2.1 iniciado');
}

document.addEventListener('DOMContentLoaded', init);
