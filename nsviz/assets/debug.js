// ---- Debug mode: where does a line come from? --------------------------------------------------------
// Shows for every object/line which rule of the tool created it (code location) and from which config line, and copies
// an ANONYMISED description: object types, connection types, rule locations, line numbers and the structure of the config
// lines (options kept, every name/IP/number/text replaced by a placeholder). No names, IPs, file names or values leave.
const DBG_IDX = {}; D.nodes.forEach((n, i) => DBG_IDX[n.id] = 'N' + i);
const DBG_NAMES = {}; D.nodes.forEach(n => { const k = n.group + '|' + n.name; if (n.name && !(k in DBG_NAMES)) DBG_NAMES[k] = n.id; });
const DBG_WORDS = new Set(('add set bind unbind link enable disable rm unset lb cs vpn gslb authentication aaa ssl rewrite responder cache cmp appfw ' +
  'appflow transform tm audit dns policy policylabel action vserver service servicegroup server monitor certkey profile cipher global group ' +
  'sessionaction sessionpolicy trafficaction trafficpolicy ldapaction ldappolicy radiusaction radiuspolicy samlaction samlpolicy loginschema ' +
  'loginschemapolicy authnprofile nameserver addrec cnamerec parameter httpcallout ns ip vlan route ica accessprofile site domain ' +
  'reqvserver resvserver true false ns_true http_req http_res').split(' '));
const DBG_UP = /^(HTTP|SSL|SSL_BRIDGE|SSL_TCP|TCP|UDP|DNS|DNS_TCP|ANY|FTP|RDP|MSSQL|MYSQL|RADIUS|LDAP|SIP_UDP|SYSLOGTCP|SYSLOGUDP|NEXT|END|USE_INVOCATION_RESULT|REQUEST|RESPONSE|REQ_DEFAULT|REQ_OVERRIDE|RES_DEFAULT|RES_OVERRIDE|OTHERTCP_REQ_DEFAULT|ON|OFF|YES|NO|ENABLED|DISABLED|ALLOW|DENY|NOOP|RESET|DROP|ROUNDROBIN|LEASTCONNECTION|SOURCEIP|COOKIEINSERT|NONE|BackEnd|FrontEnd|IPV4|IPV6)$/;
function dbgTokens(line) { const out = []; const re = /"((?:\\.|[^"\\])*)"|(\S+)/g; let m; while ((m = re.exec(line))) out.push(m[1] !== undefined ? { q: true, v: m[1] } : { q: false, v: m[2] }); return out; }
function dbgShape(text, group) {
  return dbgTokens(text).map(tk => {
    const v = tk.v;
    if (tk.q) return '<expr>';
    if (/^-[A-Za-z]/.test(v)) return v.toLowerCase();
    if (v === '***') return '***';
    if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v)) return '<ip>';
    if (/^\d+$/.test(v)) return '<num>';
    const id = DBG_NAMES[group + '|' + v];
    if (id) return `<${DBG_IDX[id]}:${nodeById[id].kind}>`;
    if (DBG_WORDS.has(v.toLowerCase()) && /^[a-z_]+$/i.test(v)) return v.toLowerCase();
    if (DBG_UP.test(v)) return v;
    return '<str>';
  }).join(' ');
}
const dbgNode = id => { const n = nodeById[id]; return n ? { id: DBG_IDX[id], kind: n.kind, etype: n.etype } : { id: '?', kind: '?' }; };
function dbgEdge(e) {
  const el = cy.getElementById(e.id);
  return { from: DBG_IDX[e.source], to: DBG_IDX[e.target], fromKind: (nodeById[e.source] || {}).kind, toKind: (nodeById[e.target] || {}).kind,
    type: e.type, rule: e.origin || '', cfgLine: e.line || 0, drawn: !!(el && el.length && el.visible()) };
}
function dbgView() {
  return { layout: state.layout, kindsShown: [...state.kinds].sort(), group: state.group ? DBG_IDX[(D.nodes.find(n => n.group === state.group && n.kind === 'device') || {}).id] || 'one' : 'all',
    onlyUnlinked: state.onlyUnlinked, onlyFindings: state.onlyFindings, collapsed: state.collapsed.size, pinned: state.pinned.size };
}
function dbgBridges(id) {
  return curBridges.filter(b => b.s === id || b.t === id).map(b => ({ from: DBG_IDX[b.s], to: DBG_IDX[b.t], through: (b.vids || []).map(v => dbgNode(v)) }));
}
function dbgNodeInfo(id) {
  const n = nodeById[id];
  return { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(),
    node: { ...dbgNode(id), dep: n.dep || {}, unlinked: unlinkedSet.has(id), findings: n.findings.map(f => (findingsById[f] || {}).rule).filter(Boolean),
      addressing: (n.props || {}).Addressing || '', fqdnTarget: !!(n.dep && n.dep.fqdn), drawn: cy.getElementById(id).visible(),
      lines: (n.lines || []).map(l => ({ line: l.line, shape: dbgShape(l.text, n.group) })) },
    outgoing: D.edges.filter(e => e.source === id).map(dbgEdge), incoming: D.edges.filter(e => e.target === id).map(dbgEdge),
    bridges: dbgBridges(id) };
}
function dbgEdgeInfo(edgeEl) {
  const id = edgeEl.id(), virt = edgeEl.hasClass('virtual');
  let info;
  if (virt) { const b = curBridges.find(x => `vb|${x.s}|${x.t}` === id) || {}; info = { type: 'bridge (through hidden objects)', from: dbgNode(b.s), to: dbgNode(b.t), through: (b.vids || []).map(v => dbgNode(v)) }; }
  else { const e = D.edges.find(x => x.id === id); info = e ? { ...dbgEdge(e), fromNode: dbgNode(e.source), toNode: dbgNode(e.target) } : { type: edgeEl.data('type'), note: 'created in this page (Links tab)' }; }
  const shapes = ids => ids.filter(Boolean).map(x => ({ id: DBG_IDX[x], lines: (nodeById[x] ? nodeById[x].lines : []).map(l => ({ line: l.line, shape: dbgShape(l.text, nodeById[x].group) })) }));
  return { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(), edge: info, objects: shapes([edgeEl.data('source'), edgeEl.data('target')]) };
}
function dbgAll() {
  return { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(),
    nodes: D.nodes.map(n => ({ id: DBG_IDX[n.id], group: 'G' + D.groups.findIndex(g => g.id === n.group), kind: n.kind, etype: n.etype, dep: n.dep || {}, unlinked: unlinkedSet.has(n.id),
      lines: (n.lines || []).map(l => ({ line: l.line, shape: dbgShape(l.text, n.group) })) })),
    edges: D.edges.map(dbgEdge), bridges: curBridges.map(b => ({ from: DBG_IDX[b.s], to: DBG_IDX[b.t], through: (b.vids || []).map(v => DBG_IDX[v]) })) };
}
function dbgBox(obj, title) {
  const txt = JSON.stringify(obj, null, 1);
  return `<section class="dbg"><h4>🐞 ${esc(title)}</h4><p class="muted small">${esc(t('dbg_hint'))}</p>
    <div class="row wrap"><button class="dbg-copy">${esc(t('dbg_copy'))}</button><button class="dbg-all">${esc(t('dbg_all'))}</button></div>
    <textarea class="dbg-txt" readonly rows="10" aria-label="${esc(t('dbg_copy'))}">${esc(txt)}</textarea></section>`;
}
function dbgWire() {
  $$('#detail .dbg-copy').forEach(b => b.onclick = () => {
    const ta = b.closest('.dbg').querySelector('.dbg-txt'); ta.select();
    (navigator.clipboard ? navigator.clipboard.writeText(ta.value) : Promise.reject()).then(() => toast(t('dbg_copied'))).catch(() => { try { document.execCommand('copy'); toast(t('dbg_copied')); } catch (e) { toast(t('dbg_manual')); } });
  });
  $$('#detail .dbg-all').forEach(b => b.onclick = () => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(dbgAll())], { type: 'application/json' })); a.download = 'nsviz-debug.json'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000); toast(t('dbg_saved'));
  });
}
const dbgRenderDetail = renderDetail;
renderDetail = function (d) {
  dbgRenderDetail(d);
  if (!state.debug || !d) return;
  const info = dbgNodeInfo(d.id);
  const rows = info.outgoing.concat(info.incoming).map(e => `<tr><td>${esc(e.from)} → ${esc(e.to)}</td><td>${esc(e.type)}</td><td><code>${esc(e.rule)}</code></td><td>${e.cfgLine || '–'}</td><td>${e.drawn ? '✓' : '–'}</td></tr>`).join('');
  $('#detail').insertAdjacentHTML('beforeend', `<section class="dbg"><h4>🐞 ${esc(t('dbg_lines'))}</h4><p class="small">${esc(DBG_IDX[d.id])} · entry=${!!(d.dep || {}).entry} · reach=${!!(d.dep || {}).reach}</p>
    <div class="tablewrap"><table class="small"><thead><tr><th>${esc(t('dbg_conn'))}</th><th>${esc(t('dbg_type'))}</th><th>${esc(t('dbg_rule'))}</th><th>${esc(t('dbg_line'))}</th><th>${esc(t('dbg_drawn'))}</th></tr></thead><tbody>${rows}</tbody></table></div></section>` + dbgBox(info, t('dbg_obj')));
  dbgWire();
};
cy.on('tap', 'edge', ev => {
  if (!state.debug) return;
  const info = dbgEdgeInfo(ev.target);
  $('#detail').innerHTML = `<h3>🐞 ${esc(t('dbg_edge'))}</h3><dl><dt>${esc(t('dbg_type'))}</dt><dd>${esc(String(info.edge.type))}</dd><dt>${esc(t('dbg_rule'))}</dt><dd><code>${esc(info.edge.rule || '–')}</code></dd><dt>${esc(t('dbg_line'))}</dt><dd>${esc(String(info.edge.cfgLine || '–'))}</dd></dl>` + dbgBox(info, t('dbg_edge'));
  dbgWire();
});
$('#debug-mode').onchange = e => { state.debug = e.target.checked; document.body.classList.toggle('debug', state.debug); if (state.selected) renderDetail(nodeById[state.selected]); else if (state.debug) { $('#detail').innerHTML = dbgBox({ tool: D.meta.generator, code: D.meta.code || '', view: dbgView(), hint: 'select an object or a line' }, t('dbg_mode')); dbgWire(); } };
