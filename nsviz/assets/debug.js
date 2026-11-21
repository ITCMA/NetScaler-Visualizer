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
const dbgNode = id => { const n = nodeById[id]; return n ? { id: DBG_IDX[id], name: (n.anon || {}).label || '', kind: n.kind, etype: n.etype } : { id: '?', kind: '?' }; };
// config lines in anonymised form (same rules as "Anonymize configs": pseudonyms, ports and protocols kept, internal/external
// FQDNs and private/public IPs recognizable); falls back to the bare structure if a report has no anonymised lines
const dbgLines = n => (n.lines || []).map((l, i) => ({ line: l.line, text: (n.anon && n.anon.lines && n.anon.lines[i]) || dbgShape(l.text, n.group) }));
// why an object or a line is not drawn (filters, folded objects, bridges, the "contains" switch)
let dbgElig = null;
const dbgEl = () => dbgElig || (dbgElig = eligible());
function dbgNodeWhy(id) {
  const n = nodeById[id], el = cy.getElementById(id);
  if (!n) return 'unknown object';
  if (el.length && el.visible()) return '';
  if (state.group && n.group !== state.group) return 'other device/group selected';
  if (!state.kinds.has(n.kind)) return 'object type hidden (Object types filter)';
  if (state.onlyUnlinked && !unlinkedSet.has(id)) return 'filter "only not connected"';
  if (!dbgEl().has(id)) return 'filter "only findings"';
  const up = cy.edges().filter(x => x.data('target') === id && !x.hasClass('virtual')).map(x => x.data('source')).filter(s => state.collapsed.has(s));
  return up.length ? 'below a folded object (' + up.map(x => DBG_IDX[x] || '?').join(', ') + '; double-click it or choose level "all")' : 'below a folded object (double-click ▸ or level "all")';
}
function dbgEdgeWhy(e, drawn) {
  if (drawn) return '';
  if (e.type === 'contains' && !state.contains) return '"contains" lines switched off';
  const ws = dbgNodeWhy(e.source), wt = dbgNodeWhy(e.target);
  const hiddenType = x => !state.kinds.has((nodeById[x] || {}).kind);
  if ((hiddenType(e.source) || hiddenType(e.target)) && curBridges.some(b => b.s === e.source || b.t === e.target || (b.vids || []).includes(e.source) || (b.vids || []).includes(e.target)))
    return 'end object type hidden; shown as a bridge line through it';
  return [ws && 'from: ' + ws, wt && 'to: ' + wt].filter(Boolean).join('; ') || 'not drawn (unknown reason)';
}
function dbgEdge(e) {
  const el = cy.getElementById(e.id), drawn = !!(el && el.length && el.visible());
  return { from: DBG_IDX[e.source], to: DBG_IDX[e.target], fromKind: (nodeById[e.source] || {}).kind, toKind: (nodeById[e.target] || {}).kind,
    type: e.type, label: e.alabel || '', rule: e.origin || '', cfgLine: e.line || 0, drawn, whyNotDrawn: dbgEdgeWhy(e, drawn) || undefined };
}
function dbgView() {
  dbgElig = null;
  return { layout: state.layout, contains: !!state.contains, kindsShown: [...state.kinds].sort(), group: state.group ? DBG_IDX[(D.nodes.find(n => n.group === state.group && n.kind === 'device') || {}).id] || 'one' : 'all',
    onlyUnlinked: state.onlyUnlinked, onlyFindings: state.onlyFindings, collapsed: state.collapsed.size, pinned: state.pinned.size };
}
const dbgBridgeDrawn = b => { const el = cy.getElementById(`vb|${b.s}|${b.t}`); return !!(el.length && el.visible()); };
function dbgBridges(id) {
  return curBridges.filter(b => b.s === id || b.t === id).map(b => { const drawn = dbgBridgeDrawn(b);
    return { from: DBG_IDX[b.s], to: DBG_IDX[b.t], through: (b.vids || []).map(v => dbgNode(v)), drawn, whyNotDrawn: drawn ? undefined : dbgEdgeWhy({ source: b.s, target: b.t, type: 'via' }, false) }; });
}
function dbgNodeInfo(id) {
  const n = nodeById[id];
  return { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(),
    node: { ...dbgNode(id), dep: n.dep || {}, unlinked: unlinkedSet.has(id), findings: n.findings.map(f => (findingsById[f] || {}).rule).filter(Boolean),
      addressing: (n.props || {}).Addressing || '', fqdnTarget: !!(n.dep && n.dep.fqdn), drawn: cy.getElementById(id).visible(),
      folded: state.collapsed.has(id), whyNotDrawn: dbgNodeWhy(id) || undefined,
      lines: dbgLines(n) },
    outgoing: D.edges.filter(e => e.source === id).map(dbgEdge), incoming: D.edges.filter(e => e.target === id).map(dbgEdge),
    bridges: dbgBridges(id) };
}
function dbgEdgeInfo(edgeEl) {
  const id = edgeEl.id(), virt = edgeEl.hasClass('virtual');
  let info;
  if (virt) { const b = curBridges.find(x => `vb|${x.s}|${x.t}` === id) || {}; info = { type: 'bridge (through hidden objects)', from: dbgNode(b.s), to: dbgNode(b.t), through: (b.vids || []).map(v => dbgNode(v)) }; }
  else { const e = D.edges.find(x => x.id === id); info = e ? { ...dbgEdge(e), fromNode: dbgNode(e.source), toNode: dbgNode(e.target) } : { type: edgeEl.data('type'), note: 'created in this page (Links tab)' }; }
  const shapes = ids => ids.filter(Boolean).map(x => ({ id: DBG_IDX[x], lines: nodeById[x] ? dbgLines(nodeById[x]) : [] }));
  return { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(), edge: info, objects: shapes([edgeEl.data('source'), edgeEl.data('target')]) };
}
function dbgAll() {
  return { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(),
    nodes: D.nodes.map(n => ({ id: DBG_IDX[n.id], name: (n.anon || {}).label || '', group: 'G' + D.groups.findIndex(g => g.id === n.group), kind: n.kind, etype: n.etype, dep: n.dep || {}, unlinked: unlinkedSet.has(n.id),
      drawn: cy.getElementById(n.id).visible(), folded: state.collapsed.has(n.id), whyNotDrawn: dbgNodeWhy(n.id) || undefined, lines: dbgLines(n) })),
    edges: D.edges.map(dbgEdge), bridges: curBridges.map(b => ({ from: DBG_IDX[b.s], to: DBG_IDX[b.t], through: (b.vids || []).map(v => DBG_IDX[v]), drawn: dbgBridgeDrawn(b) })) };
}
function dbgBox(obj, title) {
  const txt = JSON.stringify(obj, null, 1);
  return `<section class="dbg"><h4>🐞 ${esc(title)}</h4><p class="muted small">${esc(t('dbg_hint'))}</p><p class="muted small">${esc(t('dbg_add'))}</p>
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
  const rows = info.outgoing.concat(info.incoming).map(e => `<tr><td>${esc(e.from)} → ${esc(e.to)}</td><td>${esc(e.type)}${e.label ? '<br><span class="muted">' + esc(e.label) + '</span>' : ''}</td><td><code>${esc(e.rule)}</code></td><td>${e.cfgLine || '–'}</td><td>${e.drawn ? '✓' : `<span title="${esc(e.whyNotDrawn || '')}">– ${esc(e.whyNotDrawn || '')}</span>`}</td></tr>`).join('');
  $('#detail').insertAdjacentHTML('beforeend', `<section class="dbg"><h4>🐞 ${esc(t('dbg_lines'))}</h4><p class="small">${esc(DBG_IDX[d.id])} · entry=${!!(d.dep || {}).entry} · reach=${!!(d.dep || {}).reach}${state.collapsed.has(d.id) ? ' · folded ▸ (double-click)' : ''}</p>
    <div class="tablewrap"><table class="small"><thead><tr><th>${esc(t('dbg_conn'))}</th><th>${esc(t('dbg_type'))}</th><th>${esc(t('dbg_rule'))}</th><th>${esc(t('dbg_line'))}</th><th>${esc(t('dbg_drawn'))}</th></tr></thead><tbody>${rows}</tbody></table></div></section>` + dbgBox(info, t('dbg_obj')));
  dbgWire();
};
// several elements at once: Shift, Ctrl or Cmd + click adds or removes an object or line, a normal click starts anew
state.dbgSel = [];
cy.style().selector('.dbgsel').style({ 'overlay-color': '#6366f1', 'overlay-opacity': 0.28, 'overlay-padding': 6 }).update();
function dbgMarks() { cy.elements('.dbgsel').removeClass('dbgsel'); state.dbgSel.forEach(id => cy.getElementById(id).addClass('dbgsel')); }
function dbgItem(id) {
  const el = cy.getElementById(id); if (!el.length) return null;
  const { tool, code, view, ...rest } = el.isNode() ? dbgNodeInfo(id) : dbgEdgeInfo(el);
  return el.isNode() ? { object: rest } : { line: rest };
}
function dbgItemLabel(id) {
  const el = cy.getElementById(id); if (!el.length) return '?';
  if (el.isNode()) { const n = dbgNode(id); return `${n.id} · ${n.kind}`; }
  return `${DBG_IDX[el.data('source')] || '?'} → ${DBG_IDX[el.data('target')] || '?'} · ${el.data('type') || ''}`;
}
function dbgShowMulti() {
  const info = { tool: D.meta.generator, code: D.meta.code || '', view: dbgView(), items: state.dbgSel.map(dbgItem).filter(Boolean) };
  $('#detail').innerHTML = `<h3>🐞 ${esc(t('dbg_multi', { n: state.dbgSel.length }))}</h3><ul class="small">${state.dbgSel.map(id => `<li>${esc(dbgItemLabel(id))}</li>`).join('')}</ul>
    <button id="dbg-clear">${esc(t('dbg_clear'))}</button>` + dbgBox(info, t('dbg_multi', { n: state.dbgSel.length }));
  $('#dbg-clear').onclick = () => { state.dbgSel = []; dbgMarks(); clearSelection(); };
  dbgWire();
}
function dbgShowEdge(el) {
  const info = dbgEdgeInfo(el);
  $('#detail').innerHTML = `<h3>🐞 ${esc(t('dbg_edge'))}</h3><dl><dt>${esc(t('dbg_type'))}</dt><dd>${esc(String(info.edge.type))}</dd><dt>${esc(t('dbg_rule'))}</dt><dd><code>${esc(info.edge.rule || '–')}</code></dd><dt>${esc(t('dbg_line'))}</dt><dd>${esc(String(info.edge.cfgLine || '–'))}</dd></dl>` + dbgBox(info, t('dbg_edge'));
  dbgWire();
}
cy.on('tap', 'node, edge', ev => {
  if (!state.debug) return;
  const oe = ev.originalEvent || {}, id = ev.target.id();
  if (oe.shiftKey || oe.ctrlKey || oe.metaKey) { const i = state.dbgSel.indexOf(id); i >= 0 ? state.dbgSel.splice(i, 1) : state.dbgSel.push(id); }
  else state.dbgSel = [id];
  dbgMarks();
  if (state.dbgSel.length > 1) dbgShowMulti();
  else if (state.dbgSel.length === 1 && cy.getElementById(state.dbgSel[0]).isEdge()) dbgShowEdge(cy.getElementById(state.dbgSel[0]));
  else if (state.dbgSel.length === 1 && state.dbgSel[0] !== state.selected) select(state.dbgSel[0]);
});
cy.on('tap', ev => { if (ev.target === cy && state.debug) { state.dbgSel = []; dbgMarks(); } });
function dbgSet(on) {
  state.debug = on; $('#debug-mode').checked = on; $('#dbg-btn').setAttribute('aria-pressed', String(on)); document.body.classList.toggle('debug', on);
  if (!on) { state.dbgSel = []; dbgMarks(); }
  if (on) { showTab('topo'); toast(t('dbg_on')); }
  if (state.selected) renderDetail(nodeById[state.selected]);
  else if (on) { $('#detail').innerHTML = dbgBox({ tool: D.meta.generator, code: D.meta.code || '', view: dbgView(), hint: 'select an object or a line' }, t('dbg_mode')); dbgWire(); }
  else renderDetail(null);
}
$('#debug-mode').onchange = e => dbgSet(e.target.checked);
$('#dbg-btn').onclick = () => dbgSet(!state.debug);
