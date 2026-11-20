// ---- Cross-device links (Links tab, connect mode in the topology) -------------------------------------
// Scoring runs here so that a hosts file can be applied without a new run. Nothing is linked automatically:
// a link counts only after "confirm" (or from the map file). Findings/chains are updated by a new run with --map.
const LK = D.linking || { sources: [], targets: [], map: {} };
const lkHosts = {}; Object.keys(LK.map.hosts || {}).forEach(h => lkHosts[h.toLowerCase()] = LK.map.hosts[h]);
const lkGroupName = id => (D.groups.find(g => g.id === id) || {}).name || '';
const lkKey = n => `${lkGroupName(n.group)}|${n.etype}|${n.name}`;
const lkNodeByKey = {}; D.nodes.forEach(n => lkNodeByKey[lkKey(n)] = n.id);
const lkSel = {};      // source node id -> { to, status: proposed|confirmed|rejected }
let lkManual = [];     // [{ from, to }] confirmed manually (table or topology)
const LK_GENERIC = new Set(['vip', 'lb', 'vs', 'svc', 'srv', 'ssl', 'http', 'https', 'web', 'tcp', 'udp', 'server', 'service', 'group', 'test', 'example', 'com', 'net', 'org', 'local', 'corp', 'internal', 'prod', 'the']);
const lkTokens = s => new Set(String(s || '').toLowerCase().split(/[^a-z0-9]+/).filter(x => x.length >= 3 && !LK_GENERIC.has(x) && !/^\d+$/.test(x)));
function lkScore(src, tg) {
  const r = []; let sc = 0; const host = src.host.toLowerCase(), ip = lkHosts[host];
  if (ip && ip === tg.ip) { sc += 60; r.push('ip'); if (src.port && src.port === tg.port) { sc += 30; r.push('port'); } }
  else if (src.port && src.port === tg.port) { sc += 10; r.push('port_only'); }
  const a = new Set([...lkTokens(host), ...lkTokens(src.name)]), b = lkTokens(tg.name);
  if ([...a].some(x => b.has(x))) { sc += 15; r.push('name'); }
  const first = host.split('.')[0];
  if (tg.certs.some(c => { const l = c.toLowerCase(); return l.includes(host) || (first.length >= 3 && !LK_GENERIC.has(first) && l.includes(first)); })) { sc += 25; r.push('cert'); }
  return { score: Math.min(100, sc), reasons: r };
}
const lkTargetsFor = src => LK.targets.filter(x => src.url || x.group !== src.group).map(x => ({ tg: x, ...lkScore(src, x) })).sort((a, b) => b.score - a.score || a.tg.name.localeCompare(b.tg.name));
function lkAutoPick() {
  LK.sources.forEach(s => {
    const cur = lkSel[s.node]; if (cur && cur.status !== 'proposed') return;
    const best = lkTargetsFor(s)[0];
    if (best && best.score >= 40) lkSel[s.node] = { to: best.tg.node, status: 'proposed' }; else delete lkSel[s.node];
  });
}
function lkInit() {
  (LK.map.links || []).forEach(l => {
    const a = lkNodeByKey[l.from], b = lkNodeByKey[l.to]; if (!a || !b) return;
    if (LK.sources.some(s => s.node === a) && !l.manual) lkSel[a] = { to: b, status: l.status === 'rejected' ? 'rejected' : 'confirmed' };
    else if (l.status === 'confirmed') lkManual.push({ from: a, to: b });
  });
  // links from the map file were already inserted by the run; they are rebuilt here uniformly
  for (let i = D.edges.length - 1; i >= 0; i--) if (D.edges[i].type === 'link') { const id = D.edges[i].id; cy.getElementById(id).remove(); D.edges.splice(i, 1); }
  lkAutoPick(); lkSync(false);
}
let lkSeq = 0, lkDirty = false;
function lkSync(redraw) {
  for (let i = D.edges.length - 1; i >= 0; i--) if (D.edges[i].type === 'link') { cy.getElementById(D.edges[i].id).remove(); D.edges.splice(i, 1); }
  const want = [];
  Object.keys(lkSel).forEach(k => { if (lkSel[k].status === 'confirmed') want.push({ from: k, to: lkSel[k].to, manual: false }); });
  lkManual.forEach(m => want.push({ from: m.from, to: m.to, manual: true }));
  want.forEach(w => {
    if (!nodeById[w.from] || !nodeById[w.to]) return;
    const id = 'lk' + (lkSeq++), e = { id, source: w.from, target: w.to, type: 'link', label: t(w.manual ? 'lk_edge_manual' : 'lk_edge'), port: true };
    D.edges.push(e); cy.add({ group: 'edges', data: { id, source: e.source, target: e.target, type: 'link', elabel: e.label, port: true } });
  });
  Object.keys(outE).forEach(k => delete outE[k]); D.edges.forEach(e => (outE[e.source] = outE[e.source] || []).push(e));
  if (redraw) { refresh(false); lkDirty = true; renderLinks(); }
}
function lkParseHosts(text) {
  const out = {};
  text.split(/\r?\n/).forEach(line => {
    const toks = line.split('#')[0].trim().split(/[\s,;]+/).filter(Boolean), ips = toks.filter(x => /^\d{1,3}(\.\d{1,3}){3}$/.test(x));
    if (ips.length === 1) toks.filter(x => x !== ips[0]).forEach(n => out[n.toLowerCase().replace(/\.$/, '')] = ips[0]);
  });
  return out;
}
function lkDownload(name, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); }
function lkSave() {
  const links = [];
  Object.keys(lkSel).forEach(k => { const s = lkSel[k]; if (s.status === 'confirmed' || s.status === 'rejected') links.push({ from: lkKey(nodeById[k]), to: lkKey(nodeById[s.to]), status: s.status }); });
  lkManual.forEach(m => links.push({ from: lkKey(nodeById[m.from]), to: lkKey(nodeById[m.to]), status: 'confirmed', manual: true }));
  lkDownload('nsviz-links.json', JSON.stringify({ format: 'nsviz-links', version: 1, hosts: lkHosts, links }, null, 1));
  toast(t('lk_saved'));
}
function lkLoad(text) {
  let d; try { d = JSON.parse(text); } catch (e) { toast('JSON ✕'); return; }
  if (d.format !== 'nsviz-links') { toast('nsviz-links ✕'); return; }
  Object.keys(d.hosts || {}).forEach(h => lkHosts[h.toLowerCase()] = d.hosts[h]);
  Object.keys(lkSel).forEach(k => delete lkSel[k]); lkManual = [];
  (d.links || []).forEach(l => {
    const a = lkNodeByKey[l.from], b = lkNodeByKey[l.to]; if (!a || !b) return;
    if (LK.sources.some(s => s.node === a) && !l.manual) lkSel[a] = { to: b, status: l.status === 'rejected' ? 'rejected' : 'confirmed' };
    else if (l.status === 'confirmed') lkManual.push({ from: a, to: b });
  });
  lkAutoPick(); lkSync(true); toast(t('lk_loaded'));
}
const lkName = id => { const n = nodeById[id]; return n ? `${lkGroupName(n.group)} · ${n.label}` : id; };
function lkOpt(c, sel) { const tg = c.tg; return `<option value="${esc(tg.node)}" ${sel === tg.node ? 'selected' : ''}>${esc(lkGroupName(tg.group))} · ${esc(tg.name)} · ${esc(tg.ip + ':' + tg.port)}${c.score ? ' (' + c.score + ')' : ''}</option>`; }
function renderLinks() {
  const root = $('#links'); if (!root) return;
  const names = [...new Set(LK.sources.map(s => s.host.toLowerCase()))], known = names.filter(n => lkHosts[n]).length;
  const cmd = srv => `python3 -m nsviz resolve <configs> ${srv ? '--server ' + srv + ' ' : ''}-o hosts.txt`;
  const rows = LK.sources.map((s, i) => {
    const cands = lkTargetsFor(s), cur = lkSel[s.node], st = cur ? cur.status : 'open', best = cur ? cands.find(c => c.tg.node === cur.to) : null;
    const top = cands.filter(c => c.score > 0), rest = cands.filter(c => !c.score).sort((a, b) => a.tg.name.localeCompare(b.tg.name));
    const chips = best ? best.reasons.map(r => `<span class="chip">${esc(t('lkr_' + r))}</span>`).join('') : '';
    return `<tr data-i="${i}"><td><b>${esc(s.name)}</b><br><span class="muted small">${esc(lkGroupName(s.group))} · ${esc(s.host)}:${esc(s.port)} ${esc(s.proto)}${lkHosts[s.host.toLowerCase()] ? ' → ' + esc(lkHosts[s.host.toLowerCase()]) : ''}</span></td>` +
      `<td><select class="lk-sel" aria-label="${esc(t('lk_th_tgt'))} ${esc(s.name)}"><option value="">${esc(t('lk_none'))}</option>${top.map(c => lkOpt(c, cur && cur.to)).join('')}${top.length && rest.length ? '<option disabled>──────</option>' : ''}${rest.map(c => lkOpt(c, cur && cur.to)).join('')}</select></td>` +
      `<td>${best ? `<b>${best.score}</b> ` : ''}${chips}</td><td><span class="stat st-${st}">${esc(t('st_' + st))}</span></td>` +
      `<td class="nowrap"><button class="lk-ok" ${cur ? '' : 'disabled'}>${esc(t('lk_confirm'))}</button> <button class="lk-no" ${cur ? '' : 'disabled'}>${esc(t('lk_reject'))}</button> <button class="lk-reset" ${cur ? '' : 'disabled'}>${esc(t('lk_reset'))}</button></td></tr>`;
  }).join('');
  const all = D.nodes.filter(n => n.kind !== 'device' && n.kind !== 'missing').map(n => `<option value="${esc(n.id)}">${esc(lkGroupName(n.group))} · ${esc(n.label)} (${esc(kindLabel(n.kind))})</option>`).join('');
  root.innerHTML = `<h2>${esc(t('lk_title'))}</h2><p class="muted">${esc(t('lk_intro'))}</p>
    <div class="card"><div class="row wrap"><button id="lk-hosts-b">${esc(t('lk_import'))}</button><button id="lk-load-b">${esc(t('lk_load'))}</button><button id="lk-save-b">${esc(t('lk_save'))}</button>
      <span class="muted">${esc(t('lk_known', { a: known, b: names.length }))}</span></div>
      <input type="file" id="lk-hosts-f" accept=".txt,.csv,.hosts,text/plain" hidden><input type="file" id="lk-load-f" accept=".json,application/json" hidden>
      <p class="muted small">${esc(t('lk_privacy'))}</p>
      <details><summary>${esc(t('lk_dns_title'))}</summary><p class="small">${esc(t('lk_dns_text'))}</p>
        <div class="row wrap"><label for="lk-srv" class="small">${esc(t('lk_dns_server'))}</label><input id="lk-srv" placeholder="10.0.0.53" size="16"><code id="lk-cmd">${esc(cmd(''))}</code><button id="lk-copy">${esc(t('lk_copy'))}</button><button id="lk-names">${esc(t('lk_names'))}</button></div></details></div>
    <div class="card"><div class="tablewrap"><table><thead><tr><th scope="col">${esc(t('lk_th_src'))}</th><th scope="col">${esc(t('lk_th_tgt'))}</th><th scope="col">${esc(t('lk_th_score'))}</th><th scope="col">${esc(t('th_status'))}</th><th scope="col"></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="muted">${esc(t('lk_empty'))}</td></tr>`}</tbody></table></div><p class="muted small">${esc(t('lk_note'))}</p></div>
    <div class="card"><h3>${esc(t('lk_manual_h'))}</h3><p class="muted small">${esc(t('lk_manual_hint'))}</p>
      <div class="row wrap"><select id="lk-from" aria-label="${esc(t('lk_from'))}">${all}</select><span>→</span><select id="lk-to" aria-label="${esc(t('lk_to'))}">${all}</select><button id="lk-add">${esc(t('lk_add'))}</button></div>
      <ul>${lkManual.map((m, i) => `<li>${esc(lkName(m.from))} → ${esc(lkName(m.to))} <button class="lk-del" data-i="${i}">${esc(t('lk_remove'))}</button></li>`).join('')}</ul></div>`;
  $$('#links tbody tr[data-i]').forEach(tr => {
    const s = LK.sources[+tr.dataset.i], set = st => { const c = lkSel[s.node]; if (c) { c.status = st; lkSync(true); } };
    tr.querySelector('.lk-sel').onchange = e => { if (e.target.value) lkSel[s.node] = { to: e.target.value, status: 'proposed' }; else delete lkSel[s.node]; lkSync(true); };
    tr.querySelector('.lk-ok').onclick = () => set('confirmed'); tr.querySelector('.lk-no').onclick = () => set('rejected');
    tr.querySelector('.lk-reset').onclick = () => { delete lkSel[s.node]; lkAutoPick(); lkSync(true); };
  });
  $('#lk-hosts-b').onclick = () => $('#lk-hosts-f').click(); $('#lk-load-b').onclick = () => $('#lk-load-f').click(); $('#lk-save-b').onclick = lkSave;
  $('#lk-hosts-f').onchange = e => { const f = e.target.files[0]; if (!f) return; f.text().then(x => { Object.assign(lkHosts, lkParseHosts(x)); lkAutoPick(); lkSync(true); }); };
  $('#lk-load-f').onchange = e => { const f = e.target.files[0]; if (f) f.text().then(lkLoad); };
  $('#lk-srv').oninput = e => { $('#lk-cmd').textContent = cmd(e.target.value.trim()); };
  const copy = txt => { (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(() => toast('✓'), () => toast(txt)); };
  $('#lk-copy').onclick = () => copy($('#lk-cmd').textContent); $('#lk-names').onclick = () => copy(names.join('\n'));
  $('#lk-add').onclick = () => { const a = $('#lk-from').value, b = $('#lk-to').value; if (a && b && a !== b) lkAddManual(a, b); };
  $$('.lk-del').forEach(b => b.onclick = () => { lkManual.splice(+b.dataset.i, 1); lkSync(true); toast(t('lk_removed')); });
}
function lkAddManual(a, b) {
  if (lkManual.some(m => m.from === a && m.to === b)) return;
  lkManual.push({ from: a, to: b }); lkSync(true); toast(t('lk_added', { a: nodeById[a].label, b: nodeById[b].label }));
}
// Connect mode: press on a node and release on another one
let connectOn = false, connectFrom = null;
function setConnect(on) {
  connectOn = on; cy.autoungrabify(on); $('#cy').classList.toggle('connecting', on); $('#connect').setAttribute('aria-pressed', on);
  if (on) toast(t('connect_hint'));
}
cy.on('tapstart', 'node', ev => { if (connectOn) connectFrom = ev.target.id(); });
cy.on('tapend', ev => {
  if (!connectOn || !connectFrom) return; const from = connectFrom; connectFrom = null;
  const p = ev.position, hit = cy.nodes(':visible').filter(n => { const b = n.boundingBox(); return p.x >= b.x1 && p.x <= b.x2 && p.y >= b.y1 && p.y <= b.y2; })[0];
  if (hit && hit.id() !== from) lkAddManual(from, hit.id());
});
$('#connect').onclick = () => setConnect(!connectOn);
lkInit();
