// ---- Export -----------------------------------------------------------------------------------
// Offline export of the report data: images (PNG/SVG), PDF (print view), CSV, JSON, Markdown.
// Scopes: all = full model, view = what is visible/filtered now, sel = selected object with neighbourhood.
// Optional pseudonymization of names, IPs, hosts and e-mails (config lines and free text are dropped).
const exp = { scope: 'view', fmt: 'png', anon: null };  // anon is asked on every export (no silent default)

function pseudonymizer(on) {
  if (!on) return { s: x => String(x == null ? '' : x), on: false };
  const map = new Map(), ips = new Map(), subs = new Map(), hosts = new Map();
  const add = (v, kind) => { v = String(v || ''); if (v.length >= 2 && !map.has(v) && !/^\d+$/.test(v) && !(v.toUpperCase() === v && v.includes('-'))) map.set(v, (kind || 'obj') + '_' + String(map.size + 1).padStart(4, '0')); };
  D.nodes.forEach(n => { add(n.name, n.kind); add(n.label, n.kind); });
  D.groups.forEach(g => { add(g.name, 'group'); g.devices.forEach(d => { add(d.name, 'adc'); add(d.file, 'file'); }); });
  const names = [...map.keys()].sort((a, b) => b.length - a.length);
  const ip4 = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])/g;
  const mail = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
  const fqdn = /(?<![\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|de|at|ch|eu|io|info|biz|cloud|local|lan|corp|intern|internal|[a-z]{2})(?![\w-])/g;
  const esc2 = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let rx = null;
  const s = x => {
    x = String(x == null ? '' : x);
    x = x.replace(/\b[0-9a-fA-F]{40,}\b/g, '0');
    x = x.replace(mail, m => { if (!hosts.has(m)) hosts.set(m, 'user' + (hosts.size + 1) + '@example.com'); return hosts.get(m); });
    x = x.replace(ip4, (m, a, b, c, d) => { if (+a === 255 || +a === 0 || [a, b, c, d].some(v => +v > 255)) return m; const k = a + '.' + b + '.' + c; if (!subs.has(k)) subs.set(k, subs.size); const i = subs.get(k); return '10.' + (Math.floor(i / 256) % 256) + '.' + (i % 256) + '.' + d; });
    if (!rx && names.length) rx = new RegExp('(?<![\\w.-])(' + names.map(esc2).join('|') + ')(?![\\w.-])', 'g');
    if (rx) x = x.replace(rx, m => map.get(m));
    x = x.replace(fqdn, m => { if (/example\.(com|org)$/i.test(m)) return m; if (!hosts.has(m)) hosts.set(m, 'host' + (hosts.size + 1) + '.example.com'); return hosts.get(m); });
    return x;
  };
  return { s, on: true };
}

const sc = () => {  // node set for the current scope
  if (exp.scope === 'sel' && state.selected) { const c = cy.getElementById(state.selected); return c.length ? c.closedNeighborhood().nodes() : cy.collection(); }
  if (exp.scope === 'all') return cy.nodes();
  return cy.nodes(':visible');
};
const scopeIds = () => new Set(sc().map(n => n.id()));
const scopeFindings = () => {
  if (exp.scope === 'all') return D.findings;
  const ids = scopeIds();
  return (exp.scope === 'view' ? filteredFindings() : D.findings).filter(f => ids.has(f.node));
};
const stamp = () => new Date().toISOString().slice(0, 10);
function download(name, blob) { const a = document.createElement('a'); a.href = typeof blob === 'string' ? blob : URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove(); }
const csvText = rows => '﻿' + rows.map(r => r.map(c => '"' + String(c == null ? '' : c).replace(/"/g, '""') + '"').join(';')).join('\r\n');

function findingRow(f, P) {
  const r = D.rules[f.rule] || {}, rt = ruleText(r);
  return [sevLabel(f.severity), f.rule, rt.title, catLabel(r.category), P.s(msgOf(f)), f.devices.map(P.s).join(' + '), P.on ? '' : f.file, P.on ? '' : f.line, P.s((f.etype + ' ' + f.name).trim())];
}
const findingHead = () => [t('th_sev'), t('th_rule'), t('th_title'), t('th_cat'), t('th_msg'), t('th_dev'), t('th_file'), '#', t('th_object')];

function buildJson(P) {
  const ids = scopeIds(), idmap = new Map();  // ids contain object names: anonymized exports use neutral ids
  const nid = id => { if (!P.on) return id; if (!idmap.has(id)) idmap.set(id, 'n' + (idmap.size + 1)); return idmap.get(id); };
  const nodes = D.nodes.filter(n => ids.has(n.id)).map(n => ({ id: n.id, kind: n.kind, label: P.s(n.label), group: n.group, etype: n.etype, name: P.s(n.name),
    props: P.on ? Object.fromEntries(Object.entries(n.props).filter(([k]) => !/comment|description|note/i.test(k)).map(([k, v]) => [k, P.s(v)])) : n.props,
    ...(P.on ? {} : { lines: n.lines }), findings: n.findings }));
  const fids = new Set(scopeFindings().map(f => f.id));
  return JSON.stringify({
    meta: { generator: D.meta.generator, exported: new Date().toISOString(), scope: exp.scope, pseudonymized: P.on, source_masked: D.meta.redacted },
    groups: D.groups.map(g => ({ id: g.id, name: P.s(g.name), kind: g.kind, devices: g.devices.map(d => ({ name: P.s(d.name), role: d.role, version: d.version, build: d.build, ...(P.on ? {} : { file: d.file, nsip: d.nsip }) })) })),
    nodes: nodes.map(n => ({ ...n, id: nid(n.id) })),
    edges: D.edges.filter(e => ids.has(e.source) && ids.has(e.target)).map(e => ({ source: nid(e.source), target: nid(e.target), type: e.type, label: P.s(e.label) })),
    findings: D.findings.filter(f => fids.has(f.id)).map(f => ({ id: f.id, rule: f.rule, severity: f.severity, message: { en: P.s(f.msgs.en), de: P.s(f.msgs.de) }, devices: f.devices.map(P.s), object: P.s((f.etype + ' ' + f.name).trim()), node: nid(f.node) })),
    rules: D.rules,
  }, null, 1);
}

function buildMarkdown(P) {
  const fs = scopeFindings(), cnt = {}; SEV.forEach(s => cnt[s] = fs.filter(f => f.severity === s).length);
  const L = [];
  L.push('# ' + t('ex_md_title'), '', `${t('ex_md_scope')}: ${t('ex_' + exp.scope)} · ${stamp()} · ${D.meta.generator}`, '');
  L.push(`**${t('o_score')}:** ${score}/100 · ` + SEV.map(s => `${sevLabel(s)}: ${cnt[s]}`).join(' · '), '');
  L.push('## ' + t('p_devices'), '', `| ${t('th_name')} | ${t('th_role')} | ${t('th_version')} |`, '|---|---|---|');
  D.groups.forEach(g => g.devices.forEach(d => L.push(`| ${P.s(d.name)} | ${d.role || ''} | ${d.version || '?'} ${d.build || ''} |`)));
  if (D.chains.length) { L.push('', '## ' + t('p_chains'), ''); D.chains.forEach(c => L.push('- ' + c.map(P.s).join(' → '))); }
  L.push('', '## ' + t('tab_findings') + ` (${fs.length})`, '');
  SEV.forEach(s => {
    const l = fs.filter(f => f.severity === s); if (!l.length) return;
    L.push(`### ${sevLabel(s)} (${l.length})`, '');
    l.forEach(f => { const r = D.rules[f.rule] || {}, rt = ruleText(r); L.push(`- **${f.rule}** ${rt.title} - ${P.s(msgOf(f)).replace(/\|/g, '\\|')}` + (rt.remediation ? `  \n  _${t('d_fix')}_ ${rt.remediation}` : '')); });
    L.push('');
  });
  L.push('---', '', t('disclaimer'));
  return L.join('\n');
}

function svgText(P) {
  const ns = sc(); if (!ns.length) return null;
  const bb = ns.boundingBox({ includeLabels: false }), pad = 30;
  const w = Math.ceil(bb.w + pad * 2), h = Math.ceil(bb.h + pad * 2), ox = bb.x1 - pad, oy = bb.y1 - pad, ids = new Set(ns.map(n => n.id()));
  const x = v => String(v).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const out = [`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="11">`,
    '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L10 5L0 10z" fill="#94a3b8"/></marker></defs>',
    `<rect width="${w}" height="${h}" fill="#ffffff"/>`];
  cy.edges().filter(e => ids.has(e.source().id()) && ids.has(e.target().id()) && e.data('type') !== 'contains').forEach(e => {
    const a = e.source().position(), b = e.target().position();
    out.push(`<line x1="${(a.x - ox).toFixed(1)}" y1="${(a.y - oy).toFixed(1)}" x2="${(b.x - ox).toFixed(1)}" y2="${(b.y - oy).toFixed(1)}" stroke="#94a3b8" stroke-width="1.2" marker-end="url(#a)"/>`);
  });
  ns.forEach(n => {
    const p = n.position(), k = n.data('kind'), sev = n.data('sev'), cx = p.x - ox - 78, cyy = p.y - oy - 17;
    let lab = P.s(n.data('label') || ''); if (lab.length > 24) lab = lab.slice(0, 23) + '…';
    out.push(`<rect x="${cx.toFixed(1)}" y="${cyy.toFixed(1)}" width="156" height="34" rx="8" fill="${kindFill(k, false)}" stroke="${sev ? SEVCOL[sev] : kindStroke(k, false)}" stroke-width="${sev ? 2.5 : 1.5}"/>`);
    out.push(`<text x="${(cx + 78).toFixed(1)}" y="${(cyy + 21).toFixed(1)}" text-anchor="middle" fill="#0f172a">${x(lab)}</text>`);
  });
  out.push('</svg>');
  return out.join('\n');
}

function pngUrl(P, full) {  // renders with pseudonymized labels when requested
  const nodes = cy.nodes(), old = nodes.map(n => n.data('disp'));
  const keepView = { z: cy.zoom(), p: { ...cy.pan() } };
  if (P.on) nodes.forEach(n => n.data('disp', P.s(n.data('label') || '')));
  let url;
  try {
    if (exp.scope === 'sel' && state.selected) { const c = cy.getElementById(state.selected).closedNeighborhood(); cy.fit(c, 30); url = cy.png({ full: false, scale: 2, bg: '#ffffff' }); cy.zoom(keepView.z); cy.pan(keepView.p); }
    else url = cy.png({ full, scale: 2, bg: '#ffffff' });
  } finally { nodes.forEach((n, i) => n.data('disp', old[i])); }
  return url;
}

function printDoc(P) {
  const fs = scopeFindings(), cnt = {}; SEV.forEach(s => cnt[s] = fs.filter(f => f.severity === s).length);
  const root = document.createElement('div'); root.id = 'print-root';
  const img = pngUrl(P, exp.scope !== 'view');
  root.innerHTML = `<section class="cover"><h1>NetScaler Visualizer</h1><p class="muted">${esc(t('ex_md_scope'))}: ${esc(t('ex_' + exp.scope))} · ${esc(stamp())}</p>
    <p><b>${esc(t('o_score'))}: ${score}/100</b> — ${SEV.map(s => esc(sevLabel(s)) + ': ' + cnt[s]).join(' · ')}</p>
    <h2>${esc(t('p_devices'))}</h2><ul>${D.groups.map(g => g.devices.map(d => `<li>${esc(P.s(d.name))} ${esc(d.role || '')} ${esc(d.version || '')}</li>`).join('')).join('')}</ul>
    ${D.chains.length ? `<h2>${esc(t('p_chains'))}</h2><ul>${D.chains.map(c => `<li>${c.map(z => esc(P.s(z))).join(' → ')}</li>`).join('')}</ul>` : ''}
    ${P.on ? `<p class="muted">${esc(t('ex_anon_hint'))}</p>` : ''}</section>
    <section><h2>${esc(t('tab_topo'))}</h2><img src="${img}" alt="${esc(t('tab_topo'))}" style="max-width:100%"></section>
    <section><h2>${esc(t('tab_findings'))} (${fs.length})</h2><table><thead><tr>${findingHead().filter((_, i) => i !== 2 && i !== 7).map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${
      fs.map(f => { const r = findingRow(f, P); return '<tr>' + [0, 1, 3, 4, 5, 6, 8].map(i => `<td>${esc(r[i])}</td>`).join('') + '</tr>'; }).join('')}</tbody></table></section>
    <footer>${esc(t('disclaimer'))}</footer>`;
  document.body.appendChild(root); document.body.classList.add('printing');
  const oldTitle = document.title; document.title = 'netscaler-report-' + stamp();
  const done = () => { document.body.classList.remove('printing'); root.remove(); document.title = oldTitle; window.removeEventListener('afterprint', done); };
  window.addEventListener('afterprint', done);
  setTimeout(() => { window.print(); setTimeout(() => { if (document.body.classList.contains('printing')) done(); }, 1500); }, 150);
}

function runExport() {
  if (exp.anon === null) return toast(t('ex_choose'));
  const P = pseudonymizer(exp.anon), n = 'netscaler-' + stamp();
  try {
    if (exp.fmt === 'png') download(n + '-topology.png', pngUrl(P, exp.scope !== 'view'));
    else if (exp.fmt === 'svg') { const s = svgText(P); if (!s) return toast(t('ex_empty')); download(n + '-topology.svg', new Blob([s], { type: 'image/svg+xml' })); }
    else if (exp.fmt === 'pdf') { dlgx.close(); return printDoc(P); }
    else if (exp.fmt === 'csvf') download(n + '-findings.csv', new Blob([csvText([findingHead()].concat(scopeFindings().map(f => findingRow(f, P))))], { type: 'text/csv' }));
    else if (exp.fmt === 'csvi') {
      const ids = scopeIds(), rows = [[t('th_type'), t('th_name'), t('th_group'), 'etype', t('th_ipport'), t('th_proto'), t('th_status'), t('tab_findings')]];
      D.nodes.filter(x => ids.has(x.id) && x.kind !== 'missing').forEach(x => rows.push([kindLabel(x.kind), P.s(x.label), P.s((D.groups.find(g => g.id === x.group) || {}).name), x.etype, P.s(x.props['IP:Port'] || x.props.Address || ''), x.props.Protocol || '', x.props.Status || '', x.findings.length]));
      download(n + '-inventory.csv', new Blob([csvText(rows)], { type: 'text/csv' }));
    }
    else if (exp.fmt === 'csvp') {
      const ids = scopeIds(), rows = [[t('th_from'), t('th_to'), t('ex_conn'), t('th_type')]];
      D.edges.filter(e => e.port && ids.has(e.source) && ids.has(e.target)).forEach(e => rows.push([P.s(nodeById[e.source].label), P.s(nodeById[e.target].label), P.s(e.label), e.type]));
      download(n + '-communication.csv', new Blob([csvText(rows)], { type: 'text/csv' }));
    }
    else if (exp.fmt === 'json') download(n + '-model.json', new Blob([buildJson(P)], { type: 'application/json' }));
    else if (exp.fmt === 'md') download(n + '-summary.md', new Blob([buildMarkdown(P)], { type: 'text/markdown' }));
    toast(t('ex_done'));
  } catch (err) { toast(String(err.message || err)); }
}

const dlgx = $('#dlgx');
function openExport() {
  const selOk = !!state.selected;
  if (exp.scope === 'sel' && !selOk) exp.scope = 'view';
  const radio = (name, items, cur) => items.map(([v, label, dis]) => `<label class="opt${dis ? ' off' : ''}"><input type="radio" name="${name}" value="${v}" ${v === cur ? 'checked' : ''} ${dis ? 'disabled' : ''}> ${esc(label)}</label>`).join('');
  $('#ex-body').innerHTML = `<fieldset><legend>${esc(t('ex_scope'))}</legend>${radio('scope', [['all', t('ex_all')], ['view', t('ex_view')], ['sel', t('ex_sel') + (selOk ? '' : ' (' + t('ex_sel_none') + ')'), !selOk]], exp.scope)}</fieldset>
    <fieldset><legend>${esc(t('ex_format'))}</legend>${radio('fmt', [['png', 'PNG'], ['svg', 'SVG'], ['pdf', 'PDF (' + t('ex_pdf_hint') + ')'], ['csvf', t('ex_csvf')], ['csvi', t('ex_csvi')], ['csvp', t('ex_csvp')], ['json', 'JSON'], ['md', 'Markdown']], exp.fmt)}</fieldset>
    <fieldset><legend>${esc(t('ex_data'))}</legend>${radio('anon', [['0', t('ex_orig')], ['1', t('ex_anon')]], '')}
    <p class="muted small">${esc(t('ex_anon_hint'))}</p><p class="warn small" role="note">${esc(t('ex_warn'))}</p></fieldset>`;
  $$('#ex-body input[name=scope]').forEach(i => i.onchange = () => exp.scope = i.value);
  $$('#ex-body input[name=fmt]').forEach(i => i.onchange = () => exp.fmt = i.value);
  exp.anon = null; $('#ex-go').disabled = true;  // the data variant is chosen explicitly every time
  $$('#ex-body input[name=anon]').forEach(i => i.onchange = () => { exp.anon = i.value === '1'; $('#ex-go').disabled = false; });
  dlgx.showModal ? dlgx.showModal() : dlgx.setAttribute('open', '');
}
$('#export').onclick = openExport; $('#ex-go').onclick = runExport; $('#ex-x').onclick = () => dlgx.close();
dlgx.addEventListener('click', e => { if (e.target === dlgx) dlgx.close(); });
