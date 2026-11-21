// ---- nFactor tab: authentication flow per entry point ---------------------------------------------------
// Data: D.nfactor[group] = { factors: {id: {type: vserver|label|classic, name, node, schemas[], rows[]}}, entries: [...] }.
// Factors are laid out as columns by depth (entry factor first); a policy row that leads to a next factor gets an arrow.
const NF = D.nfactor || {};
const nfEntries = []; Object.entries(NF).forEach(([g, f]) => f.entries.forEach(e => nfEntries.push({ ...e, group: g })));
const nfFactor = (g, id) => (NF[g] || { factors: {} }).factors[id];
let nfSel = 0, nfP = [];  // nfP: actions with parameters of the shown flow (overlay)
const nfHas = () => nfEntries.length > 0;
// factors reachable from an entry, by depth (BFS over "next factor")
function nfLevels(e) {
  const seen = new Map(), q = [[e.factor, 0]];
  while (q.length) {
    const [id, d] = q.shift(); if (seen.has(id) || !nfFactor(e.group, id)) continue; seen.set(id, d);
    nfFactor(e.group, id).rows.forEach(r => { if (r.next_id && !seen.has(r.next_id)) q.push([r.next_id, d + 1]); });
  }
  const cols = []; seen.forEach((d, id) => (cols[d] = cols[d] || []).push(id));
  return cols;
}
const nfKind = f => f.type === 'vserver' ? kindLabel('aaavs') : f.type === 'label' ? kindLabel('nflabel') : t('nf_classic');
function nfSchema(f) {
  if (f.type === 'classic') return '';
  if (!f.schemas.length) return `<div class="nf-schema muted">${esc(f.type === 'label' ? t('nf_noschema_l') : t('nf_noschema_v'))}</div>`;
  return f.schemas.map(s => `<div class="nf-schema"><span class="nf-tag">${esc(t('nf_schema'))}</span> ${s.builtin ? esc(t('nf_noform')) : nfLink(s.node, s.name)}${s.file ? ` <code>${esc(s.file)}</code>` : ''}${s.missing ? ` <span class="nf-miss">${esc(t('nf_missing'))}</span>` : ''}${s.rule && f.schemas.length > 1 ? ` <span class="muted">${esc(t('nf_if'))}</span> <code>${esc(s.rule)}</code>` : ''}</div>`).join('');
}
const nfLink = (id, txt) => id && nodeById[id] ? `<a href="#" data-go="${esc(id)}">${esc(txt)}</a>` : esc(txt);
function nfAct(a) {
  if (!a || (!a.name && !a.type)) return '';
  const typ = { NO_AUTHN: t('nf_decision'), NOAUTH: t('nf_decision'), LOCAL: t('nf_local'), ASSIGNMENT: t('nf_assign') }[a.type] || a.type;
  const pi = a.opts && Object.keys(a.opts).length ? nfP.push(a) - 1 : -1;
  return `<span class="nf-type">${esc(typ || '?')}</span>${a.name && a.name !== a.type ? ' ' + nfLink(a.node, a.name) : ''}${a.missing ? ` <span class="nf-miss">${esc(t('nf_missing'))}</span>` : ''}${pi >= 0 ? ` <button class="nf-pbtn" data-nfp="${pi}" title="${esc(t('nf_params'))}" aria-label="${esc(t('nf_params'))}">⋯</button>` : ''}`;
}
function nfRow(g, f, r, i) {
  let ok, ko;
  if (f.type === 'classic') {
    const sec = f.rows.some(x => x.role === 'secondary');
    ok = r.role === 'primary' && sec ? t('nf_to_secondary') : r.role === 'group extraction' ? t('nf_groups') : t('nf_done');
    ko = t('nf_next_or_fail');
  } else {
    const nx = r.next_id ? nfFactor(g, r.next_id) : null;
    ok = r.next ? (nx ? `→ ${nx.name}` : `→ ${r.next} (${t('nf_missing')})`) : t('nf_done');
    ko = r.goto === 'NEXT' ? t('nf_next_pol') : r.goto && r.goto !== 'END' ? `goto ${r.goto}` : t('nf_fail');
  }
  const role = r.role ? `<span class="nf-tag">${esc(t('nf_role_' + r.role.replace(' ', '_')))}</span> ` : '';
  return `<li class="nf-row" data-next="${esc(r.next_id || '')}"><span class="nf-prio" title="${esc(t('nf_prio'))}">${esc(r.prio || '–')}</span>
    <div class="nf-main"><div>${role}${nfLink(r.node, r.policy)} ${nfAct(r.action)}</div>${r.rule && !/^(ns_)?true$/i.test(r.rule) ? `<code class="nf-rule" title="${esc(r.rule)}">${esc(r.rule)}</code>` : ''}</div>
    <div class="nf-out"><span class="nf-ok">✓ ${esc(ok)}</span><span class="nf-ko">✗ ${esc(ko)}</span></div><span class="nf-port"></span></li>`;
}
function nfCard(g, id, depth) {
  const f = nfFactor(g, id);
  return `<div class="nf-card" data-fid="${esc(id)}"><div class="nf-h"><span class="nf-step">${esc(t('nf_factor', { n: depth + 1 }))}</span><span class="nf-k">${esc(nfKind(f))}</span> <b>${nfLink(f.node, f.name)}</b></div>
    ${nfSchema(f)}<ol class="nf-rows">${f.rows.map((r, i) => nfRow(g, f, r, i)).join('') || `<li class="muted nf-empty">${esc(t('nf_nopol'))}</li>`}</ol>
    <div class="nf-end muted">${esc(t('nf_nomatch'))}</div></div>`;
}
function renderNfactor() {
  const box = $('#nfactor'); if (!box) return;
  if (!nfHas()) { box.innerHTML = `<p class="muted">${esc(t('nf_none'))}</p>`; return; }
  nfSel = Math.min(nfSel, nfEntries.length - 1); nfP = [];
  const multi = Object.keys(NF).length > 1, gname = g => (D.groups.find(x => x.id === g) || {}).name || '';
  const list = nfEntries.map((e, i) => { const f = nfFactor(e.group, e.factor);
    return `<button class="nf-entry${i === nfSel ? ' on' : ''}" data-i="${i}" aria-pressed="${i === nfSel}"><span class="nf-k">${esc(kindLabel((nodeById[e.node] || {}).kind || 'aaavs'))}</span> <b>${esc(e.name)}</b>${f && e.node !== e.factor && f.type !== 'classic' ? `<span class="muted">→ ${esc(f.name)}</span>` : ''}${multi ? `<span class="muted nf-g">${esc(gname(e.group))}</span>` : ''}</button>`; }).join('');
  const e = nfEntries[nfSel], cols = nfLevels(e);
  const head = `<div class="nf-path"><span class="nf-k">${esc(kindLabel((nodeById[e.node] || {}).kind || 'aaavs'))}</span> ${nfLink(e.node, e.name)}${e.via && e.via !== 'classic' ? ` <span class="muted">→ ${esc(t('nf_via'))}</span> <code>${esc(e.via)}</code>` : ''}${e.node !== e.factor && e.via !== 'classic' ? ` <span class="muted">→</span> ${esc(nfFactor(e.group, e.factor).name)}` : ''}</div>`;
  const cc = gwCc(e.clientcert, t('nf_cc_entry', { n: e.name })) + (e.aaa_clientcert ? gwCc(e.aaa_clientcert, t('nf_cc_aaa', { n: nfFactor(e.group, e.factor).name })) : '');
  box.innerHTML = `<div class="nf-wrap"><aside class="nf-list"><h2 class="hrow">${esc(t('nf_entries'))}${infoBtn(esc(t('nf_info')))}</h2>${list}</aside>
    <div class="nf-flowbox">${head}${cc ? `<div class="nf-cc">${cc}</div>` : ''}<div class="nf-flow"><svg class="nf-svg" aria-hidden="true"></svg>${cols.map((c, d) => `<div class="nf-col">${c.map(id => nfCard(e.group, id, d)).join('')}</div>`).join('')}</div></div></div>`;
  $$('#nfactor .nf-entry').forEach(b => b.onclick = () => { nfSel = +b.dataset.i; renderNfactor(); });
  $$('#nfactor [data-go]').forEach(a => a.onclick = ev => { ev.preventDefault(); goTo(a.dataset.go); });
  $$('#nfactor [data-nfp]').forEach(b => b.onclick = () => { const a = nfP[+b.dataset.nfp], names = (NF[e.group] || {}).names;
    paramDlg(t('nf_params_t', { a: a.name }), a.type + (a.etype ? ' · ' + a.etype : ''), [t('gw_param'), t('gw_value')], Object.entries(a.opts).map(([k, v]) => [`<code>${esc(optLabel(k, names))}</code>`, esc(v)])); });
  requestAnimationFrame(nfArrows);
}
// arrows from a policy row (success) to the card of its next factor
function nfArrows() {
  const flow = $('#nfactor .nf-flow'), svg = flow && flow.querySelector('.nf-svg'); if (!svg || !flow.offsetParent) return;
  const fb = flow.getBoundingClientRect(); svg.setAttribute('width', flow.scrollWidth); svg.setAttribute('height', flow.scrollHeight);
  const cards = {}; $$('#nfactor .nf-card').forEach(c => cards[c.dataset.fid] = c);
  const col = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#4f46e5';
  let p = `<defs><marker id="nf-ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="${col}"/></marker></defs>`;
  $$('#nfactor .nf-row[data-next]').forEach(r => {
    const tg = cards[r.dataset.next]; if (!r.dataset.next || !tg) return;
    const a = r.querySelector('.nf-port').getBoundingClientRect(), b = tg.getBoundingClientRect();
    const x1 = a.right - fb.left + flow.scrollLeft, y1 = a.top + a.height / 2 - fb.top + flow.scrollTop;
    const back = b.left - fb.left + flow.scrollLeft < x1;
    const x2 = (back ? b.right : b.left) - fb.left + flow.scrollLeft, y2 = b.top + 22 - fb.top + flow.scrollTop, dx = Math.max(30, Math.abs(x2 - x1) / 2);
    p += `<path d="M${x1} ${y1} C${x1 + dx} ${y1} ${x2 + (back ? dx : -dx)} ${y2} ${x2} ${y2}" fill="none" stroke="${col}" stroke-width="1.6" marker-end="url(#nf-ar)" opacity=".8"/>`;
  });
  svg.innerHTML = p;
}
addEventListener('resize', () => { if (curTab === 'nfactor') nfArrows(); });
// open the flow that contains a node (from the topology details)
function nfEntryFor(id) {
  let i = nfEntries.findIndex(e => e.node === id || e.factor === id); if (i >= 0) return i;
  i = nfEntries.findIndex(e => nfLevels(e).flat().some(fid => { const f = nfFactor(e.group, fid); return f.node === id || f.rows.some(r => r.node === id || (r.action && r.action.node === id)) || f.schemas.some(s => s.node === id); }));
  return i;
}
function nfOpen(id) { const i = nfEntryFor(id); if (i < 0) return; nfSel = i; showTab('nfactor'); renderNfactor(); }
