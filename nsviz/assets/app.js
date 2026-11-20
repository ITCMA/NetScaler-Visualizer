(function () {
'use strict';
const D = JSON.parse(document.getElementById('data').textContent);
const I18N = JSON.parse(document.getElementById('i18n').textContent);
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = { get(k) { try { return localStorage.getItem('nsviz.' + k); } catch (e) { return null; } }, set(k, v) { try { localStorage.setItem('nsviz.' + k, v); } catch (e) { /* file:// ohne Speicher */ } }, forget(k) { try { localStorage.removeItem('nsviz.' + k); } catch (e) { /* ignore */ } } };
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---- i18n -------------------------------------------------------------------------------------
const LANGS = Object.keys(I18N);
let lang = 'en';
function detectLang() {
  const saved = store.get('lang'); if (saved && I18N[saved]) return saved;
  for (const l of (navigator.languages || [navigator.language || 'en'])) { const p = String(l).toLowerCase().split('-')[0]; if (I18N[p]) return p; }
  return 'en';
}
function t(k, v) {
  let s = (I18N[lang] && I18N[lang][k]) || (I18N.en && I18N.en[k]) || k;
  if (v) Object.keys(v).forEach(x => { s = s.split('{' + x + '}').join(v[x]); });
  return s;
}
const SEV = D.meta.severities, SEVCOL = { critical: '#b91c1c', high: '#c2410c', medium: '#ca8a04', low: '#2563eb', info: '#64748b' };
const kindLabel = k => t('kind_' + k) !== 'kind_' + k ? t('kind_' + k) : (D.meta.kind_labels[k] || k);
const catLabel = c => t('cat_' + c);
const pick = o => (o && typeof o === 'object') ? (o[lang] || o.en || '') : (o || '');
const ruleText = r => (r && r.texts) ? (r.texts[lang] || r.texts.en) : {};
const msgOf = f => pick(f.msgs);
const propLabel = k => (I18N[lang] || {})['prop_' + k.toLowerCase().replace(/[^a-z0-9]+/g, '_')] || k;
const sevLabel = s => t('sev_' + s);
const dateStr = () => { try { return new Date(D.meta.created).toLocaleString(lang); } catch (e) { return D.meta.created; } };

// ---- Theme ------------------------------------------------------------------------------------
let themePref = store.get('theme') || 'auto';
const mq = matchMedia('(prefers-color-scheme: dark)');
const resolved = () => themePref === 'auto' ? (mq.matches ? 'dark' : 'light') : themePref;
function applyTheme() {
  document.documentElement.dataset.resolved = resolved();
  $$('#theme button').forEach(b => b.setAttribute('aria-checked', b.dataset.theme === themePref));
  if (window.cy) { styleGraph(); }
}
mq.addEventListener && mq.addEventListener('change', () => { if (themePref === 'auto') applyTheme(); });
$$('#theme button').forEach(b => { b.onclick = () => { themePref = b.dataset.theme; store.set('theme', themePref); applyTheme(); toast(t('t_' + themePref)); }; });
$$('#theme button').forEach(b => { b.title = t('t_' + b.dataset.theme); });

// ---- Hilfen -----------------------------------------------------------------------------------
const findingsById = {}; D.findings.forEach(f => findingsById[f.id] = f);
const nodeById = {}; D.nodes.forEach(n => nodeById[n.id] = n);
const sevRank = s => SEV.indexOf(s);
function worst(ids) { let w = 99; ids.forEach(i => { const r = sevRank(findingsById[i].severity); if (r < w) w = r; }); return w === 99 ? null : SEV[w]; }
let toastTimer; function toast(msg) { const el = $('#toast'); el.textContent = msg; el.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 1600); }
function announce(msg) { $('#live').textContent = ''; setTimeout(() => $('#live').textContent = msg, 30); }
const SEVW = { critical: 15, high: 7, medium: 3, low: 1, info: 0 };
const score = Math.round(100 * Math.exp(-D.findings.reduce((a, f) => a + SEVW[f.severity], 0) / (40 + D.nodes.length * 1.5)));

// ---- Tabs -------------------------------------------------------------------------------------
const TABS = ['overview', 'topo', 'findings', 'inventory', 'project', 'links', 'rules'];
let curTab = 'overview';
function renderTabs() {
  const hi = D.findings.filter(f => ['critical', 'high'].includes(f.severity)).length;
  $('#tabs').innerHTML = TABS.map((k, i) => `<button role="tab" id="tb-${k}" data-tab="${k}" aria-controls="tab-${k}" aria-selected="${k === curTab}" tabindex="${k === curTab ? 0 : -1}">${esc(t('tab_' + k))}${k === 'findings' && hi ? `<span class="badge">${hi}</span>` : ''}</button>`).join('');
  $$('#tabs button').forEach(b => { b.onclick = () => showTab(b.dataset.tab); b.onkeydown = e => { const i = TABS.indexOf(b.dataset.tab); const n = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key]; if (n !== undefined) { e.preventDefault(); showTab(TABS[(n + TABS.length) % TABS.length]); $('#tb-' + curTab).focus(); } }; });
}
function showTab(k) {
  curTab = k;
  $$('#tabs button').forEach(b => { const on = b.dataset.tab === k; b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1; });
  $$('.tab').forEach(s => { const on = s.id === 'tab-' + k; s.classList.toggle('active', on); s.setAttribute('aria-labelledby', 'tb-' + s.id.slice(4)); });
  if (k === 'topo' && window.cy) { cy.resize(); if (!laidOut) { laidOut = true; initialLayout(); } else if (lkDirty) { lkDirty = false; layout(); } }
}

// ---- Graph ------------------------------------------------------------------------------------
const HUE = { device: [220, 12], csvs: [212, 70], lbvs: [145, 60], gwvs: [32, 85], aaavs: [268, 60], gslbvs: [175, 60], svc: [215, 18], sg: [225, 22], server: [210, 8], monitor: [52, 80], gslbsvc: [190, 60], gslbsite: [185, 65], cert: [350, 70], sslprofile: [325, 60], nflabel: [282, 55], schema: [262, 55], authnprofile: [255, 55], appfwprof: [24, 80], policylabel: [232, 30], policy: [225, 25], action: [200, 35], group: [300, 40], cipher: [340, 35], vlan: [95, 45], netip: [120, 40], route: [75, 40], authpol: [255, 45], authact: [285, 50], domain: [168, 55], sta: [200, 40], missing: [0, 0] };
const SHAPE = { device: 'round-rectangle', csvs: 'round-rectangle', lbvs: 'round-rectangle', gwvs: 'round-rectangle', aaavs: 'round-rectangle', gslbvs: 'round-rectangle', svc: 'ellipse', sg: 'barrel', server: 'rectangle', monitor: 'diamond', gslbsvc: 'ellipse', gslbsite: 'round-rectangle', cert: 'tag', sslprofile: 'tag', nflabel: 'round-hexagon', schema: 'round-tag', authnprofile: 'round-rectangle', appfwprof: 'round-pentagon', policylabel: 'round-hexagon', policy: 'hexagon', authpol: 'hexagon', authact: 'round-rectangle', domain: 'round-tag', sta: 'round-rectangle', missing: 'round-rectangle' };
const kindFill = (k, dark) => { const h = HUE[k] || HUE.policy; return dark ? `hsl(${h[0]}, ${Math.min(h[1], 45)}%, 24%)` : `hsl(${h[0]}, ${h[1]}%, 91%)`; };
const kindStroke = (k, dark) => { const h = HUE[k] || HUE.policy; return dark ? `hsl(${h[0]}, ${Math.min(h[1] + 10, 60)}%, 58%)` : `hsl(${h[0]}, ${Math.min(h[1], 55)}%, 42%)`; };
const SEVDARK = { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#60a5fa' };

const HIDDEN_KINDS = ['policy', 'action', 'policylabel']; // switched on via the object-type list
const unlinkedSet = new Set((D.unlinked || []).map(u => u.node));
const kindsPresent = {}; D.nodes.forEach(n => kindsPresent[n.kind] = (kindsPresent[n.kind] || 0) + 1);
const state = { group: '', collapsed: new Set(), kinds: new Set(Object.keys(kindsPresent).filter(k => !HIDDEN_KINDS.includes(k))), pinned: new Set(), onlyUnlinked: false, layout: store.get('layout') || 'tiers', contains: false, far: false, focus: true, onlyFindings: false, labels: false, hits: [], hitIdx: -1, selected: null };
cytoscape.use(cytoscapeDagre);
const elements = D.nodes.map(n => ({ group: 'nodes', data: { id: n.id, label: n.label, kind: n.kind, grp: n.group, sev: worst(n.findings) || '', nf: n.findings.length, unl: unlinkedSet.has(n.id) } }))
  .concat(D.edges.map(e => ({ group: 'edges', data: { id: e.id, source: e.source, target: e.target, type: e.type, elabel: e.label, port: !!e.port } })));
const cy = cytoscape({ container: $('#cy'), elements, wheelSensitivity: 0.25, minZoom: 0.03, maxZoom: 3, boxSelectionEnabled: false, textureOnViewport: false });
window.cy = cy;
// ---- Icons (own simple line symbols, 24x24 grid; no third-party artwork) -------------------------
const ICONS = {
  lb: '<path d="M12 3v5M12 8l-6 6M12 8l6 6M6 14v5M18 14v5M12 8v11"/>',
  cs: '<path d="M12 3v18M12 7h6l3 3-3 3h-6M12 11H6l-3 3 3 3h6"/>',
  gw: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12h6M13 9l3 3-3 3"/>',
  aaa: '<circle cx="9" cy="9" r="4"/><path d="M12 12l8 8M17 17l2-2M15 15l2-2"/>',
  gslb: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  svc: '<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M8 7h.01M8 17h.01"/>',
  srv: '<path d="M12 3l8 4v10l-8 4-8-4V7z"/><path d="M4 7l8 4 8-4M12 11v10"/>',
  mon: '<path d="M3 12h4l2-6 4 12 2-6h6"/>',
  pol: '<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 13l2 2 4-4"/>',
  act: '<path d="M13 2L5 14h6l-1 8 8-12h-6z"/>',
  cert: '<circle cx="12" cy="9" r="6"/><path d="M9 14l-2 7 5-3 5 3-2-7M10 9l1.5 1.5L14.5 7"/>',
  tls: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  waf: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8 10h8M8 14h8M12 7v10"/>',
  flow: '<rect x="3" y="4" width="6" height="5" rx="1"/><rect x="15" y="4" width="6" height="5" rx="1"/><rect x="9" y="15" width="6" height="5" rx="1"/><path d="M9 6.5h6M6 9v3h12V9M12 12v3"/>',
  dev: '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 12h.01M11 12h.01M17 12h-3"/>',
  net: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5l-6 5.5M12 11.5l6 5.5"/>',
  miss: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
};
const ICON_BY_KIND = { device: 'dev', csvs: 'cs', lbvs: 'lb', gwvs: 'gw', aaavs: 'aaa', gslbvs: 'gslb', svc: 'svc', sg: 'svc', server: 'srv', monitor: 'mon', gslbsvc: 'gslb', gslbsite: 'gslb', cert: 'cert', sslprofile: 'tls', cipher: 'tls', nflabel: 'flow', schema: 'flow', authnprofile: 'aaa', appfwprof: 'waf', policylabel: 'pol', policy: 'pol', authpol: 'pol', action: 'act', authact: 'act', group: 'aaa', vlan: 'net', netip: 'net', route: 'net', domain: 'net', sta: 'srv', missing: 'miss' };
const iconOf = k => ICONS[ICON_BY_KIND[k] || 'pol'];
// Tiers (left -> right): device | entry (CS/Gateway/AAA/GSLB) | load balancing | services | servers & monitors | configuration objects
const TIER_OF = { device: 0, csvs: 1, gwvs: 1, aaavs: 1, gslbvs: 1, lbvs: 2, svc: 3, sg: 3, gslbsvc: 3, gslbsite: 3, server: 4, monitor: 4, sta: 4 };
const TIER_KEYS = ['tier_dev', 'tier_entry', 'tier_lb', 'tier_svc', 'tier_back', 'tier_cfg'];
const tierOf = k => k in TIER_OF ? TIER_OF[k] : 5;
// Object types hidden at first (can be switched on via the legend / object types); frequent, rarely the first thing you look for
const CARD_W = 190, CARD_H = 44, FAR_ZOOM = 0.36;
const svgUri = s => 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(s);
function cardImages(kind, dark, hc) {
  const c = kindStroke(kind, dark), g = `<g transform="translate(%X% %Y%) scale(%S%)" fill="none" stroke="${c}" stroke-width="${hc ? 2.3 : 1.9}" stroke-linecap="round" stroke-linejoin="round">${iconOf(kind)}</g>`;
  const full = `<svg xmlns="http://www.w3.org/2000/svg" width="${CARD_W}" height="${CARD_H}" viewBox="0 0 ${CARD_W} ${CARD_H}"><rect width="6" height="${CARD_H}" fill="${c}"/><circle cx="29" cy="22" r="15" fill="${c}" fill-opacity="${dark ? .28 : .16}"/>${g.replace('%X%', 18).replace('%Y%', 11).replace('%S%', .9167)}</svg>`;
  const far = `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" fill="${dark ? '#171c30' : '#ffffff'}" stroke="${c}" stroke-width="2"/>${g.replace('%X%', 11).replace('%Y%', 11).replace('%S%', 1.1667)}</svg>`;
  return [svgUri(full), svgUri(far)];
}
const imgCache = {};
function imagesFor(kind, dark, hc) { const key = kind + (dark ? 'd' : 'l') + (hc ? 'h' : ''); return imgCache[key] || (imgCache[key] = cardImages(kind, dark, hc)); }
function iconSvg(kind, size, color) { return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="${color}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconOf(kind)}</svg>`; }
const contrastMq = matchMedia('(prefers-contrast: more)');
contrastMq.addEventListener && contrastMq.addEventListener('change', () => { if (window.cy) styleGraph(); renderKinds(); });

function styleGraph() {
  const dark = resolved() === 'dark', hc = contrastMq.matches;
  const txt = hc ? (dark ? '#ffffff' : '#000000') : (dark ? '#e8ecf8' : '#161b2e');
  const edge = hc ? (dark ? '#cbd5e1' : '#334155') : (dark ? '#64748b' : '#94a3b8'), bgc = dark ? '#0e1220' : '#f4f6fb';
  const card = hc ? (dark ? '#000000' : '#ffffff') : (dark ? '#171c30' : '#ffffff');
  const sc = dark ? SEVDARK : SEVCOL, amber = dark ? '#fbbf24' : '#b45309';
  cy.style([
    { selector: 'node', style: { 'label': 'data(disp)', 'font-size': 10.5, 'font-weight': 500, 'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'wrap', 'text-max-width': 134, 'text-margin-x': 22, 'line-height': 1.25, 'width': CARD_W, 'height': CARD_H, 'border-width': hc ? 2.5 : 1.2, 'color': txt, 'shape': 'round-rectangle', 'background-color': card, 'background-fit': 'cover', 'background-image': 'data(img)', 'background-image-containment': 'inside', 'background-clip': 'node', 'background-width': '100%', 'background-height': '100%', 'transition-property': 'opacity, border-color', 'transition-duration': 150 } },
    { selector: 'node.far', style: { 'width': 48, 'height': 48, 'shape': 'ellipse', 'text-opacity': 0, 'background-image': 'data(imgFar)', 'background-color': 'transparent', 'background-opacity': 0, 'border-width': 0 } },
    { selector: 'node.far[sev]', style: { 'border-width': 0 } },
    { selector: 'node.far[nf > 0]', style: { 'underlay-color': '#ef4444', 'underlay-opacity': .35, 'underlay-padding': 4, 'underlay-shape': 'ellipse' } },
    { selector: 'edge', style: { 'width': hc ? 2.2 : 1.5, 'line-color': edge, 'target-arrow-color': edge, 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'arrow-scale': .85, 'font-size': 9.5, 'font-weight': 600, 'color': dark ? '#cbd5e1' : '#334155', 'text-background-color': card, 'text-background-opacity': 1, 'text-background-padding': 3, 'text-background-shape': 'round-rectangle', 'text-border-opacity': 1, 'text-border-width': 1, 'text-border-color': edge, 'text-border-style': 'solid' } },
    { selector: 'edge[type="contains"]', style: { 'line-color': dark ? '#2b3454' : '#d5dbe8', 'target-arrow-shape': 'none', 'width': 1 } },
    { selector: 'edge[type="doublehop"]', style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', 'line-style': 'dashed', 'width': 3.2 } },
    { selector: 'edge[type="loop"]', style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316', 'line-style': 'dashed' } },
    { selector: 'edge[type="route"]', style: { 'line-color': '#3b82f6', 'target-arrow-color': '#3b82f6', 'width': 2.2 } },
    { selector: 'edge[type="nfactor"]', style: { 'line-color': '#8b5cf6', 'target-arrow-color': '#8b5cf6' } },
    { selector: 'edge[type="auth"]', style: { 'line-color': '#8b5cf6', 'target-arrow-color': '#8b5cf6', 'line-style': 'dotted' } },
    { selector: 'edge[type="ssl"]', style: { 'line-color': '#f43f5e', 'target-arrow-color': '#f43f5e', 'width': 1, 'opacity': .55 } },
    { selector: 'edge[type="gslb"]', style: { 'line-color': '#06b6d4', 'target-arrow-color': '#06b6d4' } },
    { selector: 'edge[type="link"]', style: { 'line-color': dark ? '#e879f9' : '#a21caf', 'target-arrow-color': dark ? '#e879f9' : '#a21caf', 'width': 3.4, 'line-style': 'solid', 'color': dark ? '#e879f9' : '#a21caf', 'text-border-color': dark ? '#e879f9' : '#a21caf' } },
    { selector: 'edge.virtual', style: { 'line-color': dark ? '#38bdf8' : '#0369a1', 'target-arrow-color': dark ? '#38bdf8' : '#0369a1', 'width': 2.2, 'line-style': 'solid', 'color': dark ? '#7dd3fc' : '#075985', 'text-border-color': dark ? '#38bdf8' : '#0369a1' } },
    { selector: 'node[?unl]', style: { 'border-style': 'dashed' } },
    { selector: 'edge[type="backup"]', style: { 'line-style': 'dotted' } },
    // Plaintext (not TLS): dashed line + dashed label frame + amber, so it is recognisable without colour
    { selector: 'edge[?plain]', style: { 'line-style': 'dashed', 'line-dash-pattern': [7, 4], 'line-color': amber, 'target-arrow-color': amber, 'width': 2.2, 'color': amber, 'text-border-style': 'dashed', 'text-border-color': amber } },
    { selector: 'node[sev="critical"]', style: { 'border-color': sc.critical, 'border-width': 4 } },
    { selector: 'node[sev="high"]', style: { 'border-color': sc.high, 'border-width': 4 } },
    { selector: 'node[sev="medium"]', style: { 'border-color': sc.medium, 'border-width': 3 } },
    { selector: 'node[sev="low"]', style: { 'border-color': sc.low, 'border-width': 2.5 } },
    { selector: 'node[kind="missing"]', style: { 'border-style': 'dashed', 'border-color': '#ef4444', 'color': '#ef4444' } },
    { selector: '.dim', style: { 'opacity': .14 } },
    { selector: 'edge.onpath', style: { 'width': 3.4, 'z-index': 9 } },
    { selector: '.hit', style: { 'overlay-color': '#facc15', 'overlay-opacity': .5, 'overlay-padding': 6 } },
    { selector: 'node:selected', style: { 'overlay-color': dark ? '#8b8cf8' : '#4f46e5', 'overlay-opacity': .28, 'overlay-padding': 8 } },
    { selector: 'edge.far', style: { 'label': '' } },
    { selector: 'edge.nolabels[!port]', style: { 'label': '' } },
    { selector: 'edge.labels', style: { 'label': 'data(elabel)' } },
    { selector: 'edge[?port]', style: { 'label': 'data(elabel)' } },
    { selector: 'edge.far[?port]', style: { 'label': '' } },
    { selector: 'edge.hidec', style: { 'display': 'none' } },
    { selector: 'edge.virtual.far', style: { 'label': '' } },
  ]);
  cy.nodes().forEach(n => {
    const k = n.data('kind'), im = imagesFor(k, dark, hc);
    n.data('img', im[0]); n.data('imgFar', im[1]);
    if (k !== 'missing') n.style({ 'background-color': card, 'border-color': n.data('sev') ? sc[n.data('sev')] : kindStroke(k, dark) });
  });
  drawOverlay();
}

let roots = [], depth = {}, succ = {}, laidOut = false;
function eligible() {
  const set = new Set();
  cy.nodes().forEach(n => { const d = nodeById[n.id()]; if (state.group && d.group !== state.group) return; if (!state.kinds.has(d.kind)) return; set.add(n.id()); });
  if (state.onlyUnlinked) { [...set].forEach(id => { if (!unlinkedSet.has(id)) set.delete(id); }); }
  const pin = s => { state.pinned.forEach(id => { if (nodeById[id]) s.add(id); }); return s; };
  if (state.onlyFindings) { const keep = new Set(); set.forEach(id => { if (nodeById[id].findings.length) { keep.add(id); cy.getElementById(id).neighborhood('node').forEach(m => { if (set.has(m.id())) keep.add(m.id()); }); } }); return pin(keep); }
  return pin(set);
}
// Objects of hidden types (policies, actions, ...) must not cut a chain: visible objects are connected "through" them by
// a bridge edge that names the hidden objects it passes (e.g. CS vServer -> [policy, action] -> LB vServer).
let curBridges = [];
function computeBridges(elig) {
  const out = {}; cy.edges().forEach(e => { if (e.hasClass('virtual') || e.data('type') === 'contains') return; (out[e.data('source')] = out[e.data('source')] || []).push(e.data('target')); });
  const res = [], seen = new Set();
  elig.forEach(u => {
    const walk = (x, via, vis) => {
      (out[x] || []).forEach(v => {
        if (vis.has(v) || via.length > 6) return;
        if (elig.has(v)) { if (v !== u && !(out[u] || []).includes(v)) { const k = u + '>' + v; if (!seen.has(k)) { seen.add(k); res.push({ s: u, t: v, via: via.slice() }); } } return; }
        if (nodeById[v] && nodeById[v].kind === 'device') return;
        const nv = new Set(vis); nv.add(v); walk(v, via.concat(nodeById[v] ? nodeById[v].label : v), nv);
      });
    };
    walk(u, [], new Set([u]));
  });
  return res;
}
function computeVisible(elig) {
  succ = {}; const pred = {}; elig.forEach(id => { succ[id] = []; pred[id] = 0; });
  cy.edges().forEach(e => { if (e.hasClass('virtual')) return; const s = e.data('source'), tg = e.data('target'); if (elig.has(s) && elig.has(tg)) { succ[s].push(tg); pred[tg]++; } });
  curBridges = computeBridges(elig); curBridges.forEach(b => { succ[b.s].push(b.t); pred[b.t]++; });
  roots = []; const mark = new Set(); depth = {};
  const bfs = starts => { let q = starts.slice(); starts.forEach(s => { if (!(s in depth)) depth[s] = 0; mark.add(s); }); while (q.length) { const nq = []; q.forEach(u => succ[u].forEach(v => { if (!mark.has(v)) { mark.add(v); depth[v] = depth[u] + 1; nq.push(v); } })); q = nq; } };
  const r0 = [...elig].filter(id => pred[id] === 0); roots = r0.slice(); bfs(r0);
  elig.forEach(id => { if (!mark.has(id)) { roots.push(id); bfs([id]); } });
  const vis = new Set(roots); let q = roots.slice();
  while (q.length) { const nq = []; q.forEach(u => { if (state.collapsed.has(u)) return; succ[u].forEach(v => { if (!vis.has(v)) { vis.add(v); nq.push(v); } }); }); q = nq; }
  return vis;
}
const clip = (s, n) => s.length > n ? s.slice(0, n - 1) + '…' : s;
function subtitle(d) {
  const ep = d.props && d.props['IP:Port'];
  return clip(kindLabel(d.kind) + (ep ? ' · ' + ep : ''), 30);
}
function refresh(relayout) {
  const vis = computeVisible(eligible());
  cy.batch(() => {
    cy.edges('.virtual').remove();
    curBridges.forEach(b => { const lab = b.via.length > 2 ? b.via.slice(0, 2).join(' → ') + ` +${b.via.length - 2}` : b.via.join(' → '); cy.add({ group: 'edges', classes: 'virtual', data: { id: `vb|${b.s}|${b.t}`, source: b.s, target: b.t, type: 'via', elabel: clip(lab, 34), port: true } }); });
    cy.nodes().forEach(n => {
      const id = n.id(), v = vis.has(id); n.style('display', v ? 'element' : 'none'); const h = (succ[id] || []).length, d = nodeById[id];
      n.data('disp', clip(n.data('label') || '', 21) + (state.collapsed.has(id) && h ? `  ▸${h}` : '') + (n.data('nf') ? `  ⚠${n.data('nf')}` : '') + '\n' + subtitle(d));
    });
    cy.edges().forEach(e => { const ok = vis.has(e.data('source')) && vis.has(e.data('target')) && (e.data('type') !== 'contains' || state.contains); e.style('display', ok ? 'element' : 'none'); });
    cy.edges().toggleClass('labels', state.labels);
  });
  if (relayout) layout();
  renderLegend(); renderKinds();
}
const ROW = CARD_H + 12, COLW = CARD_W + 120, GAPY = 64;
let tierCols = [], frames = [];
function layout(animate) {
  const eles = cy.elements(':visible'); if (!eles.length) return;
  const how = state.layout;
  frames = []; tierCols = [];
  const dg = (dir, ns, rs) => eles.layout({ name: 'dagre', rankDir: dir, nodeSep: ns, rankSep: rs, edgeSep: 6, animate: false, fit: false, padding: 36 }).run();
  if (how === 'radial') {
    const rt = cy.nodes(':visible').filter(n => roots.includes(n.id()));
    eles.layout({ name: 'breadthfirst', circle: true, roots: rt.length ? rt : undefined, spacingFactor: 1.15, avoidOverlap: true, animate: false, fit: false, padding: 36 }).run();
  } else if (how === 'down') dg('TB', 30, 70);
  else dg('LR', 14, 90);
  if (how === 'tiers') tiersLayout();
  const fit = () => cy.fit(eles, 36);
  fit(); applyZoomClass(); drawOverlay(); drawMini();
  if (animate && !reduceMotion) cy.animate({ fit: { eles, padding: 36 } }, { duration: 250 });
}
const TIER_CAP = 14; // max. rows per column; longer lists wrap into further columns so the graph keeps a usable shape
function tiersLayout() {
  const nodes = cy.nodes(':visible'), ys = {}; nodes.forEach(n => ys[n.id()] = n.position('y'));
  const present = [...new Set(nodes.map(n => tierOf(n.data('kind'))))].sort((a, b) => a - b);
  const order = D.groups.map(g => g.id), byGrp = {};
  nodes.forEach(n => { const g = n.data('grp') || ''; (byGrp[g] = byGrp[g] || []).push(n); });
  const gids = Object.keys(byGrp).sort((a, b) => { const ia = order.indexOf(a), ib = order.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  const GX = CARD_W + 24, sub = {};
  present.forEach(tr => { let m = 1; gids.forEach(g => { const c = byGrp[g].filter(n => tierOf(n.data('kind')) === tr).length; m = Math.max(m, Math.ceil(c / TIER_CAP)); }); sub[tr] = m; });
  let cur = 0; const colX = {};
  tierCols = present.map(tr => { const x0 = cur, w = sub[tr] * GX - 24 + 150; colX[tr] = x0 + 75 + CARD_W / 2; cur += w; return { tier: tr, x0, x1: cur }; });
  let y0 = 0;
  gids.forEach(g => {
    const cols = {}; byGrp[g].forEach(n => { const tr = tierOf(n.data('kind')); (cols[tr] = cols[tr] || []).push(n); });
    const rows = Math.max(...Object.values(cols).map(a => Math.min(a.length, TIER_CAP))), H = rows * ROW;
    Object.keys(cols).forEach(tr => {
      const a = cols[tr].sort((p, q) => ys[p.id()] - ys[q.id()]), per = Math.ceil(a.length / Math.ceil(a.length / TIER_CAP)), off = (H - per * ROW) / 2;
      a.forEach((n, i) => n.position({ x: colX[tr] + Math.floor(i / per) * GX, y: y0 + Math.max(0, off) + ((i % per) + .5) * ROW }));
    });
    const grp = D.groups.find(x => x.id === g);
    frames.push({ id: g, name: grp ? grp.name : '', x0: Math.min(...byGrp[g].map(n => n.position('x'))) - CARD_W / 2 - 14, x1: Math.max(...byGrp[g].map(n => n.position('x'))) + CARD_W / 2 + 14, y0: y0 - 34, y1: y0 + H + 12 });
    y0 += H + GAPY;
  });
}

// ---- Overlay: tier columns and device frames (HTML behind the canvas, follows pan/zoom) -----------------
const lanes = $('#lanes');
function drawOverlay() {
  if (!lanes) return;
  const z = cy.zoom(), p = cy.pan(), W = $('#cywrap').clientWidth, H = $('#cywrap').clientHeight, dark = resolved() === 'dark';
  let h = '';
  if (state.layout === 'tiers' && tierCols.length) {
    tierCols.forEach((c, i) => {
      const l = c.x0 * z + p.x, w = (c.x1 - c.x0) * z;
      h += `<div class="lane${i % 2 ? ' alt' : ''}" style="left:${l}px;width:${w}px"><span>${esc(t(TIER_KEYS[c.tier]))}</span></div>`;
    });
    frames.forEach(f => {
      const l = f.x0 * z + p.x, tp = f.y0 * z + p.y;
      h += `<div class="frame" style="left:${l}px;top:${tp}px;width:${(f.x1 - f.x0) * z}px;height:${(f.y1 - f.y0) * z}px"><b style="font-size:${Math.max(10, Math.min(15, 13 * z))}px">${esc(f.name)}</b></div>`;
    });
  }
  lanes.innerHTML = h;
}
function applyZoomClass() { const far = cy.zoom() < FAR_ZOOM; if (far !== state.far) { state.far = far; cy.elements().toggleClass('far', far); } }
cy.on('zoom pan', () => { applyZoomClass(); drawOverlay(); drawMini(); });
cy.on('resize', () => { drawOverlay(); drawMini(); });

// ---- Minimap ----------------------------------------------------------------------------------
const mini = $('#mini'), mctx = mini && mini.getContext('2d');
let miniRaf = 0, miniMap = null;
function drawMini() {
  if (!mctx) return; cancelAnimationFrame(miniRaf);
  miniRaf = requestAnimationFrame(() => {
    const dark = resolved() === 'dark', w = mini.width, h = mini.height; mctx.clearRect(0, 0, w, h);
    const ns = cy.nodes(':visible'); if (!ns.length) return;
    const bb = ns.boundingBox({ includeLabels: false }), pad = 40, bw = bb.w + pad, bh = bb.h + pad, s = Math.min(w / bw, h / bh);
    const ox = (w - bw * s) / 2 - (bb.x1 - pad / 2) * s, oy = (h - bh * s) / 2 - (bb.y1 - pad / 2) * s;
    miniMap = { s, ox, oy };
    ns.forEach(n => { const q = n.position(); mctx.fillStyle = kindStroke(n.data('kind'), dark); mctx.fillRect(q.x * s + ox - 4, q.y * s + oy - 2, 8, 4); });
    const ex = cy.extent(); mctx.strokeStyle = dark ? '#a5b4fc' : '#4f46e5'; mctx.lineWidth = 1.5; mctx.strokeRect(ex.x1 * s + ox, ex.y1 * s + oy, ex.w * s, ex.h * s);
  });
}
if (mini) {
  const jump = ev => { if (!miniMap) return; const r = mini.getBoundingClientRect(), x = (ev.clientX - r.left) * mini.width / r.width, y = (ev.clientY - r.top) * mini.height / r.height; const mx = (x - miniMap.ox) / miniMap.s, my = (y - miniMap.oy) / miniMap.s, z = cy.zoom(); cy.pan({ x: cy.width() / 2 - mx * z, y: cy.height() / 2 - my * z }); };
  let down = false; mini.addEventListener('pointerdown', e => { down = true; mini.setPointerCapture(e.pointerId); jump(e); });
  mini.addEventListener('pointermove', e => { if (down) jump(e); }); mini.addEventListener('pointerup', () => down = false);
}
function initialLayout() { refresh(false); if (cy.nodes().length > 120) setLevel(2); else layout(); }
function setLevel(n) { state.collapsed = new Set(); computeVisible(eligible()); Object.keys(depth).forEach(id => { if (depth[id] >= n - 1 && (succ[id] || []).length) state.collapsed.add(id); }); refresh(true); }
function toggleCollapse(id) { if (!(succ[id] || []).length) return; state.collapsed.has(id) ? state.collapsed.delete(id) : state.collapsed.add(id); refresh(true); }
cy.on('dbltap', 'node', ev => toggleCollapse(ev.target.id()));
cy.on('tap', 'node', ev => select(ev.target.id()));
cy.on('tap', ev => { if (ev.target === cy) clearSelection(); });
function clearSelection() { cy.elements().removeClass('dim onpath'); cy.$(':selected').unselect(); state.selected = null; renderDetail(null); }

function revealNode(id) {
  const d = nodeById[id]; if (!d) return;
  // Filters stay as they are: a hidden object is shown as a single exception (pinned), not its whole type or device.
  if ((state.group && d.group !== state.group) || !state.kinds.has(d.kind)) state.pinned.add(id);
  computeVisible(eligible());
  const prev = {}; let q = roots.slice(); const seen = new Set(roots);
  while (q.length) { const nq = []; q.forEach(u => (succ[u] || []).forEach(v => { if (!seen.has(v)) { seen.add(v); prev[v] = u; nq.push(v); } })); q = nq; }
  let cur = id; while (prev[cur]) { state.collapsed.delete(prev[cur]); cur = prev[cur]; }
  refresh(true);
}
function select(id, center) {
  const n = cy.getElementById(id); if (!n.length) return;
  state.selected = id; cy.$(':selected').unselect(); n.select();
  cy.edges().removeClass('onpath');
  if (state.focus) { const rel = n.union(n.predecessors()).union(n.successors()); cy.elements().addClass('dim'); rel.removeClass('dim'); rel.edges().addClass('onpath'); }
  if (center) cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), .9) }, { duration: reduceMotion ? 0 : 250 });
  const d = nodeById[id]; renderDetail(d);
  announce(`${d.label}, ${kindLabel(d.kind)}, ${t('d_findings', { n: d.findings.length })}`);
}
function goTo(id) { showTab('topo'); if (!cy.getElementById(id).visible()) revealNode(id); select(id, true); }

// Tastatur im Graph
$('#cy').addEventListener('keydown', e => {
  const cur = state.selected && cy.getElementById(state.selected); const vis = x => x.filter(':visible');
  const go = id => { if (id) select(id, true); };
  if (e.key === '+' || e.key === '=') { cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); return e.preventDefault(); }
  if (e.key === '-') { cy.zoom({ level: cy.zoom() / 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); return e.preventDefault(); }
  if (e.key === '0') { cy.fit(cy.elements(':visible'), 30); return e.preventDefault(); }
  if (e.key === 'Escape') { clearSelection(); return; }
  if (!cur || !cur.length) { if (['ArrowRight', 'ArrowLeft', 'ArrowUp', 'ArrowDown', 'Enter'].includes(e.key)) { const f = cy.nodes(':visible').sort((a, b) => a.position('x') - b.position('x') || a.position('y') - b.position('y'))[0]; if (f) go(f.id()); e.preventDefault(); } return; }
  if (e.key === 'ArrowRight') { const s = vis(cur.outgoers('node')).sort((a, b) => a.position('y') - b.position('y')); if (s.length) go(s[0].id()); e.preventDefault(); }
  else if (e.key === 'ArrowLeft') { const p = vis(cur.incomers('node')); if (p.length) go(p[0].id()); e.preventDefault(); }
  else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    const x = cur.position('x'), y = cur.position('y'); const col = vis(cy.nodes()).filter(n => Math.abs(n.position('x') - x) < 4 && n.id() !== cur.id());
    const cand = col.filter(n => e.key === 'ArrowDown' ? n.position('y') > y : n.position('y') < y).sort((a, b) => Math.abs(a.position('y') - y) - Math.abs(b.position('y') - y));
    if (cand.length) go(cand[0].id()); e.preventDefault();
  } else if (e.key === 'Enter' || e.key === ' ') { toggleCollapse(cur.id()); e.preventDefault(); }
});

// ---- Seitenleiste -----------------------------------------------------------------------------
$$('[data-level]').forEach(b => b.onclick = () => setLevel(+b.dataset.level));
$('#expand-all').onclick = () => { state.collapsed = new Set(); refresh(true); };
$('#fit').onclick = () => cy.fit(cy.elements(':visible'), 30);
$('#relayout').onclick = () => layout(true);
function resetGraph() {
  state.onlyUnlinked = false; $('#only-unlinked').checked = false;
  state.group = ''; state.collapsed = new Set(); state.pinned = new Set(); state.onlyFindings = false; state.labels = false; state.contains = false; state.focus = true; state.layout = 'tiers';
  state.kinds = new Set(Object.keys(kindsPresent).filter(k => !HIDDEN_KINDS.includes(k)));
  if (typeof connectOn !== 'undefined' && connectOn) setConnect(false);
  $('#search').value = ''; state.hits = []; state.hitIdx = -1; $('#hits').textContent = '';
  $('#only-findings').checked = false; $('#edge-labels').checked = false; $('#contains').checked = false; $('#focus').checked = true; $('#layout-sel').value = 'tiers';
  clearSelection(); renderGroups(); renderKinds();
  state.far = false; cy.elements().removeClass('far hit');
  if (cy.nodes().length > 120) setLevel(2); else refresh(true);
  toast(t('reset_done'));
}
function resetAll() { ['layout', 'legend', 'theme', 'lang'].forEach(k => store.forget(k)); legendOpen = true; themePref = 'auto'; applyTheme(); lang = detectLang(); ls.value = lang; resetGraph(); renderAll(); }
$('#reset-graph').onclick = resetGraph;
$('#reset-all').onclick = resetAll;
$('#layout-sel').value = state.layout;
$('#layout-sel').onchange = e => { state.layout = e.target.value; store.set('layout', state.layout); layout(true); };
$('#only-unlinked').onchange = e => { state.onlyUnlinked = e.target.checked; refresh(true); };
$('#contains').onchange = e => { state.contains = e.target.checked; refresh(true); };
$('#edge-labels').onchange = e => { state.labels = e.target.checked; refresh(false); };
$('#only-findings').onchange = e => { state.onlyFindings = e.target.checked; refresh(true); };
$('#focus').onchange = e => { state.focus = e.target.checked; if (!state.focus) cy.elements().removeClass('dim'); };
$('#png').onclick = () => { const a = document.createElement('a'); a.href = cy.png({ full: true, scale: 2, bg: getComputedStyle(document.body).backgroundColor }); a.download = 'netscaler-topology.png'; a.click(); toast('PNG ✓'); };
$('#group').onchange = e => { state.group = e.target.value; refresh(true); };
function renderKinds() {
  const box = $('#kinds'); if (!box) return; box.innerHTML = '';
  const dark = resolved() === 'dark';
  Object.keys(kindsPresent).sort((a, b) => tierOf(a) - tierOf(b) || kindLabel(a).localeCompare(kindLabel(b), lang)).forEach(k => {
    const on = state.kinds.has(k), c = kindStroke(k, dark), l = document.createElement('label'); l.className = 'chk kind' + (on ? '' : ' off');
    l.innerHTML = `<input type="checkbox" data-k="${k}" ${on ? 'checked' : ''}><span class="ico" style="border-color:${c};background:${kindFill(k, dark)}">${iconSvg(k, 16, c)}</span><span class="nm">${esc(kindLabel(k))}</span><span class="muted cnt">${kindsPresent[k]}</span>`;
    l.querySelector('input').onchange = e => { e.target.checked ? state.kinds.add(k) : state.kinds.delete(k); refresh(true); };
    box.appendChild(l);
  });
}
function renderUnlinked() {
  const box = $('#unlinked'); if (!box) return;
  const by = {}; (D.unlinked || []).forEach(u => (by[u.kind] = by[u.kind] || []).push(u));
  const kinds = Object.keys(by).sort((x, y) => tierOf(x) - tierOf(y) || kindLabel(x).localeCompare(kindLabel(y), lang));
  box.innerHTML = `<details ${kinds.length && kinds.length < 5 ? 'open' : ''}><summary>${esc(t('unl_h', { n: (D.unlinked || []).length }))}</summary><p class="muted small">${esc(t('unl_hint'))}</p>` +
    (kinds.length ? kinds.map(k => `<details><summary class="small">${esc(kindLabel(k))} (${by[k].length})</summary><ul class="unl">${by[k].slice(0, 200).map(u => `<li><a href="#" data-goto="${esc(u.node)}">${esc(u.label)}</a></li>`).join('')}</ul></details>`).join('') : `<p class="small okc">✓ ${esc(t('unl_none'))}</p>`) + '</details>';
  $$('#unlinked [data-goto]').forEach(x => x.onclick = e => { e.preventDefault(); goTo(x.dataset.goto); });
}
function renderGroups() {
  const g = $('#group'); g.innerHTML = `<option value="">${esc(t('all_groups'))}</option>` + D.groups.map(x => `<option value="${x.id}" ${x.id === state.group ? 'selected' : ''}>${esc(x.name)}</option>`).join('');
}
let legendOpen = store.get('legend') !== '0';
function renderLegend() {
  const amber = resolved() === 'dark' ? '#fbbf24' : '#b45309';
  const ln = (style, txt) => `<div><svg width="30" height="8" aria-hidden="true"><line x1="0" y1="4" x2="30" y2="4" style="${style}"/></svg>${esc(txt)}</div>`;
  $('#legend').innerHTML = `<details ${legendOpen ? 'open' : ''}><summary>${esc(t('legend'))}</summary>` +
    ln('stroke:#94a3b8;stroke-width:3', t('lg_bind')) + ln('stroke:#3b82f6;stroke-width:3', t('lg_route')) +
    ln(`stroke:${amber};stroke-width:3;stroke-dasharray:7 4`, t('lg_plain')) + ln('stroke:#94a3b8;stroke-width:3;opacity:.5', t('lg_tls')) +
    ln(`stroke:${resolved() === 'dark' ? '#38bdf8' : '#0369a1'};stroke-width:3`, t('lg_via')) + ln('stroke:#94a3b8;stroke-width:3;stroke-dasharray:2 3', t('lg_unl')) + ln('stroke:#ef4444;stroke-width:3;stroke-dasharray:7 4', t('lg_hop')) + ln('stroke:#a21caf;stroke-width:4', t('lg_link')) + ln('stroke:#f97316;stroke-width:3;stroke-dasharray:7 4', t('lg_loop')) +
    SEV.slice(0, 4).map(s => `<div><span class="sw" style="background:transparent;border:3px solid ${SEVCOL[s]}"></span>${esc(t('lg_find', { s: sevLabel(s) }))}</div>`).join('') +
    `<p class="muted small">${esc(t('lg_note'))}</p><p class="muted small">${esc(t('visible', { a: cy.nodes(':visible').length, b: cy.nodes().length }))}</p></details>`;
  $('#legend details').addEventListener('toggle', e => { legendOpen = e.target.open; store.set('legend', legendOpen ? '1' : '0'); });
}

// ---- Details ----------------------------------------------------------------------------------
function findingHtml(f) {
  const rm = D.rules[f.rule] || {}, r = { ...rm, ...ruleText(rm) };
  return `<div class="finding ${f.severity}"><span class="sev ${f.severity}">${esc(sevLabel(f.severity))}</span> <b>${esc(f.rule)}</b> ${esc(r.title || '')}<br>${esc(msgOf(f))}
  ${f.evidence && f.evidence.length ? '<pre>' + esc(f.evidence.join('\n')) + '</pre>' : ''}
  <details><summary>${esc(t('d_why'))}</summary><p>${esc(r.rationale)}</p><p><b>${esc(t('d_fix'))}</b> ${esc(r.remediation)}</p>
  <p><b>${esc(t('d_src'))}</b> ${(r.refs || []).map(esc).join('; ') || '–'}<br><b>${esc(t('d_conf'))}</b> ${esc(r.confidence)} · ${esc(catLabel(r.category))}</p></details></div>`;
}
function renderDetail(d) {
  const box = $('#detail');
  if (!d) { box.innerHTML = `<div class="empty"><svg viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="12" r="5"/><circle cx="12" cy="36" r="5"/><circle cx="36" cy="36" r="5"/><path d="M24 17v7M24 24l-9 8M24 24l9 8"/></svg><p>${esc(t('d_ph'))}</p></div>`; return; }
  const f = d.findings.map(i => findingsById[i]).sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const props = Object.entries(d.props).map(([k, v]) => `<dt>${esc(propLabel(k))}</dt><dd>${esc(v)}</dd>`).join('');
  const nb = cy.getElementById(d.id);
  const lst = col => col.map(x => `<a href="#" data-go="${esc(x.id())}">${esc(x.data('label'))}</a> <span class="muted">${esc(kindLabel(x.data('kind')))}</span>`).join('<br>') || `<span class="muted">–</span>`;
  const out = nb.outgoers('node'), inc = nb.incomers('node');
  box.innerHTML = `<h3>${esc(d.label)}</h3><div class="kind">${esc(kindLabel(d.kind))} · ${esc(d.etype)}</div>
  ${props ? `<section><h4>${esc(t('d_props'))}</h4><dl>${props}</dl></section>` : ''}
  <section><h4>${esc(t('d_findings', { n: f.length }))}</h4>${f.map(findingHtml).join('') || `<span class="muted">${esc(t('none'))}</span>`}</section>
  <section><h4>${esc(t('d_to', { n: out.length }))}</h4>${lst(out)}</section>
  <section><h4>${esc(t('d_from', { n: inc.length }))}</h4>${lst(inc)}</section>
  <section><h4>${esc(t('d_cfg', { n: d.lines.length }))}</h4>${d.lines.map(l => `<pre data-copy="${esc(l.text)}" title="⧉"><span class="ln">${esc(l.file)}:${l.line}</span>\n${esc(l.text)}</pre>`).join('') || `<span class="muted">${esc(t('d_nolines'))}</span>`}</section>`;
  $$('#detail [data-go]').forEach(a => a.onclick = e => { e.preventDefault(); goTo(a.dataset.go); });
  $$('#detail pre[data-copy]').forEach(p => p.onclick = () => { if (getSelection().toString()) return; (navigator.clipboard ? navigator.clipboard.writeText(p.dataset.copy) : Promise.reject()).then(() => toast('✓')).catch(() => { }); });
}

// ---- Suche ------------------------------------------------------------------------------------
const search = $('#search');
function runSearch() {
  const q = search.value.trim().toLowerCase(); cy.nodes().removeClass('hit'); state.hits = []; state.hitIdx = -1;
  if (q) { D.nodes.forEach(n => { const hay = (n.label + ' ' + Object.values(n.props).join(' ') + ' ' + n.lines.map(l => l.text).join(' ')).toLowerCase(); if (hay.includes(q)) state.hits.push(n.id); }); state.hits.forEach(id => cy.getElementById(id).addClass('hit')); }
  $('#hits').textContent = q ? t('hits', { n: state.hits.length }) : '';
}
function gotoHit(dir) { if (!state.hits.length) return; state.hitIdx = (state.hitIdx + dir + state.hits.length) % state.hits.length; const id = state.hits[state.hitIdx]; if (!cy.getElementById(id).visible()) revealNode(id); cy.getElementById(id).addClass('hit'); select(id, true); }
search.oninput = runSearch; search.onkeydown = e => { if (e.key === 'Enter') gotoHit(e.shiftKey ? -1 : 1); };
$('#hit-next').onclick = () => gotoHit(1); $('#hit-prev').onclick = () => gotoHit(-1);

// ---- Befunde ----------------------------------------------------------------------------------
const sevSel = new Set(SEV);
function renderFindingsUi() {
  $('#sev-filters').innerHTML = SEV.map(s => `<label class="sevchk"><input type="checkbox" ${sevSel.has(s) ? 'checked' : ''} data-s="${s}"><span class="sev ${s}">${esc(sevLabel(s))}</span></label>`).join('');
  $$('#sev-filters input').forEach(i => i.onchange = () => { i.checked ? sevSel.add(i.dataset.s) : sevSel.delete(i.dataset.s); renderFindings(); });
  const c = $('#f-cat'), cv = c.value; c.innerHTML = `<option value="">${esc(t('f_allcat'))}</option>` + D.meta.categories.map(k => `<option value="${k}">${esc(catLabel(k))}</option>`).join(''); c.value = cv;
  const g = $('#f-group'), gv = g.value; g.innerHTML = `<option value="">${esc(t('f_alldev'))}</option>` + D.groups.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join(''); g.value = gv;
  $('#h-findings').innerHTML = ['th_sev', 'th_rule', 'th_msg', 'th_dev', 'th_loc'].map(k => `<th scope="col">${esc(t(k))}</th>`).join('');
}
['#f-cat', '#f-group'].forEach(s => $(s).onchange = () => renderFindings()); $('#f-text').oninput = () => renderFindings();
function filteredFindings() {
  const tx = $('#f-text').value.toLowerCase(), c = $('#f-cat').value, g = $('#f-group').value;
  return D.findings.filter(f => sevSel.has(f.severity) && (!c || (D.rules[f.rule] || {}).category === c) && (!g || (nodeById[f.node] && nodeById[f.node].group === g)) && (!tx || (f.rule + ' ' + msgOf(f) + ' ' + f.devices.join(' ') + ' ' + f.name).toLowerCase().includes(tx)));
}
function renderFindings() {
  const list = filteredFindings(); $('#f-count').textContent = t('f_count', { a: list.length, b: D.findings.length });
  $('#t-findings tbody').innerHTML = list.map(f => `<tr class="clickable" tabindex="0" data-id="${f.id}"><td><span class="sev ${f.severity}">${esc(sevLabel(f.severity))}</span></td><td title="${esc(ruleText(D.rules[f.rule]).title)}">${esc(f.rule)}</td><td>${esc(msgOf(f))}</td><td>${esc(f.devices.join(', '))}</td><td>${esc(f.file)}${f.line ? ':' + f.line : ''}</td></tr>`).join('');
  $$('#t-findings tbody tr').forEach(tr => { const go = () => { const f = findingsById[tr.dataset.id]; if (nodeById[f.node]) goTo(f.node); }; tr.onclick = go; tr.onkeydown = e => { if (e.key === 'Enter') go(); }; });
}
$('#csv').onclick = () => {
  const rows = [[t('th_sev'), t('th_rule'), t('th_title'), t('th_cat'), t('th_msg'), t('th_dev'), t('th_file'), '#', t('th_object')]].concat(filteredFindings().map(f => [sevLabel(f.severity), f.rule, ruleText(D.rules[f.rule]).title, catLabel((D.rules[f.rule] || {}).category), msgOf(f), f.devices.join(' + '), f.file, f.line, f.etype + ' ' + f.name]));
  const csv = '﻿' + rows.map(r => r.map(c => '"' + String(c == null ? '' : c).replace(/"/g, '""') + '"').join(';')).join('\r\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'netscaler-findings.csv'; a.click(); toast('CSV ✓');
};

// ---- Inventar ---------------------------------------------------------------------------------
const VS = ['csvs', 'lbvs', 'gwvs', 'aaavs', 'gslbvs'];
const outE = {}; D.edges.forEach(e => (outE[e.source] = outE[e.source] || []).push(e));
D.nodes.forEach(n => { const o = outE[n.id] || []; const tk = id => (nodeById[id] || {}).kind; n.__back = o.filter(e => ['svc', 'sg', 'gslbsvc'].includes(tk(e.target))).length; n.__certs = o.filter(e => tk(e.target) === 'cert').map(e => nodeById[e.target].label).join(', '); });
let invSort = [7, -1];
const invCols = () => [['th_type', n => kindLabel(n.kind)], ['th_name', n => n.label], ['th_ipport', n => n.props['IP:Port'] || ''], ['th_proto', n => n.props['Protocol'] || ''], ['th_status', n => n.props['Status'] || ''], ['th_back', n => n.__back], ['th_certs', n => n.__certs], ['th_findings', n => n.findings.length]];
function renderInvUi() {
  const k = $('#i-kind'), kv = k.value; k.innerHTML = `<option value="">${esc(t('i_all'))}</option>` + VS.filter(x => kindsPresent[x]).map(x => `<option value="${x}">${esc(kindLabel(x))}</option>`).join(''); k.value = kv;
  $('#t-inv thead tr').innerHTML = invCols().map((c, i) => `<th scope="col" data-c="${i}" tabindex="0" aria-sort="${invSort[0] === i ? (invSort[1] > 0 ? 'ascending' : 'descending') : 'none'}">${esc(c[0] === 'th_findings' ? t('tab_findings') : t(c[0]))}</th>`).join('');
  $$('#t-inv th').forEach(th => { const f = () => { const c = +th.dataset.c; invSort = [c, invSort[0] === c ? -invSort[1] : 1]; renderInvUi(); renderInv(); }; th.onclick = f; th.onkeydown = e => { if (e.key === 'Enter') f(); }; });
}
['#i-text', '#i-kind'].forEach(s => $(s).oninput = () => renderInv());
function renderInv() {
  const tx = $('#i-text').value.toLowerCase(), k = $('#i-kind').value, cols = invCols();
  let rows = D.nodes.filter(n => VS.includes(n.kind) && (!k || n.kind === k) && (!tx || cols.map(c => c[1](n)).join(' ').toLowerCase().includes(tx)));
  const [c, dir] = invSort; rows.sort((a, b) => { const x = cols[c][1](a), y = cols[c][1](b); return (typeof x === 'number' ? x - y : String(x).localeCompare(String(y), lang, { numeric: true })) * dir; });
  $('#i-count').textContent = t('i_count', { n: rows.length });
  $('#t-inv tbody').innerHTML = rows.map(n => `<tr class="clickable" tabindex="0" data-id="${esc(n.id)}">${cols.map(c => `<td>${esc(c[1](n))}</td>`).join('')}</tr>`).join('');
  $$('#t-inv tbody tr').forEach(tr => { tr.onclick = () => goTo(tr.dataset.id); tr.onkeydown = e => { if (e.key === 'Enter') goTo(tr.dataset.id); }; });
}

// ---- Projekt ----------------------------------------------------------------------------------
function renderProject() {
  let h = `<h2>${esc(t('p_devices'))}</h2><table><thead><tr>${['p_devices', 'th_file', 'th_group', 'th_role', 'th_version', 'th_nsip', 'th_stmts'].map(k => `<th scope="col">${esc(t(k === 'p_devices' ? 'th_name' : k))}</th>`).join('')}</tr></thead><tbody>`;
  D.groups.forEach(g => g.devices.forEach(d => h += `<tr><td>${esc(d.name)}</td><td>${esc(d.file)}</td><td>${esc(g.name)}</td><td>${esc(d.role)}</td><td>${esc(d.version || '?')} ${esc(d.build || '')}</td><td>${esc(d.nsip || '?')}</td><td>${d.statements}</td></tr>`));
  h += '</tbody></table>';
  const ha = D.groups.filter(g => g.kind === 'ha');
  if (ha.length) { h += `<h2>${esc(t('p_ha'))}</h2>`; ha.forEach(g => { h += `<p><b>${esc(g.name)}</b><br><span class="muted">${esc(t('p_detect', { x: pick(g.assumption) }))}</span><br><span class="muted">${esc(t('p_roles'))}</span></p>`;
    const df = D.diffs[g.id] || []; h += `<p>${esc(t('p_diffs', { n: df.length }))}</p>`;
    if (df.length) h += `<table><thead><tr><th>${esc(t('th_object'))}</th><th>${esc(t('th_kind'))}</th><th>${esc(t('th_a'))}</th><th>${esc(t('th_b'))}</th></tr></thead><tbody>` + df.slice(0, 300).map(x => `<tr><td><code>${esc(x.key.slice(0, 120))}</code></td><td>${x.kind === 'differs' ? esc(t('p_differs')) : esc(t('p_only', { x: x.kind === 'only_a' ? x.a_dev : x.b_dev }))}</td><td><code>${esc(x.a.slice(0, 160))}</code></td><td><code>${esc(x.b.slice(0, 160))}</code></td></tr>`).join('') + '</tbody></table>' + (df.length > 300 ? `<p class="muted">${esc(t('p_more', { n: df.length - 300 }))}</p>` : ''); }); }
  h += `<h2>${esc(t('p_chains'))}</h2>`;
  if (D.chains.length) h += '<p>' + D.chains.map(c => c.map(esc).join(' → ')).join('<br>') + '</p>'; else h += `<p class="muted">${esc(t('p_nochains'))}</p>`;
  if (D.links.length) h += `<table><thead><tr><th>${esc(t('th_from'))}</th><th>${esc(t('th_to'))}</th><th>${esc(t('th_target'))}</th><th>${esc(t('th_conf'))}</th></tr></thead><tbody>` + D.links.map(l => `<tr class="clickable" tabindex="0" data-from="${esc(l.from_node)}"><td>${esc(nodeById[l.from_node].label)}</td><td>${esc(nodeById[l.to_node].label)}</td><td>${esc(l.host)}:${esc(l.port)} → ${esc(l.to_port)}</td><td>${l.confidence === 'high' ? esc(t('c_high')) : esc(t('c_ip'))}</td></tr>`).join('') + '</tbody></table>';
  if (D.meta.notes.length) h += `<h2>${esc(t('p_notes'))}</h2><ul>` + D.meta.notes.map(n => `<li>${esc(pick(n))}</li>`).join('') + '</ul>';
  const w = D.groups.flatMap(g => g.devices.flatMap(d => d.warnings.map(x => d.name + ': ' + x)));
  if (w.length) h += `<h2>${esc(t('p_warn'))}</h2><ul>` + w.map(x => `<li>${esc(x)}</li>`).join('') + '</ul>';
  $('#project').innerHTML = h;
  $$('#project tr[data-from]').forEach(tr => { tr.onclick = () => goTo(tr.dataset.from); tr.onkeydown = e => { if (e.key === 'Enter') goTo(tr.dataset.from); }; });
}

// ---- Regeln -----------------------------------------------------------------------------------
function renderRulesUi() { $('#h-rules').innerHTML = ['th_id', 'th_sev', 'th_cat', 'th_certainty', 'th_rule'].map(k => `<th scope="col">${esc(t(k))}</th>`).join(''); }
$('#r-text').oninput = () => renderRules();
function renderRules() {
  const tx = $('#r-text').value.toLowerCase(); const rs = Object.values(D.rules).map(r => ({ ...r, ...ruleText(r) })).filter(r => !tx || JSON.stringify(r).toLowerCase().includes(tx));
  $('#r-count').textContent = t('r_count', { n: rs.length });
  $('#t-rules tbody').innerHTML = rs.map(r => `<tr><td>${esc(r.id)}</td><td><span class="sev ${r.severity}">${esc(sevLabel(r.severity))}</span></td><td>${esc(catLabel(r.category))}</td><td>${esc(r.confidence)}</td><td><b>${esc(r.title)}</b><br>${esc(r.rationale)}<br><b>${esc(t('d_fix'))}</b> ${esc(r.remediation)}<br><span class="muted">${(r.refs || []).map(esc).join(' · ')}</span></td></tr>`).join('');
}

// ---- Overview --------------------------------------------------------------------------------
function countUp(el, to) { if (reduceMotion) { el.textContent = to; return; } const t0 = performance.now(); const step = now => { const p = Math.min(1, (now - t0) / 900); el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(step); }; requestAnimationFrame(step); }
function renderOverview() {
  const col = score >= 80 ? 'var(--ok)' : score >= 50 ? 'var(--med)' : 'var(--crit)'; const C = 2 * Math.PI * 54;
  const cnt = {}; SEV.forEach(s => cnt[s] = D.findings.filter(f => f.severity === s).length); const max = Math.max(1, ...Object.values(cnt));
  const risk = D.nodes.map(n => [n, n.findings.reduce((a, i) => a + SEVW[findingsById[i].severity] + .1, 0)]).filter(x => x[1] > 0).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const nDev = D.groups.reduce((a, g) => a + g.devices.length, 0);
  $('#overview').innerHTML = `<div class="grid">
   <div class="card kpi"><svg class="ring" viewBox="0 0 132 132" role="img" aria-label="${esc(t('o_score'))}: ${score}"><circle class="bg" cx="66" cy="66" r="54"/><circle class="fg" cx="66" cy="66" r="54" stroke="${col}" stroke-dasharray="${C}" stroke-dashoffset="${C}" transform="rotate(-90 66 66)" data-to="${C * (1 - score / 100)}"/><text x="66" y="66" text-anchor="middle" dominant-baseline="central" id="sc">0</text></svg>
     <div><h3 style="margin:0">${esc(t('o_score'))}</h3><p class="muted small">${esc(t('o_score_hint'))}</p></div></div>
   <div class="card"><h3>${esc(t('o_bysev'))}</h3><div class="bars">${SEV.map(s => `<button data-sev="${s}" aria-label="${esc(sevLabel(s))}: ${cnt[s]}"><span class="sev ${s}">${esc(sevLabel(s))}</span><span class="bar"><i style="background:var(--${s === 'medium' ? 'med' : s === 'critical' ? 'crit' : s})" data-w="${cnt[s] / max * 100}"></i></span><span class="n">${cnt[s]}</span></button>`).join('')}</div></div>
   <div class="card"><h3>${esc(t('o_devs'))} · ${esc(t('o_obj'))} · ${esc(t('o_rel'))}</h3><div class="kpi" style="justify-content:space-around;text-align:center"><div><div class="num" data-n="${nDev}">0</div><div class="muted">${esc(t('o_devs'))}</div></div><div><div class="num" data-n="${D.nodes.length}">0</div><div class="muted">${esc(t('o_obj'))}</div></div><div><div class="num" data-n="${D.edges.length}">0</div><div class="muted">${esc(t('o_rel'))}</div></div></div>
     ${D.chains.length ? `<h3 style="margin-top:14px">${esc(t('o_chain'))}</h3><p>${D.chains.map(c => c.map(esc).join(' → ')).join('<br>')}</p>` : ''}</div></div>
   <div class="card"><h3>${esc(t('o_top'))}</h3>${risk.length ? `<ul class="toplist">${risk.map(([n]) => { const w = worst(n.findings); return `<li tabindex="0" data-id="${esc(n.id)}"><span class="sev ${w}">${esc(sevLabel(w))}</span><span class="nm">${esc(n.label)} <span class="muted">${esc(kindLabel(n.kind))}</span></span><b>${n.findings.length}</b></li>`; }).join('')}</ul>` : `<div class="clean"><span class="party" aria-hidden="true">🎉</span>${esc(t('o_clean'))}</div>`}</div>
   ${!['de', 'en'].includes(lang) ? `<p class="banner">${esc(t('note_i18n'))}</p>` : ''}`;
  requestAnimationFrame(() => { $$('#overview .fg').forEach(c => c.setAttribute('stroke-dashoffset', c.dataset.to)); $$('#overview .bar i').forEach(i => i.style.width = i.dataset.w + '%'); countUp($('#sc'), score); $$('#overview [data-n]').forEach(e => countUp(e, +e.dataset.n)); });
  $$('#overview .bars button').forEach(b => b.onclick = () => { SEV.forEach(s => s === b.dataset.sev ? sevSel.add(s) : sevSel.delete(s)); renderFindingsUi(); renderFindings(); showTab('findings'); });
  $$('#overview .toplist li').forEach(li => { li.onclick = () => goTo(li.dataset.id); li.onkeydown = e => { if (e.key === 'Enter') goTo(li.dataset.id); }; });
}

// ---- Dialog / shortcuts --------------------------------------------------------------------------
const dlg = $('#dlg');
function openHelp() {
  const k = [['/', 'sc_search'], ['←↑↓→', 'sc_arrows'], ['Enter / Space', 'sc_enter'], ['+ / −', 'sc_zoom'], ['0', 'sc_fit'], ['1 – 6', 'sc_tabs'], ['?', 'sc_help']];
  $('#keys').innerHTML = k.map(x => `<dt><kbd>${esc(x[0])}</kbd></dt><dd>${esc(t(x[1]))}</dd>`).join('');
  dlg.showModal ? dlg.showModal() : dlg.setAttribute('open', '');
}
$('#help').onclick = openHelp; $('#dlg-x').onclick = () => dlg.close(); dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });
document.addEventListener('keydown', e => {
  const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
  if (e.key === '/' && !typing) { e.preventDefault(); showTab('topo'); search.focus(); }
  else if (e.key === '?' && !typing) { e.preventDefault(); openHelp(); }
  else if (/^[1-7]$/.test(e.key) && !typing && !e.ctrlKey && !e.metaKey && !e.altKey && document.activeElement.id !== 'cy') showTab(TABS[+e.key - 1]);
});

// ---- Sprache ----------------------------------------------------------------------------------
function applyStatic() {
  document.documentElement.lang = lang; document.documentElement.dir = 'ltr';
  $$('[data-i18n]').forEach(e => e.textContent = t(e.dataset.i18n));
  $$('[data-i18n-ph]').forEach(e => e.placeholder = t(e.dataset.i18nPh));
  $$('[data-i18n-title]').forEach(e => e.title = t(e.dataset.i18nTitle));
  $$('[data-i18n-aria]').forEach(e => e.setAttribute('aria-label', t(e.dataset.i18nAria)));
  $('#cy').setAttribute('aria-label', t('u_canvas')); $('#mini').setAttribute('aria-label', t('minimap')); $('#minihint').textContent = '⌨ ?  ·  ' + t('u_keys');
  $$('#theme button').forEach(b => b.title = t('t_' + b.dataset.theme));
  document.title = 'NetScaler Visualizer';
  $('#subtitle').textContent = t('sub', { d: D.groups.reduce((a, g) => a + g.devices.length, 0), g: D.groups.length, o: D.nodes.length, t: dateStr() }) + ' · ' + (D.meta.redacted ? t('masked') : t('unmasked'));
}
function renderAll() {
  applyStatic(); renderTabs(); renderGroups(); renderKinds(); renderUnlinked(); renderLegend(); renderFindingsUi(); renderFindings(); renderInvUi(); renderInv(); renderProject(); renderLinks(); renderRulesUi(); renderRules(); renderOverview();
  renderDetail(state.selected ? nodeById[state.selected] : null); showTab(curTab);
}
const ls = $('#lang'); ls.innerHTML = LANGS.map(c => `<option value="${c}">${esc(I18N[c]._name)}</option>`).join('');
ls.onchange = () => { lang = ls.value; store.set('lang', lang); renderAll(); };

/*__EXPORT__*/
/*__LINKS__*/

// ---- Start ------------------------------------------------------------------------------------
lang = detectLang(); ls.value = lang;
applyTheme(); renderAll();
showTab('overview');
window.__nsviz = { cy, state, select, revealNode, refresh, showTab, setLang: l => { ls.value = l; ls.onchange(); }, setTheme: p => { themePref = p; applyTheme(); } };
})();
