// ---- Gateway tab: one page per gateway vServer -------------------------------------------------------------
// Data: D.gateway[group] = { gateways: [...], global: {...}, groups: [...], rdp, rdp_server } (see Graph.gateway_view).
// Global bindings (bind vpn global) and AAA groups apply to every gateway of the device; they are shown with a tag.
const GW = D.gateway || {};
const gwList = []; Object.entries(GW).forEach(([g, v]) => v.gateways.forEach(x => gwList.push({ ...x, group: g })));
let gwSel = 0;
const gwHas = () => gwList.length > 0;
const gwLink = (id, txt) => id && nodeById[id] ? `<a href="#" data-go="${esc(id)}">${esc(txt)}</a>` : esc(txt);
const gwTag = k => `<span class="nf-tag">${esc(t(k))}</span>`;
const gwOn = v => /^(ON|ENABLED|YES|TRUE)$/i.test(v || '');
function gwModes(o) {
  const m = [];
  if (o.clientsecurity) m.push('EPA');
  if (gwOn(o.icaproxy)) m.push(t('gw_ica'));
  if (gwOn(o.transparentinterception)) m.push(t('gw_vpn'));
  if (gwOn(o.clientlessvpnmode)) m.push(t('gw_cvpn'));
  return m.length ? m.map(x => `<span class="nf-type">${esc(x)}</span>`).join(' ') : '<span class="muted">–</span>';
}
// where a URL of a session action goes on this device (StoreFront LB vServer), from the model's loop/link edges
function gwTargets(actionNode) {
  if (!actionNode) return '';
  const tg = D.edges.filter(e => e.source === actionNode && ['loop', 'doublehop', 'route'].includes(e.type)).map(e => gwLink(e.target, (nodeById[e.target] || {}).label || e.target));
  return tg.length ? ` <span class="muted">${esc(t('gw_target'))}</span> ${tg.join(', ')}` : '';
}
let gwNames = {};
const gwKv = o => `<dl class="gw-kv">${Object.entries(o).map(([k, v]) => `<dt>${esc(gwNames[k] || k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
function gwSec(title, body, n) { return `<section class="gw-sec"><h3>${esc(title)}${n !== undefined ? ` <span class="muted">${n}</span>` : ''}</h3>${body || `<p class="muted gw-none">${esc(t('gw_none_sec'))}</p>`}</section>`; }
const gwRule = r => r && !/^(ns_)?true$/i.test(r) ? `<code class="nf-rule" title="${esc(r)}">${esc(r)}</code>` : '';
function gwPolRows(list, cols) {
  if (!list.length) return '';
  return `<div class="gw-tw"><table class="gw-t"><thead><tr><th>${esc(t('nf_prio'))}</th><th>${esc(t('gw_policy'))}</th>${cols.map(c => `<th>${esc(c[0])}</th>`).join('')}</tr></thead><tbody>${list.map((r, ri) => `<tr>
    <td class="gw-prio">${esc(r.prio || '–')}</td><td>${r.scope ? gwTag(r.scope) + ' ' : ''}${gwLink(r.node, r.policy)}${gwRule(r.rule)}</td>${cols.map(c => `<td>${c[1](r, ri)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function renderGateway() {
  const box = $('#gateway'); if (!box) return;
  if (!gwHas()) { box.innerHTML = `<p class="muted">${esc(t('gw_none'))}</p>`; return; }
  gwSel = Math.min(gwSel, gwList.length - 1);
  const multi = Object.keys(GW).length > 1, gname = g => (D.groups.find(x => x.id === g) || {}).name || '';
  const list = gwList.map((x, i) => `<button class="nf-entry${i === gwSel ? ' on' : ''}" data-i="${i}" aria-pressed="${i === gwSel}"><b>${esc(x.name)}</b><span class="muted">${esc(x.ip ? x.ip + ':' + x.port : '')}</span>${multi ? `<span class="muted nf-g">${esc(gname(x.group))}</span>` : ''}</button>`).join('');
  const g = gwList[gwSel], V = GW[g.group], G = V.global, grp = V.groups;
  gwNames = V.names || {};
  const scoped = (arr, scope) => arr.map(x => ({ ...x, scope }));
  const sess = [...g.policies.filter(p => p.etype === 'vpn sessionpolicy'), ...scoped(G.policies.filter(p => p.etype === 'vpn sessionpolicy'), 'gw_global'),
    ...grp.flatMap(x => scoped(x.policies.filter(p => p.etype === 'vpn sessionpolicy'), 'gw_group').map(p => ({ ...p, grp: x.name })))];
  // effective value: the session action, else the global VPN settings (set vpn parameter); a small "G" marks the latter
  const P0 = G.params || {}, eff = p => ({ ...P0, ...p.opts }), gMark = `<span class="gw-g" title="${esc(t('gw_from_global'))}">G</span>`;
  const ev = (p, k) => p.opts[k] !== undefined ? esc(p.opts[k]) : P0[k] !== undefined ? `${esc(P0[k])} ${gMark}` : '<span class="muted">–</span>';
  const sfOf = p => ['wihome', 'storefronturl'].filter(k => p.opts[k] || P0[k]).map(k => `<code>${esc(p.opts[k] || P0[k])}</code>${p.opts[k] ? gwTargets(p.action_node) : ' ' + gMark}`).join('<br>') || '<span class="muted">–</span>';
  const sessT = gwPolRows(sess, [[t('gw_action'), (p, i) => gwLink(p.action_node, p.action) + (p.grp ? ` <span class="muted">(${esc(p.grp)})</span>` : '') + `<br><button class="btn sm gw-pbtn" data-gwp="${i}">${esc(t('gw_params', { n: Object.keys(p.opts).length }))}</button>`],
    [t('gw_mode'), p => gwModes(eff(p))], [t('gw_sf'), sfOf], [t('gw_sso'), p => ev(p, 'sso')], [t('gw_split'), p => ev(p, 'splittunnel')], [t('gw_authz'), p => ev(p, 'defaultauthorizationaction')]]);
  // ICA
  const sta = [...g.sta.map(s => ({ ...s, scope: '' })), ...G.sta.map(s => ({ ...s, scope: 'gw_global' }))];
  const staH = sta.length ? `<ul class="gw-ul">${sta.map(s => `<li>${s.scope ? gwTag(s.scope) + ' ' : ''}<code>${esc(s.url)}</code></li>`).join('')}</ul>` : '';
  const sfAll = sess.filter(p => p.opts.wihome || p.opts.storefronturl);
  const sfH = sfAll.length || G.params.wihome || G.params.storefronturl ? `<ul class="gw-ul">${sfAll.map(p => `<li>${sfOf(p)} <span class="muted">${esc(t('gw_from'))} ${esc(p.action)}</span></li>`).join('')}${['wihome', 'storefronturl'].filter(k => G.params[k]).map(k => `<li>${gwTag('gw_global')} <code>${esc(G.params[k])}</code></li>`).join('')}</ul>` : '';
  const ica = [...g.policies, ...scoped(G.policies, 'gw_global')].filter(p => p.etype === 'ica policy');
  const icaT = gwPolRows(ica, [[t('gw_action'), p => gwLink(p.action_node, p.action) + (p.profile ? ` → ${esc(p.profile)}${gwKv(p.profile_opts || {})}` : '')]]);
  const icaBody = (staH ? `<h4>${esc(t('gw_sta'))}</h4>${staH}` : '') + (sfH ? `<h4>${esc(t('gw_sf'))}</h4>${sfH}` : '') + (icaT ? `<h4>${esc(t('gw_icapol'))}</h4>${icaT}` : '');
  // VPN
  const apps = [...g.apps.map(a => ({ ...a, scope: '' })), ...G.apps.map(a => ({ ...a, scope: 'gw_global' })), ...grp.flatMap(x => x.apps.map(a => ({ ...a, scope: 'gw_group', grp: x.name })))];
  const appsT = apps.length ? `<table class="gw-t"><thead><tr><th>${esc(t('gw_apps'))}</th><th>${esc(t('th_proto'))}</th><th>${esc(t('gw_dest'))}</th><th>${esc(t('gw_icpt'))}</th></tr></thead><tbody>${apps.map(a => `<tr><td>${a.scope ? gwTag(a.scope) + ' ' : ''}${gwLink(a.node, a.name)}${a.grp ? ` <span class="muted">(${esc(a.grp)})</span>` : ''}</td><td>${esc(a.proto)}</td><td><code>${esc(a.dest)}${a.port ? ':' + esc(a.port) : ''}</code></td><td>${esc(a.mode || '–')}</td></tr>`).join('')}</tbody></table>` : '';
  const tr = [...g.policies, ...scoped(G.policies, 'gw_global')].filter(p => p.etype === 'vpn trafficpolicy' || p.etype === 'tm trafficpolicy');
  const trT = gwPolRows(tr, [[t('gw_action'), p => gwLink(p.action_node, p.action) + ' ' + gwKv(p.opts)]]);
  const ao = [...new Set(sess.map(p => p.opts.alwaysonprofilename).filter(Boolean))];
  const ips = [...g.ips, ...G.ips, ...grp.flatMap(x => x.ips)];
  const vpnBody = (appsT ? appsT : '') + (ips.length ? `<h4>${esc(t('gw_ips'))}</h4><ul class="gw-ul">${ips.map(x => `<li><code>${esc(x)}</code></li>`).join('')}</ul>` : '') +
    (trT ? `<h4>${esc(t('gw_traffic'))}</h4>${trT}` : '') + (ao.length ? `<h4>${esc(t('gw_ao'))}</h4><p>${ao.map(esc).join(', ')}</p>` : '') +
    (g.nexthop.length ? `<h4>${esc(t('gw_nexthop'))}</h4><ul class="gw-ul">${g.nexthop.map(n => `<li>${esc(n.name)} <code>${esc(n.target)}</code></li>`).join('')}</ul>` : '');
  // Portal / clientless
  const bms = [...g.bookmarks.map(b => ({ ...b, scope: '' })), ...G.bookmarks.map(b => ({ ...b, scope: 'gw_global' })), ...grp.flatMap(x => x.bookmarks.map(b => ({ ...b, scope: 'gw_group', grp: x.name })))];
  const bmT = bms.length ? `<table class="gw-t"><thead><tr><th>${esc(t('gw_bm'))}</th><th>URL</th><th>${esc(t('gw_cvpn'))}</th></tr></thead><tbody>${bms.map(b => `<tr><td>${b.scope ? gwTag(b.scope) + ' ' : ''}${esc(b.label || b.name)}${b.grp ? ` <span class="muted">(${esc(b.grp)})</span>` : ''}</td><td><code>${esc(b.url)}</code></td><td>${esc(b.clientless || '–')}</td></tr>`).join('')}</tbody></table>` : '';
  const cl = [...g.policies, ...scoped(G.policies, 'gw_global')].filter(p => p.etype === 'vpn clientlessaccesspolicy');
  const clT = gwPolRows(cl, [[t('gw_action'), p => gwLink(p.action_node, p.action)]]);
  const portalBody = (g.theme ? `<p><span class="nf-tag">${esc(t('gw_theme'))}</span> ${esc(g.theme)}</p>` : '') + ([...g.eula, ...G.eula].length ? `<p><span class="nf-tag">EULA</span> ${[...g.eula, ...G.eula].map(esc).join(', ')}</p>` : '') + bmT + (clT ? `<h4>${esc(t('gw_cl'))}</h4>${clT}` : '');
  // Authorization
  const az = [...scoped(g.policies.filter(p => p.etype === 'authorization policy'), ''), ...scoped(G.policies.filter(p => p.etype === 'authorization policy'), 'gw_global'),
    ...grp.flatMap(x => x.policies.filter(p => p.etype === 'authorization policy').map(p => ({ ...p, scope: 'gw_group', grp: x.name })))];
  const azT = gwPolRows(az, [[t('gw_action'), p => `<span class="nf-type">${esc(p.action)}</span>${p.grp ? ` <span class="muted">(${esc(p.grp)})</span>` : ''}`]]);
  const defAz = [...new Set(sess.map(p => p.opts.defaultauthorizationaction).filter(Boolean))];
  const azBody = (defAz.length ? `<p>${esc(t('gw_authz'))}: ${defAz.map(x => `<span class="nf-type">${esc(x)}</span>`).join(' ')}</p>` : '') + azT;
  // Groups
  const grpBody = grp.length ? `<ul class="gw-ul">${grp.map(x => `<li>${gwLink(x.node, x.name)} <span class="muted">${esc(t('gw_grp_cnt', { p: x.policies.length, b: x.bookmarks.length, a: x.apps.length }))}</span></li>`).join('')}</ul>` : '';
  // Authentication
  const nfi = typeof nfEntryFor === 'function' ? nfEntryFor(g.node) : -1;
  const authMain = nfi >= 0 ? `<p>${esc(t(nfEntries[nfi].via === 'classic' ? 'gw_auth_classic' : 'gw_auth_nf'))} <button class="btn sm" data-nfopen="${esc(g.node)}">${esc(t('nf_open'))}</button></p>` : `<p class="muted">${esc(t('gw_noauth'))}</p>`;
  const ccH = gwCc(g.clientcert, t('gw_cc'));
  const pre = [...(g.preauth || []), ...((G.preauth || []).map(x => ({ ...x, scope: 'gw_global' })))];
  const nfEpa = nfi >= 0 ? nfLevels(nfEntries[nfi]).flat().flatMap(id => nfFactor(nfEntries[nfi].group, id).rows.filter(r => r.action && r.action.type === 'EPA').map(r => ({ ...r, fname: nfFactor(nfEntries[nfi].group, id).name }))) : [];
  const post = sess.filter(p => p.opts.clientsecurity);
  const grpOf = o => o && o.defaultepagroup ? ` <span class="muted">${esc(t('gw_epa_grp'))}</span> ${esc(o.defaultepagroup)}` : '';
  const epaH = pre.length || nfEpa.length || post.length ? `<h4>${esc(t('gw_epa'))}</h4><ul class="gw-ul">${
    pre.map(x => `<li><span class="nf-tag">${esc(t('gw_epa_pre'))}</span> ${x.scope ? gwTag(x.scope) + ' ' : ''}${gwLink(x.node, x.policy)} → <span class="nf-type">${esc(x.verdict || x.action)}</span>${grpOf(x.opts)}${gwRule(x.rule)}</li>`).join('')}${
    nfEpa.map(r => `<li><span class="nf-tag">${esc(t('gw_epa_nf'))}</span> ${gwLink(r.node, r.policy)} <span class="muted">(${esc(r.fname)})</span>${grpOf(r.action.opts)}${gwRule((r.action.opts || {}).csecexpr)}</li>`).join('')}${
    post.map(p => `<li><span class="nf-tag">${esc(t('gw_epa_post'))}</span> ${gwLink(p.action_node, p.action)}${p.opts.clientsecuritygroup ? ` <span class="muted">${esc(t('gw_epa_grp'))}</span> ${esc(p.opts.clientsecuritygroup)}` : ''}${gwRule(p.opts.clientsecurity)}</li>`).join('')}</ul>` : '';
  const authBody = authMain + ccH + epaH;
  // RDP / PCoIP
  const rdpC = [...new Set(sess.map(p => p.opts.rdpclientprofilename).filter(Boolean))];
  const rdpS = g.opts.rdpserverprofilename, pc = g.opts.pcoipvserverprofilename || '';
  const rdpBody = (rdpS ? `<p><span class="nf-tag">${esc(t('gw_rdps'))}</span> ${esc(rdpS)}${gwKv(V.rdp_server[rdpS] || {})}</p>` : '') + rdpC.map(c => `<p><span class="nf-tag">${esc(t('gw_rdpc'))}</span> ${esc(c)}${gwKv(V.rdp[c] || {})}</p>`).join('') + (pc ? `<p><span class="nf-tag">PCoIP</span> ${esc(pc)}</p>` : '');
  const other = [...g.policies.filter(p => !['vpn sessionpolicy', 'ica policy', 'vpn trafficpolicy', 'tm trafficpolicy', 'vpn clientlessaccesspolicy', 'authorization policy'].includes(p.etype)), ...g.other];
  const otherT = gwPolRows(other, [[t('gw_type'), p => esc((p.etype || '') + (p.type ? ' · ' + p.type : ''))]]);
  const vo = Object.entries(g.opts).filter(([k]) => !/^(authnprofile|rdpserverprofilename|pcoipvserverprofilename|comment)$/.test(k));
  box.innerHTML = `<div class="nf-wrap"><aside class="nf-list"><h2 class="hrow">${esc(t('gw_list'))}${infoBtn(esc(t('gw_info')))}</h2>${list}</aside>
    <div class="gw-page"><div class="gw-head"><div><span class="nf-k">${esc(kindLabel('gwvs'))}</span> <b class="gw-name">${gwLink(g.node, g.name)}</b> <code>${esc(g.proto)} ${esc(g.ip)}:${esc(g.port)}</code></div>
      <div class="gw-btns"><button class="btn sm" data-gwtopo>${esc(t('gw_topo'))}</button><button class="btn sm" data-gwexp>${esc(t('gw_export'))}</button></div>
      ${vo.length ? `<details class="gw-more"><summary>${esc(t('gw_vsopts'))}</summary>${gwKv(Object.fromEntries(vo))}</details>` : ''}</div>
      <div class="gw-grid">${gwSec(t('gw_sess'), sessT, sess.length)}${gwSec(t('gw_hauth'), authBody)}${gwSec(t('gw_hica'), icaBody)}${gwSec(t('gw_hvpn'), vpnBody)}
      ${gwSec(t('gw_hportal'), portalBody)}${gwSec(t('gw_hacl'), azBody, az.length)}${gwSec(t('gw_hgroups'), grpBody, grp.length)}${rdpBody ? gwSec(t('gw_hrdp'), rdpBody) : ''}${otherT ? gwSec(t('gw_hother'), otherT, other.length) : ''}</div></div></div>`;
  $$('#gateway .nf-entry').forEach(b => b.onclick = () => { gwSel = +b.dataset.i; renderGateway(); });
  $$('#gateway [data-go]').forEach(a => a.onclick = ev => { ev.preventDefault(); goTo(a.dataset.go); });
  $$('#gateway [data-nfopen]').forEach(b => b.onclick = () => nfOpen(b.dataset.nfopen));
  $$('#gateway [data-gwp]').forEach(b => b.onclick = () => gwParams(sess[+b.dataset.gwp], P0, V.names));
  $('#gateway [data-gwtopo]').onclick = () => goTo(g.node);
  $('#gateway [data-gwexp]').onclick = () => {
    const ids = [g.node, ...grp.map(x => x.node), ...G.policies.map(p => p.node)].filter(id => id && nodeById[id]);
    state.multi = ids; state.selected = g.node; openExport('ncfg');
  };
}
// open the gateway page that contains a node (from the topology details)
function gwEntryFor(id) {
  let i = gwList.findIndex(x => x.node === id); if (i >= 0) return i;
  return gwList.findIndex(x => [...x.policies, ...x.other].some(p => p.node === id || p.action_node === id) ||
    (GW[x.group].groups || []).some(gr => gr.node === id) || GW[x.group].global.policies.some(p => p.node === id || p.action_node === id));
}
function gwOpen(id) { const i = gwEntryFor(id); if (i < 0) return; gwSel = i; showTab('gateway'); renderGateway(); }
// client certificate authentication of a vServer (also used by the nFactor tab)
function gwCc(cc, title) {
  if (!cc || !cc.ca) return '';
  const ca = cc.ca.map((c, i) => gwLink((cc.ca_nodes || []).find(id => id.endsWith('|' + c)) || '', c)).join(', ');
  return `<h4>${esc(title)}</h4><p><span class="nf-type">${esc(cc.mode || t('gw_cc_nomode'))}</span>${cc.profile ? ` <span class="muted">${esc(t('gw_cc_prof'))}</span> ${esc(cc.profile)}` : ''} · ${ca ? 'CA: ' + ca : `<span class="muted">${esc(t('gw_cc_noca'))}</span>`}</p>`;
}
// all parameters of a session action next to the global VPN settings (set vpn parameter) and the value that applies
function gwParams(p, P0, names) {
  const A = p.opts, keys = [...new Set([...Object.keys(A), ...Object.keys(P0)])].sort((a, b) => (A[a] === undefined) - (A[b] === undefined) || a.localeCompare(b));
  const rows = keys.map(k => {
    const a = A[k], g = P0[k], src = a !== undefined ? t('gw_src_act') : t('gw_from_global');
    return [`<code>${esc(optLabel(k, names))}</code>`, a !== undefined ? `<b>${esc(a)}</b>` : '<span class="muted">–</span>',
      g !== undefined ? (a !== undefined && a !== g ? `<s class="muted">${esc(g)}</s>` : esc(g)) : '<span class="muted">–</span>', `${esc(a !== undefined ? a : g)} <span class="gw-g" title="${esc(src)}">${a !== undefined ? 'A' : 'G'}</span>`];
  });
  paramDlg(t('gw_params_t', { a: p.action || p.policy }), t('gw_params_sub', { p: p.policy }), [t('gw_param'), t('gw_src_act'), t('gw_src_glob'), t('gw_eff')], rows, t('gw_params_info'));
}
