// ---- Cleanup: unused configuration and configuration used only by disabled objects ----------------------------
// The analysis (Python, Project._cleanup) marks every candidate in n.dep.clean = { cat: unused|disabled, why, by[], sure }.
// Here: highlight in the topology, sidebar summary, details line and the batch files (removal and rollback).
const CL = {}; D.nodes.forEach(n => { if (n.dep && n.dep.clean) CL[n.id] = n.dep.clean; });
const clIds = cat => Object.keys(CL).filter(id => CL[id].cat === cat && (!state.group || nodeById[id].group === state.group));
function clApply() {
  const on = state.cleanup;
  cy.batch(() => cy.nodes().forEach(n => { const c = CL[n.id()];
    n.toggleClass('cl-u', !!(on && c && c.cat === 'unused')); n.toggleClass('cl-d', !!(on && c && c.cat === 'disabled')); n.toggleClass('cl-keep', !!(on && !c && n.data('kind') !== 'device')); }));
}
function renderCleanupSb() {
  const box = $('#cleanup'); if (!box) return;
  const u = clIds('unused'), d = clIds('disabled'), chk = [...u, ...d].filter(id => !CL[id].sure).length;
  box.innerHTML = `<details ${u.length + d.length ? '' : ''}><summary>${esc(t('cl_h', { n: u.length + d.length }))}</summary>
    <div class="cl-sum"><span class="cl-dot cl-du"></span>${esc(t('cl_unused', { n: u.length }))}<br><span class="cl-dot cl-dd"></span>${esc(t('cl_disabled', { n: d.length }))}${chk ? `<br><span class="muted">${esc(t('cl_check', { n: chk }))}</span>` : ''}</div>
    <label class="chk"><span>${esc(t('cl_show'))}</span><input type="checkbox" role="switch" id="cl-show" ${state.cleanup ? 'checked' : ''}></label>
    <div class="tgrid"><button id="cl-batch">${esc(t('cl_batch'))}</button>${infoBtn(esc(t('cl_info')))}</div></details>`;
  $('#cl-show').onchange = e => { state.cleanup = e.target.checked; clApply(); renderLegend(); };
  $('#cl-batch').onclick = () => openExport('clean');
}
function clDetail(d) {
  const c = CL[d.id]; if (!c) return '';
  const by = (c.by || []).map(id => nodeById[id] ? `<a href="#" data-go="${esc(id)}">${esc(nodeById[id].label)}</a>` : '').filter(Boolean).join(', ');
  const why = c.why === 'disabled' ? t('cl_why_dis') : c.why === 'no_ref' ? t('cl_why_noref') : t('cl_why_only') + ' ' + by;
  return `<div class="cl-det ${c.cat === 'unused' ? 'cl-du' : 'cl-dd'}"><b>${esc(t(c.cat === 'unused' ? 'cl_cat_u' : 'cl_cat_d'))}</b> · ${c.why === 'only_cand' ? `${esc(t('cl_why_only'))} ${by}` : esc(why)}${c.sure ? '' : `<br><span class="muted">${esc(t('cl_notsure'))}</span>`}</div>`;
}
// ---- batch files ----
const CL_UNBIND_DROP = new Set(['priority', 'gotopriorityexpression', 'weight', 'order', 'invoke', 'labeltype', 'labelname', 'nextfactor', 'crlcheck', 'ocspcheck',
  'skipcanames', 'customserverid', 'serverid', 'hashid', 'dbsttl', 'state', 'comment', 'monstate', 'passive']);
const clQ = w => w.q ? '"' + w.t + '"' : w.t;
// unbind from a bind line: same owner and identity, without ordering/flow options (assumption: NetScaler identifies a binding by these)
function clUnbind(txt) {
  const w = ncfgTok(txt), out = []; let drop = false;
  const nopol = w.some((x, i) => /^-policyname$/i.test(x.t) && w[i + 1] && /^NOPOLICY/i.test(w[i + 1].t));  // assumption: identified by priority
  w.forEach((x, i) => { if (i === 0) { out.push(x.t.toLowerCase() === 'link' ? 'unlink' : 'unbind'); return; }
    if (!x.q && /^-[A-Za-z]/.test(x.t)) { const k = x.t.slice(1).toLowerCase(); drop = CL_UNBIND_DROP.has(k) && !(nopol && k === 'priority'); if (!drop) out.push(x.t); return; }
    if (!drop) out.push(clQ(x)); });
  if (/^link$/i.test(w[0].t)) return out.slice(0, 4).join(' '); // unlink ssl certKey <child>
  return out.join(' ');
}
// rm from an add line: rm <type> <name> (lb monitor also needs its type)
function clRm(txt) {
  const w = ncfgTok(txt), st = ncfgStmt(txt), at = st.at - 1;
  const parts = ['rm', ...w.slice(1, at).map(x => x.t), clQ(w[at])];
  if (st.etype === 'lb monitor' && w[at + 1]) parts.push(w[at + 1].t);
  return parts.join(' ');
}
function buildClean(anon, rollback, withDisabled) {
  const cats = withDisabled ? ['unused', 'disabled'] : ['unused'];
  const all = new Set(cats.flatMap(clIds)), sure = new Set([...all].filter(id => CL[id].sure));
  const files = {}, fileName = f => { if (!anon) return f; if (!(f in files)) files[f] = 'device-' + (Object.keys(files).length + 1); return files[f]; };
  const addIdx = n => (n.lines || []).findIndex(l => { const s = ncfgStmt(l.text); return s.verb === 'add' && s.name === n.label; });
  const lineOf = (nd, i) => anon ? ((nd.anon || {}).lines || [])[i] : nd.lines[i].text;
  // names of removed objects per group -> bind/link lines of objects that stay and name them get an unbind
  const names = {}; sure.forEach(id => { const n = nodeById[id]; (names[n.group] = names[n.group] || new Set()).add(n.label); });
  const out = {}; D.edges.forEach(e => { if (e.type === 'contains' || e.type === 'network') return; (out[e.source] = out[e.source] || []).push(e.target); });
  const bar = '# ' + '='.repeat(78), L = [], stat = { rm: 0, unbind: 0, check: 0, objects: 0, masked: 0 };
  const head = rollback
    ? ['# NetScaler cleanup ROLLBACK batch - ' + D.meta.generator + ' - ' + new Date().toISOString().slice(0, 16).replace('T', ' '),
      '# Restores what the cleanup batch removes: objects (add), their settings (set), their bindings, and the bindings to',
      '#   objects that stayed. Objects marked "to check" are not part of the cleanup batch and therefore not listed here.',
      '# Certificate and key files are not restored by this batch: keep a copy of /nsconfig/ssl.',
      withDisabled ? '# Parts A and B are restored together. If only part A was run, the lines for part B fail with "already exists".' : ''].filter(Boolean)
    : ['# NetScaler cleanup batch - ' + D.meta.generator + ' - ' + new Date().toISOString().slice(0, 16).replace('T', ' '),
      '# Part A: configuration that is not used: not reachable from any addressable vServer, GSLB domain, global binding',
      '#   or user/group binding, directly or through other objects.',
      withDisabled ? '# Part B (at the end): configuration that is used only by disabled objects (state DISABLED); it would stay unused' : '# Part B (disabled objects) is not included in this file.',
      withDisabled ? '#   while they are disabled. Remove it only if the disabled objects are not needed any more.' : '',
      '# Order: 1. unbind from objects that stay, 2. remove, users first and then what they use (vServers, policies, actions,',
      '#   services and service groups, monitors, servers, certificates). Unbind lines are derived from the bind lines without',
      '#   priority/flow options: check them. Objects whose name also appears in a line that stays are listed "to check" as comments.',
      '# Before running: save ns config, keep a copy of ns.conf and create the rollback batch (export dialog). Then for example:',
      '#   batch -fileName /var/tmp/<this file> -outfile /var/tmp/<this file>.log',
      '# Test on a non-production appliance first; run it on the primary node of an HA pair.'].filter(Boolean);
  L.push(...head); if (anon) L.push('# Anonymized: names and addresses are pseudonyms; this file is for review, not to run.');
  const groups = [...new Set([...all].map(id => nodeById[id].group))].sort();
  const section = (title, rows, mk) => {
    if (!rows.length) return; L.push('', '# ' + title + ` (${rows.length})`); let cur = -2;
    rows.forEach((r, i) => { if (r.sec !== cur) { cur = r.sec; let n = 0; for (let j = i; j < rows.length && rows[j].sec === cur; j++) n++; L.push(`# --- ${(NCFG_SEC[cur] || ['Other'])[0]} (${n})`); } L.push(mk(r)); });
  };
  // removal order: users before what they use, from the config lines (an object whose own lines name another removed
  // object is removed first; the same rule NetScaler applies), then reverse section order
  const usesOf = (ids, addOnly) => {
    const byLab = {}; ids.forEach(id => (byLab[nodeById[id].label] = byLab[nodeById[id].label] || []).push(id));
    const u = {}; ids.forEach(id => { const n = nodeById[id], r = new Set();
      (n.lines || []).forEach(l => { const st = ncfgStmt(l.text); if (st.name !== n.label || (addOnly && /^(bind|link)$/.test(st.verb))) return; ncfgTok(l.text).slice(st.at).flatMap(x => x.t.match(/[A-Za-z0-9_$.:@\/-]+/g) || []).forEach(w => (byLab[w] || []).forEach(v => { if (v !== id) r.add(v); })); });
      u[id] = [...r]; });
    return u;
  };
  const rmCyc = new Set();  // objects removed while another removed object still refers to them (circular reference)
  const rmOrder = (ids, addOnly) => {
    const set = new Set(ids), indeg = {}, uses = usesOf(ids, addOnly); ids.forEach(id => indeg[id] = 0);
    ids.forEach(id => uses[id].forEach(v => { if (set.has(v)) indeg[v]++; }));
    const secOf = id => ncfgSection(nodeById[id].etype, nodeById[id].etype), res = [], done = new Set();
    const ready = () => ids.filter(id => !done.has(id) && indeg[id] === 0).sort((a, b) => secOf(b) - secOf(a) || nodeById[a].label.localeCompare(nodeById[b].label));
    while (res.length < ids.length) {
      let r = ready(); if (!r.length) { r = ids.filter(id => !done.has(id)).sort((a, b) => secOf(b) - secOf(a)).slice(0, 1); rmCyc.add(r[0]); } // cycle
      const id = r[0]; done.add(id); res.push(id); uses[id].forEach(v => { if (set.has(v) && !done.has(v)) indeg[v]--; });
    }
    return res;
  };
  groups.forEach(g => {
    const src = [...new Set([...all].filter(id => nodeById[id].group === g).flatMap(id => (nodeById[id].lines || []).slice(0, 1).map(l => fileName(l.file))))].join(', ');
    if (groups.length > 1) L.push('', bar, '# Device / HA pair: ' + (anon ? 'device-group-' + (groups.indexOf(g) + 1) : ((D.groups.find(x => x.id === g) || {}).name || g)), bar);
    L.push('# Source: ' + src);
    // rollback: one block for both parts (adds first, then settings, then bindings), because bindings can cross the parts
    const parts = rollback ? [cats] : cats.map(c => [c]), gone = new Set();
    parts.forEach((pc, ci) => {
      const ids = [...all].filter(id => nodeById[id].group === g && pc.includes(CL[id].cat)), ok = ids.filter(id => sure.has(id)), chk = ids.filter(id => !sure.has(id));
      if (!ids.length) return;
      ok.forEach(id => gone.add(id));
      if (rollback) L.push('', bar, '# ' + (pc.length > 1 ? 'Parts A and B' : 'Part A') + ` - ${ok.length} object(s) to restore`, bar);
      else L.push('', bar, '# ' + (ci ? 'B. Used only by disabled objects' : 'A. Not used') + ` - ${ok.length} object(s) to remove, ${chk.length} to check`, bar);
      if (ci) L.push('# These objects are reachable only through disabled vServers, services, servers or monitors. While those stay',
        '# disabled, nothing uses the objects below. If a disabled object is meant to be enabled again later, keep this part.');
      // bind lines of objects that stay and name a removed object of this part
      const nm = new Set(ok.map(id => nodeById[id].label)), unb = [], seen = new Set();
      D.nodes.forEach(n => { if (n.group !== g || gone.has(n.id)) return; const f0 = ((n.lines || [])[0] || {}).file;
        (n.lines || []).forEach((l, i) => { if (l.file !== f0) return; const st = ncfgStmt(l.text); if (!/^(bind|link)$/.test(st.verb)) return;
          const k = l.file + ':' + l.line; if (seen.has(k)) return;
          const refs = ncfgRefs(l.text, st.at); if (![...refs].some(w => nm.has(w))) return;
          if (st.name && nm.has(st.name) && st.verb === 'bind') return; // owner is removed itself
          seen.add(k); const txt = lineOf(n, i); if (txt) unb.push({ sec: ncfgSection(st.etype, n.etype), txt, f: l.file, line: l.line }); }); });
      // link lines owned by removed certificates (unlink before rm)
      ok.forEach(id => { const n = nodeById[id]; (n.lines || []).forEach((l, i) => { const st = ncfgStmt(l.text); if (st.verb !== 'link' || st.name !== n.label) return; const k = l.file + ':' + l.line; if (seen.has(k)) return; seen.add(k); const txt = lineOf(n, i); if (txt) unb.push({ sec: ncfgSection(st.etype, n.etype), txt, f: l.file, line: l.line, own: true }); }); });
      unb.sort((a, b) => a.sec - b.sec || a.line - b.line);
      if (rollback) {
        const rows = [], rbSeen = new Set();
        ok.forEach(id => { const n = nodeById[id], f0 = ((n.lines || [])[0] || {}).file; (n.lines || []).forEach((l, i) => { if (l.file !== f0) return; const st = ncfgStmt(l.text), txt = lineOf(n, i); if (!txt || st.name !== n.label) return;
          const k = l.file + ':' + l.line; if (rbSeen.has(k)) return; rbSeen.add(k);
          rows.push({ id, sec: ncfgSection(st.etype, n.etype), ph: st.verb === 'add' ? 0 : /^(bind|link)$/.test(st.verb) ? 2 : 1, txt: txt.replace(/\s+-devno\s+\d+/g, ''), line: l.line }); }); });
        const order = rmOrder(ok, true).reverse(), pos = {}; order.forEach((id, i) => pos[id] = i);
        const byPh = p => rows.filter(r => r.ph === p).sort((a, b) => p === 0 ? (pos[a.id] ?? 0) - (pos[b.id] ?? 0) || a.line - b.line : a.sec - b.sec || a.line - b.line);
        const rbTxt = r => /\*\*\*/.test(r.txt) ? (stat.masked++, '# SECRET MASKED - restore this line from the saved ns.conf: ' + r.txt) : r.txt;
        section('1. Objects (add)', byPh(0), rbTxt); section('2. Settings (set)', byPh(1), rbTxt); section('3. Bindings (bind, link)', byPh(2), rbTxt);
        const unb4 = unb.filter(r => !r.own);
        section('4. Bindings to objects that stayed', unb4, r => r.txt);
        stat.rm += rows.length + unb4.length;
      } else {
        section('1. Unbind from objects that stay', unb, r => clUnbind(r.txt));
        const rmRows = rmOrder(ok).map(id => { const n = nodeById[id], i = addIdx(n);
          return i < 0 ? null : { sec: ncfgSection(n.etype, n.etype), txt: lineOf(n, i), cyc: rmCyc.has(id) }; }).filter(r => r && r.txt);
        section('2. Remove (users first, then what they use)', rmRows, r => (r.cyc ? '# Note: circular reference with an object removed below; if this rm fails, unbind or remove that object first\n' : '') + clRm(r.txt));
        const chkRows = chk.map(id => { const n = nodeById[id], i = addIdx(n); return i < 0 ? null : { sec: ncfgSection(n.etype, n.etype), txt: lineOf(n, i) }; }).filter(r => r && r.txt).sort((a, b) => b.sec - a.sec);
        section('3. To check (not removed): the name also appears in a line that stays', chkRows, r => '# ' + clRm(r.txt));
        stat.rm += rmRows.length; stat.unbind += unb.length; stat.check += chkRows.length;
      }
      stat.objects += ok.length;
    });
  });
  if (!all.size) L.push('', '# Nothing to clean up.');
  if (stat.masked) { const at = L.findIndex(l => /^# Source: /.test(l)); L.splice(at < 0 ? head.length : at, 0,
    `# WARNING: ${stat.masked} line(s) contain secrets that the report masks (***). They are commented out below and must be`,
    '#   restored from the saved ns.conf (or create the report with --no-redact, which keeps encrypted values).'); }
  return { text: L.join('\n') + '\n', ...stat };
}
