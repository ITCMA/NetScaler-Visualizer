"""Project = several ns.conf files: devices, HA pairs, double-hop chains, rule runs."""
from __future__ import annotations

import datetime as _dt
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .model import BUILTIN_CERTS, BUILTIN_MONITORS, INTERNAL_SERVICES, KEYWORD_NAMES, Edge, Graph, KIND_LABELS, is_ip
from .linking import apply_map, collect
from .parser import Config
from .parser import FAMILIES, ONE_WORD
from .rules import RULES, SEVERITIES, CATEGORIES, Finding, Rule, finalize, load_builtin_rules, register_meta, render_messages, run_rules

CONF_SUFFIX = {".conf", ".txt", ".cfg", ".ns", ".config"}

HA_DIFF_SUMMARY_LIMIT = 40  # more differences than this -> one summary finding

NODE_SPECIFIC = {"ns config", "ha node", "ns hostname", "interface", "channel", "ns rpcnode",
                 "cluster node", "cluster instance", "rsskeytype", "lacp", "nd6ravariables", "ns ip6",
                 "ns encryptionparams", "ns license", "ns weblogparam"}
NODE_SPECIFIC_BINDS = {"vlan", "channel", "interface"}

# Project-level rules (no check function; texts come from the catalogs)
for _r in (
    Rule("HA-003", "high", "misconfig", ["Citrix/NetScaler documentation: high availability (synchronization)"], "likely"),
    Rule("CHAIN-001", "info", "best-practice", [], "heuristic"),
    Rule("DEP-001", "medium", "misconfig", [], "likely"),
    Rule("DEP-002", "info", "misconfig", [], "heuristic"),
    Rule("CHAIN-002", "medium", "compliance",
         ["BSI TR-02102-2", "BSI IT-Grundschutz NET.1.1 Network architecture and design"], "likely"),
):
    register_meta(_r)


@dataclass
class Device:
    name: str
    cfg: Config
    role: str = "unknown"  # primary | secondary | unknown
    gid: str = ""


@dataclass
class Group:
    id: str
    name: str
    devices: list[Device]
    kind: str  # single | ha
    assumption: dict = field(default_factory=dict)
    graph: Graph | None = None


def _norm(cfg: Config) -> dict[str, str]:
    out: dict[str, str] = {}

    def fmt(args, opts):
        o = " ".join(f"-{k} {' '.join(v)}".strip() for k, v in sorted(opts.items()) if k != "devno")
        return (" ".join(args) + " " + o).strip()
    for et, d in cfg.entities.items():
        if et in NODE_SPECIFIC:
            continue
        for name, e in d.items():
            if et == "ns ip" and (e.opt("type") or "").upper() == "NSIP":
                continue
            out[f"{et} {name}".strip()] = fmt(e.args, e.opts)
    for b in cfg.bindings:
        if b.etype in NODE_SPECIFIC_BINDS or b.etype in NODE_SPECIFIC:
            continue
        out[f"bind {b.etype} {b.owner} {' '.join(b.args)} {' '.join(f'-{k} {chr(32).join(v)}' for k, v in sorted(b.opts.items()) if k != 'devno')}".strip()] = "gebunden"
    return out


def diff_configs(a: Config, b: Config) -> list[dict]:
    na, nb = _norm(a), _norm(b)
    res = []
    for k in sorted(set(na) | set(nb)):
        if k in na and k in nb:
            if na[k] != nb[k]:
                res.append({"kind": "differs", "key": k, "a": na[k], "b": nb[k]})
        elif k in na:
            res.append({"kind": "only_a", "key": k, "a": na[k], "b": ""})
        else:
            res.append({"kind": "only_b", "key": k, "a": "", "b": nb[k]})
    return res


def _code_id() -> str:
    """Fingerprint of the tool's own source (model/project), so that debug output can be matched to the code version."""
    import hashlib
    h = hashlib.sha256()
    for f in ("model.py", "project.py", "linking.py"):
        try:
            h.update((Path(__file__).parent / f).read_bytes())
        except OSError:  # packaged app without the sources
            return "packaged"
    return h.hexdigest()[:10]


class Project:
    def __init__(self, devices: list[Device], ha_pairs: list[tuple[str, str]] | None = None, redact: bool = True,
                 link_map: dict | None = None):
        self.devices = devices
        self.link_map = link_map or {}
        self.redact = redact
        self.groups: list[Group] = []
        self.findings: list[Finding] = []
        self.diffs: dict[str, list[dict]] = {}
        self.links: list[dict] = []
        self.extra_edges: list[Edge] = []
        self.notes: list[str] = []
        self.dep: dict[str, dict] = {}
        self._pair(ha_pairs or [])
        for d in devices:
            if getattr(d.cfg, "html_decoded", 0):
                self.notes.append({
                    "en": f"{d.name}: the file is HTML-encoded (&quot; instead of \", e.g. copied from a web page); decoded for the analysis. "
                          "For a config export use the original ns.conf from the appliance.",
                    "de": f"{d.name}: Die Datei ist HTML-kodiert (&quot; statt \", z. B. aus einer Webseite kopiert); für die Analyse "
                          "dekodiert. Für einen Config-Export die originale ns.conf vom Gerät verwenden."})
        for g in self.groups:
            primary = next((d for d in g.devices if d.role == "primary"), g.devices[0])
            g.graph = Graph(primary.cfg, g.id, redact)
        self._run_rules()
        self._diff()
        self._chains()
        for w in (apply_map(self, link_map) if link_map else []):
            self.notes.append({"en": w, "de": w})
        self._url_chains()
        self._dependency()
        self._cleanup()
        self._coverage_note()
        self.findings = finalize(self.findings)
        self._attach()

    # ---- Laden ----------------------------------------------------------------------------
    @classmethod
    def load(cls, paths: list[str], ha_pairs: list[tuple[str, str]] | None = None, roles: dict[str, str] | None = None,
             redact: bool = True, link_map: dict | None = None) -> "Project":
        files: list[Path] = []
        for p in map(Path, paths):
            if p.is_dir():
                files += sorted(f for f in p.rglob("*") if f.is_file() and (f.suffix.lower() in CONF_SUFFIX or "ns.conf" in f.name.lower()))
            elif p.is_file():
                files.append(p)
            else:
                raise FileNotFoundError(p)
        if not files:
            raise FileNotFoundError("keine Konfigurationsdateien gefunden")
        devs: list[Device] = []
        skipped: list[str] = []
        used: set[str] = set()
        for f in files:
            cfg = Config.parse_file(f)
            if not any(st.verb in ("add", "set", "bind", "enable") for st in cfg.statements):
                skipped.append(f.name)  # does not look like an ns.conf (e.g. readme/license)
                continue
            name = cfg.hostname or f.stem
            base, i = name, 2
            while name in used:
                name, i = f"{base}#{i}", i + 1
            used.add(name)
            cfg.name = f.name
            d = Device(name, cfg)
            r = (roles or {}).get(f.name) or (roles or {}).get(name)
            if r:
                d.role = r
            else:
                hn = cfg.get("ha node", "0")
                st = ((hn.opt("hastatus") if hn else "") or "").upper()
                low = f.name.lower()
                if st == "STAYPRIMARY" or re.search(r"(primary|prim|pri)\b|[-_.]pri[-_.]", low):
                    d.role = "primary"
                elif st == "STAYSECONDARY" or re.search(r"(secondary|second|sec)\b|[-_.]sec[-_.]", low):
                    d.role = "secondary"
            devs.append(d)
        if not devs:
            raise FileNotFoundError("no ns.conf-like files found")
        proj = cls(devs, ha_pairs, redact, link_map)
        if skipped:
            proj.notes.append({"en": "Skipped (no ns.conf statements recognized): " + ", ".join(skipped),
                               "de": "Übersprungen (keine ns.conf-Befehle erkannt): " + ", ".join(skipped)})
        return proj

    # ---- HA-Paarung -----------------------------------------------------------------------
    def _pair(self, explicit: list[tuple[str, str]]) -> None:
        byname = {d.name: d for d in self.devices}
        byfile = {d.cfg.name: d for d in self.devices}
        parent = {d.name: d.name for d in self.devices}
        reason: dict[frozenset, dict] = {}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b, why):
            ra, rb = find(a.name), find(b.name)
            if ra != rb:
                parent[ra] = rb
            reason[frozenset((a.name, b.name))] = why
        for x, y in explicit:
            a, b = byname.get(x) or byfile.get(x), byname.get(y) or byfile.get(y)
            if a and b:
                union(a, b, {"en": "specified on the command line", "de": "per Kommandozeile angegeben"})
        for a in self.devices:
            for b in self.devices:
                if a is b:
                    continue
                peers = {e.args[1] for e in a.cfg.of("ha node").values() if len(e.args) > 1}
                if b.cfg.nsip and b.cfg.nsip in peers:
                    union(a, b, {"en": "`add ha node` points to the NSIP of the other device", "de": "`add ha node` verweist auf NSIP des anderen Geräts"})
        # Similarity: only a hint, no automatic grouping (wrong assignments are worse than none)
        fe = {d.name: {(x["ip"], x["port"]) for x in Graph(d.cfg, "tmp").frontends} for d in self.devices}
        for i, a in enumerate(self.devices):
            for b in self.devices[i + 1:]:
                if find(a.name) != find(b.name) and len(fe[a.name]) >= 3 and fe[a.name] == fe[b.name] and a.cfg.nsip != b.cfg.nsip:
                    self.notes.append({
                        "en": f"Note: {a.name} and {b.name} have identical vServer addresses - possibly an HA pair. "
                              f"Combine with `--ha {a.cfg.name},{b.cfg.name}` (assumption, not done automatically).",
                        "de": f"Hinweis: {a.name} und {b.name} haben identische vServer-Adressen — evtl. HA-Paar. "
                              f"Mit `--ha {a.cfg.name},{b.cfg.name}` zusammenfassen (Annahme, nicht automatisch)."})
        buckets: dict[str, list[Device]] = {}
        for d in self.devices:
            buckets.setdefault(find(d.name), []).append(d)
        for i, devs in enumerate(buckets.values(), 1):
            gid = f"g{i}"
            for d in devs:
                d.gid = gid
            if len(devs) > 1:
                names = {x.name for x in devs}
                whys = [v for k, v in reason.items() if k <= names]
                why = {lg: "; ".join(sorted({w[lg] for w in whys})) for lg in ("en", "de")}
                name = " + ".join(d.name for d in devs)
                self.groups.append(Group(gid, f"HA: {name}", devs, "ha", why))
            else:
                self.groups.append(Group(gid, devs[0].name, devs, "single"))

    # ---- Regeln ---------------------------------------------------------------------------
    def _run_rules(self) -> None:
        load_builtin_rules()
        for g in self.groups:
            for d in g.devices:
                graph = g.graph if d is next((x for x in g.devices if x.cfg is g.graph.cfg), None) else Graph(d.cfg, g.id, self.redact)
                self.findings += run_rules(d.cfg, graph, d.name)
                # Map findings of the second device onto nodes of the group graph
                for f in self.findings:
                    if f.device == d.name and f.node not in g.graph.nodes:
                        n = g.graph.node_for(f.etype, f.name) if f.etype else None
                        f.node = n.id if n else g.graph.device_node().id

    def _diff(self) -> None:
        for g in self.groups:
            if g.kind != "ha" or len(g.devices) < 2:
                continue
            a, b = g.devices[0], g.devices[1]
            d = diff_configs(a.cfg, b.cfg)
            self.diffs[g.id] = [{**x, "a_dev": a.name, "b_dev": b.name} for x in d]
            if len(g.devices) > 2:
                self.notes.append({"en": f"{g.name}: diff only between the first two devices (phase 1).",
                                   "de": f"{g.name}: Diff nur zwischen den ersten beiden Geräten (Phase 1)."})
            crit = ("lb vserver", "cs vserver", "vpn vserver", "gslb ", "service", "bind lb", "bind cs", "bind ssl", "ssl certkey", "authentication")
            if len(d) > HA_DIFF_SUMMARY_LIMIT:
                # Very large drift: the files are probably not from the same sync state (or not real partners).
                # One summary finding instead of hundreds of individual ones; the details stay in the project view.
                kinds = Counter(x["kind"] for x in d)
                msgs = render_messages("HA-003.many", n=len(d), a_only=kinds["only_a"], b_only=kinds["only_b"],
                                       diff=kinds["differs"], a=a.name, b=b.name)
                self.findings.append(Finding("HA-003", "high", msgs, f"{a.name}+{b.name}", "", "", a.cfg.name, 0, [],
                                             g.graph.device_node().id))
                continue
            for x in d:
                sev = "high" if x["key"].startswith(crit) else "medium"
                side = {"only_a": a.name, "only_b": b.name}.get(x["kind"])
                msgs = (render_messages("HA-003.only", key=x["key"][:140], dev=side) if side
                        else render_messages("HA-003.diff", key=x["key"][:140]))
                self.findings.append(Finding("HA-003", sev, msgs, f"{a.name}+{b.name}",
                                             "", "", a.cfg.name, 0, [f"{a.name}: {x['a'][:200]}", f"{b.name}: {x['b'][:200]}"],
                                             g.graph.device_node().id))

    # ---- Double-Hop -----------------------------------------------------------------------
    def _chains(self) -> None:
        for g in self.groups:
            for h in self.groups:
                if g is h:
                    continue
                for be in g.graph.backends:
                    host, port = be["host"], be["port"]
                    if not is_ip(host):
                        continue
                    for fe in h.graph.frontends:
                        if fe["ip"] != host:
                            continue
                        conf = "high" if fe["port"] == port else "medium"
                        if conf == "medium" and be["proto"].upper() in ("DNS", "UDP", "ANY"):
                            continue
                        self.links.append({"from_group": g.id, "to_group": h.id, "from_node": be["node"], "to_node": fe["node"],
                                           "host": host, "port": port, "to_port": fe["port"], "confidence": conf,
                                           "proto": be["proto"]})
                        self.extra_edges.append(Edge(be["node"], fe["node"], "doublehop",
                                                     f"Double-Hop {host}:{port}" + ("" if conf == "high" else " (IP only)"), True))
                        if conf == "medium":
                            self.findings.append(Finding("CHAIN-001", "info", render_messages("CHAIN-001", src=be["name"], dst=fe["name"], host=host, port=port, dport=fe["port"]),
                                                         g.devices[0].name, be["etype"], be["name"], g.devices[0].cfg.name, 0, [], be["node"]))
                        elif be["proto"].upper() in ("HTTP", "TCP"):
                            self.findings.append(Finding("CHAIN-002", "medium", render_messages("CHAIN-002", src=be["name"], proto=be["proto"], dst=fe["name"], dev=h.name),
                                                         g.devices[0].name, be["etype"], be["name"], g.devices[0].cfg.name, 0, [], be["node"]))

    def _url_chains(self) -> None:
        """Session action/STA URLs whose IP and port match a vServer of ANOTHER device (gateway -> StoreFront/LB behind it)."""
        dns: dict[str, tuple[str, str]] = {}  # name -> (ip, device) from 'add dns addRec' of any loaded config
        for g in self.groups:
            for nm, ip in g.graph.dns_rec.items():
                dns.setdefault(nm, (ip, g.name))
        for g in self.groups:
            for u in g.graph.unresolved:
                ip, note = u["ip"], ""
                if not ip and u["host"].lower().rstrip(".") in dns:
                    ip, dev = dns[u["host"].lower().rstrip(".")]
                    note = f" (DNS record on {dev})"
                if not ip:
                    continue
                for h in self.groups:
                    if h is g:
                        continue
                    for fe in h.graph.frontends:
                        if fe["ip"] == ip and (not u["port"] or fe["port"] == u["port"]):
                            self.extra_edges.append(Edge(u["node"], fe["node"], "doublehop", f"{u['via']} → {ip}:{fe['port']}{note}", True))
                            u["resolved"] = True

    # ---- Dependencies: what is reachable from an addressable vServer? --------------------------------
    VS_KINDS = {"csvs", "lbvs", "gwvs", "aaavs", "gslbvs"}
    INFRA_KINDS = {"device", "netip", "vlan", "route", "group", "missing", "domain", "netrule", "td", "crl", "lbgroup"}

    def _dependency(self) -> None:
        """Marks every object as entry (addressable vServer), reached (reachable from an entry or from a global binding)
        or not connected. Edges of all groups plus double-hop/confirmed links are followed; 'contains' is only membership."""
        nodes, adj, gof = {}, {}, {}
        for g in self.groups:
            for nid, n in g.graph.nodes.items():
                nodes[nid], gof[nid] = n, g
            for e in g.graph.edges:
                if e.type not in ("contains", "network"):
                    adj.setdefault(e.source, []).append(e.target)
        for e in self.extra_edges:
            adj.setdefault(e.source, []).append(e.target)
        entries = {nid for nid, n in nodes.items() if n.kind in self.VS_KINDS and n.props.get("Addressing", "").startswith("addressable")}
        # GSLB vServers are reached by DNS name: with a bound domain they are entry points as well
        entries |= {e.source for g in self.groups for e in g.graph.edges if e.type == "gslb" and nodes.get(e.target) is not None and nodes[e.target].kind == "domain"}
        roots = set(entries) | {nid for nid, n in nodes.items() if n.kind in ("device", "group")}
        # Policies bound to AAA users/groups or VPN/system users/groups apply at login and are not drawn (personal data):
        # they count as used, so they are roots of their own chain (action, ...).
        incoming = {t for ts in adj.values() for t in ts}
        for g in self.groups:
            for et, name in g.graph.referenced:
                n = g.graph.node_for(et, name)
                if n is not None and n.id not in incoming and n.kind in ("policy", "authpol"):
                    roots.add(n.id)
        reached, q = set(roots), list(roots)
        while q:
            u = q.pop()
            for v in adj.get(u, ()):
                if v not in reached:
                    reached.add(v)
                    q.append(v)
        self.dep = {nid: {"entry": nid in entries, "reach": nid in reached} for nid in nodes}
        fq: dict[str, list[str]] = {}
        for s in collect(self)["sources"]:
            fq.setdefault(s["node"], []).append(s["host"] + (f":{s['port']}" if s["port"] else ""))
        for nid, hosts in fq.items():
            if nid in nodes:
                nodes[nid].props["FQDN target"] = ", ".join(sorted(set(hosts))) + " (name, not resolved - see Links tab)"
                self.dep[nid]["fqdn"] = True
        for nid, n in nodes.items():
            if n.kind in self.VS_KINDS and nid not in reached:
                g = gof[nid]
                self.findings.append(Finding("DEP-001", "medium", render_messages("DEP-001", name=n.name, etype=n.etype), g.devices[0].name,
                                             n.etype, n.name, g.devices[0].cfg.name, n.lines[0]["line"] if n.lines else 0, [], nid))
        for g in self.groups:
            for u in g.graph.unresolved:
                n = nodes.get(u["node"])
                if n and not u.get("resolved") and u["via"] != "auth server":
                    self.findings.append(Finding("DEP-002", "info", render_messages("DEP-002", name=n.name, via=u["via"], host=u["host"], port=u["port"] or "?"),
                                                 g.devices[0].name, n.etype, n.name, g.devices[0].cfg.name, n.lines[0]["line"] if n.lines else 0, [], u["node"]))

    # ---- Cleanup: configuration that is not used (or only by disabled objects) ---------------------------------
    CLEAN_SKIP_KINDS = INFRA_KINDS | {"sta", "domain", "missing", "device", "gslbsite"}  # a local GSLB site is needed without services too

    @staticmethod
    def _is_disabled(n) -> bool:
        e = n.entity
        st = ((e.opt("state") if e is not None else "") or "").upper()
        return st in ("DISABLED", "OUT OF SERVICE")

    @staticmethod
    def _builtin(n) -> bool:
        nm = n.name or ""
        low = nm.lower()
        return (nm.startswith("_") or low.startswith(("ns_default", "ns-server", "ns-sftrust")) or low in BUILTIN_MONITORS
                or low in BUILTIN_CERTS or low.endswith("-default") or nm.upper() in KEYWORD_NAMES or low.startswith(INTERNAL_SERVICES)
                or n.entity is None or n.entity.implicit or not n.lines)

    def _cleanup(self) -> None:
        """Top-down analysis of what can be removed. Starting points are the addressable vServers, GSLB vServers with a
        domain, global bindings (device) and policies bound to users/groups. Everything not reachable from them is
        'unused'; what is reachable only through disabled objects (state DISABLED) is 'disabled'. The removal order and the
        batch file are built in the report (export). Certainty: 'sure' unless the object's name also appears in a line that
        stays (a reference the model does not draw) - then 'check'."""
        nodes, adj, pred = {}, {}, {}
        for g in self.groups:
            nodes.update(g.graph.nodes)
            for e in g.graph.edges:
                if e.type not in ("contains", "network"):
                    adj.setdefault(e.source, []).append(e.target)
                    pred.setdefault(e.target, []).append(e.source)
        for e in self.extra_edges:
            adj.setdefault(e.source, []).append(e.target)
            pred.setdefault(e.target, []).append(e.source)
        roots = {nid for nid, d in self.dep.items() if d.get("entry")} | {nid for nid, n in nodes.items() if n.kind in ("device", "group")}
        roots |= {e.source for g in self.groups for e in g.graph.edges if e.type == "gslb" and nodes.get(e.target) is not None and nodes[e.target].kind == "domain"}
        incoming = set(pred)
        for g in self.groups:
            for et, name in g.graph.referenced:
                n = g.graph.node_for(et, name)
                if n is not None and n.id not in incoming and n.kind in ("policy", "authpol"):
                    roots.add(n.id)

        def bfs(start: set[str], skip) -> set[str]:
            seen = {r for r in start if not skip(nodes[r])}
            q = list(seen)
            while q:
                u = q.pop()
                for v in adj.get(u, ()):
                    if v not in seen and v in nodes and not skip(nodes[v]):
                        seen.add(v)
                        q.append(v)
            return seen
        reach_all = bfs(roots, lambda n: False)
        reach_act = bfs(roots, self._is_disabled)
        cand: dict[str, dict] = {}
        for nid, n in nodes.items():
            if n.kind in self.CLEAN_SKIP_KINDS or self._builtin(n) or nid in reach_act:
                continue
            cand[nid] = {"cat": "unused" if nid not in reach_all else "disabled", "self_disabled": self._is_disabled(n)}
        # reasons: which candidates use it (the chain), or nothing at all
        for nid, c in cand.items():
            users = [u for u in pred.get(nid, []) if u in nodes and nodes[u].kind != "device"]
            c["by"] = sorted({u for u in users if u in cand})[:8]
            c["why"] = ("disabled" if c["self_disabled"] else "no_ref" if not users else "only_cand")
        # certainty: the name must not appear in a line that stays. Only an object's own lines (first word after the
        # type is its name) are removed with it; lines of other objects that are folded into a node (e.g. a CS action in
        # its policy) stay. Objects that stay ("check") keep their lines too, so this is repeated until nothing changes.
        stmts = [st for g in self.groups for d in g.devices for st in d.cfg.statements]
        stmt_at = {(st.file, st.line): st for st in stmts}
        line_nodes: dict[tuple, set] = {}
        for nid, n in nodes.items():
            for l in n.lines:
                line_nodes.setdefault((l["file"], l["line"]), set()).add(nid)

        def own_lines(nid: str) -> set:
            nm = (nodes[nid].name or "").strip('"')
            out = set()
            for l in nodes[nid].lines:
                st = stmt_at.get((l["file"], l["line"]))
                if st is not None and st.args and st.args[0].strip('"') == nm:
                    out.add((l["file"], l["line"]))
            return out
        own = {nid: own_lines(nid) for nid in cand}
        toks = {(st.file, st.line): set(re.findall(r"[A-Za-z0-9_$.:@/-]+", st.raw)) for st in stmts}
        sure = set(cand)
        for _ in range(20):
            removed = set().union(*(own[nid] for nid in sure)) if sure else set()
            words: set = set()
            for st in stmts:
                k = (st.file, st.line)
                if k in removed:
                    continue
                # bind/link lines of objects that stay become unbind/unlink lines in the batch, so they do not count
                if st.verb in ("bind", "link") and any(n not in sure for n in line_nodes.get(k, ())):
                    continue
                words |= toks[k]
            keep = {nid for nid in sure if nodes[nid].name in words or nodes[nid].name.strip('"') in words}
            if not keep:
                break
            sure -= keep
        for nid, c in cand.items():
            c["sure"] = nid in sure
        for nid, c in cand.items():
            self.dep.setdefault(nid, {})["clean"] = c
        n_un = sum(1 for c in cand.values() if c["cat"] == "unused")
        self.clean_summary = {"unused": n_un, "disabled": len(cand) - n_un, "check": sum(1 for c in cand.values() if not c["sure"])}

    def _coverage_note(self) -> None:
        """Self-check shown in the report: how much of the configuration could be linked, and what is left open."""
        gen = sum(len(getattr(g.graph, "generic_refs", [])) for g in self.groups)
        miss = sum(len(g.graph.missing) for g in self.groups)
        fq = sum(1 for d in self.dep.values() if d.get("fqdn"))
        unl = len(self.unlinked())
        self.notes.append({
            "en": f"Dependency check: {unl} objects not connected (sidebar 'Not connected'), {fq} objects with an FQDN target to link "
                  f"(Links tab), {miss} references to objects that are not defined, {gen} references linked by the generic safety net "
                  "(dashed thin lines, labelled with the option).",
            "de": f"Abhängigkeitsprüfung: {unl} Objekte nicht verknüpft (Seitenleiste 'Nicht verknüpft'), {fq} Objekte mit FQDN-Ziel "
                  f"zum Zuordnen (Tab Verknüpfungen), {miss} Verweise auf nicht definierte Objekte, {gen} Verweise über das allgemeine "
                  "Sicherheitsnetz verknüpft (dünne gestrichelte Linien, mit der Option beschriftet)."})

    def unlinked(self) -> list[dict]:
        """Objects that are not connected to any addressable vServer or global binding (grouped by the report)."""
        out = []
        for g in self.groups:
            for nid, n in g.graph.nodes.items():
                d = self.dep.get(nid)
                if d and not d["reach"] and n.kind not in self.INFRA_KINDS:
                    out.append({"node": nid, "kind": n.kind, "label": n.label, "group": g.id})
        return out

    def chains(self) -> list[list[str]]:
        succ: dict[str, set[str]] = {}
        pred: dict[str, set[str]] = {}
        for l in self.links:
            succ.setdefault(l["from_group"], set()).add(l["to_group"])
            pred.setdefault(l["to_group"], set()).add(l["from_group"])
        names = {g.id: g.name for g in self.groups}
        out: list[list[str]] = []

        def walk(path):
            nxt = [n for n in succ.get(path[-1], ()) if n not in path]
            if not nxt:
                out.append(path)
            for n in sorted(nxt):
                walk(path + [n])
        for g in sorted(succ):
            if g not in pred:
                walk([g])
        if not out and succ:  # reine Zyklen
            for g in sorted(succ):
                walk([g])
        return [[names[x] for x in p] for p in out]

    def _attach(self) -> None:
        idx = {}
        for g in self.groups:
            idx.update(g.graph.nodes)
        for f in self.findings:
            n = idx.get(f.node)
            if n:
                n.findings.append(f.id)

    # ---- Export ---------------------------------------------------------------------------
    def _anon(self):
        """Anonymizer over all loaded configs: the debug mode shows config lines and labels only in this form."""
        from .anonymize import Anonymizer
        an = Anonymizer(options={"comments": True, "timezone": True, "location": True})  # debug output: strictest form
        for g in self.groups:
            for d in g.devices:
                an.learn(d.cfg)
        return an

    def to_dict(self) -> dict:
        an = self._anon()
        alab = lambda s: an.scrub(an._replace_known_names(s or ""))  # noqa: E731
        nodes, edges = [], []
        for g in self.groups:
            for n in g.graph.nodes.values():
                nodes.append({"id": n.id, "kind": n.kind, "label": n.label, "group": g.id, "etype": n.etype, "name": n.name,
                              "props": {k: v for k, v in n.props.items() if not k.startswith("_")},
                              "lines": n.lines, "findings": n.findings, "dep": self.dep.get(n.id, {}),
                              "anon": {"label": an.names.get(n.name) or alab(n.label), "lines": [an.line(l["text"]) or "" for l in n.lines]}})
            for e in g.graph.edges:
                edges.append({"source": e.source, "target": e.target, "type": e.type, "label": e.label, **({"port": True} if e.port else {}), **({"plain": True} if e.plain else {}), "origin": e.origin, "line": e.line, "alabel": alab(e.label)})
        for e in self.extra_edges:
            edges.append({"source": e.source, "target": e.target, "type": e.type, "label": e.label, **({"port": True} if e.port else {}), **({"plain": True} if e.plain else {}), "origin": e.origin, "line": e.line, "alabel": alab(e.label)})
        for i, e in enumerate(edges):
            e["id"] = f"e{i}"
        rules = {r.id: r.meta() for r in RULES.values()}
        return {
            "meta": {"generator": f"nsviz {__version__}", "code": _code_id(), "created": _dt.datetime.now().isoformat(timespec="seconds"),
                     "redacted": self.redact, "kind_labels": KIND_LABELS, "parse": {"families": sorted(FAMILIES), "one_word": sorted(ONE_WORD)}, "severities": SEVERITIES, "categories": CATEGORIES,
                     "notes": self.notes},
            "groups": [{"id": g.id, "name": g.name, "kind": g.kind, "assumption": g.assumption,
                        "devices": [{"name": d.name, "file": d.cfg.name, "role": d.role, "version": d.cfg.version, "build": d.cfg.build,
                                     "nsip": d.cfg.nsip, "statements": len(d.cfg.statements), "warnings": d.cfg.warnings[:20]} for d in g.devices]}
                       for g in self.groups],
            "nodes": nodes, "edges": edges,
            "findings": [{"id": f.id, "rule": f.rule_id, "severity": f.severity, "msgs": f.msgs, "devices": f.devices,
                          "etype": f.etype, "name": f.name, "file": f.file, "line": f.line, "evidence": f.evidence, "node": f.node}
                         for f in self.findings],
            "rules": rules,
            "diffs": self.diffs,
            "links": self.links,
            "unlinked": self.unlinked(),
            "unresolved": [{**u, "group": g.id} for g in self.groups for u in g.graph.unresolved if not u.get("resolved") and not u.get("silent")],
            "linking": {**collect(self), "map": self.link_map},
            "chains": self.chains(),
            "nfactor": {g.id: f for g in self.groups for f in [g.graph.auth_flows()] if f},
            "cleanup": getattr(self, "clean_summary", {}),
            "gateway": {g.id: v for g in self.groups for v in [g.graph.gateway_view()] if v},
        }
