"""Misconfigurations and consistency (orphaned objects, dead references, features)."""
from collections import defaultdict

from . import rule
from ..model import BUILTIN_MONITORS

FEATURE_BY_FAMILY = {
    "lb": "LB", "cs": "CS", "ssl": "SSL", "rewrite": "REWRITE", "responder": "RESPONDER",
    "appfw": "APPFW", "gslb": "GSLB", "cmp": "CMP", "cache": "IC", "vpn": "SSLVPN",
    "authentication": "AAA", "aaa": "AAA", "appflow": "APPFLOW", "bot": "BOT",
    "feo": "FEO", "appqoe": "APPQOE", "contentinspection": "CI",
}
FEATURE_ALIASES = {"SSLVPN": {"SSLVPN"}, "APPFLOW": {"APPFLOW"}, "IC": {"IC", "CACHE"}}
# Object types whose mere existence does not prove the feature requirement (default objects/parameters)
FEATURE_TRIGGER = {
    "lb": ("lb vserver",), "cs": ("cs vserver",), "gslb": ("gslb vserver", "gslb service"),
    "vpn": ("vpn vserver",), "appfw": ("appfw profile", "appfw policy"),
    "rewrite": ("rewrite policy",), "responder": ("responder policy",), "cmp": ("cmp policy",),
    "cache": ("cache policy",), "authentication": ("authentication vserver",), "bot": ("bot profile",),
    "feo": ("feo policy",), "appqoe": ("appqoe policy",), "contentinspection": ("contentinspection policy",),
}


@rule("QA-001", "medium", "misconfig")
def lb_no_service(ctx):
    for vs in ctx.ents("lb vserver"):
        binds = ctx.cfg.binds("lb vserver", vs.name)
        has = any((b.args and not b.args[0].startswith("-")) or b.opt("servicename") for b in binds)
        if not has:
            yield ctx.finding("QA-001", vs)


@rule("QA-002", "low", "misconfig")
def svc_unused(ctx):
    for et in ("service", "servicegroup"):
        for e in ctx.ents(et):
            if (et, e.name) in ctx.graph.referenced or e.name.startswith("nshttpd") or e.name.startswith("nsrnatsip") or e.name.startswith("nskrpcs"):
                continue
            if any(e.name in (b.opt("servicename"),) for b in ctx.cfg.binds("gslb vserver")):
                continue
            yield ctx.finding("QA-002", e)


@rule("QA-003", "info", "misconfig")
def server_unused(ctx):
    used = {(a.args[1] if et == "service" and len(a.args) > 1 else "") for et in ("service",) for a in ctx.ents(et)}
    for b in ctx.cfg.bindings:
        if b.etype == "servicegroup" and b.args and not b.args[0].startswith("-"):
            used.add(b.args[0])
    for b in ctx.cfg.bindings:
        if b.etype == "gslb servicegroup" and b.args:
            used.add(b.args[0])
    for e in ctx.ents("server"):
        if e.name not in used and not e.name.startswith("ns"):
            yield ctx.finding("QA-003", e)


@rule("QA-004", "low", "misconfig")
def policy_unused(ctx):
    for et, d in ctx.cfg.entities.items():
        if not (et.endswith(" policy") or et.endswith("policy")) or et == "policy":
            continue
        if et.startswith("authentication ") and et != "authentication policy" and not et.endswith("policy"):
            continue
        for e in d.values():
            if e.implicit or (et, e.name) in ctx.graph.referenced:
                continue
            # globally bound policies (bind <x> global) are recorded as references by the graph
            yield ctx.finding("QA-004", e)


@rule("QA-005", "low", "misconfig")
def cert_unused(ctx):
    linked = {a for ab in ctx.cfg.links for a in ab}
    for e in ctx.ents("ssl certkey"):
        if ("ssl certkey", e.name) in ctx.graph.referenced or e.name in linked or e.name in ("ns-server-certificate", "ns-sftrust-certificate"):
            continue
        yield ctx.finding("QA-005", e)


@rule("QA-006", "info", "misconfig")
def monitor_unused(ctx):
    for e in ctx.ents("lb monitor"):
        if ("lb monitor", e.name) not in ctx.graph.referenced and e.name.lower() not in BUILTIN_MONITORS:
            yield ctx.finding("QA-006", e)


@rule("QA-007", "high", "misconfig", [], confidence="likely")
def dangling(ctx):
    seen = set()
    for m in ctx.graph.missing:
        k = (m["src_etype"], m["src_name"], m["ref_type"], m["ref_name"])
        if k in seen:
            continue
        seen.add(k)
        et, nm = m["src_etype"], m["src_name"]
        ent = ctx.cfg.get(et, nm) if et else None
        yield ctx.finding("QA-007", ent, etype=et, name=nm, line=m.get("line", 0), src=et or "global",
                          ref_type=m["ref_type"], ref_name=m["ref_name"])


@rule("QA-008", "high", "misconfig")
def dup_vip(ctx):
    seen = defaultdict(list)
    for fe in ctx.graph.frontends:
        seen[(fe["ip"], fe["port"], fe["proto"])].append(fe)
    for (ip, port, proto), lst in seen.items():
        if len(lst) > 1:
            names = ", ".join(f"{x['etype']} {x['name']}" for x in lst)
            ent = ctx.cfg.get(lst[0]["etype"], lst[0]["name"])
            yield ctx.finding("QA-008", ent, addr=f"{ip}:{port}/{proto}", names=names)


@rule("QA-009", "high", "misconfig")
def feature_off(ctx):
    cfg = ctx.cfg
    if not cfg.features and not cfg.disabled_features:
        return  # Config without 'enable ns feature' (partial export): no statement possible
    for fam, need in FEATURE_BY_FAMILY.items():
        trig = FEATURE_TRIGGER.get(fam)
        if not trig:
            continue
        # built-in default objects exist in every ns.conf: names starting with "_" and, for integrated caching, the
        # default "ctx_" cache policies (measured: present in configs with the feature off; assumption: shipped defaults)
        own = [(t, n) for t in trig for n in cfg.of(t)
               if not n.startswith("_") and not (fam == "cache" and n.lower().startswith("ctx_"))]
        if own:
            ok = FEATURE_ALIASES.get(need, {need})
            if not (cfg.features & ok):
                yield ctx.finding("QA-009", etype=own[0][0], name=own[0][1], feature=need)


@rule("QA-010", "high", "misconfig")
def cs_no_target(ctx):
    for vs in ctx.ents("cs vserver"):
        if not ctx.cfg.binds("cs vserver", vs.name):
            yield ctx.finding("QA-010", vs)


@rule("QA-011", "info", "best-practice", [], confidence="heuristic")
def https_redirect(ctx):
    ports = defaultdict(set)
    for fe in ctx.graph.frontends:
        ports[fe["ip"]].add(fe["port"])
    for vs in ctx.ssl_frontends():
        if vs.etype in ("authentication vserver",) or len(vs.args) < 4:
            continue
        if vs.opt("redirectfromport") or "80" in ports.get(vs.args[2], set()):
            continue
        if vs.args[3] == "443" and vs.args[2] not in ("0.0.0.0",):
            yield ctx.finding("QA-011", vs, ip=vs.args[2])


@rule("QA-012", "info", "misconfig")
def disabled(ctx):
    for vs in ctx.vservers():
        if (vs.opt("state") or "").upper() == "DISABLED":
            yield ctx.finding("QA-012", vs)
