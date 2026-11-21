"""Additional rules: load balancing, network, cluster, content policies, gateway, system.

Every rule only evaluates facts that are explicitly present in the configuration; where a statement depends on
defaults or on runtime state, the rule is marked ``likely`` or ``heuristic``.
"""
import ipaddress

from . import rule

SDG = "Citrix/NetScaler Secure Deployment Guide"
APP31 = "BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices"
NET12 = "BSI IT-Grundschutz NET.1.2 Netzmanagement"
NET11 = "BSI IT-Grundschutz NET.1.1 Netzarchitektur und -design"
OPS115 = "BSI IT-Grundschutz OPS.1.1.5 Protokollierung"

HTTP_LIKE = {"HTTP", "SSL", "HTTP_QUIC", "SSL_TCP"}


def _svc_proto(ent):
    """Protocol of a service (``add service <name> <server> <proto> <port>``) or service group (``add serviceGroup <name> <proto>``)."""
    if ent.etype == "service":
        return ent.args[2].upper() if len(ent.args) > 2 else ""
    return ent.args[1].upper() if len(ent.args) > 1 else ""


def _monitor_bound(ctx, ent):
    return any(b.opt("monitorname") for b in ctx.cfg.binds(ent.etype, ent.name))


# ---- load balancing -------------------------------------------------------------------------

@rule("LB-001", "medium", "best-practice", [SDG])
def health_monitor_off(ctx):
    for et in ("service", "servicegroup"):
        for e in ctx.ents(et):
            if (e.opt("healthmonitor") or "").upper() == "NO":
                yield ctx.finding("LB-001", e)


@rule("LB-002", "info", "best-practice", confidence="heuristic")
def only_default_monitor(ctx):
    for et in ("service", "servicegroup"):
        for e in ctx.ents(et):
            if e.name.startswith("ns") or (e.opt("healthmonitor") or "").upper() == "NO":
                continue
            if _svc_proto(e) in HTTP_LIKE and not _monitor_bound(ctx, e):
                yield ctx.finding("LB-002", e, proto=_svc_proto(e))


@rule("LB-003", "medium", "misconfig")
def backup_loop(ctx):
    nxt = {e.name: e.opt("backupvserver") for e in ctx.ents("lb vserver") if e.opt("backupvserver")}
    seen = set()
    for start in nxt:
        path, cur = [], start
        while cur in nxt and cur not in path:
            path.append(cur)
            cur = nxt[cur]
        if cur in path and cur not in seen:
            cyc = path[path.index(cur):]
            seen.update(cyc)
            yield ctx.finding("LB-003", etype="lb vserver", name=cur, chain=" → ".join(cyc + [cur]))


@rule("CS-001", "info", "misconfig", confidence="heuristic")
def cs_without_policy(ctx):
    for vs in ctx.ents("cs vserver"):
        binds = ctx.cfg.binds("cs vserver", vs.name)
        if binds and not any(b.opt("policyname") for b in binds):
            yield ctx.finding("CS-001", vs)


# ---- TLS ------------------------------------------------------------------------------------

@rule("TLS-012", "info", "best-practice", [SDG], confidence="likely")
def tls_settings_on_vserver(ctx):
    for vs in ctx.ssl_frontends():
        sv = ctx.cfg.get("ssl vserver", vs.name)
        if not sv or sv.opt("sslprofile") or vs.opt("sslprofile"):
            continue
        direct = [k for k in ("ssl3", "tls1", "tls11", "tls12", "tls13") if sv.opt(k)]
        if direct:
            yield ctx.finding("TLS-012", vs, etype=vs.etype, opts=", ".join("-" + k for k in direct))


# ---- network ------------------------------------------------------------------------------

def _local_networks(ctx):
    nets = []
    for e in ctx.ents("ns ip"):
        if len(e.args) > 1:
            try:
                nets.append(ipaddress.ip_interface(f"{e.args[0]}/{e.args[1]}").network)
            except ValueError:
                pass
    cfg = ctx.cfg.single("ns config")
    if cfg and cfg.opt("ipaddress") and cfg.opt("netmask"):
        try:
            nets.append(ipaddress.ip_interface(f"{cfg.opt('ipaddress')}/{cfg.opt('netmask')}").network)
        except ValueError:
            pass
    return nets


@rule("NET-001", "medium", "misconfig", [NET11], confidence="likely")
def route_gateway_unreachable(ctx):
    nets = _local_networks(ctx)
    if not nets:
        return
    for st in ctx.cfg.statements:
        if st.verb != "add" or st.etype != "route" or len(st.args) < 3 or st.opt("td") or st.opt("vlan"):
            continue
        try:
            gw = ipaddress.ip_address(st.args[2])
        except ValueError:
            continue
        if gw.version == 4 and not any(gw in n for n in nets):
            yield ctx.finding("NET-001", etype="route", name=st.args[0], line=st.line, evidence=[st.raw],
                              gateway=st.args[2], dest=f"{st.args[0]}/{st.args[1]}")


@rule("NET-002", "info", "misconfig", confidence="heuristic")
def vlan_without_interface(ctx):
    for e in ctx.ents("vlan"):
        if e.name in ("1", "") or e.name.startswith("_"):
            continue
        if not any(b.opt("ifnum") for b in ctx.cfg.binds("vlan", e.name)):
            yield ctx.finding("NET-002", e)


@rule("NET-003", "low", "misconfig", confidence="likely")
def td_without_vlan(ctx):
    for e in ctx.ents("ns trafficdomain"):
        if e.name == "0":
            continue
        if not any(b.opt("vlan") for b in ctx.cfg.binds("ns trafficdomain", e.name)):
            yield ctx.finding("NET-003", e)


# ---- cluster --------------------------------------------------------------------------------

@rule("CLU-001", "medium", "misconfig", confidence="likely")
def cluster_node_no_backplane(ctx):
    for e in ctx.ents("cluster node"):
        if not e.opt("backplane"):
            yield ctx.finding("CLU-001", e)


@rule("CLU-002", "high", "misconfig", confidence="likely")
def cluster_and_ha(ctx):
    if ctx.ents("cluster instance") and ctx.ents("ha node"):
        yield ctx.finding("CLU-002", etype="ha node", name=ctx.ents("ha node")[0].name)


# ---- application firewall -------------------------------------------------------------------

@rule("WAF-004", "info", "best-practice", [APP31], confidence="heuristic")
def waf_no_signatures(ctx):
    for e in ctx.ents("appfw profile"):
        if e.name.startswith("APPFW_") or e.opt("signatures"):
            continue
        yield ctx.finding("WAF-004", e)


# ---- rewrite and responder ------------------------------------------------------------------

def _policy_binds(ctx):
    """(binding, policy entity, policy type) for rewrite and responder policies bound to a vServer."""
    for b in ctx.cfg.bindings:
        if b.etype not in ("lb vserver", "cs vserver", "vpn vserver"):
            continue
        pol = b.opt("policyname") or b.opt("policy")
        for pt in ("rewrite policy", "responder policy"):
            ent = ctx.cfg.get(pt, pol) if pol else None
            if ent:
                yield b, ent, pt


@rule("RW-001", "high", "misconfig")
def bindpoint_mismatch(ctx):
    seen = set()
    for b, pol, pt in _policy_binds(ctx):
        direction = (b.opt("type") or "REQUEST").upper()
        rule_expr = pol.args[1] if len(pol.args) > 1 else ""
        bad = ""
        if direction == "REQUEST" and "HTTP.RES." in rule_expr.upper():
            bad = "rule"
        elif pt == "rewrite policy" and len(pol.args) > 2:
            act = ctx.cfg.get("rewrite action", pol.args[2])
            target = (act.args[2].upper() if act and len(act.args) > 2 else "")
            if direction == "REQUEST" and target.startswith("HTTP.RES."):
                bad = "action"
            elif direction == "RESPONSE" and target.startswith("HTTP.REQ."):
                bad = "action"
        key = (b.owner, pol.name)
        if bad and key not in seen:
            seen.add(key)
            yield ctx.finding("RW-001", pol, etype=pt, owner=b.owner, direction=direction, part=bad)


# ---- gateway ------------------------------------------------------------------------------

@rule("VPN-001", "medium", "best-practice", [SDG])
def default_authorization_allow(ctx):
    for e in ctx.ents("vpn sessionaction"):
        if (e.opt("defaultauthorizationaction") or "").upper() == "ALLOW":
            yield ctx.finding("VPN-001", e)
    p = ctx.cfg.single("vpn parameter")
    if p and (p.opt("defaultauthorizationaction") or "").upper() == "ALLOW":
        yield ctx.finding("VPN-001", p, etype="vpn parameter", name="vpn parameter")


@rule("VPN-002", "medium", "misconfig", confidence="likely")
def ica_proxy_without_sta(ctx):
    for vs in ctx.ents("vpn vserver"):
        binds = ctx.cfg.binds("vpn vserver", vs.name)
        uses_ica = False
        for b in binds:
            sp = ctx.cfg.get("vpn sessionpolicy", b.opt("policy") or b.opt("policyname") or "")
            act = ctx.cfg.get("vpn sessionaction", sp.args[2]) if sp and len(sp.args) > 2 else None
            if act and (act.opt("icaproxy") or "").upper() == "ON":
                uses_ica = True
        if uses_ica and not any(b.opt("staserver") for b in binds):
            yield ctx.finding("VPN-002", vs)


@rule("VPN-003", "low", "best-practice", [SDG], confidence="likely")
def no_login_limit(ctx):
    for et in ("vpn vserver", "authentication vserver"):
        for vs in ctx.ents(et):
            if len(vs.args) > 2 and vs.args[2] in ("0.0.0.0", "::"):
                continue
            if not vs.opt("maxloginattempts"):
                yield ctx.finding("VPN-003", vs)


# ---- system -----------------------------------------------------------------------------

@rule("MODE-001", "medium", "best-practice", [SDG], confidence="likely")
def l2_mode(ctx):
    if "L2" in ctx.cfg.modes:
        yield ctx.finding("MODE-001", etype="ns mode", name="L2")


@rule("MGMT-015", "medium", "misconfig", [NET12], confidence="likely")
def snmp_community_without_manager(ctx):
    comms = ctx.ents("snmp community")
    if comms and not ctx.ents("snmp manager"):
        yield ctx.finding("MGMT-015", comms[0], n=len(comms))


@rule("MGMT-016", "low", "best-practice", [OPS115], confidence="heuristic")
def single_ntp(ctx):
    if len(ctx.ents("ntp server")) == 1:
        yield ctx.finding("MGMT-016", ctx.ents("ntp server")[0])


@rule("MGMT-017", "info", "best-practice", confidence="heuristic")
def single_dns(ctx):
    ns = [e for e in ctx.ents("dns nameserver")]
    if len(ns) == 1:
        yield ctx.finding("MGMT-017", ns[0])


# ---- consistency -------------------------------------------------------------------------

@rule("QA-013", "info", "misconfig")
def duplicate_cert_file(ctx):
    by_file = {}
    for e in ctx.ents("ssl certkey"):
        f = e.opt("cert")
        if f:
            by_file.setdefault(f.lower(), []).append(e)
    for f, ents in by_file.items():
        if len(ents) > 1:
            yield ctx.finding("QA-013", ents[1], names=", ".join(x.name for x in ents), file=f)


@rule("QA-014", "info", "misconfig")
def disabled_server_in_use(ctx):
    users = {}
    for s in ctx.ents("service"):
        if len(s.args) > 1:
            users.setdefault(s.args[1], []).append(s.name)
    for b in ctx.cfg.binds("servicegroup"):
        if b.args and not b.args[0].startswith("-"):
            users.setdefault(b.args[0], []).append(b.owner)
    for e in ctx.ents("server"):
        if (e.opt("state") or "").upper() == "DISABLED" and e.name in users:
            yield ctx.finding("QA-014", e, n=len(set(users[e.name])))


@rule("QA-015", "info", "misconfig")
def duplicate_server_ip(ctx):
    by_ip = {}
    for e in ctx.ents("server"):
        if len(e.args) > 1:
            by_ip.setdefault(e.args[1], []).append(e)
    for ip, ents in by_ip.items():
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if len(ents) > 1:
            yield ctx.finding("QA-015", ents[1], names=", ".join(x.name for x in ents), ip=ip)
