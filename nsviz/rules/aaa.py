"""AAA, Gateway, nFactor, WAF, GSLB, HA, IP-Reputation."""
from . import rule

BSI_IAM = "BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement"
TR = "BSI TR-02102-2 (Verwendung von Transport Layer Security)"
APP31 = "BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices"
SDG = "Citrix/NetScaler Secure Deployment Guide"


@rule("AAA-001", "high", "compliance", [TR, BSI_IAM, SDG], confidence="likely")
def ldap_plain(ctx):
    for e in ctx.ents("authentication ldapaction"):
        st = (e.opt("sectype") or "PLAINTEXT").upper()
        if st == "PLAINTEXT":
            yield ctx.finding("AAA-001", e)


@rule("AAA-002", "medium", "compliance", [TR, SDG], confidence="heuristic")
def ldap_validate(ctx):
    for e in ctx.ents("authentication ldapaction"):
        if (e.opt("sectype") or "PLAINTEXT").upper() in ("SSL", "TLS") and (e.opt("validateservercert") or "NO").upper() != "YES":
            yield ctx.finding("AAA-002", e)


@rule("AAA-003", "high", "compliance", [TR, APP31])
def aaa_no_tls(ctx):
    for et in ("vpn vserver", "authentication vserver"):
        for e in ctx.ents(et):
            if len(e.args) > 1 and e.args[1].upper() not in ("SSL", "SSL_TCP", "DTLS"):
                ip = e.args[2] if len(e.args) > 2 else ""
                if et == "authentication vserver" and (not ip or ip == "0.0.0.0"):
                    continue
                yield ctx.finding("AAA-003", e, proto=e.args[1])


@rule("AAA-004", "high", "misconfig", [BSI_IAM], confidence="likely")
def gw_noauth(ctx):
    for e in ctx.ents("vpn vserver"):
        if (e.opt("authentication") or "ON").upper() == "OFF":
            yield ctx.finding("AAA-004", e)
            continue
        if e.opt("authnprofile"):
            continue
        binds = ctx.cfg.binds("vpn vserver", e.name)
        has = any((b.opt("policy") or b.opt("policyname")) and (
            (ctx.cfg.get("authentication ldappolicy", b.opt("policy") or b.opt("policyname"))) or
            any(ctx.cfg.get(t, b.opt("policy") or b.opt("policyname")) for t in ctx.cfg.entities if t.startswith("authentication ") and t.endswith("policy"))
        ) for b in binds)
        if not has:
            yield ctx.finding("AAA-004.nopol", e)


@rule("AAA-005", "medium", "misconfig", [], confidence="likely")
def nf_no_schema(ctx):
    for e in ctx.ents("authentication policylabel"):
        ls = e.opt("loginschema") or (e.args[1] if len(e.args) > 1 else "")
        if not ls:
            yield ctx.finding("AAA-005", e)


@rule("AAA-006", "low", "misconfig")
def nf_unreachable(ctx):
    for e in ctx.ents("authentication policylabel"):
        if ("authentication policylabel", e.name) not in ctx.graph.referenced:
            yield ctx.finding("AAA-006", e)


@rule("AAA-007", "medium", "misconfig")
def av_no_policy(ctx):
    for e in ctx.ents("authentication vserver"):
        if not any(b.opt("policy") or b.opt("policyname") for b in ctx.cfg.binds("authentication vserver", e.name)):
            yield ctx.finding("AAA-007", e)


@rule("AAA-008", "high", "compliance", [BSI_IAM, SDG])
def saml_unsigned(ctx):
    for e in ctx.ents("authentication samlaction"):
        if (e.opt("samlrejectunsignedassertion") or "").upper() == "OFF":
            yield ctx.finding("AAA-008", e)


@rule("WAF-001", "medium", "misconfig", [APP31])
def waf_profile_unbound(ctx):
    for e in ctx.ents("appfw profile"):
        if ("appfw profile", e.name) not in ctx.graph.referenced and not e.name.startswith("APPFW_"):
            yield ctx.finding("WAF-001", e)


@rule("WAF-002", "low", "best-practice", [APP31], confidence="heuristic")
def waf_no_block(ctx):
    for e in ctx.ents("appfw profile"):
        acts = {k: v for k, v in e.opts.items() if k.endswith("action")}
        if acts and not any("block" in [x.lower() for x in v] for v in acts.values()):
            yield ctx.finding("WAF-002", e)


@rule("WAF-003", "info", "best-practice", [APP31], confidence="heuristic")
def waf_missing(ctx):
    if not ctx.ents("appfw profile"):
        return
    names = [vs.name for vs in ctx.vservers("lb vserver", "cs vserver")
             if len(vs.args) > 1 and vs.args[1].upper() in ("HTTP", "SSL")
             and not any(ctx.graph_pol_type(b) == "appfw policy" for b in ctx.cfg.binds(vs.etype, vs.name))]
    if names:
        yield ctx.finding("WAF-003", etype="appfw profile", name="", n=len(names),
                          names=", ".join(names[:12]) + (" …" if len(names) > 12 else ""))


@rule("GSLB-001", "medium", "misconfig")
def gslb_domain(ctx):
    for e in ctx.ents("gslb vserver"):
        if not any(b.opt("domainname") for b in ctx.cfg.binds("gslb vserver", e.name)):
            yield ctx.finding("GSLB-001", e)


@rule("GSLB-002", "medium", "misconfig", [], confidence="likely")
def gslb_adns(ctx):
    if ctx.ents("gslb vserver"):
        has = any(len(s.args) > 2 and s.args[2].upper().startswith("ADNS") for s in ctx.ents("service"))
        if not has:
            yield ctx.finding("GSLB-002", etype="gslb vserver", name=ctx.ents("gslb vserver")[0].name)


@rule("GSLB-003", "info", "best-practice")
def gslb_single(ctx):
    for e in ctx.ents("gslb vserver"):
        n = sum(1 for b in ctx.cfg.binds("gslb vserver", e.name) if b.opt("servicename"))
        if n < 2:
            yield ctx.finding("GSLB-003", e, n=n)


@rule("GSLB-004", "low", "best-practice")
def gslb_mep(ctx):
    sites = ctx.ents("gslb site")
    if len(sites) > 1:
        for e in sites:
            if (e.opt("metricexchange") or "").upper() == "DISABLED":
                yield ctx.finding("GSLB-004", e)


@rule("HA-001", "medium", "misconfig")
def ha_sync(ctx):
    for e in ctx.ents_all("ha node"):
        for k in ("hasync", "haprop"):
            if (e.opt(k) or "").upper() == "DISABLED":
                yield ctx.finding("HA-001", e, opt=k[:2] + k[2:].capitalize())


@rule("HA-002", "info", "best-practice", [], confidence="heuristic")
def ha_none(ctx):
    cfg = ctx.cfg
    if cfg.nsip and not cfg.of("ha node") and not cfg.of("cluster node"):
        yield ctx.finding("HA-002", etype="ha node", name="")


@rule("REP-001", "medium", "misconfig", [], confidence="heuristic")
def iprep(ctx):
    cfg = ctx.cfg
    pols = [e for et, d in cfg.entities.items() if et.endswith("policy") for e in d.values()
            if "IPREP" in " ".join([e.opt("rule") or "", *(e.args[1:2])]).upper()]
    if pols and cfg.features and "REP" not in cfg.features:
        yield ctx.finding("REP-001", pols[0], n=len(pols))
