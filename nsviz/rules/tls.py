"""TLS/Zertifikate."""
import re

from . import rule

TR = "BSI TR-02102-2 (Verwendung von Transport Layer Security)"
CON1 = "BSI IT-Grundschutz CON.1 Kryptokonzept"
SDG = "Citrix/NetScaler Secure Deployment Guide (TLS)"
WEAK = re.compile(r"(RC4|3DES|DES-CBC|(^|-)DES(-|$)|EXP|NULL|MD5|ADH|AECDH|ANON)", re.I)
WEAK_GROUPS = {"ALL", "DEFAULT_BACKEND_ALL"}


@rule("TLS-001", "critical", "compliance", [TR, CON1])
def ssl3(ctx):
    for vs in ctx.ssl_frontends():
        if ctx.effective_ssl(vs).get("ssl3") == "ENABLED":
            yield ctx.finding("TLS-001", vs)


@rule("TLS-002", "high", "compliance", [TR])
def tls10(ctx):
    for vs in ctx.ssl_frontends():
        s = ctx.effective_ssl(vs)
        old = [v for v, k in (("TLS 1.0", "tls1"), ("TLS 1.1", "tls11")) if s.get(k) == "ENABLED"]
        if old:
            yield ctx.finding("TLS-002", vs, versions=" + ".join(old))


@rule("TLS-003", "high", "compliance", [TR, SDG])
def weak_ciphers(ctx):
    targets = [(vs, "ssl vserver", vs.name) for vs in ctx.ssl_frontends()]
    targets += [(p, "ssl profile", p.name) for p in ctx.ents("ssl profile")]
    seen = set()
    for ent, et, name in targets:
        names = ctx.cipher_names(name, et)
        bad = sorted({n for n in names if WEAK.search(n) or n.upper() in WEAK_GROUPS})
        if bad and (et, name) not in seen:
            seen.add((et, name))
            yield ctx.finding("TLS-003", ent, etype=et, name=name, bad=", ".join(bad))


@rule("TLS-004", "high", "misconfig", [TR])
def tls12_off(ctx):
    for vs in ctx.ssl_frontends():
        if ctx.effective_ssl(vs).get("tls12") == "DISABLED":
            yield ctx.finding("TLS-004", vs)


@rule("TLS-005", "low", "best-practice", [TR], confidence="likely")
def tls13_off(ctx):
    for vs in ctx.ssl_frontends():
        if ctx.effective_ssl(vs).get("tls13") == "DISABLED":
            yield ctx.finding("TLS-005", vs)


@rule("TLS-006", "medium", "best-practice", [SDG])
def reneg(ctx):
    for vs in ctx.ssl_frontends():
        if ctx.effective_ssl(vs).get("denysslreneg") == "NO":
            yield ctx.finding("TLS-006", vs)


@rule("TLS-007", "high", "best-practice", [SDG, CON1])
def default_cert(ctx):
    for b in ctx.cfg.binds("ssl vserver"):
        if (b.opt("certkeyname") or "") == "ns-server-certificate":
            vs = next((e for t in ("lb vserver", "cs vserver", "vpn vserver", "authentication vserver") if (e := ctx.cfg.get(t, b.owner))), None)
            if vs:
                yield ctx.finding("TLS-007", vs, line=b.line, evidence=[b.raw])


@rule("TLS-008", "high", "misconfig", [])
def no_cert(ctx):
    for vs in ctx.ssl_frontends():
        if vs.args[1].upper() == "DTLS":
            continue
        if not any(b.opt("certkeyname") for b in ctx.cfg.binds("ssl vserver", vs.name)):
            yield ctx.finding("TLS-008", vs)


@rule("TLS-009", "low", "best-practice", [SDG])
def expiry(ctx):
    for e in ctx.ents("ssl certkey"):
        if (e.opt("expirymonitor") or "").upper() == "DISABLED":
            yield ctx.finding("TLS-009", e)


@rule("TLS-010", "medium", "compliance", [TR, "BSI IT-Grundschutz NET.1.1 Netzarchitektur und -design (Absicherung interner Verbindungen)"], confidence="heuristic")
def backend_tls(ctx):
    for et in ("service", "servicegroup"):
        for e in ctx.ents(et):
            if len(e.args) > (2 if et == "service" else 1) and e.args[2 if et == "service" else 1].upper() in ("SSL", "SSL_TCP"):
                sv = ctx.cfg.get("ssl " + et, e.name)
                auth = (sv.opt("serverauth") if sv else None) or ""
                prof = ctx.cfg.get("ssl profile", sv.opt("sslprofile")) if sv and sv.opt("sslprofile") else None
                if prof and (prof.opt("serverauth") or "").upper() == "ENABLED":
                    continue
                if auth.upper() != "ENABLED":
                    yield ctx.finding("TLS-010", e)


@rule("TLS-011", "low", "best-practice", ["BSI IT-Grundschutz APP.3.2 Webserver / APP.3.1 Webanwendungen und Webservices"], confidence="heuristic")
def hsts(ctx):
    if not ctx.ssl_frontends():
        return
    has = any("strict-transport-security" in " ".join(" ".join(v) for v in a.opts.values()).lower() + " ".join(a.args).lower()
              for a in ctx.ents("rewrite action"))
    has = has or any((p.opt("hsts") or "").upper() == "ENABLED" for p in ctx.ents("ssl profile"))
    has = has or any((sv.opt("hsts") or "").upper() == "ENABLED" for sv in ctx.ents("ssl vserver"))
    if not has:
        yield ctx.finding("TLS-011", etype="rewrite action", name="")
