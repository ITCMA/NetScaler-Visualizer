"""Management access, hardening, logging, SNMP."""
from . import rule

SDG = "Citrix/NetScaler Secure Deployment Guide (section management access/hardening)"
BSI_NET12 = "BSI IT-Grundschutz NET.1.2 Netzmanagement"
BSI_LOG = "BSI IT-Grundschutz OPS.1.1.5 Protokollierung"
BSI_IAM = "BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement"
DEFAULT_COMMUNITIES = {"public", "private", "netscaler", "community", "snmp", "admin", "cisco"}


def _ips(ctx):
    return ctx.ents("ns ip") + ctx.ents("ns ip6")


def _type(e):
    return (e.opt("type") or "SNIP").upper()


@rule("MGMT-001", "critical", "compliance", [BSI_NET12, SDG])
def telnet(ctx):
    for e in _ips(ctx):
        if (e.opt("telnet") or "").upper() == "ENABLED":
            yield ctx.finding("MGMT-001", e)


@rule("MGMT-002", "high", "compliance", [BSI_NET12, SDG])
def gui_http(ctx):
    for e in _ips(ctx):
        if (e.opt("gui") or "").upper() == "ENABLED":
            yield ctx.finding("MGMT-002", e)


@rule("MGMT-003", "high", "best-practice", [SDG, BSI_NET12])
def mgmt_on_data_ip(ctx):
    for e in _ips(ctx):
        if _type(e) in ("SNIP", "VIP", "MIP") and (e.opt("mgmtaccess") or "").upper() == "ENABLED":
            yield ctx.finding("MGMT-003", e, type=_type(e))


@rule("MGMT-004", "medium", "compliance", [BSI_NET12])
def ftp(ctx):
    for e in _ips(ctx):
        if (e.opt("ftp") or "").upper() == "ENABLED":
            yield ctx.finding("MGMT-004", e)


@rule("MGMT-005", "medium", "compliance", [BSI_IAM, SDG], confidence="likely")
def strongpw(ctx):
    sp = ctx.cfg.single("system parameter")
    if not sp or (sp.opt("strongpassword") or "DISABLED").upper() == "DISABLED":
        yield ctx.finding("MGMT-005", sp,
                          etype="system parameter", name="")
    elif sp.opt("minpasswordlen") and sp.opt("minpasswordlen").isdigit() and int(sp.opt("minpasswordlen")) < 8:
        yield ctx.finding("MGMT-005.len", sp, n=sp.opt("minpasswordlen"))


@rule("MGMT-006", "low", "best-practice", [SDG], confidence="likely")
def force_pw(ctx):
    sp = ctx.cfg.single("system parameter")
    if not sp or (sp.opt("forcepasswordchange") or "DISABLED").upper() != "ENABLED":
        yield ctx.finding("MGMT-006", sp, etype="system parameter", name="")


@rule("MGMT-007", "high", "compliance", [BSI_IAM, "BSI IT-Grundschutz CON.1 Kryptokonzept"], confidence="likely")
def plaintext_pw(ctx):
    for st in ctx.cfg.statements:
        if st.verb not in ("add", "set"):
            continue
        if "encrypted" in st.opts:
            continue
        has_pw = any(k in st.opts for k in ("password", "ldapbinddnpassword", "radkey", "secretkey", "sharedsecret", "clientsecret"))
        if st.etype == "system user" and len(st.args) > 1 and not st.args[1].startswith("-"):
            has_pw = True
        if has_pw:
            yield ctx.finding("MGMT-007", cmd=f"{st.verb} {st.etype} {st.args[0] if st.args else ''}".strip(),
                              etype=st.etype, name=st.args[0] if st.args else "", line=st.line,
                              evidence=[f"{st.verb} {st.etype} {st.args[0] if st.args else ''} … (value masked)"])


@rule("MGMT-008", "medium", "compliance", [BSI_IAM, SDG], confidence="heuristic")
def nsroot_default(ctx):
    if not ctx.cfg.statements:
        return
    if not ctx.cfg.get("system user", "nsroot"):
        yield ctx.finding("MGMT-008",
                          etype="system user", name="nsroot")


@rule("MGMT-009", "low", "best-practice", [BSI_IAM], confidence="likely")
def ext_auth(ctx):
    if ctx.cfg.statements and not ctx.cfg.binds("system global"):
        yield ctx.finding("MGMT-009",
                          etype="system global", name="")


@rule("MGMT-010", "medium", "compliance", [BSI_LOG, SDG])
def no_syslog(ctx):
    cfg = ctx.cfg
    if not cfg.statements:
        return
    if not (cfg.binds("audit syslogglobal") or cfg.binds("audit nslogglobal") or cfg.of("audit syslogaction") or cfg.of("audit nslogaction")):
        yield ctx.finding("MGMT-010", etype="audit syslogaction", name="")


@rule("MGMT-011", "low", "best-practice", [BSI_LOG], confidence="likely")
def no_ntp(ctx):
    if ctx.cfg.statements and not ctx.cfg.of("ntp server"):
        yield ctx.finding("MGMT-011", etype="ntp server", name="")


@rule("MGMT-012", "high", "compliance", [BSI_NET12, SDG])
def snmp_default(ctx):
    for e in ctx.ents("snmp community"):
        if e.name.lower() in DEFAULT_COMMUNITIES:
            yield ctx.finding("MGMT-012", e)


@rule("MGMT-013", "low", "best-practice", [BSI_NET12], confidence="likely")
def snmp_v3(ctx):
    if ctx.ents("snmp community") and not ctx.ents("snmp user"):
        yield ctx.finding("MGMT-013", etype="snmp community", name="")


@rule("MGMT-014", "low", "best-practice", [SDG], confidence="heuristic")
def http_hardening(ctx):
    hp = ctx.cfg.single("ns httpparam")
    if ctx.cfg.statements and ctx.cfg.nsip and (not hp or (hp.opt("dropinvalreqs") or "OFF").upper() != "ON"):
        yield ctx.finding("MGMT-014", hp, etype="ns httpparam", name="")
