"""From the entity model (parser.Config) to the topology graph.

Knoten = konfigurierte Objekte (vServer, Services, Policies, Zertifikate ...), Kanten = Bindungen /
references. The graph is the data basis for the HTML view *and* for check rules that
Beziehungen brauchen (verwaiste Objekte, tote Referenzen).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

from .parser import quote, Binding, Config, Entity, Statement, is_option

VSERVER_TYPES = ["lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "gslb vserver"]

KIND_BY_ETYPE = {
    "cs vserver": "csvs", "lb vserver": "lbvs", "vpn vserver": "gwvs",
    "authentication vserver": "aaavs", "gslb vserver": "gslbvs",
    "service": "svc", "servicegroup": "sg", "server": "server", "lb monitor": "monitor",
    "gslb service": "gslbsvc", "gslb servicegroup": "gslbsvc", "gslb site": "gslbsite",
    "ssl certkey": "cert", "ssl profile": "sslprofile",
    "authentication policylabel": "nflabel", "authentication loginschema": "schema",
    "authentication authnprofile": "authnprofile", "appfw profile": "appfwprof",
    "cs policylabel": "policylabel", "rewrite policylabel": "policylabel",
    "responder policylabel": "policylabel", "cache policylabel": "policylabel",
    "cmp policylabel": "policylabel", "appfw policylabel": "policylabel",
    "rewrite action": "action", "responder action": "action", "vpn sessionaction": "action",
    "vpn trafficaction": "action", "appflow action": "action", "audit syslogaction": "action",
    "tm sessionaction": "action", "tm trafficaction": "action", "audit nslogaction": "action", "ica action": "action",
    "ica accessprofile": "action", "dns action": "action", "transform profile": "action", "vpn clientlessaccessprofile": "action",
    "contentinspection action": "action", "appqoe action": "action", "feo action": "action", "spillover action": "action",
    "aaa group": "group",
    "ssl cipher": "cipher", "vlan": "vlan", "ns ip": "netip", "route": "route",
    "transform action": "action",
    "ns acl": "netrule", "ns acl6": "netrule", "ns pbr": "netrule", "ns pbr6": "netrule", "rnat": "netrule",
    "lb group": "lbgroup", "ssl crl": "crl", "ns trafficdomain": "td",
}

KIND_LABELS = {
    "device": "Device", "csvs": "CS vServer", "lbvs": "LB vServer", "gwvs": "Gateway vServer",
    "aaavs": "Auth vServer", "gslbvs": "GSLB vServer", "svc": "Service", "sg": "Service Group",
    "server": "Server", "monitor": "Monitor", "gslbsvc": "GSLB Service", "gslbsite": "GSLB Site",
    "cert": "Certificate", "sslprofile": "SSL profile", "nflabel": "nFactor Policy Label",
    "schema": "Login Schema", "authnprofile": "Authn profile", "appfwprof": "WAF profile",
    "policylabel": "Policy Label", "policy": "Policy", "authpol": "Auth policy",
    "authact": "Auth action", "action": "Action", "group": "AAA group", "cipher": "Cipher group", "vlan": "VLAN", "netip": "IP address (SNIP/VIP)", "route": "Route", "domain": "GSLB domain", "sta": "STA",
    "netrule": "Network rule (ACL/PBR/RNAT)", "lbgroup": "Persistency group", "crl": "CRL", "td": "Traffic domain",
    "missing": "Missing reference",
}

# Well-known ports -> service names (for labels on connections); proto-specific names for NetScaler service types.
PORT_NAMES = {
    "20": "FTP data", "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP", "88": "Kerberos",
    "110": "POP3", "123": "NTP", "135": "RPC", "143": "IMAP", "161": "SNMP", "162": "SNMP trap", "389": "LDAP", "443": "HTTPS",
    "445": "SMB", "465": "SMTPS", "514": "Syslog", "587": "SMTP submission", "636": "LDAPS", "993": "IMAPS", "995": "POP3S",
    "1433": "SQL Server", "1434": "SQL Browser", "1494": "ICA", "1521": "Oracle DB", "1812": "RADIUS", "1813": "RADIUS acct",
    "2598": "ICA session reliability", "3268": "LDAP GC", "3269": "LDAPS GC", "3306": "MySQL", "3389": "RDP", "5060": "SIP",
    "5061": "SIPS", "5432": "PostgreSQL", "6379": "Redis", "8080": "HTTP alt", "8443": "HTTPS alt", "9200": "Elasticsearch",
    "27017": "MongoDB",
}
PROTO_NAMES = {"HTTP": "HTTP", "SSL": "HTTPS", "SSL_BRIDGE": "HTTPS (bridge)", "DNS": "DNS", "DNS_TCP": "DNS (TCP)", "FTP": "FTP",
               "LDAP": "LDAP", "SSL_TCP": "TLS/TCP", "MSSQL": "SQL Server", "MYSQL": "MySQL", "RDP": "RDP", "SIP_UDP": "SIP",
               "SYSLOGTCP": "Syslog", "SYSLOGUDP": "Syslog", "RADIUS": "RADIUS", "NNTP": "NNTP", "SMPP": "SMPP", "ICA": "ICA"}


def comm_name(proto: str, port: str) -> str:
    """Human-readable service name for a protocol/port pair (e.g. 'HTTPS', 'SQL Server'); empty if unknown."""
    p = (proto or "").upper()
    if p in ("TCP", "UDP", "ANY", ""):
        return PORT_NAMES.get(str(port), "")
    return PROTO_NAMES.get(p) or PORT_NAMES.get(str(port), "")


ENCRYPTED_PROTOS = {"SSL", "SSL_TCP", "SSL_BRIDGE", "DTLS", "SSL_DIAMETER", "DIAMETER_SSL", "SSL_PUSH"}
# Assumption: well-known ports of TLS-wrapped services; a plain TCP service on these is treated as encrypted end to end.
ENCRYPTED_PORTS = {"443", "636", "3269", "465", "563", "585", "614", "853", "989", "990", "992", "993", "995", "8443"}


def is_plain(proto: str, port: str) -> bool:
    if (proto or "").upper() in ENCRYPTED_PROTOS or str(port) in ENCRYPTED_PORTS:
        return False
    return bool(proto or port)


def comm_label(proto: str, port: str) -> str:
    n = comm_name(proto, port)
    pt = f"{proto}/{port}" if proto and port else (port or proto or "")
    return f"{n} {port}".strip() if n and port else pt


BUILTIN_MONITORS = {
    "ping-default", "tcp-default", "arp", "nd6", "ping", "tcp", "http", "tcp-ecv", "http-ecv",
    "udp-ecv", "dns", "ftp", "tcps", "https", "imap", "pop3", "smtp", "ldap", "radius", "mysql",
    "mssql", "oracle", "sip-udp", "rtsp", "snmp", "nntp", "ftp-extended", "dynamic-default",
    "citrix-xd-ddc", "citrix-xml-service", "citrix-web-interface", "citrix-storefront",
    "citrix-wi-extended", "stasecure", "sta", "store-front", "xnc-ecv", "tcp-ecv-default",
}
KEYWORD_NAMES = {"NOPOLICY", "NOSCHEMA", "LSCHEMA_INT", "NO_DEFAULT", "NONE", "NEXT", "END", "USE_INVOCATION_RESULT"}
BUILTIN_CERTS = {"ns-server-certificate", "ns-sftrust-certificate"}

SECRET_OPTS = {
    "password", "passwd", "keyvalue", "ldapbinddnpassword", "radkey", "secret", "secretkey",
    "sharedsecret", "passphrase", "pempassword", "authpasswd", "privpasswd", "clientsecret",
    "encryptedpassword", "accountpassword", "tacacssecret", "sessionkey", "serversecret",
}

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_addressable(ip: str, port: str) -> bool:
    """A vServer listens somewhere unless address and port are both missing/zero (non-addressable, reachable only via other objects).
    A wildcard address with a port, or an address with a wildcard port, still listens (assumption: '*' and 0.0.0.0 mean wildcard)."""
    zero_ip = ip in ("", "0.0.0.0", "::", "*")
    zero_port = port in ("", "0")
    return not (zero_ip and zero_port)


def is_ip(s: str) -> bool:
    return bool(_IP.match(s or ""))


def redact(st: Statement | Binding, enabled: bool = True) -> str:
    """Line with masked secrets (passwords, keys); the original stays in the model."""
    if not enabled:
        return st.raw
    if isinstance(st, Binding):
        return st.raw
    toks = st.tokens
    secret_opt = any(is_option(t) and t.text[1:].lower() in SECRET_OPTS for t in toks)
    if not secret_opt and not (st.etype == "system user" and st.verb in ("add", "set") and len(st.args) > 1):
        return st.raw  # nothing to mask: the line exactly as in the config (escapes kept, usable for a batch import)
    out: list[str] = []
    mask_next = False
    for i, t in enumerate(toks):
        txt = quote(t.text) if t.quoted else t.text
        if is_option(t):
            mask_next = t.text[1:].lower() in SECRET_OPTS
            out.append(txt)
            continue
        if mask_next:
            out.append("***")
            continue
        out.append(txt)
    s = " ".join(out)
    # positional password: add/set system user <name> <password>
    if st.etype == "system user" and st.verb in ("add", "set") and len(st.args) > 1:
        s = s.replace(st.args[1], "***", 1)
    return s


@dataclass
class Node:
    id: str
    kind: str
    label: str
    etype: str = ""
    name: str = ""
    props: dict[str, str] = field(default_factory=dict)
    lines: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    group: str = ""
    entity: Entity | None = field(default=None, repr=False)


@dataclass
class Edge:
    source: str
    target: str
    type: str  # bind | route | auth | ssl | gslb | policy | nfactor | loop | doublehop | backup
    label: str = ""
    port: bool = False  # label shows protocol/port (always displayed)
    plain: bool = False  # connection carries unencrypted traffic (assumption based on protocol/port, see is_plain)
    line: int = 0  # config line that produced the edge (0 = derived, e.g. from IP matching)
    origin: str = ""  # code location that created the edge (debug mode: "which rule drew this line?")

    def __post_init__(self) -> None:
        if not self.origin:
            f = sys._getframe(1)
            while f is not None and f.f_code.co_name in ("__init__", "__post_init__", "_add_edge", "_ref"):
                f = f.f_back
            if f is not None:
                self.origin = f"{f.f_code.co_filename.replace(chr(92), '/').rsplit('/', 1)[-1]}:{f.f_code.co_name}:{f.f_lineno}"


class Graph:
    def __init__(self, cfg: Config, gid: str, do_redact: bool = True):
        self.cfg = cfg
        self.gid = gid
        self.redact = do_redact
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._edge_keys: set[tuple] = set()
        self.missing: list[dict] = []  # tote Referenzen
        self.unresolved: list[dict] = []  # URL targets (session action/STA) that do not match a vServer of this device
        self.referenced: set[tuple[str, str]] = set()  # (etype, name) that are bound/used somewhere
        self.frontends: list[dict] = []  # vServers with ip/port
        self.backends: list[dict] = []  # service/service group targets with ip/port
        self._stmt_idx: dict[tuple[str, str], list[Statement | Binding]] = {}
        self._expr_names: dict[str, list[str]] | None = None
        self._server_ip: dict[str, str] = {}
        self._build()

    # ---- Hilfen ---------------------------------------------------------------------------
    def nid(self, etype: str, name: str) -> str:
        return f"{self.gid}|{etype}|{name}"

    def node_for(self, etype: str, name: str) -> Node | None:
        return self.nodes.get(self.nid(etype, name))

    def device_node(self) -> Node:
        return self.nodes[f"{self.gid}|device|{self.cfg.name}"]

    def _kind(self, etype: str) -> str | None:
        k = KIND_BY_ETYPE.get(etype)
        if k:
            return k
        if etype.startswith("authentication ") and etype.endswith("policy"):
            return "authpol"
        if etype.startswith("authentication ") and (etype.endswith("action") or etype.endswith("idpprofile")):
            return "authact"
        if etype.endswith("policy") and etype not in ("policy",):
            return "policy"
        return None

    def _ensure(self, etype: str, name: str) -> str | None:
        ent = self.cfg.get(etype, name)
        if ent is None:
            return None
        nid = self.nid(etype, name)
        if nid in self.nodes:
            return nid
        kind = self._kind(etype)
        if not kind:
            return None
        n = Node(nid, kind, name, etype, name, group=self.gid, entity=ent)
        self.nodes[nid] = n
        self._fill(n)
        return nid

    def _add_edge(self, s: str | None, t: str | None, typ: str, label: str = "", line: int = 0) -> None:
        if not s or not t or s == t:
            return
        k = (s, t, typ, label)
        if k in self._edge_keys:
            return
        self._edge_keys.add(k)
        self.edges.append(Edge(s, t, typ, label, line=line))

    def _ref(self, src: str, etypes: list[str], name: str, typ: str, label: str = "",
             src_ent: tuple[str, str] | None = None, line: int = 0) -> str | None:
        """Reference to an object (one of the etypes). If it is missing, a 'missing' node is created."""
        if not name:
            return None
        for et in etypes:
            nid = self._ensure(et, name)
            if nid:
                self.referenced.add((et, name))
                self._add_edge(src, nid, typ, label, line)
                return nid
        # do not report built-in objects as missing
        if name.upper() in KEYWORD_NAMES or (len(etypes) > 5 and _builtin_policy(name)):
            return None
        if "lb monitor" in etypes and (name.lower() in BUILTIN_MONITORS or name.lower().endswith(("-ecv", "-default"))):
            return None
        if name in BUILTIN_CERTS and "ssl certkey" in etypes:
            return None
        if name.lower().startswith(("ns_default", "nstcp_", "nshttp_", "ns_nstcp", "ns_ssl", "default")):
            return None
        rt = "policy" if len(etypes) > 5 else etypes[0]
        mid = f"{self.gid}|missing|{rt}|{name}"
        if mid not in self.nodes:
            self.nodes[mid] = Node(mid, "missing", name, rt, name,
                                   props={"Expected type": rt}, group=self.gid)
        self._add_edge(src, mid, typ, label, line)
        se = src_ent or ("", "")
        self.missing.append({"src_etype": se[0], "src_name": se[1], "ref_type": rt,
                             "ref_name": name, "node": src, "line": line})
        return mid

    POLICY_TYPES = [
        "rewrite policy", "responder policy", "cs policy", "cache policy", "cmp policy", "appfw policy",
        "appflow policy", "transform policy", "feo policy", "filter policy", "tm trafficpolicy",
        "tm sessionpolicy", "vpn sessionpolicy", "vpn trafficpolicy", "vpn clientlessaccesspolicy",
        "authorization policy", "audit syslogpolicy", "audit nslogpolicy", "spillover policy",
        "authentication policy", "authentication ldappolicy", "authentication radiuspolicy",
        "authentication samlpolicy", "authentication samlidppolicy", "authentication webauthpolicy",
        "authentication certpolicy", "authentication negotiatepolicy", "authentication tacacspolicy",
        "authentication oauthidppolicy", "authentication localpolicy", "authentication noauthpolicy",
        "authentication loginschemapolicy", "authentication logoutpolicy", "authentication dfapolicy",
        "authentication emailaction_policy", "responder htmlpage_policy", "contentinspection policy",
        "dns policy", "dos policy", "stream policy_", "ica accessprofile_", "videooptimization detectionpolicy",
        "videooptimization pacingpolicy", "bot policy", "urlfiltering policy", "appqoe policy",
    ]
    LABEL_TYPES = ["authentication policylabel", "cs policylabel", "rewrite policylabel",
                   "responder policylabel", "cache policylabel", "cmp policylabel", "appfw policylabel"]

    def _policy_etypes(self) -> list[str]:
        have = [t for t in self.cfg.entities if self._kind(t) in ("policy", "authpol")]
        return have + [t for t in self.POLICY_TYPES if t not in have]

    # ---- Aufbau ---------------------------------------------------------------------------
    def _build(self) -> None:
        cfg = self.cfg
        for st in cfg.statements:
            if st.verb in ("add", "set", "bind", "unbind", "link") and st.args:
                self._stmt_idx.setdefault((st.etype, st.args[0]), []).append(st)
        for e in cfg.of("server").values():
            if len(e.args) > 1:
                self._server_ip[e.name] = e.args[1]
        # local DNS records of this appliance (add dns addRec <name> <ip> / addRec via cnameRec): the device resolves these itself
        self.dns_rec: dict[str, str] = {}
        cname: dict[str, str] = {}
        for st in cfg.statements:
            if st.verb == "add" and len(st.args) >= 2 and st.etype in ("dns addrec", "dns cnamerec"):
                (self.dns_rec if st.etype == "dns addrec" else cname)[st.args[0].lower().rstrip(".")] = st.args[1].lower().rstrip(".") if st.etype == "dns cnamerec" else st.args[1]
        for a, b in cname.items():
            if b in self.dns_rec and a not in self.dns_rec:
                self.dns_rec[a] = self.dns_rec[b]
        # Device node
        dev = Node(f"{self.gid}|device|{cfg.name}", "device", cfg.hostname or cfg.name, "device", cfg.name, group=self.gid)
        dev.props = {"File": cfg.name, "Version": f"{cfg.version or '?'} (build {cfg.build or '?'})",
                     "NSIP": cfg.nsip or "?", "Features": ", ".join(sorted(cfg.features)) or "-"}
        if cfg.modes:
            dev.props["Modes"] = ", ".join(sorted(cfg.modes))
        ns_srv = [st.args[0] for st in cfg.statements if st.verb == "add" and st.etype == "dns nameserver" and st.args]
        if ns_srv:
            dev.props["DNS name servers"] = ", ".join(ns_srv)
        sfx = [st.args[0] for st in cfg.statements if st.verb == "add" and st.etype == "dns suffix" and st.args]
        if sfx:
            dev.props["DNS suffixes"] = ", ".join(sfx)
        # local/authoritative DNS records (ADNS, DNS proxy); counted by type, root hints (default NS records of ".") left out
        recs: dict[str, int] = {}
        for st in cfg.statements:
            if st.verb == "add" and st.etype.startswith("dns ") and st.etype.endswith("rec") and st.args:
                if st.etype == "dns nsrec" and st.args[0] == ".":
                    continue
                if st.etype == "dns addrec" and ("." + st.args[0].lower().rstrip(".")).endswith(".root-servers.net"):
                    continue
                k = {"ADD": "A", "AAAA": "AAAA"}.get(st.etype[4:-3].upper(), st.etype[4:-3].upper())
                recs[k] = recs.get(k, 0) + 1
        if recs:
            dev.props["DNS records"] = ", ".join(f"{k} {v}" for k, v in sorted(recs.items()))
        parts = [st.args[0] for st in cfg.statements if st.verb == "add" and st.etype == "ns partition" and st.args]
        if parts:
            dev.props["Admin partitions"] = str(len(parts))
        self.nodes[dev.id] = dev
        for et, d in list(cfg.entities.items()):
            if et in ("server",) or self._kind(et) is None:
                continue
            for name, e in d.items():
                if e.implicit and et not in VSERVER_TYPES:
                    continue
                self._ensure(et, name)
        for b in cfg.bindings:
            try:
                self._bind(b)
            except Exception as exc:  # pragma: no cover - defensiv
                cfg.warnings.append(f"Zeile {b.line}: Bindung nicht ausgewertet ({exc})")
        for et in list(cfg.entities):
            for name, e in list(cfg.entities[et].items()):
                try:
                    self._entity_refs(et, name, e)
                except Exception as exc:  # pragma: no cover
                    cfg.warnings.append(f"{et} {name}: Referenzen nicht ausgewertet ({exc})")
        for crt, ca in cfg.links:  # link ssl certkey <cert> <issuer>
            a = self._ensure("ssl certkey", crt)
            if a:
                self._ref(a, ["ssl certkey"], ca, "ssl", "Issuer", ("ssl certkey", crt))
        self._ha_and_local_links()
        self._generic_refs()
        self._attach_roots()

    def _attach_roots(self) -> None:
        """Device -> entry points (objects without incoming edge): one tree per device (level 1 = devices)."""
        incoming = {e.target for e in self.edges}
        dev = self.device_node().id
        for nid, n in list(self.nodes.items()):
            if nid != dev and nid not in incoming:
                self._add_edge(dev, nid, "contains", "")

    def _fill(self, n: Node) -> None:
        e = n.entity
        assert e is not None
        p = n.props
        o = e.opt
        et = e.etype
        if et in VSERVER_TYPES:
            proto = e.args[1] if len(e.args) > 1 else ""
            ip = e.args[2] if len(e.args) > 2 else ""
            port = e.args[3] if len(e.args) > 3 else ""
            p["Protocol"] = proto
            if comm_name(proto, port):
                p["Service"] = comm_name(proto, port)
            if ip:
                p["IP:Port"] = f"{ip}:{port}" if port else ip
            p["Addressing"] = "addressable" if is_addressable(ip, port) else "non-addressable (reachable only through other vServers/policies)"
            if ip and port and is_ip(ip) and ip != "0.0.0.0" and port not in ("0", "*") and et != "gslb vserver":
                self.frontends.append({"node": n.id, "ip": ip, "port": port, "proto": proto, "etype": et, "name": e.name})
            st = o("state")
            p["Status"] = st or "ENABLED"
            for k, label in (("persistencetype", "Persistence"), ("lbmethod", "LB method"),
                             ("clttimeout", "Client timeout"), ("backupvserver", "Backup vServer"),
                             ("redirecturl", "Redirect URL"), ("httpsredirecturl", "HTTPS redirect"),
                             ("redirectfromport", "Redirect from port"), ("comment", "Comment"),
                             ("authentication", "Authentication"), ("authnvsname", "Auth vServer"),
                             ("authnprofile", "Authn profile"), ("icaonly", "ICA only"), ("dnsrecordtype", "DNS record"),
                             ("td", "Traffic domain"), ("listenpolicy", "Listen policy"), ("cacheable", "Cacheable (integrated caching)"),
                             ("somethod", "Spillover method"), ("sothreshold", "Spillover threshold"), ("sobackupaction", "Spillover backup action"),
                             ("sopersistence", "Spillover persistence"), ("toggleorder", "Priority order (toggle)"),
                             ("orderthreshold", "Priority order threshold (%)"), ("disableprimaryondown", "Disable primary when down"),
                             ("rhistate", "RHI state"), ("icmpvsrresponse", "ICMP response"), ("appflowlog", "AppFlow logging"),
                             ("tcpprofilename", "TCP profile"), ("httpprofilename", "HTTP profile"), ("netprofile", "Net profile"),
                             ("dnsprofilename", "DNS profile"), ("dbprofilename", "DB profile"), ("quicprofilename", "QUIC profile")):
                v = o(k)
                if v:
                    p[label] = v
        elif et in ("service", "servicegroup"):
            p["Protocol"] = e.args[2] if et == "service" and len(e.args) > 2 else (e.args[1] if len(e.args) > 1 else "")
            if comm_name(p["Protocol"], e.args[3] if et == "service" and len(e.args) > 3 else ""):
                p["Service"] = comm_name(p["Protocol"], e.args[3] if et == "service" and len(e.args) > 3 else "")
            if et == "service":
                p["Target"] = f"{e.args[1]}:{e.args[3]}" if len(e.args) > 3 else (e.args[1] if len(e.args) > 1 else "")
            for k, label in (("maxclient", "maxClient"), ("cip", "Client IP header"), ("usip", "USIP"), ("state", "Status"), ("comment", "Comment"),
                             ("td", "Traffic domain"), ("cacheable", "Cacheable (integrated caching)"), ("appflowlog", "AppFlow logging"),
                             ("tcpprofilename", "TCP profile"), ("httpprofilename", "HTTP profile"), ("netprofile", "Net profile")):
                if o(k):
                    p[label] = o(k)
        elif et == "ns ip":
            p["Address"] = e.args[0] if e.args else ""
            if len(e.args) > 1:
                p["Netmask"] = e.args[1]
            for k, label in (("type", "Type"), ("vserver", "vServer"), ("mgmtaccess", "Management access"), ("ssh", "SSH"), ("telnet", "Telnet"),
                             ("gui", "GUI"), ("restrictaccess", "Restrict access"), ("hostroute", "Host route")):
                if o(k):
                    p[label] = o(k)
        elif et == "vlan":
            p["ID"] = e.args[0] if e.args else ""
            if o("aliasname"):
                p["Alias"] = o("aliasname")
        elif et == "route":
            p["Network"] = " ".join(e.args[:2])
            if len(e.args) > 2:
                p["Gateway"] = e.args[2]
        elif et == "ssl cipher":
            p["Ciphers bound"] = str(sum(1 for b in self.cfg.bindings if b.etype == "ssl cipher" and b.owner == e.name))
        elif et == "server":
            p["Address"] = e.args[1] if len(e.args) > 1 else ""
            if o("state"):
                p["Status"] = o("state")
            if o("td"):
                p["Traffic domain"] = o("td")
        elif et in ("ns acl", "ns acl6", "ns pbr", "ns pbr6"):
            p["Type"] = {"ns acl": "ACL (IPv4)", "ns acl6": "ACL (IPv6)", "ns pbr": "PBR (IPv4)", "ns pbr6": "PBR (IPv6)"}[et]
            if len(e.args) > 1:
                p["Action"] = e.args[1]
            for k, label in (("srcip", "Source IP"), ("srcipval", "Source IP"), ("destip", "Destination IP"), ("destipval", "Destination IP"),
                             ("srcport", "Source port"), ("srcportval", "Source port"), ("destport", "Destination port"),
                             ("destportval", "Destination port"), ("protocol", "Protocol"), ("nexthop", "Next hop"), ("nexthopval", "Next hop"),
                             ("vlan", "VLAN"), ("interface", "Interface"), ("priority", "Priority"), ("state", "Status"), ("td", "Traffic domain")):
                v = o(k)
                if v and label not in p:
                    p[label] = v
        elif et == "rnat":
            p["Type"] = "RNAT"
            for k, label in (("network", "Network"), ("netmask", "Netmask"), ("aclname", "ACL"), ("td", "Traffic domain")):
                if o(k):
                    p[label] = o(k)
            ips = [b.opt("natip") or (b.args[0] if b.args else "") for b in self.cfg.bindings if b.etype == "rnat" and b.owner == e.name]
            if [x for x in ips if x]:
                p["NAT IP"] = ", ".join(x for x in ips if x)
        elif et == "lb group":
            for k, label in (("persistencetype", "Persistence"), ("timeout", "Timeout"), ("cookiename", "Cookie"), ("usevserverpersistency", "Use vServer persistence")):
                if o(k):
                    p[label] = o(k)
        elif et == "ssl crl":
            for k, label in (("cacert", "CA certificate"), ("refresh", "Refresh"), ("method", "Method"), ("inform", "Format")):
                if o(k):
                    p[label] = o(k)
        elif et == "ns trafficdomain":
            p["ID"] = e.args[0] if e.args else ""
            if o("aliasname"):
                p["Alias"] = o("aliasname")
        elif et == "lb monitor":
            p["Type"] = e.args[1] if len(e.args) > 1 else ""
            for k, label in (("interval", "Interval"), ("resptimeout", "Timeout"), ("secure", "TLS"), ("send", "Send"), ("recv", "Recv"), ("httprequest", "HTTP request"), ("respcode", "Response code")):
                if o(k):
                    p[label] = o(k)
        elif et == "ssl certkey":
            for k, label in (("cert", "Certificate"), ("key", "Key"), ("expirymonitor", "Expiry monitor"), ("notificationperiod", "Notification (days)")):
                if o(k):
                    p[label] = o(k)
        elif et.startswith("gslb "):
            p["Details"] = " ".join(e.args[1:])
            for k, label in (("sitename", "Site"), ("publicip", "Public IP"), ("sitepersistence", "Site persistence")):
                if o(k):
                    p[label] = o(k)
        elif self._kind(et) in ("policy", "authpol"):
            rule = o("rule") or (e.args[1] if len(e.args) > 1 else "")
            act = o("action") or o("reqaction") or (e.args[2] if len(e.args) > 2 else "")
            if rule:
                p["Rule"] = rule[:300]
            if act:
                p["Action"] = act
            if rule and "IPREP" in rule.upper():
                p["IP reputation"] = "rule uses IPREP"
            uses = [lab for rx, lab in EXPR_FEATURES if rule and re.search(rx, rule, re.I)]
            if uses:
                p["Uses"] = ", ".join(uses)
        elif self._kind(et) == "authact":
            for k, label in (("serverip", "Server IP"), ("serverport", "Port"), ("sectype", "SecType"), ("ldapbase", "Base DN"), ("authtimeout", "Timeout")):
                if o(k):
                    p[label] = o(k)
        n.lines = self._lines_for(e)
        for kk in ("comment",):
            pass

    def _lines_for(self, e: Entity) -> list[dict]:
        rel = {"lb vserver": ["ssl vserver"], "cs vserver": ["ssl vserver"], "vpn vserver": ["ssl vserver"],
               "authentication vserver": ["ssl vserver"], "gslb vserver": ["ssl vserver"],
               "service": ["ssl service"], "servicegroup": ["ssl servicegroup"], "ssl profile": []}
        out: list[dict] = []
        seen: set[int] = set()
        keys = [(et, e.name) for et in [e.etype] + rel.get(e.etype, [])]
        done: set[tuple[str, str]] = set()
        while keys:  # own statements, then supporting ones (cs action of a cs policy, objects used in expressions)
            key = keys.pop(0)
            if key in done:
                continue
            done.add(key)
            for st in self._stmt_idx.get(key, []):
                if id(st) in seen:
                    continue
                seen.add(id(st))
                out.append({"file": st.file, "line": st.line, "text": redact(st, self.redact)})
                keys.extend(k for k in self._supporting(st) if k not in done)
        out.sort(key=lambda x: x["line"])
        return out[:5000]  # complete for the config export (large WAF profiles); the details panel shows them in a scroll box

    # objects that are no nodes of their own but are needed to recreate a statement elsewhere (config export)
    EXPR_ETYPES = ("policy patset", "policy dataset", "policy stringmap", "policy httpcallout", "policy expression",
                   "ns variable", "ns assignment", "policy map", "ns limitidentifier", "stream identifier", "audit messageaction")
    # referenced by name in an option value (not inside an expression); measured gaps of the export on real configs
    SUPPORT_ETYPES = EXPR_ETYPES + (
        "ns tcpprofile", "ns httpprofile", "netprofile", "dns profile", "analytics profile", "lb profile", "ns icmpprofile",
        "cache contentgroup", "cache selector", "appflow collector", "stream selector", "ns limitselector", "lb metrictable",
        "ssl ocspresponder", "ssl action", "ssl crl", "bot profile", "bot signature",
        "vpn portaltheme", "vpn url", "vpn urlaction", "vpn intranetapplication", "vpn nexthopserver", "vpn formssoaction",
        "vpn eula", "vpn alwaysonprofile", "vpn pcoipprofile", "vpn pcoipvserverprofile",
        "rdp clientprofile", "rdp serverprofile", "tm formssoaction", "tm samlssoprofile", "tm sessionparameter",
        "aaa kcdaccount", "aaa preauthenticationaction", "authentication pushservice")

    def _support_index(self) -> dict[str, list[str]]:
        if self._expr_names is None:
            self._expr_names = {}
            for (et, nm) in self._stmt_idx:
                if et in self.SUPPORT_ETYPES and len(nm) >= 2:
                    self._expr_names.setdefault(nm, []).append(et)
        return self._expr_names

    def _supporting(self, st) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if st.etype == "cs policy" and st.verb == "add":
            act = st.opt("action")
            if act and ("cs action", act) in self._stmt_idx:
                out.append(("cs action", act))
        toks = getattr(st, "tokens", [])[1:]
        exprs = [t.text for t in toks if t.quoted and ("(" in t.text or "." in t.text or "$" in t.text)]
        plain = [t.text for t in toks if not t.quoted and not is_option(t)]
        if not exprs and not plain:
            return out
        idx = self._support_index()
        own = st.args[0] if st.args else None
        for tok in plain:  # option values / positional arguments that name a supporting object
            if tok != own:
                for et in idx.get(tok, []):
                    if et != st.etype:
                        out.append((et, tok))
        for txt in exprs:
            for tok in set(re.findall(r"[$\w.-]+", txt)):
                for et in idx.get(tok.lstrip("$"), []) + idx.get(tok, []):
                    if et in self.EXPR_ETYPES:
                        out.append((et, tok.lstrip("$") if (et, tok.lstrip("$")) in self._stmt_idx else tok))
        return out

    # ---- Bindungen ------------------------------------------------------------------------
    def _vs_node(self, name: str, types: list[str] | None = None) -> tuple[str | None, str]:
        for et in (types or VSERVER_TYPES):
            nid = self._ensure(et, name)
            if nid:
                return nid, et
        return None, ""

    def _prio(self, b: Binding) -> str:
        pr = b.opt("priority")
        g = b.opt("gotopriorityexpression")
        return f"Prio {pr}" if pr and not g else (f"Prio {pr} → {g}" if pr else "")

    @staticmethod
    def _order(b: Binding) -> str:
        """Edge label for a service binding: priority order (priority load balancing) and weight."""
        parts = []
        if b.opt("order"):
            parts.append(f"Order {b.opt('order')}")
        if b.opt("weight") and b.opt("weight") != "1":
            parts.append(f"Weight {b.opt('weight')}")
        return ", ".join(parts)

    def _bind(self, b: Binding) -> None:
        et, owner = b.etype, b.owner
        if et in ("lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "gslb vserver"):
            src = self._ensure(et, owner)
            if not src:
                return
            ctx = (et, owner)
            if b.args and not is_option_like(b.args[0]):
                tgt = b.args[0]
                if et == "lb vserver":
                    self._ref(src, ["service", "servicegroup"], tgt, "bind", self._order(b), ctx, b.line)
                elif et == "cs vserver":
                    self._ref(src, ["lb vserver"], tgt, "route", "Default", ctx, b.line)
            for key, etypes, typ in (("servicename", ["service", "servicegroup", "gslb service", "gslb servicegroup"], "bind"),
                                     ("lbvserver", ["lb vserver"], "route"),
                                     ("targetlbvserver", ["lb vserver"], "route"),
                                     ("targetvserver", ["lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "gslb vserver"], "route"),
                                     ("staserver", None, "bind"),
                                     ("domainname", None, "gslb"),
                                     ("authnprofile", ["authentication authnprofile"], "auth"),
                                     ("urlname", ["vpn url"], "bind"),
                                     ("intranetapplication", ["vpn intranetapplication"], "bind")):
                v = b.opt(key)
                if not v:
                    continue
                if key == "staserver":
                    sid = f"{self.gid}|sta|{v}"
                    if sid not in self.nodes:
                        self.nodes[sid] = Node(sid, "sta", v, "sta", v, props={"URL": v}, group=self.gid)
                    self._add_edge(src, sid, "bind", "STA")
                elif key == "domainname":
                    did = f"{self.gid}|domain|{v}"
                    if did not in self.nodes:
                        self.nodes[did] = Node(did, "domain", v, "domain", v, props={"TTL": b.opt("ttl") or ""}, group=self.gid)
                    self._add_edge(src, did, "gslb", "Domain")
                elif key in ("urlname", "intranetapplication") and self.cfg.get(etypes[0], v) is not None:
                    self.referenced.add((etypes[0], v))
                else:
                    self._ref(src, etypes, v, typ, "", ctx, b.line)
            pol = b.opt("policyname") or b.opt("policy")
            if pol:
                label = self._prio(b)
                lt, lab = invoke_target(b)
                nid = self._ref(src, self._policy_etypes() + self.LABEL_TYPES, pol, "policy", label, ctx, b.line)
                if nid and et == "cs vserver" and b.opt("targetlbvserver"):
                    self._ref(nid, ["lb vserver"], b.opt("targetlbvserver"), "route", "Target", ctx, b.line)
                if lab and lt in VS_LABEL_TYPES:
                    self._ref(nid or src, ["lb vserver", "cs vserver"], lab, "route", "invoke " + lt, ctx, b.line)
                elif lab:
                    self._ref(src, self.LABEL_TYPES, lab, "nfactor" if et == "authentication vserver" else "policy", label or "Label", ctx, b.line)
            nf = b.opt("nextfactor")
            if nf:
                self._ref(self._ref_or_none(et, owner, pol), ["authentication policylabel"], nf, "nfactor", "nextFactor", ctx, b.line)
        elif et in ("service", "servicegroup"):
            src = self._ensure(et, owner)
            if not src:
                return
            ctx = (et, owner)
            if et == "servicegroup" and b.args and not is_option_like(b.args[0]):
                srv = b.args[0]
                port = b.args[1] if len(b.args) > 1 else ""
                sid = self._server_node(srv, ctx)
                self._add_edge(src, sid, "bind", comm_label(ent_proto(self.cfg.get("servicegroup", owner)), port) if port else "")
                ent = self.cfg.get("servicegroup", owner)
                ip = self._server_ip.get(srv, srv)
                self.backends.append({"node": src, "server_node": sid, "host": ip, "port": port,
                                      "proto": ent.args[1] if ent and len(ent.args) > 1 else "", "name": owner, "etype": et})
            m = b.opt("monitorname")
            if m:
                self._ref(src, ["lb monitor"], m, "bind", "Monitor", ctx, b.line)
        elif et == "lb monitor":
            mon = self._ensure("lb monitor", owner)
            for a in b.args:  # bind lb monitor <monitor> <service|servicegroup|vserver>
                v, _ = self._vs_node(a, ["service", "servicegroup", "lb vserver"])
                if v and mon:
                    self.referenced.add(("lb monitor", owner))
                    self._add_edge(v, mon, "bind", "Monitor")
        elif et in ("ssl vserver", "ssl service", "ssl servicegroup", "ssl profile"):
            if et == "ssl vserver":
                src, _ = self._vs_node(owner)
            else:
                src = self._ensure(et.replace("ssl ", "") if et != "ssl profile" else et, owner)
                if not src and et == "ssl service" and owner.lower().startswith(INTERNAL_SERVICES):
                    src = self.device_node().id  # internal management/RPC service: the certificate is used by the appliance itself
            if not src:
                return
            sp = b.opt("policyname")
            if sp:
                self._ref(src, self._policy_etypes() + ["ssl policy"], sp, "policy", self._prio(b), (et, owner), b.line)
            cn = b.opt("ciphername")
            if cn and self.cfg.get("ssl cipher", cn):
                self._ref(src, ["ssl cipher"], cn, "ssl", "Ciphers", (et, owner), b.line)
            ck = b.opt("certkeyname")
            if ck:
                lab = "CA" if b.opt("ca") else ("SNI" if b.opt("snicert") else ("Client-Cert" if et != "ssl vserver" else ""))
                self._ref(src, ["ssl certkey"], ck, "ssl", lab, (et, owner), b.line)
        elif et == "authentication policylabel":
            src = self._ensure(et, owner)
            if not src:
                return
            pol = b.opt("policyname")
            if pol:
                nid = self._ref(src, self._policy_etypes(), pol, "nfactor", self._prio(b), (et, owner), b.line)
                nf = b.opt("nextfactor")
                if nf and nid:
                    self._ref(nid, ["authentication policylabel"], nf, "nfactor", "nextFactor", (et, owner), b.line)
        elif et.endswith("policylabel") and et != "authentication policylabel":
            src = self._ensure(et, owner)
            pol = b.opt("policyname") or (b.args[0] if b.args and not is_option_like(b.args[0]) else None)
            if src and pol:
                nid = self._ref(src, self._policy_etypes(), pol, "policy", self._prio(b), (et, owner), b.line)
                tv = b.opt("targetvserver") or b.opt("targetlbvserver")
                if tv and nid:  # bind cs policylabel <label> <policy> <prio> -targetVserver <vserver>
                    self._ref(nid, ["lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "gslb vserver"], tv, "route", "Target", (et, owner), b.line)
                lt, lab = invoke_target(b)
                if lab and lt in VS_LABEL_TYPES:
                    self._ref(nid or src, ["lb vserver", "cs vserver"], lab, "route", "invoke " + lt, (et, owner), b.line)
                elif lab:
                    self._ref(nid or src, self.LABEL_TYPES, lab, "policy", "Label", (et, owner), b.line)
        elif et == "dns nameserver":
            # an LB vServer used as DNS name server is used globally (assumption: the first argument names it)
            nm = b.args[0] if b.args else owner
            v, _ = self._vs_node(nm, ["lb vserver"])
            if v:
                self.referenced.add(("lb vserver", nm))
                self._add_edge(self.device_node().id, v, "bind", "DNS name server")
        elif et == "vlan":
            src = self._ensure(et, owner)
            ipv = b.opts.get("ipaddress") or []
            if src and ipv:
                self._ref(src, ["ns ip"], ipv[0], "network", "IP", (et, owner), b.line)
        elif et == "aaa group":
            src = self._ensure(et, owner)
            pol = b.opt("policy") or b.opt("policyname")
            if src and pol:
                self._ref(src, self._policy_etypes(), pol, "policy", self._prio(b), (et, owner), b.line)
            elif pol:  # group without 'add aaa group': policy still counts as used
                for t in self._policy_etypes():
                    if self.cfg.get(t, pol):
                        self.referenced.add((t, pol))
        elif et in ("aaa user", "vpn user", "vpn group", "system group", "system user"):
            # Users are deliberately not drawn (personal data); bound policies count as used.
            pol = b.opt("policy") or b.opt("policyname")
            if pol:
                for t in self._policy_etypes():
                    if self.cfg.get(t, pol):
                        self.referenced.add((t, pol))
        elif et == "lb group":
            # drawn from the vServer to its persistency group, so exporting a vServer brings the group along
            for a in [x for x in b.args if not is_option_like(x)] + ([b.opt("vservername")] if b.opt("vservername") else []):
                v, _ = self._vs_node(a, ["lb vserver"])
                if v:
                    self._ref(v, ["lb group"], owner, "bind", "Persistency group", (et, owner), b.line)
        elif et == "ns trafficdomain":
            # Assumption (syntax): bind ns trafficdomain <id> -vlan <id> | -vServer <name> | -vxlan <id>
            src = self._ensure(et, owner)
            if src:
                for v in b.opts.get("vlan") or []:
                    self._ref(src, ["vlan"], v, "network", "VLAN", (et, owner), b.line)
                for v in b.opts.get("vserver") or []:
                    self._ref(src, list(VSERVER_TYPES), v, "network", "vServer", (et, owner), b.line)
        elif et.endswith("global") or et == "system global":
            dev = self.device_node().id
            pol = b.opt("policyname") or (b.args[0] if b.args else "")
            nid = None
            if pol and not is_option_like(pol):
                nid = self._ref(dev, self._policy_etypes(), pol, "policy", f"global {et.split()[0]}", (et, ""), b.line)
            lt, lab = invoke_target(b)
            if lab and lt in VS_LABEL_TYPES:
                self._ref(nid or dev, ["lb vserver", "cs vserver"], lab, "route", "invoke " + lt, (et, ""), b.line)
            elif lab:
                self._ref(nid or dev, self.LABEL_TYPES, lab, "policy", "Label", (et, ""), b.line)
            sta = b.opt("staserver")
            if sta:  # bind vpn global -staServer <url>: STA used by every gateway
                sid = f"{self.gid}|sta|{sta}"
                if sid not in self.nodes:
                    self.nodes[sid] = Node(sid, "sta", sta, "sta", sta, props={"URL": sta, "Scope": "global"}, group=self.gid)
                self._add_edge(dev, sid, "bind", "STA (global)")

    # ---- Citrix Gateway view -----------------------------------------------------------------
    def gateway_view(self) -> dict:
        """Per gateway vServer: access profiles (session policies), ICA (STA, StoreFront), VPN (intranet applications, IPs,
        traffic policies), clientless/portal (bookmarks, theme, EULA), RDP/PCoIP, authorization and AAA groups.
        Global bindings (bind vpn global) and AAA groups apply to every gateway of the device. Used by the Gateway tab."""
        cfg = self.cfg
        if not cfg.of("vpn vserver"):
            return {}

        def num(x):
            try:
                return float(x or "")
            except ValueError:
                return 1e12

        names: dict[str, str] = {}

        def opts(e: Entity | None) -> dict:
            if e is None:
                return {}
            self._opt_names(e, names)
            return {k: (" ".join(v) if v else "true") for k, v in e.opts.items() if k not in SECRET_OPTS}

        def node(et: str, name: str) -> str:
            nid = self.nid(et, name)
            return nid if nid in self.nodes else ""

        def preauth(name: str, b: Binding) -> dict | None:
            e = cfg.get("aaa preauthenticationpolicy", name)
            if e is None:
                return None
            rule = e.opt("rule") or (e.args[1] if len(e.args) > 1 and not is_option_like(e.args[1]) else "")
            act = e.opt("reqaction") or (e.args[2] if len(e.args) > 2 and not is_option_like(e.args[2]) else "")
            ae = cfg.get("aaa preauthenticationaction", act) if act else None
            return {"policy": name, "node": node("aaa preauthenticationpolicy", name), "prio": b.opt("priority") or "", "rule": rule[:300],
                    "action": act, "action_node": node("aaa preauthenticationaction", act) if ae is not None else "",
                    "verdict": (ae.args[1] if ae is not None and len(ae.args) > 1 else ""), "opts": opts(ae)}

        def pol(name: str, b: Binding | None = None) -> dict | None:
            for et in ("vpn sessionpolicy", "vpn trafficpolicy", "authorization policy", "vpn clientlessaccesspolicy", "ica policy",
                       "tm sessionpolicy", "tm trafficpolicy", "vpn urlpolicy", "rewrite policy", "responder policy", "cache policy",
                       "cmp policy", "audit syslogpolicy", "audit nslogpolicy", "appflow policy", "vpn eula"):
                e = cfg.get(et, name)
                if e is None:
                    continue
                rule = e.opt("rule") or (e.args[1] if len(e.args) > 1 and not is_option_like(e.args[1]) else "")
                act = e.opt("action") or e.opt("profilename") or (e.args[2] if len(e.args) > 2 and not is_option_like(e.args[2]) else "")
                aet = {"vpn sessionpolicy": "vpn sessionaction", "vpn trafficpolicy": "vpn trafficaction", "ica policy": "ica action",
                       "vpn clientlessaccesspolicy": "vpn clientlessaccessprofile", "tm sessionpolicy": "tm sessionaction",
                       "tm trafficpolicy": "tm trafficaction", "vpn urlpolicy": "vpn urlaction"}.get(et, et.replace("policy", "action"))
                ae = cfg.get(aet, act) if act else None
                r = {"policy": name, "etype": et, "node": node(et, name), "prio": (b.opt("priority") if b else "") or "",
                     "rule": rule[:300], "action": act, "action_node": node(aet, act) if ae is not None else "", "opts": opts(ae),
                     "type": (b.opt("type") or "") if b else ""}
                if et == "ica policy" and ae is not None and ae.opt("accessprofilename"):
                    r["profile"] = ae.opt("accessprofilename")
                    r["profile_opts"] = opts(cfg.get("ica accessprofile", ae.opt("accessprofilename")))
                return r
            return None

        def url(name: str) -> dict:
            e = cfg.get("vpn url", name)
            a = e.args if e is not None else []
            return {"name": name, "node": node("vpn url", name), "label": a[1] if len(a) > 1 else "", "url": a[2] if len(a) > 2 else "",
                    "clientless": (e.opt("clientlessaccess") or "") if e is not None else "", "missing": e is None}

        def app(name: str) -> dict:
            e = cfg.get("vpn intranetapplication", name)
            a = e.args if e is not None else []
            return {"name": name, "node": node("vpn intranetapplication", name), "proto": a[1] if len(a) > 1 else "",
                    "dest": a[2] if len(a) > 2 else "", "port": (e.opt("destport") or "") if e is not None else "",
                    "mode": (e.opt("interception") or "") if e is not None else "", "missing": e is None}

        def collect(binds: list[Binding]) -> dict:
            out = {"policies": [], "sta": [], "bookmarks": [], "apps": [], "ips": [], "theme": "", "eula": [], "nexthop": [], "other": [], "preauth": []}
            for b in binds:
                p = b.opt("policy") or b.opt("policyname")
                if p:
                    r = pol(p, b)
                    pa = None if r else preauth(p, b)
                    if pa:
                        out["preauth"].append(pa)
                    elif r:
                        out["policies"].append(r)
                    elif p.startswith("_") and not any(cfg.get(t, p) for t in cfg.entities):
                        pass  # built-in policies (e.g. the default caching policies the gateway binds), not part of the config
                    elif not any(cfg.get(t, p) for t in cfg.entities if self._kind(t) == "authpol"):  # auth: nFactor tab
                        out["other"].append({"policy": p, "prio": b.opt("priority") or "", "node": next((self.nid(t, p) for t in cfg.entities if cfg.get(t, p) is not None and self.nid(t, p) in self.nodes), "")})
                for k, v in b.opts.items():
                    val = " ".join(v) if isinstance(v, list) else str(v)
                    if k == "staserver":
                        out["sta"].append({"url": val, "addresstype": b.opt("staaddresstype") or ""})
                    elif k == "urlname":
                        out["bookmarks"].append(url(val))
                    elif k == "intranetapplication":
                        out["apps"].append(app(val))
                    elif k == "intranetip":
                        out["ips"].append(" ".join(v) if isinstance(v, list) else val)
                    elif k == "portaltheme":
                        out["theme"] = val
                    elif k == "eula":
                        out["eula"].append(val)
                    elif k == "nexthopserver":
                        e = cfg.get("vpn nexthopserver", val)
                        out["nexthop"].append({"name": val, "target": " ".join(e.args[1:3]) if e is not None else ""})
            out["policies"].sort(key=lambda r: (r["etype"], num(r["prio"])))
            return out

        gws = []
        for name, e in cfg.of("vpn vserver").items():
            src = self.nid("vpn vserver", name)
            if src not in self.nodes:
                continue
            g = {"name": name, "node": src, "proto": e.args[1] if len(e.args) > 1 else "", "ip": e.args[2] if len(e.args) > 2 else "",
                 "port": e.args[3] if len(e.args) > 3 else "", "opts": opts(e), "clientcert": self.client_cert(name),
                 **collect(cfg.binds("vpn vserver", name))}
            gws.append(g)
        groups = []
        for gname in sorted({b.owner for b in cfg.binds("aaa group")} | set(cfg.of("aaa group"))):
            c = collect(cfg.binds("aaa group", gname))
            if any(c[k] for k in ("policies", "bookmarks", "apps", "ips")):
                groups.append({"name": gname, "node": node("aaa group", gname), **c})
        vp = cfg.get("vpn parameter", "")
        out = {"gateways": gws, "global": {**collect(cfg.binds("vpn global")), "params": opts(vp)}, "groups": groups,
               "rdp": {n: opts(x) for n, x in cfg.of("rdp clientprofile").items()},
               "rdp_server": {n: opts(x) for n, x in cfg.of("rdp serverprofile").items()}}
        out["names"] = names
        return out

    @staticmethod
    def _opt_names(e: Entity, names: dict) -> None:
        """Option names as written in the config (the model keeps them lower-cased), for display."""
        for st in e.stmts:
            for tok in st.tokens:
                if not tok.quoted and tok.text.startswith("-") and len(tok.text) > 1 and tok.text[1].isalpha():
                    names.setdefault(tok.text[1:].lower(), tok.text[1:])

    def client_cert(self, vs_name: str) -> dict:
        """Client certificate authentication of a vServer (set ssl vserver -clientAuth / SSL profile) and its CA certificates."""
        sv = self.cfg.get("ssl vserver", vs_name)
        if sv is None:
            return {}
        src, via = sv, ""
        if (sv.opt("clientauth") or "").upper() != "ENABLED" and sv.opt("sslprofile"):
            pr = self.cfg.get("ssl profile", sv.opt("sslprofile"))
            if pr is not None and (pr.opt("clientauth") or "").upper() == "ENABLED":
                src, via = pr, sv.opt("sslprofile")
        if (src.opt("clientauth") or "").upper() != "ENABLED":
            return {}
        ca = [b.opt("certkeyname") for b in self.cfg.binds("ssl vserver", vs_name) if "ca" in b.opts and b.opt("certkeyname")]
        return {"mode": src.opt("clientcert") or "", "profile": via, "ca": ca,
                "ca_nodes": [self.nid("ssl certkey", c) for c in ca if self.nid("ssl certkey", c) in self.nodes]}

    # ---- nFactor / authentication flow ------------------------------------------------------
    def auth_flows(self) -> dict:
        """Authentication flow per entry point: factors (auth vServer, policy labels, classic gateway binds) with their
        policies in priority order, the action type, the login schema and the next factor. Used by the nFactor view."""
        cfg = self.cfg
        authpol_types = [t for t in cfg.entities if self._kind(t) == "authpol"]
        authact_types = [t for t in cfg.entities if self._kind(t) == "authact"]
        names: dict[str, str] = {}

        def num(x: str | None) -> float:
            try:
                return float(x or "")
            except ValueError:
                return 1e12

        def schema_info(name: str | None) -> dict | None:
            if not name:
                return None
            if name.upper() in ("LSCHEMA_INT", "NOSCHEMA"):
                return {"name": name, "file": "", "builtin": True}
            e = cfg.get("authentication loginschema", name)
            f = (e.opt("authenticationschema") or "") if e else ""
            return {"name": name, "file": f.replace("\\", "/").rsplit("/", 1)[-1], "node": self.nid("authentication loginschema", name) if e else None,
                    "missing": e is None}

        def action_info(pet: str, pe: Entity) -> dict:
            act = pe.opt("action") or pe.opt("reqaction") or (pe.args[2] if len(pe.args) > 2 and not is_option_like(pe.args[2]) else "")
            if not act:
                kind = {"authentication localpolicy": "LOCAL", "authentication noauthpolicy": "NOAUTH"}.get(pet, "")
                return {"name": "", "type": kind}
            if ("ns assignment", act) in self._stmt_idx:
                return {"name": act, "type": "ASSIGNMENT"}
            cands = [pet[: -len("policy")] + "action", pet[: -len("policy")] + "profile"] if pet != "authentication policy" else []
            for t in cands + authact_types:
                if cfg.get(t, act):
                    base = t.split(" ", 1)[1]
                    typ = AUTH_TYPE_LABELS.get(base, base.replace("action", "").replace("profile", " profile").strip().upper())
                    ae = cfg.get(t, act)
                    self._opt_names(ae, names)
                    return {"name": act, "type": typ, "etype": t, "node": self.nid(t, act),
                            "opts": {k: (" ".join(v) if v else "true") for k, v in ae.opts.items() if k not in SECRET_OPTS}}
            if re.fullmatch(r"[A-Z_]+", act):
                return {"name": act, "type": act}  # built-in (NO_AUTHN, ...)
            return {"name": act, "type": "", "missing": True}

        def policy_row(b: Binding, pol: str, secondary: str = "") -> dict | None:
            pet = next((t for t in authpol_types if cfg.get(t, pol)), None)
            if not pet:
                return None
            pe = cfg.get(pet, pol)
            rule = pe.opt("rule") or (pe.args[1] if len(pe.args) > 1 and not is_option_like(pe.args[1]) else "")
            nf = b.opt("nextfactor")
            return {"policy": pol, "etype": pet, "node": self.nid(pet, pol), "prio": b.opt("priority") or "",
                    "goto": (b.opt("gotopriorityexpression") or "").upper(), "rule": rule[:400],
                    "next": nf or "", "next_id": self.nid("authentication policylabel", nf) if nf and cfg.get("authentication policylabel", nf) else "",
                    "action": action_info(pet, pe), "line": b.line, **({"role": secondary} if secondary else {})}

        factors: dict[str, dict] = {}
        for name in cfg.of("authentication vserver"):
            fid = self.nid("authentication vserver", name)
            rows, schemas = [], []
            for b in cfg.binds("authentication vserver", name):
                pol = b.opt("policy") or b.opt("policyname")
                if not pol:
                    continue
                if cfg.get("authentication loginschemapolicy", pol):
                    le = cfg.get("authentication loginschemapolicy", pol)
                    sch = schema_info(le.opt("action") or (le.args[2] if len(le.args) > 2 else None))
                    if sch:
                        schemas.append({**sch, "policy": pol, "prio": b.opt("priority") or "",
                                        "rule": (le.opt("rule") or (le.args[1] if len(le.args) > 1 else ""))[:200]})
                    continue
                r = policy_row(b, pol)
                if r:
                    rows.append(r)
            rows.sort(key=lambda r: num(r["prio"]))
            schemas.sort(key=lambda r: num(r["prio"]))
            factors[fid] = {"id": fid, "type": "vserver", "etype": "authentication vserver", "name": name, "node": fid, "schemas": schemas, "rows": rows}
        for name, e in cfg.of("authentication policylabel").items():
            fid = self.nid("authentication policylabel", name)
            ls = e.opt("loginschema") or (e.args[1] if len(e.args) > 1 and not is_option_like(e.args[1]) else None)
            rows = [r for b in cfg.binds("authentication policylabel", name) for r in [policy_row(b, b.opt("policyname") or "")] if r]
            rows.sort(key=lambda r: num(r["prio"]))
            sch = schema_info(ls)
            factors[fid] = {"id": fid, "type": "label", "etype": "authentication policylabel", "name": name, "node": fid,
                            "schemas": [sch] if sch else [], "rows": rows}
        entries = []
        for et in ("vpn vserver", "lb vserver", "cs vserver"):
            for name, e in cfg.of(et).items():
                src = self.nid(et, name)
                if src not in self.nodes:
                    continue
                aaa, via = e.opt("authnvsname"), ""
                prof = e.opt("authnprofile")
                if prof and cfg.get("authentication authnprofile", prof):
                    aaa, via = cfg.get("authentication authnprofile", prof).opt("authnvsname") or aaa, prof
                if aaa and self.nid("authentication vserver", aaa) in factors:
                    entries.append({"node": src, "etype": et, "name": name, "factor": self.nid("authentication vserver", aaa), "via": via})
                if et == "vpn vserver":  # classic authentication policies bound directly to the gateway
                    rows = []
                    for b in cfg.binds(et, name):
                        pol = b.opt("policy") or b.opt("policyname")
                        r = policy_row(b, pol, "secondary" if "secondary" in b.opts else ("group extraction" if "groupextraction" in b.opts else "primary")) if pol else None
                        if r:
                            rows.append(r)
                    if rows:
                        rows.sort(key=lambda r: ({"primary": 0, "secondary": 1}.get(r.get("role"), 2), num(r["prio"])))
                        fid = src + "|classic"
                        factors[fid] = {"id": fid, "type": "classic", "etype": et, "name": name, "node": src, "schemas": [], "rows": rows}
                        entries.append({"node": src, "etype": et, "name": name, "factor": fid, "via": "classic"})
        reached = {x["factor"] for x in entries}
        for fid, f in factors.items():  # auth vServers that no other vServer uses are entry points of their own
            if f["type"] == "vserver" and fid not in reached:
                entries.append({"node": fid, "etype": "authentication vserver", "name": f["name"], "factor": fid, "via": ""})
        for x in entries:  # client certificate on the entry vServer and on the authentication vServer of the flow
            et, nm = x["etype"], x["name"]
            x["clientcert"] = self.client_cert(nm) if et in ("vpn vserver", "lb vserver", "cs vserver", "authentication vserver") else {}
            f = factors.get(x["factor"])
            if f and f["type"] == "vserver" and f["name"] != nm:
                x["aaa_clientcert"] = self.client_cert(f["name"])
        return {"factors": factors, "entries": entries, "names": names} if factors else {}

    def _ref_or_none(self, et: str, owner: str, pol: str | None) -> str | None:
        if pol:
            for t in self._policy_etypes():
                n = self._ensure(t, pol)
                if n:
                    return n
        return self._ensure(et, owner)

    def _server_node(self, name: str, ctx: tuple[str, str]) -> str:
        nid = self._ensure("server", name)
        if nid:
            self.referenced.add(("server", name))
            return nid
        nid = self.nid("server", name)
        if nid not in self.nodes:
            ent = Entity("server", name, [name, name], implicit=True)
            self.nodes[nid] = Node(nid, "server", name, "server", name, props={"Address": name, "Note": "direct by IP, no 'add server'"}, group=self.gid, entity=ent)
        return nid

    # ---- Options on objects (add/set) ---------------------------------------------------
    def _entity_refs(self, et: str, name: str, e: Entity) -> None:
        kind = self._kind(et)
        if et in VSERVER_TYPES and not e.implicit:
            src = self.nid(et, name)
            if src not in self.nodes:
                return
            ctx = (et, name)
            for key, etypes, typ, lab in (("authnvsname", ["authentication vserver", "vpn vserver"], "auth", "Auth"),
                                          ("authnprofile", ["authentication authnprofile"], "auth", "Authn profile"),
                                          ("backupvserver", ["gslb vserver"] if et == "gslb vserver" else [et] + [t for t in ("lb vserver", "cs vserver") if t != et], "backup", "Backup"),
                                          ("sslprofile", ["ssl profile"], "ssl", "SSL profile")):
                v = e.opt(key)
                if v:
                    self._ref(src, etypes, v, typ, lab, ctx, e.line)
        if et in ("vpn vserver", "lb vserver", "cs vserver", "authentication vserver", "gslb vserver", "service", "servicegroup"):
            sv = self.cfg.get("ssl vserver" if "vserver" in et else "ssl " + et, name)
            src = self.nid(et, name)
            if sv and src in self.nodes:
                pr = sv.opt("sslprofile")
                if pr:
                    self._ref(src, ["ssl profile"], pr, "ssl", "SSL profile", (et, name), sv.line)
        if et == "service":
            src = self.nid(et, name)
            if src in self.nodes and len(e.args) > 1:
                srv = e.args[1]
                sid = self._server_node(srv, (et, name))
                self._add_edge(src, sid, "bind", comm_label(e.args[2] if len(e.args) > 2 else "", e.args[3]) if len(e.args) > 3 else "")
                ip = self._server_ip.get(srv, srv)
                self.backends.append({"node": src, "server_node": sid, "host": ip, "port": e.args[3] if len(e.args) > 3 else "",
                                      "proto": e.args[2] if len(e.args) > 2 else "", "name": name, "etype": et})
        if et == "authentication authnprofile":
            src = self.nid(et, name)
            v = e.opt("authnvsname")
            if v and src in self.nodes:
                self._ref(src, ["authentication vserver", "vpn vserver"], v, "auth", "authnVsName", (et, name), e.line)
        if et == "authentication policylabel":
            src = self.nid(et, name)
            ls = e.opt("loginschema") or (e.args[1] if len(e.args) > 1 and not e.args[1].startswith("-") else None)
            if ls and src in self.nodes and ls.upper() != "LSCHEMA_INT":
                self._ref(src, ["authentication loginschema"], ls, "nfactor", "Login Schema", (et, name), e.line)
        if kind == "authpol":
            src = self.nid(et, name)
            act = e.opt("action") or e.opt("reqaction") or (e.args[2] if len(e.args) > 2 else None)
            builtin = re.fullmatch(r"[A-Z_]+", act or "") and not any(act in self.cfg.of(t) for t in self.cfg.entities)
            if act and ("ns assignment", act) in self._stmt_idx:
                act = None  # nFactor: an assignment (variable) as action; part of the policy's config lines, no node
            if act and src in self.nodes and not builtin and not et.endswith("localpolicy") and not et.endswith("noauthpolicy"):
                if et.endswith("loginschemapolicy"):
                    self._ref(src, ["authentication loginschema"], e.opt("action") or act, "nfactor", "Login Schema", (et, name), e.line)
                elif et.endswith("policy") and et != "authentication policy":
                    cands = [et[: -len("policy")] + "action", et[: -len("policy")] + "profile"]
                    self._ref(src, cands + [t for t in self.cfg.entities if self._kind(t) == "authact"], act, "bind", "Action", (et, name), e.line)
                else:
                    self._ref(src, [t for t in self.cfg.entities if self._kind(t) == "authact"] or ["authentication ldapaction"], act, "bind", "Action", (et, name), e.line)
        if kind == "authact":
            ip, port = e.opt("serverip"), e.opt("serverport")
            src = self.nid(et, name)
            if ip and src in self.nodes:
                for fe in list(self.frontends):
                    if fe["ip"] == ip and (not port or fe["port"] == port) and fe["etype"] == "lb vserver":
                        self._add_edge(src, fe["node"], "loop", "Server via LB")
        if et == "cs policy":
            src = self.nid(et, name)
            act = e.opt("action") or (e.args[2] if len(e.args) > 2 else None)
            if act and src in self.nodes:
                a = self.cfg.get("cs action", act)
                if a:
                    self.referenced.add(("cs action", act))
                    tl = a.opt("targetlbvserver")
                    if tl:
                        self._ref(src, ["lb vserver"], tl, "route", act, ("cs action", act), a.line)
                    tv = a.opt("targetvserver")
                    if tv:
                        self._ref(src, ["lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "gslb vserver"], tv, "route", act, ("cs action", act), a.line)
                elif act:
                    self.missing.append({"src_etype": et, "src_name": name, "ref_type": "cs action", "ref_name": act, "node": src, "line": e.line})
        if et == "ssl crl":
            src, ca = self.nid(et, name), e.opt("cacert")
            if ca and src in self.nodes:
                c = self._ensure("ssl certkey", ca)
                if c:  # CA certificate -> its revocation list (exporting the certificate brings the CRL along)
                    self.referenced.add(("ssl certkey", ca))
                    self._add_edge(c, src, "ssl", "CRL", e.line)
                else:
                    self._ref(src, ["ssl certkey"], ca, "ssl", "CA", (et, name), e.line)
        if et == "transform action":
            prof = e.opt("profilename") or (e.args[1] if len(e.args) > 1 else None)
            src = self.nid(et, name)
            if prof and src in self.nodes and self.nid("transform profile", prof) in self.nodes:
                self._ref(self.nid("transform profile", prof), ["transform action"], name, "bind", "Action", ("transform profile", prof), e.line)
        if et == "appfw policy":
            src = self.nid(et, name)
            prof = e.opt("profilename") or (e.args[2] if len(e.args) > 2 else None)
            if prof and src in self.nodes:
                self._ref(src, ["appfw profile"], prof, "policy", "Profil", (et, name), e.line)
        if kind in ("policy",) and et not in ("cs policy", "appfw policy"):
            act = e.opt("action") or (e.args[2] if len(e.args) > 2 else None)
            src = self.nid(et, name)
            if act and src in self.nodes:
                for t in POLICY_ACTION.get(et, (et.replace("policy", "action"),)):
                    if self._kind(t) == "action" and self.cfg.get(t, act):
                        self._ref(src, [t], act, "bind", "Action", (et, name), e.line)
        if et == "dns nameserver":
            v, _ = self._vs_node(name, ["lb vserver"])
            if v:
                self.referenced.add(("lb vserver", name))
                self._add_edge(self.device_node().id, v, "bind", "DNS name server")
        if et == "vpn sessionaction":
            src = self.nid(et, name)
            dv = e.opt("dnsvservername")
            if dv and src in self.nodes:
                self._ref(src, ["lb vserver"], dv, "route", "DNS vServer", (et, name), e.line)
        if et == "policy httpcallout":
            vs = e.opt("vserver")
            if vs:  # assumption: a defined callout is in use; it is drawn from the device (global) to its vServer
                v, _ = self._vs_node(vs, ["lb vserver", "cs vserver"])
                if v:
                    self.referenced.add((self.nodes[v].etype, vs))
                    self._add_edge(self.device_node().id, v, "bind", f"HTTP callout {name}")
        if et == "gslb service":
            self._gslb_service(name, e)
        if et == "gslb servicegroup":
            site = e.opt("sitename")
            src = self.nid(et, name)
            if site and src in self.nodes:
                self._ref(src, ["gslb site"], site, "gslb", "Site", (et, name), e.line)

    def _gslb_service(self, name: str, e: Entity) -> None:
        src = self.nid("gslb service", name)
        if src not in self.nodes:
            return
        a = e.args[1:]
        sites = self.cfg.of("gslb site")
        site = e.opt("sitename")
        host = None
        rest = list(a)
        for x in a[:2]:
            if x in sites and not site:
                site = x
                rest.remove(x)
                break
        if rest:
            host = rest[0]
        proto = rest[1] if len(rest) > 1 else ""
        port = rest[2] if len(rest) > 2 else ""
        n = self.nodes[src]
        n.props["Target"] = f"{host}:{port}" if port else (host or "")
        n.props["Protocol"] = proto
        if site:
            n.props["Site"] = site
            self._ref(src, ["gslb site"], site, "gslb", "Site", ("gslb service", name), e.line)
        ip = self._server_ip.get(host or "", host or "")
        n.props["_ip"] = ip
        for fe in self.frontends:
            if fe["ip"] == ip and (not port or fe["port"] == port) and fe["etype"] in ("lb vserver", "cs vserver"):
                self._add_edge(src, fe["node"], "gslb", "lokaler vServer")

    # ---- local links: service -> vServer on the same device ------------------------
    def _port_labels(self) -> None:
        """Label connections with protocol/port: vServer -> service (service port), service -> server (member port)."""
        vs_kinds = {"csvs", "lbvs", "gwvs", "aaavs", "gslbvs"}
        for e in self.edges:
            sn, tn = self.nodes.get(e.source), self.nodes.get(e.target)
            if not sn or not tn:
                continue
            if sn.kind in vs_kinds and tn.kind in ("svc", "sg") and e.type == "bind" and not e.label and tn.entity is not None:
                ent = tn.entity
                if tn.etype == "service" and len(ent.args) > 3:
                    e.label, e.port = comm_label(ent.args[2], ent.args[3]), True
                    e.plain = is_plain(ent.args[2], ent.args[3])
                else:
                    nm = comm_name(ent_proto(ent), "")
                    if nm:
                        e.label, e.port = nm, True
                        e.plain = is_plain(ent_proto(ent), "")
            elif sn.kind in ("svc", "sg") and tn.kind == "server" and e.label:
                e.port = True
                se = sn.entity
                proto = (se.args[2] if sn.etype == "service" and se is not None and len(se.args) > 2 else ent_proto(se))
                m = re.search(r"\d+", e.label)
                e.plain = is_plain(proto, m.group(0) if m else "")

    @staticmethod
    def _url_target(url: str) -> tuple[str, str]:
        m = re.match(r"^\s*(?:(https?|ftp|ldaps?)://)?([^/:?#\s]+)(?::(\d+))?", url or "", re.I)
        if not m:
            return "", ""
        scheme = (m.group(1) or "").lower()
        return m.group(2), m.group(3) or {"https": "443", "http": "80", "ldaps": "636", "ldap": "389"}.get(scheme, "")

    def _url_links(self) -> None:
        """Gateway session actions (web interface/StoreFront URLs) and STA servers that point to a vServer of this device.
        Assumption: an IP (or a server name defined here) in the URL that matches the IP:port of a local vServer means 'goes there'.
        Names that cannot be resolved here are recorded in ``unresolved`` (shown separately, never guessed)."""
        items = []
        for n in self.nodes.values():
            if n.etype == "vpn sessionaction" and n.entity is not None:
                for key in ("wihome", "storefronturl", "ssodomain"):
                    u = n.entity.opt(key)
                    if u and key != "ssodomain":
                        items.append((n.id, key, u))
            elif n.kind == "sta":
                items.append((n.id, "STA", n.props.get("URL", n.label)))
        vp = self.cfg.get("vpn parameter", "")
        if vp is not None:  # global session parameters (set vpn parameter -wihome/-storefronturl) apply to every gateway
            for key in ("wihome", "storefronturl"):
                u = vp.opt(key)
                if u:
                    items.append((self.device_node().id, f"vpn parameter {key}", u))
        for nid, via, url in items:
            host, port = self._url_target(url)
            if not host:
                continue
            ip = self._server_ip.get(host, host)
            by_dns = not is_ip(ip) and ip.lower().rstrip(".") in self.dns_rec
            if by_dns:
                ip = self.dns_rec[ip.lower().rstrip(".")]
            hit = [fe for fe in self.frontends if fe["ip"] == ip and (not port or fe["port"] == port) and fe["node"] != nid]
            if is_ip(ip) and hit:
                for fe in hit:
                    self._add_edge(nid, fe["node"], "route", f"{via} → vServer" + (" (local DNS record)" if by_dns else ""))
            else:
                self.unresolved.append({"node": nid, "via": via, "host": host, "port": port, "ip": ip if is_ip(ip) else ""})
        # Authentication servers (LDAP/RADIUS/...): a local LB vServer is already linked ("Server via LB"). Another device's
        # vServer may match by IP (checked across configs, not listed otherwise); a server *name* is listed like a URL target.
        local = {(e.source) for e in self.edges if e.type == "loop" and e.label == "Server via LB"}
        for n in list(self.nodes.values()):
            if n.kind != "authact" or n.entity is None or n.id in local:
                continue
            ip, name, port = n.entity.opt("serverip"), n.entity.opt("servername"), n.entity.opt("serverport") or ""
            if ip and is_ip(ip):
                self.unresolved.append({"node": n.id, "via": "auth server", "host": ip, "port": port, "ip": ip, "silent": True})
            elif name:
                self.unresolved.append({"node": n.id, "via": "auth server", "host": name, "port": port, "ip": ""})

    # Safety net: options that name another object but are not modelled by a specific rule above still become an edge
    # ("ref", labelled with the option), so that no named dependency is lost. Only options whose key says which object type
    # is meant are used (e.g. ...vserver..., ...cert..., ...monitor...), to avoid matching unrelated values by accident.
    REF_HINTS = (
        (("vserver", "vsname", "vservername"), VSERVER_TYPES),
        (("certkey", "certname", "cacert", "certkeyname", "encryptionkey"), ["ssl certkey"]),
        (("monitor",), ["lb monitor"]),
        (("sslprofile",), ["ssl profile"]),
        (("authnprofile",), ["authentication authnprofile"]),
        (("loginschema",), ["authentication loginschema"]),
        (("servicegroup",), ["servicegroup", "gslb servicegroup"]),
        (("servicename", "service"), ["service", "servicegroup", "gslb service"]),
        (("labelname", "policylabel", "nextfactor"), LABEL_TYPES),
        (("accessprofile",), ["ica accessprofile"]),
        (("profilename",), ["appfw profile", "transform profile", "vpn clientlessaccessprofile"]),
        (("group", "defaultauthenticationgroup"), ["aaa group"]),
    )
    REF_SKIP = {"td", "comment", "rule", "priority", "state", "gotopriorityexpression", "type", "bindpoint", "invoke", "labeltype"}
    generic_refs: list[tuple[str, str, str]]

    def _ref_hint(self, key: str) -> list[str]:
        for keys, etypes in self.REF_HINTS:
            if any(k in key for k in keys):
                return list(etypes)
        return []

    def _generic_refs(self) -> None:
        self.generic_refs = []
        linked: set[frozenset] = {frozenset((e.source, e.target)) for e in self.edges}
        dev = self.device_node().id

        adj: dict[str, set[str]] = {}
        for e in self.edges:
            if e.type != "contains":
                adj.setdefault(e.source, set()).add(e.target)

        def near(a: str, b: str, depth: int = 3) -> bool:  # already connected through the modelled chain?
            front = {a}
            for _ in range(depth):
                front = {y for x in front for y in adj.get(x, ())}
                if b in front:
                    return True
            return False

        def subject(et: str, name: str) -> str | None:
            if et.endswith("global") or et in ("vpn parameter", "aaa parameter", "ns param"):
                return dev
            if et.startswith("ssl ") and et in ("ssl vserver", "ssl service", "ssl servicegroup"):
                base = et[4:]
                if base == "vserver":
                    return self._vs_node(name)[0]
                nid = self.node_for(base, name)
                if nid is None and base == "service" and name.lower().startswith(INTERNAL_SERVICES):
                    return dev
                return nid.id if nid else None
            n = self.node_for(et, name)
            return n.id if n else None

        items: list[tuple[str, str, dict, int]] = []
        for et, d in self.cfg.entities.items():
            for name, e in d.items():
                items.append((et, name, e.opts, e.line))
        for b in self.cfg.bindings:
            items.append((b.etype, b.owner, b.opts, b.line))
        for et, name, opts, line in items:
            src = None
            for key, vals in opts.items():
                if key in self.REF_SKIP or not vals:
                    continue
                cand = [] if any(x in key for x in ("fqdn", "expr", "url")) else self._ref_hint(key)
                if not cand:
                    continue
                for v in vals:
                    if not v or is_option_like(v) or v.upper() in KEYWORD_NAMES:
                        continue
                    tgt = next((self.nid(t, v) for t in cand if self.cfg.get(t, v) is not None and self._ensure(t, v)), None)
                    if not tgt:
                        continue
                    src = src or subject(et, name)
                    if not src or src == tgt or frozenset((src, tgt)) in linked or near(src, tgt):
                        continue
                    self._add_edge(src, tgt, "ref", f"-{key}", line)
                    adj.setdefault(src, set()).add(tgt)
                    self.referenced.add((self.nodes[tgt].etype, v))
                    linked.add(frozenset((src, tgt)))
                    self.generic_refs.append((et, key, self.nodes[tgt].etype))

    def _ha_and_local_links(self) -> None:
        self._url_links()
        self._port_labels()
        for be in self.backends:
            for fe in self.frontends:
                if be["host"] == fe["ip"] and be["port"] == fe["port"] and be["node"] != fe["node"]:
                    self._add_edge(be["node"], fe["node"], "loop", "lokal (Loopback/Chain)")


# action/profile type -> short label in the nFactor view (others: upper-cased type word)
AUTH_TYPE_LABELS = {"ldapaction": "LDAP", "radiusaction": "RADIUS", "samlaction": "SAML", "oauthaction": "OAuth/OIDC", "certaction": "Certificate",
                    "negotiateaction": "Kerberos", "epaaction": "EPA", "webauthaction": "Web auth", "tacacsaction": "TACACS+",
                    "emailaction": "E-mail OTP", "storefrontauthaction": "StoreFront", "dfaaction": "DFA", "captchaaction": "CAPTCHA",
                    "noauthaction": "No auth", "samlidpprofile": "SAML IdP", "oauthidpprofile": "OAuth IdP", "citrixauthaction": "Citrix auth",
                    "adfsproxyprofile": "ADFS proxy", "pushservice": "Push"}

# special functions inside policy expressions (shown as "Uses" on the policy)
EXPR_FEATURES = ((r"IPREP_", "IP reputation"), (r"CHECK_LIMIT|\.LIMIT\(|limitidentifier", "Rate limiting"),
                 (r"HTTP_CALLOUT", "HTTP callout"), (r"\.LOCATION\b|MATCHES_LOCATION", "Geo location"),
                 (r"URL_CATEGORIZE", "URL categorization"), (r"\bBOT\.", "Bot management"))

POLICY_ACTION = {"transform policy": ("transform profile",), "vpn clientlessaccesspolicy": ("vpn clientlessaccessprofile",),
                 "ica policy": ("ica action",), "tm trafficpolicy": ("tm trafficaction",), "tm sessionpolicy": ("tm sessionaction",)}
VS_LABEL_TYPES = ("reqvserver", "resvserver")  # -labelType values whose -labelName is a vServer (invoke a vServer's policy bank)
INTERNAL_SERVICES = ("nshttps-", "nsrpcs-", "nskrpcs-", "nssslvpn-", "nsrnatsip-", "nsdns-", "nsntp-")


def invoke_target(b) -> tuple[str, str]:
    """(label type, label name) of a policy binding: ``-labelType X -labelName Y`` or ``-invoke X Y`` (ns.conf form)."""
    lt, lab = (b.opt("labeltype") or "").lower(), b.opt("labelname") or ""
    inv = b.opts.get("invoke") or []
    if not lab and len(inv) >= 2:
        lt, lab = inv[0].lower(), inv[1]
    return lt, lab


def ent_proto(ent) -> str:
    return ent.args[1] if ent is not None and len(ent.args) > 1 else ""


def _builtin_policy(name: str) -> bool:
    n = name.lower()
    # Assumption: names starting with "_" are system-generated policies that are not part of the exported ns.conf
    # (observed as bound-but-undefined in many real exports); to be confirmed against the product documentation.
    # All-caps names with a hyphen are factory objects as well (confirmed by the project owner).
    if name.upper() == name and "-" in name:
        return True
    return n.startswith(("ns_", "_")) or (name.startswith("SET") and name.endswith("_POL")) or n.startswith("default_")


def is_option_like(s: str) -> bool:
    return bool(s) and s.startswith("-") and len(s) > 1 and s[1].isalpha()


def vserver_endpoint(e: Entity) -> tuple[str, str]:
    ip = e.args[2] if len(e.args) > 2 else ""
    port = e.args[3] if len(e.args) > 3 else ""
    return ip, port
