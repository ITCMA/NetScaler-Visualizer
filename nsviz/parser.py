"""Parser for NetScaler (ADC) ns.conf.

The ns.conf is line based: ``<verb> <objecttype> [<name/positional args>] [-option value ...]``.
The parser is deliberately generic (no schema per command): it splits every line into
verb, object type, positional arguments and options and builds an entity model from them
(``add`` creates, ``set`` amends, ``unset``/``rm`` remove, ``bind``/``unbind`` manage
bindings, ``link`` chains certificates, ``enable``/``disable`` features/modes).
Unknown commands are never lost; they end up in ``Config.statements``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# First words after which the object type is two words long ("lb vserver", "ssl certKey" ...).
FAMILIES = {
    "ns", "ssl", "lb", "cs", "gslb", "vpn", "authentication", "authorization", "aaa", "appfw",
    "rewrite", "responder", "cache", "cmp", "dns", "snmp", "audit", "system", "network", "policy",
    "ha", "cluster", "appflow", "bot", "filter", "tm", "transform", "stream", "ica", "rdp", "dos",
    "lsn", "ipsec", "reputation", "appqoe", "pq", "sc", "cr", "feo", "videooptimization",
    "urlfiltering", "contentinspection", "ntp", "tunnel", "user", "wi", "mgmt", "basic", "db",
    "spillover", "subscriber", "pcp", "ulfd", "adaptivetcp", "analytics", "smpp", "quic", "rise",
    "botsettings", "videooptimization", "tm", "ip6tunnel", "lldp", "ptp", "vxlan", "bridgegroup",
}

# Object types that do not follow the "two words" pattern.
ONE_WORD = {
    "server", "service", "servicegroup", "interface", "channel", "vlan", "route", "route6",
    "netprofile", "rsskeytype", "lacp", "nd6ravariables", "extendedmemoryparam", "nstimer",
    "ip6", "linkset", "arp", "arpparam", "inat", "rnat", "rnat6", "mapbmr", "mapdmr", "bridgetable",
}

# Singleton objects: ``set <type> -opt ...`` without a name (or with the value as positional argument).
SINGLETONS = {
    "ns config", "ns param", "ns hostname", "ns httpparam", "ns tcpparam", "ns timeout",
    "ns encryptionparams", "ns weblogparam", "ns tcpbufparam", "ns spparam", 
    "system parameter", "aaa parameter", "aaa ldapparams", "aaa radiusparams", "aaa tacacsparams",
    "lb parameter", "ssl parameter", "ssl fipssim", "cmp parameter", "cache parameter",
    "appflow param", "bot settings", "rsskeytype", "lacp", "nd6ravariables", "dns parameter",
    "vpn parameter", "gslb parameter", "cs parameter", "appfw settings", "appfw parameter",
    "reputation settings", "audit nslogparams", "audit syslogparams", "snmp engineid",
    "snmp option", 
    "network l3param", "network l2param", 
    "ns diameter", "ns stats", "ns spillover", "ns extendedmemoryparam",
    "rewrite param", "responder param", "tm sessionparameter",
    "authentication parameter", "ica parameter",
    "ntp param", "ntp sync", "ns ratecontrol", 
    "lsn parameter", "ns lldpparam", "ns ptpparam", "ns vpxparam", "ns acls", "ns acls6",
    "ns capacity", "ns ipv6param", "ns feature", "ns mode", "ns license", "videooptimization parameter",
    "contentinspection parameter", "appqoe parameter", 
}


@dataclass
class Token:
    text: str
    quoted: bool = False


def tokenize(line: str) -> list[Token]:
    """Split a line into tokens; double quotes with ``\\`` escapes are resolved."""
    toks: list[Token] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1
        elif c == '"':
            i += 1
            buf: list[str] = []
            while i < n:
                c = line[i]
                if c == "\\" and i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                elif c == '"':
                    i += 1
                    break
                else:
                    buf.append(c)
                    i += 1
            toks.append(Token("".join(buf), True))
        else:
            j = i
            while j < n and not line[j].isspace():
                j += 1
            toks.append(Token(line[i:j], False))
            i = j
    return toks


_OPT = re.compile(r"^-[A-Za-z][\w.]*$")


def is_option(t: Token) -> bool:
    return not t.quoted and bool(_OPT.match(t.text))


@dataclass
class Statement:
    verb: str
    etype: str  # kleingeschrieben, z.B. "lb vserver"
    args: list[str]
    opts: dict[str, list[str]]  # keys lower-cased
    line: int
    file: str
    raw: str
    tokens: list[Token] = field(default_factory=list, repr=False)

    def opt(self, key: str, default: str | None = None) -> str | None:
        v = self.opts.get(key.lower())
        if v is None:
            return default
        return v[0] if v else "true"


def split_etype(words: list[str]) -> int:
    """Number of words of the object type starting at words[0] (words after the verb)."""
    if not words:
        return 0
    w0 = words[0].lower()
    if w0 in ONE_WORD:
        return 1
    if w0 in FAMILIES and len(words) >= 2 and not is_option(Token(words[1])):
        return 2
    return 1


def parse_statement(line: str, lineno: int, file: str) -> Statement | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    toks = tokenize(s)
    if not toks:
        return None
    verb = toks[0].text.lower()
    rest = toks[1:]
    words = [t.text for t in rest]
    # 'bind/unbind/link' with object type; 'enable/disable ns feature' etc. go through the same logic.
    n = split_etype(words)
    etype = " ".join(w.lower() for w in words[:n])
    body = rest[n:]
    args: list[str] = []
    opts: dict[str, list[str]] = {}
    cur: str | None = None
    for t in body:
        if is_option(t):
            cur = t.text[1:].lower()
            opts.setdefault(cur, [])
        elif cur is None:
            args.append(t.text)
        else:
            opts[cur].append(t.text)
    return Statement(verb, etype, args, opts, lineno, file, s, toks)


@dataclass
class Entity:
    etype: str
    name: str
    args: list[str] = field(default_factory=list)
    opts: dict[str, list[str]] = field(default_factory=dict)
    line: int = 0
    file: str = ""
    implicit: bool = False  # only known through 'set' without 'add' (e.g. built-in objects)
    stmts: list[Statement] = field(default_factory=list, repr=False)
    bindings: list["Binding"] = field(default_factory=list, repr=False)

    def opt(self, key: str, default: str | None = None) -> str | None:
        v = self.opts.get(key.lower())
        if v is None:
            return default
        return v[0] if v else "true"

    def has(self, key: str) -> bool:
        return key.lower() in self.opts


@dataclass
class Binding:
    etype: str
    owner: str
    args: list[str]
    opts: dict[str, list[str]]
    line: int
    file: str
    raw: str

    def opt(self, key: str, default: str | None = None) -> str | None:
        v = self.opts.get(key.lower())
        if v is None:
            return default
        return v[0] if v else "true"


class Config:
    """Eine geparste ns.conf."""

    def __init__(self, name: str = "", path: str = ""):
        self.name = name
        self.path = path
        self.version: str | None = None  # z.B. "13.1"
        self.build: str | None = None
        self.header: str = ""
        self.statements: list[Statement] = []
        self.entities: dict[str, dict[str, Entity]] = {}
        self.bindings: list[Binding] = []
        self.links: list[tuple[str, str]] = []  # (certkey, ca-certkey)
        self.features: set[str] = set()
        self.modes: set[str] = set()
        self.disabled_features: set[str] = set()
        self.warnings: list[str] = []

    # ---- Zugriff -------------------------------------------------------------------------
    def of(self, etype: str) -> dict[str, Entity]:
        return self.entities.get(etype.lower(), {})

    def get(self, etype: str, name: str) -> Entity | None:
        return self.of(etype).get(name)

    def types(self) -> list[str]:
        return sorted(self.entities)

    def binds(self, etype: str, owner: str | None = None) -> list[Binding]:
        et = etype.lower()
        return [b for b in self.bindings if b.etype == et and (owner is None or b.owner == owner)]

    def single(self, etype: str) -> Entity | None:
        return self.of(etype).get("")

    @property
    def nsip(self) -> str | None:
        e = self.single("ns config")
        return e.opt("ipaddress") if e else None

    @property
    def hostname(self) -> str | None:
        e = self.single("ns hostname")
        return e.args[0] if e and e.args else None

    # ---- Aufbau --------------------------------------------------------------------------
    def _put(self, st: Statement, name: str, implicit: bool) -> Entity:
        d = self.entities.setdefault(st.etype, {})
        e = Entity(st.etype, name, list(st.args), {k: list(v) for k, v in st.opts.items()},
                   st.line, st.file, implicit, [st])
        d[name] = e
        return e

    def apply(self, st: Statement) -> None:
        self.statements.append(st)
        v, et = st.verb, st.etype
        if v in ("enable", "disable") and et in ("ns feature", "ns mode"):
            target = self.features if et == "ns feature" else self.modes
            names = {a.upper() for a in st.args}
            if v == "enable":
                target |= names
                if et == "ns feature":
                    self.disabled_features -= names
            else:
                target -= names
                if et == "ns feature":
                    self.disabled_features |= names
            return
        if v == "add":
            name = "" if et in SINGLETONS else (st.args[0] if st.args else "")
            self._put(st, name, False)
        elif v == "set":
            name = "" if et in SINGLETONS or not st.args else st.args[0]
            d = self.entities.setdefault(et, {})
            e = d.get(name)
            if e is None:
                e = self._put(st, name, True)
            else:
                for k, val in st.opts.items():
                    e.opts[k] = list(val)
                if et in SINGLETONS and st.args:
                    e.args = list(st.args)
                elif len(st.args) > len(e.args):
                    e.args = list(st.args)
                e.stmts.append(st)
        elif v == "unset":
            name = "" if et in SINGLETONS or not st.args else st.args[0]
            e = self.of(et).get(name)
            if e:
                for k in list(st.opts) + [a.lstrip("-").lower() for a in st.args[1:]]:
                    e.opts.pop(k, None)
                e.stmts.append(st)
        elif v == "rm":
            name = "" if et in SINGLETONS or not st.args else st.args[0]
            self.of(et).pop(name, None)
        elif v == "bind":
            if et.endswith("global"):
                owner, args = "", list(st.args)
            else:
                owner, args = (st.args[0] if st.args else ""), list(st.args[1:])
            b = Binding(et, owner, args, {k: list(x) for k, x in st.opts.items()}, st.line, st.file, st.raw)
            self.bindings.append(b)
            ent = self.of(et).get(owner)
            if ent:
                ent.bindings.append(b)
        elif v == "unbind":
            if et.endswith("global"):
                owner, args = "", list(st.args)
            else:
                owner, args = (st.args[0] if st.args else ""), list(st.args[1:])
            for b in list(self.bindings):
                if b.etype == et and b.owner == owner and self._unbind_match(b, args, st.opts):
                    self.bindings.remove(b)
                    ent = self.of(et).get(owner)
                    if ent and b in ent.bindings:
                        ent.bindings.remove(b)
                    break
        elif v == "link" and et == "ssl certkey" and len(st.args) >= 2:
            self.links.append((st.args[0], st.args[1]))

    @staticmethod
    def _unbind_match(b: Binding, args: list[str], opts: dict[str, list[str]]) -> bool:
        if args and b.args[: len(args)] != args:
            return False
        for k, val in opts.items():
            if b.opts.get(k) != val:
                return False
        return True

    # ---- Quellen -------------------------------------------------------------------------
    @classmethod
    def parse_text(cls, text: str, name: str = "", path: str = "") -> "Config":
        cfg = cls(name, path)
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if i <= 3 and line.startswith("#NS"):
                m = re.match(r"#NS(\d+\.\d+)(?:\s+Build\s+([\w.\-]+))?", line)
                if m:
                    cfg.version, cfg.build = m.group(1), m.group(2)
                cfg.header = line.strip()
                continue
            try:
                st = parse_statement(line, i, name or path)
            except Exception as exc:  # defensive: a broken line must never stop the run
                cfg.warnings.append(f"Zeile {i}: nicht parsebar ({exc})")
                continue
            if st:
                cfg.apply(st)
        return cfg

    @classmethod
    def parse_file(cls, path: str | Path) -> "Config":
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        return cls.parse_text(text, name=p.name, path=str(p))
