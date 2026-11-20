"""Anonymize ns.conf files so they can be shared or used for development.

Design goals
- Safe by default: every value that is not clearly a keyword, a number or an enum constant is treated as a name and
  replaced by a consistent pseudonym. Over-anonymizing is acceptable, leaking is not.
- Consistent across all files of one run (HA pairs and double-hop links keep working): the same name, IP, host or file
  name always maps to the same pseudonym.
- Structure-preserving: the output still parses to the same statements and objects; IPs keep their subnet relations.
- No reverse mapping is stored unless ``--map-file`` is given explicitly (that file is as sensitive as the input).

The result must still be reviewed by a human before it leaves the private folder (see docs/PRIVACY.md).
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from .model import BUILTIN_CERTS, BUILTIN_MONITORS, KEYWORD_NAMES, SECRET_OPTS, is_ip
from .parser import Config, FAMILIES, ONE_WORD, Token, is_option, tokenize

# Option values that are free text or customer-specific identifiers -> replaced by a placeholder.
FREE_TEXT_OPTS = {
    "comment", "description", "contact", "location", "ldapbase", "ldapbinddn", "ldaploginname", "searchfilter",
    "kcdaccount", "domain", "samlissuername", "metadataurl", "clientid", "audience", "issuer", "redirecturl",
    "httpsredirecturl", "email", "url", "hostname", "fqdn", "domainname", "orgname", "subjectnameattribute",
    "groupnameattribute", "ssonameattribute", "defaultauthenticationgroup", "authorizationgroup", "authentication",
    "ldaphostname", "serverip", "servername", "customheaders",
    "username", "adminname", "ssodomain", "storefronturl", "wihome", "homepage", "staserver", "emailaddress",
    "samlidpurl", "samlredirecturl", "signaturealg", "metadataurl", "text", "message", "responsemessage",
}
FILE_OPTS = {"cert", "key", "certfilename", "keyfilename", "certfile", "keyfile", "crlfile", "dhfile", "file",
             "filename", "fipskey", "intermediatecacert", "cacert"}
# Options whose value is an IP or host that is replaced through the IP/host mapping (not by a placeholder).
HOSTISH_OPTS = {"serverip", "servername"}
# Positional secrets: etype -> index in args that holds a secret.
POSITIONAL_SECRETS = {"system user": 1, "aaa user": 1}

SAFE_LOWER = {
    "true", "false", "none", "null", "yes", "no", "on", "off", "http", "https", "tcp", "udp", "ssl", "ftp", "dns",
    "ping", "ldap", "radius", "sip", "ssl_bridge", "any", "default",
}
_ENUM = re.compile(r"^[A-Z0-9_.:/*+-]+$")
_NUM = re.compile(r"^[+-]?\d+(\.\d+)?$|^\d+(,\d+)*$|^\d+-\d+$")
_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_FQDN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|de|at|ch|eu|io|info|biz|cloud|local|lan|corp|intern|internal|"
                   r"fritz\.box|[a-z]{2})(?![\w-])")
_URL_HOST = re.compile(r"(https?://)([^/\s\"':]+)")


class Anonymizer:
    def __init__(self, keep_literals: bool = False):
        self.keep_literals = keep_literals
        self.names: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.prefixes: dict[tuple[str, str, str], int] = {}
        self.subnets: dict[tuple[str, str, str], int] = {}
        self.v6: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.files: dict[str, str] = {}
        self.counts = Counter()
        self._sensitive: set[str] = set()
        self._keywords: set[str] = set()

    # ---- mappings -------------------------------------------------------------------------
    def _name(self, original: str, kind: str = "obj") -> str:
        if original not in self.names:
            self.names[original] = f"{kind}_{len(self.names) + 1:04d}"
        self._sensitive.add(original)
        return self.names[original]

    def _ip(self, m: re.Match) -> str:
        a, b, c, d = m.groups()
        whole = m.group(0)
        if any(int(x) > 255 for x in (a, b, c, d)):
            return whole
        if int(a) == 255 or whole in ("0.0.0.0",) or int(a) == 0:
            return whole  # netmasks / wildcard
        key = (a, b, c)
        if key not in self.subnets:
            self.subnets[key] = len(self.subnets)
        i = self.subnets[key]
        self._sensitive.add(whole)
        self.counts["ips"] += 1
        return f"10.{i // 256 % 256}.{i % 256}.{d}"

    def _v6(self, m: re.Match) -> str:
        s = m.group(0)
        if s not in self.v6:
            self.v6[s] = f"2001:db8::{len(self.v6) + 1:x}"
        self._sensitive.add(s)
        return self.v6[s]

    def _host(self, m: re.Match) -> str:
        s = m.group(0)
        if s.lower().endswith(("example.com", "example.org")):
            return s
        if s not in self.hosts:
            self.hosts[s] = f"host{len(self.hosts) + 1}.example.com"
        self._sensitive.add(s)
        self.counts["hosts"] += 1
        return self.hosts[s]

    def _email(self, m: re.Match) -> str:
        s = m.group(0)
        if s.lower().endswith(("@example.com", "@example.org")):
            return s
        if s not in self.hosts:
            self.hosts[s] = f"user{len(self.hosts) + 1}@example.com"
        self._sensitive.add(s)
        self.counts["emails"] += 1
        return self.hosts[s]

    def _file(self, original: str) -> str:
        if original not in self.files:
            ext = Path(original).suffix[:8] if re.fullmatch(r"\.[A-Za-z0-9]{1,6}", Path(original).suffix) else ""
            self.files[original] = f"file_{len(self.files) + 1:04d}{ext}"
        self._sensitive.add(original)
        return self.files[original]

    def scrub(self, text: str) -> str:
        """Replace IPs, e-mails, host names and long hex blobs inside free text."""
        text = _HEX.sub(lambda m: "0" * len(m.group(0)), text)
        text = _EMAIL.sub(self._email, text)
        text = _URL_HOST.sub(lambda m: m.group(1) + (m.group(2) if is_ip(m.group(2)) else self._host(re.match(r".*", m.group(2)))), text)
        text = _IPV4.sub(self._ip, text)
        text = _IPV6.sub(self._v6, text)
        text = _FQDN.sub(self._host, text)
        return text

    # ---- names known from the model ------------------------------------------------------
    @staticmethod
    def _is_builtin_name(n: str) -> bool:
        low = n.lower()
        return (n.upper() in KEYWORD_NAMES or low in BUILTIN_MONITORS or n in BUILTIN_CERTS or low in SAFE_LOWER
                or low.startswith(("ns_", "nstcp_", "nshttp_", "default", "_")) or (n.upper() == n and "-" in n))

    def learn(self, cfg: Config) -> None:
        for et, ents in cfg.entities.items():
            for name in ents:
                if name and not self._is_builtin_name(name) and not is_ip(name) and not _NUM.match(name):
                    self._name(name, et.split()[-1][:10].replace("-", "") or "obj")
        for st in cfg.statements:
            if st.etype == "ns hostname" and st.args:
                self._name(st.args[0], "adc")

    # ---- token level ----------------------------------------------------------------------
    def _replace_known_names(self, s: str) -> str:
        for n in sorted(self.names, key=len, reverse=True):
            if len(n) >= 3 and n in s:
                s = re.sub(r"(?<![\w.-])" + re.escape(n) + r"(?![\w.-])", self.names[n], s)
        return s

    _EXPR = re.compile(r"[A-Z]{2,}\.[A-Z_]+|\(|^(true|false)$", re.I)

    def _literal(self, m: re.Match) -> str:
        inner = m.group(1)
        if not inner:
            return m.group(0)
        if self.keep_literals:
            return '"' + self.scrub(self._replace_known_names(inner)) + '"'
        return '"lit"'

    def _quoted(self, s: str) -> str:
        if s in self.names:
            return self.names[s]
        if self._EXPR.search(s):  # expression: keep structure, replace literals, names, hosts, IPs
            return self.scrub(self._replace_known_names(re.sub(r'"(.*?)"', self._literal, s)))
        if self.keep_literals:
            return self.scrub(self._replace_known_names(s))
        self.counts["text"] += 1
        return "anon"

    def _value(self, t: Token, opt: str | None) -> str:
        s = t.text
        low = (opt or "").lower()
        if low in SECRET_OPTS:
            self.counts["secrets"] += 1
            return "removed"
        if low in FILE_OPTS and s:
            return self._file(s)
        if low in FREE_TEXT_OPTS and low not in HOSTISH_OPTS and s:
            self.counts["text"] += 1
            return "anon"
        if t.quoted:
            return self._quoted(s)
        if s in self.names:
            return self.names[s]
        if is_ip(s) or _NUM.match(s) or _ENUM.match(s) or self._is_builtin_name(s):
            return self.scrub(s)
        if _IPV6.fullmatch(s) or _EMAIL.fullmatch(s) or _FQDN.fullmatch(s) or "://" in s:
            return self.scrub(s)
        return self._name(s)  # unknown mixed/lower-case value: treat as a name

    def line(self, raw: str) -> str | None:
        s = raw.strip()
        if not s:
            return None
        if s.startswith("#"):
            return s if re.match(r"#NS\d", s) else None
        toks = tokenize(s)
        if len(toks) < 2:
            return None
        verb = toks[0].text.lower()
        # object type words are keywords
        n_type = 1
        if verb in ("add", "set", "bind", "unbind", "rm", "unset", "link", "enable", "disable", "show"):
            n_type = 2 if len(toks) > 1 and (toks[1].text.lower() in FAMILIES) else 1
            if len(toks) > 1 and toks[1].text.lower() in ONE_WORD:
                n_type = 1
            n_type += 1  # include verb
        self._keywords.update(t.text for t in toks[:n_type])
        out: list[str] = []
        opt: str | None = None
        etype = " ".join(t.text.lower() for t in toks[1:n_type])
        pos = 0
        for i, t in enumerate(toks):
            if i < n_type:
                out.append(t.text)
                continue
            if is_option(t):
                opt = t.text[1:]
                out.append(t.text)
                continue
            if opt is None:
                if POSITIONAL_SECRETS.get(etype) == pos and t.text:
                    new = "removed"
                    self.counts["secrets"] += 1
                else:
                    new = self._value(t, None)
                pos += 1
            else:
                new = self._value(t, opt)
            out.append(self._quote(new, t.quoted))
        return " ".join(out)

    @staticmethod
    def _quote(s: str, was_quoted: bool) -> str:
        if not was_quoted and s and not re.search(r"\s|\"", s):
            return s
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def text(self, raw: str) -> str:
        out = []
        for ln in raw.splitlines():
            r = self.line(ln)
            if r:
                out.append(r)
        return "\n".join(out) + "\n"

    def leaks(self, anonymized: str) -> list[str]:
        """Original sensitive strings that still appear in the output (should be empty). Returns counts-safe hashes only."""
        bad = []
        for s in self._sensitive:
            if len(s) >= 4 and s in anonymized and s not in self.names.values() and s not in self._keywords and not s.endswith("example.com"):
                bad.append(s)
        return bad


def anonymize_paths(paths: list[str], out_dir: str, keep_literals: bool = False, map_file: str | None = None) -> dict:
    """Anonymize all config files below ``paths`` into ``out_dir``. Returns aggregate, content-free statistics."""
    import json

    files = []
    for p in paths:
        pp = Path(p)
        files += sorted(f for f in (pp.rglob("*") if pp.is_dir() else [pp]) if f.is_file() and not f.name.startswith("."))
    configs: list[tuple[Path, str]] = []
    for f in files:
        t = f.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^\s*(add|set|bind|enable|link)\s", t, re.M):
            configs.append((f, t))
    an = Anonymizer(keep_literals)
    for f, t in configs:
        an.learn(Config.parse_text(t, name=f.name))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stmts_in = stmts_out = 0
    leaks = 0
    for i, (f, t) in enumerate(configs, 1):
        res = an.text(t)
        marker = "-primary" if re.search(r"primary|[-_.]pri[-_.]|\bpri\b", f.name.lower()) else (
            "-secondary" if re.search(r"secondary|[-_.]sec[-_.]|\bsec\b", f.name.lower()) else "")
        (out / f"device-{i:03d}{marker}.conf").write_text(res, encoding="utf-8")
        stmts_in += len(Config.parse_text(t).statements)
        stmts_out += len(Config.parse_text(res).statements)
        leaks += len(an.leaks(res))
    if map_file:
        Path(map_file).write_text(json.dumps({"names": an.names, "hosts": an.hosts, "files": an.files},
                                              ensure_ascii=False, indent=1), encoding="utf-8")
    return {"files": len(configs), "statements_in": stmts_in, "statements_out": stmts_out, "names": len(an.names),
            "ips": len(an.subnets), "hosts": len(an.hosts), "leaks": leaks, "counts": dict(an.counts)}
