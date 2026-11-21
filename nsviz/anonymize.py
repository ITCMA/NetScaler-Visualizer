"""Anonymize ns.conf files so they can be shared (for analysis, support, development).

Design goals
- Safe by default: every value that is not clearly a keyword, a number or an enum constant is treated as a name and
  replaced by a consistent pseudonym. Over-anonymizing is acceptable, leaking is not. Secrets are always removed.
- No loss of information for the analysis: the same original always maps to the same pseudonym (across all files of one
  run, so HA pairs and double-hop chains keep working); pseudonyms keep the object type (``lbvserver_0003``); IPs keep
  their subnet relations and whether they were private or public; FQDNs keep their structure, generic labels (www, sf,
  gateway, ...) and whether they were internal or external; LDAP DNs keep their structure; URLs keep scheme, port and
  product paths (``/Citrix/StoreWeb``).
- Every category can be switched off (``options``); all are on by default.
- A structure check compares the original and the anonymized config (statements, objects and connections by type), so a
  loss of information is detected instead of assumed.
- No reverse mapping is stored unless it is asked for explicitly (that file is as sensitive as the input).

The result should still be looked over before it leaves the private folder (see docs/PRIVACY.md).
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from pathlib import Path

from .model import BUILTIN_CERTS, BUILTIN_MONITORS, KEYWORD_NAMES, SECRET_OPTS, Graph, is_ip
from .parser import Config, FAMILIES, ONE_WORD, Token, is_option, quote, tokenize

# ---- categories ---------------------------------------------------------------------------------
OPTIONS = {  # key: (English label, German label). "secrets" cannot be switched off; see DEFAULT_OPTIONS for the preselection.
    "secrets": ("Passwords, keys, hashes, SNMP communities (always removed)", "Kennwörter, Schlüssel, Hashes, SNMP-Communities (immer entfernt)"),
    "names": ("Object names (vServers, services, policies, certificates, ...)", "Objektnamen (vServer, Services, Policies, Zertifikate, ...)"),
    "users": ("User and group names", "Benutzer- und Gruppennamen"),
    "hostnames": ("Device host names, HA and partition names", "Gerätenamen, HA- und Partitionsnamen"),
    "ips": ("IP and MAC addresses (subnets and private/public kept)", "IP- und MAC-Adressen (Subnetze und privat/öffentlich bleiben erkennbar)"),
    "fqdns": ("FQDNs, domains, e-mail addresses (internal/external kept)", "FQDNs, Domänen, E-Mail-Adressen (intern/extern bleibt erkennbar)"),
    "urls": ("Customer-specific URL paths (product paths kept)", "Kundenspezifische URL-Pfade (Produktpfade bleiben)"),
    "text": ("Descriptions, contacts, LDAP base/bind DN, NetBIOS and SAML identifiers", "Beschreibungen, Kontakte, LDAP-Base/Bind-DN, NetBIOS- und SAML-Kennungen"),
    "literals": ("Text inside policy expressions (structure kept)", "Text in Policy-Ausdrücken (Aufbau bleibt)"),
    "files": ("Certificate, key, CRL and KEK file names", "Zertifikats-, Schlüssel-, CRL- und KEK-Dateinamen"),
    # optional, off by default: these remove information instead of replacing it
    "comments": ("Remove comments (-comment values and # lines); otherwise kept, only IPs/FQDNs/names inside are replaced",
                 "Kommentare entfernen (-comment-Werte und #-Zeilen); sonst bleiben sie, nur IPs/FQDNs/Namen darin werden ersetzt"),
    "timezone": ("Remove the device time zone", "Gerätezeitzone entfernen"),
    "location": ("Remove location and GeoIP data (SNMP location, location entries, location files, coordinates)",
                 "Standort- und GeoIP-Angaben entfernen (SNMP-Standort, Location-Einträge, Location-Dateien, Koordinaten)"),
}
OPTIONAL = ("comments", "timezone", "location")
DEFAULT_OPTIONS = {k: k not in OPTIONAL for k in OPTIONS}
# what the optional categories remove: whole statements (by type) and options with their value
DROP_ETYPES = {"location": {"location", "locationfile", "locationfile6", "locationparameter"}}
DROP_OPTS = {"comments": {"comment"}, "timezone": {"timezone"}, "location": {"location", "latitude", "longitude", "geolocation"}}

EXTRA_SECRETS = {"passplain", "pwd", "psk", "presharedkey", "sharedsecretkey", "authpassword", "privpassword", "bindpassword",
                 "communityname", "community", "tokenkey", "apikey", "accesskey", "secretaccesskey", "encryptedsecret"}
SECRETS = set(SECRET_OPTS) | EXTRA_SECRETS
# Option values that are free text or customer identifiers (DN-like values keep their structure, see _text)
TEXT_OPTS = {
    "description", "contact", "ldapbase", "ldapbinddn", "searchfilter", "kcdaccount", "samlissuername",
    "clientid", "audience", "issuer", "orgname", "ssodomain", "domain", "text", "message", "responsemessage", "customheaders",
    "defaultauthenticationgroup", "authorizationgroup", "groupname", "ifalias", "realmstr", "entityid", "spnname", "realm",
    "identity", "originhost", "originrealm",
}
USER_OPTS = {"username", "adminname", "user", "userdomain"}
URLISH_OPTS = {"metadataurl", "redirecturl", "httpsredirecturl", "url", "storefronturl", "wihome", "homepage", "staserver",
               "samlidpurl", "samlredirecturl", "authorizationendpoint", "tokenendpoint", "idtokendecryptendpoint", "logouturl",
               "samlacsurl", "acsurlrule", "userinfourl", "certendpoint", "introspecturl", "ocspurl", "url_s", "serverurl"}
# Options whose values are attribute names, algorithms or other product vocabulary (kept)
KEEP_OPTS = {"subjectnameattribute", "groupnameattribute", "ssonameattribute", "groupattrname", "ldaploginname",
             "subattributename", "signaturealg", "digestmethod", "authentication", "attribute1", "attribute2", "attribute3",
             "attribute4", "attribute5", "attribute6", "attribute7", "attribute8", "attribute9", "attribute10",
             "attribute11", "attribute12", "attribute13", "attribute14", "attribute15", "attribute16", "followreferrals",
             "nestedgroupextraction", "groupsearchattribute", "groupsearchsubattribute", "defaultloginschema",
             "strongpassword", "passwordchange", "passwdchange", "passwordexpirynotification"}  # settings, no secret
FILE_OPTS = {"authenticationschema", "cert", "key", "certfilename", "keyfilename", "certfile", "keyfile", "crlfile", "dhfile", "file", "filename",
             "fipskey", "intermediatecacert", "cacertfile", "src", "importfile", "suffix", "kekfile", "certkeyfile"}
POSITIONAL_SECRETS = {"system user": 1, "aaa user": 1, "snmp community": 0}  # etype -> positional index that is a secret
USER_ETYPES = {"system user", "aaa user", "aaa group", "system group", "vpn user", "vpn group", "snmp user", "snmp group"}
HOST_ETYPES = {"ns hostname", "ns partition", "ha node", "cluster instance", "cluster node"}

SAFE_LOWER = {
    "true", "false", "none", "null", "yes", "no", "on", "off", "http", "https", "tcp", "udp", "ssl", "ftp", "dns",
    "ping", "ldap", "radius", "sip", "ssl_bridge", "any", "default",
}
SAFE_VALUES = {"samaccountname", "userprincipalname", "memberof", "mail", "cn", "objectclass", "displayname", "givenname",
               "sn", "uid", "objectsid", "distinguishedname", "proxyaddresses", "telephonenumber", "mobile", "member"}
# FQDN labels that describe a function, not a customer (kept, also with digits: sf01, gw2)
GENERIC_LABELS = {
    "www", "web", "mail", "smtp", "imap", "pop", "mx", "owa", "autodiscover", "exchange", "outlook", "sts", "adfs", "fs", "sso",
    "login", "logon", "auth", "idp", "saml", "oauth", "mfa", "otp", "radius", "ldap", "ldaps", "dc", "ad", "gc", "kdc", "ns",
    "dns", "ntp", "proxy", "gateway", "gw", "vpn", "remote", "access", "citrix", "ctx", "xa", "xd", "cvad", "ddc", "sta",
    "storefront", "sf", "store", "receiver", "workspace", "adc", "netscaler", "lb", "vip", "api", "app", "apps", "portal", "intranet",
    "extranet", "internal", "external", "int", "ext", "dev", "test", "qa", "stage", "staging", "prod", "uat", "pre", "dmz", "lan",
    "wan", "ocsp", "crl", "pki", "ca", "cdp", "aia", "files", "ftp", "sftp", "git", "wiki", "jira", "confluence", "sharepoint",
    "teams", "lync", "sip", "meet", "dialin", "rds", "rdweb", "rdgw", "vdi", "horizon", "files", "backup", "monitor", "monitoring",
    "admin", "mgmt", "management", "console", "cloud", "edge", "cdn", "static", "assets", "img", "media", "m", "mobile",
}
INTERNAL_TLDS = {"local", "lan", "corp", "intern", "internal", "intranet", "home", "ad", "int", "private", "localdomain", "loc",
                 "priv", "domain", "office", "net-int"}
# Public vendor/CA domains: not customer data, kept so that e.g. OCSP/CRL, IdP and Citrix Cloud targets stay recognizable
VENDOR_DOMAINS = ("citrix.com", "cloud.com", "citrixworkspacesapi.net", "netscaler.com", "microsoft.com", "microsoftonline.com",
                  "windows.net", "office.com", "office365.com", "live.com", "azure.com", "azurewebsites.net", "google.com",
                  "googleapis.com", "gstatic.com", "apple.com", "okta.com", "oktapreview.com", "duosecurity.com", "digicert.com",
                  "letsencrypt.org", "lencr.org", "sectigo.com", "globalsign.com", "globalsign.net", "entrust.net", "verisign.com",
                  "godaddy.com", "usertrust.com", "comodoca.com", "identrust.com", "amazonaws.com", "example.com", "example.org",
                  "example.net", "example", "invalid", "test", "localhost")
SAFE_PATH = {"citrix", "store", "storeweb", "web", "vpn", "cgi", "logon", "login", "logout", "auth", "receiver", "nf", "api",
             "saml", "oauth", "adfs", "ls", "wsfed", "idp", "sso", "owa", "ecp", "ews", "mapi", "rpc", "autodiscover",
             "microsoft-server-activesync", "oab", "metadata", "federationmetadata", "2007-06", "federationmetadata.xml",
             "certsrv", "ocsp", "crl", "pki", "favicon.ico", "index.html", "default.htm", "default.aspx", "home", "portal",
             "authentication", "callback", "token", "authorize", "userinfo", "discovery", "keys", "v1", "v2", "v3", "well-known",
             ".well-known", "openid-configuration", "storefront", "discovery", "cgi-bin", "menu", "epa", "scripts", "static",
             "logon.html", "setclient", "resources", "auth.html", "pcp", "xml", "admin", "ica", "launch", "sessions"}
# Words inside expression literals that are product/protocol vocabulary (kept)
SAFE_WORDS = SAFE_PATH | SAFE_LOWER | {
    "host", "user-agent", "cookie", "set-cookie", "authorization", "accept", "accept-encoding", "accept-language",
    "content-type", "content-length", "location", "referer", "origin", "x-forwarded-for", "x-forwarded-proto",
    "x-forwarded-host", "x-real-ip", "x-citrix-via", "x-citrix-via-vip", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "content-security-policy", "server", "via", "connection", "upgrade", "cache-control",
    "pragma", "expires", "etag", "max-age", "includesubdomains", "preload", "nosniff", "deny", "sameorigin", "secure",
    "httponly", "samesite", "lax", "strict", "path", "domain", "get", "post", "put", "delete", "head", "options",
    "citrixreceiver", "citrix receiver", "mozilla", "windows", "android", "iphone", "ipad", "mac", "linux", "chrome",
    "firefox", "safari", "edge", "msie", "trident", "html", "json", "text", "application", "javascript", "css", "png",
    "jpg", "gif", "svg", "ico", "woff", "woff2", "ttf", "xml", "utf-8", "gzip", "deflate", "br", "keep-alive", "close",
    "request", "response", "override", "symmetric", "asymmetric", "ascii", "utf_8", "unicode", "next", "end", "noop",
    "allow", "deny", "drop", "reset", "other", "enabled", "disabled", "both", "client", "header", "body", "query", "method",
    "storeweb", "nsc_", "nsc_tmas", "nsc_aaac", "nsc_tass", "pwcount", "csrftoken", "aspxauth", "redirect", "true", "false",
    # login vocabulary (field names in forms, schemas and expressions; no customer data)
    "password", "passwd", "passcode", "username", "user", "login", "logon", "otp", "token", "credentials", "credential",
    "email", "submit", "form", "account", "newpassword", "oldpassword", "confirmpassword", "password1", "password2",
}

# internal services of the appliance (nshttps-127.0.0.1-443, nsrpcs-::1l-3008, ...): the prefix is product vocabulary
_INTERNAL_SVC = re.compile(r"^(nshttps|nshttp|nsrpcs|nskrpcs|nsrpc|nssslvpn|nsrnatsip|nsdns|nsntp|nssnmp|nsssh|nsgui)-(.+)-(\d+)$", re.I)
ACTION_WORDS = {"apply", "save", "clear", "reset", "flush", "sync", "force", "ns", "acls", "acls6", "pbrs", "pbrs6", "simpleacls",
                "simpleacls6", "config", "rnat", "rnat6", "nat", "all", "basic", "extended", "full", "cache", "objects", "ha",
                "files", "cluster", "running", "-level", "-force"}
_ENUM = re.compile(r"^[A-Z0-9_.:/*+-]+$")
_NUM = re.compile(r"^[+-]?\d+(\.\d+)?$|^\d+(,\d+)*$|^\d+-\d+$")
_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_MAC = re.compile(r"(?<![\w:-])[0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}(?![\w:-])")
_NET = re.compile(r"(?P<mac>(?<![\w:-])[0-9a-fA-F]{2}(?P<sep>[:-])[0-9a-fA-F]{2}(?:(?P=sep)[0-9a-fA-F]{2}){4}(?![\w:-]))|"
                  r"(?P<v4>(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.]))|"
                  r"(?P<v6>(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:]))")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_FQDN = re.compile(r"(?<![\w@-])(?<!\w\.)(?:\*\.)?(?:[a-z0-9-]+\.)+(?:com|net|org|de|at|ch|eu|io|info|biz|cloud|local|lan|corp|intern|"
                   r"internal|intranet|home|ad|int|private|localdomain|loc|priv|[a-z]{2})(?![\w-])", re.I)
_URL = re.compile(r"\b(https?|ldaps?|ftp|sftp|wss?)://([^/\s\"':?#]+)(:\d+)?((?:/[^\s\"'?#]*)?)(\?[^\s\"'#]*)?", re.I)
_DN_DC = re.compile(r"(?i)\bDC=[^,()\"]+(?:\s*,\s*DC=[^,()\"]+)*")
_DN_RDN = re.compile(r"(?i)\b(CN|OU|O|L|ST|C|UID)=([^,()\"]+)")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
_SUFFIX2 = {"co", "com", "org", "net", "gv", "ac", "or", "ne", "gov", "edu"}


class Anonymizer:
    def __init__(self, keep_literals: bool = False, options: dict | None = None):
        self.opt = {**DEFAULT_OPTIONS, **(options or {})}
        self.opt["secrets"] = True
        if keep_literals:  # backwards compatible CLI flag
            self.opt["literals"] = False
        self.names: dict[str, str] = {}
        self._odd: list[str] = []
        self._produced_ips: set[str] = set()  # names with characters outside [\w.-]
        self.ips: dict[str, str] = {}
        self.subnets: dict[tuple, int] = {}
        self.v6: dict[str, str] = {}
        self.macs: dict[str, str] = {}
        self.hosts: dict[str, str] = {}      # fqdn / e-mail -> pseudonym
        self.domains: dict[str, str] = {}    # registrable domain -> pseudonym domain
        self.labels: dict[str, str] = {}     # customer label -> hN
        self.paths: dict[str, str] = {}
        self.words: dict[str, str] = {}
        self.texts: dict[str, str] = {}
        self.files: dict[str, str] = {}
        self.counts = Counter()
        self._sensitive: set[str] = set()
        self._keywords: set[str] = set()
        self._private_names: set[str] = set()  # FQDNs that resolve to a private IP in the configs (internal evidence)
        self._dom_n = {"int": 0, "ext": 0}

    # ---- mappings -------------------------------------------------------------------------
    def _name(self, original: str, kind: str = "obj") -> str:
        if original not in self.names:
            self.names[original] = f"{kind}_{len(self.names) + 1:04d}"
            if len(original) >= 3 and not re.fullmatch(r"[\w.-]+", original):
                self._odd.append(original)
        self._sensitive.add(original)
        return self.names[original]

    def _ip(self, m: re.Match) -> str:
        whole = m.group(0)
        if not self.opt["ips"]:
            return whole
        a, b, c, d = m.groups()
        if any(int(x) > 255 for x in (a, b, c, d)):
            return whole
        if int(a) in (0, 127, 255) or int(a) >= 224 or whole in ("0.0.0.0",):
            return whole  # netmasks, wildcard, loopback, multicast
        ip = ipaddress.ip_address(whole)
        priv = ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")
        key = ("p" if priv else "g", a, b, c)
        if key not in self.subnets:
            self.subnets[key] = sum(1 for k in self.subnets if k[0] == key[0])
        i = self.subnets[key]
        self._sensitive.add(whole)
        self.counts["ips"] += 1
        # private stays private (10.0.0.0/8), public -> 198.18.0.0/15 (reserved, never routed); /24 grouping and host part kept
        new = f"10.{i // 256 % 256}.{i % 256}.{d}" if priv else f"198.{18 + i // 256 % 2}.{i % 256}.{d}"
        self._produced_ips.add(new)
        return new

    def _v6(self, m: re.Match) -> str:
        s = m.group(0)
        if not self.opt["ips"] or s in ("::", "::1") or not any(ch.isdigit() or ch in "abcdefABCDEF" for ch in s.replace(":", "")):
            return s
        if s not in self.v6:
            self.v6[s] = f"2001:db8::{len(self.v6) + 1:x}"
        self._sensitive.add(s)
        return self.v6[s]

    def _mac(self, m: re.Match) -> str:
        s = m.group(0)
        if not self.opt["ips"]:
            return s
        if s.lower() not in self.macs:
            n = len(self.macs) + 1
            self.macs[s.lower()] = f"02:00:00:{n >> 16 & 255:02x}:{n >> 8 & 255:02x}:{n & 255:02x}"  # locally administered
        self._sensitive.add(s)
        return self.macs[s.lower()]

    @staticmethod
    def _vendor(h: str) -> bool:
        return any(h == d or h.endswith("." + d) for d in VENDOR_DOMAINS)

    def _reg(self, labels: list[str]) -> int:
        """Number of labels of the registrable domain (acme.de = 2, acme.co.uk = 3)."""
        if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SUFFIX2:
            return 3
        return min(2, len(labels))

    def _label(self, lab: str) -> str:
        if lab == "*" or re.fullmatch(r"[a-z]+\d{0,3}", lab) and re.sub(r"\d+$", "", lab) in GENERIC_LABELS:
            return lab
        if re.fullmatch(r"[a-z]+-?\d{0,3}", lab) and re.sub(r"-?\d+$", "", lab) in GENERIC_LABELS:
            return lab
        if lab not in self.labels:
            self.labels[lab] = f"h{len(self.labels) + 1}"
        self._sensitive.add(lab) if len(lab) >= 4 else None
        return self.labels[lab]

    def fqdn(self, s: str) -> str:
        """Consistent pseudonym for a host/domain name; internal names end in .internal, external ones in .example."""
        if not self.opt["fqdns"]:
            return s
        low = s.lower().rstrip(".")
        if self._vendor(low) or "." not in low:
            return s
        if low in self.hosts:
            return self.hosts[low]
        if any(low == d or low.endswith("." + d) for d in self.domains.values()):
            return s  # already a pseudonym (text is scrubbed in several passes)
        labels = low.split(".")
        n = self._reg(labels)
        reg, sub = ".".join(labels[-n:]), labels[:-n]
        internal = labels[-1] in INTERNAL_TLDS or low in self._private_names or reg in {self._regof(x) for x in self._private_names}
        if reg not in self.domains:
            k = "int" if internal else "ext"
            self._dom_n[k] += 1
            self.domains[reg] = f"corp{self._dom_n[k]}.internal" if internal else f"company{self._dom_n[k]}.example"
            self._sensitive.add(reg)
        out = ".".join([self._label(x) for x in sub] + [self.domains[reg]])
        self.hosts[low] = out
        self._sensitive.add(low)
        self.counts["fqdns"] += 1
        return out

    def _regof(self, h: str) -> str:
        labels = h.split(".")
        return ".".join(labels[-self._reg(labels):])

    def _fqdn_m(self, m: re.Match) -> str:
        return self.fqdn(m.group(0))

    def _email(self, m: re.Match) -> str:
        s = m.group(0)
        if not self.opt["fqdns"]:
            return s
        local, _, dom = s.partition("@")
        if self._vendor(dom.lower()):
            return s
        key = s.lower()
        if key not in self.hosts:
            self.hosts[key] = f"user{sum(1 for v in self.hosts.values() if v.startswith('user')) + 1}@{self.fqdn(dom)}"
            self._sensitive.add(s)
            self._sensitive.add(local) if len(local) >= 4 else None
            self.counts["emails"] += 1
        return self.hosts[key]

    def _path(self, p: str) -> str:
        if not self.opt["urls"] or not p:
            return p
        out = []
        for seg in p.split("/"):
            low = seg.lower()
            if not seg or low in SAFE_PATH or _NUM.match(seg) or re.fullmatch(r"[\w-]+\.(html?|aspx?|php|js|css|png|gif|ico|jpg|svg|xml|json)", low) and low.split(".")[0] in SAFE_PATH:
                out.append(seg)
                continue
            if seg not in self.paths:
                self.paths[seg] = f"p{len(self.paths) + 1}"
            if len(seg) >= 4:
                self._sensitive.add(seg)
            out.append(self.paths[seg])
        return "/".join(out)

    def _url(self, m: re.Match) -> str:
        scheme, host, port, path, query = m.group(1), m.group(2), m.group(3) or "", m.group(4) or "", m.group(5) or ""
        if host in self.names:  # URL that uses a server name defined in the config (https://sf01/...)
            host = self.names[host]
        elif is_ip(host):
            host = _IPV4.sub(self._ip, host)
        else:
            host = self.fqdn(host)
        if query and self.opt["urls"]:
            query = "?" + "&".join((kv.split("=", 1)[0] + ("=v" if "=" in kv else "")) for kv in query[1:].split("&"))
        self.counts["urls"] += 1
        return f"{scheme}://{host}{port}{self._path(path)}{query}"

    def _file(self, original: str) -> str:
        if not self.opt["files"]:
            return original
        d, _, base = original.replace("\\", "/").rpartition("/")
        keep_dir = d if d.startswith(("/nsconfig", "/var/netscaler", "/flash/nsconfig")) else ""
        if base not in self.files:
            ext = Path(base).suffix[:8] if re.fullmatch(r"\.[A-Za-z0-9]{1,6}", Path(base).suffix) else ""
            self.files[base] = f"file_{len(self.files) + 1:04d}{ext}"
        self._sensitive.add(base) if len(Path(base).stem) >= 4 else None
        self.counts["files"] += 1
        return (keep_dir + "/" if keep_dir else "") + self.files[base]

    def _dn(self, text: str) -> str:
        """LDAP DNs/filters: DC= sequences follow the domain mapping, other RDN values become pseudonyms."""
        def dc(m: re.Match) -> str:
            parts = [p.split("=", 1)[1].strip() for p in re.split(r"\s*,\s*", m.group(0))]
            mapped = self.fqdn(".".join(parts)) if self.opt["fqdns"] and len(parts) > 1 else ".".join(parts)
            return ",".join("DC=" + x for x in mapped.split("."))

        def rdn(m: re.Match) -> str:
            k, v = m.group(1), m.group(2).strip()
            if v.lower() in {"users", "computers", "groups", "builtin", "domain users", "domain admins", "system", "configuration"} or v == "*":
                return f"{k}={v}"
            return f"{k}={self._text(v, 'dn')}"
        text = _DN_DC.sub(dc, text)
        return _DN_RDN.sub(rdn, text)

    def _text(self, s: str, kind: str = "text") -> str:
        if not self.opt["text"]:
            return s
        if s not in self.texts:
            self.texts[s] = f"{kind}{len(self.texts) + 1}"
        self._sensitive.add(s) if len(s) >= 4 else None
        self.counts["text"] += 1
        return self.texts[s]

    def scrub(self, text: str) -> str:
        """Replace secrets-like hex blobs, URLs, e-mails, IPs, MACs and host names inside any text."""
        text = _HEX.sub(lambda m: "0" * len(m.group(0)), text)
        out, pos = [], 0
        for m in _URL.finditer(text):  # each part is replaced exactly once (no second pass over a pseudonym)
            out.append(self._scrub_plain(text[pos:m.start()]))
            out.append(self._url(m))
            pos = m.end()
        out.append(self._scrub_plain(text[pos:]))
        return "".join(out)

    def _scrub_plain(self, text: str) -> str:
        if not text:
            return text
        out, pos = [], 0
        for m in _EMAIL.finditer(text):
            out.append(self._scrub_net(text[pos:m.start()]))
            out.append(self._email(m))
            pos = m.end()
        out.append(self._scrub_net(text[pos:]))
        return "".join(out)

    def _scrub_net(self, text: str) -> str:
        if not text:
            return text
        rx = _NET
        # MAC/IPv4/IPv6 in one pass, then host names in the untouched parts
        out, pos = [], 0
        for m in rx.finditer(text):
            out.append(_FQDN.sub(self._fqdn_m, text[pos:m.start()]))
            k = "mac" if m.group("mac") else "v4" if m.group("v4") else "v6"
            frag = m.group(0)
            out.append(_MAC.sub(self._mac, frag) if k == "mac" else _IPV4.sub(self._ip, frag) if k == "v4" else _IPV6.sub(self._v6, frag))
            pos = m.end()
        out.append(_FQDN.sub(self._fqdn_m, text[pos:]))
        return "".join(out)

    # ---- names known from the model ------------------------------------------------------
    @staticmethod
    def _is_builtin_name(n: str) -> bool:
        low = n.lower()
        return (n.upper() in KEYWORD_NAMES or low in BUILTIN_MONITORS or n in BUILTIN_CERTS or low in SAFE_LOWER
                or low.endswith(("-ecv", "-default")) or bool(_INTERNAL_SVC.match(n))
                or low.startswith(("ns_", "nstcp_", "nshttp_", "default", "_")) or (n.upper() == n and "-" in n))

    def learn(self, cfg: Config) -> None:
        for et, ents in cfg.entities.items():
            cat = "users" if et in USER_ETYPES else ("hostnames" if et in HOST_ETYPES else "names")
            if not self.opt[cat]:
                continue
            for name in ents:
                if name and not self._is_builtin_name(name) and not is_ip(name) and not _NUM.match(name) \
                        and not re.fullmatch(r"(LA/)?\d+(/\d+)*", name) and not (_FQDN.fullmatch(name) and "." in name) \
                        and not _IPV6.fullmatch(name):
                    kind = "user" if et in ("system user", "aaa user", "vpn user", "snmp user") else (
                        "group" if cat == "users" else re.sub(r"[^a-z]", "", et.replace(" ", ""))[:16] or "obj")
                    self._name(name, kind)
        for st in cfg.statements:
            if st.etype == "ns hostname" and st.args and self.opt["hostnames"]:
                self._name(st.args[0], "adc")
            if st.verb == "add" and st.etype == "dns addrec" and len(st.args) >= 2 and is_ip(st.args[1]):
                if ipaddress.ip_address(st.args[1]).is_private:
                    self._private_names.add(st.args[0].lower().rstrip("."))
        for e in cfg.of("server").values():  # add server <name> <fqdn>: a name used by a server with a private IP elsewhere
            if len(e.args) > 1 and not is_ip(e.args[1]) and "." in e.args[1] and is_ip(e.name) and ipaddress.ip_address(e.name).is_private:
                self._private_names.add(e.args[1].lower())

    # ---- token level ----------------------------------------------------------------------
    _TOKEN = re.compile(r"[\w.-]+")

    def _replace_known_names(self, s: str) -> str:
        """Known object names inside a text (word boundaries as in ns.conf names: letters, digits, '_', '.', '-')."""
        def rep(m: re.Match) -> str:
            x = m.group(0)
            return self.names.get(x, x) if len(x) >= 3 else x
        s = self._TOKEN.sub(rep, s)
        for n in self._odd_names():  # names with other characters (rare): plain replacement
            if n in s:
                s = s.replace(n, self.names[n])
        return s

    def _odd_names(self) -> list[str]:
        return self._odd

    _EXPR = re.compile(r"\b(HTTP|CLIENT|SERVER|SYS|AAA|TEXT|DNS|SIP|DIAMETER|MSSQL|MYSQL|ORACLE|RADIUS|ANALYTICS|TARGET|SUBSCRIBER|"
                       r"IPV6|IP|TCP|UDP|VPN|SMPP|MQTT|ICA|SSL|CONNECTION|LDAP|SPEC|PLUGIN|URL|STREAM|HTTP2)\.[A-Z_]+|\(|^(true|false)$", re.I)

    def _words(self, s: str) -> str:
        """Customer words inside expression literals -> wN; product/protocol vocabulary and pseudonyms stay."""
        def w(m: re.Match) -> str:
            x = m.group(0)
            if (x.lower() in SAFE_WORDS or x in self.names.values() or re.fullmatch(r"(h|p|w|text|dn)\d+|corp\d+|company\d+|internal|example|user\d+", x)
                    or re.fullmatch(r"[a-z]+\d{0,3}", x.lower()) and re.sub(r"\d+$", "", x.lower()) in GENERIC_LABELS):
                return x
            if not self.opt["fqdns"]:  # names of hosts stay as they are when FQDNs are kept
                a, b = m.start(), m.end()
                while a > 0 and re.match(r"[\w.-]", m.string[a - 1]):
                    a -= 1
                while b < len(m.string) and re.match(r"[\w.-]", m.string[b]):
                    b += 1
                if _FQDN.fullmatch(m.string[a:b]) or "@" in m.string[max(0, a - 1):b]:
                    return x
            if x not in self.words:
                self.words[x] = f"w{len(self.words) + 1}"
            self._sensitive.add(x) if len(x) >= 4 else None
            return self.words[x]
        return _WORD.sub(w, s)

    def _literal(self, m: re.Match | None, raw: str = "") -> str:
        if m is None:
            return self.scrub(raw)
        inner = m.group(1)
        if not inner:
            return m.group(0)
        s = self.scrub(self._replace_known_names(inner))
        if self.opt["literals"]:
            s = self._words(s)
            self.counts["literals"] += 1
        return '"' + s + '"'

    _QLIT = re.compile(r"\bq([/|~^!#%&*+,.:;=?@`'-])(.*?)\1", re.S)

    def _code(self, p: str) -> str:
        """Expression code outside "..." literals: q/.../ literals, names and IPs."""
        def ql(m: re.Match) -> str:
            lit = self._literal(re.match(r"(.*)", m.group(2), re.S))
            return "q" + m.group(1) + lit[1:-1] + m.group(1)
        p = self._QLIT.sub(ql, p)
        return _IPV4.sub(self._ip, self._replace_known_names(p))

    def _quoted(self, s: str) -> str:
        if s in self.names:
            return self.names[s]
        if self._EXPR.search(s):  # expression: keep structure, replace names, hosts, IPs and customer words in literals
            parts = re.split(r'("(?:[^"\\]|\\.)*")', s)  # literals vs. expression code
            return "".join(self._literal(re.match(r'"(.*)"', p, re.S), p) if p.startswith('"') else self._code(p) for p in parts)
        s2 = self.scrub(self._replace_known_names(s))
        return self._words(s2) if self.opt["literals"] else s2

    def _value(self, t: Token, opt: str | None, etype: str) -> str:
        s = t.text
        low = (opt or "").lower()
        if not s:
            return s
        if low in SECRETS or s == "***":
            self.counts["secrets"] += 1
            return "removed"
        if low in FILE_OPTS:
            return self._file(s)
        mi = _INTERNAL_SVC.match(s)
        if mi:
            return f"{mi.group(1)}-{self.scrub(mi.group(2))}-{mi.group(3)}"
        if re.match(r"^/(nsconfig|var|flash)/", s) or re.search(r"\.(pem|crt|cer|der|pfx|p12|key|crl|xml|cert|csr|txt|html?|js|css|lic)$", s, re.I) and not "://" in s:
            return self._file(s)
        if etype in ("policy patset", "policy dataset", "policy stringmap") and opt is None:
            return self._quoted(s) if not s in self.names else self.names[s]
        if low in KEEP_OPTS or s.lower() in SAFE_VALUES:
            return s
        if low == "timezone" or (etype in DROP_ETYPES["location"] and not is_ip(s) and low not in FILE_OPTS):
            return s  # time zone and GeoIP qualifiers stay unless removed on request (addresses are still replaced)
        if low in ("comment", "location"):  # kept as written; addresses, host names and object names inside are replaced
            self.counts["kept_" + low] += 1
            return self.scrub(s)
        if low in URLISH_OPTS:
            return self.scrub(s)
        if low in USER_OPTS:
            return self._name(s, "user") if self.opt["users"] else s
        if low in TEXT_OPTS:
            if "=" in s and re.search(r"(?i)\b(dc|cn|ou)=", s):
                return self._dn(self.scrub(s))
            if _FQDN.fullmatch(s) or _EMAIL.fullmatch(s) or "://" in s:
                return self.scrub(s)
            if s in self.names:
                return self.names[s]
            return self._text(s, "dom" if low in ("ssodomain", "domain", "userdomain") else "text")
        if t.quoted:
            return self._quoted(s)
        if s in self.names:
            return self.names[s]
        if is_ip(s) or _NUM.match(s) or _ENUM.match(s) or self._is_builtin_name(s):
            return self.scrub(s)
        if (_IPV6.fullmatch(s) or _MAC.fullmatch(s) or _EMAIL.fullmatch(s) or _FQDN.fullmatch(s) or "://" in s or re.search(r"/\d{1,2}$", s)
                or re.fullmatch(r"[\w.-]+\.[a-z]{2,}:\d+", s, re.I)):
            return self.scrub(s)
        if not self.opt["names"]:
            return s
        return self._name(s)  # unknown mixed/lower-case value: treat as a name

    def line(self, raw: str) -> str | None:
        s = raw.strip()
        if not s:
            return None
        if s.startswith("#"):
            if re.match(r"#NS\d", s):
                return s
            if self.opt["comments"]:
                self.counts["removed_comments"] += 1
                return None
            self.counts["kept_comment"] += 1
            return self.scrub(s)
        toks = tokenize(s)
        if len(toks) == 1 and toks[0].text.lower() in ("done", "save"):
            return s
        if len(toks) < 2:
            return None
        verb = toks[0].text.lower()
        if verb not in ("add", "set", "bind", "unbind", "rm", "unset", "link", "unlink", "enable", "disable", "show") and \
                all(t.text.lower() in ACTION_WORDS for t in toks):
            return s  # apply ns acls, save ns config, ...: only product words
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
        for cat, ets in DROP_ETYPES.items():
            if self.opt[cat] and etype in ets:
                self.counts["removed_" + cat] += 1
                return None
        drop = set().union(*(v for k, v in DROP_OPTS.items() if self.opt[k]))
        skipping = False
        pos = 0
        for i, t in enumerate(toks):
            if i < n_type:
                out.append(t.text)
                continue
            if is_option(t):
                opt = t.text[1:]
                skipping = opt.lower() in drop
                if skipping:
                    self.counts["removed_" + next(k for k, v in DROP_OPTS.items() if opt.lower() in v)] += 1
                else:
                    out.append(t.text)
                continue
            if skipping:
                continue
            if opt is None:
                if POSITIONAL_SECRETS.get(etype) == pos and t.text and verb in ("add", "set"):
                    new = "removed"
                    self.counts["secrets"] += 1
                else:
                    new = self._value(t, None, etype)
                pos += 1
            else:
                new = self._value(t, opt, etype)
            out.append(self._quote(new, t.quoted))
        return " ".join(out)

    @staticmethod
    def _quote(s: str, was_quoted: bool) -> str:
        if not was_quoted and s and not re.search(r"\s|\"", s):
            return s
        return quote(s)

    def text(self, raw: str) -> str:
        out = []
        for ln in raw.splitlines():
            r = self.line(ln)
            if r:
                out.append(r)
        return self.finalize("\n".join(out) + "\n")

    def finalize(self, text: str) -> str:
        """Last safety pass: an original that was replaced somewhere but survived elsewhere (e.g. inside a display text or a
        value without a known type) is replaced by its pseudonym everywhere. Options, command words and product vocabulary
        are never touched; the structure check afterwards shows whether this changed anything."""
        table: dict[str, str] = {}
        for src in (self.words, self.paths, self.texts, self.labels, self.names):
            for k, v in src.items():
                if (len(k) >= 4 and k not in self._keywords and k.lower() not in SAFE_WORDS and k.lower() not in ACTION_WORDS
                        and not _ENUM.fullmatch(k) and not _NUM.match(k)):
                    table.setdefault(k, v)
        if not table:
            return text
        rx = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(map(re.escape, sorted(table, key=len, reverse=True))) + r")(?![A-Za-z0-9])")

        def rep(m: re.Match) -> str:
            i = m.start()
            if i > 0 and text[i - 1] == "-" and (i < 2 or text[i - 2].isspace()):
                return m.group(0)  # an option name (-send), not a value
            if not self.opt["fqdns"]:
                a, b = i, m.end()
                while a > 0 and re.match(r"[\w.@-]", text[a - 1]):
                    a -= 1
                while b < len(text) and re.match(r"[\w.@-]", text[b]):
                    b += 1
                if _FQDN.fullmatch(text[a:b]) or _EMAIL.fullmatch(text[a:b]):
                    return m.group(0)
            self.counts["final_pass"] += 1
            return table[m.group(1)]
        return rx.sub(rep, text)

    def leaks(self, anonymized: str) -> list[str]:
        """Original sensitive strings that still appear in the output (should be empty). Never printed, only counted."""
        produced = set(self.names.values()) | set(self.hosts.values()) | set(self.domains.values()) | set(self.files.values())
        bad = []
        tokens = set(re.findall(r"[\w.@:/-]+", anonymized)) | set(re.findall(r"\w+", anonymized))
        for s in self._sensitive:
            if len(s) < 4 or s in produced or s in self._produced_ips or s in self._keywords or s.lower() in SAFE_WORDS or s.endswith((".example", ".internal")):
                continue
            if re.fullmatch(r"[\w.@:/-]+", s):
                if s in tokens:
                    bad.append(s)
            elif s in anonymized:
                bad.append(s)
        return bad


# ---- structure check: nothing may get lost ------------------------------------------------------------
def structure(text: str) -> Counter:
    """Content-free signature of a config: statements by verb/type, objects by kind, connections by type, missing refs."""
    cfg = Config.parse_text(text, name="x")
    g = Graph(cfg, "g", True)
    sig = Counter()
    for st in cfg.statements:
        sig[f"stmt:{st.verb} {st.etype}"] += 1
    for n in g.nodes.values():
        sig[f"obj:{n.kind}"] += 1
    for e in g.edges:
        sig[f"conn:{e.type}"] += 1
    sig["missing"] += len(g.missing)
    sig["frontends"] += len(g.frontends)
    return sig


def compare(a: Counter, b: Counter) -> list[str]:
    keys = sorted(set(a) | set(b))
    return [f"{k}: {a.get(k, 0)} -> {b.get(k, 0)}" for k in keys if a.get(k, 0) != b.get(k, 0)]


def anonymize_texts(items: list[tuple[str, str]], options: dict | None = None, keep_literals: bool = False) -> tuple[list[tuple[str, str]], dict, "Anonymizer"]:
    """Anonymize several configs consistently. Returns [(new name, text)], content-free statistics and the anonymizer."""
    configs = [(n, t) for n, t in items if re.search(r"^\s*(add|set|bind|enable|link)\s", t, re.M)]
    an = Anonymizer(keep_literals, options)
    for n, t in configs:
        an.learn(Config.parse_text(t, name=n))
    out, diffs, leaks, sin, sout, review = [], [], 0, 0, 0, []
    for i, (n, t) in enumerate(configs, 1):
        res = an.text(t)
        low = n.lower()
        marker = "-primary" if re.search(r"primary|[-_.]pri[-_.]|\bpri\b", low) else (
            "-secondary" if re.search(r"secondary|[-_.]sec[-_.]|\bsec\b", low) else "")
        out.append((f"device-{i:03d}{marker}.conf", res))
        a, b = structure(t), structure(res)
        for cat, ets in DROP_ETYPES.items():  # statements removed on request are not a loss
            if an.opt[cat]:
                for k in [k for k in a if k.startswith("stmt:") and k.split(" ", 1)[-1] in ets]:
                    del a[k]
        sin += sum(v for k, v in a.items() if k.startswith("stmt:"))
        sout += sum(v for k, v in b.items() if k.startswith("stmt:"))
        d = compare(a, b)
        diffs.append(d)
        lk = an.leaks(res)
        leaks += len(lk)
        if lk:  # where to look (shown only locally: GUI/CLI); never part of the anonymized output
            lines = res.splitlines()
            for v in sorted(lk)[:200]:
                rx = re.compile(r"(?<![\w.@-])" + re.escape(v) + r"(?![\w.@-])") if re.fullmatch(r"[\w.@:/-]+", v) else None
                ln = next((k for k, x in enumerate(lines, 1) if (rx.search(x) if rx else v in x)), 0)
                review.append({"file": out[-1][0], "line": ln, "value": v})
    st = {"files": len(configs), "skipped": len(items) - len(configs), "statements_in": sin, "statements_out": sout,
          "structure_ok": all(not d for d in diffs), "structure_diffs": [d[:20] for d in diffs], "names": len(an.names),
          "ips": len(an.subnets), "hosts": len(an.hosts), "leaks": leaks, "review": review, "counts": dict(an.counts),
          "options": {k: v for k, v in an.opt.items()}}
    return out, st, an


def mapping(an: Anonymizer) -> dict:
    return {"names": an.names, "hosts": an.hosts, "domains": an.domains, "labels": an.labels, "paths": an.paths,
            "words": an.words, "texts": an.texts, "files": an.files, "macs": an.macs}


def anonymize_paths(paths: list[str], out_dir: str, keep_literals: bool = False, map_file: str | None = None,
                    options: dict | None = None) -> dict:
    """Anonymize all config files below ``paths`` into ``out_dir``. Returns aggregate, content-free statistics."""
    import json

    files = []
    for p in paths:
        pp = Path(p)
        files += sorted(f for f in (pp.rglob("*") if pp.is_dir() else [pp]) if f.is_file() and not f.name.startswith("."))
    items = [(f.name, f.read_text(encoding="utf-8", errors="replace")) for f in files]
    out, st, an = anonymize_texts(items, options, keep_literals)
    od = Path(out_dir)
    od.mkdir(parents=True, exist_ok=True)
    for name, text in out:
        (od / name).write_text(text, encoding="utf-8")
    if map_file:
        Path(map_file).write_text(json.dumps(mapping(an), ensure_ascii=False, indent=1), encoding="utf-8")
    return st
