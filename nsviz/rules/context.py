from __future__ import annotations

from ..model import Graph, redact
from ..parser import Config, Entity, Binding, Statement
from . import Finding, render_messages


class Ctx:
    def __init__(self, cfg: Config, graph: Graph, device: str, rule):
        self.cfg, self.graph, self.device, self.rule = cfg, graph, device, rule

    def ents(self, etype: str) -> list[Entity]:
        return [e for e in self.cfg.of(etype).values() if not e.implicit or e.name == ""]

    def ents_all(self, etype: str) -> list[Entity]:
        return list(self.cfg.of(etype).values())

    def vservers(self, *types: str) -> list[Entity]:
        types = types or ("lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "gslb vserver")
        return [e for t in types for e in self.ents(t)]

    def evidence(self, ent: Entity | None) -> list[str]:
        if not ent:
            return []
        return [redact(s, self.graph.redact) for s in ent.stmts][:6]

    def finding(self, key: str, ent: Entity | None = None, etype: str = "", name: str = "", line: int = 0,
                evidence: list[str] | None = None, severity: str | None = None, **params) -> Finding:
        """Finding from a message key (rules/i18n/messages_*.json); ``{etype}``/``{name}`` are filled from the entity."""
        if ent is not None:
            etype, name = etype or ent.etype, name or ent.name
            line = line or ent.line
        node = self.graph.node_for(etype, name) if etype else None
        return Finding(self.rule.id, severity or self.rule.severity,
                       render_messages(key, **{"etype": etype, "name": name, **params}), self.device,
                       etype, name, self.cfg.name, line,
                       evidence if evidence is not None else self.evidence(ent),
                       node.id if node else self.graph.device_node().id)

    # -- shared helpers -----------------------------------------------------------------
    def ssl_frontends(self) -> list[Entity]:
        """vServers that terminate TLS."""
        out = []
        for t in ("lb vserver", "cs vserver", "vpn vserver", "authentication vserver"):
            for e in self.ents(t):
                if len(e.args) > 1 and e.args[1].upper() in ("SSL", "SSL_TCP", "DTLS"):
                    out.append(e)
        return out

    def effective_ssl(self, vs: Entity) -> dict[str, str]:
        """Effective TLS settings (profile > ssl vserver); missing keys = unknown."""
        sv = self.cfg.get("ssl vserver", vs.name)
        prof_name = sv.opt("sslprofile") if sv else None
        if not prof_name:
            prof_name = vs.opt("sslprofile")
        res: dict[str, str] = {}
        prof = self.cfg.get("ssl profile", prof_name) if prof_name else None
        if not prof and not prof_name:
            sp = self.cfg.single("ssl parameter")
            if sp and (sp.opt("defaultprofile") or "").upper() == "ENABLED":
                prof = self.cfg.get("ssl profile", "ns_default_ssl_profile_frontend")
        for src in (sv, prof):
            if src:
                for k in ("ssl3", "tls1", "tls11", "tls12", "tls13", "denysslreneg", "hsts", "sessreuse"):
                    v = src.opt(k)
                    if v:
                        res[k] = v.upper()
        res["_profile"] = prof_name or ""
        return res

    def cipher_names(self, vs_or_profile: str, etype: str) -> list[str]:
        """Bound ciphers/cipher groups (one level resolved)."""
        names: list[str] = []
        for b in self.cfg.binds(etype, vs_or_profile):
            c = b.opt("ciphername")
            if c:
                names.append(c)
        out = list(names)
        for n in names:
            for b in self.cfg.binds("ssl cipher", n):
                c = b.opt("ciphername") or (b.args[0] if b.args else "")
                if c:
                    out.append(c)
        return out

    def graph_pol_type(self, b):
        """Policy type of a binding (resolved by name in the graph)."""
        name = b.opt("policyname") or b.opt("policy")
        if not name:
            return None
        for et, d in self.cfg.entities.items():
            if et.endswith("policy") and name in d:
                return et
        return None
