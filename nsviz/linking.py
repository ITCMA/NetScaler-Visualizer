"""Cross-device linking: which service/server in config A points to which vServer in config B?

A NetScaler usually addresses its backends by IP, but a service may also point to an FQDN (``add server s1 app.example.com``)
while the next device only knows the IP of its vServer. The tool cannot decide that on its own. This module therefore

* collects the *sources* (service/service group targets with an FQDN) and the *targets* (vServers of other groups with IP:port)
  together with the signals needed to suggest a pairing (scoring happens in the report so that a hosts file can be applied
  there without a new run),
* reads/writes the mapping file (confirmed/rejected links, FQDN->IP hosts),
* applies confirmed links to the project (edge, chain, check),
* optionally resolves the FQDNs by DNS (only when the user asks for it explicitly, see ``resolve_names``).

Nothing is linked automatically: every link needs a confirmation by the user (or an entry in the mapping file).
"""
from __future__ import annotations

import json
import re
import socket
import struct
from pathlib import Path

from .model import Edge, is_ip
from .rules import Finding, render_messages

MAP_FORMAT = "nsviz-links"
MAP_VERSION = 1


def node_key(project, node_id: str) -> str:
    """Stable key of a node across runs: ``<group name>|<object type>|<name>`` (no internal ids)."""
    for g in project.groups:
        n = g.graph.nodes.get(node_id)
        if n:
            return f"{g.name}|{n.etype}|{n.name}"
    return ""


def node_by_key(project, key: str) -> str:
    parts = key.split("|", 2)
    if len(parts) != 3:
        return ""
    for g in project.groups:
        if g.name == parts[0]:
            for n in g.graph.nodes.values():
                if n.etype == parts[1] and n.name == parts[2]:
                    return n.id
    return ""


def _cert_strings(g, node_id: str) -> list[str]:
    out: list[str] = []
    for e in g.graph.edges:
        if e.source == node_id and e.type == "ssl":
            c = g.graph.nodes.get(e.target)
            if c and c.kind == "cert":
                out += [c.name, c.props.get("Certificate", "")]
    return [x for x in out if x]


def collect(project) -> dict:
    """Sources and targets for the report. Sources: service/service group members whose host is an FQDN (not an IP)."""
    sources, targets, seen = [], [], set()  # sources: service targets with an FQDN and URL targets that match no local vServer
    for g in project.groups:
        for be in g.graph.backends:
            host = be["host"]
            if not host or is_ip(host) or (be["node"], host) in seen:
                continue
            seen.add((be["node"], host))
            sources.append({"node": be["node"], "group": g.id, "name": be["name"], "etype": be["etype"], "host": host,
                            "port": be["port"], "proto": be["proto"], "key": node_key(project, be["node"])})
        for u in g.graph.unresolved:  # session action / STA URL targets: FQDN or an address that is not a local vServer
            if (u["node"], u["host"]) in seen or u.get("resolved") or u.get("silent"):
                continue
            seen.add((u["node"], u["host"]))
            nd = g.graph.nodes[u["node"]]
            sources.append({"node": u["node"], "group": g.id, "name": nd.name, "etype": nd.etype, "host": u["host"], "port": u["port"],
                            "proto": u["via"], "url": True, "key": node_key(project, u["node"])})
        for fe in g.graph.frontends:
            targets.append({"node": fe["node"], "group": g.id, "name": fe["name"], "ip": fe["ip"], "port": fe["port"],
                            "proto": fe["proto"], "certs": _cert_strings(g, fe["node"]), "key": node_key(project, fe["node"])})
    return {"sources": sources, "targets": targets}


# ---- Files -------------------------------------------------------------------------------------
def parse_hosts_text(text: str) -> dict[str, str]:
    """hosts format (``ip name [name ...]``) or CSV/semicolon (``name;ip`` or ``ip;name``); ``#`` starts a comment."""
    hosts: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        toks = [t for t in re.split(r"[\s,;]+", line) if t]
        ips = [t for t in toks if is_ip(t)]
        names = [t for t in toks if not is_ip(t)]
        if len(ips) == 1:
            for nm in names:
                hosts[nm.lower().rstrip(".")] = ips[0]
    return hosts


def load_hosts(path: str) -> dict[str, str]:
    return parse_hosts_text(Path(path).read_text(encoding="utf-8-sig"))


def load_map(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != MAP_FORMAT:
        raise ValueError(f"{path}: not a {MAP_FORMAT} file")
    if int(data.get("version", 0)) > MAP_VERSION:
        raise ValueError(f"{path}: map version {data.get('version')} is newer than supported ({MAP_VERSION})")
    data.setdefault("hosts", {})
    data.setdefault("links", [])
    return data


def apply_map(project, data: dict) -> list[str]:
    """Confirmed links of the map file become edges/chain entries; returns warnings (unknown keys)."""
    warn: list[str] = []
    gof = {}
    for g in project.groups:
        for nid in g.graph.nodes:
            gof[nid] = g
    for l in data.get("links", []):
        if l.get("status") != "confirmed":
            continue
        a, b = node_by_key(project, l.get("from", "")), node_by_key(project, l.get("to", ""))
        if not a or not b:
            warn.append(f"link not found in these configs: {l.get('from')} -> {l.get('to')}")
            continue
        ga, gb = gof[a], gof[b]
        na, nb = ga.graph.nodes[a], gb.graph.nodes[b]
        be = next((x for x in ga.graph.backends if x["node"] == a), None)
        fe = next((x for x in gb.graph.frontends if x["node"] == b), None)
        proto = be["proto"] if be else na.props.get("Protocol", "")
        port = be["port"] if be else ""
        host = be["host"] if be else ""
        label = "Link " + (f"{host}:{port}" if host else "") + (" (confirmed)" if not l.get("manual") else " (manual)")
        project.extra_edges.append(Edge(a, b, "link", label.replace("  ", " ").strip(), True))
        if ga is not gb:
            project.links.append({"from_group": ga.id, "to_group": gb.id, "from_node": a, "to_node": b, "host": host, "port": port,
                                  "to_port": fe["port"] if fe else "", "confidence": "confirmed", "proto": proto})
            if proto.upper() in ("HTTP", "TCP"):
                project.findings.append(Finding("CHAIN-002", "medium", render_messages("CHAIN-002", src=na.name, proto=proto, dst=nb.name, dev=gb.devices[0].name),
                                                ga.devices[0].name, na.etype, na.name, ga.devices[0].cfg.name, 0, [], a))
    return warn


# ---- DNS (only on explicit request: `nsviz resolve`) -------------------------------------------------
def fqdns(project) -> list[str]:
    return sorted({s["host"].lower() for s in collect(project)["sources"] if "." in s["host"]})


def _query_a(name: str, server: str, port: int = 53, timeout: float = 3.0) -> list[str]:
    qid = 0x1A2B
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode("idna")
    q += b"\x00" + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, port))
        data, _ = s.recvfrom(2048)
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
        return []
    an = struct.unpack(">H", data[6:8])[0]
    i = 12
    while data[i] != 0:  # skip the question name
        i += data[i] + 1
    i += 5
    ips: list[str] = []
    for _ in range(an):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i] != 0:
                i += data[i] + 1
            i += 1
        typ, _cls, _ttl, ln = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if typ == 1 and ln == 4:
            ips.append(".".join(str(b) for b in data[i:i + 4]))
        i += ln
    return ips


def resolve_names(names: list[str], server: str = "") -> dict[str, str]:
    """Resolves names (IPv4). ``server`` empty = system resolver, else ``ip[:port]`` queried directly."""
    out: dict[str, str] = {}
    for nm in names:
        try:
            if server:
                host, _, p = server.partition(":")
                r = _query_a(nm, host, int(p or 53))
            else:
                r = [x[4][0] for x in socket.getaddrinfo(nm, None, socket.AF_INET, socket.SOCK_STREAM)]
        except (OSError, UnicodeError, IndexError, struct.error):
            r = []
        if r:
            out[nm] = r[0]
    return out
