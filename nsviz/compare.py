"""Compare two configuration states (for example before and after a change window).

``nsviz compare OLD NEW -o compare.html`` reads both states (files or folders), matches the devices by host name
(or file name) and lists, per device, the objects that were added, removed or changed, down to the changed
configuration lines. In addition it shows which findings are new and which are resolved.
"""
from __future__ import annotations

import collections
import datetime as _dt
import html
import re
from pathlib import Path

from . import __version__
from .model import redact
from .parser import SINGLETONS
from .project import Project

_DEVNO = re.compile(r"\s+-devno\s+\d+")


def _norm(st) -> str:
    return _DEVNO.sub("", re.sub(r"\s+", " ", redact(st, True).strip()))


def _objects(cfg) -> dict[tuple[str, str], collections.Counter]:
    """(object type, name) -> multiset of normalized configuration lines of this object."""
    res: dict[tuple[str, str], collections.Counter] = {}
    for st in cfg.statements:
        if st.verb not in ("add", "set", "unset", "bind", "unbind", "link", "unlink", "rm"):
            continue
        name = "" if st.etype in SINGLETONS else (st.args[0] if st.args else "")
        res.setdefault((st.etype, name), collections.Counter())[_norm(st)] += 1
    return res


def diff_configs(old_cfg, new_cfg) -> dict:
    a, b = _objects(old_cfg), _objects(new_cfg)
    added, removed, changed = [], [], []
    for k in sorted(set(a) | set(b)):
        if k not in a:
            added.append({"etype": k[0], "name": k[1], "lines": sorted(b[k].elements())})
        elif k not in b:
            removed.append({"etype": k[0], "name": k[1], "lines": sorted(a[k].elements())})
        elif a[k] != b[k]:
            changed.append({"etype": k[0], "name": k[1], "removed": sorted((a[k] - b[k]).elements()),
                            "added": sorted((b[k] - a[k]).elements())})
    return {"added": added, "removed": removed, "changed": changed}


def _devices(proj: Project) -> dict[str, object]:
    return {d.name: d for d in proj.devices}


def compare(old: Project, new: Project) -> dict:
    """Result of the comparison as a plain data structure."""
    od, nd = _devices(old), _devices(new)
    if len(od) == 1 and len(nd) == 1 and set(od) != set(nd):  # one device on each side: the same device under another name
        o_dev, (n_name, n_dev) = next(iter(od.values())), next(iter(nd.items()))
        od, nd = {n_name: o_dev}, {n_name: n_dev}
    devices = []
    for name in sorted(set(od) | set(nd)):
        if name not in od:
            devices.append({"name": name, "state": "added", **diff_configs(type("C", (), {"statements": []})(), nd[name].cfg)})
        elif name not in nd:
            devices.append({"name": name, "state": "removed", **diff_configs(od[name].cfg, type("C", (), {"statements": []})())})
        else:
            d = diff_configs(od[name].cfg, nd[name].cfg)
            devices.append({"name": name, "state": "both", **d})
    fo = {f.key(): f for f in old.findings}
    fn = {f.key(): f for f in new.findings}

    def brief(f):
        return {"rule": f.rule_id, "severity": f.severity, "etype": f.etype, "name": f.name, "devices": f.devices, "msgs": f.msgs}

    return {"devices": devices,
            "new_findings": [brief(fn[k]) for k in fn if k not in fo],
            "resolved_findings": [brief(fo[k]) for k in fo if k not in fn],
            "unchanged_findings": len(set(fo) & set(fn))}


def summary(result: dict) -> dict:
    s = collections.Counter()
    for d in result["devices"]:
        s["added"] += len(d["added"])
        s["removed"] += len(d["removed"])
        s["changed"] += len(d["changed"])
    s["new_findings"] = len(result["new_findings"])
    s["resolved_findings"] = len(result["resolved_findings"])
    return dict(s)


TEXT = {
    "en": {"title": "Configuration comparison", "old": "Before", "new": "After", "added": "Added objects", "removed": "Removed objects",
           "changed": "Changed objects", "newf": "New findings", "resf": "Resolved findings", "none": "none", "dev": "Device",
           "state_added": "device added", "state_removed": "device removed", "nochange": "No differences in the configuration.",
           "sev": "Severity", "rule": "Rule", "msg": "Message", "obj": "Object", "unch": "{n} finding(s) unchanged",
           "intro": "Differences between two configuration states, per device and object. Secrets are masked."},
    "de": {"title": "Konfigurationsvergleich", "old": "Vorher", "new": "Nachher", "added": "Hinzugefügte Objekte", "removed": "Entfernte Objekte",
           "changed": "Geänderte Objekte", "newf": "Neue Befunde", "resf": "Behobene Befunde", "none": "keine", "dev": "Gerät",
           "state_added": "Gerät hinzugefügt", "state_removed": "Gerät entfernt", "nochange": "Keine Unterschiede in der Konfiguration.",
           "sev": "Schweregrad", "rule": "Regel", "msg": "Meldung", "obj": "Objekt", "unch": "{n} Befund(e) unverändert",
           "intro": "Unterschiede zwischen zwei Konfigurationsständen, je Gerät und Objekt. Secrets sind maskiert."},
}

CSS = """body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:#f5f6fa;color:#1c1c1e}
main{max-width:1100px;margin:0 auto;padding:24px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.muted{color:#6b6f76}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.card{background:#fff;border-radius:12px;padding:12px 18px;box-shadow:0 1px 3px #0001}
.card b{display:block;font-size:26px}.add{color:#1a7f37}.rem{color:#c0392b}.chg{color:#9a6700}
details{background:#fff;border-radius:10px;margin:6px 0;padding:8px 12px;box-shadow:0 1px 2px #0001}summary{cursor:pointer}
pre{margin:6px 0 2px;padding:8px;background:#f0f1f5;border-radius:8px;overflow:auto;font-size:12.5px}pre .a{color:#1a7f37}pre .r{color:#c0392b}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #e5e6ea}
.sev{font-size:12px;border-radius:6px;padding:1px 7px;background:#e5e6ea}.sev.critical,.sev.high{background:#f8d7da}.sev.medium{background:#fff3cd}
@media (prefers-color-scheme:dark){body{background:#17181c;color:#eee}.card,details,table{background:#22242a}pre{background:#2b2d34}th,td{border-color:#33353d}.muted{color:#9aa0a8}}"""


def render(result: dict, old_label: str, new_label: str, lang: str = "en") -> str:
    t = TEXT[lang]
    e = html.escape
    s = summary(result)

    def lines(prefix, items, cls):
        return "".join(f'<span class="{cls}">{prefix} {e(x)}</span>\n' for x in items)

    def objs(title, key, d):
        items = d[key]
        if not items:
            return ""
        out = [f"<h3>{e(title)} ({len(items)})</h3>"]
        for o in items:
            body = (lines("-", o["removed"], "r") + lines("+", o["added"], "a")) if key == "changed" else lines("+" if key == "added" else "-", o["lines"], "a" if key == "added" else "r")
            out.append(f"<details><summary>{e(o['etype'])} {e(o['name'])}</summary><pre>{body}</pre></details>")
        return "".join(out)

    parts = [f"<!DOCTYPE html><html lang=\"{lang}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
             f"<title>{e(t['title'])}</title><style>{CSS}</style></head><body><main>",
             f"<h1>{e(t['title'])}</h1><p class=\"muted\">{e(t['intro'])}<br>{e(t['old'])}: {e(old_label)} · {e(t['new'])}: {e(new_label)}</p>",
             "<div class=\"cards\">"
             f"<div class=\"card\"><b class=\"add\">{s.get('added', 0)}</b>{e(t['added'])}</div>"
             f"<div class=\"card\"><b class=\"rem\">{s.get('removed', 0)}</b>{e(t['removed'])}</div>"
             f"<div class=\"card\"><b class=\"chg\">{s.get('changed', 0)}</b>{e(t['changed'])}</div>"
             f"<div class=\"card\"><b class=\"rem\">{s.get('new_findings', 0)}</b>{e(t['newf'])}</div>"
             f"<div class=\"card\"><b class=\"add\">{s.get('resolved_findings', 0)}</b>{e(t['resf'])}</div></div>"]
    for d in result["devices"]:
        state = {"added": f" – {t['state_added']}", "removed": f" – {t['state_removed']}"}.get(d["state"], "")
        parts.append(f"<h2>{e(t['dev'])}: {e(d['name'])}{e(state)}</h2>")
        if not (d["added"] or d["removed"] or d["changed"]):
            parts.append(f"<p class=\"muted\">{e(t['nochange'])}</p>")
            continue
        parts.append(objs(t["changed"], "changed", d) + objs(t["added"], "added", d) + objs(t["removed"], "removed", d))

    def ftable(title, items):
        if not items:
            return f"<h2>{e(title)}</h2><p class=\"muted\">{e(t['none'])}</p>"
        rows = "".join(f"<tr><td><span class=\"sev {e(f['severity'])}\">{e(f['severity'])}</span></td><td>{e(f['rule'])}</td>"
                       f"<td>{e(f['msgs'].get(lang) or f['msgs']['en'])}</td><td>{e(', '.join(f['devices']))}</td></tr>" for f in items)
        return (f"<h2>{e(title)} ({len(items)})</h2><table><thead><tr><th>{e(t['sev'])}</th><th>{e(t['rule'])}</th><th>{e(t['msg'])}</th>"
                f"<th>{e(t['dev'])}</th></tr></thead><tbody>{rows}</tbody></table>")

    parts.append(ftable(t["newf"], result["new_findings"]) + ftable(t["resf"], result["resolved_findings"]))
    parts.append(f"<p class=\"muted\">{e(t['unch'].format(n=result['unchanged_findings']))} · nsviz {e(__version__)} · "
                 f"{_dt.datetime.now().strftime('%Y-%m-%d %H:%M')}</p></main></body></html>")
    return "".join(parts)


def write(result: dict, out: str, old_label: str, new_label: str, lang: str = "en") -> Path:
    p = Path(out)
    p.write_text(render(result, old_label, new_label, lang), encoding="utf-8")
    return p
