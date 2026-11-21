"""Builds the self-contained offline HTML report (no external resources, no network)."""
from __future__ import annotations

import html as _html
import json
from pathlib import Path

from .project import Project

ASSETS = Path(__file__).parent / "assets"


def _read(p: str) -> str:
    return (ASSETS / p).read_text(encoding="utf-8")


def _js(s: str) -> str:
    return s.replace("</script", "<\\/script")


def _json(obj) -> str:
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return s.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def load_i18n() -> dict[str, dict[str, str]]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((ASSETS / "i18n").glob("*.json"))}


def render(project: Project, title: str = "NetScaler Visualizer", debug: bool = False) -> str:
    html = _read("template.html").replace("<title>NetScaler Visualizer</title>", f"<title>{_html.escape(title)}</title>")
    # Daten/Skripte zuletzt einsetzen (enthalten beliebige Zeichen)
    for key, val in (("/*__CSS__*/", _read("style.css")),
                     ("/*__CYTOSCAPE__*/", _js(_read("vendor/cytoscape.min.js"))),
                     ("/*__DAGRE__*/", _js(_read("vendor/dagre.min.js"))),
                     ("/*__CYDAGRE__*/", _js(_read("vendor/cytoscape-dagre.js"))),
                     ("/*__APP__*/", _js(_read("app.js").replace("/*__EXPORT__*/", _read("export.js")).replace("/*__LINKS__*/", _read("links.js")).replace("/*__DEBUG__*/", _read("debug.js")))),
                     ("/*__I18N__*/", _json(load_i18n())),
                     ("/*__DATA__*/", _json(project.to_dict()))):
        html = html.replace(key, val, 1)
    html = html.replace("/*__DBG__*/", "true" if debug else "false", 1)
    return html


def write(project: Project, out: str | Path, title: str = "NetScaler Visualizer", debug: bool = False) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(project, title, debug), encoding="utf-8")
    return out
