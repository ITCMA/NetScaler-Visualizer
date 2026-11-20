"""Local web GUI: ``python -m nsviz gui``.

A small HTTP server (Python standard library only) that listens on 127.0.0.1 and lets you pick config files, set the
options and create the report in a browser window. Nothing leaves the computer: the server is bound to the loopback
interface, every request needs a random token, the Host header is checked and uploads live in a temporary folder that is
removed on exit. No telemetry, no external requests.
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, linking, report
from .parser import Config
from .project import CONF_SUFFIX, Project

ASSET = Path(__file__).parent / "assets" / "gui.html"
MAX_UPLOAD = 100 * 1024 * 1024  # per file; ns.conf files are small, this only protects against mistakes
MAX_JSON = 2 * 1024 * 1024


def _safe_name(name: str) -> str:
    base = Path(name.replace("\\", "/")).name
    base = re.sub(r"[^\w.\- ]", "_", base).strip(". ") or "config"
    return base[:120]


def _looks_like_conf(p: Path) -> bool:
    return p.is_file() and (p.suffix.lower() in CONF_SUFFIX or "ns.conf" in p.name.lower())


class State:
    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(24)
        self.dir = Path(tempfile.mkdtemp(prefix="nsviz-gui-"))
        self.paths: dict[str, Path] = {}      # display name -> file (uploads and referenced local paths)
        self.extra: dict[str, Path] = {}      # hosts / map files
        self.reports: dict[str, str] = {}
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None

    def add_upload(self, kind: str, name: str, data: bytes) -> str:
        name = _safe_name(name)
        folder = self.dir / kind
        folder.mkdir(exist_ok=True)
        target, i = folder / name, 2
        while target.exists():
            target = folder / f"{target.stem}_{i}{target.suffix}"
            i += 1
        target.write_bytes(data)
        with self.lock:
            (self.paths if kind == "conf" else self.extra)[target.name if kind == "conf" else kind] = target
        return target.name

    def describe(self) -> list[dict]:
        out = []
        for name, p in sorted(self.paths.items()):
            info = {"name": name, "source": "upload" if self.dir in p.parents else "path", "ok": True}
            try:
                cfg = Config.parse_file(p)
                info.update(host=cfg.hostname or "", version=cfg.version or "", statements=len(cfg.statements),
                            ns_conf=any(st.verb in ("add", "set", "bind", "enable") for st in cfg.statements))
                hn = cfg.get("ha node", "0")
                info["nsip"] = cfg.nsip or ""
                info["hastatus"] = ((hn.opt("hastatus") if hn else "") or "").upper()
            except Exception as e:  # noqa: BLE001 - show the reason instead of failing the whole list
                info.update(ok=False, error=str(e)[:200])
            out.append(info)
        return out

    def analyze(self, opts: dict) -> dict:
        files = [self.paths[n] for n in opts.get("files", list(self.paths)) if n in self.paths]
        if not files:
            raise ValueError("no config files selected")
        pairs = [tuple(x[:2]) for x in opts.get("ha", []) if isinstance(x, list) and len(x) >= 2]
        roles = {k: v for k, v in (opts.get("roles") or {}).items() if v in ("primary", "secondary")}
        lm = None
        if "map" in self.extra:
            lm = linking.load_map(str(self.extra["map"]))
        if "hosts" in self.extra:
            lm = lm or {"format": linking.MAP_FORMAT, "version": linking.MAP_VERSION, "links": []}
            lm.setdefault("hosts", {}).update(linking.load_hosts(str(self.extra["hosts"])))
        proj = Project.load([str(f) for f in files], pairs, roles, redact=bool(opts.get("redact", True)), link_map=lm)
        title = str(opts.get("title") or "NetScaler Visualizer")[:120]
        html = report.render(proj, title)
        rid = secrets.token_urlsafe(8)
        self.reports[rid] = html
        d = proj.to_dict()
        sev = {}
        for f in proj.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {"id": rid, "devices": len(proj.devices), "groups": len(proj.groups), "objects": len(d["nodes"]), "relations": len(d["edges"]),
                "findings": sev, "notes": [n.get("en", "") for n in proj.notes], "bytes": len(html)}


def make_handler(st: State, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(BaseHTTPRequestHandler):
        server_version = "nsviz-gui"

        def log_message(self, *a):  # keep the terminal quiet (no file names in logs)
            pass

        # -- helpers
        def _ok(self) -> bool:
            if self.headers.get("Host", "") not in allowed_hosts:
                self.send_error(403, "bad host")
                return False
            q = parse_qs(urlparse(self.path).query)
            tok = self.headers.get("X-Token") or (q.get("t") or [""])[0]
            if not secrets.compare_digest(tok, st.token):
                self.send_error(403, "token")
                return False
            return True

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _body(self, limit: int) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                raise ValueError("too large")
            return self.rfile.read(n)

        # -- routes
        def do_GET(self):  # noqa: N802
            if not self._ok():
                return
            u = urlparse(self.path)
            if u.path == "/":
                html = ASSET.read_text(encoding="utf-8").replace("__TOKEN__", st.token).replace("__VERSION__", __version__)
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8",
                           {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'", "Referrer-Policy": "no-referrer"})
            elif u.path == "/api/files":
                self._json({"files": st.describe(), "extra": sorted(st.extra)})
            elif u.path.startswith("/report/"):
                rid = u.path.split("/")[2]
                html = st.reports.get(rid)
                if html is None:
                    self.send_error(404)
                    return
                extra = {"Content-Disposition": 'attachment; filename="netscaler-report.html"'} if u.path.endswith("/download") else {}
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", extra)
            else:
                self.send_error(404)

        def do_POST(self):  # noqa: N802
            if not self._ok():
                return
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/api/upload":
                    kind = (q.get("kind") or ["conf"])[0]
                    if kind not in ("conf", "hosts", "map"):
                        raise ValueError("kind")
                    name = st.add_upload(kind, (q.get("name") or ["config"])[0], self._body(MAX_UPLOAD))
                    self._json({"name": name})
                elif u.path == "/api/addpath":
                    p = Path((json.loads(self._body(MAX_JSON)).get("path") or "").strip().strip('"')).expanduser()
                    if not p.exists():
                        raise ValueError("path not found")
                    found = sorted(f for f in p.rglob("*") if _looks_like_conf(f)) if p.is_dir() else [p]
                    names = []
                    for f in found:
                        n, i = f.name, 2
                        while n in st.paths and st.paths[n] != f:
                            n, i = f"{f.stem}_{i}{f.suffix}", i + 1
                        st.paths[n] = f
                        names.append(n)
                    self._json({"added": names})
                elif u.path == "/api/remove":
                    st.paths.pop(json.loads(self._body(MAX_JSON)).get("name", ""), None)
                    self._json({"ok": True})
                elif u.path == "/api/clear-extra":
                    st.extra.pop(json.loads(self._body(MAX_JSON)).get("kind", ""), None)
                    self._json({"ok": True})
                elif u.path == "/api/analyze":
                    self._json(st.analyze(json.loads(self._body(MAX_JSON) or b"{}")))
                elif u.path == "/api/shutdown":
                    self._json({"ok": True})
                    threading.Thread(target=st.server.shutdown, daemon=True).start()
                else:
                    self.send_error(404)
            except (ValueError, FileNotFoundError, KeyError, json.JSONDecodeError) as e:
                self._json({"error": str(e)}, 400)

    return H


def serve(port: int = 0, open_browser: bool = True) -> int:
    st = State()
    # the handler needs the real port for the Host check; bind first
    srv = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    real = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(st, real)
    st.server = srv
    url = f"http://127.0.0.1:{real}/?t={st.token}"
    print(f"nsviz GUI: {url}")
    print("Listening on this computer only (127.0.0.1). Close with Ctrl+C or the button in the page.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        shutil.rmtree(st.dir, ignore_errors=True)
    return 0
