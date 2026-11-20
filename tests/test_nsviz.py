import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nsviz import report  # noqa: E402
from nsviz.model import Graph, redact  # noqa: E402
from nsviz.parser import Config, tokenize, parse_statement  # noqa: E402
from nsviz.project import Project  # noqa: E402

DEMO = ROOT / "examples" / "demo"
CORPUS = ROOT / "testdata"


class ParserTests(unittest.TestCase):
    def test_tokenize_quotes_and_escapes(self):
        t = tokenize('add cs policy p -rule "HTTP.REQ.HOSTNAME.EQ(\\"a b.de\\")" -action x')
        self.assertEqual(t[5].text, 'HTTP.REQ.HOSTNAME.EQ("a b.de")')
        self.assertTrue(t[5].quoted)

    def test_statement_types(self):
        s = parse_statement("add lb vserver vs1 SSL 10.0.0.1 443 -persistenceType NONE -cltTimeout 180", 1, "f")
        self.assertEqual((s.verb, s.etype, s.args), ("add", "lb vserver", ["vs1", "SSL", "10.0.0.1", "443"]))
        self.assertEqual(s.opts["persistencetype"], ["NONE"])
        s = parse_statement("add server srv1 10.0.0.5", 1, "f")
        self.assertEqual(s.etype, "server")
        s = parse_statement("add authentication ldapAction a -serverIP 1.2.3.4", 1, "f")
        self.assertEqual(s.etype, "authentication ldapaction")

    def test_negative_number_is_not_option(self):
        s = parse_statement("set lb vserver v -weight -1", 1, "f")
        self.assertEqual(s.opts["weight"], ["-1"])

    def test_apply_set_unset_bind_unbind_rm(self):
        cfg = Config.parse_text("#NS13.1 Build 37.38\nadd lb vserver v HTTP 1.1.1.1 80\nset lb vserver v -cltTimeout 99\n"
                                "bind lb vserver v s1\nbind lb vserver v s2\nunbind lb vserver v s1\n"
                                "unset lb vserver v -cltTimeout\nadd server a 1.1.1.2\nrm server a\n")
        self.assertEqual((cfg.version, cfg.build), ("13.1", "37.38"))
        v = cfg.get("lb vserver", "v")
        self.assertFalse(v.has("clttimeout"))
        self.assertEqual([b.args for b in cfg.binds("lb vserver", "v")], [["s2"]])
        self.assertIsNone(cfg.get("server", "a"))

    def test_features(self):
        cfg = Config.parse_text("enable ns feature LB CS SSL\ndisable ns feature CS\n")
        self.assertEqual(cfg.features, {"LB", "SSL"})

    def test_global_bind(self):
        cfg = Config.parse_text("bind rewrite global pol1 100 END -type REQ_DEFAULT\n")
        self.assertEqual(cfg.bindings[0].owner, "")
        self.assertEqual(cfg.bindings[0].args[0], "pol1")


@unittest.skipUnless(len(list(CORPUS.glob("*conf"))) >= 30, "sample configs missing: run scripts/fetch_testdata.py")
class CorpusTests(unittest.TestCase):
    """All public sample configs (Apache-2.0, see docs/SOURCES.md) must load without warnings."""

    def test_all_files_parse_and_build(self):
        files = sorted(CORPUS.glob("*conf"))
        self.assertGreaterEqual(len(files), 30)
        for f in files:
            cfg = Config.parse_file(f)
            self.assertEqual(cfg.warnings, [], f.name)
            self.assertGreater(len(cfg.statements), 0, f.name)
            g = Graph(cfg, "g1")
            self.assertGreater(len(g.nodes), 0, f.name)

    def test_project_over_corpus_and_report(self):
        p = Project.load([str(CORPUS)])
        html = report.render(p)
        self.assertIn("cytoscape", html)
        data = json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S).group(1).replace("<\\/", "</"))
        self.assertEqual(len(data["groups"]), len(list(CORPUS.glob("*conf"))))
        self.assertTrue(data["findings"])


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = Project.load([str(DEMO)])
        cls.by_rule = {}
        for f in cls.p.findings:
            cls.by_rule.setdefault(f.rule_id, []).append(f)

    def test_expected_findings(self):
        for rid in ("MGMT-001", "MGMT-003", "MGMT-012", "TLS-001", "TLS-002", "TLS-003", "AAA-001", "AAA-003", "AAA-004", "HA-003", "CHAIN-002", "TLS-009"):
            self.assertIn(rid, self.by_rule, rid)

    def test_no_false_positive_on_clean_tls(self):
        names = {f.name for f in self.by_rule.get("TLS-002", [])}
        self.assertNotIn("be_lb_ssl", names)  # TLS1.0/1.1 dort explizit DISABLED

    def test_ha_pair_detected_by_peer_ip(self):
        ha = [g for g in self.p.groups if g.kind == "ha"]
        self.assertEqual(len(ha), 1)
        self.assertEqual(len(ha[0].devices), 2)

    def test_ha_diff_finds_extra_vserver(self):
        keys = [d["key"] for d in list(self.p.diffs.values())[0]]
        self.assertIn("lb vserver be_extra", keys)

    def test_double_hop_links(self):
        hosts = {(l["host"], l["port"], l["confidence"]) for l in self.p.links}
        self.assertIn(("10.20.0.50", "443", "high"), hosts)
        self.assertEqual(self.p.chains(), [["dmz-adc01", "HA: be-adc-a + be-adc-b"]])

    def test_nfactor_flow_edges(self):
        g = next(g for g in self.p.groups if g.name == "dmz-adc01").graph
        pairs = {(e.source.split("|")[1] + ":" + e.source.split("|")[2], e.target.split("|")[1] + ":" + e.target.split("|")[2]) for e in g.edges}
        self.assertIn(("vpn vserver:gw_vs", "authentication authnprofile:ap_gw"), pairs)
        self.assertIn(("authentication authnprofile:ap_gw", "authentication vserver:auth_vs"), pairs)
        self.assertIn(("authentication policylabel:pl_factor2", "authentication loginschema:schema_user_pw"), pairs)

    def test_redaction(self):
        html = report.render(self.p)
        self.assertNotIn("s3cret", html)
        p2 = Project.load([str(DEMO)], redact=False)
        self.assertIn("s3cret", report.render(p2))


class HygieneTests(unittest.TestCase):
    """No secrets/personal data in test data, examples, code and docs."""

    def _files(self):
        for d in ("testdata", "examples", "nsviz", "docs", "scripts", ".github"):
            for f in (ROOT / d).rglob("*"):
                if f.is_file() and "vendor" not in f.parts and "__pycache__" not in f.parts and f.suffix not in (".html", ".gz", ".pyc"):
                    yield f
        for f in ROOT.glob("*"):
            if f.is_file() and f.suffix in (".md", ".toml", ".txt", "") and f.name != ".DS_Store":
                yield f

    def test_no_ai_tool_references(self):
        terms = ["clau" + "de", "anthr" + "opic", "chat" + "gpt", "co-authored"]
        for f in self._files():
            t = f.read_text(encoding="utf-8", errors="replace").lower()
            for term in terms:
                self.assertNotIn(term, t, f"forbidden reference in {f.name}")

    def test_no_secrets_or_personal_data(self):
        mail = re.compile(r"[\w.+-]+@(?!example\.(com|org)\b)[\w-]+\.[a-z]{2,}", re.I)
        hexsecret = re.compile(r"\b(?![0]+\b)[0-9a-f]{40,}\b")
        for f in self._files():
            t = f.read_text(encoding="utf-8", errors="replace")
            self.assertIsNone(hexsecret.search(t), f"Hex-Secret in {f}")
            self.assertIsNone(mail.search(t), f"E-Mail in {f}")
            for bad in ("/Users/", "/home/", "Co-Authored-By"):
                self.assertNotIn(bad, t, f"{bad} in {f}")


class HaSummaryTests(unittest.TestCase):
    def test_large_drift_is_summarized(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a = "set ns config -IPAddress 192.0.2.1 -netmask 255.255.255.0\nadd ha node 1 192.0.2.2\n" + "".join(f"add server s{i} 198.51.100.{i}\n" for i in range(1, 60))
            b = "set ns config -IPAddress 192.0.2.2 -netmask 255.255.255.0\nadd ha node 1 192.0.2.1\n"
            (Path(d) / "a.conf").write_text(a)
            (Path(d) / "b.conf").write_text(b)
            p = Project.load([d])
            ha = [f for f in p.findings if f.rule_id == "HA-003"]
            self.assertEqual(len(ha), 1)
            self.assertIn("59", ha[0].msgs["en"])


class BuiltinRefTests(unittest.TestCase):
    def test_underscore_policy_is_not_reported_missing(self):
        cfg = Config.parse_text("add lb vserver v HTTP 192.0.2.5 80\nbind lb vserver v -policyName _sys_pol -priority 1\n"
                                "bind lb vserver v -policyName my_pol -priority 2\n", name="t")
        g = Graph(cfg, "g1")
        missing = {m["ref_name"] for m in g.missing}
        self.assertNotIn("_sys_pol", missing)
        self.assertIn("my_pol", missing)


class GroupBindingTests(unittest.TestCase):
    def test_policy_bound_to_aaa_group_is_used(self):
        cfg = Config.parse_text("add authorization policy ap1 true ALLOW\nadd authorization policy ap2 true ALLOW\n"
                                "bind aaa group g1 -policy ap1 -priority 10\n", name="t")
        g = Graph(cfg, "g1")
        self.assertIn(("authorization policy", "ap1"), g.referenced)
        self.assertNotIn(("authorization policy", "ap2"), g.referenced)

    def test_group_and_action_nodes(self):
        cfg = Config.parse_text("add aaa group g1\nadd authorization policy ap1 true ALLOW\nbind aaa group g1 -policy ap1 -priority 10\n"
                                "add rewrite action ra1 replace http.req.url \"x\"\nadd rewrite policy rp1 true ra1\n", name="t")
        g = Graph(cfg, "g1")
        kinds = {n.kind for n in g.nodes.values()}
        self.assertIn("group", kinds)
        self.assertIn("action", kinds)
        self.assertTrue(any(e.type == "bind" and e.label == "Action" for e in g.edges))


class AnonymizeTests(unittest.TestCase):
    SRC = (
        "#NS14.1 Build 29.63\n"
        "set ns hostname acme-prod-adc01\n"
        "set ns config -IPAddress 10.77.1.10 -netmask 255.255.255.0\n"
        "add server web01 10.77.2.21 -comment \"Acme intranet server\"\n"
        "add service svc_web01 web01 HTTP 80\n"
        "add lb vserver vs_acme_portal HTTP 10.77.1.50 80\n"
        "bind lb vserver vs_acme_portal svc_web01\n"
        "add authentication ldapAction ldap_acme -serverIP 10.77.9.5 -ldapBase \"dc=acme,dc=de\" -ldapBindDnPassword s3cretpw\n"
        "add rewrite policy pol_acme true act_acme\n"
        "add responder policy rp1 \"HTTP.REQ.HOSTNAME.EQ(\\\"portal.acme.de\\\")\" NOOP\n"
    )

    def test_anonymize_removes_originals_and_keeps_structure(self):
        import tempfile
        from nsviz.anonymize import anonymize_paths
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "in").mkdir()
            (Path(d) / "in" / "acme-prod.conf").write_text(self.SRC)
            st = anonymize_paths([str(Path(d) / "in")], str(Path(d) / "out"))
            out = (Path(d) / "out" / "device-001.conf").read_text()
            for secret in ("acme", "10.77", "s3cretpw", "web01", "intranet"):
                self.assertNotIn(secret, out, secret)
            self.assertEqual(st["statements_in"], st["statements_out"])
            cfg = Config.parse_text(out)
            self.assertEqual(sorted(cfg.entities), sorted(Config.parse_text(self.SRC).entities))
            g = Graph(cfg, "g1")
            self.assertFalse(g.missing)  # references still resolve


class PortLabelTests(unittest.TestCase):
    def test_connections_show_service_and_port(self):
        from nsviz.model import comm_label
        self.assertEqual(comm_label("SSL", "443"), "HTTPS 443")
        self.assertEqual(comm_label("TCP", "1433"), "SQL Server 1433")
        self.assertEqual(comm_label("TCP", "9999"), "TCP/9999")
        cfg = Config.parse_text("add server db1 192.0.2.50\nadd service svc_db db1 TCP 1433\nadd lb vserver vs_db TCP 192.0.2.60 1433\nbind lb vserver vs_db svc_db\n", name="t")
        g = Graph(cfg, "g1")
        labels = {e.label for e in g.edges if e.port}
        self.assertIn("SQL Server 1433", labels)


class CatalogTests(unittest.TestCase):
    def test_rule_texts_complete_in_en_and_de(self):
        from nsviz import rules as R
        import nsviz.project  # noqa: F401
        R.load_builtin_rules()
        for lang in R.LANGS:
            for rid in R.RULES:
                t = R.TEXTS[lang].get(rid)
                self.assertTrue(t and all(t.get(k, "").strip() for k in ("title", "rationale", "remediation")), f"{lang}:{rid}")
            self.assertEqual(set(R.TEXTS[lang]) - set(R.RULES), set(), f"{lang}: texts without rule")
        self.assertEqual(set(R.MESSAGES["en"]), set(R.MESSAGES["de"]))

    def test_findings_have_both_languages(self):
        p = Project.load([str(DEMO)])
        d = p.to_dict()
        for f in d["findings"]:
            self.assertTrue(f["msgs"]["en"] and f["msgs"]["de"], f["rule"])


class I18nTests(unittest.TestCase):
    def test_all_languages_complete(self):
        i18n = report.load_i18n()
        self.assertEqual(set(i18n), {"de", "en", "es", "fr", "pt", "zh", "ja", "hi"})
        base = {k for k in i18n["en"] if not k.startswith("kind_")}
        ph = lambda s: sorted(re.findall(r"\{\w+\}", s))
        for code, d in i18n.items():
            self.assertTrue(base <= set(d), f"{code}: missing keys {base - set(d)}")
            for k in base:
                self.assertTrue(d[k].strip(), f"{code}.{k} leer")
                self.assertEqual(ph(d[k]), ph(i18n["en"][k]), f"{code}.{k} Platzhalter")

    def test_every_used_key_exists(self):
        js = (ROOT / "nsviz" / "assets" / "app.js").read_text(encoding="utf-8") + (ROOT / "nsviz" / "assets" / "template.html").read_text(encoding="utf-8") + (ROOT / "nsviz" / "assets" / "links.js").read_text(encoding="utf-8")
        used = set(re.findall(r"\bt\('([a-z_]+)'", js)) | set(re.findall(r"data-i18n(?:-ph|-title|-aria)?=\"([a-z_]+)\"", js))
        used |= {m for m in re.findall(r"'(th_\w+|sc_\w+|p_\w+|o_\w+)'", js)}
        en = report.load_i18n()["en"]
        missing = {k for k in used if k not in en and not k.startswith("kind_") and not k.endswith("_")}
        self.assertEqual(missing - {"th_findings"}, set())

    def test_accessibility_markup(self):
        html = report.render(Project.load([str(DEMO)]))
        for needle in ('class="skip"', 'role="tablist"', 'aria-live', 'prefers-color-scheme', 'prefers-reduced-motion', "focus-visible", "<dialog"):
            self.assertIn(needle, html, needle)


class LinkingTests(unittest.TestCase):
    def test_hosts_parsing(self):
        from nsviz.linking import parse_hosts_text
        h = parse_hosts_text("# c\n10.1.1.1 A.example.test b.example.test\napp.example.test;10.1.1.2\nbroken line\n")
        self.assertEqual(h, {"a.example.test": "10.1.1.1", "b.example.test": "10.1.1.1", "app.example.test": "10.1.1.2"})

    def test_sources_and_targets(self):
        from nsviz.linking import collect, fqdns
        p = Project.load([str(DEMO)])
        c = collect(p)
        self.assertEqual([s["host"] for s in c["sources"]], ["extra.backend.example.test"])
        self.assertTrue(any(t["ip"] == "10.20.0.52" and t["port"] == "8080" for t in c["targets"]))
        self.assertEqual(fqdns(p), ["extra.backend.example.test"])

    def test_map_roundtrip_adds_chain(self):
        from nsviz.linking import collect, apply_map, MAP_FORMAT
        p0 = Project.load([str(DEMO)])
        c = collect(p0)
        src = c["sources"][0]["key"]
        dst = next(t["key"] for t in c["targets"] if t["ip"] == "10.20.0.52")
        n0 = len(p0.links)
        p = Project.load([str(DEMO)], link_map={"format": MAP_FORMAT, "version": 1, "links": [
            {"from": src, "to": dst, "status": "confirmed"}, {"from": "x|y|z", "to": dst, "status": "confirmed"}]})
        self.assertEqual(len(p.links), n0 + 1)
        d = p.to_dict()
        self.assertTrue(any(e["type"] == "link" for e in d["edges"]))
        self.assertTrue(any("not found" in n["en"] for n in p.notes))
        rejected = Project.load([str(DEMO)], link_map={"format": MAP_FORMAT, "version": 1, "links": [{"from": src, "to": dst, "status": "rejected"}]})
        self.assertEqual(len(rejected.links), n0)

    def test_dns_query_against_local_server(self):
        import socket, struct, threading
        from nsviz.linking import resolve_names
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        def serve():
            data, addr = srv.recvfrom(512)
            q = data[12:]
            resp = data[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + q + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 7])
            srv.sendto(resp, addr)
        th = threading.Thread(target=serve, daemon=True)
        th.start()
        self.assertEqual(resolve_names(["app.example.test"], f"127.0.0.1:{port}"), {"app.example.test": "192.0.2.7"})
        th.join(2)
        srv.close()


class GuiTests(unittest.TestCase):
    def test_gui_roundtrip_and_security(self):
        import threading, urllib.request, urllib.error
        from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
        from nsviz import gui
        st = gui.State()
        srv = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        port = srv.server_address[1]
        srv.RequestHandlerClass = gui.make_handler(st, port)
        st.server = srv
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        base = f"http://127.0.0.1:{port}"

        def call(path, data=None, token=True, method=None):
            req = urllib.request.Request(base + path, data=data, method=method or ("POST" if data is not None else "GET"))
            if token:
                req.add_header("X-Token", st.token)
            return urllib.request.urlopen(req, timeout=10)
        try:
            with self.assertRaises(urllib.error.HTTPError) as cm:
                call("/api/files", token=False)
            self.assertEqual(cm.exception.code, 403)
            for f in sorted(DEMO.glob("*.conf")):
                call("/api/upload?kind=conf&name=" + f.name, f.read_bytes())
            files = json.load(call("/api/files"))["files"]
            self.assertEqual(len(files), 3)
            call("/api/upload?kind=conf&name=../../evil.conf", b"add lb vserver x HTTP 10.0.0.1 80\n")
            self.assertTrue(all(st.dir in p.parents for p in st.paths.values()))
            res = json.load(call("/api/analyze", json.dumps({"files": [x["name"] for x in files]}).encode()))
            self.assertGreater(res["objects"], 10)
            html = call(f"/report/{res['id']}").read().decode()
            self.assertIn("NetScaler Visualizer", html)
            self.assertTrue(html.lstrip().lower().startswith("<!doctype html"))
        finally:
            srv.shutdown()
            srv.server_close()
            import shutil
            shutil.rmtree(st.dir, ignore_errors=True)


class ReportTests(unittest.TestCase):
    def test_report_is_self_contained(self):
        html = report.render(Project.load([str(DEMO)]))
        self.assertFalse(re.search(r"<script[^>]+src=", html))
        self.assertFalse(re.search(r"<link[^>]+href=", html))
        self.assertNotIn("__CSS__", html)
        self.assertNotIn("__DATA__", html)


if __name__ == "__main__":
    unittest.main()
