import json
import re
import sys
import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nsviz import report  # noqa: E402
from nsviz.model import Graph  # noqa: E402
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
        s = parse_statement("add authentication ldapAction a -serverIP 198.51.100.4", 1, "f")
        self.assertEqual(s.etype, "authentication ldapaction")

    def test_negative_number_is_not_option(self):
        s = parse_statement("set lb vserver v -weight -1", 1, "f")
        self.assertEqual(s.opts["weight"], ["-1"])

    def test_apply_set_unset_bind_unbind_rm(self):
        cfg = Config.parse_text("#NS13.1 Build 37.38\nadd lb vserver v HTTP 198.51.100.1 80\nset lb vserver v -cltTimeout 99\n"
                                "bind lb vserver v s1\nbind lb vserver v s2\nunbind lb vserver v s1\n"
                                "unset lb vserver v -cltTimeout\nadd server a 198.51.100.2\nrm server a\n")
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
        terms = ["clau" + "de", "anthr" + "opic", "chat" + "gpt", "co-" + "authored"]
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
            for bad in ("/Users/", "/home/", "Co-" + "Authored-By"):
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
            st = anonymize_paths([str(Path(d) / "in")], str(Path(d) / "out"), options={"comments": True})
            out = (Path(d) / "out" / "device-001.conf").read_text()
            for secret in ("acme", "10.77", "s3cretpw", "web01", "intranet"):
                self.assertNotIn(secret, out, secret)
            self.assertEqual(st["statements_in"], st["statements_out"])
            cfg = Config.parse_text(out)
            self.assertEqual(sorted(cfg.entities), sorted(Config.parse_text(self.SRC).entities))
            g = Graph(cfg, "g1")
            self.assertFalse(g.missing)  # references still resolve


class ConfigLineTests(unittest.TestCase):
    """Config lines in the report are exact (usable for the config export) and carry the statements they need."""
    SRC = (
        'add lb vserver lb1 HTTP 0.0.0.0 0\n'
        'add policy patset ps_hosts\n'
        'bind policy patset ps_hosts "a.example.com" -index 1\n'
        'add cs action act1 -targetLBVserver lb1\n'
        'add cs policy pol1 -rule "HTTP.REQ.HOSTNAME.CONTAINS_ANY(\\"ps_hosts\\")" -action act1\n'
        'add responder action ra1 respondwith "\\"HTTP/1.1 503 x\\r\\n\\r\\n\\""\n'
        'add system user admin2 secretpw -timeout 900\n'
    )

    def test_lines(self):
        g = Graph(Config.parse_text(self.SRC), "g1")
        by = {(n.etype, n.name): n for n in g.nodes.values()}
        pol = [l["text"] for l in by[("cs policy", "pol1")].lines]
        self.assertIn('add cs policy pol1 -rule "HTTP.REQ.HOSTNAME.CONTAINS_ANY(\\"ps_hosts\\")" -action act1', pol)  # escapes kept
        self.assertIn("add cs action act1 -targetLBVserver lb1", pol)          # the action belongs to the policy
        self.assertIn("add policy patset ps_hosts", pol)                       # objects named in the expression
        self.assertTrue(any(x.startswith("bind policy patset ps_hosts") for x in pol))
        ra = [n for n in g.nodes.values() if n.name == "ra1"]
        if ra:
            self.assertIn("\\r\\n", ra[0].lines[0]["text"])
        users = [n for n in g.nodes.values() if n.name == "admin2"]
        if users and users[0].lines:
            self.assertNotIn("secretpw", users[0].lines[0]["text"])


    def test_feature_objects(self):
        """Priority order, spillover, traffic domains, ACL/PBR/RNAT, persistency groups, CRLs, transform actions."""
        src = ('enable ns feature LB CS REWRITE\n'
               'enable ns mode FR L3\n'
               'add dns nameServer 192.0.2.53\n'
               'add dns addRec host1.example.test 192.0.2.10\n'
               'add ns trafficDomain 10\n'
               'add vlan 20\n'
               'bind ns trafficDomain 10 -vlan 20\n'
               'add server s1 192.0.2.11 -td 10\n'
               'add service svc1 s1 HTTP 80\n'
               'add service svc2 s1 HTTP 8080\n'
               'add lb vserver lb1 HTTP 192.0.2.20 80 -soMethod CONNECTION -soThreshold 100 -toggleorder ASCENDING -orderThreshold 50\n'
               'bind lb vserver lb1 svc1 -order 1\n'
               'bind lb vserver lb1 svc2 -order 2 -weight 3\n'
               'add lb group grp1 -persistenceType COOKIEINSERT\n'
               'bind lb group grp1 lb1\n'
               'add ns acl acl1 ALLOW -srcIP = 192.0.2.0-192.0.2.255 -priority 10\n'
               'add ns pbr pbr1 ALLOW -srcIP = 192.0.2.5 -nexthop 192.0.2.1\n'
               'add ssl certKey ca1 -cert ca1.pem\n'
               'add ssl crl crl1 /nsconfig/ssl/crl1.crl -CAcert ca1\n'
               'add transform profile tp1\n'
               'add transform action ta1 tp1 10\n'
               'add responder policy rp1 "CLIENT.IP.SRC.IPREP_IS_MALICIOUS" DROP\n')
        g = Graph(Config.parse_text(src), "g1")
        by = {(n.etype, n.name): n for n in g.nodes.values()}
        kinds = {k: by[k].kind for k in by}
        self.assertEqual(kinds[("ns acl", "acl1")], "netrule")
        self.assertEqual(kinds[("ns pbr", "pbr1")], "netrule")
        self.assertEqual(kinds[("lb group", "grp1")], "lbgroup")
        self.assertEqual(kinds[("ssl crl", "crl1")], "crl")
        self.assertEqual(kinds[("ns trafficdomain", "10")], "td")
        lb = by[("lb vserver", "lb1")].props
        self.assertEqual(lb["Spillover method"], "CONNECTION")
        self.assertEqual(lb["Priority order threshold (%)"], "50")
        self.assertEqual(by[("server", "s1")].props["Traffic domain"], "10")
        self.assertEqual(by[("ns pbr", "pbr1")].props["Next hop"], "192.0.2.1")
        dev = g.device_node().props
        self.assertEqual(dev["Modes"], "FR, L3")
        self.assertIn("192.0.2.53", dev["DNS name servers"])
        self.assertEqual(dev["DNS records"], "A 1")
        self.assertEqual(by[("responder policy", "rp1")].props["Uses"], "IP reputation")
        lab = {(g.nodes[e.source].name, g.nodes[e.target].name): e.label for e in g.edges}
        self.assertEqual(lab[("lb1", "svc1")], "Order 1")
        self.assertEqual(lab[("lb1", "svc2")], "Order 2, Weight 3")
        self.assertIn(("lb1", "grp1"), lab)
        self.assertIn(("ca1", "crl1"), lab)
        self.assertIn(("tp1", "ta1"), lab)
        self.assertIn(("10", "20"), lab)

    def test_cleanup(self):
        """Cleanup: unused objects (top-down), objects used only by disabled ones, certainty when a staying bind names them."""
        import tempfile
        src = (
               'enable ns feature LB CS SSL REWRITE RESPONDER\n'
               'add server web1 192.0.2.11\n'
               'add server web2 192.0.2.12\n'
               'add server old1 192.0.2.13\n'
               'add server old2 192.0.2.14 -state DISABLED\n'
               'add lb monitor mon_http HTTP -respCode 200\n'
               'add lb monitor mon_old HTTP-ECV -send "GET /health"\n'
               'add serviceGroup sg_web HTTP\n'
               'bind serviceGroup sg_web web1 80\n'
               'bind serviceGroup sg_web web2 80\n'
               'bind serviceGroup sg_web old2 80\n'
               'bind serviceGroup sg_web -monitorName mon_http\n'
               'add serviceGroup sg_old HTTP\n'
               'bind serviceGroup sg_old old1 80\n'
               'bind serviceGroup sg_old -monitorName mon_old\n'
               'add service svc_old old1 HTTP 8080\n'
               'add lb vserver lb_web HTTP 192.0.2.100 80\n'
               'bind lb vserver lb_web sg_web\n'
               'add lb vserver lb_internal HTTP 0.0.0.0 0\n'
               'bind lb vserver lb_internal sg_old\n'
               'add lb vserver lb_legacy HTTP 192.0.2.101 80 -state DISABLED\n'
               'bind lb vserver lb_legacy svc_old\n'
               'add rewrite action rw_act_old replace HTTP.REQ.URL "\\"/\\""\n'
               'add rewrite policy rw_pol_old true rw_act_old\n'
               'add responder action rs_act_used respondwith "\\"HTTP/1.1 200 OK\\r\\n\\r\\n\\""\n'
               'add responder policy rs_pol_used true rs_act_used\n'
               'bind lb vserver lb_web -policyName rs_pol_used -priority 100 -gotoPriorityExpression END -type REQUEST\n'
               'add ssl certKey cert_unused -cert unused.pem -key unused.key\n'
        )
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ns.conf"
            f.write_text(src)
            p = Project.load([str(f)])
        cl = {nid.split("|")[-1]: d["clean"] for nid, d in p.dep.items() if "clean" in d}
        self.assertEqual({k for k, c in cl.items() if c["cat"] == "unused"},
                         {"lb_internal", "sg_old", "mon_old", "rw_pol_old", "rw_act_old", "cert_unused"})
        self.assertEqual({k for k, c in cl.items() if c["cat"] == "disabled"}, {"lb_legacy", "svc_old", "old1", "old2"})
        for k in ("lb_web", "sg_web", "web1", "mon_http", "rs_pol_used", "rs_act_used"):
            self.assertNotIn(k, cl)
        self.assertTrue(all(c["sure"] for c in cl.values()))   # the bind in sg_web becomes an unbind, no "check"
        self.assertEqual(p.clean_summary, {"unused": 6, "disabled": 4, "check": 0})

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_cleanup_batch_and_rollback(self):
        """Cleanup batch: users removed before what they use (also with a shared name), rollback adds in reverse order,
        masked secrets are commented out in the rollback."""
        import tempfile, json, subprocess
        src = ('add authentication ldapAction ldap_old -serverIP 192.0.2.30 -ldapBindDnPassword secret1 -encrypted\n'
               'add authentication ldapPolicy ldap_old "ns_true" ldap_old\n'
               'add rewrite action rw_x replace HTTP.REQ.URL "\\"/\\""\n'
               'add rewrite policy rw_x true rw_x\n'
               'add lb vserver lb_x HTTP 0.0.0.0 0\n'
               'bind lb vserver lb_x -policyName rw_x -priority 100 -type REQUEST\n')
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ns.conf"
            f.write_text(src)
            d = Project.load([str(f)]).to_dict()
            dj = Path(td) / "d.json"
            dj.write_text(json.dumps({k: d[k] for k in ("nodes", "edges", "groups", "meta")}))
            assets = Path(__file__).resolve().parent.parent / "nsviz" / "assets"
            js = Path(td) / "run.js"
            js.write_text("""const fs = require('fs'); const [a, f] = process.argv.slice(2);
const ex = fs.readFileSync(a + '/export.js', 'utf8').split('\\n');
const i0 = ex.findIndex(l => l.startsWith('const NCFG_SKIP')), i1 = ex.findIndex(l => l.startsWith('function ncfgStart'));
const code = ex.slice(i0, i1).join('\\n') + '\\n' + fs.readFileSync(a + '/cleanup.js', 'utf8');
const D = JSON.parse(fs.readFileSync(f, 'utf8')); const nodeById = {}; D.nodes.forEach(x => nodeById[x.id] = x);
const api = new Function('D', 'nodeById', 'state', 'cy', '$', 't', 'esc', 'infoBtn', 'kindLabel', code + '\\nreturn { buildClean };')(
  D, nodeById, { group: null }, {}, () => null, k => k, s => s, s => s, k => k);
console.log(JSON.stringify([api.buildClean(false, false, true).text, api.buildClean(false, true, true).text]));""")
            out = subprocess.run(["node", str(js), str(assets), str(dj)], capture_output=True, text=True, check=True).stdout
        batch, rb = json.loads(out)
        rm = [l for l in batch.splitlines() if l.startswith("rm ")]
        self.assertLess(rm.index("rm lb vserver lb_x"), rm.index("rm rewrite policy rw_x"))
        self.assertLess(rm.index("rm rewrite policy rw_x"), rm.index("rm rewrite action rw_x"))
        self.assertLess(rm.index("rm authentication ldapPolicy ldap_old"), rm.index("rm authentication ldapAction ldap_old"))
        adds = [l for l in rb.splitlines() if l.startswith("add ")]
        self.assertLess(adds.index('add rewrite action rw_x replace HTTP.REQ.URL "\\"/\\""'), adds.index("add rewrite policy rw_x true rw_x"))
        self.assertTrue(any(l.startswith("# SECRET MASKED") and "ldapAction ldap_old" in l for l in rb.splitlines()))
        self.assertNotIn("secret1", rb)
        self.assertIn("bind lb vserver lb_x -policyName rw_x -priority 100 -type REQUEST", rb)

    def test_extended_rules(self):
        """Rules for load balancing, network, cluster, content policies, gateway and system settings."""
        src = ("set ns config -IPAddress 192.0.2.5 -netmask 255.255.255.0\n"
               "add ns ip 192.0.2.6 255.255.255.0 -type SNIP\n"
               "add route 10.9.0.0 255.255.0.0 203.0.113.1\n"
               "add vlan 20\nadd ns trafficDomain 3\n"
               "add cluster instance 1\nadd ha node 1 192.0.2.7\nadd cluster node 0 192.0.2.5\n"
               "enable ns mode L2\n"
               "add server s1 198.51.100.1\nadd server s2 198.51.100.1 -state DISABLED\n"
               "add service svc1 s1 HTTP 80 -healthMonitor NO\n"
               "add serviceGroup sg1 HTTP\nbind serviceGroup sg1 s2 80\n"
               "add lb vserver a HTTP 192.0.2.10 80 -backupVServer b\nadd lb vserver b HTTP 192.0.2.11 80 -backupVServer a\n"
               "add ssl certKey c1 -cert same.pem -key k1\nadd ssl certKey c2 -cert same.pem -key k2\n"
               "add rewrite action ra replace HTTP.RES.BODY(100) \"x\"\nadd rewrite policy rp true ra\n"
               "bind lb vserver a -policyName rp -priority 10 -type REQUEST\n"
               "add vpn sessionAction sa -icaProxy ON -defaultAuthorizationAction ALLOW\n"
               "add vpn sessionPolicy sp true sa\nadd vpn vserver gw SSL 192.0.2.50 443\nbind vpn vserver gw -policy sp -priority 10\n"
               "add snmp community mon GET_ALL\nadd ntp server 192.0.2.99\nadd dns nameServer 192.0.2.53\n")
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ns.conf"
            f.write_text(src)
            p = Project.load([str(f)])
        got = {x.rule_id for x in p.findings}
        for rid in ("LB-001", "LB-003", "NET-001", "NET-002", "NET-003", "CLU-001", "CLU-002", "MODE-001", "QA-013", "QA-014",
                    "QA-015", "RW-001", "VPN-001", "VPN-002", "VPN-003", "MGMT-015", "MGMT-016", "MGMT-017"):
            self.assertIn(rid, got, rid)

    def test_rule_configuration(self):
        """Disabled rules, severity changes and exceptions with reason and expiry."""
        import tempfile
        from nsviz import ruleconfig
        src = "add server s1 198.51.100.1\nadd server s2 198.51.100.2\nadd lb vserver lb_old HTTP 192.0.2.10 80\nadd lb vserver lb_new HTTP 192.0.2.11 80\n"
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ns.conf"
            f.write_text(src)
            base = Project.load([str(f)])
            cfg = {"format": "nsviz-rules", "version": 1, "disable": ["QA-003"], "severity": {"QA-001": "info"},
                   "exceptions": [{"rule": "QA-001", "object": "lb_old", "reason": "decommissioned in Q3"},
                                  {"rule": "QA-001", "object": "lb_new", "reason": "old", "expires": "2000-01-01"}]}
            p = Project.load([str(f)], rule_config=ruleconfig.validate(cfg))
        self.assertTrue(any(x.rule_id == "QA-003" for x in base.findings))
        self.assertFalse(any(x.rule_id == "QA-003" for x in p.findings))
        qa1 = {x.name: x.severity for x in p.findings if x.rule_id == "QA-001"}
        self.assertEqual(qa1, {"lb_new": "info"})                     # lb_old accepted, the expired exception no longer applies
        self.assertEqual([(x.name, r) for x, r, _ in p.suppressed], [("lb_old", "decommissioned in Q3")])
        self.assertEqual(p.to_dict()["suppressed"][0]["reason"], "decommissioned in Q3")
        for bad in ({"format": "x"}, {"format": "nsviz-rules", "disable": ["NOPE-1"]},
                    {"format": "nsviz-rules", "exceptions": [{"rule": "QA-001"}]}):
            with self.assertRaises(ValueError):
                ruleconfig.validate(bad)

    def test_compare_states(self):
        """Comparison of two states: added, removed and changed objects, new and resolved findings."""
        import tempfile
        from nsviz import compare
        old = ("add server s1 198.51.100.1\nadd serviceGroup sg1 HTTP\nbind serviceGroup sg1 s1 80\n"
               "add lb vserver lb1 HTTP 192.0.2.10 80\nbind lb vserver lb1 sg1\nadd lb vserver gone HTTP 192.0.2.11 80\n"
               "add authentication ldapAction la -serverIP 192.0.2.30 -ldapBindDnPassword oldsecret\n")
        new = ("add server s1 198.51.100.1\nadd serviceGroup sg1 HTTP\nbind serviceGroup sg1 s1 8080\n"
               "add lb vserver lb1 HTTP 192.0.2.10 80 -persistenceType SOURCEIP\nbind lb vserver lb1 sg1\n"
               "add lb vserver fresh HTTP 192.0.2.12 80\n"
               "add authentication ldapAction la -serverIP 192.0.2.30 -ldapBindDnPassword newsecret\n")
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.conf").write_text(old)
            (Path(td) / "b.conf").write_text(new)
            res = compare.compare(Project.load([str(Path(td) / "a.conf")]), Project.load([str(Path(td) / "b.conf")]))
            page = compare.render(res, "a", "b", "de")
        dev = res["devices"][0]
        self.assertEqual([o["name"] for o in dev["added"]], ["fresh"])
        self.assertEqual([o["name"] for o in dev["removed"]], ["gone"])
        changed = {o["name"] for o in dev["changed"]}
        self.assertTrue({"lb1", "sg1"} <= changed)
        self.assertNotIn("oldsecret", page)
        self.assertNotIn("newsecret", page)
        self.assertIn("Konfigurationsvergleich", page)
        self.assertEqual(compare.summary(res)["added"], 1)

    def test_gateway_epa_clientcert_html(self):
        """HTML-encoded files are decoded; client certificate, EPA (pre-auth, nFactor, post-auth) and option names."""
        src = ('add ssl certKey ca_root -cert ca_root.cer\n'
               'add authentication epaAction epa_act -csecexpr "sys.client_expr(\\"proc_0_x\\")" -defaultEPAGroup ok\n'
               'add authentication Policy p_epa -rule true -action epa_act\n'
               'add authentication vserver aaa1 SSL 0.0.0.0\n'
               'bind authentication vserver aaa1 -policy p_epa -priority 100\n'
               'add authentication authnProfile prof1 -authnVsName aaa1\n'
               'add aaa preauthenticationaction pre_act ALLOW -defaultEPAGroup epa_ok\n'
               'add aaa preauthenticationpolicy pre_pol "CLIENT.OS(win10) EXISTS" pre_act\n'
               'add vpn sessionAction sa1 -clientSecurity "CLIENT.APPLICATION.PROCESS(av.exe) EXISTS" -SSO ON\n'
               'add vpn sessionPolicy sp1 "HTTP.REQ.HEADER(\\"User-Agent\\").CONTAINS(\\"X\\") && true" sa1\n'
               'set vpn parameter -splitTunnel OFF\n'
               'add vpn vserver gw1 SSL 192.0.2.50 443 -authnProfile prof1\n'
               'bind vpn vserver gw1 -policy pre_pol -priority 10\n'
               'bind vpn vserver gw1 -policy sp1 -priority 100\n'
               'set ssl vserver gw1 -clientAuth ENABLED -clientCert Mandatory\n'
               'bind ssl vserver gw1 -certkeyName ca_root -CA -ocspCheck Optional\n')
        enc = src.replace("&", "&amp;").replace('"', "&quot;")
        cfg = Config.parse_text(enc)
        self.assertTrue(cfg.html_decoded)
        g = Graph(cfg, "g1")
        gv = g.gateway_view()
        gw = gv["gateways"][0]
        sp = [x for x in gw["policies"] if x["policy"] == "sp1"][0]
        self.assertEqual(sp["action"], "sa1")                              # not split at blanks or "&&"
        self.assertIn("&&", sp["rule"])
        self.assertEqual(gw["clientcert"]["mode"], "Mandatory")
        self.assertEqual(gw["clientcert"]["ca"], ["ca_root"])
        self.assertEqual(gw["preauth"][0]["verdict"], "ALLOW")
        self.assertEqual(gv["global"]["params"]["splittunnel"], "OFF")
        self.assertEqual(gv["names"]["clientsecurity"], "clientSecurity")
        fl = g.auth_flows()
        row = fl["factors"]["g1|authentication vserver|aaa1"]["rows"][0]
        self.assertEqual(row["action"]["type"], "EPA")
        self.assertEqual(row["action"]["opts"]["defaultepagroup"], "ok")

    def test_auth_flows(self):
        """nFactor flow: factors in priority order, login schemas, next factor, decision and classic gateway policies."""
        src = ('add authentication loginSchema ls1 -authenticationSchema "/nsconfig/loginschema/LoginSchema/SingleAuth.xml"\n'
               'add authentication loginSchemaPolicy lsp1 -rule true -action ls1\n'
               'add authentication ldapAction ldap1 -serverIP 192.0.2.10\n'
               'add authentication radiusAction rad1 -serverIP 192.0.2.20\n'
               'add authentication Policy p_ldap -rule true -action ldap1\n'
               'add authentication Policy p_dec -rule true -action NO_AUTHN\n'
               'add authentication Policy p_rad -rule true -action rad1\n'
               'add authentication policylabel lbl2 -loginSchema LSCHEMA_INT\n'
               'bind authentication policylabel lbl2 -policyName p_rad -priority 100 -gotoPriorityExpression NEXT\n'
               'add authentication vserver aaa1 SSL 0.0.0.0\n'
               'bind authentication vserver aaa1 -policy lsp1 -priority 100\n'
               'bind authentication vserver aaa1 -policy p_ldap -priority 200 -nextFactor lbl2 -gotoPriorityExpression NEXT\n'
               'bind authentication vserver aaa1 -policy p_dec -priority 100 -gotoPriorityExpression END\n'
               'add authentication authnProfile prof1 -authnVsName aaa1\n'
               'add vpn vserver gw1 SSL 192.0.2.50 443 -authnProfile prof1\n'
               'add authentication ldapPolicy cl1 ns_true ldap1\n'
               'add vpn vserver gw2 SSL 192.0.2.51 443\n'
               'bind vpn vserver gw2 -policy cl1 -priority 100 -secondary\n')
        g = Graph(Config.parse_text(src), "g1")
        fl = g.auth_flows()
        aaa = fl["factors"]["g1|authentication vserver|aaa1"]
        self.assertEqual([r["policy"] for r in aaa["rows"]], ["p_dec", "p_ldap"])         # priority order, schema policy separate
        self.assertEqual(aaa["schemas"][0]["file"], "SingleAuth.xml")
        self.assertEqual(aaa["rows"][0]["action"]["type"], "NO_AUTHN")
        self.assertEqual(aaa["rows"][1]["action"]["type"], "LDAP")
        self.assertEqual(aaa["rows"][1]["next_id"], "g1|authentication policylabel|lbl2")
        self.assertTrue(fl["factors"]["g1|authentication policylabel|lbl2"]["schemas"][0]["builtin"])
        ent = {e["name"]: e for e in fl["entries"]}
        self.assertEqual(ent["gw1"]["factor"], "g1|authentication vserver|aaa1")
        self.assertEqual(ent["gw1"]["via"], "prof1")
        self.assertEqual(fl["factors"][ent["gw2"]["factor"]]["rows"][0]["role"], "secondary")
        self.assertNotIn("aaa1", ent)                                                      # reached through gw1

    def test_supporting_objects_and_builtin_actions(self):
        src = ('add ns httpProfile hp_custom -http2 ENABLED\n'
               'add ns tcpProfile tp_custom -WS ENABLED\n'
               'add lb vserver lb2 HTTP 192.0.2.5 80 -httpProfileName hp_custom -tcpProfileName tp_custom\n'
               'add cache contentGroup cg1\n'
               'add cache policy cp1 -rule true -action CACHE -storeInGroup cg1\n'
               'add ns assignment as1 -variable $v1 -set 1\n'
               'add authentication Policy ap_noauth -rule true -action NO_AUTHN\n'
               'add authentication Policy ap_var -rule true -action as1\n')
        g = Graph(Config.parse_text(src), "g1")
        by = {(n.etype, n.name): n for n in g.nodes.values()}
        lb = [l["text"] for l in by[("lb vserver", "lb2")].lines]
        self.assertIn("add ns httpProfile hp_custom -http2 ENABLED", lb)       # profiles named in options travel along
        self.assertIn("add ns tcpProfile tp_custom -WS ENABLED", lb)
        cp = [n for n in g.nodes.values() if n.name == "cp1"]
        if cp:
            self.assertIn("add cache contentGroup cg1", [l["text"] for l in cp[0].lines])
        self.assertFalse([n for n in g.nodes.values() if n.kind == "missing"])  # NO_AUTHN is built in, as1 is an assignment


class DebugAnonTests(unittest.TestCase):
    def test_debug_data_has_no_originals(self):
        p = Project.load([str(DEMO)])
        d = p.to_dict()
        originals = set()
        for g in p.groups:
            for dv in g.devices:
                for et, ents in dv.cfg.entities.items():
                    originals |= {n for n in ents if len(n) >= 4 and not n.lower().startswith(("ns_", "default"))}
                originals |= set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "\n".join(st.raw for st in dv.cfg.statements)))
        originals = {o for o in originals if not o.startswith(("255.", "0.0.0.0", "127."))}
        blob = json.dumps([[n["anon"] for n in d["nodes"]], [e["alabel"] for e in d["edges"]]])
        self.assertEqual([o for o in originals if re.search(r"(?<![\w.-])" + re.escape(o) + r"(?![\w-])", blob)], [])
        self.assertTrue(any(n["anon"]["lines"] for n in d["nodes"]))


class AnonymizeOptionTests(unittest.TestCase):
    SRC = "\n".join([
        "add ns ip 10.1.2.3 255.255.255.0 -type VIP",
        "add dns addRec sf.acme.de 10.1.2.40",
        "add vpn sessionAction sa -wihome \"https://sf.acme.de/Citrix/AcmeWeb\" -storefronturl \"https://storefront.acme.local\" -ssoDomain ACME",
        "add authentication ldapAction ldap1 -serverName dc01.acme.local -ldapBase \"OU=Staff,DC=acme,DC=local\" -ldapBindDn svc_ldap@acme.local "
        "-ldapBindDnPassword abc123 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2023_01_02_03_04_05 -ldapLoginName sAMAccountName",
        "add ssl certKey wild_acme -cert wildcard_acme_de_2025.pfx -key wildcard_acme_de_2025.pfx -inform PFX -passplain secretpass",
        "add snmp community s3cretcomm ALL",
        "add responder policy rp \"HTTP.REQ.HOSTNAME.EQ(\\\"portal.acme.de\\\") && HTTP.REQ.URL.STARTSWITH(\\\"/acmeportal/login\\\")\" NOOP",
        "add server ext1 81.2.3.4",  # arbitrary public address (documentation ranges count as private here)
        "add lb vserver lb1 HTTP 10.1.2.50 80 -comment \"Acme portal\"",
        "set interface 0/1 -ifAlias \"uplink acme core\"", ""])

    def run_(self, **opt):
        from nsviz.anonymize import anonymize_texts
        out, st, _ = anonymize_texts([("a.conf", self.SRC)], opt)
        return out[0][1], st

    def test_all_on(self):
        out, st = self.run_(comments=True, timezone=True, location=True)
        for secret in ("acme", "Acme", "ACME", "abc123", "secretpass", "s3cretcomm", "81.2.3.4", "10.1.2", "wildcard", "2023_01", "Staff", "svc_ldap"):
            self.assertNotIn(secret, out, secret)
        self.assertTrue(st["structure_ok"])
        self.assertEqual(st["leaks"], 0)
        self.assertIn("/Citrix/", out)                       # product path kept
        self.assertIn("sAMAccountName", out)                 # attribute names kept
        self.assertIn("HTTP.REQ.HOSTNAME.EQ(", out)          # expression structure kept
        self.assertRegex(out, r"https://sf\.corp\d+\.internal")  # generic label kept, internal (private DNS record)
        self.assertIn("198.18.", out)                        # public IP stays public (reserved range)
        self.assertIn("set interface 0/1", out)               # interface ids are not names
        self.assertRegex(out, r"DC=corp\d+,DC=internal")     # LDAP DN follows the domain mapping
        m = re.search(r"dc01\.(corp\d+)\.internal", out)
        self.assertIsNotNone(m)
        self.assertIn(f"DC={m.group(1)},DC=internal", out)     # same domain -> same pseudonym

    def test_optional_categories(self):
        from nsviz.anonymize import DEFAULT_OPTIONS
        self.assertFalse(any(DEFAULT_OPTIONS[k] for k in ("comments", "timezone", "location")))
        src = self.SRC + "\n".join([
            "# owner team 10.1.2.3", "set ns param -timezone \"GMT+01:00-CET-Europe/Berlin\" -cookieversion 1",
            "set snmp mib -location \"Rack 4\" -contact \"ops\"",
            "add location 10.1.9.0 10.1.9.255 \"Europe.DE.Hesse.*.*.*\" -latitude 50 -longitude 8", ""])
        from nsviz.anonymize import anonymize_texts
        out = anonymize_texts([("a.conf", src)])[0][0][1]       # default: kept, addresses inside replaced
        self.assertIn('-comment "Acme portal"', out)
        self.assertIn("# owner team 10.", out)
        self.assertNotIn("10.1.2.3", out)
        self.assertIn("GMT+01:00-CET-Europe/Berlin", out)
        self.assertIn('-location "Rack 4"', out)
        self.assertIn("Europe.DE.Hesse", out)
        out, st, _ = anonymize_texts([("a.conf", src)], {"comments": True, "timezone": True, "location": True})
        out = out[0][1]
        for gone in ("-comment", "# owner", "-timezone", "-location", "add location", "-latitude"):
            self.assertNotIn(gone, out, gone)
        self.assertIn("set ns param -cookieversion 1", out)
        self.assertTrue(st["structure_ok"])
        self.assertEqual(st["statements_in"], st["statements_out"])

    def test_keep_categories(self):
        out, st = self.run_(ips=False, fqdns=False)
        self.assertIn("81.2.3.4", out)
        self.assertIn("dc01.acme.local", out)
        self.assertNotIn("abc123", out)  # secrets always go
        self.assertTrue(st["structure_ok"])


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
        self.assertEqual(sorted(s["host"] for s in c["sources"]), ["extra.backend.example.test", "sta.example.com", "storefront.example.com", "storefront.example.com"])  # service target, STA URL, StoreFront of both session actions
        self.assertTrue(any(t["ip"] == "10.20.0.52" and t["port"] == "8080" for t in c["targets"]))
        self.assertEqual(fqdns(p), ["extra.backend.example.test", "sta.example.com", "storefront.example.com"])

    def test_map_roundtrip_adds_chain(self):
        from nsviz.linking import collect, MAP_FORMAT
        p0 = Project.load([str(DEMO)])
        c = collect(p0)
        src = next(x["key"] for x in c["sources"] if not x.get("url"))
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


class DependencyTests(unittest.TestCase):
    CONF = "\n".join([
        "add server s1 10.0.0.5",
        "add service svc1 s1 HTTP 80",
        "add lb vserver lb_front HTTP 192.0.2.10 80",
        "bind lb vserver lb_front svc1",
        "add lb vserver lb_hidden HTTP 0.0.0.0 0",          # non-addressable, targeted by CS policy
        "bind lb vserver lb_hidden svc1",
        "add lb vserver lb_orphan HTTP 0.0.0.0 0",          # non-addressable, nobody points to it
        "add lb vserver lb_wild HTTP 0.0.0.0 443",          # wildcard address with port = addressable
        "add cs vserver cs1 SSL 192.0.2.20 443",
        "add cs action act1 -targetLBVserver lb_hidden",
        "add cs policy pol1 -rule \"HTTP.REQ.URL.CONTAINS(\\\"/a\\\")\" -action act1",
        "bind cs vserver cs1 -policyName pol1 -priority 10",
        "bind cs vserver cs1 lb_front",
        "add vpn sessionAction sa -wihome \"https://192.0.2.10:80/Citrix/Store\"",
        "add vpn sessionPolicy sp ns_true sa",
        "add vpn vserver gw SSL 192.0.2.30 443",
        "bind vpn vserver gw -policy sp -priority 100",
        "add vpn sessionAction sa2 -wihome \"https://store.example.test/Citrix/Store\"",
        "add vpn sessionPolicy sp2 ns_true sa2",
        "bind vpn vserver gw -policy sp2 -priority 110",
        "add lb vserver lb_dns DNS 0.0.0.0 0",
        "add dns nameserver lb_dns",
        "add lb vserver lb_callout HTTP 0.0.0.0 0",
        "add policy httpCallout co1 -vServer lb_callout",
        "add lb vserver lb_label_target HTTP 0.0.0.0 0",
        "add cs policylabel lbl1 http_req",
        "add cs policy pol2 -rule true -action act1",
        "bind cs policylabel lbl1 pol2 20 -targetVserver lb_label_target",
        "bind cs vserver cs1 -policyName pol1 -priority 20 -type REQUEST -labelType policylabel -labelName lbl1",
        "add server unused 10.9.9.9", ""])

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        f = Path(self.tmp.name) / "a.ns.conf"
        f.write_text(self.CONF)
        self.p = Project.load([str(f)])
        self.g = self.p.groups[0].graph

    def tearDown(self):
        self.tmp.cleanup()

    def node(self, name):
        return next(n for n in self.g.nodes.values() if n.name == name)

    def test_fqdn_target_marked(self):
        n = self.node("sa2")
        self.assertIn("store.example.test", n.props.get("FQDN target", ""))
        self.assertTrue(self.p.dep[n.id].get("fqdn"))
        self.assertNotIn("FQDN target", self.node("sa").props)

    def test_addressing_and_reachability(self):
        self.assertTrue(self.node("lb_wild").props["Addressing"].startswith("addressable"))
        self.assertTrue(self.node("lb_hidden").props["Addressing"].startswith("non-addressable"))
        dep = self.p.dep
        self.assertTrue(dep[self.node("lb_hidden").id]["reach"])      # via CS policy -> action
        self.assertFalse(dep[self.node("lb_orphan").id]["reach"])
        for nm in ("lb_dns", "lb_callout", "lb_label_target"):
            self.assertTrue(dep[self.node(nm).id]["reach"], nm)
        self.assertTrue(any(f.rule_id == "DEP-001" and f.name == "lb_orphan" for f in self.p.findings))
        self.assertFalse(any(f.rule_id == "DEP-001" and f.name == "lb_hidden" for f in self.p.findings))

    def test_cs_and_gateway_edges(self):
        ids = {n.name: n.id for n in self.g.nodes.values()}
        edges = {(e.source, e.target) for e in self.g.edges}
        self.assertIn((ids["cs1"], ids["lb_front"]), edges)           # default target
        self.assertIn((ids["pol1"], ids["lb_hidden"]), edges)          # policy target (via action)
        self.assertIn((ids["sa"], ids["lb_front"]), edges)             # session action URL -> local vServer by IP:port
        self.assertTrue(any(f.rule_id == "DEP-002" and f.name == "sa2" for f in self.p.findings))   # FQDN: shown separately, not guessed
        self.assertTrue(any(u["host"] == "store.example.test" for u in self.g.unresolved))


class GuiTests(unittest.TestCase):
    def test_gui_addpath_restricted_to_allowed_roots(self):
        import os, tempfile
        from nsviz import gui
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as other:
            f = Path(allowed) / "a.ns.conf"
            f.write_text("add lb vserver x HTTP 10.0.0.1 80\n")
            out = Path(other) / "b.ns.conf"
            out.write_text("x\n")
            st = gui.State(allow_roots=(allowed,))
            st.roots = [os.path.realpath(allowed)]  # only this folder: on Windows the temp folders lie below the home folder, which is allowed by default
            try:
                self.assertEqual(st.local_path(str(f)), [f.resolve()])
                self.assertEqual(st.local_path(allowed), [f.resolve()])
                with self.assertRaises(ValueError):
                    st.local_path(str(out))
                with self.assertRaises(ValueError):
                    st.local_path(allowed + "/../" + Path(other).name + "/b.ns.conf")
                with self.assertRaises(ValueError):
                    st.local_path(str(Path(allowed) / "missing.conf"))
                # a symlink inside the allowed folder that points outside is neither listed nor accepted directly
                try:
                    os.symlink(out, Path(allowed) / "link.ns.conf")
                except (OSError, NotImplementedError):
                    return
                self.assertEqual(st.local_path(allowed), [f.resolve()])
                with self.assertRaises(ValueError):
                    st.local_path(str(Path(allowed) / "link.ns.conf"))
            finally:
                shutil.rmtree(st.dir, ignore_errors=True)

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
            opts = json.load(call("/api/anon-options"))["options"]
            self.assertTrue(any(o["key"] == "secrets" and o["fixed"] for o in opts))
            an = json.load(call("/api/anonymize", json.dumps({"files": [x["name"] for x in files], "map": True}).encode()))
            self.assertTrue(an["stats"]["structure_ok"])
            self.assertEqual(an["stats"]["leaks"], 0)
            one = call(f"/anon/{an['id']}/0").read().decode()
            self.assertIn("add ", one)
            self.assertTrue(call(f"/anon/{an['id']}/zip").read().startswith(b"PK"))
            self.assertIn("names", json.load(call(f"/anon/{an['id']}/map")))
            call("/api/reset", b"{}")
            self.assertEqual(json.load(call("/api/files"))["files"], [])
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



class ChainCoverageTests(unittest.TestCase):
    """Reference forms that used to be missed: -invoke, CS -> Gateway via cs action, certificate chains, internal services,
    global STA, local DNS records, policies bound to AAA groups, bookmarks, generic safety net."""
    CONF = "\n".join([
        "add server s1 10.0.0.5",
        "add service svc1 s1 HTTP 80",
        "add lb vserver lb_front HTTP 192.0.2.10 80",
        "bind lb vserver lb_front svc1",
        "add lb vserver lb_sf HTTP 192.0.2.11 80",
        "bind lb vserver lb_sf svc1",
        "add lb vserver lb_inv HTTP 0.0.0.0 0",
        "bind lb vserver lb_inv svc1",
        "add rewrite action ra1 replace HTTP.REQ.URL \"\\\"/\\\"\"",
        "add rewrite policy rp1 true ra1",
        "add rewrite policy rp2 true ra1",
        "add rewrite policylabel rl1 http_req",
        "bind rewrite policylabel rl1 rp2 10 END",
        "bind lb vserver lb_front -policyName rp1 -priority 10 -gotoPriorityExpression NEXT -type REQUEST -invoke policylabel rl1",
        "add responder policy resp1 true NOOP",
        "bind lb vserver lb_front -policyName resp1 -priority 20 -gotoPriorityExpression NEXT -type REQUEST -invoke reqvserver lb_inv",
        "add vpn vserver gw SSL 0.0.0.0 0",
        "add authentication vserver aaa1 SSL 0.0.0.0 0",
        "add cs vserver cs1 SSL 192.0.2.20 443",
        "add cs action a_gw -targetVserver gw",
        "add cs policy p_gw -rule true -action a_gw",
        "bind cs vserver cs1 -policyName p_gw -priority 10",
        "add ssl certkey leaf -cert leaf.crt -key leaf.key",
        "add ssl certkey inter -cert inter.crt",
        "link ssl certkey leaf inter",
        "bind ssl vserver cs1 -certkeyName leaf",
        "add ssl certkey mgmt -cert mgmt.crt -key mgmt.key",
        "bind ssl service nshttps-127.0.0.1-443 -certkeyName mgmt",
        "bind vpn global -staServer \"http://10.0.0.9\"",
        "add dns addRec sf.example.test 192.0.2.11",
        "add vpn sessionAction sa -wihome \"https://sf.example.test:80/Citrix/StoreWeb\"",
        "add vpn sessionPolicy sp true sa",
        "bind vpn vserver gw -policy sp -priority 100",
        "add vpn url bm1 Intranet http://intranet.example.test",
        "bind vpn vserver gw -urlName bm1",
        "add vpn sessionAction sa_grp -splitTunnel OFF",
        "add vpn sessionPolicy sp_grp true sa_grp",
        "add aaa group g1",
        "bind aaa group g1 -policy sp_grp -priority 10",
        "add ssl profile sp_mon -sslProfileType BackEnd",
        "add lb monitor mon1 HTTP -secure YES -sslProfile sp_mon",
        "bind service svc1 -monitorName mon1",
        ""])

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        f = Path(self.tmp.name) / "c.ns.conf"
        f.write_text(self.CONF)
        self.p = Project.load([str(f)])
        self.g = self.p.groups[0].graph

    def tearDown(self):
        self.tmp.cleanup()

    def n(self, etype, name):
        return self.g.node_for(etype, name)

    def edge(self, a, b):
        return any(e.source == a.id and e.target == b.id for e in self.g.edges)

    def reach(self, etype, name):
        return self.p.dep[self.n(etype, name).id]["reach"]

    def test_invoke_policylabel(self):
        self.assertTrue(self.reach("rewrite policylabel", "rl1"))
        self.assertTrue(self.reach("rewrite policy", "rp2"))

    def test_invoke_vserver(self):
        self.assertTrue(self.edge(self.n("responder policy", "resp1"), self.n("lb vserver", "lb_inv")))
        self.assertTrue(self.reach("lb vserver", "lb_inv"))

    def test_cs_action_to_gateway(self):
        self.assertTrue(self.edge(self.n("cs policy", "p_gw"), self.n("vpn vserver", "gw")))
        self.assertTrue(self.reach("vpn vserver", "gw"))
        self.assertFalse(self.reach("authentication vserver", "aaa1"))

    def test_certificate_chain_and_internal_service(self):
        self.assertTrue(self.edge(self.n("ssl certkey", "leaf"), self.n("ssl certkey", "inter")))
        self.assertTrue(self.reach("ssl certkey", "inter"))
        self.assertTrue(self.reach("ssl certkey", "mgmt"))

    def test_global_sta_and_dns_record(self):
        self.assertTrue(any(n.kind == "sta" and self.p.dep[n.id]["reach"] for n in self.g.nodes.values()))
        sa = self.n("vpn sessionaction", "sa")
        self.assertTrue(self.edge(sa, self.n("lb vserver", "lb_sf")))
        self.assertNotIn("FQDN target", sa.props)

    def test_group_policy_and_bookmark(self):
        self.assertTrue(self.reach("vpn sessionaction", "sa_grp"))
        self.assertFalse(any(m["ref_type"] == "vpn url" for m in self.g.missing))

    def test_generic_safety_net(self):
        self.assertTrue(self.reach("ssl profile", "sp_mon"))
        self.assertIn(("lb monitor", "sslprofile", "ssl profile"), self.g.generic_refs)

    def test_no_dep001_for_reached(self):
        names = {f.name for f in self.p.findings if f.rule_id == "DEP-001"}
        self.assertEqual(names, {"aaa1"})


if __name__ == "__main__":
    unittest.main()
