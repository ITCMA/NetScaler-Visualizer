"""Command line: ``python -m nsviz analyze <files|folders> -o report.html``."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import __version__, report
from .project import Project
from .rules import RULES, SEVERITIES, CATEGORIES, load_builtin_rules


_MD = {
    "en": {
        "title": "# Check rules", "cats": {"misconfig": "Misconfiguration", "best-practice": "Best practice", "compliance": "Compliance (BSI / vendor guidance)"},
        "intro": ["Generated with `python -m nsviz rules --markdown`. Every rule has a severity, a category and a **confidence** "
                  "(`certain` = derivable from the config alone, `likely` = common assumption, `heuristic` = approximation, please verify case by case).",
                  "> References to BSI modules and the vendor secure deployment guidance name the module or topic, **not** individual "
                  "requirement IDs. The mapping is a technical classification and must be checked against the current edition before use in an audit."],
        "sev": "Severity", "conf": "Confidence", "why": "Rationale", "fix": "Remediation", "src": "Sources"},
    "de": {
        "title": "# Prüfregeln", "cats": {"misconfig": "Fehlkonfiguration", "best-practice": "Best Practice", "compliance": "Compliance (BSI / Herstellervorgaben)"},
        "intro": ["Automatisch erzeugt mit `python -m nsviz rules --markdown --lang de`. Jede Regel hat Schweregrad, Kategorie und eine "
                  "**Sicherheit der Aussage** (`certain` = eindeutig aus der Config ableitbar, `likely` = übliche Annahme, "
                  "`heuristic` = Näherung, bitte im Einzelfall prüfen).",
                  "> Die Verweise auf BSI-Bausteine und die Secure-Deployment-Hinweise des Herstellers nennen den Baustein bzw. das Thema, "
                  "**nicht** einzelne Anforderungs-IDs. Das Mapping ist als fachliche Einordnung gedacht und sollte vor Verwendung in einem Audit "
                  "gegen die jeweils aktuelle Fassung geprüft werden."],
        "sev": "Schweregrad", "conf": "Sicherheit der Aussage", "why": "Begründung", "fix": "Behebung", "src": "Quellen"},
}


def _load_rules() -> None:
    load_builtin_rules()
    import nsviz.project  # noqa: F401 (registers project-level rules)


def _rules_markdown(lang: str = "en") -> str:
    _load_rules()
    m = _MD[lang]
    out = [m["title"], ""]
    for line in m["intro"]:
        out += [line, ""]
    for cat in CATEGORIES:
        rs = [r for r in RULES.values() if r.category == cat]
        out += [f"## {m['cats'][cat]}", ""]
        for r in sorted(rs, key=lambda r: (SEVERITIES.index(r.severity), r.id)):
            t = r.text(lang)
            out += [f"### {r.id} – {t['title']}", "",
                    f"- **{m['sev']}:** {r.severity} · **{m['conf']}:** {r.confidence}",
                    f"- **{m['why']}:** {t['rationale']}", f"- **{m['fix']}:** {t['remediation']}",
                    f"- **{m['src']}:** {'; '.join(r.refs) if r.refs else '–'}", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nsviz", description="Read, check and visualize NetScaler ns.conf files as an offline HTML report")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="Analyze configs and write an HTML report")
    a.add_argument("paths", nargs="+", help="ns.conf files or folders")
    a.add_argument("-o", "--output", default="netscaler-report.html")
    a.add_argument("--ha", action="append", default=[], metavar="A,B", help="treat two files/device names as an HA pair (repeatable)")
    a.add_argument("--role", action="append", default=[], metavar="FILE=primary|secondary")
    a.add_argument("--no-redact", action="store_true", help="do NOT mask passwords/keys in the embedded config lines")
    a.add_argument("--json", metavar="FILE", help="also write the complete result as JSON")
    a.add_argument("--csv", metavar="FILE", help="write findings as CSV (Excel, semicolon-separated)")
    a.add_argument("--fail-on", choices=SEVERITIES, help="exit code 2 if findings of this severity or higher exist (CI)")
    a.add_argument("--title", default="NetScaler Visualizer")
    a.add_argument("--map", metavar="FILE", help="link map (JSON) with confirmed/rejected cross-device links; save it from the report")
    a.add_argument("--hosts", metavar="FILE", help="FQDN->IP list (hosts format or CSV) used to suggest cross-device links")
    z = sub.add_parser("anonymize", help="write anonymized copies of configs (names, IPs, hosts, secrets, text)")
    z.add_argument("paths", nargs="+", help="ns.conf files or folders")
    z.add_argument("-o", "--output", required=True, help="output folder (created; must not be inside a git repository you push)")
    z.add_argument("--keep-literals", action="store_true", help="keep string literals in expressions (only hosts/IPs/names are replaced)")
    z.add_argument("--map-file", metavar="FILE", help="also write the reverse mapping (as sensitive as the input!)")
    g = sub.add_parser("gui", help="open the local web GUI (127.0.0.1 only) to pick configs and create the report")
    g.add_argument("--port", type=int, default=0, help="port (default: a free one)")
    g.add_argument("--no-browser", action="store_true", help="only print the URL")
    d = sub.add_parser("resolve", help="OPTIONAL: resolve the FQDNs found in the configs by DNS and write a hosts file (queries a DNS server!)")
    d.add_argument("paths", nargs="+", help="ns.conf files or folders")
    d.add_argument("-o", "--output", help="write the hosts file here (default: print)")
    d.add_argument("--server", default="", metavar="IP[:PORT]", help="DNS server to ask (default: the system resolver)")
    d.add_argument("--list", action="store_true", help="only list the names that would be asked, query nothing")
    d.add_argument("--yes", action="store_true", help="do not ask for confirmation (for scripts)")
    r = sub.add_parser("rules", help="list check rules")
    r.add_argument("--markdown", action="store_true")
    r.add_argument("--lang", choices=["en", "de"], default="en")
    a.add_argument("--lang", choices=["en", "de"], default="en", help="language of CSV texts and console output")
    args = ap.parse_args(argv)

    if args.cmd == "gui":
        from .gui import serve
        return serve(args.port, not args.no_browser)

    if args.cmd == "anonymize":
        from .anonymize import anonymize_paths
        st = anonymize_paths(args.paths, args.output, args.keep_literals, args.map_file)
        print(f"{st['files']} config(s) written to {args.output}; statements {st['statements_in']} -> {st['statements_out']}; "
              f"{st['names']} names, {st['ips']} subnets, {st['hosts']} hosts/e-mails replaced; possible leftovers to review: {st['leaks']}")
        print("Review the result manually before using it outside the private folder.")
        return 0 if st["statements_in"] == st["statements_out"] else 3

    if args.cmd == "resolve":
        from . import linking
        try:
            proj = Project.load(args.paths)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        names = linking.fqdns(proj)
        print(f"{len(names)} name(s) from the configs:")
        for nm in names:
            print("  " + nm)
        if args.list or not names:
            return 0
        print(f"\nThese names would be sent to: {args.server or 'the system DNS resolver of this computer (which server that is depends on your OS/network)'}")
        print("Customer host names then leave this computer; the DNS server and anything on the path can see them.")
        if not args.yes and input("Type 'yes' to query: ").strip().lower() != "yes":
            print("Aborted, nothing was sent.")
            return 0
        res = linking.resolve_names(names, args.server)
        text = "# resolved by nsviz resolve (explicit user request)\n" + "".join(f"{ip}\t{nm}\n" for nm, ip in sorted(res.items()))
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"{len(res)} of {len(names)} resolved -> {args.output}  (contains customer names: keep it private)")
        else:
            print(text)
        return 0

    if args.cmd == "rules":
        if args.markdown:
            print(_rules_markdown(args.lang))
        else:
            _load_rules()
            for rule in sorted(RULES.values(), key=lambda x: x.id):
                print(f"{rule.id:10} {rule.severity:9} {rule.category:14} {rule.text(args.lang)['title']}")
        return 0

    pairs = [tuple(x.split(",", 1)) for x in args.ha if "," in x]
    roles = dict(x.split("=", 1) for x in args.role if "=" in x)
    try:
        from . import linking
        lm = linking.load_map(args.map) if args.map else None
        if args.hosts:
            lm = lm or {"format": linking.MAP_FORMAT, "version": linking.MAP_VERSION, "links": []}
            lm.setdefault("hosts", {}).update(linking.load_hosts(args.hosts))
        proj = Project.load(args.paths, pairs, roles, redact=not args.no_redact, link_map=lm)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    out = report.write(proj, args.output, args.title)
    d = proj.to_dict()
    sev = {s: sum(1 for f in proj.findings if f.severity == s) for s in SEVERITIES}
    L = args.lang
    if L == "de":
        print(f"{len(proj.devices)} Gerät(e), {len(proj.groups)} Gruppe(n), {len(d['nodes'])} Objekte, {len(d['edges'])} Beziehungen")
        print("Befunde: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
    else:
        print(f"{len(proj.devices)} device(s), {len(proj.groups)} group(s), {len(d['nodes'])} objects, {len(d['edges'])} relations")
        print("Findings: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
    for n in proj.notes:
        print("Hinweis:" if L == "de" else "Note:", n.get(L) or n["en"])
    print("Report:", out)
    if args.json:
        Path(args.json).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    if args.csv:
        head = {"en": ["Severity", "Rule", "Title", "Category", "Finding", "Devices", "File", "Line", "Object"],
                "de": ["Schwere", "Regel", "Titel", "Kategorie", "Befund", "Geräte", "Datei", "Zeile", "Objekt"]}[L]
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow(head)
            for f in proj.findings:
                r = RULES.get(f.rule_id)
                w.writerow([f.severity, f.rule_id, r.text(L)["title"] if r else "", _MD[L]["cats"].get(r.category, "") if r else "",
                            f.msgs.get(L) or f.msgs["en"], " + ".join(f.devices), f.file, f.line, f"{f.etype} {f.name}".strip()])
    if args.fail_on:
        lim = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) <= lim for f in proj.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
