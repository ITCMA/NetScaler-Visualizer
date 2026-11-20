# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/) (0.x = interface may change).

## [Unreleased]
### Added
- Parser for ns.conf (13.1 / 14.1 / 15.1), entity model, topology graph, HA pair detection and diff, double-hop chains.
- About 60 check rules (misconfiguration, best practice, compliance) with confidence levels and references.
- Single-file offline HTML report: topology, findings, inventory, project view, rule catalog, overview with health score.
- UI in 8 languages (de, en, es, fr, pt, zh, ja, hi), light/dark theme, keyboard operation, reduced-motion support.
- Rule texts and finding messages in English and German.
- CSV/JSON export, `--fail-on` exit code for CI, secret masking in embedded config lines.
- Trademark/affiliation disclaimer in the report.
