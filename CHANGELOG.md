# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/) (0.x = interface may change).

## [Unreleased]
### Added
- Topology: responder/rewrite/session actions as nodes (policy → action) and AAA groups with their bound policies.
- Corpus helper `scripts/corpus_stats.py` (duplicate detection, content-free statistics) for private config collections.
- Parser for ns.conf (13.1 / 14.1 / 15.1), entity model, topology graph, HA pair detection and diff, double-hop chains.
- About 60 check rules (misconfiguration, best practice, compliance) with confidence levels and references.
- Single-file offline HTML report: topology, findings, inventory, project view, rule catalog, overview with health score.
- UI in 8 languages (de, en, es, fr, pt, zh, ja, hi), light/dark theme, keyboard operation, reduced-motion support.
- Rule texts and finding messages in English and German.
- CSV/JSON export, `--fail-on` exit code for CI, secret masking in embedded config lines.
- Trademark/affiliation disclaimer in the report.

### Changed
- HA drift: more than 40 differences between two nodes produce one summary finding instead of one per difference.
- Fewer false positives: system-generated policy names (leading `_`, all-caps with hyphen) are not reported as missing (assumption, to be verified against the documentation); policies bound to AAA groups/users count as used.
