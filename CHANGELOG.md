# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/) (before 1.0 the
interface may change between minor versions).

## [Unreleased]

## [0.4.0] - 2026-11-21
### Added
- 22 further rules (82 in total): load balancing (health monitor, backup vServer loop), content switching, TLS options on
  vServers, network (routes, VLANs, traffic domains), cluster, application firewall, rewrite and responder bind points,
  Gateway (default authorization, STA, login attempts), management services and configuration quality.
- Rule configuration (`--rules`, GUI option): disable rules, change severities, record accepted exceptions with a reason
  and an optional expiry date. Accepted exceptions are listed in the Findings tab.
- `nsviz compare`: compares two configuration states per device (added, removed and changed objects and lines, new and
  resolved findings) and writes an HTML report.
- draw.io export of the topology.
- `docs/SIGNING.md`: signing and notarization of the macOS releases, notes on the unsigned Windows build;
  `scripts/release_macos.sh` (one run per architecture: sign the app bundle, build the DMG with the app icon, notarize,
  staple), `scripts/sign_app_macos.sh` and an entitlements file.
- macOS app bundle `nsviz.app` (PyInstaller, `scripts/build_app.py --bundle`): double-click opens the GUI; the command
  line is part of the bundle (`nsviz.app/Contents/MacOS/nsviz`). The release workflow builds it for Apple silicon and
  Intel; there is no separate command-line download for macOS.
### Changed
- Documentation, interface texts and release notes revised for end users, IT departments and service providers.
- Architecture document rewritten as a description of the current design.
- Faster analysis of large configurations through an index for bindings and certificate links (24,000 objects: 27 s to 10 s).

## [0.3.10] - 2026-11-21
### Added
- Release builds for Windows and macOS (Apple silicon and Intel) with GitHub Actions; a version tag creates a draft
  release with the files and SHA-256 checksums.
- README with key features, screenshots of the demo environment and getting started; issue and pull request templates;
  Dependabot for the GitHub Actions.
- Demo environment: Gateway with two session policies (ICA proxy, StoreFront).
### Fixed
- Packaged app: `--version` and the start failed because the code fingerprint read source files that are not packaged.
- Gateway tab: StoreFront URLs wrap at "/" instead of letter by letter.
- Rule catalog (`docs/RULES*.md`) lacked the cleanup rules.

## [0.3.9] - 2026-11-21
### Security
- Test data uses documentation addresses (RFC 5737) instead of public addresses where the test allows it.
- `.gitignore` excludes report exports, cleanup and rollback batches, transfer bundles and archives.

## [0.3.x] - 2026-11-21
### Added
- Gateway tab: parameters of each session policy with the global VPN settings and the effective value; client certificate
  authentication; endpoint analysis (pre-authentication policies, nFactor EPA factors, client security); export of the page
  as PNG, SVG or PDF.
- nFactor tab: client certificate on entry and authentication vServer; parameters of each authentication action; export of
  the page as PNG, SVG or PDF.
- Cleanup analysis with an ordered batch (`unbind`, `rm`) and a rollback batch.
- Configuration export of selected objects, optionally with all objects they depend on.
### Fixed
- Cleanup detection: an object counts as certain only when no remaining line names it; removal order follows the
  dependencies in the configuration lines; the rollback restores objects in reverse order and comments out lines with masked
  secrets.
- Configuration export uses the selected object by default; the Gateway export contains only the Gateway and what it needs.
- HTML-encoded configuration files (`&quot;` instead of `"`) are decoded.

## [0.2.x] - 2026-11-21
### Added
- Local interface `nsviz gui` (127.0.0.1 only, token, standard library only) to select configurations, roles, HA pairs, link
  map and options and to create the report.
- Linking of devices: suggestions by address, port and name, confirmation, manual links, hosts file import, link map,
  optional DNS lookup (`nsviz resolve`).
- Anonymization (`nsviz anonymize`, GUI section 5): consistent pseudonyms by category, secrets always removed, optional
  removal of comments, time zone and location data, structure check before and after.
- Export dialog: PNG, SVG, PDF, CSV, JSON and Markdown, scope all, view or selection, original or anonymized names.
- Debug mode (`--debug`) with anonymized description of the rule and configuration line behind every connection.
- Dependency analysis: objects not reachable from an addressable vServer or a global binding are marked; rules DEP-001 and
  DEP-002; FQDN targets are marked and resolved through the DNS records of the appliance.
- Report: Content Security Policy (no external requests), version and code fingerprint in the header.
### Changed
- Topology redesigned: cards with icons, tier columns per device or HA pair, several layouts, path highlighting, minimap,
  collapsible legend, high-contrast and dark variants.
- More complete dependency detection (policy invocation, Unified Gateway behind content switching, certificate chains, global
  STA servers, session action types, bookmarks), checked against a corpus of real configurations (counts only).

## [0.1.x] - 2026-11-21
### Added
- Parser for `ns.conf` (13.1, 14.1, 15.1), entity model, topology graph, HA pair detection and comparison, double-hop chains.
- About 60 rules (misconfiguration, best practice, compliance) with confidence levels, rationale, remediation and sources.
- Single-file offline HTML report: topology, findings, inventory, project view, rule catalog, overview with health score.
- Interface in 8 languages, light and dark mode, keyboard control, reduced-motion support; rule texts in English and German.
- CSV and JSON export, `--fail-on` exit code for CI, masking of secrets in embedded configuration lines.
