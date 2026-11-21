# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/) (0.x = interface may change).

## [Unreleased]
### Added
- Safety net: options that name another object (vServer, certificate, monitor, SSL profile, AAA group, ...) but have no specific rule still become a thin dashed line labelled with the option, so no named dependency is lost. Report note with a dependency self-check (not connected, FQDN targets, undefined references, safety-net links).
- Report: Content Security Policy (no external requests possible, offline by design); report title is escaped.
- Dependency analysis: every object is marked as connected or not (reachable from an addressable vServer or a global binding); sidebar card "Not connected" with filter; rules DEP-001 (vServer not addressable and not referenced) and DEP-002 (URL target without matching vServer); vServers show whether they are addressable.
- GUI: the report opens directly in the same window (back to the selection or start over without quitting); GUI in 8 languages.
- FQDN targets (service targets, session action/STA URLs) are marked: orange halo in the topology, property "FQDN target", legend entry; DEP-002 points to the Links tab (suggestions, hosts file, DNS, manual).
- Topology: "Reset graph" and "Reset all settings".
### Fixed
- Dependencies, systematically checked against a corpus of real configurations (counts only): policy bindings in the ns.conf form `-invoke <type> <name>` were not followed, so policy labels and vServers invoked that way (`reqvserver`/`resvserver`) looked unconnected; CS policies/actions and policy labels pointing to Gateway, AAA or GSLB vServers (`-targetVserver`) were not linked (Unified Gateway behind CS); `-authnVsName` naming a Gateway vServer; SSL policies on SSL vServers; certificate chains (`link ssl certkey`); certificates of internal management services; global STA servers (`bind vpn global -staServer`); session action types `tm`, `ica`, `transform`, clientless access and others; bookmarks (`vpn url`, intranet applications) were reported as missing although defined; policies bound only to AAA groups/users count as used.
- Session action/STA URLs and global `set vpn parameter` URLs are resolved through the appliance's own DNS records (`add dns addRec/cnameRec`), also across loaded configurations. Authentication servers (LDAP/RADIUS) on another loaded device are linked by IP; server names are listed in the Links tab.
- Dependencies: hiding policies/actions no longer cuts the chain. CS and Gateway vServers stay connected to their LB targets through bridge lines that name the hidden policies/actions. Session actions and STA servers whose URL points to a local vServer (IP and port) are linked; FQDN targets are listed separately instead of guessed.
- Jumping to a finding no longer switches on a whole object type or device; the object is shown as a single exception and the filters stay. Long lists in the configuration column wrap into several columns so the graph keeps a usable shape; card background image sized explicitly (rendered wrongly in some browsers).
- `nsviz gui`: local web GUI (127.0.0.1 only, token, standard library only) to choose config files or folders, roles, HA pairs, hosts file, link map and options, and to create the report; the command line stays.
- Cross-device links: Links tab with suggestions (IP/port via hosts file, name and certificate-file-name similarity), confirm/reject, manual links (table or Connect mode in the topology), hosts import, link map save/load (`--map`, `--hosts`); confirmed links become chain entries and edges.
- `nsviz resolve`: optional DNS resolution of FQDNs, only on explicit request (lists names and server first, asks for confirmation; `--list` queries nothing).
- Topology redesign: cards with own icon set, name, type/address and finding badge; icons-only at far zoom; tier columns (device, entry, load balancing, services, servers, configuration) with frames per device/HA pair; layouts tiers/flow/top-down/radial; full-path highlight on selection; minimap; policies/actions hidden at first; plaintext (non-TLS) connections dashed (assumption by protocol/port); collapsible icon legend that toggles object types; high-contrast and dark variants.
- Topology: connections show protocol/service and port (e.g. HTTPS 443, SQL Server 1433); communication CSV export.
- Export dialog: PNG, SVG, PDF (print view), CSV (findings, inventory, communication), JSON, Markdown; scope all/view/selection; original or anonymized (asked on every export).
- Topology: VLANs, IP addresses (SNIP/VIP), routes and cipher groups (linked from SSL bindings).
- `nsviz anonymize`: consistent pseudonymization of names, IPs, hosts, e-mails, secrets and free text for sharing/development use.
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
