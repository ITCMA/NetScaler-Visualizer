# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/) (0.x = interface may change).

## [Unreleased]

## [0.3.9] - 2026-11-21
### Security
- Test data uses documentation addresses (RFC 5737) instead of public addresses where the test allows it.
- .gitignore: report exports (images, PDF, CSV, cleanup/rollback batches), transfer bundles and archives are never committed.

## [0.3.8] - 2026-11-21
### Fixed
- Cleanup detection: an object counts as "sure" only when no line that stays names it; lines of other candidates that
  are not removed themselves are taken into account (repeated until stable). Before, a removed object could still be
  named by such a line.
- Cleanup batch: removal order from the config lines (an object whose own lines name another removed object goes
  first), also when a policy and its action share a name. A circular reference gets a note in the batch.
- Rollback: adds in the reverse order (an object before the lines that use it, by object, not by name); link lines of
  certificates are no longer restored twice; lines with masked secrets (***) are commented out with a warning, as they
  cannot restore the object (restore them from the saved ns.conf or create the report with --no-redact).
- Unbind of a binding without a policy (NOPOLICY, e.g. to invoke a policy label) keeps the priority, which identifies it
  (assumption, check before running).

## [0.3.7] - 2026-11-21
### Fixed
- Config export: with a selected object the export now uses the selection by default (before, the scope stayed on
  "current view", so all visible objects were exported although one object was selected). The dialog shows the basis
  and the number of objects (highlighted when it is not the selection); the file names its basis in the header.
- Gateway tab "Export config": exports only this gateway (with what it needs), no longer all AAA groups and global policies.
### Changed
- Clearer labels: "Only these objects" / "These objects with everything they need"; "Selected object (images: with its neighbourhood)".

## [0.3.6] - 2026-11-21
### Added
- Gateway tab: "Parameters" per session policy opens a table of all parameters of the session action next to the global
  VPN settings (set vpn parameter) and the value that applies; columns Mode, StoreFront, SSO, split tunnel and default
  authorization fall back to the global settings (marked "G"). Option names as written in the config.
- Gateway tab: client certificate authentication (mode, CA certificates) and endpoint analysis (pre-auth policies,
  nFactor EPA factors, post-auth client security of session actions).
- nFactor tab: client certificate on the entry and the authentication vServer; parameters of each authentication action.
- Export on the Gateway and nFactor tab: the page shown as PNG, SVG or PDF (anonymized on request).
- Links tab: "Confirm" is highlighted while a proposal is open, with a hint and a confirmation message.
### Fixed
- HTML-encoded configuration files (&quot; instead of ", e.g. copied from a web page) are decoded; before, quoted
  expressions were split at blanks (wrong action, missing StoreFront URLs). A note in the overview names the file.
- Gateway tab: column widths of traffic policy settings.

## [0.3.5] - 2026-11-21
### Added
- Cleanup analysis: configuration that is not used (top-down from addressable vServers, GSLB domains, global and
  user/group bindings) and configuration used only by disabled objects. Highlighted in the graph (sidebar "Cleanup",
  details panel shows the reason and the chain).
- Export formats "Cleanup batch" and "Cleanup rollback": unbind from objects that stay, then rm in a working order
  (users before what they use); part A not used, part B (optional) used only by disabled objects with an explanation;
  objects whose name appears in a line that stays are listed as comments "to check".

## [0.3.4] - 2026-11-21
### Added
- Gateway tab: one page per Gateway vServer with access profiles (session policies and their mode: ICA proxy, full VPN,
  clientless; StoreFront/Web Interface URL and the local vServer it goes to; SSO, split tunnel, default authorization),
  STA servers, ICA policies, intranet applications and IPs, traffic policies, AlwaysOn and next hop, portal theme,
  EULA, bookmarks, clientless access policies, authorization policies (ACLs), AAA groups, RDP/PCoIP profiles and other
  bound policies. Global bindings and AAA groups are tagged. "Export config" exports the gateway with its dependencies.
- nFactor tab: the login flow per entry point as factor columns with login schema, policies in priority order, action
  type, success/failure paths and arrows to the next factor; classic gateway authentication (primary/secondary) too.
- Topology details: "Open in Gateway tab" / "Open in nFactor tab" for related objects.
### Changed
- Narrow windows: below 1600 px the Export button shows only its icon, below 1380 px the version badge is hidden (the header has up to nine tabs now).
- The keyboard shortcut for tabs covers all shown tabs.

## [0.3.3] - 2026-11-21
### Added
- New objects in the topology: network rules (ACL, PBR, RNAT), traffic domains (with their VLANs and vServers), persistency groups (from each member vServer) and certificate revocation lists (from their CA certificate). Transform actions hang under their transform profile.
- Priority load balancing: the order and weight of a service binding are shown on the connection (`Order 1`, `Weight 3`); vServers show priority order (toggle, threshold), spillover (method, threshold, backup action, persistence), "disable primary when down", traffic domain, listen policy, integrated caching, AppFlow logging, RHI/ICMP state and the TCP/HTTP/net/DNS profiles. Services, service groups and servers show their traffic domain.
- Device details: enabled modes, DNS name servers and suffixes, local/authoritative DNS records by type (root hints left out) and the number of admin partitions.
- Policies show special functions used in their expression: IP reputation, rate limiting, HTTP callout, geo location, URL categorization, bot management.
- "Feature not enabled" check (QA-009) also covers Front-End Optimization, AppQoE and Content Inspection.
### Fixed
- QA-009 reported integrated caching as "not enabled" on almost every config because of the built-in default cache policies (`_...`, `ctx_...`); measured on real configs: 70 of 93 configs affected, now 2.
- QA-006 (unused monitor) never ran because of an internal error; monitors bound with `bind lb monitor <monitor> <service>` count as used.

## [0.3.2] - 2026-11-21
### Changed
- Config export is structured: 1. objects (add), 2. settings (set), 3. bindings (bind/link), each grouped by feature (monitors, servers, services, service groups, LB vServers, content switching, SSL, rewrite, responder, authentication, gateway, ...) with counts. Objects are ordered so that every object is added before a line names it, independent of the source order (checked on 3,109 vServer exports of real configs and the public sample corpus).
- Less in the export: other vServers that only share a server IP, the network (SNIP/VIP/VLAN/routes) and the global default SSL profiles with their cipher groups are no longer pulled in (a header line points out the default profiles).
### Fixed
- Missing parts in the export and in an object's config lines: TCP/HTTP/network/DNS/analytics profiles, cache content groups, AppFlow collectors, OCSP responders, SSL actions, portal themes, bookmarks, intranet applications, RDP profiles, SSO actions, KCD accounts, policy expressions, assignments and log messages named in options are now included; names used in exported lines that the graph does not link are followed as well.
- Large WAF profiles were cut at 1,000 statements; the limit is now 5,000.
- nFactor: built-in actions (for example NO_AUTHN) and assignments used as policy actions are no longer reported as missing objects; the backup of a GSLB vServer is resolved as a GSLB vServer.
- `scripts/fetch_testdata.py` found only 2 of 38 public sample configs (they moved to a subfolder at the pinned commit).

## [0.3.1] - 2026-11-21
### Added
- Light/dark/system theme switch on the start page (config selection), matching the report; the choice is remembered and shared with the report.
### Changed
- Debug tools (bug button and its sidebar switch) are off by default and no longer shown to normal users. Turn them on with `--debug` when creating a report (`analyze --debug`) or starting the GUI (`gui --debug`), or by adding `#debug` to the report URL.

## [0.3.0] - 2026-11-21
### Changed
- One design language for the start page and the report, close to macOS: shared colors, spacing, radii and system font; on/off options are switches, small choices are segmented controls (levels, tabs, theme), the export format is a row of chips, original/anonymized are option cards, dialogs have Cancel plus the main action.
- Start page: grouped sections (files, options), HA pairs, cross-device links and anonymization collapsible, explanations behind the info button, "Create report" in a fixed bar at the bottom with the privacy note.
- Report: sidebar in collapsible sections (search, device, levels, object types with round checks, view, tools), inspector as grouped cards, tables as inset groups, severity filter as toggle chips, explanations on the link tab moved into info buttons.
### Added
- Cmd/Ctrl+F focuses the search or filter of the current tab; Esc clears the selection or leaves a field.
### Fixed
- Standalone reports no longer show the GUI navigation buttons; the start page's warnings only appear when the risky option is switched on; the primary button in dark mode has enough contrast; tabs no longer get cut off in narrow windows in all 8 languages; switches and chips stay readable with forced colors (Windows high contrast).

## [0.2.7] - 2026-11-21
### Added
- Info button (i) with a popover for longer explanations: opens on hover, click/tap and Enter/Space, closes with Escape, a click outside or when the mouse leaves; stays inside the window. Used in the export dialog and for the multi-selection.
### Changed
- Config export: the two variants are option cards with live figures (objects, statements, warnings) for the current selection; the info button compares both with an example (a CS vServer: only its own statements vs. everything it needs to be rebuilt).
- Export dialog: notes on anonymization and on passing on original data moved into the info button; the warning about original data only appears when "original" is chosen.

## [0.2.6] - 2026-11-21
### Added
- Multi-selection in the topology for everyone (not only in debug mode): Shift, Cmd or Option + click adds or removes an object, Ctrl + click too (a right click on macOS), Shift + drag on the background draws a selection frame. Selected objects are highlighted and listed in the side panel.
- Export as NetScaler config: the chosen objects (or the current view / everything) as a batch file, optionally with everything they use directly or indirectly; statements in the order of the source config (add before set/bind), `-devno` removed, header with what is not included (certificate/key files, system/HA/global settings), masked or encrypted secrets, and warnings for references outside the export. Available in the export dialog, in the details of an object and for a multi-selection; original or anonymized.
### Fixed
- Config lines in the report are now exact: quotes and escapes (`\"`, `\r\n`) stay as in ns.conf (before, lines with quoted expressions lost their escapes); only lines with secrets are rebuilt. Objects list up to 1000 statements (was 60).
- An object's config lines include what is needed to recreate it: the CS action of a CS policy and pattern sets, data sets, string maps, callouts, named expressions and variables used in its expressions.

## [0.2.5] - 2026-11-21
### Changed
- Topology: smooth zoom towards the pointer. Mouse wheel and two-finger scroll glide to the new zoom level (eased, faster than before); a trackpad pinch follows the fingers directly; a quick drag of the background keeps moving and slows down. Reduced-motion settings switch easing and inertia off.
- Faster pan and zoom on large graphs: column and device frames are only moved (not rebuilt) per frame, the minimap redraws only its viewport frame.
### Fixed
- Version badge in the header was hard to read in the dark theme; it now meets WCAG AA contrast in light, dark and high-contrast mode.

## [0.2.4] - 2026-11-21
### Fixed
- Topology: with more than 120 objects the graph starts at level 2, which folded every entry vServer (its objects counted one level below the device), so a CS vServer showed no lines to its LB vServers. Entry vServers now count as the first level together with the device; level 2 shows them with their first hop.
### Added
- Debug output: every object, line and bridge states whether it is drawn and, if not, why (folded object, object type filter, device/group filter, "only findings"/"only not connected", "contains" lines off, replaced by a bridge line); objects show whether they are folded.

## [0.2.3] - 2026-11-21
### Added
- Debug mode: 🐞 button in the report header (switches to the topology); Shift, Ctrl or Cmd + click selects several objects and lines, "Copy debug info" then contains all of them (anonymized).
### Changed
- GUI: the report view has a single slim header row; "Change selection", "Start over" and "Quit" are icon buttons in the report header, one language selector (report and GUI stay in sync), the GUI statistics line is gone (figures are in the report subtitle and tabs).
- Trademark notice moved from the report footer to the GUI start page, the report overview and the help dialog.
### Fixed
- Anonymization: `-strongpassword` and similar settings keep their value; login vocabulary such as "password" or "username" is no longer reported as a possible leftover; review lines point to the exact token (not to option names that merely contain it).

## [0.2.2] - 2026-11-21
### Added
- Anonymization: optional categories (off by default) to remove comments (`-comment` values and `#` lines), the device time zone and location/GeoIP data (SNMP location, `add location`, location files, coordinates). GUI: extra check boxes; CLI: `--remove comments,timezone,location`. Statements removed on request do not count as a structure difference.
### Changed
- Comments, time zone and location data are kept by default; IP addresses, FQDNs and object names inside comments are still replaced. Customer names written in a comment therefore stay: tick "Remove comments" before passing a config on if that matters.
- Debug mode always uses the strictest form (comments, time zone and location removed).

## [0.2.1] - 2026-11-21
### Added
- Anonymization rebuilt: categories to choose (all on by default; passwords, keys, hashes and SNMP communities are always removed) in the GUI (section 5, download single files or ZIP, optional private mapping table) and the CLI (`--keep`). Pseudonyms keep the object type; IPs keep subnets and private/public (public -> 198.18.0.0/15); FQDNs keep generic labels and internal/external (internal TLDs or private DNS records); LDAP DNs follow the domain mapping; URL product paths, ports and LDAP attribute names stay; text inside expressions is replaced word by word with the expression structure kept (also `q/.../` literals); certificate, key, CRL and KEK file names are replaced. A structure check compares statements, objects and connections before and after; places that may still contain original values are listed locally for review.
- Debug mode uses the same anonymization: config lines and line labels appear only in anonymized form.
### Changed
- The GUI shows only the version number (the code fingerprint stays in `--version` and the debug output).

## [0.2.0] - 2026-11-21
### Added
- Debug mode in the topology (sidebar checkbox): every line shows the rule (code location) and config line that created it; "Copy debug info" and "Export whole graph" produce an anonymised description (types, rules, line numbers, structure of the config lines; no names, IPs, file names or values) to report wrong or missing lines.
- Version visible in the report header, the GUI and `nsviz --version`, together with a code fingerprint; the version is kept in one place (`nsviz/__init__.py`).
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
