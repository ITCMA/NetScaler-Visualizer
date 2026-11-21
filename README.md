# NetScaler Visualizer (`nsviz`)

🇩🇪 [Deutsche Version](README.de.md)

**See your whole NetScaler environment on one page – and know what is wrong with it.**

Drop in your `ns.conf` files – one device or a whole landscape – and get **one single HTML file** that you can open
anywhere, offline. Nothing is uploaded, nothing is installed on the NetScaler.

![Topology of a demo environment: DMZ NetScaler and backend HA pair](docs/images/topology.png)

## Key features
| | |
|---|---|
| 🗺️ **Topology** | Interactive map of vServers, services, policies, certificates and authentication – by level, filterable, searchable. |
| 🔗 **Several NetScalers** | HA pairs merged and compared, double-hop chains (DMZ → internal → backend) followed across devices. |
| 🚪 **Gateway view** | Per gateway: session policies with effective values (incl. global defaults), StoreFront/STA, EPA, client certificates, ACLs. |
| 🔐 **nFactor flow** | The login flow per entry point as factor columns: schemas, policies, actions, success/failure paths. |
| ✅ **Checks** | About 60 rules (misconfiguration, vendor best practice, BSI hints) with rationale, source and remediation; health score. |
| 🧹 **Cleanup** | Finds unused configuration and writes an ordered cleanup batch plus a rollback batch. |
| 📤 **Export** | PNG/SVG/PDF, CSV, and selected objects as NetScaler config (with their dependencies). |
| 🕶️ **Privacy** | Secrets masked by default; anonymize configs for sharing; runs on 127.0.0.1 only. |
| 🌍 **Languages** | UI in 8 languages, light/dark mode, keyboard control. |

<table><tr>
<td><img src="docs/images/gateway.png" alt="Gateway view with session policies" width="100%"></td>
<td><img src="docs/images/nfactor.png" alt="nFactor login flow" width="100%"></td>
</tr><tr>
<td><img src="docs/images/overview.png" alt="Overview with health score" width="100%"></td>
<td><img src="docs/images/findings.png" alt="Findings with rationale and remediation" width="100%"></td>
</tr></table>

All screenshots show the synthetic demo environment from [`examples/demo`](examples/demo) (documentation IP ranges,
invented names).

## Getting started
### Option A – ready-to-run app (no Python needed)
Download `nsviz-windows-x64.exe`, `nsviz-macos-arm64` (Apple silicon) or `nsviz-macos-x64` (Intel) from the
*Releases* page and start it: a local page opens in your browser.

The builds are **not code-signed**:
- **Windows:** SmartScreen shows "Windows protected your PC" → *More info* → *Run anyway*.
- **macOS:** Gatekeeper blocks the first start. Right-click the file → *Open* → *Open*, or run
  `xattr -d com.apple.quarantine nsviz-macos-arm64 && chmod +x nsviz-macos-arm64` in Terminal.

### Option B – with Python ≥ 3.10 (no packages needed)
```bash
git clone https://github.com/ITCMA/NetScaler-Visualizer.git && cd NetScaler-Visualizer
python3 -m nsviz gui                                   # local page: drop configs, set options, create the report
python3 -m nsviz analyze examples/demo -o demo.html   # or straight from the command line (demo data)
```

### Your first report
1. Save the running config on each NetScaler (`save ns config`) and copy `/nsconfig/ns.conf`.
2. Start `nsviz gui`, drop the files, mark HA pairs if they are not detected, create the report.
3. Open the HTML file. Start with **Overview**, then **Topology**, **Gateway** and **nFactor**.
   The report contains your topology – store and share it like customer data.

### Command line
```bash
# single device, a folder with several configs, or both
python3 -m nsviz analyze customer/adc01.conf customer/adc02.conf -o report.html --csv findings.csv

# state an HA pair explicitly (otherwise detected via `add ha node` only), set roles
python3 -m nsviz analyze configs/ --ha pri.conf,sec.conf --role pri.conf=primary --role sec.conf=secondary

# German console output / CSV texts
python3 -m nsviz analyze configs/ --lang de

# fail a CI job on critical findings (exit code 2)
python3 -m nsviz analyze configs/ -o report.html --fail-on critical

# anonymized copies of configs (for sharing or development), see docs/PRIVACY.md
python3 -m nsviz anonymize configs/ -o anonymized/            # everything anonymized (default)
python3 -m nsviz anonymize configs/ -o anonymized/ --keep ips   # keep IP addresses
python3 -m nsviz anonymize configs/ -o anonymized/ --remove comments,timezone,location

# rule catalog, tests
python3 -m nsviz rules --markdown > docs/RULES.md
python3 -m unittest discover -s tests
```

Supports NetScaler 13.1 / 14.1 / 15.1. The only network access is the optional DNS lookup in the Links tab, started
by hand.

> **Trademarks / independence:** NetScaler and Citrix are trademarks of their respective owners. This project is
> independent and is not affiliated with, endorsed or supported by them. Results are automated hints without
> warranty. See [docs/LEGAL.md](docs/LEGAL.md).

## Feature details
### Visualization and multi-instance view
- **Topology** (Cytoscape + dagre, everything embedded): zoom/pan, double-click collapses/expands substructures,
  levels 1–4, filter by object kind, only objects with findings, search (name/IP/config text), neighbourhood
  highlighting, edge labels, PNG export. Red outlines = findings (colour = severity).
- **Gateway tab** (shown when the config has Gateway vServers): one page per gateway with the access profiles (session
  policies: ICA proxy, full VPN, clientless, StoreFront URL and where it goes, SSO, split tunnel, default authorization),
  STA servers, ICA policies, intranet applications and IPs, traffic policies, portal theme, bookmarks, clientless access,
  authorization policies (ACLs), AAA groups, RDP/PCoIP profiles and other bound policies; global bindings and AAA groups
  are tagged. "Export config" exports the gateway with its dependencies.
- **Cleanup** (Topology sidebar): finds configuration that is not used, top-down from the addressable vServers, GSLB
  domains, global and user/group bindings: e.g. non-addressable vServers without a reference, services and service groups
  without a vServer, then the monitors, servers, policies, actions and certificates that become free. Objects used only
  by disabled objects are marked separately. Both are highlighted in the graph; "Cleanup batch" in the export dialog
  writes the unbind/rm commands in a working order (not used first, the disabled part with an explanation at the end)
  and a rollback batch. Objects whose name also appears in a line that stays are listed "to check" only. Lines with masked secrets (***) are
  commented out in the rollback and must be restored from the saved ns.conf (or use --no-redact).
- **Gateway and nFactor details**: parameters of session and authentication actions in an overlay (with the global VPN
  settings), client certificate authentication and endpoint analysis (EPA); both tabs can be exported as PNG, SVG or PDF.
- **nFactor tab** (shown when the config has authentication): the login flow per entry point (gateway, LB/CS vServer with
  authentication, auth vServer) as factor columns: login schema, policies in priority order with action type (LDAP,
  RADIUS, SAML, OAuth, certificate, decision, ...), success → next factor or login complete, failure → next policy or
  login fails, arrows between factors. Classic gateway authentication (primary/secondary) is shown as well.
  In the topology, the details of related objects have buttons to open these tabs.
- **Several NetScalers in one picture:** HA pairs (explicit via `--ha` or detected from `add ha node`) are shown as one group with a
  configuration diff; backend targets that match another device's vServer are linked as **double-hop** chains (IP+port = certain, IP only = marked as assumption).
- **Multilingual, light/dark:** UI in 8 languages (de, en, es, fr, pt, zh, ja, hi); follows the browser language and
  can be switched. Light/dark follows `prefers-color-scheme` and can be switched; the choice is remembered in the browser.
  Rule texts and finding messages are available in English and German. UI translations other than en/de are not
  reviewed by native speakers.
- **Anonymize configs** (GUI section 5 or `nsviz anonymize`): choose what to replace (all on by default; secrets are always removed; comments, time zone and location/GeoIP data are kept unless you tick their "remove" option). Consistent pseudonyms keep the object type, IP subnets and private/public, FQDN structure and internal/external, LDAP DNs and product URL paths; a structure check compares objects and connections before and after, and remaining places to check are listed locally.
- **Debug mode** (off by default; turn it on with `--debug` when creating the report, or with `#debug` in the report URL): a 🐞 button in the header shows for every line which rule and config line created it; copies an anonymised description (no names, IPs or values) to report wrong or missing lines. Shift, Cmd or Option + click (or Shift + drag a frame) selects several objects and lines for one combined description.
- **Export as NetScaler config:** the chosen objects as a batch file, optionally with all direct and indirect dependencies, in the order of the source config; certificate/key files and global settings are listed as not included.
- **One consistent interface (start page and report):** switches, segmented controls, collapsible sections, option cards and
  info buttons (i) for longer explanations, same look in light, dark and high contrast.
- **Accessibility/usability:** skip link, ARIA tabs, focus outlines, keyboard control in the graph (arrows, Enter,
  +/−, 0, `/`, Cmd/Ctrl+F, Esc, `?` lists all shortcuts), reduced motion support, overview page with health score.
### Checks
- **Findings:** filterable, click jumps to the object; rationale, source and remediation per rule; CSV export.
- **Inventory** of all vServers (sortable), **Project** (devices, HA diff, double-hop chains), **Rules** (catalog).
- Passwords/keys in embedded config lines are masked by default (`--no-redact` disables this). The report still
  contains customer topology → treat it like customer data ([docs/PRIVACY.md](docs/PRIVACY.md)).

## Limits (stated openly)
- Not verifiable from an `ns.conf`: certificate expiry, runtime state (UP/DOWN), the real nsroot password,
  primary/secondary role at runtime. Rules touching this are marked `heuristic` or `likely`.
- Defaults of individual options differ between versions; rules therefore only report *explicitly* configured
  insecure values unless an assumption is documented.
- References to BSI modules and the vendor's secure deployment guidance are at topic level and not verified
  against the current editions.

## Documentation
[Architecture](docs/ARCHITECTURE.md) · [Rules](docs/RULES.md) · [Sources & licenses](docs/SOURCES.md) ·
[Privacy / customer data](docs/PRIVACY.md) · [Legal notes](docs/LEGAL.md) · [Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

## License
Proprietary, all rights reserved – see [LICENSE](LICENSE).
