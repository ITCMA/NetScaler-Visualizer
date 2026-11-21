# NetScaler Visualizer (`nsviz`)

🇩🇪 [Deutsche Version](README.de.md)

**See your whole NetScaler environment on one page – and know what is wrong with it.**

Drop in your `ns.conf` files – one device or a whole landscape – and get **one single HTML file** that you can open anywhere,
offline:

- 🗺️ **Visualize** – an interactive map of every vServer, service, policy, certificate and authentication flow. Several
  NetScalers are stitched together: **HA pairs** are merged and compared (what differs between the nodes?), and
  **double-hop chains** (e.g. DMZ gateway → internal NetScaler → backend) are followed from one device to the next.
  Zoom, collapse, search, filter, export as PNG.
- ✅ **Check** – about 60 rules for misconfiguration, vendor best practice and BSI hints, each with rationale, source and
  remediation, plus a health score, CSV export and a CI exit code.

It runs locally, needs only Python ≥ 3.10 (no packages) and sends nothing over the network. Supports 13.1 / 14.1 / 15.1.

> **Trademarks / independence:** NetScaler and Citrix are trademarks of their respective owners. This project is
> independent and is not affiliated with, endorsed or supported by them. Results are automated hints without
> warranty. See [docs/LEGAL.md](docs/LEGAL.md).

**No command line needed:** `python3 -m nsviz gui` opens a local page (127.0.0.1 only, nothing leaves your computer) where you drop the config files, set HA pairs, hosts file and options, and create the report. The command line below stays available for scripts and CI.

```bash
# single device, a folder with several configs, or both
python3 -m nsviz analyze customer/adc01.conf customer/adc02.conf -o report.html --csv findings.csv

# state an HA pair explicitly (otherwise detected via `add ha node` only), set roles
python3 -m nsviz analyze configs/ --ha pri.conf,sec.conf --role pri.conf=primary --role sec.conf=secondary

# German console output / CSV texts
python3 -m nsviz analyze configs/ --lang de

# rule catalog, tests
python3 -m nsviz rules --markdown > docs/RULES.md
# anonymized copies of configs (for sharing or development), see docs/PRIVACY.md
python3 -m nsviz anonymize configs/ -o anonymized/            # everything anonymized (default)
python3 -m nsviz anonymize configs/ -o anonymized/ --keep ips   # keep IP addresses
python3 -m nsviz anonymize configs/ -o anonymized/ --remove comments,timezone,location   # also remove comments, time zone, location/GeoIP (off by default)
python3 -m unittest discover -s tests
```

Try it: `python3 -m nsviz analyze examples/demo -o demo.html` (synthetic: DMZ frontend with gateway/nFactor →
backend HA pair with a deliberate deviation). Prebuilt report: `examples/demo/report.html`.

## Features
### Visualization and multi-instance view
- **Topology** (Cytoscape + dagre, everything embedded): zoom/pan, double-click collapses/expands substructures,
  levels 1–4, filter by object kind, only objects with findings, search (name/IP/config text), neighbourhood
  highlighting, edge labels, PNG export. Red outlines = findings (colour = severity).
- **Several NetScalers in one picture:** HA pairs (explicit via `--ha` or detected from `add ha node`) are shown as one group with a
  configuration diff; backend targets that match another device's vServer are linked as **double-hop** chains (IP+port = certain, IP only = marked as assumption).
- **Multilingual, light/dark:** UI in 8 languages (de, en, es, fr, pt, zh, ja, hi); follows the browser language and
  can be switched. Light/dark follows `prefers-color-scheme` and can be switched; the choice is remembered in the browser.
  Rule texts and finding messages are available in English and German. UI translations other than en/de are not
  reviewed by native speakers.
- **Anonymize configs** (GUI section 5 or `nsviz anonymize`): choose what to replace (all on by default; secrets are always removed; comments, time zone and location/GeoIP data are kept unless you tick their "remove" option). Consistent pseudonyms keep the object type, IP subnets and private/public, FQDN structure and internal/external, LDAP DNs and product URL paths; a structure check compares objects and connections before and after, and remaining places to check are listed locally.
- **Debug mode** (🐞 button in the header): shows for every line which rule and config line created it; copies an anonymised description (no names, IPs or values) to report wrong or missing lines. Shift, Cmd or Option + click (or Shift + drag a frame) selects several objects and lines for one combined description.
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
