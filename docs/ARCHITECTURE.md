# Architecture

🇩🇪 [Deutsche Version](ARCHITECTURE.de.md)

nsviz reads NetScaler `ns.conf` files, builds a model of the objects and their relations, evaluates rules against it and
writes the result as one self-contained HTML file. Everything runs locally and uses only the Python standard library.

## Data flow
```
ns.conf ──► parser.py ──► Config (entities, bindings, features)
                              │
                 model.py ◄───┘  Graph: nodes (objects) + edges (bindings, references)
                              │
 rules/*.py  ◄── Ctx(cfg, graph) ── Findings (rule ID, severity, object, evidence; messages in en and de)
                              │
 project.py: several files → devices → HA groups (diff) → double-hop links → JSON
                              │
 report.py + assets/ ──► one HTML file (data as JSON, Cytoscape, dagre and the application inline)
```

## Components
| Module | Task |
|---|---|
| `parser.py` | Generic line parser: verb, object type, positional arguments and `-options`. There is no schema per command, so commands of new firmware versions are kept. `add`, `set`, `unset`, `rm`, `bind`, `unbind`, `link`, `enable` and `disable` are applied in order. HTML-encoded files are decoded. |
| `model.py` | Translates entities into nodes (vServers of all types, services, servers, monitors, certificates, profiles, policies, actions, nFactor labels and schemas, network objects, and more) and edges (bindings, policy references, certificate links, backend targets, authentication chains). References to undefined objects are marked as missing. Also builds the Gateway and nFactor views. |
| `rules/` | One module per topic. A rule is a function registered with `@rule(id, severity, category, refs, confidence)`. Titles, rationale and remediation are kept in language catalogs (`rules/i18n/`). Modules are loaded automatically. |
| `ruleconfig.py` | Rule configuration: disable rules, change severities, record accepted risks with a reason and an optional expiry date. |
| `project.py` | Combines several files: devices, HA groups with a configuration diff, double-hop chains, link maps, cleanup analysis. Produces the JSON for the report. |
| `linking.py` | Cross-device links: FQDN targets, link maps, optional DNS resolution (started manually). |
| `compare.py` | Comparison of two configuration states: added, removed and changed objects, new and resolved findings. |
| `anonymize.py` | Consistent pseudonymization of configurations, with a structure check before and after. |
| `report.py`, `assets/` | Embeds data, texts (`assets/i18n/`, 8 languages) and libraries into one HTML file. |
| `gui.py` | Local web interface (127.0.0.1 only, access token, host check, upload limits). |
| `cli.py` | Command line: `analyze`, `compare`, `anonymize`, `gui`, `resolve`, `rules`. |

## Rules
A rule only evaluates facts that are explicitly present in the configuration. Where a statement depends on defaults or on
runtime state, the rule carries the confidence `likely` or `heuristic`; `certain` means the statement follows from the
configuration alone. The rule catalog is generated (`python3 -m nsviz rules --markdown`, see [RULES.md](RULES.md)) and
checked in CI.

A new rule consists of a function in a module under `nsviz/rules/` and entries in `i18n/en.json`, `i18n/de.json`,
`i18n/messages_en.json` and `i18n/messages_de.json`. A test verifies that every rule has texts in both languages.

## Multiple devices
- **HA pairs** are recognized by `add ha node` (partner NSIP) or stated with `--ha`. The configuration diff leaves out
  node-specific objects (NSIP, host name, interfaces, `rpcNode`).
- **Double hop:** a backend target (service or service group member) whose address matches a vServer of another device
  creates a `double-hop` edge. A match on address and port is certain; a match on the address alone is marked as an
  assumption.
- **FQDN targets** are not resolved automatically. They are listed on the Links tab; a link map or an optional DNS lookup
  turns them into links.

## Views in the report
Overview, Topology (layered map with levels, filters and search), Gateway, nFactor, Findings, Inventory, Project (devices,
HA diff, chains), Links, Rules. Both Gateway and nFactor can be exported as PNG, SVG or PDF. The topology can additionally
be exported as a draw.io file; selected objects can be exported as NetScaler configuration, together with their
dependencies if required.

## Security properties
- The report is a static file without network access; its Content-Security-Policy forbids external resources.
- Passwords and keys in embedded configuration lines are masked by default.
- The local GUI binds to 127.0.0.1, requires a random token, checks the `Host` header, limits request sizes and keeps
  uploads in a temporary folder.
- The only optional network access is the DNS lookup of host names on the Links tab, started manually.

## Scale
The analysis and the report were measured with synthetic configurations: about 9,000 objects are analysed in
approximately 4 seconds and open in the browser in about 4 seconds; about 24,000 objects take approximately 10 seconds
and open in about 11 seconds (a layout run of the topology adds time). Use the level selection and filters for very large
environments.
