# Architecture, recommendation and phase plan

🇩🇪 [Deutsche Version](ARCHITECTURE.de.md)

## Recommendation: an offline HTML report is enough (phase 1) – no app needed
**Assumption:** customer configs are sensitive and are analysed on the consultant's laptop; the report may be sent to the customer by mail/share.

Reasons:
- One file, offline, nothing to install for the recipient, no cloud/server → no data leaves the machine, easy hand-over to the customer.
- Expand/collapse, zoom, show/hide, search, filters and path highlighting are fully doable in the browser with embedded JS (Cytoscape); tested up to ~750 nodes, the library scales considerably further.
- The report is produced by a small local CLI (`python3 -m nsviz`) that needs only the standard library.

An app or local server only pays off if you want (a) to load configs by drag & drop in the browser (the parser would have to be ported to JS or a small local server `nsviz serve` built), (b) history/comparison of several config states with data storage, (c) very large environments (> ~10,000 objects: lazy loading/clustering), (d) config changes/generation. This is planned as phase 3; the architecture (JSON model between analysis and view) allows it.

## Structure
```
ns.conf ──► parser.py ──► Config (entities, bindings, features)
                              │
                 model.py ◄───┘  Graph: nodes (objects) + edges (bindings/references)
                              │
 rules/*.py  ◄── Ctx(cfg, graph) ── Findings (rule ID, severity, location, evidence; messages en+de)
                              │
 project.py: several files → devices → HA groups (diff) → double-hop links → JSON
                              │
 report.py + assets/ ──► one HTML (data as JSON, Cytoscape/dagre/app JS inline)
```
- **parser.py** – generic (verb, object type, positional arguments, `-options`), no schema per command → unknown/new commands (14.1/15.1) are not lost. `add/set/unset/rm/bind/unbind/link/enable/disable` are applied.
- **model.py** – translates objects into node kinds (CS/LB/GW/AAA/GSLB vServers, service(group), server, monitor, certificate, SSL profile, policies, nFactor labels/schemas, WAF profiles …) and edges (CS→policy→LB, LB→service→server, vServer→certificate, gateway→authn profile→auth vServer→policy→nextFactor label→login schema, GSLB service→local vServer …). Dead references are marked "missing".
- **rules/** – one file per topic; new rule = a function with `@rule(id, severity, category, refs, confidence)`; title, rationale, remediation and finding messages live in the catalogs `rules/i18n/{en,de}.json` and `messages_{en,de}.json` (English leads, German is added; a test checks completeness). Modules are loaded automatically. `python3 -m nsviz rules --markdown [--lang de]` generates the catalog.
- **project.py** – HA detection via `add ha node` (partner NSIP) or `--ha`; similarity of identical vServer addresses is only printed as a *hint* (no automatic assignment). HA diff excludes node-specific objects (NSIP, hostname, interfaces, rpcNode …). **Double hop:** a backend target (service/service group member) of one device = vServer address of another device → `double-hop` edge; IP+port = certain, IP only = marked as an assumption. FQDN targets are not resolved.
- **report.py / assets/** – embeds data, UI texts (`assets/i18n/*.json`, 8 languages) and libraries into one HTML file. Secrets in embedded config lines are masked by default.

## Phase plan
| Phase | Content | Status |
|---|---|---|
| 1 | Parser, model, topology view, ~60 rules, HA diff, double hop, CSV/JSON, i18n, themes, accessibility | done |
| 2 | Deeper gateway (session policies/actions, STA, ICA proxy, StoreFront, EPA), nFactor flow view with rule expressions, AppFW checks/signatures, rewrite/responder actions as nodes, network view (VLAN/SNIP/routes/TD/cluster), version default tables 13.1/14.1/15.1, configurable rules (change severity, disable, exceptions), ~120 rules | open |
| 3 | Compare two config states, optional `nsviz serve` (browser upload), draw.io/SVG export, performance > 10k objects | open |

## Open questions
1. Which BSI baseline should apply: IT-Grundschutz modules (NET.1.1/1.2, OPS.1.1.5, ORP.4, APP.3.1 …), only TR-02102-2 (TLS), or a customer security concept? Currently modules are mapped **at topic level**, no requirement IDs.
2. Should output of `show ssl certKey` or similar be read as well to check expiry dates? (Not contained in the ns.conf.)
3. File-name conventions in customer environments (e.g. `*_pri`/`*_sec`) for role detection?
4. How should exceptions ("customer accepts risk") be documented (a file next to the config)?
5. Project name: "NetScaler" in the name is a trademark risk, see [LEGAL.md](LEGAL.md).
