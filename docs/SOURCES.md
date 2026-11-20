# Sources and licenses

🇩🇪 [Deutsche Version](SOURCES.de.md)

## Test / training data (not part of this repository)
Public sample configs are **not** stored in the repository. `python3 scripts/fetch_testdata.py` downloads them into
the git-ignored folder `testdata/`; the corpus tests are skipped if the folder is absent.

Source: <https://github.com/f5devcentral/vscode-f5-flipper>, directory `tests/artifacts/` (pinned to commit `e89eb68d6790`),
**Apache License 2.0** (the script also downloads the license text). 38 files (`*.ns.conf`, `namaste.conf`, `ns1_v13.1*.conf`);
a version header (`#NS…`) is present in 28 of them: 13.0 (1), 13.1 (27), the rest have no header. According to the upstream readme
some were deployed on a real NetScaler VPX ("verified"), some are synthetic. The script replaces long hex blobs
(≥ 40 hex characters: nsroot hash, `encryptionParams -keyValue`, `rpcNode -password`) with zeros of the same length.
The data was checked for e-mail addresses (only `example.com`), hex secrets and public IPs/domains (example values, DNS root
servers, `example.com`, `f5flipper.com`); this is **not** a full audit for real customer data. The origin of the content
of each upstream file is not verified.

Coverage: LB, CS, GSLB, AppFW, authentication (LDAP/RADIUS/SAML/OAuth/nFactor), caching, compression, rate limiting, HA/cluster,
SSL profiles, monitors, persistence, audit, network objects.
**Gaps:** no gateway (`vpn vserver`), no 14.1/15.1, no IP reputation example. `examples/demo/` fills them (own, fully synthetic configs; 14.1 header).

Not used: examples from vendor documentation and support articles (copyright, no re-use license) – they served only as a syntax
reference for own synthetic configs. Other projects found (e.g. vendor script repositories, Ansible/Puppet modules) were not
checked for sample configs and license.

## Embedded libraries (`nsviz/assets/vendor/`)
| Library | License |
|---|---|
| cytoscape 3.x | MIT |
| dagre 0.8.x (bundles graphlib, lodash) | MIT |
| cytoscape-dagre 2.x | MIT |

License texts are next to the files (`LICENSE-*.txt`); see also [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Rule references
See [RULES.md](RULES.md). Named are BSI TR-02102-2, BSI IT-Grundschutz modules (topic level) and the Citrix/NetScaler Secure
Deployment Guide. The mapping is a technical classification by the author and is **not verified against the current
documents** (no access while writing) – please verify before audit use and cite the edition.
