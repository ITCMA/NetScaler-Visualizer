# Sources and licenses

🇩🇪 [Deutsche Version](SOURCES.de.md)

## Sample configurations (not part of this repository)
`python3 scripts/fetch_testdata.py` downloads public sample configurations into the folder `testdata/`, which is excluded
from git. Tests that use them are skipped when the folder is absent.

- **Source:** <https://github.com/f5devcentral/vscode-f5-flipper>, directory `tests/artifacts/`, pinned to a fixed commit.
- **License:** Apache License 2.0; the script also downloads the license text.
- **Content:** 38 files covering load balancing, content switching, GSLB, application firewall, authentication (LDAP, RADIUS,
  SAML, OAuth, nFactor), caching, compression, rate limiting, HA and cluster, SSL profiles, monitors, persistence, audit and
  network objects. Most files are NetScaler 13.1 configurations.
- **Handling:** the script replaces long hex values (password hashes, key values) with zeros of the same length.
- **Not covered by the samples:** Gateway (`vpn vserver`), NetScaler 14.1 and 15.1 and IP reputation. The synthetic
  configurations in `examples/demo/` cover these.

Examples from vendor documentation and support articles are not used, because they are copyrighted. They served only as a
syntax reference for the synthetic configurations.

## Embedded libraries (`nsviz/assets/vendor/`)
| Library | License |
|---|---|
| Cytoscape.js 3.x | MIT |
| dagre 0.8.x (includes graphlib and lodash) | MIT |
| cytoscape-dagre 2.x | MIT |

License texts are stored next to the files (`LICENSE-*.txt`); see also [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Rule references
Rules refer to BSI TR-02102-2, BSI IT-Grundschutz modules and the vendor's secure deployment guidance at topic level; see
[RULES.md](RULES.md). The assignment is a technical classification and has to be checked against the current edition of the
document before it is used in an audit.
