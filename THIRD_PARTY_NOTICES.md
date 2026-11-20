# Third-party notices

The report embeds the following libraries (unchanged, minified builds) so that it works offline.
License texts are kept next to the files in `nsviz/assets/vendor/`.

| Component | License | Notes |
|---|---|---|
| Cytoscape.js | MIT | © The Cytoscape Consortium |
| cytoscape-dagre | MIT | © The Cytoscape Consortium |
| dagre | MIT | © Chris Pettitt; the minified build bundles graphlib and lodash (both MIT) - exact versions and notices of the bundled parts still to be recorded |

The Python code uses the standard library only (no runtime dependencies).

Optional test data (**not** part of this repository, downloaded on demand by `scripts/fetch_testdata.py`)
comes from a third-party project under the Apache License 2.0; see `docs/SOURCES.md`.

# Hinweise zu Drittkomponenten (Deutsch)

Der Report bettet die oben genannten Bibliotheken unverändert (minifizierte Builds) ein, damit er offline funktioniert.
Die Lizenztexte liegen neben den Dateien in `nsviz/assets/vendor/`. Der Python-Code nutzt nur die Standardbibliothek.
Die optionalen Testdaten gehören **nicht** zum Repository; sie werden bei Bedarf von `scripts/fetch_testdata.py`
aus einem Drittprojekt (Apache License 2.0) geladen, siehe `docs/SOURCES.de.md`.
