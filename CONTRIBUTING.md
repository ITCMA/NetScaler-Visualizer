# Contributing / Mitarbeit

Contributions are welcome. Unless you state otherwise, a contribution you submit is licensed under the Apache License 2.0 (section 5 of the [LICENSE](LICENSE)). Please open an issue first for larger changes.
Beiträge sind willkommen. Sofern nicht anders angegeben, wird ein eingereichter Beitrag unter der Apache License 2.0 lizenziert (Abschnitt 5 der [LICENSE](LICENSE)). Bei größeren Änderungen bitte zuerst ein Issue anlegen.

## Guidelines / Richtlinien
1. **No customer data** in the repository, issues, commits, tests or examples: no real names, host names, IP addresses,
   certificates, hashes, passwords or file paths. Use synthetic data (documentation ranges `192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`, `example.com`). See [docs/PRIVACY.md](docs/PRIVACY.md).
2. **English and German** for all user-facing texts (interface, rules, messages, documentation). A new rule is a function in
   `nsviz/rules/` plus entries in `rules/i18n/{en,de}.json` and `messages_{en,de}.json`.
3. Python 3.10 or newer, standard library only, no network access at runtime.
4. Rules state their confidence (`certain`, `likely`, `heuristic`) and name their source at topic level; do not invent
   requirement IDs.
5. Run `python3 -m unittest discover -s tests` before every commit. The tests include a hygiene check for secrets,
   e-mail addresses and absolute paths.
6. One logical change per commit, with an imperative English commit message; update `CHANGELOG.md`.

## Setup
```bash
python3 -m venv .venv && . .venv/bin/activate
python3 scripts/fetch_testdata.py        # optional: public sample configurations for the corpus tests
python3 -m unittest discover -s tests
```
