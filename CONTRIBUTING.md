# Contributing / Mitarbeit

This is a proprietary project; contributions are accepted only by agreement with the copyright holder.
Dies ist ein proprietäres Projekt; Beiträge nur nach Absprache mit dem Rechteinhaber.

## Rules that always apply / Regeln, die immer gelten
1. **No customer data** in the repository, issues, commits, tests or examples: no real names, hostnames, IPs, certificates,
   hashes, passwords, file paths. Use synthetic data (documentation address ranges `192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `example.com`). Details: [docs/PRIVACY.md](docs/PRIVACY.md).
2. **English leads, German is added** to all user-facing texts (UI, rules, messages, docs). New rule = function in
   `nsviz/rules/` + entries in `rules/i18n/{en,de}.json` and `messages_{en,de}.json`.
3. Python ≥ 3.10, standard library only. No network access at runtime.
4. Do not guess: rules must state their *confidence* (`certain`, `likely`, `heuristic`) and cite a source at topic
   level; do not invent requirement IDs.
5. Run `python3 -m unittest discover -s tests` before every commit (includes a hygiene check for secrets, e-mail
   addresses, absolute paths).
6. One logical change per commit; imperative, English commit messages; update `CHANGELOG.md`.

## Setup
```bash
python3 -m venv .venv && . .venv/bin/activate
python3 scripts/fetch_testdata.py        # optional: public sample configs for the corpus tests
python3 -m unittest discover -s tests
```
