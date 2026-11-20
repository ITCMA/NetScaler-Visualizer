# Handling customer data (privacy concept)

🇩🇪 [Deutsche Version](PRIVACY.de.md)

Status: proposal; to be agreed with the project owner. Not legal advice (see [LEGAL.md](LEGAL.md)).

## What is sensitive
A `ns.conf` can contain: internal IP addresses and topology, host and domain names, user and admin names, LDAP bind DNs,
SNMP community strings, e-mail addresses, certificate/key names, encrypted (but crackable) password/key blobs and
comments written by administrators. The generated **report** contains topology and config lines of the customer.
Treat configs, reports, CSV/JSON exports and screenshots as customer data.

## Principles
1. **Local first.** The tool runs locally and sends nothing. Customer configs are analysed on the consultant's machine.
2. **Customer data never enters the repository** – not in code, tests, docs, examples, issues, commit messages or CI.
   Tests and examples use synthetic data (documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `example.com`)
   or public sample configs downloaded on demand.
3. **Separate place, outside the repository.** Keep customer material in a folder *outside* the working copy
   (e.g. `~/nsviz-private/<engagement-id>/`, use neutral engagement IDs, not customer names). If it must be inside the
   working copy, only below `private/` (git-ignored).
4. **Layered protection against accidents:**
   - `.gitignore` excludes `private/`, `customer*/`, `local/`, `anonymized/`, reports, CSV exports and archives.
   - `scripts/hooks/pre-commit` (install with `sh scripts/install-hooks.sh`) blocks staged customer paths, long hex blobs,
     private key headers and absolute user paths, and runs the tests.
   - The hygiene tests scan code, docs, examples and scripts for secrets, e-mail addresses, absolute paths and forbidden references.
   - Enable GitHub *secret scanning* and *push protection* for the repository (repository settings; requires an owner).
5. **Masking.** Reports mask passwords and keys in embedded config lines by default (pattern based on known option names –
   not a guarantee). Keep `--no-redact` off for anything that leaves your machine.
6. **Sharing a report** with the customer is a decision per engagement; check contract/NDA first. Prefer sharing the HTML
   report only with the customer who owns the data.
7. **Minimise and delete.** Keep only what the engagement needs; delete configs and reports when the engagement ends
   (agree on retention with the customer).

## Using customer configs for development (e.g. to improve rules)
Only after **anonymization** and only if the customer agrees.

```bash
python3 -m nsviz anonymize ~/nsviz-private/configs -o ~/nsviz-private/anonymized
```
What it does (safe by default - over-anonymizing is accepted, leaking is not):
- all object names (and every other value that is not a keyword, number or enum constant) → consistent pseudonyms such as `lbvserver_0012`;
- IPv4 addresses → synthetic `10.x.y.z` addresses; hosts in the same /24 stay in the same /24 (netmasks and `0.0.0.0` are kept);
  IPv6 → `2001:db8::N`; host names and e-mail addresses → `hostN.example.com` / `userN@example.com`;
- passwords, keys and long hex blobs removed; comments, descriptions, LDAP DNs/filters, certificate/key file names replaced;
- string literals inside policy expressions replaced by `lit` (`--keep-literals` keeps them, with hosts/IPs/names still replaced);
- the same input always maps to the same pseudonym across **all files of one run**, so HA pairs and double-hop chains still link up;
- no reverse mapping is stored unless `--map-file` is given (that file is as sensitive as the input).

Checks: the tool compares statement counts before/after and reports possible leftovers (original strings that still occur); on the
public sample corpus the number of findings stays within about 3 % of the original. **A human must still review the result** before it
leaves the private folder; automatic anonymization can miss values that are only identifiable in context (e.g. internal naming
schemes in comments, unusual option names). Even then the anonymized output stays in the private folder; only *derived, generic*
findings (e.g. "rule X missed pattern Y") go into the repository as new synthetic test cases.

## Duplicates and content-free statistics
`python3 scripts/corpus_stats.py <private-folder>` detects duplicate configs (same content after removing comments, blank lines and
formatting differences; also same lines in a different order) and prints **counts only**: no file names, host names, values or config
lines. Each unique config is processed once. Run it on the machine where the data lives; use `--manifest` only to write the list of unique
files to a local file.

## Checklist before every push
- [ ] `git status` shows no files from `private/` or exports
- [ ] `python3 -m unittest discover -s tests` is green (includes the hygiene test)
- [ ] no real names, host names, IPs, hashes, certificates, paths in the diff
- [ ] git identity is the intended one

## Link maps and DNS
A link map (`nsviz-links.json`) and a hosts file contain object and host names from customer configs: keep them private (they are in `.gitignore`). `nsviz resolve` sends the FQDNs found in the configs to a DNS server; it lists names and server first and asks for confirmation. Nothing is queried automatically, and the HTML report itself never uses the network.
