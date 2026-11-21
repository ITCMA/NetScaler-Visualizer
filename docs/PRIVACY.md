# Handling customer data

🇩🇪 [Deutsche Version](PRIVACY.de.md)

This document describes how to work with customer configurations safely. It is not legal advice (see [LEGAL.md](LEGAL.md)).

## What is sensitive
A `ns.conf` can contain internal IP addresses and topology, host and domain names, user and administrator names, LDAP bind
DNs, SNMP community strings, e-mail addresses, certificate and key names, encrypted password and key values, and comments
written by administrators. The generated report contains the topology and configuration lines of the environment.
Treat configurations, reports, CSV and JSON exports and screenshots as customer data.

## Principles
1. **Local processing.** nsviz runs on your computer and sends nothing. The report never uses the network.
2. **Keep customer data out of repositories.** Do not put it into code, tests, documentation, examples, issues, commit
   messages or CI. Tests and examples use synthetic data (documentation ranges `192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `example.com`) or public sample configurations that are downloaded on request.
3. **Separate storage.** Keep customer material in a folder outside the working copy, named with neutral engagement IDs
   instead of customer names. If it must be inside the working copy, use `private/`, which is excluded from git.
4. **Protection against mistakes.**
   - `.gitignore` excludes `private/`, `customer*/`, `local/`, `anonymized/`, reports, exports and archives.
   - `scripts/hooks/pre-commit` (install with `sh scripts/install-hooks.sh`) blocks staged customer paths, long hex blobs,
     private key headers and absolute user paths, and runs the tests.
   - The hygiene tests scan code, documentation, examples and scripts for secrets, e-mail addresses, absolute paths and
     forbidden references.
   - Enable GitHub secret scanning and push protection for the repository.
5. **Masking.** Reports mask passwords and keys in embedded configuration lines by default. The masking is based on known
   option names and is not a guarantee. Do not use `--no-redact` for anything that leaves your computer.
6. **Sharing a report** with the customer is a decision per engagement; check the contract and any non-disclosure
   agreement first, and share the report only with the customer who owns the data.
7. **Minimize and delete.** Keep only what the engagement needs and delete configurations and reports when it ends,
   following the retention agreed with the customer.

## Anonymizing configurations
To pass a configuration on, for example to reproduce a problem, anonymize it first and only with the customer's agreement.

```bash
python3 -m nsviz anonymize ~/nsviz-private/configs -o ~/nsviz-private/anonymized
```
The default is to anonymize as much as possible:
- Object names and every other value that is not a keyword, number or constant become consistent pseudonyms such as
  `lbvserver_0012`.
- IPv4 addresses become synthetic `10.x.y.z` addresses; hosts of one /24 stay in one /24, and netmasks and `0.0.0.0` are
  kept. IPv6 addresses become `2001:db8::N`; host names and e-mail addresses become `hostN.example.com` and
  `userN@example.com`.
- Passwords, keys and long hex values are removed; descriptions, LDAP DNs and filters, and certificate and key file names are
  replaced.
- Comments, the time zone and location data are kept by default, while IP addresses, host names and object names inside
  comments are replaced. `--remove comments,timezone,location` (in the GUI: the "remove" check boxes) deletes them.
  Comments can contain customer names, so remove them before passing a configuration on.
- String literals in policy expressions are replaced by `lit`; `--keep-literals` keeps them with hosts, IPs and names
  still replaced.
- The same input maps to the same pseudonym across all files of one run, so HA pairs and double-hop chains stay linked.
- No reverse mapping is stored unless `--map-file` is given; that file is as sensitive as the input.

The tool compares the number of statements before and after and lists possible leftovers. Review the result manually before
it leaves your computer: values that can only be identified from context, such as internal naming schemes in comments, can
be missed.

## Statistics without content
`python3 scripts/corpus_stats.py <folder>` detects duplicate configurations (same content apart from comments, blank lines,
formatting and order) and prints counts only, without file names, host names, values or configuration lines. Run it on the
machine where the data is stored.

## Link maps and DNS
A link map (`nsviz-links.json`) and a hosts file contain object and host names from customer configurations; keep them
private (they are excluded from git). `nsviz resolve` sends the host names found in the configurations to a DNS server; it
first lists the names and the server and asks for confirmation. Nothing is queried automatically.

## Checklist before every push
- [ ] `git status` shows no files from `private/` and no exports
- [ ] `python3 -m unittest discover -s tests` passes (includes the hygiene test)
- [ ] the changes contain no real names, host names, IP addresses, hashes, certificates or paths
- [ ] the git identity is the intended one
