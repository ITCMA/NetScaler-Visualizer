# Security policy / Sicherheitshinweise

## Reporting a vulnerability / Schwachstelle melden
Please do **not** open a public issue for security problems. Use GitHub's private vulnerability reporting
(*Security* tab → *Report a vulnerability*) of this repository. Do not attach customer configurations or reports;
describe the problem with synthetic data.

Bitte für Sicherheitsprobleme **kein** öffentliches Issue anlegen, sondern die private Schwachstellenmeldung von GitHub
nutzen (Reiter *Security* → *Report a vulnerability*). Keine Kundenconfigs oder -reports anhängen; das Problem
mit synthetischen Daten beschreiben.

## Scope / Geltungsbereich
- The tool runs locally, has no runtime dependencies and sends no data. The only network access is the optional DNS
  lookup of host names in the Links tab, started by hand (system resolver, no other connections).
  The generated report is a single offline HTML file.
  Das Tool läuft lokal, hat keine Laufzeitabhängigkeiten und sendet keine Daten. Einziger Netzzugriff ist die optionale,
  von Hand gestartete DNS-Auflösung im Reiter Verknüpfungen (System-Resolver).
- Reports contain the customer's topology and must be handled like customer data. Passwords and keys in embedded
  config lines are masked by default (`--no-redact` disables this).
- Relevant: parser or report issues that execute injected content (e.g. XSS from crafted config values), leaks of
  masked secrets, path handling.

## Supported versions / Unterstützte Versionen
Only the latest release (pre-1.0: latest `0.x`) receives fixes.

## Handling of customer data / Umgang mit Kundendaten
See [docs/PRIVACY.md](docs/PRIVACY.md).
