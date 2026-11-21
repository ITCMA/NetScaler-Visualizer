"""Rule configuration: disable rules, change severities and record accepted risks.

File format (JSON)::

    {
      "format": "nsviz-rules", "version": 1,
      "disable": ["QA-003"],
      "severity": {"MGMT-013": "info"},
      "exceptions": [
        {"rule": "QA-001", "object": "lb_legacy*", "device": "*", "reason": "accepted by the customer", "expires": "2027-06-30"}
      ]
    }

``object`` and ``device`` are shell-style patterns (case-insensitive, default ``*``). An exception ends after the
optional ``expires`` date; the finding then appears again.
"""
from __future__ import annotations

import importlib
import datetime as _dt
import fnmatch
import json
from pathlib import Path

from .rules import RULES, SEVERITIES

FORMAT = "nsviz-rules"
VERSION = 1


def load(path: str) -> dict:
    """Read and validate a rule configuration file."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"rule configuration not readable: {exc}") from exc
    return validate(data)


def validate(data: dict) -> dict:
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError(f"rule configuration: \"format\" must be \"{FORMAT}\"")
    importlib.import_module("nsviz.project")  # registers the project-level rules
    from .rules import load_builtin_rules
    load_builtin_rules()
    errors = []
    for rid in data.get("disable", []):
        if rid not in RULES:
            errors.append(f"unknown rule in \"disable\": {rid}")
    for rid, sev in (data.get("severity") or {}).items():
        if rid not in RULES:
            errors.append(f"unknown rule in \"severity\": {rid}")
        if sev not in SEVERITIES:
            errors.append(f"severity of {rid} must be one of {', '.join(SEVERITIES)}")
    for i, ex in enumerate(data.get("exceptions", []), 1):
        if ex.get("rule") not in RULES:
            errors.append(f"exception {i}: unknown rule {ex.get('rule')!r}")
        if not str(ex.get("reason", "")).strip():
            errors.append(f"exception {i}: \"reason\" is required")
        if ex.get("expires"):
            try:
                _dt.date.fromisoformat(str(ex["expires"]))
            except ValueError:
                errors.append(f"exception {i}: \"expires\" must be YYYY-MM-DD")
    if errors:
        raise ValueError("rule configuration: " + "; ".join(errors))
    return data


def _match(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase((value or "").lower(), (pattern or "*").lower())


def apply(findings: list, cfg: dict, today: _dt.date | None = None) -> tuple[list, list, list[dict]]:
    """Apply the configuration. Returns (remaining findings, suppressed findings with reason, notes)."""
    today = today or _dt.date.today()
    disabled = set(cfg.get("disable", []))
    sev = cfg.get("severity") or {}
    kept, suppressed, notes = [], [], []
    expired = 0
    exceptions = []
    for ex in cfg.get("exceptions", []):
        if ex.get("expires") and _dt.date.fromisoformat(str(ex["expires"])) < today:
            expired += 1
            continue
        exceptions.append(ex)
    n_disabled = n_changed = 0
    for f in findings:
        if f.rule_id in disabled:
            n_disabled += 1
            continue
        hit = next((ex for ex in exceptions if ex["rule"] == f.rule_id and _match(ex.get("object", "*"), f.name)
                    and any(_match(ex.get("device", "*"), d) for d in (f.devices or [f.device]))), None)
        if hit:
            suppressed.append((f, hit["reason"].strip(), hit.get("expires", "")))
            continue
        if f.rule_id in sev and sev[f.rule_id] != f.severity:
            f.severity = sev[f.rule_id]
            n_changed += 1
        kept.append(f)
    kept.sort(key=lambda f: (SEVERITIES.index(f.severity), f.rule_id, f.name))
    if n_disabled or n_changed or suppressed or expired:
        en = (f"Rule configuration applied: {n_disabled} finding(s) of disabled rules hidden, {n_changed} severity change(s), "
              f"{len(suppressed)} accepted exception(s)" + (f", {expired} exception(s) expired" if expired else "") + ".")
        de = (f"Regelkonfiguration angewendet: {n_disabled} Befund(e) deaktivierter Regeln ausgeblendet, {n_changed} Schweregrad-Änderung(en), "
              f"{len(suppressed)} akzeptierte Ausnahme(n)" + (f", {expired} Ausnahme(n) abgelaufen" if expired else "") + ".")
        notes.append({"en": en, "de": de})
    return kept, suppressed, notes
