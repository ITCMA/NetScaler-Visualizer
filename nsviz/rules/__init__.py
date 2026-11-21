"""Extensible check rules.

A rule is a function ``check(ctx)`` registered with ``@rule(...)`` that yields ``ctx.finding(key, ...)``.
Texts (title, rationale, remediation) and finding messages live in language catalogs under
``rules/i18n/`` (``en.json``/``de.json`` and ``messages_en.json``/``messages_de.json``); English is the leading
language. New rule = a function in a module of this package (modules are imported automatically) plus
catalog entries in both languages.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CATEGORIES = ["misconfig", "best-practice", "compliance"]
LANGS = ("en", "de")
_I18N = Path(__file__).parent / "i18n"


def _load(name: str) -> dict:
    return json.loads((_I18N / name).read_text(encoding="utf-8"))


TEXTS = {lang: _load(f"{lang}.json") for lang in LANGS}
MESSAGES = {lang: _load(f"messages_{lang}.json") for lang in LANGS}


def render_messages(msg_key: str, **params) -> dict[str, str]:
    """Message for all languages; missing German entries fall back to English."""
    out = {}
    for lang in LANGS:
        tpl = MESSAGES[lang].get(msg_key) or MESSAGES["en"][msg_key]
        out[lang] = tpl.format(**params)
    return out


@dataclass
class Rule:
    id: str
    severity: str
    category: str
    refs: list[str] = field(default_factory=list)
    confidence: str = "certain"  # certain | likely | heuristic
    func: Callable | None = field(default=None, repr=False)

    def text(self, lang: str = "en") -> dict[str, str]:
        t = TEXTS.get(lang, {}).get(self.id) or TEXTS["en"][self.id]
        return t

    @property
    def title(self) -> str:
        return self.text()["title"]

    def meta(self) -> dict:
        return {"id": self.id, "severity": self.severity, "category": self.category, "refs": self.refs,
                "confidence": self.confidence, "texts": {lang: self.text(lang) for lang in LANGS}}


RULES: dict[str, Rule] = {}


def rule(id: str, severity: str, category: str, refs: Iterable[str] = (), confidence: str = "certain"):
    assert severity in SEVERITIES and category in CATEGORIES, id

    def deco(fn):
        assert id not in RULES, f"duplicate rule id {id}"
        RULES[id] = Rule(id, severity, category, list(refs), confidence, fn)
        return fn
    return deco


def register_meta(r: Rule) -> None:
    """Register a rule without a check function (project-level rules)."""
    RULES[r.id] = r


@dataclass
class Finding:
    rule_id: str
    severity: str
    msgs: dict[str, str]  # language -> message
    device: str
    etype: str = ""
    name: str = ""
    file: str = ""
    line: int = 0
    evidence: list[str] = field(default_factory=list)
    node: str = ""
    devices: list[str] = field(default_factory=list)
    id: str = ""

    @property
    def message(self) -> str:
        return self.msgs["en"]

    def key(self) -> tuple:
        return (self.rule_id, self.etype, self.name, self.message)


def load_builtin_rules() -> None:
    from . import __path__ as p  # noqa
    for m in pkgutil.iter_modules(p):
        importlib.import_module(f"{__name__}.{m.name}")


def run_rules(cfg, graph, device_name: str, only: set[str] | None = None) -> list[Finding]:
    from .context import Ctx
    load_builtin_rules()
    out: list[Finding] = []
    for r in RULES.values():
        if r.func is None or (only and r.id not in only):
            continue
        ctx = Ctx(cfg, graph, device_name, r)
        try:
            for f in r.func(ctx) or []:
                out.append(f)
        except Exception as exc:  # a faulty rule must never stop the run
            cfg.warnings.append(f"Rule {r.id} failed: {exc!r}")
    return out


def finalize(findings: list[Finding]) -> list[Finding]:
    """Merge identical findings of several devices (HA pair) and assign IDs."""
    merged: dict[tuple, Finding] = {}
    for f in findings:
        k = f.key()
        if k in merged:
            if f.device not in merged[k].devices:
                merged[k].devices.append(f.device)
        else:
            f.devices = [f.device]
            merged[k] = f
    res = sorted(merged.values(), key=lambda f: (SEVERITIES.index(f.severity), f.rule_id, f.name))
    for f in res:
        f.id = "F" + hashlib.sha1(repr(f.key()).encode(), usedforsecurity=False).hexdigest()[:8]
    return res
