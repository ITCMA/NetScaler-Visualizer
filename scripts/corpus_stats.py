#!/usr/bin/env python3
"""Local-only helper: find duplicate configs and print aggregate, content-free statistics.

Intended for private config collections that must stay on the local machine (see docs/PRIVACY.md).
Nothing is sent anywhere. The console output contains counts only - no file names, host names, values
or config lines. Use ``--manifest`` to write the list of unique files (file names!) to a local file.

Duplicates are detected on normalized content:
  exact  = same lines after removing comments, blank lines, version/timestamp headers and whitespace differences
  loose  = same set of lines regardless of order (e.g. re-exported config of the same device)

Usage:  python3 scripts/corpus_stats.py <folder> [--manifest unique.txt] [--no-analyze]
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_KEYWORD = re.compile(r"^[a-z0-9 _.-]{1,40}$")


def normalize(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = " ".join(line.split())
        if s and not s.startswith("#"):
            out.append(s)
    return out


def digest(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode("utf-8", "replace")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("folder")
    ap.add_argument("--manifest", help="write the unique file list (contains file names) to this local file")
    ap.add_argument("--no-analyze", action="store_true", help="only report duplicates")
    ap.add_argument("--min-files", type=int, default=3, help="only print keywords seen in at least this many files")
    a = ap.parse_args()

    files = sorted(p for p in Path(a.folder).rglob("*") if p.is_file() and not p.name.startswith("."))
    exact: dict[str, list[Path]] = {}
    texts: dict[Path, str] = {}
    skipped = 0
    for p in files:
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        lines = normalize(t)
        if not any(l.split(" ", 1)[0] in ("add", "set", "bind", "enable", "link") for l in lines):
            skipped += 1  # not a config
            continue
        exact.setdefault(digest(lines), []).append(p)
        texts[p] = t
    unique = [g[0] for g in exact.values()]
    loose: dict[str, Path] = {}
    for p in unique:
        loose.setdefault(digest(sorted(set(normalize(texts[p])))), p)
    final = list(loose.values())
    dup_groups = Counter(len(g) for g in exact.values() if len(g) > 1)
    print(f"files found: {len(files)}; not a config / unreadable: {skipped}; configs: {len(texts)}")
    print(f"exact duplicates removed: {len(texts) - len(unique)} (groups by size: {dict(sorted(dup_groups.items())) or '-'})")
    print(f"same lines in different order removed: {len(unique) - len(final)}")
    print(f"unique configs to process: {len(final)}")
    if a.manifest:
        Path(a.manifest).write_text("\n".join(str(p) for p in final) + "\n", encoding="utf-8")
        print("manifest written (contains file names - keep it local)")
    if a.no_analyze or not final:
        return 0

    from nsviz.parser import Config
    from nsviz.project import Project
    verbs: Counter = Counter()
    warn_files = 0
    for p in final:
        cfg = Config.parse_text(texts[p], name="x")
        if cfg.warnings:
            warn_files += 1
        for k in {(s.verb, s.etype) for s in cfg.statements}:
            verbs[k] += 1
    print(f"parse warnings in {warn_files} of {len(final)} files")
    try:
        proj = Project.load([str(p) for p in final])
        by_rule = Counter(r for f in proj.findings for r in [f.rule_id])
        print(f"project: {len(proj.devices)} device(s), {len(proj.groups)} group(s), {len(proj.findings)} findings")
        print("findings per rule: " + ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items())))
    except Exception as exc:  # aggregate error type only
        print("project load failed:", type(exc).__name__)
    from nsviz.model import Graph
    probe = Graph(Config.parse_text("", name="x"), "g")
    unmapped = [(k, n) for k, n in verbs.items() if k[1] and probe._kind(k[1]) is None and n >= a.min_files
                and k[0] in ("add", "set") and _KEYWORD.match(k[1])]
    unmapped.sort(key=lambda x: -x[1])
    print(f"object types (add/set) without a topology node kind, seen in >= {a.min_files} files (candidates for new support):")
    for (v, et), n in unmapped[:60]:
        print(f"  {et}: {n} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
