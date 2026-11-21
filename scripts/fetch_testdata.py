#!/usr/bin/env python3
"""Download the public sample configs used by the corpus tests into ``testdata/``.

The files are NOT part of this repository. They come from a third-party project under the
Apache License 2.0 (see docs/SOURCES.md). Pinned to one commit so results are reproducible.
Secret-looking hex blobs (>= 40 hex characters) are replaced by zeros of the same length after download.

Usage:  python3 scripts/fetch_testdata.py [--dest testdata]
Needs network access to raw.githubusercontent.com. Nothing is sent except the file requests.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from pathlib import Path

REPO = "f5devcentral/vscode-f5-flipper"
COMMIT = "e89eb68d6790"  # pinned (short commit id)
BASE = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/tests/artifacts/"
LICENSE_URL = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/LICENSE"
FILES = """aaaLegacy.ns.conf anyProtocol.ns.conf appFirewall.ns.conf apple.ns.conf auditLogging.ns.conf
authorization.ns.conf banana.ns.conf bren.ns.conf caching.ns.conf compression.ns.conf customMonitors.ns.conf
diagnosticsTriggers.ns.conf dnsLoadBalancer.ns.conf fn-2187.ns.conf groot.ns.conf gslbComplete.ns.conf
haCluster.ns.conf nFactorAuth.ns.conf namaste.conf networkObjects.ns.conf ns1_v13.1-simple.conf ns1_v13.1.conf
oauthAuth.ns.conf persistence.ns.conf productionWeb.ns.conf profiles.ns.conf rateLimiting.ns.conf samlAuth.ns.conf
skree.ns.conf specialCharacters.ns.conf spillover.ns.conf sslBridge.ns.conf starlord.ns.conf t1-apps.ns.conf
t1.ns.conf tcpLdaps.ns.conf tcpListenPolicy.ns.conf udpNtp.ns.conf""".split()
_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 (fixed https URL)
        return r.read()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", default="testdata")
    dest = Path(ap.parse_args().dest)
    dest.mkdir(parents=True, exist_ok=True)
    failed = []
    for name in FILES:
        text = None
        for sub in ("", "apps/"):  # most samples live in tests/artifacts/apps/ at the pinned commit
            try:
                text = _get(BASE + sub + name).decode("utf-8", errors="replace")
                break
            except Exception as exc:  # try the next location, report if none works
                err = exc
        if text is None:
            failed.append(f"{name}: {err}")
            continue
        text = _HEX.sub(lambda m: "0" * len(m.group(0)), text)
        (dest / name).write_text(text, encoding="utf-8")
    try:
        (dest / "LICENSE-Apache-2.0.txt").write_bytes(_get(LICENSE_URL))
    except Exception as exc:
        failed.append(f"LICENSE: {exc}")
    print(f"{len(FILES) - len([f for f in failed if not f.startswith('LICENSE')])}/{len(FILES)} files in {dest}")
    for f in failed:
        print("FAILED", f, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
