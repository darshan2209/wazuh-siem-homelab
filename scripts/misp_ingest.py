#!/usr/bin/env python3
"""Pull IoCs from MISP and write them where Zeek and Wazuh can match on them.

Outputs three files:
  /opt/zeek/intel/misp-indicators.dat        Zeek intel framework
  /var/ossec/etc/lists/misp-domains          Wazuh CDB list (rule 100005)
  /var/ossec/etc/lists/misp-ips              Wazuh CDB list (rule 100006)

Run it on a timer:
    */30 * * * * /opt/lab/misp_ingest.py >> /var/log/misp_ingest.log 2>&1

Credentials come from the environment, never from source:
    export MISP_URL=https://localhost:8443
    export MISP_KEY=<your automation key>

This script is part of what backs the "secure development practices" claim:
credentials out of source, every external value validated before it reaches a
file, and no shell interpolation anywhere. Run `bandit -r scripts/` to show it.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
import urllib3
from pathlib import Path

import requests

# MISP ships a self-signed cert in the lab compose file. Verification is
# disabled ONLY because of that; MISP_VERIFY=1 turns it back on and you should
# set it if you put a real cert on the box.
VERIFY = os.environ.get("MISP_VERIFY", "0") == "1"
if not VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ZEEK_INTEL = Path(os.environ.get("ZEEK_INTEL_PATH", "/opt/zeek/intel/misp-indicators.dat"))
WAZUH_LISTS = Path(os.environ.get("WAZUH_LISTS_PATH", "/var/ossec/etc/lists"))

# Only these MISP attribute types are actionable for this lab. Anything else
# (file paths, mutexes, registry keys) has no matcher here, so it is dropped
# rather than written out as dead weight.
WANTED = {
    "ip-src": "ADDR",
    "ip-dst": "ADDR",
    "domain": "DOMAIN",
    "hostname": "DOMAIN",
    "url": "URL",
    "md5": "FILE_HASH",
    "sha1": "FILE_HASH",
    "sha256": "FILE_HASH",
}

# Validation. MISP is a trusted-ish source, but an attribute is still attacker-
# influenced data: anyone who can submit to a feed you subscribe to can put a
# newline or a shell metacharacter in a value. These files are parsed by Zeek
# and Wazuh, so a stray tab or newline corrupts the whole list.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                       r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
URL_RE = re.compile(r"^https?://[^\s\t\"'<>\\]{4,2000}$")


def env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"{name} is not set. Export it before running; do not hardcode it.")
    return value


def valid(kind: str, value: str) -> bool:
    """Reject anything that is not exactly the shape we expect."""
    if not value or len(value) > 2048:
        return False
    if any(c in value for c in "\n\r\t\x00"):
        return False
    if kind == "ADDR":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        # Never let a feed blocklist loopback or your own RFC1918 space: one
        # bad indicator would light up every rule you have.
        return not (ip.is_loopback or ip.is_private or ip.is_unspecified)
    if kind == "DOMAIN":
        return bool(DOMAIN_RE.match(value))
    if kind == "FILE_HASH":
        return bool(HASH_RE.match(value))
    if kind == "URL":
        return bool(URL_RE.match(value))
    return False


def fetch(url: str, key: str, days: int) -> list[dict]:
    """Restricted search: only to_ids attributes, only recent, only wanted types."""
    resp = requests.post(
        f"{url.rstrip('/')}/attributes/restSearch",
        headers={"Authorization": key, "Accept": "application/json"},
        json={
            "returnFormat": "json",
            "type": sorted(WANTED),
            "to_ids": True,
            "published": True,
            "last": f"{days}d",
            "limit": 10000,
        },
        timeout=60,
        verify=VERIFY,
    )
    resp.raise_for_status()
    return resp.json().get("response", {}).get("Attribute", [])


def write_atomic(path: Path, lines: list[str]) -> None:
    """Write via a temp file and rename, so Zeek never reads a half-written list."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)
    print(f"wrote {len(lines)} lines to {path}")


def main() -> int:
    url, key = env("MISP_URL"), env("MISP_KEY")
    days = int(os.environ.get("MISP_LAST_DAYS", "30"))

    try:
        attributes = fetch(url, key, days)
    except requests.RequestException as exc:
        sys.exit(f"MISP query failed: {exc}")

    zeek = ["#fields\tindicator\tindicator_type\tmeta.source"]
    domains, ips = [], []
    kept = dropped = 0

    for attr in attributes:
        kind = WANTED.get(attr.get("type", ""))
        value = str(attr.get("value", "")).strip()
        if not kind or not valid(kind, value):
            dropped += 1
            continue
        kept += 1
        zeek.append(f"{value}\tIntel::{kind}\tMISP")
        if kind == "DOMAIN":
            domains.append(f"{value}:malicious")
        elif kind == "ADDR":
            ips.append(f"{value}:malicious")

    write_atomic(ZEEK_INTEL, zeek)
    write_atomic(WAZUH_LISTS / "misp-domains", sorted(set(domains)))
    write_atomic(WAZUH_LISTS / "misp-ips", sorted(set(ips)))

    print(f"kept {kept}, dropped {dropped} malformed or unusable indicators")
    print("now run: /var/ossec/bin/wazuh-control restart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
