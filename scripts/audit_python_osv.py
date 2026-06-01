#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_FILES = [
    ROOT / "core/cf/deployment/requirements.lock",
    ROOT / "core/cf/deployment/slack_socket_app/requirements.lock",
    ROOT / "core/cf/deployment/sfn/sso_manager/build/requirements.lock",
]
PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)")


def normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def locked_packages() -> dict[str, str]:
    packages: dict[str, str] = {}
    for lock_file in LOCK_FILES:
        for line in lock_file.read_text().splitlines():
            match = PACKAGE_RE.match(line.strip())
            if match:
                packages[normalize(match.group(1))] = match.group(2)
    return packages


def main() -> int:
    packages = locked_packages()
    queries = [
        {"package": {"ecosystem": "PyPI", "name": name}, "version": version}
        for name, version in sorted(packages.items())
    ]
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)

    findings: list[str] = []
    for query, result in zip(queries, data.get("results", [])):
        vulnerabilities = result.get("vulns") or []
        if vulnerabilities:
            vuln_ids = ", ".join(vulnerability["id"] for vulnerability in vulnerabilities)
            findings.append(f"{query['package']['name']}=={query['version']}: {vuln_ids}")

    if findings:
        print("OSV PyPI audit failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    print(f"OSV PyPI audit passed for {len(packages)} locked packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
