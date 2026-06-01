#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)==[^\\s]+")


def normalize_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def fail(errors: list[str], path: Path, line: int | None, message: str) -> None:
    location = str(path.relative_to(ROOT))
    if line is not None:
        location = f"{location}:{line}"
    errors.append(f"{location}: {message}")


def check_workflows(errors: list[str]) -> None:
    workflows_dir = ROOT / ".github" / "workflows"
    if not workflows_dir.exists():
        fail(errors, workflows_dir, None, "workflow directory is missing")
        return

    for workflow in sorted(workflows_dir.glob("*.y*ml")):
        for index, line in enumerate(workflow.read_text().splitlines(), start=1):
            uses_match = re.search(r"\buses:\s*([^@\s]+)@([^\s#]+)", line)
            if uses_match and not uses_match.group(1).startswith("./"):
                ref = uses_match.group(2)
                if not HEX_SHA_RE.fullmatch(ref):
                    fail(errors, workflow, index, f"GitHub Action must be pinned to a full commit SHA, not {ref!r}")

            runner_match = re.search(r"\bruns-on:\s*['\"]?([^'\"\s]+)", line)
            if runner_match and runner_match.group(1).endswith("-latest"):
                fail(errors, workflow, index, "runner image must be explicit, not *-latest")


def check_requirement_lock(req_file: Path, errors: list[str]) -> None:
    lock_file = req_file.with_suffix(".lock")
    if not lock_file.exists():
        fail(errors, req_file, None, f"missing hash lock file {lock_file.name}")
        return

    direct_packages: set[str] = set()
    for index, raw_line in enumerate(req_file.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            fail(errors, req_file, index, "pip options are not allowed in direct requirements")
            continue
        if "@" in line or "://" in line or line.startswith("git+"):
            fail(errors, req_file, index, "URL and VCS requirements are not allowed")
            continue
        match = REQ_RE.match(line)
        if not match:
            fail(errors, req_file, index, "direct requirement must use exact == version pinning")
            continue
        direct_packages.add(normalize_package_name(match.group(1)))

    lock_packages: set[str] = set()
    current_package: str | None = None
    current_has_hash = False
    for index, raw_line in enumerate(lock_file.read_text().splitlines(), start=1):
        line = raw_line.strip()
        match = REQ_RE.match(line)
        if match:
            if current_package and not current_has_hash:
                fail(errors, lock_file, index - 1, f"locked package {current_package} has no sha256 hash")
            current_package = normalize_package_name(match.group(1))
            current_has_hash = "--hash=sha256:" in line
            lock_packages.add(current_package)
            continue
        if current_package and "--hash=sha256:" in line:
            current_has_hash = True

    if current_package and not current_has_hash:
        fail(errors, lock_file, None, f"locked package {current_package} has no sha256 hash")

    for package in sorted(direct_packages - lock_packages):
        fail(errors, req_file, None, f"direct package {package} is missing from {lock_file.name}")


def check_requirements(errors: list[str]) -> None:
    ignored_parts = {".git", ".venv", "venv", "__pycache__"}
    for req_file in sorted(ROOT.rglob("requirements.txt")):
        if ignored_parts.intersection(req_file.parts):
            continue
        check_requirement_lock(req_file, errors)


def check_dockerfiles(errors: list[str]) -> None:
    for dockerfile in sorted(ROOT.rglob("Dockerfile")):
        if ".git" in dockerfile.parts:
            continue
        for index, raw_line in enumerate(dockerfile.read_text().splitlines(), start=1):
            line = raw_line.strip()
            if line.startswith("FROM ") and "@sha256:" not in line:
                fail(errors, dockerfile, index, "base image must be digest-pinned")
            if "pip install" in line and "--require-hashes" not in line:
                fail(errors, dockerfile, index, "pip installs must use --require-hashes")
            if "apk add" in line and "=" not in line:
                fail(errors, dockerfile, index, "apk packages must be version-pinned or removed")


def check_go_modules(errors: list[str]) -> None:
    go_mod = ROOT / "core" / "go.mod"
    go_sum = ROOT / "core" / "go.sum"
    if not go_mod.exists():
        return
    if not go_sum.exists():
        fail(errors, go_mod, None, "go.sum is required for checksum verification")

    go_mod_text = go_mod.read_text()
    if re.search(r"github\.com/aws/aws-sdk-go\s+v1", go_mod_text):
        fail(errors, go_mod, None, "AWS SDK for Go v1 is end-of-support; use aws-sdk-go-v2")


def main() -> int:
    errors: list[str] = []
    check_workflows(errors)
    check_requirements(errors)
    check_dockerfiles(errors)
    check_go_modules(errors)

    if errors:
        print("Supply-chain policy check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Supply-chain policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
