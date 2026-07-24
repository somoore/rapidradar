#!/usr/bin/env python3
"""Keep the central EventBridge policy aligned with forwarded child events."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "core/cf/templates/nested-stacks/event-rules.yml"

REQUIRED = {
    "capture-existing-resources": "Capture Existing Resources",
    "detect-unused-resources": "Detect Unused Resources",
    "aws.guardduty": "GuardDuty Finding",
}

PRODUCERS = (
    ROOT / "core/cf/templates/stacksets/child-accounts-stackset.yml",
    ROOT / "core/cf/templates/stacksets/guardduty/enabler.yml",
)


def event_bus_policy_block(text: str) -> str:
    start = text.index("  EventBusPolicy:")
    end = text.index("\n  EventBusRule", start)
    return text[start:end]


def main() -> None:
    block = event_bus_policy_block(POLICY.read_text())
    producer_text = "\n".join(path.read_text() for path in PRODUCERS)
    missing: list[str] = []

    for source, detail_type in REQUIRED.items():
        if f"- {source}" not in producer_text or f"- {detail_type}" not in producer_text:
            missing.append(f"producer contract {source!r} / {detail_type!r}")
        if f"- {source}" not in block or f"- {detail_type}" not in block:
            missing.append(f"central allowlist {source!r} / {detail_type!r}")

    if missing:
        raise SystemExit("event bus forwarding contract is incomplete:\n- " + "\n- ".join(missing))

    print("event bus forwarding contract: OK")


if __name__ == "__main__":
    main()
