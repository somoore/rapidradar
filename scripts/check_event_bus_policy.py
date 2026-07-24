#!/usr/bin/env python3
"""Keep the central EventBridge policy aligned with every forwarded event."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "core/cf/templates"
POLICY = TEMPLATES / "nested-stacks/event-rules.yml"
PRODUCERS = tuple(
    path for path in TEMPLATES.rglob("*.yml")
    if "AutomationEventBusName" in path.read_text()
)
RESOURCE = re.compile(r"^  [A-Za-z0-9]+:\s*$")


def indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def resource_blocks(text: str) -> list[list[str]]:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if RESOURCE.match(line)]
    starts.append(len(lines))
    return [lines[start:end] for start, end in zip(starts, starts[1:])]


def nested_block(lines: list[str], key: str) -> list[str]:
    for start, line in enumerate(lines):
        if line.strip() != f"{key}:":
            continue
        base = indent(line)
        end = start + 1
        while end < len(lines):
            if lines[end].strip() and indent(lines[end]) <= base:
                break
            end += 1
        return lines[start + 1:end]
    return []


def list_values(lines: list[str], key: str) -> set[str]:
    for start, line in enumerate(lines):
        match = re.fullmatch(rf"{re.escape(key)}\s*:(.*)", line.strip())
        if not match:
            continue
        inline_value = match.group(1).strip()
        if inline_value:
            raise ValueError(
                f"{key} must use a block list; unsupported inline value: "
                f"{inline_value}"
            )
        base = indent(line)
        values: set[str] = set()
        for item in lines[start + 1:]:
            stripped = item.strip()
            # YAML permits indentationless sequences, where "- value" is at
            # the same indentation as its "key:" (used by GuardDuty here).
            if stripped.startswith("- ") and indent(item) >= base:
                values.add(stripped[2:].strip("'\""))
                continue
            if stripped and indent(item) <= base:
                break
        return values
    return set()


def forwarded_contracts() -> tuple[set[str], set[str]]:
    sources: set[str] = set()
    detail_types: set[str] = set()
    for path in PRODUCERS:
        for resource in resource_blocks(path.read_text()):
            block_text = "\n".join(resource)
            if "AutomationEventBusName" not in block_text:
                continue
            pattern = nested_block(resource, "EventPattern")
            sources.update(list_values(pattern, "source"))
            detail_types.update(list_values(pattern, "detail-type"))
    return sources, detail_types


def policy_allowlist() -> tuple[set[str], set[str]]:
    block = next(
        block for block in resource_blocks(POLICY.read_text())
        if block[0].strip() == "EventBusPolicy:"
    )
    return (
        list_values(block, "events:source"),
        list_values(block, "events:detail-type"),
    )


def main() -> None:
    forwarded_sources, forwarded_types = forwarded_contracts()
    policy_sources, policy_types = policy_allowlist()
    missing_sources = sorted(forwarded_sources - policy_sources)
    missing_types = sorted(forwarded_types - policy_types)

    if missing_sources or missing_types:
        lines = [f"missing source: {value}" for value in missing_sources]
        lines += [f"missing detail-type: {value}" for value in missing_types]
        raise SystemExit("event bus forwarding contract is incomplete:\n- " + "\n- ".join(lines))

    print(
        "event bus forwarding contract: OK "
        f"({len(forwarded_sources)} sources, {len(forwarded_types)} detail types)"
    )


if __name__ == "__main__":
    main()
