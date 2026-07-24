#!/usr/bin/env python3
"""Keep the central EventBridge policy aligned with every forwarded event."""

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "core/cf/templates"
POLICY = TEMPLATES / "nested-stacks/event-rules.yml"
RUNTIME_RULES = (
    ROOT / "core/cf/deployment/lambdas/process_events/utils/events.py"
)
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


def rule_contract(
    resource: list[str], context: str
) -> tuple[set[str], set[str]]:
    pattern = nested_block(resource, "EventPattern")
    sources = list_values(pattern, "source")
    detail_types = list_values(pattern, "detail-type")
    if not sources or not detail_types:
        missing = []
        if not sources:
            missing.append("source")
        if not detail_types:
            missing.append("detail-type")
        raise ValueError(
            f"{context} forwards to the central bus without "
            + " and ".join(missing)
        )
    return sources, detail_types


def literal_assignments(path: Path) -> dict[str, object]:
    tree = ast.parse(path.read_text(), filename=str(path))
    values: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            try:
                values[target.id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
    return values


def runtime_contracts() -> tuple[set[str], set[str]]:
    source = RUNTIME_RULES.read_text()
    tree = ast.parse(source, filename=str(RUNTIME_RULES))
    values = literal_assignments(RUNTIME_RULES)
    try:
        function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "create_rules_to_capture_iam_user_events"
        )
        pattern = next(
            call.args[0] for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "json"
            and call.func.attr == "dumps"
            and call.args
            and isinstance(call.args[0], ast.Dict)
        )
        fields = {
            key.value: value
            for key, value in zip(pattern.keys, pattern.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }

        def resolve(field: str) -> object:
            node = fields[field]
            if isinstance(node, ast.Name):
                return values[node.id]
            return ast.literal_eval(node)

        sources = set(resolve("source"))
        detail_types = set(resolve("detail-type"))
    except (KeyError, StopIteration, TypeError, ValueError) as error:
        raise ValueError(
            "runtime IAM-user EventPattern contract must be literal"
        ) from error
    if not sources or not detail_types:
        raise ValueError("runtime IAM-user forwarding contract is empty")
    return sources, detail_types


def forwarded_contracts() -> tuple[set[str], set[str]]:
    sources: set[str] = set()
    detail_types: set[str] = set()
    for path in PRODUCERS:
        for resource in resource_blocks(path.read_text()):
            block_text = "\n".join(resource)
            if (
                "EventPattern:" not in block_text
                or "AutomationEventBusName" not in block_text
            ):
                continue
            resource_name = resource[0].strip().removesuffix(":")
            rule_sources, rule_types = rule_contract(
                resource, f"{path.relative_to(ROOT)}:{resource_name}"
            )
            sources.update(rule_sources)
            detail_types.update(rule_types)
    runtime_sources, runtime_types = runtime_contracts()
    sources.update(runtime_sources)
    detail_types.update(runtime_types)
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
    stale_sources = sorted(policy_sources - forwarded_sources)
    stale_types = sorted(policy_types - forwarded_types)

    if missing_sources or missing_types or stale_sources or stale_types:
        lines = [f"missing source: {value}" for value in missing_sources]
        lines += [f"missing detail-type: {value}" for value in missing_types]
        lines += [f"stale source: {value}" for value in stale_sources]
        lines += [f"stale detail-type: {value}" for value in stale_types]
        raise SystemExit("event bus forwarding contract is incomplete:\n- " + "\n- ".join(lines))

    print(
        "event bus forwarding contract: OK "
        f"({len(forwarded_sources)} sources, {len(forwarded_types)} detail types)"
    )


if __name__ == "__main__":
    main()
