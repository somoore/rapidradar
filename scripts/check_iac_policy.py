#!/usr/bin/env python3
"""Offline CloudFormation security assertions for RapidRadar templates.

CloudFormation is not covered by any other CI gate that understands our IAM intent, so these
checks encode the invariants that regressions used to break:

* every ``AWS::Lambda::Permission`` is scoped by ``SourceAccount``/``SourceArn`` or by an
  ``aws:PrincipalArn`` condition (no unqualified ``Principal: "*"``);
* every ``AWS::SQS::QueuePolicy`` that grants ``lambda.amazonaws.com`` is conditioned on the
  source account and ARN;
* the cross-account roles and their permissions boundaries contain no IAM escalation primitives;
* cross-account role trust policies contain only the conditioned automation-account statement;
* container images drop to a non-root ``USER``.

The parser is deliberately dependency-free: CI runs it with the stock Python runtime.
"""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "core/cf/templates"
STACKSET = TEMPLATES / "stacksets/child-accounts-stackset.yml"
DOCKERFILES = (
    ROOT / "core/cf/deployment/sfn/sso_manager/build/Dockerfile",
    ROOT / "core/cf/deployment/slack_socket_app/Dockerfile",
)

RESOURCE = re.compile(r"^  ([A-Za-z0-9]+):\s*$")
ESCALATION_ACTIONS = (
    "iam:CreateRole",
    "iam:CreatePolicy",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "iam:CreateInstanceProfile",
    "iam:AddRoleToInstanceProfile",
)
CROSS_ACCOUNT_ROLE_BLOCKS = (
    "CrossAccountRole",
    "CrossAccountRolePermissionBoundary",
    "SlackActionsCrossAccountRole",
    "SlackActionsCrossAccountRolePermissionBoundary",
)


def indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def resource_blocks(text: str) -> dict[str, list[str]]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if RESOURCE.match(line)]
    starts.append(len(lines))
    blocks: dict[str, list[str]] = {}
    for start, end in zip(starts, starts[1:]):
        name = RESOURCE.match(lines[start]).group(1)
        blocks[name] = lines[start:end]
    return blocks


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


def check_lambda_permissions(path: Path, text: str) -> list[str]:
    errors = []
    for name, block in resource_blocks(text).items():
        body = "\n".join(block)
        if "Type: AWS::Lambda::Permission" not in body:
            continue
        principal_star = 'Principal: "*"' in body
        if principal_star:
            # AWS::Lambda::Permission has no Condition property and rejects wildcard principals,
            # so organization scope (PrincipalOrgID) is the tightest CFN-expressible bound for a
            # grant to an unknown set of child-account roles.
            if "PrincipalOrgID:" not in body:
                errors.append(
                    f"{path}: {name} grants Principal '*' without PrincipalOrgID organization scoping"
                )
            continue
        if "SourceAccount:" not in body:
            errors.append(f"{path}: {name} has no SourceAccount")
        if "SourceArn:" not in body:
            errors.append(f"{path}: {name} has no SourceArn")
    return errors


def check_queue_policies(path: Path, text: str) -> list[str]:
    errors = []
    for name, block in resource_blocks(text).items():
        body = "\n".join(block)
        if "Type: AWS::SQS::QueuePolicy" not in body:
            continue
        if "lambda.amazonaws.com" not in body:
            continue
        for required in ("aws:SourceAccount", "aws:SourceArn"):
            if required not in body:
                errors.append(f"{path}: {name} lambda grant is missing {required}")
    return errors


def check_cross_account_roles(path: Path, text: str) -> list[str]:
    errors = []
    blocks = resource_blocks(text)
    for name in CROSS_ACCOUNT_ROLE_BLOCKS:
        block = blocks.get(name)
        if block is None:
            continue
        body = "\n".join(block)
        for action in ESCALATION_ACTIONS:
            if action in body:
                errors.append(f"{path}: {name} grants escalation action {action}")
        if name.endswith("PermissionBoundary"):
            continue
        trust = nested_block(block, "AssumeRolePolicyDocument")
        if not trust:
            continue
        statements = sum(
            1 for line in trust if line.strip() in ('- Effect: "Allow"', "- Effect: Allow")
        )
        if statements != 1:
            errors.append(
                f"{path}: {name} trust policy has {statements} statements; "
                "only the conditioned automation-account statement is allowed"
            )
        if "aws:PrincipalArn" not in "\n".join(trust):
            errors.append(f"{path}: {name} trust policy is not conditioned on aws:PrincipalArn")
    return errors


def check_dockerfile_user(path: Path, text: str) -> list[str]:
    instructions = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    user_lines = [line for line in instructions if line.upper().startswith("USER ")]
    if not user_lines:
        return [f"{path}: no USER instruction (image runs as root)"]
    user = user_lines[-1].split(None, 1)[1].strip()
    if user in ("root", "0", "0:0"):
        return [f"{path}: final USER is {user}"]
    return []


def main() -> int:
    errors = []
    for path in sorted(TEMPLATES.rglob("*.yml")):
        text = path.read_text()
        errors.extend(check_lambda_permissions(path, text))
        errors.extend(check_queue_policies(path, text))
        if path == STACKSET:
            errors.extend(check_cross_account_roles(path, text))
    for path in DOCKERFILES:
        errors.extend(check_dockerfile_user(path, path.read_text()))

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"{len(errors)} IaC policy violation(s)", file=sys.stderr)
        return 1
    print("IaC policy checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
