# Security Policy

RapidRadar is a cloud security automation project and should be treated as privileged infrastructure code.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately to the project maintainer before opening a public issue.

Include:

- affected file or component;
- deployment mode or AWS service involved;
- impact and exploit conditions;
- reproduction steps if available;
- recommended fix if known.

## Secret Handling

Do not commit credentials or raw integration secrets. Use AWS Secrets Manager or SSM Parameter Store for:

- Slack bot tokens and signing secrets;
- PagerDuty routing keys and API tokens;
- Azure shared keys;
- Tailscale OAuth secrets;
- AWS access keys or temporary credentials.

The `core/env/*.yml` files should contain only configuration values and secret/parameter names.

## Operational Security

Review generated IAM policies, StackSets, permission boundaries, and cross-account roles before deploying to production. RapidRadar can make changes across AWS accounts by design, so remediation settings should be enabled gradually and tested in non-production accounts first.
