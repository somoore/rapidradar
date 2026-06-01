# RapidRadar

RapidRadar is an AWS organization security automation platform for teams that want to move from reactive alerting to proactive cloud governance.

It watches high-risk AWS activity across accounts and regions, applies preventive guardrails where possible, enriches events with ownership context, notifies the right people, and can remediate common issues automatically or through Slack actions.

## What RapidRadar Does

- Enables organization-wide security foundations such as GuardDuty, Inspector, Security Hub, default EBS encryption, CloudTrail, and VPC Flow Logs.
- Detects risky resource changes from CloudTrail and EventBridge, including public S3 access, public snapshots and AMIs, permissive security groups, IAM user activity, root logins, missing tags, and unencrypted resources.
- Enforces preventive controls with Service Control Policies for required tags, IMDSv2, encryption, public IPs, Elastic IPs, load balancers, IAM users, and public snapshots.
- Builds a lightweight CMDB for active and deleted AWS resources, ownership, tags, cost metadata, and user attribution.
- Sends alerts to Slack, Microsoft Teams, Google Chat, email, PagerDuty, and optional Azure Log Analytics.
- Supports automated remediation, human-approved Slack actions, SSO user IP tracking, offboarding reports, and unused resource cleanup.

## Why Use RapidRadar

Cloud security usually fails in the gap between detection and action. RapidRadar closes that gap:

- Prevent unsafe changes before they land with SCPs and baseline services.
- Catch drift quickly with event-driven detection.
- Attribute resources to owners and teams instead of dumping alerts into a shared queue.
- Give engineers clear remediation paths where they already work.
- Keep security admins informed without requiring them to manually inspect every account.

## Quick Setup

### 1. Prerequisites

Install:

- AWS CLI
- Docker
- Go
- `yq`
- `rain`

Configure AWS profiles for the management account and automation account. If email alerts are enabled, verify the sender and receiver addresses in Amazon SES.

### 2. Configure RapidRadar

Edit the YAML files in [core/env](core/env):

- [common.yml](core/env/common.yml): organization, regions, notifications, feature flags
- [sra.yml](core/env/sra.yml): GuardDuty, Inspector, Security Hub, encryption
- [scp.yml](core/env/scp.yml): preventive organization policies
- [auto-remediation.yml](core/env/auto-remediation.yml): automated fixes
- [auto-tagger.yml](core/env/auto-tagger.yml): tagging behavior
- [post-deploy-ssm-automation.yml](core/env/post-deploy-ssm-automation.yml): EC2 SSM/IMDSv2 automation
- [alerts-customization.yml](core/env/alerts-customization.yml): severity, ports, suppression, reminders

Keep real tokens, routing keys, shared keys, and OAuth secrets in AWS Secrets Manager or SSM Parameter Store. The YAML files should reference secret names, not contain secret values.

### 3. Deploy

```bash
cd core
./rapidradar deploy
```

For non-interactive deployment:

```bash
cd core
./rapidradar deploy --yes
```

### 4. Validate

After deployment, check:

- CloudFormation stacks and StackSets completed successfully.
- The automation account contains the RapidRadar EventBridge bus.
- Child accounts have forwarding rules and cross-account roles.
- DynamoDB tables are receiving resource/security records.
- Slack, PagerDuty, email, or your selected notification channel receives a test alert.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Security Policy](core/SECURITY.md)

## Repository Layout

```text
.
├── core/
│   ├── cmd/                 # Go deployment CLI
│   ├── cf/                  # CloudFormation templates and Lambda/Step Functions code
│   ├── config/              # Stack naming configuration
│   └── env/                 # Deployment configuration
└── docs/                    # Human-readable architecture and setup docs
```
