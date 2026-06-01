# Configuration

RapidRadar is configured from YAML files in [core/env](../core/env). Keep these files focused on deployment choices and secret references. Do not put raw API tokens, OAuth secrets, routing keys, or shared keys in the repository.

## Core Files

- [common.yml](../core/env/common.yml): project name, organization targets, regions, notification channels, feature flags, optional integrations.
- [sra.yml](../core/env/sra.yml): GuardDuty, Inspector, Security Hub, and default encryption settings.
- [scp.yml](../core/env/scp.yml): preventive Service Control Policy behavior.
- [auto-remediation.yml](../core/env/auto-remediation.yml): which findings RapidRadar can automatically fix.
- [auto-tagger.yml](../core/env/auto-tagger.yml): tagging defaults and tag-template behavior.
- [post-deploy-ssm-automation.yml](../core/env/post-deploy-ssm-automation.yml): EC2 SSM role, endpoint, association, and IMDSv2 automation.
- [alerts-customization.yml](../core/env/alerts-customization.yml): alert ports, suppression tags, severity reminders, and unused-resource detection options.

## Minimum Setup

Set these first:

```yaml
ProjectName: rapidradar
AwsOrgName: your-org-name
DeploymentTargets: "r-xxxx"
ExcludeAccounts: ""
IsControlTowerEnabled: true
LogArchiveAccountId: "<LOG_ARCHIVE_ACCOUNT_ID>"
ActiveRegions: "us-east-1,us-east-2,us-west-1,us-west-2"
```

Then choose notification settings:

```yaml
EngineerFacingNotificationsApp: slack
EngineerFacingNotificationsConfigsSecretName: /rapidradar/ENGINEER_FACING_NOTIFICATION_CONFIGS
SecurityAdminFacingNotificationsApp:
SecurityAdminFacingNotificationsConfigsSecretName:
```

## Secrets

Use AWS Secrets Manager or SSM Parameter Store for sensitive values:

- Slack bot token, signing secret, and channel IDs
- PagerDuty routing key or API token
- Azure shared key
- Tailscale OAuth client secret

The YAML values should look like names or paths:

```yaml
SlackBotConfigSecretName: /rapidradar/SLACK_BOT_SECRET
PagerDutyRoutingKeySSM: /rapidradar/pagerduty/ROUTING_KEY
AzureSharedKeySSM: /rapidradar/azure/SHARED_KEY
OAuthClientSecretSSM: /rapidradar/tailscale/OAUTH_CLIENT_SECRET
```

## Feature Flags

Start with the smallest useful set, then enable more automation after you trust the notifications.

Recommended first deployment:

```yaml
AddSupportforCMDB: true
AddSupportforIAMKeyPairAccessTracker: true
AddSupportforIPTracker: true
AddSupportforUserOffboardingWorkflow: false
EnableCostOptimizerRecommendations: true
```

Recommended first remediation posture:

```yaml
AllTrafficSGRulesRemediation: false
RemoteAccessPortsSGRulesRemediation: false
TrafficPortsSGRulesRemediation: false
S3AccountPublicBlockRemediation: false
PublicAMIsRemediation: false
PublicRDSSnapshotsRemediation: false
UnusedSecretAccessKeypairRemediation: true
```

Enable destructive remediation only after reviewing IAM permissions, alert quality, and owner workflows.

## Deployment

```bash
cd core
./rapidradar deploy --yes
```

To tear down the deployment:

```bash
cd core
./rapidradar destroy
```
