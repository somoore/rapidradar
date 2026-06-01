# RapidRadar Environment Configuration

The full configuration guide now lives in [docs/configuration.md](../../docs/configuration.md).

This directory contains the YAML files consumed by the deployment CLI:

- [common.yml](common.yml)
- [sra.yml](sra.yml)
- [scp.yml](scp.yml)
- [auto-remediation.yml](auto-remediation.yml)
- [auto-tagger.yml](auto-tagger.yml)
- [post-deploy-ssm-automation.yml](post-deploy-ssm-automation.yml)
- [alerts-customization.yml](alerts-customization.yml)

Keep real secrets out of these files. Store sensitive values in AWS Secrets Manager or SSM Parameter Store and reference those names from YAML.
