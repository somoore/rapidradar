# RapidRadar Core

This directory contains the RapidRadar deployment CLI, CloudFormation templates, Lambda functions, Step Functions, and environment configuration.

Start with the root [README](../README.md), then read:

- [Architecture](../docs/architecture.md)
- [Configuration](../docs/configuration.md)

Deploy from this directory:

```bash
./rapidradar deploy
```

The CLI reads configuration from [env](env), packages deployment assets from [cf](cf), and applies stacks/StackSets using the names in [config/stacks.yml](config/stacks.yml).
