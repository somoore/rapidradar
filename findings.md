# RapidRadar — security findings and remediation

- **Repository:** `/Users/scottmoore/github/rapidradar` @ `e1d5f0c` (working tree modified, nothing committed)
- **Scanned:** 2026-11-02. 303 tracked files: Go CLI, Python 3.11 Lambdas/Step Functions, 27 CloudFormation
  templates, 2 Dockerfiles, 1 GitHub Actions workflow.
- **Tools:** trivy (image/config), semgrep, gosec, govulncheck, gitleaks, hadolint, shellcheck, cfn-lint
  1.59.0, actionlint, `go vet`, `go test -race`, plus the repo's own `check_supply_chain_policy.py`,
  `check_event_bus_policy.py` and the new `check_iac_policy.py`.
- **Team roles:** PM, AppSec, pentest, devil's advocate, QA. Adjudication follows `04-devil.md` on verdicts
  and `03-pentest.md` on reachability.

## Verification (all run after the fixes)

```text
cd core && go mod verify && go build ./... && go vet ./...                 PASS
cd core && go test -race -count=1 ./...                                   PASS
cd core && gofmt -l .                                                     PASS (no output)
cd core && go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...          PASS (0 vulnerabilities)
cd core && go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -quiet ./...   PASS (0 issues)
python3 -m compileall -q core/cf/deployment                               PASS
python3 -m unittest scripts/test_check_event_bus_policy.py                PASS (5)
python3 -m unittest scripts/test_check_iac_policy.py                      PASS (14)
python3 -m unittest discover -s core/cf/deployment/lambdas/process_events/tests -p 'test_*.py'
                                                                          PASS (15)
python3 -m unittest discover -s core/cf/deployment/lambdas/slack_interactivity/tests -p 'test_*.py'
                                                                          PASS (6)
python3 scripts/check_event_bus_policy.py                                 PASS
python3 scripts/check_iac_policy.py                                       PASS
python3 scripts/check_supply_chain_policy.py                              PASS
cfn-lint 1.59.0 --non-zero-exit-code error <27 templates>                 PASS (0 errors)
gitleaks detect --source . --no-git --redact --exit-code 1                PASS (no leaks)
actionlint .github/workflows/ci.yml                                       PASS
hadolint <both Dockerfiles>                                               PASS
docker build + docker run --entrypoint id                                 PASS (uid=10001(appuser) both)
```

Deployment-time checks that need live AWS (`aws iam simulate-principal-policy`, `aws lambda get-policy`,
throwaway-account invoke tests) were **not** run here; the offline equivalents are in
`scripts/check_iac_policy.py` and `findings.md` lists the exact commands for the coordinator.

## Findings

| ID | Severity | Status | Location | Issue | Fix | Verification |
|----|----------|--------|----------|-------|-----|--------------|
| SC-01 / SEC-01 / P-02 | LOW (team: HIGH) | FIXED | `nested-stacks/lambda-functions.yml` `BackgroundTaskRunnerLambdaPermission` | Only Lambda permission in the repo with no `SourceAccount`/`SourceArn` (confused deputy; principal is the Lambda service, so org-wide blast radius was over-claimed) | Added `SourceAccount: !Ref AWS::AccountId` and `SourceArn: !GetAtt SlackInteractivityLambda.Arn` | `python3 scripts/check_iac_policy.py` passes; policy shape asserted by `test_check_iac_policy.py` |
| SC-02 | INFO | FALSE POSITIVE | `slack-socket-application.yml:158` | `SLACK_BOT_CONFIG_SECRET_NAME` is a secret *name*, not a token | none | re-read: no credential literal |
| SC-03 | INFO | FALSE POSITIVE | `slack-socket-application.yml:129-137` | Unrestricted egress 443/53 is required for Socket Mode; no ingress | none | n/a |
| SC-04 | LOW | ACCEPTED RISK | `management-account-stack.yml:1004`, `child-accounts-stackset.yml:888` | CloudTrail uses AWS-managed encryption, not a CMK | policy preference; multi-region trail already set | n/a |
| SC-05 | LOW | ACCEPTED RISK | `s3-buckets.yml:55,70`, `child-accounts-stackset.yml:801` | SSE-S3 instead of CMK | policy preference; public-access block fully on | n/a |
| SC-06 | LOW | FIXED | same three S3 buckets | Versioning absent (ransomware/recovery gap) | Added `VersioningConfiguration: {Status: Enabled}` | cfn-lint + `check_iac_policy.py` pass |
| SC-07 | LOW | ACCEPTED RISK | 6 buckets | Server-access logging absent; CloudTrail covers API access | none | n/a |
| SC-08 ×94 | INFO | ACCEPTED RISK | every Lambda | X-Ray tracing off (observability) | selective adoption later | n/a |
| SC-09 ×8 | INFO | ACCEPTED RISK | log groups | AWS-managed log encryption | none | n/a |
| SC-10 | LOW | ACCEPTED RISK | `child-accounts-stackset.yml:910` | Child trail not multi-region | StackSet deploys per target region | n/a |
| SC-11 | LOW | FIXED | `automation-dynamodb.yml` (17 tables) | No point-in-time recovery | Added `PointInTimeRecoverySpecification` to all 17 tables | cfn-lint; `grep -c` = 17 |
| SC-12 | LOW | ACCEPTED RISK | DynamoDB | AWS-managed encryption, not CMK | policy preference | n/a |
| SC-13 | LOW | ACCEPTED RISK | `automation-secrets.yml:1707` | Secrets Manager default key | policy preference | n/a |
| SC-14 | INFO | ACCEPTED RISK | `slack-socket-application.yml:138` | ECS container insights off | observability only | n/a |
| SC-15 ×3 | INFO | FIXED | `slack-socket-application.yml:126-140` | Missing SG rule descriptions | Descriptions added | cfn-lint pass |
| SC-16 | INFO | ACCEPTED RISK | `api-gateway.yml:132` | API Gateway X-Ray off | observability only | n/a |
| SC-17 | INFO | ACCEPTED RISK | `api-gateway.yml:140` | Response caching off | correct for an authenticated POST | n/a |
| SC-18 | LOW | DEFERRED | `network.yml:24` | Slack/Batch VPC has no flow log (flow logs only exist for child VPCs) | needs a delivery bucket/role; cost/ops decision | residual risk below |
| SC-19 | LOW | FIXED | `lambda-functions.yml:1026` | DLQ unencrypted | `KmsMasterKeyId: alias/aws/sqs` | cfn-lint pass |
| SC-20 | LOW | FIXED | `lambda-functions.yml:1104` | Alarms SNS topic unencrypted | `KmsMasterKeyId: alias/aws/sns` | cfn-lint pass |
| SC-21 | INFO | FALSE POSITIVE | `network.yml:43,57` | `MapPublicIpOnLaunch` on the two *public* subnets only | none | re-read |
| SC-22 / SEC-12 | LOW | FIXED | `sfn/sso_manager/build/Dockerfile` | Image ran as root | `adduser -D -u 10001 appuser`, `chown`, `USER 10001` | `docker run --entrypoint id` → uid=10001(appuser) |
| SC-23 | INFO | ACCEPTED RISK | both Dockerfiles | No HEALTHCHECK; not used by Lambda/Batch health | none | n/a |
| SC-24 | LOW | FIXED | `slack_socket_app/Dockerfile` | Non-numeric UID | `adduser -D -u 10001`, `USER 10001` | hadolint 0 findings; image uid=10001 |
| SC-25 / SEC-09 | LOW | FIXED | `core/go.mod` | `golang.org/x/text v0.4.0` had two DoS advisories (symbol-unreachable) | `go get golang.org/x/text@v0.43.0` + `go mod tidy` | `go mod verify`, build/test, govulncheck 0 |
| SC-26 | INFO | FALSE POSITIVE | `envloader.go:201-248` | G101 hits are Secrets Manager JSON *field names* | added rule-scoped `#nosec G101` with reasons | gosec v2.30.0 0 issues |
| SC-27 | INFO | FALSE POSITIVE | `ecr.go:105,123,127`, `cloudformation.go:315` | G204 hits are fixed binaries with argv-only args | added rule-scoped `#nosec G204` with reasons | gosec v2.30.0 0 issues |
| SC-28 | INFO | FALSE POSITIVE | `core/env/common.yml:35` (history) | gitleaks hit is the tag key `notifications=suppressed` | none (already `# gitleaks:allow`) | gitleaks clean; no rotation needed |
| SC-29 ×11 | INFO | FALSE POSITIVE | 11 logger calls | All log secret *names*/paths or error text, never values | none | re-read all 11 |
| SC-30 ×2 | INFO | FALSE POSITIVE | `utility.py:217`, `get_user_details/main.py:220` | `HTTPSConnection` with default verifying context | none | re-read |
| SC-31 | INFO | FALSE POSITIVE | `scripts/audit_python_osv.py:45` | URL is a literal; only the POST body is dynamic | none | re-read |
| SC-32 | INFO | ACCEPTED RISK | `.github/dependabot.yml` | No cooldown | hygiene; hash locks + SHA pins already enforced | n/a |
| SC-33 | INFO | n/a | shell scripts | shellcheck: 0 findings | none | n/a |
| SEC-02 / P-03 | LOW (team: HIGH) | MITIGATED | `lambda-functions.yml` `EventsProcessorLambdaDLQPolicy` | DLQ `SendMessage` grant had no source conditions; "any account can write" was not demonstrated (DLQ delivery uses the execution role) | Added `aws:SourceAccount` + `aws:SourceArn` conditions; forged-account validation added in `main.py` (M-03) | `check_iac_policy.py` queue-policy assertions |
| SEC-03 / SEC-10 | MEDIUM | MITIGATED | `slack-socket-application.yml`, `lambda-functions.yml` bg-runner role | Wildcard `sts:AssumeRole`; wildcard secret reads | `sts:AssumeRole` now scoped to `${ProjectName}-sso-cross-account-role` and `${ProjectName}-slack-cross-account-role-*`; secret ARNs left wildcard (dynamic names — O-10) | cfn-lint; residual risk below |
| SEC-04 / P-04 | LOW | MITIGATED | `request_verifier/main.py`, `api-gateway.yml` | Authorizer only shape-checks the signature; it cannot HMAC without the body | Documented precisely (template comment, code docstring, `docs/architecture.md`), fixed NaN bypass; the handler's real HMAC is untouched | `test_request_verifier.py` (6 tests) |
| SEC-05 | MEDIUM | DEFERRED | `responses_handler/main.py` | `user_id` never authorised; account-wide `s3:PutAccountPublicAccessBlock` reachable by any workspace member | needs an admin/allowlist setting — product change (HIGH fix risk) | residual risk below |
| SEC-06 | MEDIUM | MITIGATED | `event-rules.yml:249-274` | Bus policy allows any org principal (shape-check only) | account/identity mismatch and non-target accounts now rejected before STS (M-03); bus principal change deferred (needs forwarding-role rollout) | `test_event_account.py` (5 tests) |
| SEC-07 | INFO | FIXED | `slack-socket-application.yml:204` | `AssignPublicIp: ENABLED` in private/NAT subnets (hygiene; not internet-reachable) | `DISABLED` | cfn-lint pass |
| SEC-08 / O-09 | LOW | FIXED | `cmd/helper/helper.go:Ask` | Secret prompts echoed to TTY/scrollback | `readline.Config{EnableMask: true}` (all `Ask` call sites are secret prompts) | `go build`/`vet`/`test` pass |
| SEC-11 / P-07 | LOW | FIXED | `slack_socket_app/app.py`, `responses_handler/helper.py:52` | Full Slack bodies (incl. `response_url`) and payloads logged at INFO | `_redact_body()` strips `response_url`, `trigger_id`, tokens and `private_metadata`; background-task log now records only `Action` | `python -m compileall`; grep for `response_url` in log calls returns nothing |
| SEC-13 | LOW | MITIGATED | SQS/SNS/DynamoDB/S3 | Resilience items (PITR, versioning, SQS/SNS keys) | PITR ×17, versioning ×3, `alias/aws/sqs`, `alias/aws/sns` added; CMK choices accepted | cfn-lint pass |
| M-01 | HIGH | FIXED | `child-accounts-stackset.yml` `CrossAccountRole` + boundary | Identity policy ∩ boundary allowed `iam:CreateRole`, `iam:CreatePolicy*`, `iam:AttachRolePolicy`, `iam:PassRole`, `iam:CreateInstanceProfile`, `iam:AddRoleToInstanceProfile` → full child-account takeover from one Lambda compromise | Removed all six from the identity policy **and** the permissions boundary | `check_iac_policy.py` escalation-action assertion + repo-state unit test |
| M-02 / P-01 | MEDIUM | MITIGATED | `lambda-functions.yml` `StepFunctionExecutorLambdaPermissions` | `Principal: "*"` + `PrincipalOrgID`: any org principal can invoke `sfn-executor` | Cannot be role-scoped in CFN (`Condition` is not a valid property and wildcard principals are rejected); handler now allowlists `KwArgs` (`stateMachineArn`/`input`/`name`), validates name/JSON/size and the state-machine ARN prefix | cfn-lint (E3002 regression proven) + code review; residual risk below |
| M-03 | MEDIUM | FIXED | `process_events/main.py`, new `utils/event_account.py` | Account derived from a forgeable event; `get_active_session()` could run before the allowlist check | Envelope account must match `detail.userIdentity.accountId` and be a deployment target (management allowed); runs before `AWSHelper`/STS | `test_event_account.py` (5 tests) |
| M-04 | LOW-MED | DEFERRED | `child-accounts-stackset.yml` `CrossAccountRole` S3 statement | `s3:GetObject`/`ListBucket` on `*` in every child account | needs a per-check audit before removal | residual risk below |
| M-05 | LOW | DEFERRED | `lambda-layers.yml:201-218` | Layer-ARN secret readable org-wide | intentional cross-account dynamic references | residual risk below |
| M-06 | INFO | DEFERRED | `responses_handler/main.py:64-69` | `required_keys` includes `actions`, so `view_submission` is unreachable | functional bug; fix needs per-`type` validation (not in this security pass) | residual risk below |
| M-07 / P-05 | LOW | FIXED | `request_verifier/main.py`, `responses_handler/helper.py` | `float("nan")` bypassed the 300 s window | `math.isfinite()` check in both files | `test_request_verifier.py` nan/inf tests |
| M-08 | LOW-MED | DEFERRED | `child-accounts-stackset.yml:2244-2286` | `DefaultHostManagementConfigurationCustomRole` has `iam:CreateRole/AttachRolePolicy/PassRole` on `*` | CFN-trusted input only; needs its own scoping/boundary pass | residual risk below |
| P-06 | LOW | FIXED | `child-accounts-stackset.yml` both cross-account roles | Unconditional `lambda.amazonaws.com` trust statement | Removed; only the `aws:PrincipalArn`-conditioned automation statement remains | `check_iac_policy.py` trust-statement assertion |
| X-01 (coordinator) | MEDIUM | MITIGATED | `management-account-stack.yml:1124,1138` | SCP bypass tag uses request-wide `aws:TagKeys`; a tag on any resource in `RunInstances` satisfies it | AWS does not allow a parameterised per-resource condition key in an SCP; documented in template + `docs/architecture.md`; compensating detector (`run_instances.py`) reads the per-resource `tagSpecificationSet` and still raises High | code + docs review; residual risk below |
| X-02 (missed by team) | HIGH | FIXED | `messenger/email_alerts.py`, `messenger/channels/slack.py` | Resource-controlled values (names, tags, user agents, PagerDuty URLs) interpolated unescaped into SES HTML and Slack mrkdwn → HTML/phishing/mass-mention injection | New `messenger/sanitize.py`; every public message builder now escapes all string arguments (HTML for SES, mrkdwn for Slack), plus tag/attachment helpers | `test_sanitize.py` (10 tests); live import of both builders verified with stubs |
| QA-01 | MEDIUM | FIXED | `.github/workflows/ci.yml` | gosec pinned at v2.22.9 (blind to G101/G204, crashes on Go ≥1.27) | Pinned v2.30.0; the 9 true false positives carry rule-scoped `#nosec … -- reason` | gosec v2.30.0 → 0 issues |
| QA-02 | MEDIUM | DEFERRED | GitHub branch settings | `main` unprotected, no required checks | repo-admin action, not a code change | residual risk below |
| QA-03 | MEDIUM | FIXED | `slack_interactivity/tests/` | Authorizer and handler HMAC had no tests | Added verifier tests (deny/expiry/nan/inf/allow-prefilter) | 6 tests pass |
| QA-04 | MEDIUM | PARTIAL | `process_events/tests/` | `main.py` still cannot be imported without AWS credentials | Pure logic (`event_account`, `sanitize`) extracted and unit-tested; full handler harness still missing | 15 tests pass |
| QA-05 | MEDIUM | DEFERRED | repo-wide | 1.7 % Go coverage, 0 Python handler tests | incremental; no gate added that could not pass | residual risk below |
| QA-06 | LOW | FIXED | CI + `core/cf/templates/**` | No IaC/container gate | New `iac` job (cfn-lint 1.59.0, exit on errors) + `check_iac_policy.py` in the Python job | cfn-lint 0 errors; policy script passes |
| QA-07 | LOW | FIXED | CI | Race detector not run | `go test -race -count=1 ./...` in CI | passes locally |
| QA-08 | LOW | DEFERRED | `scripts/check_supply_chain_policy.py` | Only the event-bus gate has negative tests | residual risk below |
| QA-09 | LOW | DEFERRED | `.github/dependabot.yml` | No `docker` ecosystem entry | digest-pinned images are not refreshed automatically | residual risk below |
| QA-10 | INFO | DEFERRED | requirements locks | Local test env ≠ Lambda env (`pkg_resources` missing) | documentation/dev-requirements task | residual risk below |

## Residual risk

1. **M-01 capability impact (deliberate).** Removing `iam:CreateRole/CreatePolicy*/AttachRolePolicy/PassRole/
   CreateInstanceProfile/AddRoleToInstanceProfile` from `CrossAccountRole` and its boundary also removes the
   ability of `AUTO_ATTACH_MISSING_POLICIES`, `AUTO_ATTACH_IAM_ROLE_EC2` and
   `ENABLE_EC2_INSTANCE_CONFIGURATOR` to create/attach IAM policy on EC2 instance roles. Those paths will now
   fail with `AccessDenied` (they raise after retrying). A dedicated, narrowly-scoped role for the
   instance-configurator (with `iam:PermissionsBoundary` required on `CreateRole` and `PassRole` limited to
   `${ProjectName}-managed-ec2-ssm-role`) is the follow-up; the coordinator should decide whether to gate the
   feature off in the release notes.
2. **M-02 `sfn-executor` remains organization-invokable.** CloudFormation cannot express `aws:PrincipalArn`
   on `AWS::Lambda::Permission` and rejects wildcard principals, and the child-account triggerer roles cannot
   be enumerated in one resource policy. Mitigated by strict `KwArgs` allowlisting, name/JSON/size validation
   and the state-machine ARN prefix check. Full fix requires a per-account permission (custom resource) or an
   invoke-through-SQS design.
3. **SEC-03/SEC-10 secret ARNs stay wildcard** (`secret:*`, `secret:/…`). Secret names are user-configurable
   (`SlackBotConfigSecretName`, engineer-facing configs), so a prefix can silently break rotation/deploy
   (O-10). `sts:AssumeRole` is scoped.
4. **SEC-05.** Any member of the Slack workspace who can see an alert can still trigger `DELETE`/`REMEDIATE`
   and the account-wide S3 public-access-block action for in-scope child accounts. Needs a product decision
   (admin allowlist / approval step); actor + action are logged.
5. **SEC-06.** The central event bus still trusts `Principal: "*"` within `PrincipalOrgID`; forged-event
   *consequences* are now bounded by M-03 validation. Moving to per-account forwarding-role principals needs a
   staged StackSet rollout (`check_event_bus_policy.py` pins the current contract).
6. **X-01 SCP bypass tag.** `aws:TagKeys` is request-wide in EC2 `RunInstances`; CloudFormation cannot build a
   per-resource condition key from the parameter. The existing bypass *detector* inspects only the instance
   (IMDSv2), network-interface (public IP) and volume (encryption) tag specifications, so a bypass supplied on
   a different resource type still raises a High finding. Removing the tag exception entirely (principal-based
   exceptions instead) is the durable fix.
7. **M-04/M-05/M-08.** `s3:GetObject` on `*` in the child-account role, org-wide read of the layer-ARN
   secret, and the SSM default-host-management custom role's IAM writes were not changed — each needs a
   per-handler audit or a StackSet staging window.
8. **M-06.** `view_submission` (tagging modal through API Gateway) is still unreachable because `actions` is
   required for every payload type. Functional, not exploitable; fix should branch on `payload["type"]`.
9. **SC-18.** The Slack/Batch VPC has no flow log (log-delivery bucket + role is an ops/cost decision).
10. **QA-02/04/05/08/09/10.** No branch protection (repo-admin), no full `process_events` import harness, low
    coverage, no negative tests for the supply-chain gate, no Dependabot `docker` ecosystem, local test env
    drift. None of these are exploitable, but they are the remaining verification gaps.
11. **SC-28 gitleaks history hit** is a false positive (`notifications=suppressed` tag key). No history
    rewrite performed and no credential rotation needed.
