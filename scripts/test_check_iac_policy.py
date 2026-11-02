import unittest
from pathlib import Path

from scripts.check_iac_policy import (
    DOCKERFILES,
    ROOT,
    STACKSET,
    TEMPLATES,
    check_alarm_topic_encryption,
    check_cross_account_roles,
    check_dockerfile_user,
    check_lambda_permissions,
    check_queue_policies,
)


class LambdaPermissionTest(unittest.TestCase):
    def test_unscoped_permission_is_rejected(self):
        template = """
Resources:
  Permission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      Principal: lambda.amazonaws.com
"""
        errors = check_lambda_permissions(Path("f.yml"), template)
        self.assertEqual(len(errors), 2)  # SourceAccount + SourceArn

    def test_source_scoped_permission_passes(self):
        template = """
Resources:
  Permission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      Principal: lambda.amazonaws.com
      SourceAccount: !Ref AWS::AccountId
      SourceArn: !GetAtt Function.Arn
"""
        self.assertEqual(check_lambda_permissions(Path("f.yml"), template), [])

    def test_principal_star_requires_organization_scoping(self):
        template = """
Resources:
  Permission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      Principal: "*"
      PrincipalOrgID: !Ref OrganizationId
"""
        self.assertEqual(check_lambda_permissions(Path("f.yml"), template), [])

    def test_principal_star_without_org_scoping_is_rejected(self):
        template = """
Resources:
  Permission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      Principal: "*"
"""
        errors = check_lambda_permissions(Path("f.yml"), template)
        self.assertTrue(any("PrincipalOrgID" in error for error in errors))


ALARM_TOPIC_TEMPLATE = """
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: {key}
  Alarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
      - !Ref Topic
      Dimensions:
      - Name: FunctionName
"""


class AlarmTopicEncryptionTest(unittest.TestCase):
    def test_aws_managed_key_on_alarm_topic_is_rejected(self):
        template = ALARM_TOPIC_TEMPLATE.format(key="alias/aws/sns")
        errors = check_alarm_topic_encryption(Path("f.yml"), template)
        self.assertEqual(len(errors), 1)
        self.assertIn("Topic", errors[0])

    def test_customer_managed_key_on_alarm_topic_passes(self):
        template = ALARM_TOPIC_TEMPLATE.format(key="!GetAtt TopicKey.Arn")
        self.assertEqual(check_alarm_topic_encryption(Path("f.yml"), template), [])

    def test_aws_managed_key_on_topic_without_alarms_passes(self):
        template = """
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
"""
        self.assertEqual(check_alarm_topic_encryption(Path("f.yml"), template), [])


class QueuePolicyTest(unittest.TestCase):
    def test_unconditioned_lambda_queue_grant_is_rejected(self):
        template = """
Resources:
  Policy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      PolicyDocument:
        Statement:
          - Principal:
              Service: lambda.amazonaws.com
"""
        errors = check_queue_policies(Path("f.yml"), template)
        self.assertEqual(len(errors), 2)

    def test_conditioned_lambda_queue_grant_passes(self):
        template = """
Resources:
  Policy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      PolicyDocument:
        Statement:
          - Principal:
              Service: lambda.amazonaws.com
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
              ArnLike:
                aws:SourceArn: !GetAtt Function.Arn
"""
        self.assertEqual(check_queue_policies(Path("f.yml"), template), [])


class CrossAccountRoleTest(unittest.TestCase):
    def test_escalation_action_is_rejected(self):
        template = """
Resources:
  CrossAccountRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Effect: "Allow"
          Condition:
            ArnLike:
              aws:PrincipalArn: arn:aws:iam::111122223333:role/x-*
      Policies:
      - PolicyDocument:
          Statement:
          - Action:
            - iam:CreateRole
"""
        errors = check_cross_account_roles(Path("f.yml"), template)
        self.assertTrue(any("iam:CreateRole" in error for error in errors))

    def test_unconditioned_lambda_trust_is_rejected(self):
        template = """
Resources:
  CrossAccountRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Effect: "Allow"
          Principal:
            Service:
            - lambda.amazonaws.com
        - Effect: "Allow"
          Principal:
            AWS:
            - arn:aws:iam::111122223333:root
          Condition:
            ArnLike:
              aws:PrincipalArn: arn:aws:iam::111122223333:role/x-*
"""
        errors = check_cross_account_roles(Path("f.yml"), template)
        self.assertTrue(any("statements" in error for error in errors))


class DockerfileUserTest(unittest.TestCase):
    def test_missing_user_is_rejected(self):
        errors = check_dockerfile_user(Path("Dockerfile"), "FROM python:3.11\nCMD ['x']\n")
        self.assertEqual(len(errors), 1)

    def test_root_user_is_rejected(self):
        errors = check_dockerfile_user(Path("Dockerfile"), "FROM python:3.11\nUSER root\n")
        self.assertEqual(len(errors), 1)

    def test_non_root_user_passes(self):
        errors = check_dockerfile_user(Path("Dockerfile"), "FROM python:3.11\nUSER appuser\n")
        self.assertEqual(errors, [])


class RepositoryStateTest(unittest.TestCase):
    def test_templates_are_compliant(self):
        errors = []
        for path in sorted(TEMPLATES.rglob("*.yml")):
            text = path.read_text()
            errors.extend(check_lambda_permissions(path, text))
            errors.extend(check_queue_policies(path, text))
            errors.extend(check_alarm_topic_encryption(path, text))
            if path == STACKSET:
                errors.extend(check_cross_account_roles(path, text))
        self.assertEqual(errors, [])

    def test_dockerfiles_are_compliant(self):
        errors = []
        for path in DOCKERFILES:
            errors.extend(check_dockerfile_user(path, path.read_text()))
        self.assertEqual(errors, [])

    def test_templates_exist(self):
        self.assertTrue(TEMPLATES.is_dir())
        self.assertTrue(STACKSET.is_file())
        self.assertTrue(Path(ROOT, "core/cf/deployment").is_dir())


if __name__ == "__main__":
    unittest.main()
