import datetime
import logging
import json
import time
from os import getenv
import boto3

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

IAM_USER_EVENT_SOURCES = [
    'aws.backup',
    'aws.controltower',
    'aws.ec2',
    'aws.eks',
    'aws.elasticfilesystem',
    'aws.elasticloadbalancing',
    'aws.fsx',
    'aws.guardduty',
    'aws.iam',
    'aws.identitystore',
    'aws.organizations',
    'aws.rds',
    'aws.s3',
    'aws.secretsmanager',
    'aws.signin',
    'aws.ssm',
    'capture-existing-resources',
    'detect-unused-resources',
    'aws.sso',
    'aws.sso-directory',
]
IAM_USER_EVENT_DETAIL_TYPES = ['AWS API Call via CloudTrail']


class Events:
    def __init__(self, account_id, region):
        self.account_id = account_id
        self.region = region
        self.client = boto3.client('events')

    def create_security_group_rule_remediation_cron(self, security_group_id, port, protocol, target_arn):
        plus_two_timestamp = datetime.datetime.now() + datetime.timedelta(minutes=2)
        cron_expression = f"{plus_two_timestamp.minute} {plus_two_timestamp.hour} {plus_two_timestamp.day} {plus_two_timestamp.month} ? {plus_two_timestamp.year}"
        event_rule_name = f'remediation-cron-{security_group_id}-{"alltraffic" if port in ["-1", -1] else str(port)}-{"all" if port in ["-1", -1] else protocol}'
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                event_rule = self.client.put_rule(
                    Name=event_rule_name,
                    ScheduleExpression=f'cron({cron_expression})',
                    State='ENABLED',
                    Description=f'Remediation Scheduler for {security_group_id} for port {str(port)}',
                )
                self.client.put_targets(
                    Rule=event_rule['RuleArn'].split('/')[-1],
                    Targets=[{
                        'Id': 'trigger-process-events-lambda',
                        'Arn': target_arn
                    }]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def create_5_min_status_update_rule(self, resource_type: str, resource_id: str, target_arn: str) -> bool:
        cron_expression = "0/5 * ? * * *"
        event_rule_name = f"5-min-cron-{resource_type}_{self.account_id}_{self.region}_{resource_id}"
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.put_rule(
                    Name = event_rule_name,
                    ScheduleExpression=f'cron({cron_expression})',
                    State='ENABLED',
                    Description=f'5 min Cron for {resource_type} {resource_id} in Account={self.account_id} and Region={self.region}'
                )
                self.client.put_targets(
                    Rule=response['RuleArn'].split('/')[-1],
                    Targets=[{
                        'Id': 'InventoryManager',
                        'Arn': target_arn
                    }]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def create_10_min_delete_scp_bypassed_resource_rule(self, resource_id: str, target_arn):
        plus_ten_timestamp = datetime.datetime.now() + datetime.timedelta(minutes=10)
        cron_expression = f"{plus_ten_timestamp.minute} {plus_ten_timestamp.hour} {plus_ten_timestamp.day} {plus_ten_timestamp.month} ? {plus_ten_timestamp.year}"
        event_rule_name = f'ten-min-cron-{self.account_id}_{self.region}_{resource_id}'
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                event_rule = self.client.put_rule(
                    Name=event_rule_name,
                    ScheduleExpression=f'cron({cron_expression})',
                    State='ENABLED',
                    Description=f'Scheduler for {resource_id} for SCP Bypassed resource deletion in Account {self.account_id} and Region {self.region}',
                )
                self.client.put_targets(
                    Rule=event_rule['RuleArn'].split('/')[-1],
                    Targets=[{
                        'Id': 'trigger-process-events-lambda',
                        'Arn': target_arn
                    }]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def create_rules_to_capture_iam_user_events(self, active_session, iam_user, access_key_id, project_name, event_bus_arn):
        events = active_session.client('events', region_name=self.region)
        event_rule_name = f'{project_name}-{iam_user}-{access_key_id}'
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                event_rule = events.put_rule(
                    Name=event_rule_name,
                    EventPattern=json.dumps({
                        "source": IAM_USER_EVENT_SOURCES,
                        "detail-type": IAM_USER_EVENT_DETAIL_TYPES,
                        "detail": {
                            "userIdentity": {
                            "type": ["IAMUser"],
                            "accessKeyId": [access_key_id]
                            }
                        }
                    }),
                    State='ENABLED',
                    Description=f'Event Rule to capture policy-allowed events for Access Key ID {access_key_id} for IAM User {iam_user}',
                )
                events.put_targets(
                    Rule=event_rule['RuleArn'].split('/')[-1],
                    Targets=[{
                        'Id': f'capture-iam-user-events-{self.account_id}',
                        'Arn': event_bus_arn,
                        'RoleArn': f'arn:aws:iam::{self.account_id}:role/{project_name}-child-send-automation-events-{self.region}'
                    }]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def cleanup_rules_to_capture_iam_user_events(self, active_session, iam_user, access_key_id, project_name):
        events = active_session.client('events', region_name=self.region)
        event_rule_name = f'{project_name}-{iam_user}-{access_key_id}'
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                events.remove_targets(
                    Rule=f'{event_rule_name}',
                    Ids=[f'capture-iam-user-events-{self.account_id}']
                )
                events.delete_rule(Name=f'{event_rule_name}')
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def cleanup_security_group_rule_remediation_cron(self, security_group_id, port, protocol):
        event_rule_name = f'remediation-cron-{security_group_id}-{"alltraffic" if port in ["-1", -1] else str(port)}-{"all" if port in ["-1", -1] else protocol}'
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.remove_targets(
                    Rule=event_rule_name,
                    Ids=['trigger-process-events-lambda']
                )
                self.client.delete_rule(Name=event_rule_name)
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def cleanup_5_min_cron_rule(self, resource_type: str, resource_id: str) -> bool:
        event_rule_name = f"5-min-cron-{resource_type}_{self.account_id}_{self.region}_{resource_id}"
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.remove_targets(
                    Rule=event_rule_name,
                    Ids=['InventoryManager']
                )
                self.client.delete_rule(Name=event_rule_name)
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def cleanup_10_min_cron_rule(self, resource_id) -> bool:
        event_rule_name = f"ten-min-cron-{self.account_id}_{self.region}_{resource_id}"
        event_rule_name = event_rule_name[:64]
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.remove_targets(
                    Rule=event_rule_name,
                    Ids=['trigger-process-events-lambda']
                )
                self.client.delete_rule(Name=event_rule_name)
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False
