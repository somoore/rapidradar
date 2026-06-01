import json
import logging
import datetime
import time
from os import getenv
import boto3

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class GetData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def get(self):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.scan(TableName=self.table_name)
                if response['Count'] > 0:
                    return response['Items']
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return []

    def get_by_id(self, first_attribute_name, first_attribute_value, second_attribute_name, second_attribute_value):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    Select='ALL_ATTRIBUTES',
                    ConsistentRead=True,
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': first_attribute_value,
                        },
                        ':v2': {
                            'S': second_attribute_value
                        }
                    },
                    KeyConditionExpression=f'{first_attribute_name} = :v1 AND {second_attribute_name} = :v2'
                )
                if response['Count'] > 0:
                    return response['Items']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return []

    def found_suppression_tag(self, account_id, attribute_name, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    Select='SPECIFIC_ATTRIBUTES',
                    ConsistentRead=True,
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': account_id,
                        },
                        ':v2': {
                            'S': resource_id
                        }
                    },
                    KeyConditionExpression=f'account_id = :v1 AND {attribute_name} = :v2',
                    ProjectionExpression='notifications_suppressed'
                )
                if response['Count'] > 0:
                    return json.loads(response['Items'][0]['notifications_suppressed']['S'])
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class DeleteData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def delete(self, first_attribute_name, first_attribute_value, second_attribute_name, second_attribute_value):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.delete_item(
                    TableName=self.table_name,
                    Key={
                        f'{first_attribute_name}': { 'S': first_attribute_value },
                        f'{second_attribute_name}': { 'S': second_attribute_value }
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class SecurityGroupsData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id: str, region: str, security_group_id: str, ports: list, is_attached: bool, found_suppression_tag: bool, pagerduty_incident_id=None, pagerduty_dedup_keys=None) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 'security_group_id': security_group_id, 'ports': ports, 'is_attached': is_attached, 'found_suppression_tag': found_suppression_tag}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                if ports:
                    table_items = {
                        'account_id': {'S': account_id},
                        'region': {'S': region},
                        'security_group_id': {'S': security_group_id},
                        'port': {'SS': ports},
                        'attached': {'S': str(is_attached).lower()},
                        'open_to': {'S': '0.0.0.0/0'},
                        'notifications_suppressed': {'S': str(found_suppression_tag).lower()},
                        'last_checked': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'}
                    }
                    if pagerduty_incident_id is not None and pagerduty_incident_id:
                        table_items['pagerduty_incident_id'] = {}
                        table_items['pagerduty_incident_id']['SS'] = pagerduty_incident_id
                    elif pagerduty_dedup_keys is not None and pagerduty_dedup_keys:
                        table_items['pagerduty_dedup_keys'] = {}
                        table_items['pagerduty_dedup_keys']['SS'] = pagerduty_dedup_keys
                    self.client.put_item(
                        TableName=self.table_name,
                        Item=table_items
                    )
                    return True
                LOGGER.info("No opened ports found for Security Group %s. Skipping...", security_group_id)
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def query_by_group_id(self, group_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    Select='SPECIFIC_ATTRIBUTES',
                    IndexName='SecurityGroupIndex',
                    ExpressionAttributeNames={
                        '#region': 'region'
                    },
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': group_id,
                        }
                    },
                    KeyConditionExpression='security_group_id = :v1',
                    ProjectionExpression='account_id, #region, port'
                )
                if response['Count'] > 0:
                    return response['Items'][0]['account_id']['S'], response['Items'][0]['region']['S'], response['Items'][0]['port']['SS']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return None, None, None

class RemediatedResourcesData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id, region, resource_id, resource_type):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 'resource_id': resource_id, 'resource_type': resource_type}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'resource_id': {'S': resource_id},
                        'account_id': {'S': account_id},
                        'region': {'S': region},
                        'resource_type': {'S': resource_type},
                        'remediated_at': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class ActiveResourcesData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id: str, account_name: str, region: str, deploy_method: str, team: str, created_by: str, resource_id: str, instance_type: str, resource_type: str, state: str, public_ip:str, created_at: str, launch_time: str, hourly_cost: str, daily_cost: str, monthly_cost: str, cost_type: str, platform: str, is_ssm_managed: str, is_imdsv2_enabled: str, all_tags: list) -> bool:
        unique_id = f"{account_id}_{region}_{resource_type}_{resource_id}"
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'account_name': account_name, 'region': region, 'deploy_method': deploy_method, 'team': team, 'created_by': created_by, 'resource_id': resource_id, 'instance_type': instance_type, 'resource_type': resource_type, 'state': state, 'public_ip': public_ip, 'created_at': created_at, 'launch_time': launch_time, 'hourly_cost': hourly_cost, 'daily_cost': daily_cost, 'monthly_cost': monthly_cost, 'cost_type': cost_type, 'platform': platform, 'is_ssm_managed': is_ssm_managed, 'is_imdsv2_enabled': is_imdsv2_enabled, 'all_tags': all_tags}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'identifier': {'S': unique_id},
                        'account_id': {'S': account_id},
                        'account_name': {'S': account_name},
                        'region': {'S': region},
                        'deploy_method': {'S': deploy_method},
                        'team': {'S': team},
                        'created_by': {'S': created_by},
                        'resource_id': {'S': resource_id},
                        'instance_type': {'S': instance_type},
                        'resource_type': {'S': resource_type},
                        'public_ip': {'S': public_ip},
                        'created_at': {'S': created_at},
                        'launch_time': {'S': launch_time},
                        'current_status': {'S': state},
                        'hourly_cost': {'S': hourly_cost},
                        'daily_cost': {'S': daily_cost},
                        'monthly_cost': {'S': monthly_cost},
                        'cost_type': {'S': cost_type},
                        'platform': {'S': platform},
                        'ssm_managed': {'S': is_ssm_managed},
                        'imdsv2_enabled': {'S': is_imdsv2_enabled},
                        'all_tags': {'SS': all_tags}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def delete(self, unique_id) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.delete_item(
                    TableName=self.table_name,
                    Key={'identifier': { 'S': unique_id }}
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def record_exists(self, account_id, region, resource_type, resource_id):
        unique_id = f"{account_id}_{region}_{resource_type}_{resource_id}"
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    Select='SPECIFIC_ATTRIBUTES',
                    ConsistentRead=True,
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': unique_id,
                        }
                    },
                    KeyConditionExpression='identifier = :v1',
                    ProjectionExpression='account_name, deploy_method, team, created_by, created_at, all_tags, instance_type, platform, hourly_cost, daily_cost, monthly_cost'
                )
                if response['Count'] > 0:
                    item = response['Items'][0]
                    return item['account_name']['S'], item['deploy_method']['S'], item['team']['S'], item['created_by']['S'], item['created_at']['S'], item['all_tags']['SS'], item['instance_type']['S'], item['platform']['S'], item['hourly_cost']['S'], item['daily_cost']['S'], item['monthly_cost']['S']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return None, None, None, None, None, None, None, None, None, None, None

    def get_data_for_resource_type(self, account_id, region, resource_type) -> list:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    IndexName='AccountRegionIndex',
                    ExpressionAttributeNames={
                        '#region': 'region'
                    },
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': account_id,
                        },
                        ':v2': {
                            'S': region
                        },
                        ':v3': {
                            'S': resource_type
                        }
                    },
                    KeyConditionExpression='account_id = :v1 AND #region = :v2',
                    FilterExpression='resource_type = :v3'
                )
                if response['Count'] > 0:
                    return response['Items']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return []

class DeletedResourcesData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id: str, account_name: str, region: str, deleted_by: str, resource_id: str, resource_type: str, deleted_at: str, all_tags: list) -> bool:
        unique_id = f"{account_id}_{region}_{resource_type}_{resource_id}"
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'account_name': account_name, 'region': region, 'deleted_by': deleted_by, 'resource_id': resource_id, 'resource_type': resource_type, 'deleted_at': deleted_at, 'all_tags': all_tags}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                if unique_id and deleted_at:
                    self.client.put_item(
                        TableName=self.table_name,
                        Item={
                            'identifier': {'S': unique_id},
                            'account_id': {'S': account_id},
                            'account_name': {'S': account_name},
                            'region': {'S': region},
                            'deleted_by': {'S': deleted_by},
                            'resource_id': {'S': resource_id},
                            'resource_type': {'S': resource_type},
                            'deleted_at': {'S': deleted_at},
                            'all_tags': {'SS': all_tags}
                        }
                    )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class IAMUsersData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id: str, region: str, iam_user: str, is_programmatic_access_enabled: bool, is_console_access_enabled: bool, found_suppression_tag: bool, pagerduty_incident_id=None, pagerduty_dedup_keys=None):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 'iam_user': iam_user}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                table_items = {
                    'account_id': {'S': account_id},
                    'region': {'S': region},
                    'iam_user': {'S': iam_user},
                    'is_programmatic_access_enabled': {'S': str(is_programmatic_access_enabled).lower()},
                    'is_console_access_enabled': {'S': str(is_console_access_enabled).lower()},
                    'notifications_suppressed': {'S': str(found_suppression_tag).lower()},
                    'last_checked': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'}
                }
                if pagerduty_incident_id is not None and pagerduty_incident_id:
                    table_items['pagerduty_incident_id'] = {}
                    table_items['pagerduty_incident_id']['SS'] = pagerduty_incident_id
                elif pagerduty_dedup_keys is not None and pagerduty_dedup_keys:
                    table_items['pagerduty_dedup_keys'] = {}
                    table_items['pagerduty_dedup_keys']['SS'] = pagerduty_dedup_keys
                self.client.put_item(
                    TableName=self.table_name,
                    Item=table_items
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class IAMKeyPairAccessTrackerData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id, account_name, iam_user, access_key_id, status, created_by, create_date, last_used_date, key_activity, expiry_reminders, tags):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'account_name': account_name, 'iam_user': iam_user, 'access_key_id': access_key_id, 'status': status, 'created_by': created_by, 'create_date': create_date, 'last_used_date': last_used_date, 'key_activity': key_activity, 'expiry_reminders': expiry_reminders, 'tags': tags}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'account_id': {'S': account_id},
                        'account_name': {'S': account_name},
                        'iam_user': {'S': iam_user},
                        'access_key_id': {'S': access_key_id},
                        'status': {'S': status},
                        'created_by': {'S': created_by},
                        'create_date': {'S': create_date},
                        'last_used_date': {'S': last_used_date},
                        'key_activity': {'SS': key_activity},
                        'expiry_reminders': {'SS': expiry_reminders},
                        'iam_user_tags': {'SS': tags},
                        'last_checked': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def get_data_by_account_user(self, user: str, account_id: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    Select='ALL_ATTRIBUTES',
                    IndexName='AccountUserIndex',
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': user,
                        },
                        ':v2': {
                            'S': account_id
                        }
                    },
                    KeyConditionExpression='iam_user = :v1 AND account_id = :v2'
                )
                if response['Count'] > 0:
                    return response['Items']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return []

class S3BucketsData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id: str, region: str, s3_bucket_name: str, is_encryption_enabled: bool, is_public_bucket: bool, found_public_objects: bool, found_suppression_tag: bool, pagerduty_incident_id=None, pagerduty_dedup_keys=None):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 's3_bucket_name': s3_bucket_name}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                table_items = {
                    'account_id': {'S': account_id},
                    'region': {'S': region},
                    's3_bucket_name': {'S': s3_bucket_name},
                    'is_encryption_enabled': {'S': str(is_encryption_enabled).lower()},
                    'is_public_bucket': {'S': str(is_public_bucket).lower()},
                    'found_public_objects': {'S': str(found_public_objects).lower()},
                    'notifications_suppressed': {'S': str(found_suppression_tag).lower()},
                    'last_checked': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'}
                }
                if pagerduty_incident_id:
                    table_items['pagerduty_incident_id'] = {}
                    table_items['pagerduty_incident_id']['SS'] = pagerduty_incident_id
                elif pagerduty_dedup_keys:
                    table_items['pagerduty_dedup_keys'] = {}
                    table_items['pagerduty_dedup_keys']['SS'] = pagerduty_dedup_keys
                self.client.put_item(
                    TableName=self.table_name,
                    Item=table_items
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class IAMRootUsersLoginData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id, event_id, user, ip_address, attempts, status, first_attempt_at, last_attempt_at):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'event_id': event_id, 'account_id': account_id, 'user': user, 'ip_address': ip_address, 'status': status, 'first_attempt_at': first_attempt_at, 'last_attempt_at': last_attempt_at}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'event_id': {'S': event_id},
                        'account_id': {'S': account_id},
                        'user': {'S': user},
                        'ip_address': {'S': ip_address},
                        'attempts': {'N': attempts},
                        'status': {'S': status},
                        'first_attempt_at': {'S': first_attempt_at},
                        'last_attempt_at': {'S': last_attempt_at}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def query_by_account_ip_user(self, account_id, ip_address, user):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    IndexName='AccountIPIndex',
                    ExpressionAttributeNames={
                        '#user': 'user'
                    },
                    ExpressionAttributeValues={
                        ':account_id': {
                            'S': account_id,
                        },
                        ':ip_address': {
                            'S': ip_address
                        },
                        ':user': {
                            'S': user
                        }
                    },
                    KeyConditionExpression='account_id = :account_id AND ip_address = :ip_address',
                    FilterExpression='#user = :user'
                )
                if response['Count'] > 0:
                    return response['Items']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return []

class UsersIPData:
    def __init__(self, table_name, track_tailscale_ips):
        self.table_name = table_name
        self.track_tailscale_ips = track_tailscale_ips
        self.client = boto3.client('dynamodb')

    def store_ip_data(self, user: str, sso_user_id: str, login_date: str, ip_address: str, tailscale_user_ips: list) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'user': user, 'sso_user_id': sso_user_id, 'login_date': login_date, 'ip_address': ip_address}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                db_items = {
                    'user': {'S': user},
                    'sso_user_id': {'S': sso_user_id},
                    'updated_at': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'},
                    'last_login_date': {'S': login_date},
                    'known_aws_ip': {'S': ip_address}
                }
                if self.track_tailscale_ips:
                    db_items['tailscale_user_ips'] = {}
                    db_items['tailscale_user_ips']['SS'] = tailscale_user_ips
                self.client.put_item(
                    TableName=self.table_name,
                    Item=db_items
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def store_ip_history(self, user: str, sso_user_id: str, ip_addresses: list) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'user': user, 'sso_user_id': sso_user_id, 'ip_addresses': ip_addresses}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'user': {'S': user},
                        'sso_user_id': {'S': sso_user_id},
                        'updated_at': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'},
                        'ip_addresses': {'SS': ip_addresses}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def get_ip_data_by_user(self, user: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    IndexName='UserIndex',
                    ExpressionAttributeNames={
                        '#user': 'user'
                    },
                    ExpressionAttributeValues={
                        ':user': {
                            'S': user,
                        }
                    },
                    KeyConditionExpression='#user = :user',
                )
                if response['Count'] > 0:
                    return response['Items']
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return []

    def delete(self, user_id: str) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.delete_item(
                    TableName=self.table_name,
                    Key={'sso_user_id': { 'S': user_id }}
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class SSMDocAssocFailureData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id: str, account_name: str, region: str, ssm_document_name: str, association_id: str, instance_id: str, attempts: int, first_failed_at: str, last_failed_at: str, all_tags: list, pagerduty_incident_id=None, pagerduty_dedup_keys=None):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'account_name': account_name, 'region': region, 'ssm_document_name': ssm_document_name, 'association_id': association_id, 'instance_id': instance_id, 'attempts': attempts, 'first_failed_at': first_failed_at, 'last_failed_at': last_failed_at, 'all_tags': all_tags}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                table_items = {
                    'account_id': {'S': account_id},
                    'account_name': {'S': account_name},
                    'region': {'S': region},
                    'ssm_document_name': {'S': ssm_document_name},
                    'association_id': {'S': association_id},
                    'instance_id': {'S': instance_id},
                    'attempts': {'N': attempts},
                    'first_failed_at': {'S': first_failed_at},
                    'last_failed_at': {'S': last_failed_at},
                    'all_tags': {'SS': all_tags},
                    'last_checked': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'}
                }
                if pagerduty_incident_id:
                    table_items['pagerduty_incident_id'] = {}
                    table_items['pagerduty_incident_id']['SS'] = pagerduty_incident_id
                elif pagerduty_dedup_keys:
                    table_items['pagerduty_dedup_keys'] = {}
                    table_items['pagerduty_dedup_keys']['SS'] = pagerduty_dedup_keys
                self.client.put_item(
                    TableName=self.table_name,
                    Item=table_items
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def query_by_instance_id(self, instance_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    Select='ALL_ATTRIBUTES',
                    IndexName='EC2InstanceIndex',
                    ExpressionAttributeValues={
                        ':v1': {
                            'S': instance_id,
                        }
                    },
                    KeyConditionExpression='instance_id = :v1'
                )
                if response['Count'] > 0:
                    return response['Items'][0]
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return {}

class UnusedEC2InstancesData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id, region, instance_id, created_by, created_at, stopped_at, step, notified_at):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 'instance_id': instance_id, 'created_by': created_by, 'created_at': created_at, 'stopped_at': stopped_at, 'step': step, 'notified_at': notified_at}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'account_id': {'S': account_id},
                        'region': {'S': region},
                        'instance_id': {'S': instance_id},
                        'created_by': {'S': created_by},
                        'created_at': {'S': created_at},
                        'stopped_at': {'S': stopped_at},
                        'step': {'S': step},
                        'notified_at': {'S': notified_at}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class UnusedSecurityGroupsData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id, region, group_id, group_name, is_launch_wizard, created_by, created_at):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 'group_id': group_id, 'group_name': group_name, 'created_by': created_by, 'created_at': created_at}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'account_id': {'S': account_id},
                        'region': {'S': region},
                        'security_group_id': {'S': group_id},
                        'security_group_name': {'S': group_name},
                        'is_launch_wizard': {'S': json.dumps(is_launch_wizard)},
                        'created_by': {'S': created_by},
                        'created_at': {'S': created_at}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class UnusedEBSVolumesData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store(self, account_id, region, volume_id, created_by, created_at):
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'account_id': account_id, 'region': region, 'volume_id': volume_id, 'created_by': created_by, 'created_at': created_at}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'account_id': {'S': account_id},
                        'region': {'S': region},
                        'volume_id': {'S': volume_id},
                        'created_by': {'S': created_by},
                        'created_at': {'S': created_at}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

class UserCostReportsData:
    def __init__(self, table_name):
        self.table_name = table_name
        self.client = boto3.client('dynamodb')

    def store_daily_data(self, user: str, date: str, total_hourly_cost: str, total_daily_cost: str, total_weekly_cost: str, total_monthly_cost: str) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'user': user, 'date': date, 'total_hourly_cost': total_hourly_cost, 'total_daily_cost': total_daily_cost, 'total_weekly_cost': total_weekly_cost, 'total_monthly_cost': total_monthly_cost}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'user': {'S': user},
                        'date': {'S': date},
                        'total_hourly_cost': {'S': total_hourly_cost},
                        'total_daily_cost': {'S': total_daily_cost},
                        'total_weekly_cost': {'S': total_weekly_cost},
                        'total_monthly_cost': {'S': total_monthly_cost}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def store_weekly_data(self, user: str, date: str, total_weekly_cost: str, percentage_status: str) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'user': user, 'date': date, 'total_weekly_cost': total_weekly_cost, 'percentage_status': percentage_status}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'user': {'S': user},
                        'date': {'S': date},
                        'total_weekly_cost': {'S': total_weekly_cost},
                        'difference': {'S': percentage_status}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def store_monthly_data(self, user: str, date: str, total_monthly_cost: str, percentage_status: str) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        LOGGER.info("Storing data to %s table: %s", self.table_name, json.dumps({'user': user, 'date': date, 'total_monthly_cost': total_monthly_cost, 'percentage_status': percentage_status}))
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_item(
                    TableName=self.table_name,
                    Item={
                        'user': {'S': user},
                        'date': {'S': date},
                        'total_monthly_cost': {'S': total_monthly_cost},
                        'difference': {'S': percentage_status}
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False

    def get_latest_data_by_user(self, user: str, last_week_start_date: datetime.date, two_weeks_before_start_date: datetime.date):
        final_record = {}
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.query(
                    TableName=self.table_name,
                    ConsistentRead=True,
                    ExpressionAttributeNames={
                        '#user': 'user'
                    },
                    ExpressionAttributeValues={
                        ':user': {
                            'S': user,
                        }
                    },
                    KeyConditionExpression='#user = :user',
                )
                if response['Count'] > 0:
                    for data in response['Items']:
                        report_date = datetime.datetime.strptime(data['date']['S'], '%b %d, %Y').date()
                        if two_weeks_before_start_date < report_date <= last_week_start_date:
                            final_record = data
                    return final_record
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] not in ['ValidationException', 'ResourceNotFoundException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return final_record
