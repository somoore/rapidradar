from os import getenv
import logging
import re
import uuid
import json
import datetime
from dateutil.parser import parse
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROJECT_NAME = getenv('PROJECT_NAME')
CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
UNUSED_RESOURCES_DETECTION_BYPASS_TAG_KEY = getenv('UNUSED_RESOURCES_DETECTION_BYPASS_TAG_KEY')

def __assume_role(region, arn):
    """
    Assumes Role to get into Child Accounts to get details for a specific event
    Args:
        arn (str): IAM Role ARN
    Returns:
        session
    """
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=arn, RoleSessionName=PROJECT_NAME)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def get_secret_value(name: str) -> str:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=name)
        return json.loads(response["SecretString"])
    except Exception as error:
        logger.error(str(error))
    return ''

def scan_dynamodb(dynamodb_table):
    dynamodb = boto3.client('dynamodb')
    response = ""
    try:
        response = dynamodb.scan(TableName=dynamodb_table)
    except dynamodb.exceptions.ClientError as error:
        logger.error(error.response['Error']['Message'])
    return response

def update_instance_metadata(table_name, account_id, region, instance_id, created_by, created_at, stopped_at, step, notified_at):
    dynamodb = boto3.client('dynamodb')
    try:
        dynamodb.put_item(
            TableName=table_name,
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
    except Exception as error:
        logger.error(str(error))
        return False
    return True

def cleanup_dynamodb(table_name, account_id, resource_type, resource_id):
    dynamodb = boto3.client('dynamodb')
    try:
        dynamodb.delete_item(
            TableName=table_name,
            Key={
                'account_id': { 'S': account_id },
                f'{resource_type}': { 'S': resource_id }
            }
        )
    except Exception as error:
        logger.error(f"{str(error)}")
        return False
    return True

def is_instance_older_than_5_days(account_id, region, instance_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        skip_resource = False
        reservations = ec2.describe_instances(InstanceIds=[instance_id])['Reservations']
        if len(reservations) > 0:
            instance = reservations[0]['Instances'][0]
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    if tag['Key'] == UNUSED_RESOURCES_DETECTION_BYPASS_TAG_KEY:
                        skip_resource = True
            if 'State' in instance and instance['State']['Name'] == 'stopped':
                last_stopped_at = get_last_stopped_at_timestamp(instance['StateTransitionReason'])
                difference = datetime.datetime.now(datetime.timezone.utc) - last_stopped_at
                hour_diff = int(difference.total_seconds() / 3600)
                if hour_diff >= 120:
                    if not skip_resource:
                        return True, 'OLD'
                    return False, 'SKIP'
            elif 'State' in instance and instance['State']['Name'] == 'terminated':
                return False, 'InvalidInstanceID.NotFound'
        else:
            return False, 'InvalidInstanceID.NotFound'
    except ec2.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            logger.info("Instance %s does not exist.", instance_id)
        else:
            logger.error(str(error))
        return False, error.response["Error"]["Code"]
    return False, 'INUSE'

def get_last_stopped_at_timestamp(timestamp_str):
    last_stopped_at = ''
    re_match = re.search(
        "([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3})",
        timestamp_str)
    if re_match is not None:
        last_stopped_at = parse(re_match.group(0))
    return last_stopped_at.astimezone(datetime.timezone.utc)

def add_deletion_tag(account_id, region, instance_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{
                'Key': 'Pending Deletion',
                'Value': 'true'
            }]
        )
    except ec2.exceptions.ClientError as error:
        logger.error(str(error))
        return False
    return True

def remove_deletion_tag(account_id, region, instance_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        ec2.delete_tags(
            Resources=[instance_id],
            Tags=[{
                'Key': 'Pending Deletion',
                'Value': 'true'
            }]
        )
    except ec2.exceptions.ClientError as error:
        logger.error(str(error))
        return False
    return True

def create_instance_image(account_id, region, instance_id, user):
    ami_id = ''
    name_tag = 'null'
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        if 'Tags' in instance and len(instance['Tags']) > 0:
            for tag in instance['Tags']:
                if tag['Key'] == 'Name':
                    name_tag = tag['Value']
        ami_id = ec2.create_image(
            InstanceId=instance_id,
            Name=str(uuid.uuid4()),
            TagSpecifications=[
                {
                    'ResourceType': 'image',
                    'Tags': [
                        {'Key': 'Name', 'Value': name_tag},
                        {'Key': 'Owner', 'Value': user},
                        {'Key': 'Environment', 'Value': 'prod'},
                        {'Key': 'Team', 'Value': 'security'},
                        {'Key': 'DeployedBy', 'Value': 'threatOps'},
                        {'Key': 'DeployMethod', 'Value': 'aws-console'}
                    ]
                },
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': name_tag},
                        {'Key': 'Owner', 'Value': user},
                        {'Key': 'Environment', 'Value': 'prod'},
                        {'Key': 'Team', 'Value': 'security'},
                        {'Key': 'DeployedBy', 'Value': 'threatOps'},
                        {'Key': 'DeployMethod', 'Value': 'aws-console'}
                    ]
                }
            ]
        )['ImageId']
    except ec2.exceptions.ClientError as error:
        logger.error(str(error))
        return ami_id
    return ami_id

def terminate_instance(account_id, region, instance_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        ec2.terminate_instances(
            InstanceIds=[instance_id]
        )
    except ec2.exceptions.ClientError as error:
        logger.error(str(error))
        return False
    return True

def get_cst_cdt_datetime(timestamp: datetime.datetime):
    cst_offset = datetime.timedelta(hours=-6)  # CST is UTC-6
    cdt_offset = datetime.timedelta(hours=-5)  # CDT is UTC-5
    is_dst = bool(timestamp.dst())
    timezone_abbreviation = ''
    if is_dst:
        cst_cdt_time = timestamp + cdt_offset
        timezone_abbreviation = 'CDT'
    else:
        cst_cdt_time = timestamp + cst_offset
        timezone_abbreviation = 'CST'
    return cst_cdt_time.strftime(f'%b %d, %Y %I:%M %p {timezone_abbreviation}')

def extract_timezone_abbreviation(datetime_str):
    pattern = r'([A-Z]{3})$'
    match = re.search(pattern, datetime_str)
    if match:
        return match.group(1)
    return ''

def is_unused_security_group(account_id, region, group_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        skip_resource = False
        security_groups_details = ec2.describe_security_groups(GroupIds=[group_id])
        security_group = security_groups_details['SecurityGroups'][0]
        if 'Tags' in security_group:
            for tag in security_group['Tags']:
                if tag['Key'] == UNUSED_RESOURCES_DETECTION_BYPASS_TAG_KEY:
                    skip_resource = True
        result = ec2.describe_network_interfaces(Filters=[{'Name': 'group-id','Values': [group_id]}])['NetworkInterfaces']
        if len(result) == 0 and not skip_resource:
            return True
    except ec2.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidGroup.NotFound']:
            logger.info("Security Group %s not Found", group_id)
        else:
            logger.error(str(error))
        return False
    return False

def delete_security_group(account_id, region, group_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        ec2.delete_security_group(GroupId=group_id)
    except ec2.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidGroup.NotFound']:
            print("Security Group %s not Found", group_id)
            return False, 'InvalidGroup.NotFound'
        elif error.response['Error']['Code'] in ['DependencyViolation']:
            print("Group Dependency")
            return False, 'DependencyViolation'
        else:
            print(str(error))
            return False, 'OTHER'
    return True, 'DELETED'

def is_unused_ebs_volume(account_id, region, volume_id):
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2 = active_session.client(service_name='ec2',region_name=region)
    try:
        skip_resource = False
        volume_detail = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes']
        if len(volume_detail) > 0:
            if 'Tags' in volume_detail[0]:
                for tag in volume_detail[0]['Tags']:
                    if tag['Key'] == UNUSED_RESOURCES_DETECTION_BYPASS_TAG_KEY:
                        skip_resource = True
            if volume_detail[0]['State'] == 'available' and not skip_resource:
                return True
    except ec2.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidVolume.NotFound']:
            logger.info("Volume %s not Found", volume_id)
        else:
            logger.error(str(error))
        return False
    return False
