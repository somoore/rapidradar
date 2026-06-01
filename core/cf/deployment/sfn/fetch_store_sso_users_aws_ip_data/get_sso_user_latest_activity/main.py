from os import getenv
import logging
import re
import datetime
import json
import copy
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROJECT_NAME = getenv('PROJECT_NAME')
CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')

def lambda_handler(event, context):
    logger.info('FETCHING DATA FOR SSO USER PAYLOAD: %s', event)
    account = event['AccountId']
    region = event['Region']
    ip_regex_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    current_datetime = datetime.datetime.now(datetime.UTC)
    kwargs = {
        'LookupAttributes': [{
            'AttributeKey': 'Username',
            'AttributeValue': event['UserName']
        }],
        'MaxResults': 1,
        'StartTime': current_datetime - datetime.timedelta(days=1),
        'EndTime': current_datetime
    }
    payload = copy.deepcopy(event)
    payload['LastActivity'] = ''
    payload['SourceIpAddress'] = ''
    assume_role_arn = SSO_CROSS_ACCOUNT_ROLE_ARN if account == __get_management_account_id() else f"arn:aws:iam::{account}:role/{CROSS_ACCOUNT_ROLE}-{region}"
    active_session = __assume_role(region, assume_role_arn)
    cloudtrail = active_session.client(service_name='cloudtrail', region_name=region)
    response = cloudtrail.lookup_events(**kwargs)
    if len(response['Events']) > 0:
        cloudtrail_event = json.loads(response['Events'][0]['CloudTrailEvent'])
        result = re.search(ip_regex_pattern, cloudtrail_event['sourceIPAddress'])
        if result:
            last_activity = response['Events'][0]['EventTime'].strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(response['Events'][0]['EventTime'], datetime.datetime) else response['Events'][0]['EventTime']
            payload['LastActivity'] = last_activity
            payload['SourceIpAddress'] = result.group(0)
    return payload

def __assume_role(region, arn):
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=arn, RoleSessionName=PROJECT_NAME)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def __get_management_account_id():
    match = re.search(r'([0-9]{12})', SSO_CROSS_ACCOUNT_ROLE_ARN)
    return match.group(0)
