from os import getenv
import uuid
import logging
import datetime
from time import sleep
import json
import base64
import hashlib
import http.client
import hmac
import boto3
import botocore
from messenger import Messenger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_decrypted_value(name: str) -> str:
    ssm = boto3.client('ssm')
    decrypted_value = ''
    try:
        decrypted_value = ssm.get_parameter(
            Name=name,
            WithDecryption=True
        )['Parameter']['Value']
    except Exception as error:
        logger.error(str(error))
    return decrypted_value

def get_secret_value(name: str) -> str:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=name)
        return json.loads(response["SecretString"])
    except Exception as error:
        logger.error(str(error))
    return ''

PROJECT_NAME = getenv('PROJECT_NAME')
DEPLOYMENT_TARGETS = getenv('DEPLOYMENT_TARGETS').replace(' ','').split(',')
EXCLUDE_ACCOUNTS = str(getenv('EXCLUDE_ACCOUNTS'))
EXCLUDE_ACCOUNTS = EXCLUDE_ACCOUNTS.replace(' ', '').split(',') if EXCLUDE_ACCOUNTS else []
ACTIVE_REGIONS = getenv('ACTIVE_REGIONS').replace(' ', '').split(',')
SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
NOTIFICATION_CONFIGS_SECRET_NAME = getenv('NOTIFICATION_CONFIGS_SECRET_NAME')
NOTIFICATION_CONFIGS = get_secret_value(NOTIFICATION_CONFIGS_SECRET_NAME)
NOTIFICATION_APP = NOTIFICATION_CONFIGS.get('NOTIFICATION_APP', '')
WEBHOOK_URLS = ""
if "APP_CONFIG" in NOTIFICATION_CONFIGS:
    WEBHOOK_URLS = NOTIFICATION_CONFIGS.get("APP_CONFIG")
else:
    WEBHOOK_URLS = NOTIFICATION_CONFIGS.get("WEBHOOK_URL")
WEBHOOK_URLS = WEBHOOK_URLS.replace(' ', '').split(',')
SEND_LOGS_TO_AZURE = json.loads(getenv('SEND_LOGS_TO_AZURE'))
CUSTOMER_ID = getenv('CUSTOMER_ID', '')
SHARED_KEY = get_decrypted_value(getenv('SHARED_KEY_SSM')) if getenv('SHARED_KEY_SSM') else ''
LOG_TYPE = getenv('AZURE_LOG_TYPE', '')
SSO_USER_ID_NAMES = get_secret_value(getenv('SSO_USER_ID_NAMES_SECRET'))
ORG_THROTTLE_PERIOD = 0.2

def lambda_handler(event, context):
    if 'requestParameters' in event['detail']:
        request_params = event['detail']['requestParameters']
        if 'identityStoreId' in request_params and 'userId' in request_params:
            sso_user_id = request_params['userId']
            username = SSO_USER_ID_NAMES[sso_user_id]
            process_id = str(uuid.uuid4())
            org_accounts = __get_active_organization_accounts()
            org_account_regions = []
            messenger = Messenger(NOTIFICATION_APP, WEBHOOK_URLS)
            payload = {}

            for account in org_accounts:
                for region in ACTIVE_REGIONS:
                    items = {
                        "accountId": account,
                        "region": region,
                        "processId": process_id,
                        "userId": sso_user_id,
                        "userName": username,
                        "eventName": event['detail']['eventName']
                    }
                    org_account_regions.append(items)
            payload['orgAccountRegion'] = org_account_regions
            if not messenger.send_alert(username, 'disabled' if event['detail']['eventName'] == 'DisableUser' else 'deleted'):
                logger.error("Could not send alert to Notification Channel")
            iam_user, account_id, region = get_account_details(event['detail'])
            json_data = {
                "AccountID": account_id,
                "AccountName": get_account_name(account_id),
                "Region": region,
                "User": iam_user,
                "Event": f"User {iam_user} has {'disabled' if event['detail']['eventName'] == 'DisableUser' else 'deleted'} AWS User {username} from AWS IAM Identity Centre"
            }
            if SEND_LOGS_TO_AZURE:
                if not send_data_to_azure_log_analytics(CUSTOMER_ID, SHARED_KEY, LOG_TYPE, json_data):
                    logger.error("Data %s could not be sent to Azure Log Analytics", json_data)
            return payload

def __assume_role(region, arn):
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=arn, RoleSessionName=PROJECT_NAME)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session
def __get_children(client, child_type, ou_id, exclude_accounts):
    children = []
    retry_attempts, max_retry_attempts, initial_delay = 0, 5, 5
    delay = initial_delay
    base_kwargs, next_token = {'ParentId': ou_id, 'ChildType': child_type}, ''
    while next_token is not None:
        kwargs = base_kwargs.copy()
        if next_token != '':
            kwargs.update({'NextToken': next_token})
        sleep(ORG_THROTTLE_PERIOD)
        while retry_attempts < max_retry_attempts:
            try:
                response = client.list_children(**kwargs)
                for child in response['Children']:
                    if child_type == 'ACCOUNT':
                        if child['Id'] not in exclude_accounts:
                            children.append(child['Id'])
                    elif child_type == 'ORGANIZATIONAL_UNIT':
                        children.extend(__get_children(client, 'ACCOUNT', child['Id'], exclude_accounts))
                        children.extend(__get_children(client, 'ORGANIZATIONAL_UNIT', child['Id'], exclude_accounts))
                next_token = response['NextToken'] if 'NextToken' in response else None
                break
            except client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'TooManyRequestsException' and retry_attempts < max_retry_attempts:
                    retry_attempts += 1
                    print(f"TooManyRequestsException occurred. Retrying in {delay} seconds...")
                    sleep(delay)
                    delay *= 2
                    continue
                print(str(error))
                break
    return children
def __get_active_organization_accounts():
    active_accounts = []
    active_accounts_details = []
    active_session = __assume_role("us-east-1", SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN)
    organizations = active_session.client('organizations', region_name='us-east-1')
    describe_method=getattr(organizations, 'describe_account')
    try:
        for target in DEPLOYMENT_TARGETS:
            active_accounts.extend(__get_children(organizations, 'ACCOUNT', target, EXCLUDE_ACCOUNTS))
            active_accounts.extend(__get_children(organizations, 'ORGANIZATIONAL_UNIT', target, EXCLUDE_ACCOUNTS))
        for account in active_accounts:
            response = describe_method(AccountId=account)
            if 'Account' in response:
                if response["Account"]["Status"] == "ACTIVE":
                    active_accounts_details.append(response["Account"]["Id"])
            sleep(ORG_THROTTLE_PERIOD)
    except Exception as error:
        logger.error(str(error))
    return active_accounts
def get_account_details(event):
    iam_user = 'Unknown'
    account_id = 'Unknown'
    region = 'Unknown'
    if 'userIdentity' in event:
        if 'principalId' in event['userIdentity']:
            iam_user = event['userIdentity']['principalId'].split(':')[-1]
        if 'accountId' in event['userIdentity']:
            account_id = event['userIdentity']['accountId']
    if 'awsRegion' in event:
        region = event['awsRegion']
    return iam_user, account_id, region
def get_account_name(account_id):
    retry_attempts = 0
    max_retry_attempts = 5
    initial_delay = 5
    delay = initial_delay
    account_name = ''
    active_session = __assume_role('us-east-1', f"{SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN}")
    organizations = active_session.client(service_name='organizations', region_name='us-east-1')
    while retry_attempts < max_retry_attempts:
        try:
            account_details = organizations.describe_account(AccountId=account_id)
            account_name = account_details['Account']['Name']
            break
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'TooManyRequestsException' and retry_attempts < max_retry_attempts:
                retry_attempts += 1
                logger.info("TooManyRequestsException occurred. Retrying in %s seconds...", delay)
                sleep(delay)
                delay *= 2
                continue
            account_name = "Unknown"
            logger.error(str(error))
        except Exception as error:
            account_name = "Unknown"
            logger.error(str(error))
    return account_name
def __build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    try:
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = f"SharedKey {customer_id}:{encoded_hash}"
    except Exception as error:
        logger.error(str(error))
    return authorization
def send_data_to_azure_log_analytics(customer_id, shared_key, log_type, json_data):
    data = json.dumps(json_data)
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    current_datetime = datetime.datetime.now(datetime.UTC).strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(data)
    retries = 3
    delay = 1
    signature = __build_signature(customer_id, shared_key, current_datetime, content_length, method, content_type, resource)
    uri = customer_id + '.ods.opinsights.azure.com'
    status = False
    try:
        conn = http.client.HTTPSConnection(uri, timeout=10)
        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': current_datetime
        }
        while retries > 0:
            try:
                conn.request(method, resource+'?api-version=2016-04-01', data, headers)
                response = conn.getresponse()
                if response.status >= 200 and response.status <= 299:
                    logger.info("Data sent successfully")
                    status = True
                else:
                    logger.error("Response Code: %s", response.status)
                    status = False
                conn.close()
                break
            except http.client.HTTPException as http_error:
                logger.error("HTTPException occurred: %s", str(http_error))
                status = False
                break
            except Exception as error:
                logger.error(str(error))
                retries -= 1
                if retries > 0:
                    logger.info("Retrying in %s seconds...", delay)
                    sleep(delay)
                    delay *= 2
                else:
                    status = False
    except Exception as error:
        logger.error(str(error))
        status = False
    return status
