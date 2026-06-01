from os import getenv
import logging
from time import sleep
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROJECT_NAME = getenv('PROJECT_NAME')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
CHILD_ACCOUNTS_STACKSET_NAME = getenv('CHILD_ACCOUNTS_STACKSET_NAME')
DEPLOYMENT_TARGETS = getenv('DEPLOYMENT_TARGETS').replace(" ", "").split(",")
EXCLUDE_ACCOUNTS = str(getenv('EXCLUDE_ACCOUNTS'))
EXCLUDE_ACCOUNTS = EXCLUDE_ACCOUNTS.replace(" ", "").split(",") if EXCLUDE_ACCOUNTS else []
CURRENT_ACCOUNT = getenv('CURRENT_ACCOUNT')
MANAGEMENT_ACCOUNT = getenv('MANAGEMENT_ACCOUNT')
ORG_THROTTLE_PERIOD = 0.2
CALL_AS = 'SELF' if CURRENT_ACCOUNT == MANAGEMENT_ACCOUNT else 'DELEGATED_ADMIN'

def lambda_handler(event, context):
    logger.info('PROCESSING NEW EVENT: %s', event)

    payload = event.copy()
    payload['WaitTime'] = 0
    if 'TaskMarker' not in payload:
        payload['TaskMarker'] = 'Initialize'
    try:
        get_child_accounts(CHILD_ACCOUNTS_STACKSET_NAME, payload)
        if payload['TaskMarker'] in ['Initialize', 'WaitforChildStackSetCreation', 'WaitforChildStackSetInstancesCreation']:
            if payload['WaitTime'] != 0:
                wait_time = payload['WaitTime']
                task_marker = payload['TaskMarker']
                logger.info('...WaitTime found while getting accounts from Child StackSet at task marker %s of %s seconds. Exiting Function...', task_marker, wait_time)
                return payload
    except Exception as error:
        raise error
    return payload
def get_child_accounts(stackset_name: str, payload):
    wait_period = 60

    cloudformation = boto3.client('cloudformation')
    try:
        response = cloudformation.list_stack_instances(
            StackSetName=stackset_name,
            MaxResults=100,
            CallAs=CALL_AS
        )
        stack_instances = response['Summaries']
        if not stack_instances:
            payload['TaskMarker'] = 'WaitforChildStackSetInstancesCreation'
            payload['WaitTime'] = wait_period
            return
        while 'NextToken' in response:
            response = cloudformation.list_stack_instances(
                StackSetName=stackset_name,
                MaxResults=100,
                CallAs=CALL_AS,
                NextToken=response['NextToken']
            )
            stack_instances.extend(response['Summaries'])
        stack_instance_accounts = list(set(instance['Account'] for instance in stack_instances))
        org_deployment_accounts = get_active_organization_accounts(DEPLOYMENT_TARGETS, EXCLUDE_ACCOUNTS)
        for instance in stack_instances:
            if instance['StackInstanceStatus']['DetailedStatus'] in ['RUNNING', 'PENDING']:
                payload['TaskMarker'] = 'WaitforChildStackSetInstancesCreation'
                payload['WaitTime'] = wait_period
                return
        for account in org_deployment_accounts:
            if account not in stack_instance_accounts:
                payload['TaskMarker'] = 'WaitforAccountToBeAddedAsChildStackSetInstance'
                payload['WaitTime'] = wait_period
                return
    except cloudformation.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'StackSetNotFoundException':
            payload['TaskMarker'] = 'WaitforChildStackSetCreation'
            payload['WaitTime'] = wait_period
            return
        raise error
    return
def __assume_role(role_arn):
    sts = boto3.client('sts')
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName=PROJECT_NAME)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])
    return session
def get_children(client, child_type, ou_id, exclude_accounts):
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
                        children.extend(get_children(client, 'ACCOUNT', child['Id'], exclude_accounts))
                        children.extend(get_children(client, 'ORGANIZATIONAL_UNIT', child['Id'], exclude_accounts))
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
def get_active_organization_accounts(deployment_targets, exclude_accounts) -> list:
    active_accounts = []
    active_accounts_details = []
    active_session = __assume_role(SSO_CROSS_ACCOUNT_ROLE_ARN)
    organizations = active_session.client('organizations', region_name='us-east-1')
    describe_method=getattr(organizations, 'describe_account')
    try:
        for target in deployment_targets:
            active_accounts.extend(get_children(organizations, 'ACCOUNT', target, exclude_accounts))
            active_accounts.extend(get_children(organizations, 'ORGANIZATIONAL_UNIT', target, exclude_accounts))
        for account in active_accounts:
            response = describe_method(AccountId=account)
            if 'Account' in response:
                if response["Account"]["Status"] == "ACTIVE":
                    active_accounts_details.append(response["Account"]["Id"])
            sleep(ORG_THROTTLE_PERIOD)
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return active_accounts_details
