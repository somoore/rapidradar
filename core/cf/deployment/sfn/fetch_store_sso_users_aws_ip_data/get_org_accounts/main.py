from os import getenv
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MANAGEMENT_ACCOUNT_ID = getenv('MANAGEMENT_ACCOUNT_ID')
CHILD_ACCOUNTS_STACKSET_NAME = getenv('CHILD_ACCOUNTS_STACKSET_NAME')
SSM_PARAMETER_NAME = getenv('SSM_PARAMETER_NAME')

def lambda_handler(event, context):
    logger.info('PROCESSING NEW EVENT: %s', event)
    active_accounts = []
    try:
        active_accounts = get_child_accounts(CHILD_ACCOUNTS_STACKSET_NAME)
        active_accounts.append(MANAGEMENT_ACCOUNT_ID)
        if not store_accounts(SSM_PARAMETER_NAME, active_accounts):
            logger.error("Could not store accounts to SSM Parameter Store.")
    except Exception as error:
        raise error
    return active_accounts

def get_child_accounts(stackset_name: str):
    account_ids = []
    try:
        cloudformation = boto3.client('cloudformation')
        response = cloudformation.list_stack_instances(
            StackSetName=stackset_name,
            MaxResults=100,
            CallAs='DELEGATED_ADMIN'
        )
        stack_instances = response['Summaries']
        while 'NextToken' in response:
            response = cloudformation.list_stack_instances(
                StackSetName=stackset_name,
                MaxResults=100,
                CallAs='DELEGATED_ADMIN',
                NextToken=response['NextToken']
            )
            stack_instances.extend(response['Summaries'])
        for instance in stack_instances:
            if instance['StackInstanceStatus']['DetailedStatus'] == 'SUCCEEDED':
                account_ids.append(instance['Account'])
    except Exception as error:
        raise error
    return list(set(account_ids))

def store_accounts(parameter_name: str, accounts: list):
    ssm = boto3.client('ssm')
    accounts_str_list = ','.join(accounts)
    try:
        ssm.put_parameter(
            Name=parameter_name,
            Description='SSM Parameter to store Org Accounts',
            Value=accounts_str_list,
            Type='StringList',
            Overwrite=True,
            Tier='Standard'
        )
        return True
    except Exception as error:
        logger.error(str(error))
        return False
