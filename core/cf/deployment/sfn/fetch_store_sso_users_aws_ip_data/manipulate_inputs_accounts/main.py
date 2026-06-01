from os import getenv
import copy
import boto3

SSM_PARAMETER_NAME = getenv('SSM_PARAMETER_NAME')

def lambda_handler(event, context):
    payload = []
    aws_accounts = get_parameter_value(SSM_PARAMETER_NAME)
    for account in aws_accounts:
        events_copy = copy.deepcopy(event)
        events_copy['AccountId'] = account
        payload.append(events_copy)
    return payload

def get_parameter_value(parameter_name: str) -> list:
    ssm = boto3.client('ssm')
    parameter_value = ''
    try:
        parameter_value = ssm.get_parameter(
            Name=parameter_name
        )['Parameter']['Value']
        return parameter_value.split(',')
    except Exception as error:
        raise error
