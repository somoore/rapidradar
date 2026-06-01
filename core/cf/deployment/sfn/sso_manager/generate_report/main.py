import logging
import os
import copy
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

JOB_QUEUE = os.getenv('JOB_QUEUE')
JOB_DEFINITION = os.getenv('JOB_DEFINITION')
BUCKET_NAME = os.getenv('ARTIFACTS_BUCKET_NAME')
CROSS_ACCOUNT_ROLE = os.getenv('CROSS_ACCOUNT_ROLE')
SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN = os.getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')

def lambda_handler(event, context):
    process_id = event['processId']
    user_id = event['userId']
    username = event['userName']
    account_id = event['accountId']
    region = event['region']

    payload = copy.deepcopy(event)

    status, job_id = trigger_job(process_id, user_id, username, account_id, region)
    try:
        if not status:
            raise Exception("Could not trigger Batch Job")
        else:
            payload['jobId'] = job_id
    except Exception as error:
        raise error
    return payload

def trigger_job(process_id, user_id, username, account_id, region):
    batch = boto3.client('batch')
    job_id = ''
    try:
        response = batch.submit_job(
            jobName=f'generate-report-{account_id}',
            jobQueue=JOB_QUEUE,
            jobDefinition=JOB_DEFINITION,
            containerOverrides={
                'environment': [
                    { 'name': 'PROCESS_ID', 'value': process_id },
                    { 'name': 'USER_ID', 'value': user_id },
                    { 'name': 'USERNAME', 'value': username },
                    { 'name': 'ACCOUNT_ID', 'value': account_id },
                    { 'name': 'REGION', 'value': region },
                    { 'name': 'CROSS_ACCOUNT_ROLE', 'value': CROSS_ACCOUNT_ROLE },
                    { 'name': 'SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN', 'value': SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN },
                    { 'name': 'BUCKET_NAME', 'value': BUCKET_NAME }
                ]
            }
        )
    except Exception as error:
        logger.error(str(error))
        return False, job_id
    job_id = response['jobId']
    return True, job_id
