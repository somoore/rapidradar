import copy
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    account_id = event['accountId']
    region = event['region']
    job_id = event['jobId']
    payload = copy.deepcopy(event)

    logger.info("Checking Report Status for Account %s and Region %s", account_id, region)

    job_status = check_job_status(job_id)

    try:
        if job_status in [ 'SUCCEEDED', 'FAILED' ]:
            logger.info("Job is done running. Status: %s", job_status)
            payload['jobCompleted'] = True
            if job_status == 'FAILED':
                raise Exception("Job Failed")
        else:
            payload['jobCompleted'] = False
    except Exception as error:
        raise error
    return payload

def check_job_status(job_id):
    batch = boto3.client('batch')
    status = ''
    try:
        response = batch.describe_jobs(jobs=[job_id])
        status = response['jobs'][0]['status']
    except Exception as error:
        logger.error(str(error))
        raise error
    return status
