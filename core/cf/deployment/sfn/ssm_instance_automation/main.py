from os import getenv
import logging
import json
import utils

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROJECT_NAME = getenv('PROJECT_NAME')
CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
AUTO_ATTACH_IAM_ROLE_EC2 = json.loads(getenv('AUTO_ATTACH_IAM_ROLE_EC2'))
EC2_SSM_IAM_ROLE_NAME = getenv('EC2_SSM_IAM_ROLE_NAME')
AUTO_ATTACH_MISSING_POLICIES = json.loads(getenv('AUTO_ATTACH_MISSING_POLICIES'))
AUTO_CREATE_VPC_ENDPOINTS = json.loads(getenv('AUTO_CREATE_VPC_ENDPOINTS'))
VPC_ENDPOINTS = getenv('VPC_ENDPOINTS').replace(' ', '').split(',')
MANAGED_SG_NAME = f'{PROJECT_NAME}-vpc-endpoint-sg'
MANAGED_EC2_IAM_ROLE_NAME = f'{PROJECT_NAME}-managed-ec2-ssm-role'
AUTO_MANAGE_ROLES = False if EC2_SSM_IAM_ROLE_NAME else True

def lambda_handler(event, context):
    """
    Lambda Handler which is invoked when Event Bus receives event from CloudTrail API
    Args:
        event, context
    """
    logger.info('PROCESSING NEW EVENT: %s', event)
    payload = event.copy()

    payload['WaitTime'] = 0
    if 'TaskMarker' not in payload:
        payload['TaskMarker'] = 'Initialize'

    detail = ''
    if 'detail' in event and 'account' in event and event['detail-type'] == 'EC2 Instance State-change Notification':
        detail = event['detail']
        account_id, region = utils.get_account_details(event)
        instance_id = detail['instance-id']
        logger.info("Checking if this is a Cloud9 Instance...")
        if utils.is_cloud9_instance(account_id, region, instance_id):
            logger.info("This is a Cloud9 Instance.")
            logger.info("Skipping all EC2 Instance Management Steps...")
        else:
            logger.info("Not a Cloud9 Instance.")

            if AUTO_CREATE_VPC_ENDPOINTS:
                if payload['TaskMarker'] in ['Initialize', 'WaitForEndpointAvailableState']:
                    logger.info("Checking if required VPC Endpoints exist...")
                    utils.vpc_endpoint_manager(account_id, region, MANAGED_SG_NAME, VPC_ENDPOINTS, instance_id, payload)
                    if payload['WaitTime'] != 0:
                        wait_time = payload['WaitTime']
                        task_marker = payload['TaskMarker']
                        logger.info('...WaitTime found during VPC Endpoint Checks at task marker %s of %s seconds. Exiting Function...', task_marker, wait_time)
                        return payload
            else:
                logger.info("Auto-creation of VPC Endpoints is disabled. Skipping...")

            if AUTO_ATTACH_IAM_ROLE_EC2:
                if payload['TaskMarker'] in ['Initialize', 'WaitForProperInstanceState']:
                    logger.info("Managing Instance IAM Role for Instance(s) %s", instance_id)
                    utils.instance_role_manager(instance_id, account_id, region, MANAGED_EC2_IAM_ROLE_NAME, payload, AUTO_MANAGE_ROLES, EC2_SSM_IAM_ROLE_NAME, AUTO_ATTACH_MISSING_POLICIES)
                    if payload['WaitTime'] != 0:
                        wait_time = payload['WaitTime']
                        task_marker = payload['TaskMarker']
                        logger.info('...WaitTime found during IAM role modification at task marker %s of %s seconds. Exiting Function...', task_marker, wait_time)
                        return payload
    return payload
