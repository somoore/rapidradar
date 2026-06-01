from os import getenv
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACTIVE_REGIONS = getenv('ACTIVE_REGIONS').replace(' ', '').split(',')
SSM_PARAMETER_NAME = getenv('SSM_PARAMETER_NAME')

def lambda_handler(event, context):
    active_org_regions = ACTIVE_REGIONS
    try:
        if not store_regions(SSM_PARAMETER_NAME, active_org_regions):
            logger.error("Could not store regions to SSM Parameter Store.")
    except Exception as error:
        raise error
    return active_org_regions

def store_regions(parameter_name: str, regions: list):
    ssm = boto3.client('ssm')
    regions_str_list = ','.join(regions)
    try:
        ssm.put_parameter(
            Name=parameter_name,
            Description='SSM Parameter to store Org Regions',
            Value=regions_str_list,
            Type='StringList',
            Overwrite=True,
            Tier='Standard'
        )
        return True
    except Exception as error:
        logger.error(str(error))
        return False
