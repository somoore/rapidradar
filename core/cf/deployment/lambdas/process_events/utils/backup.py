import logging
import time
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class Backup:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='backup', region_name=self.region)

    def get_backup_plan_tags(self, backup_plan_arn):
        retry_attempts = 0
        delay = DELAY_SECONDS
        plan_tags = {}
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                plan_tags = self.client.list_tags(ResourceArn=backup_plan_arn)['Tags']
                return plan_tags
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'ResourceNotFoundException':
                    LOGGER.info("Backup plan %s was not found", backup_plan_arn)
                    return plan_tags
                if error.response['Error']['Code'] in ['ServiceUnavailableException', 'ThrottlingException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return plan_tags

    def tag_backup_plan(self, backup_plan_arn, tags):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.tag_resource(
                    ResourceArn=backup_plan_arn,
                    Tags=tags
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'ResourceNotFoundException':
                    LOGGER.info("Backup plan %s was not found", backup_plan_arn)
                    return True
                if error.response['Error']['Code'] in ['ServiceUnavailableException', 'ThrottlingException'] and retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return False
