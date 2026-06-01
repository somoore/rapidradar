import logging
import time
import json
from os import getenv
import boto3

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class StepFunction:
    def __init__(self):
        self.client = boto3.client('stepfunctions')

    def trigger(self, state_machine_arn: str, trigger_type: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                execution_arn = self.client.start_execution(
                    stateMachineArn=state_machine_arn,
                    input=json.dumps({'TriggerType': trigger_type})
                )['executionArn']
                return execution_arn.split(":")[-1]
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return ''
