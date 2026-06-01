import logging
import time
import json
from os import getenv
import boto3

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class SecretsManager:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='secretsmanager', region_name=self.region)

    def get_secrets_tags(self, secret_arn):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_secret(SecretId=secret_arn)['Tags']
                return response
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return ''

    def tag_secret(self, secret_arn, tags):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.tag_resource(
                    SecretId=secret_arn,
                    Tags=tags
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False

class Store:
    def __init__(self, name, description, value):
        self.name = name
        self.description = description
        self.value = json.dumps(value)

    def store_value(self):
        secretsmanager = boto3.client('secretsmanager')
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                secretsmanager.put_secret_value(
                    SecretId=self.name,
                    SecretString=self.value
                )
                return True
            except secretsmanager.exceptions.ResourceNotFoundException:
                secretsmanager.create_secret(
                    Name=self.name,
                    Description=self.description,
                    SecretString=self.value
                )
                return True
            except secretsmanager.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False

class GetConfig:
    def __init__(self, secret_id):
        self.client = boto3.client('secretsmanager')
        self.values = self.__get_secret(secret_id)

    def __get_secret(self, secret_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_secret_value(SecretId=secret_id)
                return json.loads(response["SecretString"])
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error
