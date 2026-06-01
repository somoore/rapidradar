import boto3
import time
from os import getenv
import json
from utils.logger import LOGGER

PROJECT_NAME = getenv('PROJECT_NAME')
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3

class AssumeRole:
    def __init__(self, role_arn):
        self.role_arn = role_arn

    def assume_role(self, region):
        sts = boto3.client('sts', region_name=region)
        response = {}
        try:
            response = sts.assume_role(RoleArn=self.role_arn, RoleSessionName=PROJECT_NAME)
        except sts.exceptions.ClientError as error:
            LOGGER.error("Cross-account access denied: %s", str(error))
            raise error
        session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])
        return session

class DecodeMessage:
    def __init__(self, active_session, encoded_message):
        self.client = active_session.client('sts')
        self.decoded_message = self.__decode_authorization_message(encoded_message)

    def __decode_authorization_message(self, message: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                decoded_message=json.loads((self.client.decode_authorization_message(EncodedMessage=message))['DecodedMessage'])
                return decoded_message
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
