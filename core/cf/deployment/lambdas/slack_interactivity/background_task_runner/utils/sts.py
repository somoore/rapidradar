from os import getenv
import boto3
from utils.logger import LOGGER

PROJECT_NAME = getenv('PROJECT_NAME')

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
