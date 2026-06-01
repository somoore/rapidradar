import logging
import time
from os import getenv
import requests
import botocore
from botocore.client import Config

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class S3:
    def __init__(self, active_session, region):
        self.region = region
        self.active_session = active_session
        self.client = self.active_session.client(service_name='s3', region_name=self.region)

    def found_suppression_tag(self, bucket_name, alert_suppression_tag_key, alert_suppression_tag_value):
        found_suppression_tag = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_bucket_tagging(Bucket=bucket_name)['TagSet']
                if isinstance(response, list):
                    for s3_tag in response:
                        if s3_tag['Key'] == alert_suppression_tag_key and s3_tag['Value'] == alert_suppression_tag_value:
                            found_suppression_tag = True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'NoSuchTagSet':
                    LOGGER.info("No Tags Found")
                    return False
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False
        return found_suppression_tag

    def found_s3_public_objects(self, bucket_name):
        found_public_objects = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                objects_list = self.client.list_objects(Bucket=bucket_name)
                if 'Contents' in objects_list:
                    for s3_object in objects_list['Contents']:
                        config = Config(signature_version=botocore.UNSIGNED)
                        object_url = self.active_session.client(service_name='s3', region_name=self.region, config=config).generate_presigned_url('get_object', Params={'Bucket': bucket_name, 'Key': s3_object['Key']})
                        resp = requests.get(object_url, timeout=10)
                        if resp.status_code == 200:
                            found_public_objects = True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False
        return found_public_objects

    def is_bucket_policy_public(self, bucket_name):
        public_bucket_policy = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                public_bucket_policy = self.client.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']['IsPublic']
                return public_bucket_policy
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    LOGGER.info("No Bucket Policy Found")
                    return False
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False
        return public_bucket_policy

    def is_bucket_acls_public(self, bucket_name):
        is_public_bucket = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_bucket_acl(Bucket=bucket_name)['Grants']
                if isinstance(response, list):
                    for acl in response:
                        if 'URI' in acl['Grantee']:
                            if acl['Grantee']['URI'] in ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                                is_public_bucket = True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False
        return is_public_bucket

    def is_bucket_encryption_enabled(self, bucket_name):
        is_bucket_encrypted = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_bucket_encryption(Bucket=bucket_name)['ServerSideEncryptionConfiguration']['Rules']
                if type(response) is list:
                    for rule in response:
                        if 'SSEAlgorithm' in rule['ApplyServerSideEncryptionByDefault']:
                            is_bucket_encrypted = True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    LOGGER.info("The server side encryption configuration was not found")
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return is_bucket_encrypted

class S3Control:
    def __init__(self, active_session):
        self.client = active_session.client(service_name='s3control')

    def enable_account_block_public_access(self, account_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.put_public_access_block(
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    },
                    AccountId=account_id
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
