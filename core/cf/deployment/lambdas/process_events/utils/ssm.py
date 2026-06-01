import logging
import time
from os import getenv
import boto3

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class SSM:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='ssm', region_name=self.region)

    def is_instance_ssm_managed(self, instance_id: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_instance_information(
                    Filters=[{
                        'Key': 'InstanceIds',
                        'Values': [instance_id]
                    }]
                )
                instance_info = response['InstanceInformationList']
                return len(instance_info) > 0
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False

    def share_ssm_document_w_all_accounts(self, region: str, document_name: str, accounts: list):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            ssm = boto3.client(service_name='ssm', region_name=region)
            try:
                ssm.modify_document_permission(
                    Name=document_name,
                    PermissionType='Share',
                    AccountIdsToAdd=accounts
                )
                return True
            except ssm.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False

    def get_instance_association_status(self, instance_id, association_id):
        association_status = None
        next_token = ''
        base_kwargs = { 'InstanceId': instance_id, 'MaxResults': 50 }
        while next_token is not None:
            kwargs = base_kwargs.copy()
            if next_token != '':
                kwargs.update({'NextToken': next_token})
            response = self.client.describe_instance_associations_status(**kwargs)
            for association in response['InstanceAssociationStatusInfos']:
                if association['AssociationId'] == association_id:
                    association_status = association['Status']
                    break
            next_token = response['NextToken'] if 'NextToken' in response else None
        return association_status

    def get_decrypted_value(self, parameter_name: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                decrypted_value = self.client.get_parameter(
                    Name=parameter_name,
                    WithDecryption=True
                )['Parameter']['Value']
                return decrypted_value
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

class Decrypt:
    def __init__(self, name):
        self.decrypted_value = self.__get_decrypted_value(name)

    @staticmethod
    def __get_decrypted_value(name: str) -> str:
        ssm = boto3.client('ssm')
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                decrypted_value = ssm.get_parameter(
                    Name=name,
                    WithDecryption=True
                )['Parameter']['Value']
                return decrypted_value
            except ssm.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return ''
