"""Module for handling AWS S3 account-level Remediation"""
from utils.logger import LOGGER

class S3Control:
    """S3Control Class used to handle S3 actions cross-account"""
    def __init__(self, active_session):
        self.client = active_session.client(service_name='s3control')

    def enable_account_block_public_access(self, account_id):
        """Remediate disabled S3 Account Public Access Block Config by enabling it again"""
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
            LOGGER.info("Successfully enabled S3 Account Public Access Block for Account %s", account_id)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
            return False
