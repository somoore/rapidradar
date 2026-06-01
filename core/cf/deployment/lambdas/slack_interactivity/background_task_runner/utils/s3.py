from utils.logger import LOGGER

class S3Control:
    def __init__(self, active_session):
        self.client = active_session.client(service_name='s3control')

    def enable_account_block_public_access(self, account_id):
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
