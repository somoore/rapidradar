from utils.logger import LOGGER

class SecretsManager:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='secretsmanager', region_name=self.region)

    def tag_secret(self, secret_arn, tags):
        try:
            self.client.tag_resource(
                SecretId=secret_arn,
                Tags=tags
            )
            LOGGER.info("Successfully added following tags to SecretsManager Secret %s: %s", secret_arn, tags)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
            return False
