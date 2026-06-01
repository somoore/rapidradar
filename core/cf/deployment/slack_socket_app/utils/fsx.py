"""Module for handling AWS FSX FileSystem Tagging"""
from utils.logger import LOGGER

class FSX:
    """FSX Class used to tag FileSystems cross-account"""
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='fsx', region_name=self.region)

    def tag_filesystem(self, account_id, resource, tags):
        """Tag FSX FileSystem with specified tags"""
        try:
            self.client.tag_resource(
                ResourceARN=f"arn:aws:fsx:{self.region}:{account_id}:file-system/{resource}",
                Tags=tags
            )
            LOGGER.info("Successfully added following tags to FSX FileSystem %s: %s", resource, tags)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False
