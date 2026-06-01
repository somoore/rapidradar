"""Module for handling AWS EFS FileSystem Tagging"""
from utils.logger import LOGGER

class EFS:
    """EFS Class used to tag FileSystems cross-account"""
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='efs', region_name=self.region)

    def add_tags_to_filesystem(self, resource: str, tags: list) -> bool:
        """Tag EFS FileSystem with specified tags"""
        try:
            self.client.create_tags(
                FileSystemId=resource,
                Tags=tags
            )
            LOGGER.info("Successfully added following tags to EFS FileSystem %s: %s", resource, tags)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False
