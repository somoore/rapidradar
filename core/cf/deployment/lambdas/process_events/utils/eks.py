import logging
import time
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class EKS:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='eks', region_name=self.region)

    def add_tags_to_eks_cluster(self, account_id, resource: str, tags) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.tag_resource(
                    resourceArn=f'arn:aws:eks:{self.region}:{account_id}:cluster/{resource}',
                    tags=tags
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
                break
        return False

    def get_eks_cluster_status(self, cluster_name: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_cluster(name=cluster_name)
                status = response['cluster']['status']
                return status
            except self.client.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == "ResourceNotFoundException":
                    return "DELETED"
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return None

    def get_eks_cluster_launch_time(self, cluster_name: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_cluster(name=cluster_name)['cluster']
                launch_time = response['createdAt'].strftime("%Y-%m-%dT%H:%M:%S")
                return launch_time
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

    def get_eks_cluster_tags(self, cluster_name: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_cluster(name=cluster_name)
                tags = [ f"{k}: {v}" for k,v in response['cluster']['tags'].items() ]
                return tags
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return []
