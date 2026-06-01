import logging
import time
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class EFS:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='efs', region_name=self.region)

    @staticmethod
    def __bytes_to_gb(size_in_bytes):
        gb = size_in_bytes / (1024**3)  # 1 GB = 1024^3 bytes
        return gb

    def get_efs_cost_details(self, efs_id):
        is_multi_az = False
        standard_gb_hours = 0.0
        infa_gb_hours = 0.0
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                efs_details = self.client.describe_file_systems(FileSystemId=efs_id)['FileSystems'][0]
                if 'AvailabilityZoneId' not in efs_details:
                    is_multi_az = True
                standard_gb_hours = self.__bytes_to_gb(efs_details['SizeInBytes']['ValueInStandard']) * 30 * 24
                infa_gb_hours = self.__bytes_to_gb(efs_details['SizeInBytes']['ValueInIA']) * 30 * 24
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return is_multi_az, standard_gb_hours, infa_gb_hours

    def add_tags_to_efs(self, resource: str, tags: list) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.create_tags(
                    FileSystemId=resource,
                    Tags=tags
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

    def get_efs_filesystem_status(self, efs_id: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_file_systems(FileSystemId=efs_id)['FileSystems']
                if len(response) > 0:
                    state = response[0]['LifeCycleState']
                    return state
                return "deleted"
            except self.client.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == "FileSystemNotFound":
                    return "deleted"
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return None

    def get_efs_details(self, efs_id: str):
        tags = []
        launch_time = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_file_systems(FileSystemId=efs_id)
                tags = [ f"{tag['Key']}: {tag['Value']}" for tag in response['FileSystems'][0]['Tags'] ]
                launch_time = response['FileSystems'][0]['CreationTime'].strftime("%Y-%m-%dT%H:%M:%S")
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return tags, launch_time
