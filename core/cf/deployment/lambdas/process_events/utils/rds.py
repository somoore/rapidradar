import logging
import time
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class RDS:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='rds', region_name=self.region)

    def make_public_db_snapshot_private(self, snapshot_id, is_cluster):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                method = getattr(self.client, 'modify_db_cluster_snapshot_attribute') if is_cluster else getattr(self.client, 'modify_db_snapshot_attribute')
                snapshot_id_field = 'DBClusterSnapshotIdentifier' if is_cluster else 'DBSnapshotIdentifier'
                kwargs = {
                    snapshot_id_field: snapshot_id,
                    'AttributeName': 'restore',
                    'ValuesToRemove': [ 'all' ]
                }
                method(**kwargs)
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

    def get_rds_instance_status(self, db_identifier: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_instances(DBInstanceIdentifier=db_identifier)['DBInstances']
                if len(response) > 0:
                    state = response[0]['DBInstanceStatus']
                    return state
                return "deleted"
            except self.client.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == "DBInstanceNotFound":
                    return "deleted"
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return None

    def get_rds_cluster_status(self, db_cluster_identifier: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_clusters(DBClusterIdentifier=db_cluster_identifier)['DBClusters']
                if len(response) > 0:
                    state = response[0]['Status']
                    return state
                return "deleted"
            except self.client.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == "DBClusterNotFoundFault":
                    return "deleted"
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return None

    def __get_db_instance_arn(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_instances(MaxRecords=100)
                for instance in response['DBInstances']:
                    if instance['DBInstanceIdentifier'].startswith(resource_id):
                        return instance['DBInstanceArn']
                return ''
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return ''

    def __get_db_cluster_arn(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_clusters(MaxRecords=100)
                for cluster in response['DBClusters']:
                    if cluster['DBClusterIdentifier'].startswith(resource_id):
                        return cluster['DBClusterArn']
                return ''
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return ''

    def found_keep_alive_tag(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                resource_arn = ''
                if resource_id.startswith('db-'):
                    resource_arn = self.__get_db_instance_arn(resource_id[3:])
                else:
                    resource_arn = self.__get_db_cluster_arn(resource_id[3:])
                response = self.client.list_tags_for_resource(ResourceName=resource_arn)
                for tag in response['TagList']:
                    if tag['Key'] == 'keep-alive' and tag['Value'] == 'true':
                        return True
                return False
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False

    def get_rds_tags(self, account_id, resource_type: str, resource_id: str):
        resource_arn = ''
        if resource_type == 'RDSDBInstance':
            resource_arn = f'arn:aws:rds:{self.region}:{account_id}:db:{resource_id}'
        elif resource_type == 'RDSDBCluster':
            resource_arn = f'arn:aws:rds:{self.region}:{account_id}:cluster:{resource_id}'
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.list_tags_for_resource(ResourceName=resource_arn)
                tags = [ f"{tag['Key']}: {tag['Value']}" for tag in response['TagList']]
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

    def get_rds_instance_launch_time(self, db_identifier: str):
        launch_time = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_instances(DBInstanceIdentifier=db_identifier)['DBInstances'][0]
                if 'InstanceCreateTime' in response:
                    launch_time = response['InstanceCreateTime'].strftime("%Y-%m-%dT%H:%M:%S")
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
        return launch_time

    def get_rds_cluster_launch_time(self, db_cluster_identifier: str):
        launch_time = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_clusters(DBClusterIdentifier=db_cluster_identifier)['DBClusters'][0]
                if 'ClusterCreateTime' in response:
                    launch_time = response['ClusterCreateTime'].strftime("%Y-%m-%dT%H:%M:%S")
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
        return launch_time

    def __get_rds_member_instance_type(self, identifier):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_db_instances(DBInstanceIdentifier=identifier)['DBInstances'][0]
                instance_class = response['DBInstanceClass']
                return instance_class
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

    def get_rds_cost_details(self, resource_type: str, identifier: str):
        instance_class, engine, storage_type = '', '', ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = ''
                if resource_type == 'RDSDBInstance':
                    response = self.client.describe_db_instances(DBInstanceIdentifier=identifier)['DBInstances'][0]
                    instance_class = response['DBInstanceClass']
                else:
                    response = self.client.describe_db_clusters(DBClusterIdentifier=identifier)['DBClusters'][0]
                    if len(response['DBClusterMembers']) > 0:
                        for member in response['DBClusterMembers']:
                            if instance_class:
                                instance_class = instance_class + ',' + self.__get_rds_member_instance_type(member['DBInstanceIdentifier'])
                            else:
                                instance_class = self.__get_rds_member_instance_type(member['DBInstanceIdentifier'])
                    else:
                        if response['EngineMode'] == 'serverless' and 'ServerlessV2ScalingConfiguration' not in response:
                            instance_class = 'db.serverless'
                        else:
                            instance_class = 'db.serverlessv2'
                engine = response['Engine']
                if 'StorageType' in response:
                    storage_type = response['StorageType']
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
        return instance_class, engine, storage_type

    def add_tags_to_rds(self, account_id, resource: str, tags: list) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.add_tags_to_resource(
                    ResourceName=f"arn:aws:rds:{self.region}:{account_id}:{resource}",
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
