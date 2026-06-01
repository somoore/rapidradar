"""Module for handling AWS RDS Resources Tagging and Remediation"""
from utils.logger import LOGGER

class RDS:
    """RDS Class used to handle RDS Resources actions cross-account"""
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='rds', region_name=self.region)

    def add_tags_to_rds(self, account_id, resource: str, tags: list) -> bool:
        """Tag RDS Resource with specified tags"""
        try:
            self.client.add_tags_to_resource(
                ResourceName=f"arn:aws:rds:{self.region}:{account_id}:{resource}",
                Tags=tags
            )
            LOGGER.info("Successfully added following tags to RDS %s: %s", resource, tags)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False

    def make_public_db_snapshot_private(self, snapshot_id, is_cluster):
        """Remediate particular public DB snapshot by making it private"""
        try:
            method = getattr(self.client, 'modify_db_cluster_snapshot_attribute') if is_cluster else getattr(self.client, 'modify_db_snapshot_attribute')
            snapshot_id_field = 'DBClusterSnapshotIdentifier' if is_cluster else 'DBSnapshotIdentifier'
            kwargs = {
                snapshot_id_field: snapshot_id,
                'AttributeName': 'restore',
                'ValuesToRemove': [ 'all' ]
            }
            method(**kwargs)
            LOGGER.info("Successfully made Public RDS DB Snapshot %s private", snapshot_id)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
            return False
