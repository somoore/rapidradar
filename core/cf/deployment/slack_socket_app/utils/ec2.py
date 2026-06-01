"""Module for handling AWS EC2 Resources Tagging, Remediation and Deletion"""
from utils.logger import LOGGER

class EC2:
    """EC2 Class used to handle EC2 Resources actions cross-account"""
    def __init__(self, active_session, region):
        self.region = region
        self.active_session = active_session
        self.client = self.active_session.client(service_name='ec2', region_name=self.region)

    def add_tags_to_ec2_resource(self, resource: list, tags: list) -> bool:
        """Tag EC2 Resource with specified tags"""
        try:
            self.client.create_tags(
                Resources=[resource],
                Tags=tags
            )
            LOGGER.info("Successfully added following tags to Resource %s: %s", resource, tags)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False

    def release_eip(self, allocation_id) -> bool:
        """Release Elastic IP using allocation ID"""
        try:
            self.client.release_address(AllocationId=allocation_id)
            LOGGER.info("Successfully released Elastic IP %s", allocation_id)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False

    def delete_security_group_rule(self, group_id, ingress_rule_id):
        """Delete Security Group Rule using ingress rule ID"""
        try:
            self.client.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[ingress_rule_id])
            LOGGER.info("Successfully revoked Security Group Rule %s", ingress_rule_id)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False

    def make_public_ami_private(self, ami_id):
        """Remediate particular Public AMI by making it private"""
        try:
            self.client.modify_image_attribute(
                ImageId=ami_id,
                LaunchPermission={
                    'Remove': [{
                        'Group': 'all',
                    }]
                }
            )
            LOGGER.info("Successfully made Public AMI %s private", ami_id)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False

    def make_public_snapshot_private(self, snapshot_id):
        """Remediate particular public EBS Snapshot by making it private"""
        try:
            self.client.modify_snapshot_attribute(
                Attribute='createVolumePermission',
                CreateVolumePermission={
                    'Remove': [{
                        'Group': 'all',
                    }]
                },
                GroupNames=['all',],
                OperationType='remove',
                SnapshotId=snapshot_id
            )
            LOGGER.info("Successfully made Public EBS Snapshot %s private", snapshot_id)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False
