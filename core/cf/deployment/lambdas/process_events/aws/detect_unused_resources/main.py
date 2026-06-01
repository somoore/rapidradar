from utils.dynamodb import (
    UnusedEC2InstancesData,
    UnusedSecurityGroupsData,
    UnusedEBSVolumesData,
    GetData
)
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, unused_ec2_instances_table, unused_security_groups_table, unused_ebs_volumes_table):
    if unused_ec2_instances_table:
        unused_ec2_instances_table_ops = UnusedEC2InstancesData(unused_ec2_instances_table)
        if event['ResourceType'] == 'EC2Instance':
            scan_records = GetData(unused_ec2_instances_table).get_by_id('account_id', helper.account_id, 'instance_id', event['InstanceId'])
            if scan_records:
                if not unused_ec2_instances_table_ops.store(
                    helper.account_id,
                    helper.region,
                    event['InstanceId'],
                    event['CreatedBy'],
                    event['CreatedAt'],
                    event['LastStoppedAt'],
                    scan_records[0]['step']['S'],
                    scan_records[0]['notified_at']['S']):
                    LOGGER.error('Could not add data for Unused EC2 Instances')
            else:
                if not unused_ec2_instances_table_ops.store(
                    helper.account_id,
                    helper.region,
                    event['InstanceId'],
                    event['CreatedBy'],
                    event['CreatedAt'],
                    event['LastStoppedAt'],
                    '0',
                    'None'):
                    LOGGER.error('Could not add data for Unused EC2 Instances')

    if unused_security_groups_table:
        unused_security_groups_table_ops = UnusedSecurityGroupsData(unused_security_groups_table)
        if event['ResourceType'] == 'SecurityGroup':
            scan_records = GetData(unused_security_groups_table).get_by_id('account_id', helper.account_id, 'security_group_id', event['GroupId'])
            if scan_records:
                if not unused_security_groups_table_ops.store(
                    helper.account_id,
                    helper.region,
                    event['GroupId'],
                    event['GroupName'],
                    bool(event['GroupName'].startswith('launch-wizard')),
                    event['CreatedBy'],
                    event['CreatedAt']):
                    LOGGER.error('Could not add data for Unused Security Groups')
            else:
                if not unused_security_groups_table_ops.store(
                    helper.account_id,
                    helper.region,
                    event['GroupId'],
                    event['GroupName'],
                    bool(event['GroupName'].startswith('launch-wizard')),
                    event['CreatedBy'],
                    event['CreatedAt']):
                    LOGGER.error('Could not add data for Unused Security Groups')

    if unused_ebs_volumes_table:
        unused_ebs_volumes_table_ops = UnusedEBSVolumesData(unused_ebs_volumes_table)
        if event['ResourceType'] == 'EBSVolume':
            scan_records = GetData(unused_ebs_volumes_table).get_by_id('account_id', helper.account_id, 'volume_id', event['VolumeId'])
            if scan_records:
                if not unused_ebs_volumes_table_ops.store(
                    helper.account_id,
                    helper.region,
                    event['VolumeId'],
                    event['CreatedBy'],
                    event['CreatedAt']):
                    LOGGER.error('Could not add data for Unused EBS Volumes')
            else:
                if not unused_ebs_volumes_table_ops.store(
                    helper.account_id,
                    helper.region,
                    event['VolumeId'],
                    event['CreatedBy'],
                    event['CreatedAt']):
                    LOGGER.error('Could not add data for Unused EBS Volumes')
