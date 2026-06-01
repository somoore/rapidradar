from utils.eks import EKS
from utils.efs import EFS
from utils.events import Events
from utils.pricing import Pricing
from utils.cloudtrail import CloudTrail
from utils.dynamodb import (
    ActiveResourcesData,
    DeletedResourcesData
)
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(event, active_resources_table, deleted_resources_table):
    event_trigger_name = event['resources'][0].split('/')[-1]
    resource_details = event_trigger_name.replace("5-min-cron-", "").split("_")
    resource_type, account_id, region, resource_id_from_event = resource_details[0], resource_details[1], resource_details[2], resource_details[3]
    detail = { 'account': account_id, 'region': region }
    helper = AWSHelper(detail)
    active_resources_table_ops = ActiveResourcesData(active_resources_table)

    active_resources = active_resources_table_ops.get_data_for_resource_type(account_id, region, resource_type)
    for resource in active_resources:
        active_session = helper.get_active_session()
        eks_utils = EKS(active_session, helper.region)
        efs_utils = EFS(active_session, helper.region)
        events_utils = Events(helper.account_id, helper.region)
        pricing_utils = Pricing(active_session, helper.region)
        cloudtrail_utils = CloudTrail(active_session, helper.region)

        account_name, resource_id, deploy_method, team, created_by, created_at, platform, hourly_cost, daily_cost, monthly_cost = resource['account_name']['S'], resource['resource_id']['S'], resource['deploy_method']['S'], resource['team']['S'], resource['created_by']['S'], resource['created_at']['S'], resource['platform']['S'], resource['hourly_cost']['S'], resource['daily_cost']['S'], resource['monthly_cost']['S']
        current_state = 'Unknown'
        cloudtrail_delete_event_name = ''
        all_tags, launch_time, public_ip, cost_type, is_instance_ssm_managed, is_imdsv2_enabled = [], '', '', '', '', ''

        if resource_id.startswith(resource_id_from_event):
            if resource_type == 'EKSCluster':
                current_state = (eks_utils.get_eks_cluster_status(resource_id)).lower()
                cloudtrail_delete_event_name = 'DeleteCluster'
            elif resource_type == 'EFSFileSystem':
                current_state = efs_utils.get_efs_filesystem_status(resource_id)
                cloudtrail_delete_event_name = 'DeleteFileSystem'

            if current_state in ['terminated', 'deleted']:
                deleted_by, deleted_at = cloudtrail_utils.get_resource_details(cloudtrail_delete_event_name, resource_id)
                account_name, deploy_method, team, created_by, created_at, all_tags, instance_type, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(account_id, region, resource_type, resource_id)
                if all_tags is not None:
                    if not DeletedResourcesData(deleted_resources_table).store(account_id, account_name, region, deleted_by, resource_id, resource_type, deleted_at, all_tags):
                        LOGGER.error("Could not store data for deleted resource %s", resource_id)
                    else:
                        LOGGER.info("Added resource details to Deleted Resource Table. Removing from Active Resource Table...")
                        unique_id = f"{account_id}_{region}_{resource_type}_{resource_id}"
                        if not active_resources_table_ops.delete(unique_id):
                            LOGGER.error("Could not delete record for %s from active resources table", resource_id)
                        else:
                            LOGGER.info("Deleted record for %s from active resource table", resource_id)
                        if not events_utils.cleanup_5_min_cron_rule(resource_type, resource_id):
                            LOGGER.error("Could not delete 5 min rule for %s %s", resource_type, resource_id)
                else:
                    LOGGER.info("...Skipping. No Record existed for %s", resource_id)
            elif current_state in ['creating', 'updating', 'deleting', 'pending']:
                all_tags = []
                if resource_type == 'EKSCluster':
                    all_tags = eks_utils.get_eks_cluster_tags(resource_id)
                    launch_time = eks_utils.get_eks_cluster_launch_time(resource_id)
                    hourly_cost, daily_cost, monthly_cost = pricing_utils.get_cluster_cost()
                elif resource_type == 'EFSFileSystem':
                    all_tags, launch_time = efs_utils.get_efs_details(resource_id)
                if not active_resources_table_ops.store(account_id, account_name, region, deploy_method, team, created_by, resource_id, '', resource_type, current_state, public_ip, created_at, launch_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                    LOGGER.error("Could not update data for Resource %s in Account=%s and Region=%s", resource_id, account_id, region)
            elif current_state in ['available', 'error', 'active', 'failed']:
                if resource_type == 'EKSCluster':
                    all_tags = eks_utils.get_eks_cluster_tags(resource_id)
                    launch_time = eks_utils.get_eks_cluster_launch_time(resource_id)
                    hourly_cost, daily_cost, monthly_cost = pricing_utils.get_cluster_cost()
                elif resource_type == 'EFSFileSystem':
                    all_tags, launch_time = efs_utils.get_efs_details(resource_id)
                if not active_resources_table_ops.store(account_id, account_name, region, deploy_method, team, created_by, resource_id, '', resource_type, current_state, public_ip, created_at, launch_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                    LOGGER.error("Could not store data for Resource %s in Account=%s and Region=%s", resource_id, account_id, region)
                else:
                    LOGGER.info("Updated record. Deleting 5 min cron rule now...")
                    if not events_utils.cleanup_5_min_cron_rule(resource_type, resource_id):
                        LOGGER.error("Could not delete 5 min rule for %s %s", resource_type, resource_id)
