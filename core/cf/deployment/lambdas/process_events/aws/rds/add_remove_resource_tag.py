import re
from utils.rds import RDS
from utils.dynamodb import (
    ActiveResourcesData
)
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, event_source, active_resources_table):
    if 'errorCode' not in event:
        if 'requestParameters' in event:
            active_session = helper.get_active_session()
            rds_utils = RDS(active_session, helper.region)
            active_resources_table_ops = ActiveResourcesData(active_resources_table)
            request_params = event['requestParameters']
            _, account_name = helper.get_cmdb_event_details()

            resource_type, resource_id, current_state = '', '', ''
            instance_arn_match = re.search(
                r'arn:aws:'+event_source.split('.')[0]+':'+helper.region+':'+helper.account_id+':db:([A-Za-z0-9_-]+)',
                request_params['resourceName'])
            cluster_arn_match = re.search(
                r'arn:aws:'+event_source.split('.')[0]+':'+helper.region+':'+helper.account_id+':cluster:([A-Za-z0-9_-]+)',
                request_params['resourceName'])
            if instance_arn_match is not None:
                resource_type = 'RDSDBInstance'
                resource_id = instance_arn_match.group(0).partition(f'{helper.account_id}:db:')[2]
                current_state = rds_utils.get_rds_instance_status(resource_id)
            elif cluster_arn_match is not None:
                resource_type = 'RDSDBCluster'
                resource_id = cluster_arn_match.group(0).partition(f'{helper.account_id}:cluster:')[2]
                current_state = rds_utils.get_rds_cluster_status(resource_id)
            account_name, deploy_method, team, created_by, created_at, all_tags, instance_type, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, resource_id)
            if all_tags is not None:
                LOGGER.info("Record exists. Updating it...")
                all_tags = rds_utils.get_rds_tags(helper.account_id, resource_type, resource_id)
                for tag in all_tags:
                    if tag.split(' ')[0].rstrip(':') in ['DeployedBy', 'deployedby', 'Deployedby', 'deployedBy']:
                        created_by = tag.split(': ')[1]
                    if tag.split(' ')[0].rstrip(':') in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                        deploy_method = tag.split(': ')[1]
                    if tag.split(' ')[0].rstrip(':') in ['Team', 'team']:
                        team = tag.split(': ')[1]
                launch_time = rds_utils.get_rds_instance_launch_time(resource_id) if resource_type == 'RDSDBInstance' else rds_utils.get_rds_cluster_launch_time(resource_id)
                cost_type, is_instance_ssm_managed, is_imdsv2_enabled = '', '', ''
                if not active_resources_table_ops.store(helper.account_id, account_name, helper.region, deploy_method, team, created_by, resource_id, instance_type, resource_type, current_state, '', created_at, launch_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                    LOGGER.error("Could not store data for RDS %s in Account=%s and Region=%s", resource_id, helper.account_id, helper.region)
                else:
                    LOGGER.info("Updated record")
