from utils.dynamodb import (
    ActiveResourcesData
)
from utils.efs import EFS
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, active_resources_table):
    if 'errorCode' not in event:
        if 'requestParameters' in event:
            active_session = helper.get_active_session()
            efs_utils = EFS(active_session, helper.region)
            request_params = event['requestParameters']

            efs_id = request_params['resourceId']
            resource_type = 'EFSFileSystem'
            active_resources_table_ops = ActiveResourcesData(active_resources_table)
            account_name, deploy_method, team, created_by, created_at, all_tags, _, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, efs_id)
            if all_tags is not None:
                LOGGER.info("Record exists. Updating it...")
                current_state = efs_utils.get_efs_filesystem_status(efs_id)
                all_tags, launch_time = efs_utils.get_efs_details(efs_id)
                for tag in all_tags:
                    if tag.split(' ')[0].rstrip(':') in ['DeployedBy', 'deployedby', 'Deployedby', 'deployedBy']:
                        created_by = tag.split(': ')[1]
                    if tag.split(' ')[0].rstrip(':') in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                        deploy_method = tag.split(': ')[1]
                    if tag.split(' ')[0].rstrip(':') in ['Team', 'team']:
                        team = tag.split(': ')[1]
                is_instance_ssm_managed, is_imdsv2_enabled = '', ''
                if not active_resources_table_ops.store(helper.account_id, account_name, helper.region, deploy_method, team, created_by, efs_id, '', resource_type, current_state, '', created_at, launch_time, hourly_cost, daily_cost, monthly_cost, '', platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                    LOGGER.error("Could not update data for Resource %s in Account=%s and Region=%s", efs_id, helper.account_id, helper.region)
                else:
                    LOGGER.info("Updated record")
