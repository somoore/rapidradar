import re
from utils.eks import EKS
from utils.dynamodb import (
    ActiveResourcesData
)
from utils.pricing import Pricing
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, event_source, active_resources_table):
    if 'errorCode' not in event:
        if 'requestParameters' in event:
            active_session = helper.get_active_session()
            eks_utils = EKS(active_session, helper.region)
            pricing_utils = Pricing(active_session, helper.region)
            request_params = event['requestParameters']

            arn_match = re.search(
                r'arn:aws:'+event_source.split('.')[0]+':'+helper.region+':'+helper.account_id+':cluster/([A-Za-z0-9_-]+)',
                request_params['resourceArn'])
            if arn_match is not None:
                active_resources_table_ops = ActiveResourcesData(active_resources_table)
                resource_type = 'EKSCluster'
                cluster_name = arn_match.group(0).partition('cluster/')[2]
                current_state = (eks_utils.get_eks_cluster_status(cluster_name)).lower()
                hourly_cost, daily_cost, monthly_cost = pricing_utils.get_cluster_cost()
                launch_time = eks_utils.get_eks_cluster_launch_time(cluster_name)

                account_name, deploy_method, team, created_by, created_at, all_tags, _, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, cluster_name)
                if all_tags is not None:
                    LOGGER.info("Record exists. Updating it...")
                    all_tags = eks_utils.get_eks_cluster_tags(cluster_name)
                    for tag in all_tags:
                        if tag.split(' ')[0].rstrip(':') in ['DeployedBy', 'deployedby', 'Deployedby', 'deployedBy']:
                            created_by = tag.split(': ')[1]
                        if tag.split(' ')[0].rstrip(':') in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deployMethod']:
                            deploy_method = tag.split(': ')[1]
                        if tag.split(' ')[0].rstrip(':') in ['Team', 'team']:
                            team = tag.split(': ')[1]
                    is_instance_ssm_managed, is_imdsv2_enabled = '', ''
                    if not active_resources_table_ops.store(helper.account_id, account_name, helper.region, deploy_method, team, created_by, cluster_name, '', resource_type, current_state, '', created_at, launch_time, hourly_cost, daily_cost, monthly_cost, '', platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                        LOGGER.error("Could not store data for Resource %s in Account=%s and Region=%s", cluster_name, helper.account_id, helper.region)
                    else:
                        LOGGER.info("Updated record.")
