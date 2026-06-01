from utils.rds import RDS
from utils.pricing import Pricing
from utils.dynamodb import (
    ActiveResourcesData
)
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, detail_type, identifier, active_resources_table):
    active_session = helper.get_active_session()
    rds_utils = RDS(active_session, helper.region)
    pricing_utils = Pricing(active_session, helper.region)
    current_state = 'Unknown'
    resource_type = ''
    public_ip = ''
    if detail_type == 'RDS DB Instance Event':
        current_state = rds_utils.get_rds_instance_status(identifier)
        resource_type = 'RDSDBInstance'
    elif detail_type == 'RDS DB Cluster Event':
        current_state = rds_utils.get_rds_cluster_status(identifier)
        resource_type = 'RDSDBCluster'
    if current_state == 'deleted':
        LOGGER.info("...Skipping because current status is %s", current_state)
    else:
        active_resources_table_ops = ActiveResourcesData(active_resources_table)
        account_name, deploy_method, team, created_by, created_at, all_tags, instance_type, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, identifier)
        if all_tags is not None:
            LOGGER.info("Record exists. Updating it...")
            all_tags = rds_utils.get_rds_tags(helper.account_id, resource_type, identifier)
            launch_time = rds_utils.get_rds_instance_launch_time(identifier) if resource_type == 'RDSDBInstance' else rds_utils.get_rds_cluster_launch_time(identifier)
            cost_type, is_instance_ssm_managed, is_imdsv2_enabled = '', '', ''
            instance_class, rds_engine, storage_type = rds_utils.get_rds_cost_details(resource_type, identifier)
            hourly_cost = 0.0
            instance_classes = instance_class.split(',')
            for instance in instance_classes:
                hourly_cost += pricing_utils.get_rds_hourly_cost(instance, rds_engine, storage_type)
            daily_cost, monthly_cost = '', ''
            if hourly_cost:
                daily_cost = hourly_cost * 24
                monthly_cost = daily_cost * 30
                hourly_cost = f"USD {hourly_cost:.2f}"
                daily_cost = f"USD {daily_cost:.2f}"
                monthly_cost = f"USD {monthly_cost:.2f}"
            if not isinstance(hourly_cost, str):
                hourly_cost = f"USD {hourly_cost:.2f}"
            if not active_resources_table_ops.store(helper.account_id, account_name, helper.region, deploy_method, team, created_by, identifier, instance_type, resource_type, current_state, public_ip, created_at, launch_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                LOGGER.error("Could not store data for RDS %s in Account=%s and Region=%s", identifier, helper.account_id, helper.region)
            else:
                LOGGER.info("Updated record")
