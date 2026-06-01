from utils.dynamodb import (
    ActiveResourcesData,
    DeletedResourcesData
)
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, event_time, active_resources_table, deleted_resources_table):
    if 'errorCode' not in event:
        if 'responseElements' in event:
            response_elements = event['responseElements']
            event_by, account_name = helper.get_cmdb_event_details()
            active_resources_table_ops = ActiveResourcesData(active_resources_table)

            db_cluster_identifier = response_elements['dBClusterIdentifier']
            resource_type = 'RDSDBCluster'
            account_name, deploy_method, team, created_by, created_at, all_tags, instance_type, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, db_cluster_identifier)
            if all_tags is not None:
                if not DeletedResourcesData(deleted_resources_table).store(helper.account_id, account_name, helper.region, event_by, db_cluster_identifier, resource_type, event_time, all_tags):
                    LOGGER.error("Could not store data for deleted resource %s", db_cluster_identifier)
                else:
                    LOGGER.info("Added resource details to Deleted Resource Table. Removing from Active Resource Table if exists...")
                    unique_id = f"{helper.account_id}_{helper.region}_{resource_type}_{db_cluster_identifier}"
                    if not active_resources_table_ops.delete(unique_id):
                        LOGGER.error("Could not delete record for %s from active resources table", db_cluster_identifier)
                    else:
                        LOGGER.info("Deleted record for %s from active resource table", db_cluster_identifier)
            else:
                LOGGER.info("...Skipping. No Record existed for %s", db_cluster_identifier)
