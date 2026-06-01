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

            cluster_name = response_elements['cluster']['name']
            resource_type = 'EKSCluster'
            active_resources_table_ops = ActiveResourcesData(active_resources_table)
            account_name, _, _, _, _, all_tags, _, _, _, _, _ = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, cluster_name)
            if all_tags is not None:
                if not DeletedResourcesData(deleted_resources_table).store(helper.account_id, account_name, helper.region, event_by, cluster_name, resource_type, event_time, all_tags):
                    LOGGER.error("Could not store data for deleted resource %s", cluster_name)
                else:
                    LOGGER.info("Added resource details to Deleted Resource Table. Removing from Active Resource Table if exists...")
                    unique_id = f"{helper.account_id}_{helper.region}_{resource_type}_{cluster_name}"
                    if not active_resources_table_ops.delete(unique_id):
                        LOGGER.error("Could not delete record for %s from active resources table", cluster_name)
                    else:
                        LOGGER.info("Deleted record for %s from active resource table", cluster_name)
            else:
                LOGGER.info("...Skipping. No Record existed for %s", cluster_name)
