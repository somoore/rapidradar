from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from utils.dynamodb import (
    ActiveResourcesData,
    DeletedResourcesData,
    DeleteData,
    SSMDocAssocFailureData
)
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, pagerduty_helper, is_pd_integration_type_restapi, event, event_time, notification_app, webhook_urls, active_resources_table, deleted_resources_table, track_ssm_doc_assoc_failures, ssm_document_association_failure_tracker_table, send_logs_to_azure, customer_id, shared_key, log_type):
    event_by, account_name = helper.get_cmdb_event_details()

    if 'errorCode' not in event:
        if 'eventName' in event and 'responseElements' in event and 'principalId' in event['userIdentity'] and 'accountId' in event['userIdentity']:
            response_elements = event['responseElements']

            active_resources_table_ops = ActiveResourcesData(active_resources_table)
            ssm_doc_assoc_failure_table_ops = SSMDocAssocFailureData(ssm_document_association_failure_tracker_table)
            instance_ids = [ item['instanceId'] for item in response_elements['instancesSet']['items'] ]
            resource_type = 'EC2Instance'
            for instance in instance_ids:
                account_name, _, _, _, _, all_tags, _, _, _, _, _ = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, instance)
                if all_tags is not None:
                    if not DeletedResourcesData(deleted_resources_table).store(helper.account_id, account_name, helper.region, event_by, instance, resource_type, event_time, all_tags):
                        LOGGER.error("Could not store data for deleted resource %s", instance)
                    else:
                        LOGGER.info("Added resource details to Deleted Resource Table. Removing from Active Resource Table...")
                        unique_id = f"{helper.account_id}_{helper.region}_{resource_type}_{instance}"
                        if not active_resources_table_ops.delete(unique_id):
                            LOGGER.error("Could not delete record for %s from active resources table", instance)
                        else:
                            LOGGER.info("Deleted record for %s from active resource table", instance)
                else:
                    LOGGER.info("...Skipping. No Record existed for %s", instance)

                if track_ssm_doc_assoc_failures:
                    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
                    instance_record = ssm_doc_assoc_failure_table_ops.query_by_instance_id(instance)
                    if instance_record:
                        if pagerduty_helper is not None:
                            if 'pagerduty_incident_id' in instance_record:
                                for incident_id in instance_record['pagerduty_incident_id']['SS']:
                                    pagerduty_helper.resolve_incident(incident_id)
                            elif 'pagerduty_dedup_keys' in instance_record:
                                for dedup_key in instance_record['pagerduty_dedup_keys']['SS']:
                                    pagerduty_helper.resolve_incident(dedup_key)
                        if not DeleteData(ssm_document_association_failure_tracker_table).delete('ssm_document_name', instance_record['ssm_document_name']['S'], 'instance_id', instance_record['instance_id']['S']):
                            LOGGER.error("Could not delete metadata for SSM Document Association failure for document %s from DynamoDB Table", instance_record['ssm_document_name']['S'])
                        severity = 'Informational'
                        azure_data = {
                            "Severity": severity,
                            "AccountID": helper.account_id,
                            "AccountName": messenger.account_name,
                            "Region": helper.region,
                            "User": "SSM Association"
                        }
                        alert_args = {
                            "severity": severity,
                            "account_name": messenger.account_name,
                            "account_id": helper.account_id,
                            "region": helper.region,
                            "instance_id": instance,
                            "association_id": instance_record['association_id']['S'],
                            "document_name": instance_record['ssm_document_name']['S'],
                            "is_terminated": True
                        }
                        azure_data['Event'] = f"EC2 Instance {instance} which was previously in a failed state in the SSM Document Association for document {instance_record['ssm_document_name']['S']} has been terminated."
                        alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('ssm_associated_ec2_instance_update_message', alert_args, None, None)
            LOGGER.info("Terminated instances %s handled successfully.", ', '.join(instance_ids))
        else:
            LOGGER.info("required props not found")
    else:
        LOGGER.info("EC2 Instance Termination failed for some reason")
