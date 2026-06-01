from utils.dynamodb import SSMDocAssocFailureData, GetData, DeleteData
from utils.ec2 import EC2
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event_time, event, notification_app, webhook_urls, slack_oauth_token, ssm_document_association_failure_tracker_table, send_logs_to_azure, customer_id, shared_key, log_type, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    ec2_utils = EC2(active_session, helper.region)

    instance_id = event['instance-id']
    ssm_document_name = event['document-name'].split('/')[-1]
    association_id = event['association-id']
    association_status = event['status']

    current_state = ec2_utils.get_instance_status(instance_id)
    records = GetData(ssm_document_association_failure_tracker_table).get_by_id('ssm_document_name', ssm_document_name, 'instance_id', instance_id)
    if current_state not in ['terminated']:
        severity = 'High'
        alert_args = {
            "severity": severity,
            "account_name": messenger.account_name,
            "account_id": helper.account_id,
            "region": helper.region,
            "instance_id": instance_id,
            "association_id": association_id,
            "document_name": ssm_document_name
        }
        azure_data = {
            "Severity": severity,
            "AccountID": helper.account_id,
            "AccountName": messenger.account_name,
            "Region": helper.region,
            "User": "SSM Association",
        }
        ssm_doc_assoc_failure_table_ops = SSMDocAssocFailureData(ssm_document_association_failure_tracker_table)
        all_tags, launch_time, public_ip, ec2_instance_exists = ec2_utils.get_cmdb_instance_details(instance_id)
        attempts = 1
        first_failed_at = event_time
        updated_incident_ids = []
        failed_instance_succeeded = False
        if records:
            if association_status in ['Failed']:
                attempts = int(records[0]['attempts']['N']) + 1
                first_failed_at = records[0]['first_failed_at']['S']
                if pagerduty_helper is not None:
                    if 'pagerduty_incident_id' in records[0]:
                        for incident_id in records[0]['pagerduty_incident_id']['SS']:
                            incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                            if incident_status not in ['resolved']:
                                updated_incident_ids.append(incident_id)
                    elif 'pagerduty_dedup_keys' in records[0]:
                        for dedup_key in records[0]['pagerduty_dedup_keys']['SS']:
                            updated_incident_ids.append(dedup_key)
            else:
                failed_instance_succeeded = True
                severity = 'Informational'
                alert_args['severity'] = severity
                azure_data['Severity'] = severity
                if pagerduty_helper is not None:
                    if 'pagerduty_incident_id' in records[0]:
                        for incident_id in records[0]['pagerduty_incident_id']['SS']:
                            pagerduty_helper.resolve_incident(incident_id)
                    elif 'pagerduty_dedup_keys' in records[0]:
                        for dedup_key in records[0]['pagerduty_dedup_keys']['SS']:
                            pagerduty_helper.resolve_incident(dedup_key)

        if failed_instance_succeeded:
            alert_args["is_terminated"] = False
            if not DeleteData(ssm_document_association_failure_tracker_table).delete('ssm_document_name', ssm_document_name, 'instance_id', instance_id):
                LOGGER.error("Could not delete metadata for SSM Document Association failure for document %s from DynamoDB Table", ssm_document_name)
            azure_data['Event'] = f"EC2 Instance {instance_id} which was previously in a failed state in the SSM Document Association for document {ssm_document_name} has now successfully associated."
            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('ssm_associated_ec2_instance_update_message', alert_args, None, slack_bot)
        else:
            if association_status in ['Failed']:
                azure_data['Event'] = f"An SSM Document Association failure has been detected for document {ssm_document_name} with Association ID {association_id} for EC2 Instance {instance_id}"
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                updated_incident_ids.append(alerts_handler.handler('ssm_document_association_failure_message', alert_args, None, slack_bot))
                if not ssm_doc_assoc_failure_table_ops.store(helper.account_id, messenger.account_name, helper.region, ssm_document_name, association_id, instance_id, str(attempts), first_failed_at, event_time, all_tags if all_tags else [""], pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                    LOGGER.error("Could not store data for Instance %s in %s %s with Association ID %s", instance_id, helper.account_id, helper.region, association_id)
