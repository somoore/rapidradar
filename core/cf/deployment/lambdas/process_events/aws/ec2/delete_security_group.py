from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from utils.dynamodb import (
    RemediatedResourcesData,
    GetData,
    DeleteData
)
from pagerduty.main import PagerDuty
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, send_logs_to_azure, customer_id, shared_key, log_type, sg_table_name, remediated_table_name, create_incidents_on_pagerduty, is_pd_integration_type_restapi, pagerduty_routing_key, pagerduty_api_token, pagerduty_service_id, pagerduty_user_email_address):
    if 'errorCode' not in event and 'requestParameters' in event:
        request_params = event['requestParameters']
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        try:
            if 'groupId' in request_params:
                security_group_id = request_params['groupId']
                scan_records = GetData(sg_table_name).get_by_id('account_id', helper.account_id, 'security_group_id', security_group_id)
                if scan_records:
                    if create_incidents_on_pagerduty:
                        pagerduty_helper = PagerDuty(
                            helper.account_id,
                            messenger.account_name,
                            helper.region,
                            is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                            routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                            api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                            service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                            from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                        if 'pagerduty_incident_id' in scan_records[0]:
                            for incident_id in scan_records[0]['pagerduty_incident_id']['SS']:
                                pagerduty_helper.resolve_incident(incident_id)
                        elif 'pagerduty_dedup_keys' in scan_records[0]:
                            for dedup_key in scan_records[0]['pagerduty_dedup_keys']['SS']:
                                pagerduty_helper.resolve_incident(dedup_key)
                    if not DeleteData(sg_table_name).delete('account_id', helper.account_id, 'security_group_id', security_group_id):
                        LOGGER.error("Could not delete metadata for Security Group %s from DynamoDB Table", security_group_id)
                    if not RemediatedResourcesData(remediated_table_name).store(helper.account_id, helper.region, security_group_id, 'Security Group with Open Ports'):
                        LOGGER.error("Could not add metadata for Security Group %s to remediated DynamoDB Table", security_group_id)

                    severity = 'Informational'
                    alert_args = {
                        "severity": severity,
                        "port": "",
                        "security_group_id": security_group_id,
                        "is_attached": False,
                        "attached_instances": [],
                        "attached_lb": [],
                        "is_deleted": True
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                        "Event": f"Security group with ID {security_group_id} got remediated and does not exist anymore"
                    }
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('security_group_ingress_open_to_all_attachment_remediation_message', alert_args, None, None)
                else:
                    LOGGER.info("Metadata not found in DyanmoDB Table for %s", security_group_id)
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Security Group was not deleted for some reason")
