import json
from utils.dynamodb import GetData
from utils.utility import AWSHelper, Alert
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, ip_history_table, deploy_ip_tracker_project, send_logs_to_azure, customer_id, shared_key, log_type, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'responseElements' in event and 'PasswordRecoveryCompleted' in event['responseElements']:
        response_elements = event['responseElements']
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        if response_elements['PasswordRecoveryCompleted'] == 'Success':
            matched_ip_history_users = []
            if deploy_ip_tracker_project:
                ip_history_records = GetData(ip_history_table).get()
                for ip_record in ip_history_records:
                    for ip_addr in ip_record['ip_addresses']['SS']:
                        if ip_addr:
                            ip_data = json.loads(ip_addr)
                            if ip_data['IpAddress'] == event['sourceIPAddress']:
                                matched_ip_history_users.append(ip_record['user']['S'])
                matched_ip_history_users = list(set(matched_ip_history_users))
            severity = 'Critical'
            alert_args = {
                "severity": severity,
                "ip_address": helper.user_ip_address,
                "user_agent": helper.user_agent,
                "is_completed": True,
                "matched_ip_users": matched_ip_history_users,
                "deploy_ip_tracker_project": deploy_ip_tracker_project
            }
            azure_message = f" Based on our data, this could potentially be [{' or '.join(matched_ip_history_users)}]." if matched_ip_history_users else ""
            azure_data = {
                "Severity": severity,
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "Event": f"Someone changed password for ROOT user.{azure_message} Please verify the legitimacy of the password change event"
            }
            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('root_user_password_change', alert_args, None, None)
