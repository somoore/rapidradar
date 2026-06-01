import datetime
import uuid
from utils.dynamodb import IAMRootUsersLoginData
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, iam_logins_table, send_logs_to_azure, customer_id, shared_key, log_type, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorMessage' in event and 'responseElements' in event and 'ConsoleLogin' in event['responseElements']:
        if event['responseElements']['ConsoleLogin'] == 'Failure':
            LOGGER.info("Failed login attempt")
            messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
            attempts = 1
            record_exists = False

            iam_users_login_table_ops = IAMRootUsersLoginData(iam_logins_table)
            scan_records = iam_users_login_table_ops.query_by_account_ip_user(helper.account_id, event['sourceIPAddress'], event['userIdentity']['userName'])
            if len(scan_records) > 0:
                for item in scan_records:
                    difference = datetime.datetime.strptime(event['eventTime'],"%Y-%m-%dT%H:%M:%SZ") - datetime.datetime.strptime(item['first_attempt_at']['S'],"%Y-%m-%dT%H:%M:%SZ")
                    if difference.seconds < 300 and item['status']['S'] == 'Failure':
                        attempts = int(item['attempts']['N']) + 1
                        record_exists = True
                        if attempts == 3:
                            severity = 'Critical'
                            alert_args = {
                                "severity": severity,
                                "ip_address": event['sourceIPAddress'],
                                "user": event['userIdentity']['userName'],
                                "matched_ip_users": [],
                                "deploy_ip_tracker_project": False
                            }
                            azure_data = {
                                "Severity": severity,
                                "AccountID": helper.account_id,
                                "AccountName": messenger.account_name,
                                "Region": helper.region,
                                "User": event['userIdentity']['userName'],
                                "Event": f"A brute force attack has been detected from compromised user {event['userIdentity']['userName']} with Source IP Address {event['sourceIPAddress']}"
                            }
                            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('signin_brute_force_attack_message', alert_args, None, None)
                        iam_users_login_table_ops.store(helper.account_id, item['event_id']['S'], event['userIdentity']['userName'], event['sourceIPAddress'], str(attempts), event['responseElements']['ConsoleLogin'], item['first_attempt_at']['S'], event['eventTime'])
            if not scan_records or not record_exists:
                iam_users_login_table_ops.store(helper.account_id, str(uuid.uuid4()), event['userIdentity']['userName'], event['sourceIPAddress'], str(attempts), event['responseElements']['ConsoleLogin'], event['eventTime'], event['eventTime'])
