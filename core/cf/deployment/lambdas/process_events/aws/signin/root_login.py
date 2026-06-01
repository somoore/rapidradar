import datetime
import uuid
import json
from utils.dynamodb import (
    IAMRootUsersLoginData,
    GetData
)
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, root_logins_table, ip_history_table, send_logs_to_azure, customer_id, shared_key, log_type, deploy_ip_tracker_project, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'responseElements' in event and 'ConsoleLogin' in event['responseElements']:
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        root_users_login_table_ops = IAMRootUsersLoginData(root_logins_table)
        azure_data = {
            "AccountID": helper.account_id,
            "AccountName": messenger.account_name,
            "Region": helper.region,
            "User": "Root"
        }

        if 'errorMessage' not in event:
            if event['responseElements']['ConsoleLogin'] == 'Success':
                LOGGER.info("Successful Root Login")
                attempts = 1
                record_exists = False
                scan_records = root_users_login_table_ops.query_by_account_ip_user(helper.account_id, event['sourceIPAddress'], 'root')
                if len(scan_records) > 0:
                    for item in scan_records:
                        difference = datetime.datetime.strptime(event['eventTime'],"%Y-%m-%dT%H:%M:%SZ") - datetime.datetime.strptime(item['first_attempt_at']['S'],"%Y-%m-%dT%H:%M:%SZ")
                        if item['status']['S'] == 'Failure' and difference.seconds < 300:
                            record_exists = True
                            attempts = int(item['attempts']['N']) + 1
                            if not root_users_login_table_ops.store(helper.account_id, item['event_id']['S'], 'root', event['sourceIPAddress'], str(attempts), event['responseElements']['ConsoleLogin'], item['first_attempt_at']['S'], event['eventTime']):
                                LOGGER.error("Could not store metadata for root login")
                if not scan_records or not record_exists:
                    if not root_users_login_table_ops.store(helper.account_id, str(uuid.uuid4()), 'root', event['sourceIPAddress'], str(attempts), event['responseElements']['ConsoleLogin'], event['eventTime'], event['eventTime']):
                        LOGGER.error("Could not store metadata for root login")

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
                    "ip_address": event['sourceIPAddress'],
                    "user_agent": event['userAgent'],
                    "matched_ip_users": matched_ip_history_users,
                    "deploy_ip_tracker_project": deploy_ip_tracker_project
                }
                azure_data['Severity'] = severity
                azure_data['Event'] = f"A login to the AWS Management Console by the root user has been detected with Source IP Address {event['sourceIPAddress']} and User Agent {event['userAgent']}"
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('root_user_login_message', alert_args, None, None)

        elif 'errorMessage' in event:
            if event['responseElements']['ConsoleLogin'] == 'Failure':
                LOGGER.info("Failed login attempt")
                attempts = 1
                record_exists = False
                scan_records = root_users_login_table_ops.query_by_account_ip_user(helper.account_id, event['sourceIPAddress'], 'root')
                if len(scan_records) > 0:
                    for item in scan_records:
                        difference = datetime.datetime.strptime(event['eventTime'],"%Y-%m-%dT%H:%M:%SZ") - datetime.datetime.strptime(item['first_attempt_at']['S'],"%Y-%m-%dT%H:%M:%SZ")
                        if difference.seconds < 300 and item['status']['S'] != 'Success':
                            attempts = int(item['attempts']['N']) + 1
                            record_exists = True
                            if attempts == 3:
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
                                    "ip_address": event['sourceIPAddress'],
                                    "user": 'root',
                                    "matched_ip_users": matched_ip_history_users,
                                    "deploy_ip_tracker_project": deploy_ip_tracker_project
                                }
                                azure_data['Severity'] = severity
                                azure_data['Event'] = f"A brute force attack has been detected from compromised root user with Source IP Address {event['sourceIPAddress']}"
                                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                alerts_handler.handler('signin_brute_force_attack_message', alert_args, None, None)
                            if not root_users_login_table_ops.store(helper.account_id, item['event_id']['S'], 'root', event['sourceIPAddress'], str(attempts), event['responseElements']['ConsoleLogin'], item['first_attempt_at']['S'], event['eventTime']):
                                LOGGER.error("Could not store metadata for root login")
                if not scan_records or not record_exists:
                    if not root_users_login_table_ops.store(helper.account_id, str(uuid.uuid4()), 'root', event['sourceIPAddress'], str(attempts), event['responseElements']['ConsoleLogin'], event['eventTime'], event['eventTime']):
                        LOGGER.error("Could not store metadata for root login")
