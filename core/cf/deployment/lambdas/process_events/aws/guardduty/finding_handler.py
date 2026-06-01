from os import getenv
from utils.secretsmanager import Store
from utils.sso_helper import SSOHelper
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from pagerduty.main import PagerDuty
from messenger.events_messenger import EventAlert

DEPLOYMENT_TARGET_ACCOUNTS_SECRET = getenv('DEPLOYMENT_TARGET_ACCOUNTS')

def handle_event(guardduty_admin_account_id, event, deployment_targets, exclude_accounts, notification_app, webhook_urls, send_logs_to_azure, customer_id, shared_key, log_type, create_incidents_on_pagerduty, incident_finding_types, is_pd_integration_type_restapi, pagerduty_routing_key, pagerduty_api_token, pagerduty_service_id, pagerduty_user_email_address):
    account_id = event['accountId']
    region = event['region']
    sso_helper = SSOHelper()
    deployment_accounts = sso_helper.get_active_child_accounts(deployment_targets, exclude_accounts)

    if account_id in deployment_accounts:
        all_active_accounts = sso_helper.get_all_active_accounts()
        if not Store(DEPLOYMENT_TARGET_ACCOUNTS_SECRET, 'Secret to store Account Names against active AWS Account IDs in Deployment Targets', all_active_accounts).store_value():
            LOGGER.error("Could not store updated list of accounts with their names to SecretsManager: %s", all_active_accounts)

        helper = AWSHelper({'account': account_id, 'region': region})
        messenger = EventAlert(notification_app, account_id, region, webhook_urls)
        severity_number = event['severity']
        severity = ''
        if 7.0 <= severity_number <= 8.9:
            severity = 'High'
        elif 4.0 <= severity_number <= 6.9:
            severity = 'Medium'
        elif 1.0 <= severity_number <= 3.9:
            severity = 'Low'
        if severity:
            account_name = helper.get_account_name(event['accountId'])
            pagerduty_helper = None
            if create_incidents_on_pagerduty:
                pagerduty_helper = PagerDuty(
                    helper.account_id,
                    account_name,
                    helper.region,
                    is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                    routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                    api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                    service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                    from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
            alert_args = {
                "severity": severity,
                "severity_number": severity_number,
                "guardduty_admin_account": {'AccountId': guardduty_admin_account_id, 'AccountName': helper.get_account_name(guardduty_admin_account_id)},
                "account_name": account_name,
                "account_id": event['accountId'],
                "region": event['region'],
                "finding_id": event['id'],
                "finding_type": event['type'],
                "finding_description": event['description']
            }
            azure_data = {
                "Severity": severity,
                "AccountID": account_id,
                "AccountName": messenger.account_name,
                "Region": region,
                "User": "GuardDuty",
                "Event": f"AWS {event['accountId']} has a severity {severity_number} GuardDuty finding type {event['type']} in {event['region']} region. Finding Description: {event['description']}"
            }
            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('guardduty_finding_message', alert_args, None, None)
