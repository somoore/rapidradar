from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    request_params = event['requestParameters']
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    affected_user = ''
    is_failed_event = False
    if 'errorCode' in event:
        affected_user = request_params['userName']
        is_failed_event = True
    elif 'errorCode' not in event:
        affected_user = request_params['userName']

    if affected_user:
        severity = 'Critical'
        azure_data = {
            "Severity": severity,
            "AccountID": helper.account_id,
            "AccountName": messenger.account_name,
            "Region": helper.region,
            "User": helper.iam_user,
            "Event": f"User {helper.iam_user} { 'tried to change' if is_failed_event else 'changed'} console password for IAM User {affected_user}. Please verify the legitimacy of the password change event."
        }
        alert_args = {
            "severity": severity,
            "iam_user": helper.iam_user,
            "affected_user": affected_user,
            "is_failed": is_failed_event,
            "user_agent": helper.user_agent,
            "source_ip_address": helper.user_ip_address
        }
        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
        alerts_handler.handler('iam_user_password_change_message', alert_args, email_messenger, slack_bot)
