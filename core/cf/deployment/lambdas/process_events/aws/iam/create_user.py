from utils.dynamodb import IAMUsersData
from utils.sso_helper import SSOHelper
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, alert_suppression_resource_tag_key_value, alert_suppression_permission_set_tag_key_value, send_logs_to_azure, customer_id, shared_key, log_type, iam_table, iam_user_creation_blocked, iam_user_creation_blocked_bypass_tag_key, alert_on_iam_users_creation_bypass, iam_user_creation_blocked_wo_certain_tags, iam_user_creation_scp_tag_keys, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    alert_suppression_tag_key, alert_suppression_tag_value = alert_suppression_resource_tag_key_value.split('=')
    admin_alert_suppression_tag_key, admin_alert_suppression_tag_value = alert_suppression_permission_set_tag_key_value.split('=')
    azure_data = {
        "AccountID": helper.account_id,
        "AccountName": messenger.account_name,
        "Region": helper.region,
        "User": helper.iam_user
    }
    if 'errorCode' not in event and 'responseElements' in event and event['responseElements'] is not None and 'user' in event['responseElements']:
        user_response_elements = event['responseElements']['user']
        try:
            found_suppression_tag = False
            found_bypass_tag = False
            found_admin_suppression_tag = SSOHelper().found_admin_suppression_tag(helper.user_arn, admin_alert_suppression_tag_key, admin_alert_suppression_tag_value)
            new_iam_user = user_response_elements['userName']
            if 'tags' in user_response_elements:
                for tag in user_response_elements['tags']:
                    if tag['key'] == alert_suppression_tag_key and tag['value'] == alert_suppression_tag_value and found_admin_suppression_tag:
                        found_suppression_tag = True
                    if tag['key'] == iam_user_creation_blocked_bypass_tag_key and iam_user_creation_blocked:
                        found_bypass_tag = True

            pagerduty_incidents_ids = []
            severity = 'Informational' if found_bypass_tag else 'Medium'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "new_iam_user": new_iam_user,
                "found_bypass_tag": found_bypass_tag
            }
            azure_data['Severity'] = severity
            azure_data['Event'] = f"User {helper.iam_user} created a new IAM User named {new_iam_user}{' against SCP applied on your Organization using bypass tag' if found_bypass_tag else ''}"
            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alert_id = None
            if iam_user_creation_blocked and found_bypass_tag and alert_on_iam_users_creation_bypass:
                alert_id = 'iam_user_creation_bypass_tag_message'
            elif not iam_user_creation_blocked:
                alert_id = 'iam_user_creation_bypass_tag_message'
            new_incident_id = alerts_handler.handler(alert_id, alert_args, email_messenger, slack_bot)
            if new_incident_id:
                pagerduty_incidents_ids.append(new_incident_id)
            if not found_bypass_tag:
                if not IAMUsersData(iam_table).store(helper.account_id, helper.region, new_iam_user, False, False, found_suppression_tag, pagerduty_incident_id=pagerduty_incidents_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else pagerduty_incidents_ids):
                    LOGGER.error("Could not add metadata to DynamoDB table for User %s in Account=%s", new_iam_user, helper.account_id)
        except Exception as error:
            LOGGER.error(str(error))
    elif 'errorCode' in event and 'errorMessage' in event:
        if event['errorCode'] == 'AccessDenied' and 'explicit deny in a service control policy' in event['errorMessage']:
            # Check if IAM Users creation failed due to general restriction or missing specific tags
            if iam_user_creation_blocked or iam_user_creation_blocked_wo_certain_tags:
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user,
                    "is_creation_blocked": iam_user_creation_blocked,
                    "is_creation_blocked_wo_tags": iam_user_creation_blocked_wo_certain_tags,
                    "iam_user_creation_scp_tag_keys": iam_user_creation_scp_tag_keys
                }
                azure_data['Severity'] = severity
                azure_data['Event'] = f"User {helper.iam_user} tried to create a new IAM User but failed due to explicit deny in a service control policy"
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('iam_user_creation_scp_block_error_message', alert_args, email_messenger, slack_bot)
    else:
        LOGGER.info("IAM User Creation failed for some reason")
