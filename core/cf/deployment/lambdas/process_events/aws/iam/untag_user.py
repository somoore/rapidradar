import json
from utils.iam import IAM
from utils.dynamodb import (
    IAMKeyPairAccessTrackerData,
    IAMUsersData,
    GetData
)
from utils.sso_helper import SSOHelper
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, alert_suppression_resource_tag_key_value, alert_suppression_permission_set_tag_key_value, iam_table_name, deploy_iam_keypair_access_tracker_project, iam_keypair_access_tracker_table, send_logs_to_azure, customer_id, shared_key, log_type, pagerduty_helper, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    alert_suppression_tag_key, alert_suppression_tag_value = alert_suppression_resource_tag_key_value.split('=')
    admin_alert_suppression_tag_key, admin_alert_suppression_tag_value = alert_suppression_permission_set_tag_key_value.split('=')

    if 'errorCode' not in event and 'requestParameters' in event:
        active_session = helper.get_active_session()
        iam_utils = IAM(active_session)
        request_params = event['requestParameters']
        try:
            if 'tags' in request_params:
                tagged_user = request_params['userName']
                found_suppression_tag = False
                found_admin_suppression_tag = SSOHelper().found_admin_suppression_tag(helper.user_arn, admin_alert_suppression_tag_key, admin_alert_suppression_tag_value)

                if deploy_iam_keypair_access_tracker_project:
                    iam_keypair_access_tracker_table_ops = IAMKeyPairAccessTrackerData(iam_keypair_access_tracker_table)
                    records = iam_keypair_access_tracker_table_ops.get_data_by_account_user(tagged_user, helper.account_id)
                    for record in records:
                        account_id, account_name, access_key_id, create_date, key_activity, expiry_reminders = record['account_id']['S'], record['account_name']['S'], record['access_key_id']['S'], record['create_date']['S'], record['key_activity']['SS'], record['expiry_reminders']['SS']
                        last_used = iam_utils.get_access_key_last_used(access_key_id)
                        current_status = iam_utils.get_access_key_status(tagged_user, access_key_id)
                        iam_user_tags, created_by = iam_utils.get_iam_user_tags_created_by(tagged_user)
                        if not iam_keypair_access_tracker_table_ops.store(account_id, account_name, tagged_user, access_key_id, current_status, created_by, create_date, last_used, key_activity, expiry_reminders, iam_user_tags if iam_user_tags else [""]):
                            LOGGER.error("Could not update data for Access Key ID %s of IAM User %s of Account %s", access_key_id, tagged_user, account_id)

                for key in request_params['tagKeys']:
                    if key == alert_suppression_tag_key:
                        found_suppression_tag = iam_utils.found_suppression_tag(tagged_user, alert_suppression_tag_key, alert_suppression_tag_value)
                scan_records = GetData(iam_table_name).get_by_id('account_id', helper.account_id, 'iam_user', tagged_user)
                if scan_records:
                    severity = 'Informational'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": 'IAM User',
                        "resource_id": tagged_user,
                        "alert_suppression_tag_key": alert_suppression_tag_key,
                        "alert_suppression_tag_value": alert_suppression_tag_value
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                    }
                    previously_notifications_compressed = json.loads(scan_records[0]['notifications_suppressed']['S'])
                    if previously_notifications_compressed and not found_suppression_tag and found_admin_suppression_tag:
                        updated_incident_ids = []
                        if pagerduty_helper is not None and scan_records:
                            if 'pagerduty_incident_id' in scan_records[0]:
                                for incident_id in scan_records[0]['pagerduty_incident_id']['SS']:
                                    incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                                    if incident_status not in ['resolved']:
                                        updated_incident_ids.append(incident_id)
                            elif 'pagerduty_dedup_keys' in scan_records[0]:
                                for dedup_key in scan_records[0]['pagerduty_dedup_keys']['SS']:
                                    updated_incident_ids.append(dedup_key)
                        azure_data['Event'] = f"User {helper.iam_user} has removed {alert_suppression_tag_key}={alert_suppression_tag_value} tag from IAM User {tagged_user}. Notifications for this specific IAM User will now continue until remediated or silenced once again"
                        alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('notifications_suppression_removal_message', alert_args, email_messenger, slack_bot)
                        if not IAMUsersData(iam_table_name).store(helper.account_id, helper.region, tagged_user, scan_records[0]['is_programmatic_access_enabled']['S'], scan_records[0]['is_console_access_enabled']['S'], found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                            LOGGER.error("Could not add metadata to DynamoDB table for User %s in Account=%s", tagged_user, helper.account_id)
                    elif previously_notifications_compressed and not found_suppression_tag and not found_admin_suppression_tag:
                        azure_data['Event'] = f"User {helper.iam_user} removed {alert_suppression_tag_key}={alert_suppression_tag_value} tag from IAM User {tagged_user} but they do not have permission to enable or disable notifications, that's why alerts for this resource will remain disabled"
                        alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('notifications_suppression_removal_failure_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("IAM User not found in DynamoDB Table")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Tags were not deleted from IAM User for some reason")
