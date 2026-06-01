from utils.iam import IAM
from utils.dynamodb import (
    IAMUsersData,
    GetData
)
from utils.utility import AWSHelper, Helper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, iam_table_name, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    if 'errorCode' not in event and 'responseElements' in event and 'loginProfile' in event['responseElements']:
        active_session = helper.get_active_session()
        iam_utils = IAM(active_session)
        login_profile_response_elements = event['responseElements']['loginProfile']

        try:
            login_profile_user = login_profile_response_elements['userName']
            found_suppression_tag = False
            is_programmatic_access_enabled = False
            created_at = Helper().get_cst_datetime(login_profile_response_elements['createDate'])
            is_programmatic_access_enabled = iam_utils.found_user_access_keys(login_profile_user)
            found_suppression_tag = GetData(iam_table_name).found_suppression_tag(helper.account_id, 'iam_user', login_profile_user)
            scan_records = GetData(iam_table_name).get_by_id('account_id', helper.account_id, 'iam_user', login_profile_user)
            severity = 'High'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "login_profile_user": login_profile_user,
                "created_at": created_at
            }
            azure_data = {
                "Severity": severity,
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user,
                "Event": f"User {helper.iam_user} enabled AWS Console Access for IAM User {login_profile_user}"
            }
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
            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            updated_incident_ids.append(alerts_handler.handler('login_profile_creation_message', alert_args, email_messenger, slack_bot))
            if not IAMUsersData(iam_table_name).store(helper.account_id, helper.region, login_profile_user, is_programmatic_access_enabled, True, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                LOGGER.error("Could not add metadata to DynamoDB table for User %s in Account=%s", login_profile_user, helper.account_id)
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Login Profile for IAM User was not enabled for some reason")
