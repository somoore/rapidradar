import json
import datetime
from utils.iam import IAM
from utils.events import Events
from utils.dynamodb import (
    IAMUsersData,
    IAMKeyPairAccessTrackerData,
    GetData
)
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, project_name, event_bus_arn, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, iam_table_name, iam_keypair_access_tracker_table, deploy_iam_keypair_access_tracker_project, disable_reminders_for_secret_access_key_expiry, iam_secret_access_key_expiry, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    account_name = helper.get_account_name()
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    if 'errorCode' not in event and 'responseElements' in event and 'accessKey' in event['responseElements']:
        active_session = helper.get_active_session()
        iam_utils = IAM(active_session)
        events_utils = Events(helper.account_id, helper.region)
        access_key_response_elements = event['responseElements']['accessKey']
        try:
            access_key_user = access_key_response_elements['userName']
            access_key_id = access_key_response_elements['accessKeyId']
            found_suppression_tag = False
            create_date = (datetime.datetime.strptime(access_key_response_elements['createDate'], "%b %d, %Y %I:%M:%S %p")).strftime("%Y-%m-%dT%H:%M:%S")
            is_console_access_enabled = iam_utils.found_iam_user_login_profile(access_key_user)
            iam_user_tags, created_by = iam_utils.get_iam_user_tags_created_by(access_key_user)
            found_suppression_tag = GetData(iam_table_name).found_suppression_tag(helper.account_id, 'iam_user', access_key_user)
            scan_records = GetData(iam_table_name).get_by_id('account_id', helper.account_id, 'iam_user', access_key_user)
            severity = 'High'
            alert_args = {
                "severity": severity,
                "is_new": True,
                "iam_user": helper.iam_user,
                "secret_access_key_user": access_key_user,
                "access_key_id": access_key_id,
                "created_by": created_by,
                "created_at": create_date,
                "deploy_iam_keypair_access_tracker_project": deploy_iam_keypair_access_tracker_project
            }
            azure_data = {
                "Severity": severity,
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user,
                "Event": f"User {helper.iam_user} created a new Secret-Access KeyPair with Access Key ID {access_key_id} for IAM User {access_key_user}"
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
            if deploy_iam_keypair_access_tracker_project and not created_by:
                email_messenger = None
            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            updated_incident_ids.append(alerts_handler.handler('secret_access_key_creation_message', alert_args, email_messenger, slack_bot))

            if not IAMUsersData(iam_table_name).store(helper.account_id, helper.region, access_key_user, True, is_console_access_enabled, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                LOGGER.error("Could not add metadata to DynamoDB table for User %s in Account=%s", access_key_user, helper.account_id)
            if deploy_iam_keypair_access_tracker_project:
                key_status = iam_utils.get_access_key_status(access_key_user, access_key_id)
                if key_status == 'Active':
                    if not events_utils.create_rules_to_capture_iam_user_events(active_session, access_key_user, access_key_id, project_name, event_bus_arn):
                        LOGGER.error("Could not create EventBridge Rules for Access Key ID %s of IAM User %s in Account %s", access_key_id, access_key_user, helper.account_id)
                reminder_dates = []
                if not disable_reminders_for_secret_access_key_expiry:
                    creation_date = datetime.datetime.strptime(create_date, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
                    reminder_after_days = [int(round(iam_secret_access_key_expiry/3, 0)), int(round(iam_secret_access_key_expiry/2, 0)), int(round(iam_secret_access_key_expiry/1.5, 0)), iam_secret_access_key_expiry-5, iam_secret_access_key_expiry-2, iam_secret_access_key_expiry-1, iam_secret_access_key_expiry]
                    for day in reminder_after_days:
                        reminder_dates.append(json.dumps({"date": (creation_date + datetime.timedelta(days=day)).strftime('%Y-%m-%d'), "sent": False}))
                if not IAMKeyPairAccessTrackerData(iam_keypair_access_tracker_table).store(helper.account_id, account_name, access_key_user, access_key_id, access_key_response_elements['status'], created_by, create_date, '', [""], reminder_dates if reminder_dates else [""], iam_user_tags if iam_user_tags else [""]):
                    LOGGER.error("Could not store data for Access Key ID %s of IAM User %s into IAM KeyPair Access Tracker DynamoDB Table", access_key_id, access_key_user)
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Secret-Access Keypair was not created for some reason")
