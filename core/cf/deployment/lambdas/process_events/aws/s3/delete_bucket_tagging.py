from utils.s3 import S3
from utils.dynamodb import (
    S3BucketsData,
    GetData
)
from utils.sso_helper import SSOHelper
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, alert_suppression_resource_tag_key_value, alert_suppression_permission_set_tag_key_value, send_logs_to_azure, customer_id, shared_key, log_type, s3_buckets_table_name, pagerduty_helper, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    alert_suppression_tag_key, alert_suppression_tag_value = alert_suppression_resource_tag_key_value.split('=')
    admin_alert_suppression_tag_key, admin_alert_suppression_tag_value = alert_suppression_permission_set_tag_key_value.split('=')

    if 'errorCode' not in event and 'requestParameters' in event:
        active_session = helper.get_active_session()
        s3_utils = S3(active_session, helper.region)
        s3_buckets_table_ops = S3BucketsData(s3_buckets_table_name)
        request_params = event['requestParameters']
        is_bucket_encrypted = False
        found_suppression_tag = False
        found_public_objects = False
        is_public_bucket = False
        try:
            bucket_name = request_params['bucketName']

            found_public_objects = s3_utils.found_s3_public_objects(bucket_name)
            is_bucket_policy_public = s3_utils.is_bucket_policy_public(bucket_name)
            is_bucket_acls_public = s3_utils.is_bucket_acls_public(bucket_name)
            is_bucket_encrypted = s3_utils.is_bucket_encryption_enabled(bucket_name)

            previously_notifications_compressed = GetData(s3_buckets_table_name).found_suppression_tag(helper.account_id, 's3_bucket_name', bucket_name)
            scan_records = GetData(s3_buckets_table_name).get_by_id('account_id', helper.account_id, 's3_bucket_name', bucket_name)
            found_admin_suppression_tag = SSOHelper().found_admin_suppression_tag(helper.user_arn, admin_alert_suppression_tag_key, admin_alert_suppression_tag_value)
            found_suppression_tag = s3_utils.found_suppression_tag(bucket_name, alert_suppression_tag_key, alert_suppression_tag_value)

            is_public_bucket = is_bucket_policy_public or is_bucket_acls_public
            severity = 'Informational'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "resource_type": 'S3 Bucket',
                "resource_id": bucket_name,
                "alert_suppression_tag_key": alert_suppression_tag_key,
                "alert_suppression_tag_value": alert_suppression_tag_value
            }
            azure_data = {
                "Severity": severity,
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user
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
            if previously_notifications_compressed and not found_suppression_tag and found_admin_suppression_tag:
                if not s3_buckets_table_ops.store(helper.account_id, helper.region, bucket_name, is_bucket_encrypted, is_public_bucket, found_public_objects, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                    LOGGER.error("Could not add metadata for S3 Bucket %s in Account ID=%s and Region=%s", bucket_name, helper.account_id, helper.region)
                azure_data['Event'] = f"User {helper.iam_user} has removed {alert_suppression_tag_key}={alert_suppression_tag_value} tag from S3 Bucket {bucket_name}. Notifications for this specific S3 Bucket will now continue until remediated or silenced once again"
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('notifications_suppression_removal_message', alert_args, email_messenger, slack_bot)

            elif previously_notifications_compressed and not found_suppression_tag and not found_admin_suppression_tag:
                azure_data['Event'] = f"User {helper.iam_user} removed {alert_suppression_tag_key}={alert_suppression_tag_value} tag from S3 Bucket {bucket_name} but they do not have permission to enable or disable notifications, that's why alerts for this resource will remain disabled"
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('notifications_suppression_removal_failure_message', alert_args, email_messenger, slack_bot)

            elif (is_public_bucket or found_public_objects) and not found_suppression_tag:
                if not s3_buckets_table_ops.store(helper.account_id, helper.region, bucket_name, is_bucket_encrypted, is_public_bucket, found_public_objects, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                    LOGGER.error("Could not add metadata for S3 Bucket %s in Account ID=%s and Region=%s", bucket_name, helper.account_id, helper.region)
                LOGGER.info("Not Notifying")
            else:
                LOGGER.info("Not Notifying")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("S3 Bucket tags were not deleted for some reason")
