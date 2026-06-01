from utils.s3 import S3
from utils.dynamodb import (
    S3BucketsData,
    GetData
)
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot
from pagerduty.main import PagerDuty

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, s3_buckets_table_name, pagerduty_helper: PagerDuty, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    if 'errorCode' not in event and 'requestParameters' in event:
        active_session = helper.get_active_session()
        s3_utils = S3(active_session, helper.region)
        request_params = event['requestParameters']
        is_bucket_encrypted = False
        found_suppression_tag = False
        is_open_to_everyone = False
        is_public_bucket = False
        try:
            bucket_name = request_params['bucketName']

            is_bucket_policy_public = s3_utils.is_bucket_policy_public(bucket_name)
            is_bucket_acls_public = s3_utils.is_bucket_acls_public(bucket_name)
            is_bucket_encrypted = s3_utils.is_bucket_encryption_enabled(bucket_name)
            is_object_encrypted = True if 'x-amz-server-side-encryption' in request_params else False

            if 'x-amz-acl' in request_params and request_params['x-amz-acl'] == 'public-read':
                is_open_to_everyone = True
            elif 'accessControlList' in request_params:
                for val in request_params['accessControlList'].values():
                    if 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' in val or 'http://acs.amazonaws.com/groups/global/AllUsers' in val:
                        is_open_to_everyone = True

            found_suppression_tag = GetData(s3_buckets_table_name).found_suppression_tag(helper.account_id, 's3_bucket_name', bucket_name)
            scan_records = GetData(s3_buckets_table_name).get_by_id('account_id', helper.account_id, 's3_bucket_name', bucket_name)
            is_public_bucket = is_bucket_policy_public or is_bucket_acls_public

            if is_open_to_everyone or is_public_bucket:
                severity = 'Critical'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user,
                    "s3_bucket_name": bucket_name,
                    "is_encryption_enabled": is_bucket_encrypted
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user,
                    "Event": f"User {helper.iam_user} enabled Public Access for some Objects in S3 Bucket named {bucket_name} which can potentially be downloaded externally"
                }
                updated_incident_ids = []
                if pagerduty_helper is not None and scan_records:
                    if 'pagerduty_incident_id' in scan_records[0]:
                        for incident_id in scan_records[0]['pagerduty_incident_id']['SS']:
                            incident_status, _, _ = pagerduty_helper.get_incident_details(incident_id)
                            if incident_status not in ['resolved']:
                                updated_incident_ids.append(incident_id)
                    elif 'pagerduty_dedup_keys' in scan_records[0]:
                        for dedup_key in scan_records[0]['pagerduty_dedup_keys']['SS']:
                            updated_incident_ids.append(dedup_key)
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                updated_incident_ids.append(alerts_handler.handler('s3_public_object_message', alert_args, email_messenger, slack_bot))
                if not S3BucketsData(s3_buckets_table_name).store(helper.account_id, helper.region, bucket_name, is_bucket_encrypted, is_public_bucket, True, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                    LOGGER.error("Could not add metadata for S3 Bucket %s in Account=%s and Region=%s", bucket_name, helper.account_id, helper.region)
            else:
                LOGGER.info("S3 Object not Public")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("S3 Object not added for some reason")
