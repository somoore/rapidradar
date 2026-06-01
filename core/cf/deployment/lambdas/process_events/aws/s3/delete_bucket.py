from utils.dynamodb import (
    RemediatedResourcesData,
    GetData,
    DeleteData
)
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.slack_bot import SlackBot
from pagerduty.main import PagerDuty

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, s3_buckets_table_name, remediated_table_name, create_incidents_on_pagerduty, is_pd_integration_type_restapi, pagerduty_routing_key, pagerduty_api_token, pagerduty_service_id, pagerduty_user_email_address):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    if 'errorCode' not in event and 'requestParameters' in event:
        request_params = event['requestParameters']
        try:
            bucket_name = request_params['bucketName']

            scan_records = GetData(s3_buckets_table_name).get_by_id('account_id', helper.account_id, 's3_bucket_name', bucket_name)
            if scan_records:
                if create_incidents_on_pagerduty:
                    pagerduty_helper = PagerDuty(
                        helper.account_id,
                        messenger.account_name,
                        helper.region,
                        is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                        routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                        api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                        service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                        from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                    if 'pagerduty_incident_id' in scan_records[0]:
                        for incident_id in scan_records[0]['pagerduty_incident_id']['SS']:
                            pagerduty_helper.resolve_incident(incident_id)
                    elif 'pagerduty_dedup_keys' in scan_records[0]:
                        for dedup_key in scan_records[0]['pagerduty_dedup_keys']['SS']:
                            pagerduty_helper.resolve_incident(dedup_key)

                if not DeleteData(s3_buckets_table_name).delete('account_id', helper.account_id, 's3_bucket_name', bucket_name):
                    LOGGER.error("Could not delete metadata for S3 Bucket %s from DynamoDB Table", bucket_name)
                if not RemediatedResourcesData(remediated_table_name).store(helper.account_id, helper.region, bucket_name, 'Public S3 Bucket'):
                    LOGGER.error("Could not add metadata for S3 Bucket %s to remediated DynamoDB Table", bucket_name)

                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "bucket_name": bucket_name
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user,
                    "Event": f"User {helper.iam_user} deleted Public S3 Bucket named {bucket_name} and the finding has been remediated"
                }
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('s3_public_bucket_deletion_remediation_message', alert_args, None, slack_bot)
            else:
                LOGGER.info("Bucket not found in DynamoDB Table")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("S3 Bucket not delete for some reason")
