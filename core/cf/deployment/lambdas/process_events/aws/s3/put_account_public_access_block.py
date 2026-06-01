from utils.s3 import S3Control
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, auto_remediate, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    if 'errorCode' not in event and 'requestParameters' in event and 'PublicAccessBlockConfiguration' in event['requestParameters']:
        account_public_access_request_params = event['requestParameters']['PublicAccessBlockConfiguration']
        restrict_public_buckets = account_public_access_request_params.get('RestrictPublicBuckets', False)
        block_public_policy = account_public_access_request_params.get('BlockPublicPolicy', False)
        block_public_acls = account_public_access_request_params.get('BlockPublicAcls', False)
        ignore_public_acls = account_public_access_request_params.get('IgnorePublicAcls', False)

        if not restrict_public_buckets or not block_public_policy or not block_public_acls or not ignore_public_acls:
            azure_data = {
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user
            }
            if auto_remediate:
                active_session = helper.get_active_session()
                if not S3Control(active_session).enable_account_block_public_access(helper.account_id):
                    LOGGER.error("Could not enable S3 Account Public Access Block for Account %s", helper.account_id)
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user
                }
                azure_data['Severity'] = severity
                azure_data['Event'] = f"User {helper.iam_user} modified the S3 account block public access setting and disabled it. The change was automatically reverted and remediated and the setting is enabled again to ensure the security and compliance of our AWS account"
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('s3_account_public_access_auto_remediation_message', alert_args, email_messenger, slack_bot)
            else:
                severity = 'Critical'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user,
                    "restrict_public_buckets": restrict_public_buckets,
                    "block_public_policy": block_public_policy,
                    "block_public_acls": block_public_acls,
                    "ignore_public_acls": ignore_public_acls
                }
                azure_data['Severity'] = severity
                azure_data['Event'] = f"User {helper.iam_user} modified the S3 account block public access setting and disabled it. Restrict Public Buckets={restrict_public_buckets}, Block Public Policy={block_public_policy}, Block Public ACLs={block_public_acls}, Ignore Public ACLs={ignore_public_acls}"
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('s3_account_public_access_config_modification_message', alert_args, email_messenger, slack_bot)
        else:
            LOGGER.info("S3 Account Public Access Block Configuration is enabled")
    else:
        LOGGER.info("S3 Account Public Access Block Modification Failed for some reason")
