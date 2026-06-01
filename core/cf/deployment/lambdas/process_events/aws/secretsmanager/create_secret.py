import json
from utils.secretsmanager import SecretsManager
from utils.ssm import SSM
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, sender_email, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, project_name, tag_secrets, tag_secrets_using_tag_template_for_tf_deployment, tags_key_value_secrets, send_missing_tags_notification_secrets, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'responseElements' in event and 'requestParameters' in event:
        active_session = helper.get_active_session()
        secretsmanager_utils = SecretsManager(active_session, helper.region)
        ssm_utils = SSM(active_session, helper.region)
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

        response_elements = event['responseElements']
        request_params = event['requestParameters']
        try:
            secret_name = request_params['name']
            secret_arn = response_elements['arn']
            found_tf_deploy_method = False
            is_tf_deployment = False
            secret_tag_keys = []

            secret_tags = secretsmanager_utils.get_secrets_tags(secret_arn)
            if isinstance(secret_tags, list):
                for tag in secret_tags:
                    secret_tag_keys.append(tag['Key'])
                    if tag['Key'] in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                        if tag['Value'] in ['Terraform','terraform']:
                            found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if tag_secrets:
                use_params_tags = True
                if tag_secrets_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/SECRETS_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not secretsmanager_utils.tag_secret(secret_arn, [{'Key': key, 'Value': value}]):
                                LOGGER.error("Could not add tag %s to Secret %s in Account=%s and Region=%s", key, secret_arn, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_secrets:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in secret_tag_keys:
                            if not secretsmanager_utils.tag_secret(secret_arn, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to Secret %s in Account=%s and Region=%s", key_value[0], secret_arn, helper.account_id, helper.region)

            if send_missing_tags_notification_secrets and not tag_secrets:
                secret_tags_key_value_missing = []
                for tag in tags_key_value_secrets:
                    tag_key = tag.split('=')[0]
                    if tag_key not in secret_tag_keys:
                        secret_tags_key_value_missing.append(tag)
                if not all(value in secret_tag_keys for value in tags_key_value_secrets):
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "secret_name": secret_name,
                        "secret_arn": secret_arn,
                        "tags": secret_tags_key_value_missing
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                        "Event": f"User {helper.iam_user} created a SecretsManager Secret named {secret_name} without proper tags"
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('secret_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("Secret was created with proper tags")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Secret creation failed for some reason")
