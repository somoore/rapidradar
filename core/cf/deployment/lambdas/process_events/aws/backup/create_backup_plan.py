import json
from utils.backup import Backup
from utils.ssm import SSM
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, sender_email, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, project_name, tag_backup_plans, tag_backup_plans_using_tag_template_for_tf_deployment, tags_key_value_backup_plans, send_missing_tags_notification_backup_plans, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'responseElements' in event and 'requestParameters' in event and 'backupPlan' in event['requestParameters']:
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

        response_elements = event['responseElements']
        request_params = event['requestParameters']
        try:
            active_session = helper.get_active_session()
            backup_utils = Backup(active_session, helper.region)
            ssm_utils = SSM(active_session, helper.region)
            backup_plan_name = request_params['backupPlan']['backupPlanName']
            backup_plan_arn = response_elements['backupPlanArn']
            found_tf_deploy_method = False
            is_tf_deployment = False

            backup_plan_tags = backup_utils.get_backup_plan_tags(backup_plan_arn)
            for key, value in backup_plan_tags.items():
                if key in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                    if value in ['Terraform','terraform']:
                        found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if tag_backup_plans:
                use_params_tags = True
                if tag_backup_plans_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/BACKUP_PLAN_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not backup_utils.tag_backup_plan(backup_plan_arn, {key: value}):
                                LOGGER.error("Could not add tag %s to Backup Plan %s in Account=%s and Region=%s", key, backup_plan_arn, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_backup_plans:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in backup_plan_tags.keys():
                            if not backup_utils.tag_backup_plan(backup_plan_arn, {key_value[0]: key_value[1]}):
                                LOGGER.error("Could not add tag %s to Backup Plan %s in Account=%s and Region=%s", key_value[0], backup_plan_arn, helper.account_id, helper.region)

            if send_missing_tags_notification_backup_plans and not tag_backup_plans:
                backup_tags_key_value_missing = []
                for tag in tags_key_value_backup_plans:
                    tag_key = tag.split('=')[0]
                    if tag_key not in backup_plan_tags.keys():
                        backup_tags_key_value_missing.append(tag)
                if not all(value in backup_plan_tags.keys() for value in tags_key_value_backup_plans):
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "backup_plan_name": backup_plan_name,
                        "backup_plan_arn": backup_plan_arn,
                        "tags": backup_tags_key_value_missing
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                        "Event": f"User {helper.iam_user} created a Backup Plan named {backup_plan_name} without proper tags"
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('backup_plan_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("Backup Plan was created with proper tags")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Backup Plan was not created for some reason")
