import json
from utils.ec2 import EC2
from utils.ssm import SSM
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, project_name, tag_ebs_snapshots, tag_ebs_snapshots_using_tag_template_for_tf_deployment, tags_key_value_ebs_snapshots, send_missing_tags_notification_ebs_snapshots, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'responseElements' in event:
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

        response_elements = event['responseElements']
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        ssm_utils = SSM(active_session, helper.region)
        try:
            snapshot_id = response_elements['snapshotId']
            found_tf_deploy_method = False
            is_tf_deployment = False
            snapshot_tag_keys = []

            if 'tagSet' in response_elements and 'items' in response_elements['tagSet']:
                for tag in response_elements['tagSet']['items']:
                    snapshot_tag_keys.append(tag['key'])
                    if tag['key'] in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                        if tag['value'] in ['Terraform','terraform']:
                            found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if tag_ebs_snapshots:
                use_params_tags = True
                if tag_ebs_snapshots_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/EBS_SNAPSHOT_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not ec2_utils.add_tags_to_ec2_resource(snapshot_id, [{'Key': key, 'Value': value}]):
                                LOGGER.error("Could not add tag %s to EBS Snapshot %s in Account=%s and Region=%s", key, snapshot_id, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_ebs_snapshots:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in snapshot_tag_keys:
                            if not ec2_utils.add_tags_to_ec2_resource(snapshot_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to EBS Snapshot %s in Account=%s and Region=%s", key_value[0], snapshot_id, helper.account_id, helper.region)

            if send_missing_tags_notification_ebs_snapshots and not tag_ebs_snapshots:
                snapshot_tags_key_value_missing = []
                for tag in tags_key_value_ebs_snapshots:
                    tag_key = tag.split('=')[0]
                    if tag_key not in snapshot_tag_keys:
                        snapshot_tags_key_value_missing.append(tag)
                if snapshot_tags_key_value_missing:
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": "EBS Snapshot",
                        "resource_id": snapshot_id,
                        "tags": snapshot_tags_key_value_missing
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                        "Event": f"User {helper.iam_user} created Snapshot {snapshot_id} of an EBS Volume without proper tags"
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("Snapshot was created with proper tags")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Snapshot was not created for some reason")
