import json
from utils.sts import DecodeMessage
from utils.ec2 import EC2
from utils.ssm import SSM
from utils.events import Events
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, disable_finding_for_unencrypted_ebs_volume, unencrypted_ebs_volume_creation_blocked, unencrypted_ebs_volume_creation_blocked_bypass_tag_key, alert_on_unencrypted_ebs_volume_creation_bypass, aws_service_deployment_action, project_name, tag_ebs_volumes, tag_ebs_volumes_using_tag_template_for_tf_deployment, tags_key_value_ebs_volumes, send_missing_tags_notification_ebs_volumes, target_arn, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    azure_data = {
        "AccountID": helper.account_id,
        "AccountName": messenger.account_name,
        "Region": helper.region,
        "User": helper.iam_user
    }

    if 'errorCode' in event and 'errorMessage' in event and event['errorCode'] == 'Client.UnauthorizedOperation':
        severity = 'Informational'
        alert_args = {
            "severity": severity,
            "iam_user": helper.iam_user,
            "resource_type": 'EBS Volume',
            "is_unencrypted": True,
            "bypass_tag_key": unencrypted_ebs_volume_creation_blocked_bypass_tag_key,
            "is_missing_tags": False,
            "scp_tags": []
        }
        azure_data['Severity'] = severity
        azure_data['Event'] = f"User {helper.iam_user} tried to created an EBS Volume without encryption enabled which was blocked by a service control policy."
        encoded_error_message = event['errorMessage'].split(': ')[-1].strip()
        scp_blocked_creation = False
        if not encoded_error_message.endswith('...'):
            try:
                active_session = helper.get_active_session()
                decoded_message = DecodeMessage(active_session, encoded_error_message).decoded_message
                LOGGER.debug(decoded_message)
                if len(decoded_message['matchedStatements']['items']) > 0:
                    for item in decoded_message['matchedStatements']['items']:
                        if 'statementId' in item:
                            if 'VolumeWithoutEncryption' in item['statementId']:
                                scp_blocked_creation = True
            except Exception as error:
                LOGGER.error(str(error))
        elif encoded_error_message.endswith('...'):
            if unencrypted_ebs_volume_creation_blocked:
                LOGGER.debug("EBS Volume Creation Failed Because of SCP, but could not decode encoded error message in CloudTrail API because it got truncated, as it can only consist of 1024B")
                scp_blocked_creation = True

        if scp_blocked_creation:
            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('ebs_vol_rds_creation_without_encryption_missing_tags_scp_block_error_message', alert_args, email_messenger, slack_bot)
        else:
            LOGGER.info("EBS Volume creation didn't fail because of SCP")

    elif 'errorCode' not in event and 'responseElements' in event:
        response_elements = event['responseElements']
        found_encrypted_ebs_bypass_tag = False
        try:
            active_session = helper.get_active_session()
            ec2_utils = EC2(active_session, helper.region)
            ssm_utils = SSM(active_session, helper.region)
            events_utils = Events(helper.account_id, helper.region)
            volume_id = response_elements['volumeId']
            is_vol_encrypted = response_elements['encrypted']
            found_tf_deploy_method = False
            is_tf_deployment = False
            volume_tag_keys = []
            service_bypassed_scp = False
            if 'tagSet' in response_elements and 'items' in response_elements['tagSet']:
                for tag in response_elements['tagSet']['items']:
                    volume_tag_keys.append(tag['key'])
                    if tag['key'] == unencrypted_ebs_volume_creation_blocked_bypass_tag_key:
                        found_encrypted_ebs_bypass_tag = True
                    if tag['key'] in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                        if tag['value'] in ['Terraform','terraform']:
                            found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if not is_vol_encrypted:
                if helper.is_invoked_by_service is not None:
                    if unencrypted_ebs_volume_creation_blocked and not found_encrypted_ebs_bypass_tag:
                        service_bypassed_scp = True
                else:
                    severity = 'Informational' if found_encrypted_ebs_bypass_tag else 'High'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "volume_id": volume_id,
                        "found_bypass_tag": found_encrypted_ebs_bypass_tag
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} created an EBS Volume with ID {volume_id} without encryption enabled{' against SCP applied on your Organization using bypass tag' if found_encrypted_ebs_bypass_tag else ''}"
                    if not disable_finding_for_unencrypted_ebs_volume:
                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alert_id = None
                        if unencrypted_ebs_volume_creation_blocked and found_encrypted_ebs_bypass_tag and alert_on_unencrypted_ebs_volume_creation_bypass:
                            alert_id = 'unencrypted_volume_creation_bypass_tag_message'
                        elif not unencrypted_ebs_volume_creation_blocked:
                            alert_id = 'unencrypted_volume_creation_bypass_tag_message'
                        alerts_handler.handler(alert_id, alert_args, email_messenger, slack_bot)

            if tag_ebs_volumes:
                use_params_tags = True
                if tag_ebs_volumes_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/EBS_VOLUME_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not ec2_utils.add_tags_to_ec2_resource(volume_id, [{'Key': key, 'Value': value}]):
                                LOGGER.error("Could not add tag %s to EBS Volume %s in Account=%s and Region=%s", key, volume_id, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_ebs_volumes:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in volume_tag_keys:
                            if not ec2_utils.add_tags_to_ec2_resource(volume_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to EBS Volume %s in Account=%s and Region=%s", key_value[0], volume_id, helper.account_id, helper.region)

            if send_missing_tags_notification_ebs_volumes and not tag_ebs_volumes:
                volume_tags_key_value_missing = []
                for tag in tags_key_value_ebs_volumes:
                    tag_key = tag.split('=')[0]
                    if tag_key not in volume_tag_keys:
                        volume_tags_key_value_missing.append(tag)
                if volume_tags_key_value_missing:
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": "EBS Volume",
                        "resource_id": volume_id,
                        "tags": volume_tags_key_value_missing
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} created an EBS Volume with ID {volume_id} without proper tags"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("Volume was created with proper tags")

            if helper.is_invoked_by_service is not None:
                if service_bypassed_scp and aws_service_deployment_action == 'Delete':
                    severity = 'High'
                    alert_args = {
                        "severity": severity,
                        "volume": volume_id,
                        "service": helper.is_invoked_by_service,
                        "action": aws_service_deployment_action
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, False, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('unencrypted_ebs_vol_creation_invoked_by_aws_service_action_message', alert_args, None, slack_bot)
                    if not events_utils.create_10_min_delete_scp_bypassed_resource_rule(volume_id, target_arn):
                        LOGGER.error("Could not create 10 min scheduler for deletion of scp bypassed resource %s", volume_id)
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("EBS Volume was not created for some reason")
