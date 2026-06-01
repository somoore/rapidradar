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

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, eip_allocation_blocked, eip_allocation_blocked_bypass_tag_key, alert_on_eip_allocation_bypass, project_name, tag_eip, tag_eip_using_tag_template_for_tf_deployment, tags_key_value_eip, send_missing_tags_notification_eip, aws_service_deployment_action, target_arn, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
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
    if 'errorCode' not in event and 'responseElements' in event and 'requestParameters' in event:
        response_elements = event['responseElements']
        request_params = event['requestParameters']
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        ssm_utils = SSM(active_session, helper.region)
        events_utils = Events(helper.account_id, helper.region)
        try:
            eip_allocation_id = response_elements['allocationId']
            found_tf_deploy_method = False
            is_tf_deployment = False
            eip_tag_keys = []
            found_bypass_tag = False

            if 'tagSpecificationSet' in request_params and 'items' in request_params['tagSpecificationSet']:
                for item in request_params['tagSpecificationSet']['items']:
                    if item['resourceType'] == 'elastic-ip':
                        for tag in item['tags']:
                            eip_tag_keys.append(tag['key'])
                            if tag['key'] == eip_allocation_blocked_bypass_tag_key:
                                found_bypass_tag = True
                            if tag['key'] in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                                if tag['value'] in ['Terraform','terraform']:
                                    found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if helper.is_invoked_by_service is not None:
                if eip_allocation_blocked and not found_bypass_tag and aws_service_deployment_action == 'Delete':
                    severity = 'High'
                    alert_args = {
                        "severity": severity,
                        "allocation_id": eip_allocation_id,
                        "service": helper.is_invoked_by_service,
                        "action": aws_service_deployment_action
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, False, {}, None, None, None)
                    alerts_handler.handler('eip_allocation_invoked_by_aws_service_action_message', alert_args, None, None)
                    if not events_utils.create_10_min_delete_scp_bypassed_resource_rule(eip_allocation_id, target_arn):
                        LOGGER.error("Could not create 10 min scheduler for deletion of scp bypassed resource %s", eip_allocation_id)
            else:
                if eip_allocation_blocked and found_bypass_tag and alert_on_eip_allocation_bypass:
                    severity = 'Informational'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "allocation_id": eip_allocation_id
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} allocated an Elastic IP with ID {eip_allocation_id} against SCP applied on your Organization using bypass tag"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('eip_allocation_bypass_tag_message', alert_args, email_messenger, slack_bot)

            if tag_eip:
                use_params_tags = True
                if tag_eip_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/ELASTIC_IP_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not ec2_utils.add_tags_to_ec2_resource(eip_allocation_id, [{'Key': key, 'Value': value}]):
                                LOGGER.error("Could not add tag %s to EIP %s in Account=%s and Region=%s", key, eip_allocation_id, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_eip:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in eip_tag_keys:
                            if not ec2_utils.add_tags_to_ec2_resource(eip_allocation_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to EIP %s in Account=%s and Region=%s", key_value[0], eip_allocation_id, helper.account_id, helper.region)

            if send_missing_tags_notification_eip and not tag_eip:
                eip_tags_key_value_missing = []
                for tag in tags_key_value_eip:
                    tag_key = tag.split('=')[0]
                    if tag_key not in eip_tag_keys:
                        eip_tags_key_value_missing.append(tag)
                if eip_tags_key_value_missing:
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": "Elastic IP",
                        "resource_id": eip_allocation_id,
                        "tags": eip_tags_key_value_missing
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} allocated an Elastic IP with ID {eip_allocation_id} without proper tags"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("EIP was allocated with proper tags")
        except Exception as error:
            LOGGER.error(str(error))

    elif 'errorCode' in event and 'errorMessage' in event and event['errorCode'] == 'Client.UnauthorizedOperation':
        severity = 'Informational'
        alert_args = {
            "severity": severity,
            "iam_user": helper.iam_user
        }
        azure_data['Severity'] = severity
        azure_data['Event'] = f"User {helper.iam_user} tried to allocate an Elastic IP but it was blocked due to explicit deny in a service control policy"
        scp_blocked_creation = False
        encoded_error_message = event['errorMessage'].split(': ')[-1].strip()
        if not encoded_error_message.endswith('...'):
            active_session = helper.get_active_session()
            decoded_message = DecodeMessage(active_session, encoded_error_message).decoded_message
            LOGGER.debug(decoded_message)
            for item in decoded_message['matchedStatements']['items']:
                if 'statementId' in item and 'BypassTag' in item['statementId']:
                    scp_blocked_creation = True

        elif encoded_error_message.endswith('...'):
            if eip_allocation_blocked:
                LOGGER.debug("EIP Allocation Failed Because of SCP, but could not decode encoded error message in CloudTrail API because it got truncated, as it can only consist of 1024B")
                scp_blocked_creation = True

        if scp_blocked_creation:
            alerts_handler = Alert(None, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('eip_allocation_scp_block_error_message', alert_args, email_messenger, slack_bot)
        else:
            LOGGER.info("Allocation didn't fail because of SCP")
    else:
        LOGGER.info("EIP was not allocated for some reason")
