import json
from utils.ec2 import EC2
from utils.ssm import SSM
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, enable_vpc_flow_logs, log_archive_account_id, home_region, flowlogs_delivery_bucket_prefix, vpc_flow_log_tag_key_value, send_logs_to_azure, customer_id, shared_key, log_type, project_name, tag_vpc, tag_vpc_using_tag_template_for_tf_deployment, tags_key_value_vpc, send_missing_tags_notification_vpc, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'responseElements' in event and 'vpc' in event['responseElements']:
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        ssm_utils = SSM(active_session, helper.region)
        vpc_response_elements = event['responseElements']['vpc']

        try:
            vpc_id = vpc_response_elements['vpcId']
            found_tf_deploy_method = False
            is_tf_deployment = False
            vpc_tag_keys = []
            key_value = vpc_flow_log_tag_key_value.split('=')

            if 'tagSet' in vpc_response_elements and 'items' in vpc_response_elements['tagSet']:
                for item in vpc_response_elements['tagSet']['items']:
                    vpc_tag_keys.append(item['key'])
                    if item['key'] in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                        if item['value'] in ['Terraform','terraform']:
                            found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if not ec2_utils.add_tags_to_ec2_resource(vpc_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                LOGGER.error("Could not add VPC flowlog tag to VPC %s in Account=%s and Region=%s", vpc_id, helper.account_id, helper.region)

            if enable_vpc_flow_logs:
                traffic_type = (vpc_flow_log_tag_key_value.split('=')[-1]).upper()
                destination_arn = None
                if log_archive_account_id:
                    destination_arn = f"arn:aws:s3:::{flowlogs_delivery_bucket_prefix}-{log_archive_account_id}-{home_region}"
                else:
                    destination_arn = f"arn:aws:s3:::{flowlogs_delivery_bucket_prefix}-{helper.account_id}-{home_region}"
                print(f"destination_arn: {destination_arn}")
                if not ec2_utils.create_flow_logs(vpc_id, traffic_type, destination_arn):
                    LOGGER.error("Could not enable VPC Flow Logs for VPC '%s'", vpc_id)

            if tag_vpc:
                use_params_tags = True
                if tag_vpc_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/VPC_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not ec2_utils.add_tags_to_ec2_resource(vpc_id, [{'Key': key, 'Value': value}]):
                                LOGGER.error("Could not add tag %s to VPC %s in Account=%s and Region=%s", key, vpc_id, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_vpc:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in vpc_tag_keys:
                            if not ec2_utils.add_tags_to_ec2_resource(vpc_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to VPC %s in Account=%s and Region=%s", key_value[0], vpc_id, helper.account_id, helper.region)

            if send_missing_tags_notification_vpc and not tag_vpc:
                vpc_tags_key_value_missing = []
                for tag in tags_key_value_vpc:
                    tag_key = tag.split('=')[0]
                    if tag_key not in vpc_tag_keys:
                        vpc_tags_key_value_missing.append(tag)
                if vpc_tags_key_value_missing:
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": "EC2 VPC",
                        "resource_id": vpc_id,
                        "tags": vpc_tags_key_value_missing
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                        "Event": f"User {helper.iam_user} created a VPC with ID {vpc_id} without proper tags"
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("VPC was created with proper tags")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("VPC was not created for some reason")
