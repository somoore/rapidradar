from utils.ec2 import EC2
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, eip_association_override_tag_key_base64, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'requestParameters' in event:
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
        active_session = helper.get_active_session()
        ec2_client = EC2(active_session, helper.region)

        request_params = event['requestParameters']
        try:
            eip_allocation_id = request_params['allocationId']
            severity = 'Low'
            azure_data = {
                "Severity": severity,
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user
            }
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "eip_allocation_id": eip_allocation_id,
                "override_tag_key": eip_association_override_tag_key_base64
            }
            if 'networkInterfaceId' in request_params:
                resource_id = request_params['networkInterfaceId']
                found_override_tag, is_value_base64_encoded = ec2_client.found_override_tag(resource_id, 'network-interface', eip_association_override_tag_key_base64)
                alert_args['resource_id'] = resource_id
                alert_args['resource_type'] = 'Network Interface'
                alert_args['found_override_tag'] = found_override_tag
                alert_args['is_value_base64_encoded'] = is_value_base64_encoded
                if not found_override_tag:
                    azure_data['Event'] = f"User {helper.iam_user} associated Elastic IP with ID {eip_allocation_id} to Network Interface with ID {resource_id} missing proper tags"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('eip_association_without_override_tag_message', alert_args, email_messenger, slack_bot)
                elif found_override_tag and not is_value_base64_encoded:
                    azure_data['Event'] = f"User {helper.iam_user} associated Elastic IP with ID {eip_allocation_id} to Network Interface with ID {resource_id} with invalid value for tag {eip_association_override_tag_key_base64}"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('eip_association_without_override_tag_message', alert_args, email_messenger, slack_bot)
            elif 'instanceId' in request_params:
                resource_id = request_params['instanceId']
                found_override_tag = False
                is_value_base64_encoded = False
                network_interfaces = ec2_client.get_instance_network_interfaces(resource_id)
                for interface in network_interfaces:
                    found_override_tag, is_value_base64_encoded = ec2_client.found_override_tag(interface['NetworkInterfaceId'], 'network-interface', eip_association_override_tag_key_base64)
                alert_args['resource_id'] = resource_id
                alert_args['resource_type'] = 'Network Interface of this EC2 Instance'
                alert_args['found_override_tag'] = found_override_tag
                alert_args['is_value_base64_encoded'] = is_value_base64_encoded
                if not found_override_tag:
                    azure_data['Event'] = f"User {helper.iam_user} associated Elastic IP with ID {eip_allocation_id} to Network Interface of EC2 Instance {resource_id} missing proper tags"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('eip_association_without_override_tag_message', alert_args, email_messenger, slack_bot)
                elif found_override_tag and not is_value_base64_encoded:
                    azure_data['Event'] = f"User {helper.iam_user} associated Elastic IP with ID {eip_allocation_id} to Network Interface of EC2 Instance {resource_id} with invalid value for tag {eip_association_override_tag_key_base64}"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('eip_association_without_override_tag_message', alert_args, email_messenger, slack_bot)
            else:
                LOGGER.info("EIP was associated with tags")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("EIP was not associated for some reason")
