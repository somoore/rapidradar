from utils.iam import IAM
from utils.ec2 import EC2
from utils.utility import AWSHelper, Helper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, active_regions, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, ec2_instance_iam_role_detection_bypass_tag_key, auto_remediate_over_permissive_roles, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    active_session = helper.get_active_session()
    ec2_utils = EC2(active_session, helper.region)
    iam_utils = IAM(active_session)
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)

    if 'errorCode' not in event and 'requestParameters' in event and 'roleName' in event['requestParameters']:
        request_params = event['requestParameters']
        try:
            role_name = request_params['roleName']
            is_role_attached_to_ec2, instances = ec2_utils.is_role_attached_to_ec2(helper.account_id, active_regions, role_name)
            if is_role_attached_to_ec2:
                is_role_policy_overly_permissive = Helper().is_role_policy_overly_permissive(request_params['policyDocument'])
                if is_role_policy_overly_permissive:
                    azure_data = {
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user
                    }
                    if not iam_utils.found_iam_role_bypass_tag(role_name, ec2_instance_iam_role_detection_bypass_tag_key):
                        email_resources_block = []
                        alert_resources_block = []
                        for region, instance_ids in instances.items():
                            if len(instance_ids) > 0:
                                email_resources_block.append(f"<b>Instances in Region {region}</b>")
                                email_resources_block.append(f"<b>Instance ID(s):</b> {', '.join(instance_ids)}")
                                email_resources_block.append("<br>")

                                if notification_app == 'slack':
                                    alert_resources_block = [str(item).replace("<b>", "*").replace("</b>", "*").replace("<br>","") for item in email_resources_block]
                                elif notification_app == 'msteams':
                                    alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**").replace("<br>","\n") for item in email_resources_block]
                                elif notification_app == 'googlechat':
                                    alert_resources_block = email_resources_block
                        if auto_remediate_over_permissive_roles:
                            if not iam_utils.delete_role_policy(role_name, request_params['policyName']):
                                LOGGER.error("Could not delete IAM Role Policy %s from IAM Role %s", request_params['policyName'], role_name)
                            else:
                                if len(email_resources_block) > 0:
                                    del email_resources_block[-1]
                                    severity = 'Informational'
                                    alert_args = {
                                        "severity": severity,
                                        "iam_user": helper.iam_user,
                                        "role_name": role_name,
                                        "resources": alert_resources_block,
                                        "policy_name": request_params['policyName']
                                    }
                                    azure_data['Severity'] = severity
                                    azure_data['Event'] = f"User {helper.iam_user} created/attached an over-permissive policy named {request_params['policyName']} to IAM Role {role_name} which is attached to EC2 Instance. The policy has been detached by our threatOps automation"
                                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                    alerts_handler.handler('overpermissive_role_policy_deleted_message', alert_args, email_messenger, slack_bot)
                                else:
                                    LOGGER.info("no resource found")
                        else:
                            if len(email_resources_block) > 0:
                                del email_resources_block[-1]
                                severity = 'Critical'
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "role_name": role_name,
                                    "resources": alert_resources_block,
                                    "policy_name": request_params['policyName']
                                }
                                azure_data['Severity'] = severity
                                azure_data['Event'] = f"User {helper.iam_user} created/attached an over-permissive policy named {request_params['policyName']} to IAM Role {role_name} which is attached to EC2 Instance"
                                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                alerts_handler.handler('overpermissive_role_policy_attached_message', alert_args, email_messenger, slack_bot)
                            else:
                                LOGGER.info("no resource found")
                    else:
                        email_resources_block = []
                        alert_resources_block = []
                        for region, instance_ids in instances.items():
                            if len(instance_ids) > 0:
                                email_resources_block.append(f"<b>Instances in Region {region}</b>")
                                email_resources_block.append(f"<b>Instance IDs:</b> {', '.join(instance_ids)}")
                                email_resources_block.append("<br>")

                                if notification_app == 'slack':
                                    alert_resources_block = [str(item).replace("<b>", "*").replace("</b>", "*").replace("<br>","") for item in email_resources_block]
                                elif notification_app == 'msteams':
                                    alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**").replace("<br>","\n") for item in email_resources_block]
                                elif notification_app == 'googlechat':
                                    alert_resources_block = email_resources_block
                        if len(email_resources_block) > 0:
                            del email_resources_block[-1]
                            severity = 'Low'
                            alert_args = {
                                "severity": severity,
                                "iam_user": helper.iam_user,
                                "role_name": role_name,
                                "resources": alert_resources_block,
                                "policy_name": request_params['policyName']
                            }
                            azure_data['Severity'] = severity
                            azure_data['Event'] = f"User {helper.iam_user} created/attached an over-permissive policy {request_params['policyName']} to IAM Role {role_name} which is attached to EC2 Instance. But, this policy was not deleted/detached because Admin has used bypass tag on IAM Role"
                            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('overpermissive_role_policy_bypass_message', alert_args, email_messenger, slack_bot)
                        else:
                            LOGGER.info("no resource found")
                else:
                    LOGGER.info("Policy not over-permissive")
            else:
                LOGGER.info("Not Attached to any EC2 Instance")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Policy was not attached for some reason")
