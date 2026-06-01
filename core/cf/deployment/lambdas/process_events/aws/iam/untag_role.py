from utils.ec2 import EC2
from utils.iam import IAM
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, active_regions, event, notification_app, webhook_urls, send_logs_to_azure, customer_id, shared_key, log_type, ec2_instance_iam_role_detection_bypass_tag_key, auto_remediate_over_permissive_roles, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)

    if 'errorCode' not in event and 'requestParameters' in event and 'roleName' in event['requestParameters']:
        active_session = helper.get_active_session()
        iam_utils = IAM(active_session)
        ec2_utils = EC2(active_session, helper.region)
        request_params = event['requestParameters']

        detached_role_policies = []
        deleted_role_policies = []
        try:
            role_name = request_params['roleName']
            is_role_attached_to_ec2, instances = ec2_utils.is_role_attached_to_ec2(helper.account_id, active_regions, role_name)
            if is_role_attached_to_ec2:
                attached_role_policies = iam_utils.overly_permissive_attached_role_policies(role_name)
                role_policies = iam_utils.overly_permissive_inline_role_policies(role_name)
                if not attached_role_policies and not role_policies:
                    LOGGER.info("No Over-Permissive Policies Found for IAM Role %s", role_name)
                elif not iam_utils.found_iam_role_bypass_tag(role_name, ec2_instance_iam_role_detection_bypass_tag_key):
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
                                alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**") for item in email_resources_block]
                            elif notification_app == 'googlechat':
                                alert_resources_block = email_resources_block
                    if auto_remediate_over_permissive_roles:
                        for policy in role_policies:
                            if not iam_utils.delete_role_policy(role_name, policy):
                                LOGGER.error("Could not delete IAM Role Policy %s from IAM Role %s", policy, role_name)
                            else:
                                deleted_role_policies.append(policy)
                        for policy in attached_role_policies:
                            if not iam_utils.detach_role_policy(role_name, policy):
                                LOGGER.error("Could not detach IAM Role Policy %s from IAM Role %s", policy, role_name)
                            else:
                                detached_role_policies.append(policy)
                        if len(email_resources_block) > 0:
                            del email_resources_block[-1]
                            severity = 'Informational'
                            alert_args = {
                                "severity": severity,
                                "role_name": role_name,
                                "resources": alert_resources_block,
                                "detached_policies": detached_role_policies,
                                "deleted_policies": deleted_role_policies
                            }
                            azure_data = {
                                "Severity": severity,
                                "AccountID": helper.account_id,
                                "AccountName": messenger.account_name,
                                "Region": helper.region,
                                "User": helper.iam_user,
                                "Event": f"A scan was run on IAM Role named {role_name} after the user {helper.iam_user} removed bypass tag from it. Following policies were deleted/detached from IAM Role: [{', '.join(detached_role_policies)} {', '.join(deleted_role_policies)}]"
                            }
                            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('overpermissive_role_policies_deleted_message', alert_args, None, None)
                    else:
                        LOGGER.info("Auto-remediation disabled")
                else:
                    LOGGER.info("Found Bypass Tag")
            else:
                LOGGER.info("Not attached to any EC2 Instance")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Tags were not deleted from IAM Role for some reason")
