from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from utils.ec2 import EC2
from utils.iam import IAM
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, active_regions, event, notification_app, webhook_urls, additional_policies_names, create_new_managed_policy, managed_policy_name, enable_ec2_instance_configurator, send_logs_to_azure, customer_id, shared_key, log_type, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    if 'errorCode' not in event and 'requestParameters' in event:
        automation_policy_detached = False
        request_params = event['requestParameters']
        role_name = request_params['roleName']
        policy_arn = request_params['policyArn']
        policy_name = policy_arn.split('/')[-1]
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        iam_utils = IAM(active_session)
        additional_policies_arns = iam_utils.get_policy_arns(additional_policies_names)

        if policy_arn in additional_policies_arns or policy_name in ['AmazonSSMManagedInstanceCore', 'AmazonSSMManagedEC2InstanceDefaultPolicy']:
            automation_policy_detached = True

        role_instance_profiles = iam_utils.get_role_instance_profiles_arns(role_name)
        if role_instance_profiles:
            associated_instances = ec2_utils.role_associated_instances(role_instance_profiles, helper.account_id, active_regions)
            if associated_instances and automation_policy_detached:
                custom_managed_policy_arn = ''
                if create_new_managed_policy and enable_ec2_instance_configurator:
                    custom_managed_policy_arn = iam_utils.get_custom_policy_arn(helper.account_id, managed_policy_name)
                LOGGER.info("Policy named %s got detached from IAM Role associated to EC2 Instance(s) %s. Attaching again...", policy_name, ', '.join(associated_instances))
                iam_utils.attach_policies(role_name, additional_policies_arns, custom_managed_policy_arn)
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "role_name": role_name,
                    "policy": policy_name,
                    "ec2_instances": associated_instances
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user,
                    "Event": f"IAM role named {role_name} associated with EC2 instance(s) [{', '.join(associated_instances)}] had certain policies detached but the policies have been re-attached to ensure proper access and security controls are maintained."
                }
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('iam_role_auto_remediation', alert_args, None, None)
