from time import sleep
from utils.ec2 import EC2
from utils.iam import IAM
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, event, event_name, notification_app, webhook_urls, project_name, auto_attach_iam_role_ec2, auto_attach_missing_policies, ec2_ssm_iam_role_name, additional_policies_names, create_new_managed_policy, managed_policy_name, enable_ec2_instance_configurator, send_logs_to_azure, customer_id, shared_key, log_type, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'responseElements' in event:
        response_elements = event['responseElements']
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        iam_utils = IAM(active_session)
        association_details = {}

        if 'AssociateIamInstanceProfileResponse' in response_elements:
            association_details = response_elements['AssociateIamInstanceProfileResponse']['iamInstanceProfileAssociation']
        elif 'ReplaceIamInstanceProfileAssociationResponse' in response_elements:
            association_details = response_elements['ReplaceIamInstanceProfileAssociationResponse']['iamInstanceProfileAssociation']
        elif 'DisassociateIamInstanceProfileResponse' in response_elements:
            association_details = response_elements['DisassociateIamInstanceProfileResponse']['iamInstanceProfileAssociation']

        instance_id = association_details['instanceId']
        attached_instance_profile = association_details['iamInstanceProfile']['arn']
        profile_name = attached_instance_profile.split('/')[1]
        auto_manage_role = False if ec2_ssm_iam_role_name else True
        managed_role_name = f'{project_name}-managed-ec2-ssm-role'
        existing_role_name = ec2_ssm_iam_role_name
        custom_managed_policy_arn = ''
        if create_new_managed_policy and enable_ec2_instance_configurator:
            custom_managed_policy_arn = iam_utils.get_custom_policy_arn(helper.account_id, managed_policy_name)

        additional_policies_arns = iam_utils.get_policy_arns(additional_policies_names)
        if event_name in ['AssociateIamInstanceProfile', 'ReplaceIamInstanceProfileAssociation']:
            LOGGER.info("IAM Instance Profile %s got attached to EC2 Instance %s in Account=%s Region=%s", attached_instance_profile, instance_id, helper.account_id, helper.region)
            if auto_attach_missing_policies:
                LOGGER.info("...Checking whether IAM Instance Profile %s has required policies attached to it", attached_instance_profile)
                iam_utils.attach_missing_role_policies(profile_name, additional_policies_arns, custom_managed_policy_arn)
        elif event_name == 'DisassociateIamInstanceProfile':
            LOGGER.info("IAM Instance Profile %s got detached from EC2 Instance %s in Account=%s Region=%s", attached_instance_profile, instance_id, helper.account_id, helper.region)
            if auto_attach_iam_role_ec2:
                LOGGER.info("...Attaching IAM Role to EC2 Instance %s", instance_id)
                instance_profile_arn = iam_utils.check_role(custom_managed_policy_arn, auto_manage_role, managed_role_name, existing_role_name, additional_policies_arns)
                if instance_profile_arn:
                    sleep(10)
                    ec2_utils.attach_managed_role_to_ec2(instance_id, instance_profile_arn)
                    severity = 'Informational'
                    alert_args = {
                        "severity": severity,
                        "role_name": managed_role_name if auto_manage_role else existing_role_name,
                        "ec2_instances": [instance_id]
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": "threatOps",
                        "Event": f"An IAM role was disassociated from EC2 instance(s) [{', '.join([instance_id])}] and IAM Role named {managed_role_name if auto_manage_role else existing_role_name} with required policies has been associated to this EC2 instance to ensure proper access and security controls are maintained"
                    }
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('ec2_instance_profile_auto_remediated', alert_args, None, None)
