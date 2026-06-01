from typing import Optional
import re
import requests
from utils.sso_helper import SSOHelper
class SlackMessenger():
    def __init__(self, account_id, account_name, org_name, region):
        self.account_id = account_id
        self.account_name = account_name
        self.org_name = org_name
        self.region = region

    def get_message(self, alert_id, message_params):
        method = getattr(Messages(self.account_id, self.account_name, self.org_name, self.region), alert_id)
        return method(**message_params)

class Messages():
    def __init__(self, account_id, account_name, org_name, region):
        self.account_id = account_id
        self.account_name = account_name
        self.org_name = org_name
        self.region = region

    def __get_tags(self, tags):
        tags_msg = ''
        for tag in tags:
            if '=' in tag:
                key_value = tag.split('=')
                tags_msg += f'{key_value[0]}: {key_value[1]}\n'
            else:
                tags_msg += f'• {tag}\n'
        return tags_msg

    @staticmethod
    def __is_user_email(iam_user):
        match = re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', iam_user)
        if match is not None:
            return True
        return False

    @staticmethod
    def __get_formatted_json(text):
        return {
            "blocks": [{
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"{text}"
                }]
            }]
        }

    def __get_user_member_id(self, token, email):
        headers = { 'Content-Type': 'application/x-www-form-urlencoded', "Authorization": f"Bearer {token}" }
        if token:
            if not self.__is_user_email(email):
                sso_helper = SSOHelper()
                email = sso_helper.get_sso_user_email(iam_user=email)
            params = { 'email': email }
            try:
                response = requests.get("https://slack.com/api/users.lookupByEmail", headers=headers, params=params, timeout=30)
                if response.status_code // 100 == 2:
                    response_json = response.json()
                    if response_json['ok']:
                        return f"<@{response_json['user']['id']}>"
            except Exception as error:
                print(f"[ERROR] Failed to get Slack member ID against email {email}: {error}")
        return f"@{email.split('@')[0]}"

    @staticmethod
    def __get_sg_attachment_details(is_attached, attached_instances, attached_lb):
        attachment_details = []
        if attached_instances or attached_lb:
            attachment_details = []
            attachment_details.append("*Attachment Details:*")
            if len(attached_instances) > 0:
                instances_details = ''
                for instance in attached_instances:
                    instances_details += f"• {instance['ResourceId']} ({instance['Context']})\n"
                attachment_details.append(f"*EC2 Instance(s):*\n{instances_details}")
            if len(attached_lb) > 0:
                lb_details = ''
                for lb in attached_lb:
                    lb_details += f"• {lb['ResourceId']} ({lb['Context']})\n"
                attachment_details.append(f"*LoadBalancers(s):*\n{lb_details}")
        attachment_details = '\n'.join(attachment_details) if attachment_details else '*Attachment:* Currently Not Attached to Any Resource' if not is_attached else ''
        return attachment_details

    @staticmethod
    def __get_pagerduty_incidents_details(incidents: list):
        pagerduty_incidents_details = {}
        if len(incidents) > 0:
            pagerduty_incidents = []
            for incident in incidents:
                pagerduty_incidents.append(f"<{incident['IncidentUrl']}|{incident['IncidentNumber']}>")
            pagerduty_incidents_details = f"""
*PagerDuty Incidents:*
{', '.join(pagerduty_incidents)}"""
        return pagerduty_incidents_details

    def resource_creation_without_tags_message(self, severity, iam_user, resource_type, resource_id, tags, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{resource_type} Created Without Proper Tags!`*
User {slack_user_id} created {resource_type} *{resource_id}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Add Following Tags to {resource_type}:* ```{self.__get_tags(tags)}```"""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all(self, severity, iam_user, ip_protocol, port, security_group_id, security_group_rule_id, is_attached, attached_instances, attached_lb, is_critical, incident_number, incident_url, slack_token=None):
        remediation_message = 'Please Close Access to 0.0.0.0/0'
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        if is_attached and attached_instances:
            remediation_message = "Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."
        elif not is_attached:
            remediation_message = "Either Attach Security Group to a Resource or Delete it."
        remediation_block = f"*Remediation Recommendation:*\n{remediation_message}" if is_critical else ''

        message = f"""*[{severity}] {':heavy_exclamation_mark: `Security Group Ingress Open to Everyone!`' if is_critical else ':bell: Security Group Ingress Open to Everyone!'}*
User {slack_user_id} opened a {ip_protocol} port to *0.0.0.0/0* in Security Group Ingress in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Ingress Details:*
Security Group ID: {security_group_id}
Security Group Rule ID: {security_group_rule_id}
IP Protocol: {ip_protocol}
Port: {port}

{attachment_details}

{remediation_block}"""
        return self.__get_formatted_json(message)

    def critical_port_closed_message(self, severity, security_group_id, ip_protocol, port, slack_token=None):
        message = f"""*[{severity}] :white_check_mark:`Security Group Ingress Port {'Deleted' if port == '-1' else 'Closed'}!`*
{ip_protocol} port{'' if port == '-1' else f' {port}'} was open to the 0.0.0.0/0 IP range, which is against our company's security policy. Therefore, we have taken the necessary steps to {'delete' if port == '-1' else 'close'} this port to prevent unauthorized access to your resources with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Security Group ID: {security_group_id}

*Please note that in future, {'' if port == '-1' else f'to access resources over port {port}, '}you should either use SSM Session Manager or an ACL Inbound rule with your IP address/32. These are both secure methods for accessing resources over the internet and will help to ensure the safety and integrity of your AWS resources.*"""
        return self.__get_formatted_json(message)

    def ec2_launch_scp_block_error_message(self, severity, iam_user, is_imdsv2_failure=False, is_unencrypted_ebs_failure=False, is_publicip_failure=False, bypass_tag_key=None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        remediation_message = ""
        failure_reason = "The launch failed due to an SCP policy restricting the deployment of instances "
        if is_imdsv2_failure:
            failure_reason += "without IMDSv2 enabled. Please ensure that the EC2 instance is launched with IMDSv2 enabled."
            remediation_message = f"""
If you have a specific use case that requires launching an instance without IMDSv2 enabled, you can bypass this SCP policy by tagging your instance with the following key and value:
*{bypass_tag_key}: enabled*"""
        if is_unencrypted_ebs_failure:
            failure_reason += "with unencrypted Root EBS Volume. Please ensure that the EC2 instance is launched with encrypted Root EBS Volume."
            remediation_message = f"""
If you have a specific use case that requires launching an instance without encrypted Root EBS Volume, you can bypass this SCP policy by tagging your instance with the following key and value:
*{bypass_tag_key}: enabled*"""
        if is_publicip_failure:
            failure_reason += "with Public IP. Please ensure that the EC2 instance is launched without Public IPs."
        message = f"""*[{severity}] :heavy_exclamation_mark:`EC2 Deployment Failed!`*
User {slack_user_id} tried to launch EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

{failure_reason}
{remediation_message}"""
        return self.__get_formatted_json(message)

    def ec2_launch_scp_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, is_imdsv2=False, is_publicip=False, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        instance_status = ""
        remediation_block = ""
        pagerduty_block = {}
        msg_header = "EC2 Instance Launched "
        if is_imdsv2:
            instance_status = "without enabling IMDSv2"
            if found_bypass_tag:
                msg_header += "Bypassing IMDSV2 SCP!"
                instance_status += " against SCP applied on your Organization using bypass tag"
            else:
                msg_header += "Without IMDSv2 enabled!"
                remediation_block = """
*Remediation Recommendation:*
Ensure that the EC2 instance metadata service (IMDSv2) is enabled by updating the instance's configuration. This can be done by modifying the instance metadata options to require IMDSv2."""
        if is_publicip:
            if found_bypass_tag:
                msg_header += "Bypassing Public IP!"
                instance_status = "bypassing Public IP SCP using bypass tag"
            else:
                msg_header += "With Public IP!"
                instance_status = "with Public IP"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{msg_header}`*

User {slack_user_id} launched EC2 Instance {instance_status} in the following location and with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Instance ID: {instance_id}
{pagerduty_block if pagerduty_block else ''}
{remediation_block}"""
        return self.__get_formatted_json(message)

    def ec2_instance_profile_auto_remediated(self, severity, role_name, ec2_instances, slack_token=None):
        message = f"""*[{severity}] :white_check_mark: EC2 Instance Profile Auto-Remediated!*

IAM role was disassociated from EC2 instance [{', '.join(ec2_instances)}] in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

As part of our security measures, IAM Role named {role_name} with required policies has been associated to this EC2 instance to ensure proper access and security controls are maintained."""
        return self.__get_formatted_json(message)

    def iam_role_auto_remediation(self, severity, role_name, policy, ec2_instances, slack_token=None):
        message = f"""*[{severity}] :white_check_mark: IAM Role Auto-Remediated!*

The IAM role named {role_name} associated with EC2 instance(s) [{', '.join(ec2_instances)}] had certain policies detached in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Detached Policies: {policy}

As part of our security measures, the policies have been re-attached to ensure proper access and security controls are maintained."""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all_attached_to_public_resource(self, severity, iam_user, security_group_id, resource_type, ports, is_attached, attached_instances, attached_lb, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Security Group Attached to {resource_type} with ports Open to 0.0.0.0/0!`*
User {slack_user_id} attached a Security Group with ports open to 0.0.0.0/0 to {resource_type} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Ingress Details:*
Security Group ID: {security_group_id}
Port: {', '.join(ports).replace("-1", "All Traffic")}

{attachment_details}

*Remediation Recommendation:*
Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all_attachment_remediation_message(self, severity, port, security_group_id, is_attached, attached_instances, attached_lb, is_deleted, slack_token=None):
        conditional_message = ""
        ingress_details = ""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        if is_deleted:
            conditional_message = f"Security group with ID *{security_group_id}* got remediated and does not exist anymore"
        elif not is_deleted:
            conditional_message = "Security Group with ports open to everyone got remediated"
            ingress_details = f"""
*Here are the Ingress Details:*
Security Group ID: {security_group_id}
Ports: {', '.join(port).replace("-1", "All Traffic")}

{attachment_details}"""

        message = f"""*[{severity}] :white_check_mark: Security Group Remediated!*
{conditional_message} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{ingress_details}"""
        return self.__get_formatted_json(message)

    def iam_user_creation_scp_block_error_message(self, severity, iam_user, is_creation_blocked, is_creation_blocked_wo_tags, iam_user_creation_scp_tag_keys, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        block_message = "."
        remediation_message = """
If you have a specific use case that requires creating an IAM User, please contact your administrator."""
        if is_creation_blocked and is_creation_blocked_wo_tags:
            block_message = " either fully or due to missing specific tags."
            remediation_message = f"""
If you believe this is a general restriction, please contact your administrator otherwise ensure the following tags are present when creating the IAM User: [{', '.join(iam_user_creation_scp_tag_keys)}]"""
        elif is_creation_blocked_wo_tags:
            block_message = f""" without specific tags.
Please ensure the following tags are present when creating the IAM User: [{', '.join(iam_user_creation_scp_tag_keys)}]"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`IAM User Creation Failed!`*
User {slack_user_id} tried to create an IAM User in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

The creation failed due to an SCP policy restricting the creation of IAM Users{block_message}
{remediation_message}"""
        return self.__get_formatted_json(message)

    def iam_user_creation_bypass_tag_message(self, severity, iam_user, new_iam_user, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = """
*Remediation Recommendation:*
Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`New IAM User Created{bypass_msg_header}!`*
User {slack_user_id} created an IAM User {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
IAM User: {new_iam_user}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def iam_user_remediation_message(self, severity, iam_user, slack_token=None):
        message = f"""*[{severity}] :white_check_mark: IAM User Remediated!*
IAM User *{iam_user}* does not exist anymore in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
"""
        return self.__get_formatted_json(message)

    def secret_access_key_creation_message(self, severity, is_new, iam_user, secret_access_key_user, access_key_id, created_by, created_at, deploy_iam_keypair_access_tracker_project, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message_header = "New Secret-Access KeyPair Generated"
        creation_message = f"User {slack_user_id} created a new Secret-Access KeyPair"
        pagerduty_block = {}
        remediation_block = """
*Remediation Recommendation:*
Please DELETE this newly generated Secret-Access KeyPair and utilize IAM Roles or AWS IAM Identity Center instead."""
        if deploy_iam_keypair_access_tracker_project:
            remediation_block = """
This Secret-Access KeyPair has been successfully registered in our tracking system for security and compliance purposes. If you did not create this key pair or have any concerns, please contact your administrator."""
            if is_new:
                message_header += " and Registered"
                owner_message = f"by {self.__get_user_member_id(slack_token, created_by)}" if self.__is_user_email(created_by) else "and its owner is unknown"
                creation_message = f"A new Secret-Access KeyPair has been created {owner_message}"
            else:
                message_header = "Secret-Access KeyPair Registered"
                owner_message = f"{self.__get_user_member_id(slack_token, created_by)}" if self.__is_user_email(created_by) else "unknown owner"
                creation_message = f"A Secret-Access KeyPair owned by {owner_message} has been detected"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{message_header}!`*
{creation_message} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

*Secret-Access KeyPair Details:*
Access Key ID: {access_key_id}
Associated with IAM User: {secret_access_key_user}
Created At: {created_at}
{remediation_block}"""
        return self.__get_formatted_json(message)

    def secret_access_key_expiry_reminder_message(self, severity, iam_user, access_key_id, created_by, creation_date, expiry_date, days_remaining, slack_token=None):
        owner_message = f"@{self.__get_user_member_id(slack_token, created_by)}" if self.__is_user_email(created_by) else "unknown owner"
        message = f"""*[{severity}] :heavy_exclamation_mark:`Secret-Access Key Expiration Reminder!`*
A Secret-Access Key Pair owned by {owner_message} is approaching its expiry date in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

*Secret-Access KeyPair Details:*
Access Key ID: {access_key_id}
Associated with IAM User: {iam_user}
Creation Date: {creation_date}
Expiry Date: {expiry_date}
Days Remaining: {days_remaining} days

Please take the necessary action to rotate this key pair before it expires. If you have any concerns or need assistance, please contact your administrator."""
        return self.__get_formatted_json(message)

    def login_profile_creation_message(self, severity, iam_user, login_profile_user, created_at, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`AWS Console Access Enabled!`*
User {slack_user_id} enabled AWS Console Access in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

*Console Access Details:*
IAM User: {login_profile_user}
Enabled At: {created_at}

*Remediation Recommendation:*
Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User. Please utilize AWS IAM Identity Center for access instead."""
        return self.__get_formatted_json(message)

    def s3_account_public_access_auto_remediation_message(self, severity, iam_user, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :white_check_mark: S3 Account Block Public Access Auto Remediated!*
We have detected that user {slack_user_id} modified the S3 account block public access setting and disabled it for the following account:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

In order to ensure the security and compliance of our AWS account, we have automatically reverted your change and enabled the setting.
Please be aware that this setting is critical to preventing public access to your S3 buckets, and disabling it may result in data exposure and security risks.

*If you have any questions or concerns, please contact our support team for assistance.*
"""
        return self.__get_formatted_json(message)

    def s3_account_public_access_config_modification_message(self, severity, iam_user, restrict_public_buckets, block_public_policy, block_public_acls, ignore_public_acls, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        restrict_public_buckets = 'Enabled' if restrict_public_buckets else 'Disabled'
        block_public_policy = 'Enabled' if block_public_policy else 'Disabled'
        block_public_acls = 'Enabled' if block_public_acls else 'Disabled'
        ignore_public_acls = 'Enabled' if ignore_public_acls else 'Disabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`S3 Account Block Public Access Settings Modified!`*
User {slack_user_id} modified S3 Block Public Access Settings for the following account:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

*Block Public Access Settings for S3 Account*
Restrict Public Buckets: {restrict_public_buckets}
Block Public Policy: {block_public_policy}
Block Public ACLs: {block_public_acls}
Ignore Public ACLs: {ignore_public_acls}

*Remediation Recommendation:*
Please enable all of the above settings for S3 Account Block Public Access and block all Public Access."""
        return self.__get_formatted_json(message)

    def notifications_suppression_removal_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        alert_message = ""
        if resource_type == 'Security Group':
            alert_message = "Security Group with some ports open to everyone"
        elif resource_type == 'IAM User':
            alert_message = 'IAM User'
        elif resource_type == 'S3 Bucket':
            alert_message = 'S3 Bucket'
        message = f"""*[{severity}] :heavy_exclamation_mark:`Notification Continuation Confirmation!`*
User {slack_user_id} has removed *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag from {resource_type} {resource_id} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*Notifications for this specific {alert_message} will now continue until remediated or silenced once again*

To disable notifications once again, add the *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag to the resource
"""
        return self.__get_formatted_json(message)

    def notifications_suppression_removal_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Notification Suppression Disable Failure!`*
User {slack_user_id} removed *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag from {resource_type} {resource_id} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag has been removed from the resource, User {slack_user_id} does not have permission to enable or disable notifications and alerts for this resource will remain disabled.
*Please contact Security to for further help.*
"""
        return self.__get_formatted_json(message)

    def notifications_suppression_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        silence_message = "Security Group with some ports open to everyone" if resource_type == 'Security Group' else resource_type
        message = f"""*[{severity}] :white_check_mark: Suppressed Notification Confirmation!*
User {slack_user_id} has tagged {resource_type} {resource_id} with *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*This will silence the notifications for this {silence_message}*
To enable notifications, remove the *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag from the resource in order to continue receiving notifications.
"""
        return self.__get_formatted_json(message)

    def notifications_suppression_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Notification Suppression Failure!`*
User {slack_user_id} added *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag to {resource_type} {resource_id}  in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag was added to the resource, User {slack_user_id} does not have permission to enable or disable notifications and you will continue to receive alerts for this resource.
*Please contact Security to for further help.*
"""
        return self.__get_formatted_json(message)

    def s3_public_bucket_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        encryption_enabled_message = ' and encrypted at REST' if not is_encryption_enabled else ''
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Public S3 Bucket!`*
User {slack_user_id} enabled Public Access for an S3 Bucket in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*S3 Bucket Details:*
Bucket Name: {s3_bucket_name}
Encryption: {encryption_status}

*Remediation Recommendation:*
Please check the bucket permissions and ensure this S3 bucket is private{encryption_enabled_message}."""
        return self.__get_formatted_json(message)

    def s3_public_object_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        message = f"""*[{severity}] :heavy_exclamation_mark:`Objects Public in S3 Bucket!`*
User {slack_user_id} enabled Public Access for some Objects in S3 Bucket in the following location and can potentially be downloaded externally:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*S3 Bucket Details:*
Bucket Name: {s3_bucket_name}
Encryption: {encryption_status}

*Remediation Recommendation:*
Please check the bucket and/or object permissions and ensure this S3 bucket is private and encrypted at REST."""
        return self.__get_formatted_json(message)

    def s3_public_bucket_deletion_remediation_message(self, severity, bucket_name, slack_token=None):
        message = f"""*[{severity}] :white_check_mark: Public S3 Bucket Remediated!*
S3 Bucket *{bucket_name}* has been deleted and does not exist anymore in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
"""
        return self.__get_formatted_json(message)

    def ec2_creation_invoked_by_aws_service_action_message(self, severity, instances, service, action, to_do_list, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        to_do_list = "\n".join(to_do_list) if to_do_list else ''
        action_message = f"""deleted in 10 minutes if the following actions are not taken:
{ to_do_list }

*Or you can also tag your resource(s) with keep-alive=true tag to bypass deletion*""" if action == 'Delete' else 'ignored'
        message = f"""*[{severity}] :heavy_exclamation_mark:`EC2 Instance(s) launched by AWS Service bypassing SCPs`*
EC2 Instance(s) were launched by *{service}* against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Instance IDs: {', '.join(instances)}
{pagerduty_block if pagerduty_block else ''}

*While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.*
So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def unencrypted_ebs_vol_creation_invoked_by_aws_service_action_message(self, severity, volume, service, action, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        action_message = """deleted in 10 minutes if the following actions are not taken:

Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        message = f"""*[{severity}] :heavy_exclamation_mark:`EBS Volume created by AWS Service bypassing SCPs`*
EBS Volume was created by *{service}* against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
EBS Volume: {volume}
{pagerduty_block if pagerduty_block else ''}

*While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.*
So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_invoked_by_aws_service_action_message(self, severity, loadbalancer, service, action, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        action_message = """deleted in 10 minutes if the following actions are not taken:

Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        message = f"""*[{severity}] :heavy_exclamation_mark:`LoadBalancer created by AWS Service bypassing SCPs`*
LoadBalancer was created by *{service}* against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
LoadBalancer Name: {loadbalancer}
{pagerduty_block if pagerduty_block else ''}

*While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.*
So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_bypass_tag_message(self, severity, iam_user, loadbalancer_name, lb_type, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`LoadBalancer Created Bypassing SCP!`*
User {slack_user_id} created LoadBalancer named *{loadbalancer_name}* against SCP applied on your Organization using bypass tag in the following location and with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}
{pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def eip_allocation_invoked_by_aws_service_action_message(self, severity, allocation_id, service, action, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        action_message = """deleted in 10 minutes if the following actions are not taken:

Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        message = f"""*[{severity}] :heavy_exclamation_mark:`Elastic IP allocated by AWS Service bypassing SCPs`*
Elastic IP was allocated by *{service}* against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
EIP Allocation ID: {allocation_id}
{pagerduty_block if pagerduty_block else ''}

*While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.*
So, these resources will be {action_message}
        """
        return self.__get_formatted_json(message)

    def eip_allocation_bypass_tag_message(self, severity, iam_user, allocation_id, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Elastic IP allocated Bypassing SCP!`*
User {slack_user_id} allocated an Elastic IP with ID *{allocation_id}* against SCP applied on your Organization using bypass tag in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def unencrypted_volume_creation_bypass_tag_message(self, severity, iam_user, volume_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        msg_header = "Unencrypted EBS Volume Created Bypassing SCP!" if found_bypass_tag else "EBS Volume Created Without Encryption Enabled!"
        remediation_block = """
*Remediation Recommendation:*
Encrypt the volume using AWS Key Management Service (KMS) to safeguard sensitive data and update associated configurations, such as EC2 instance attachments, to use the newly encrypted volume."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{msg_header}`*
User {slack_user_id} created an EBS Volume with ID *{volume_id}* without encryption enabled {'using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def root_volume_unencrypted_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        remediation_block = """
*Remediation Recommendation:*
Encrypt the root volume using AWS Key Management Service (KMS) to safeguard sensitive data and update EC2 instance attachments to use the newly encrypted volume."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`EC2 Instance launched with unencrypted Root EBS Volume{ ' Bypassing SCP' if found_bypass_tag else ''}!`*
User {slack_user_id} launched EC2 Instance *{instance_id}* with unencrypted Root EBS Volume {'using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def eip_allocation_scp_block_error_message(self, severity, iam_user, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Elastic IP Allocation Blocked!`*
User {slack_user_id} tried to allocate an Elastic IP in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

This allocation was blocked because it was an unauthorized action with an *explicit deny in a service control policy*.
Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance.
"""
        return self.__get_formatted_json(message)

    def eip_association_without_override_tag_message(self, severity, iam_user, eip_allocation_id, resource_id, resource_type, override_tag_key, found_override_tag, is_value_base64_encoded, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message_title = "Without Proper Tags"
        issue_message = "missing proper tags"
        remediation_message = f"""*Add Following Tags to {resource_type}:*
```{override_tag_key}: Base64EncodedSecretKey```"""
        if found_override_tag and not is_value_base64_encoded:
            message_title = "With Invalid Tag Value"
            issue_message = f"having invalid value for Tag {override_tag_key}"
            remediation_message = f"Please add valid base64 encoded value for Tag *{override_tag_key}* to {resource_type}."
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Elastic IP Association {message_title}!`*
User {slack_user_id} associated Elastic IP with ID *{eip_allocation_id}* to {resource_type} with ID {resource_id} {issue_message} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

{remediation_message}"""
        return self.__get_formatted_json(message)

    def public_resource_message(self, severity, iam_user, resource_type, resource_id, auto_remediate, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        remediation_message = f"Please make this {resource_type} private and share it with only those AWS accounts you need to share it with."
        alert_title = f"Public {resource_type}"
        alert_emoji = ":heavy_exclamation_mark:"
        if auto_remediate:
            remediation_message = f"Since, you have turned auto-remediation on for public {resource_type}s, we have automatically made this {resource_type} PRIVATE."
            alert_title = f"Public {resource_type} Remediated"
            alert_emoji = ":white_check_mark:"
        message = f"""*[{severity}] {alert_emoji} {alert_title}!*

User {slack_user_id} made an {resource_type} with ID *{resource_id}* PUBLIC in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*{remediation_message}*"""
        return self.__get_formatted_json(message)

    def public_ebs_snapshot_scp_block_error_message(self, severity, iam_user, snapshot_id, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :heavy_exclamation_mark:`EBS Snapshot Permission Modification Blocked!`*
User {slack_user_id} tried to modify permissions for EBS Snapshot {snapshot_id} to make it public in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*This modification was blocked due to an SCP policy that restricts making an EBS Snapshot public. Please ensure that you only share it with those AWS accounts you need to share it with.*"""
        return self.__get_formatted_json(message)

    def public_ebs_snapshot_message(self, severity, iam_user, snapshot_id, auto_remediate, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        remediation_message = "Since, you have turned auto-remediation on for public EBS Snapshots, we have automatically made this snapshot PRIVATE." if auto_remediate else "Please make this EBS Snapshot private and share it with only those AWS accounts you need to share it with."
        title = f"[{severity}] :white_check_mark: Public EBS Snapshot Remediated!" if auto_remediate else f"[{severity}] :heavy_exclamation_mark:`Public EBS Snapshot!`"
        message = f"""*{title}*
User {slack_user_id} made EBS Snapshot with ID *{snapshot_id}* PUBLIC in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*{remediation_message}*"""
        return self.__get_formatted_json(message)

    def secret_creation_without_tags_message(self, severity, iam_user, secret_name, secret_arn, tags, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Secret Created Without Proper Tags!`*
User {slack_user_id} created a SecretsManager Secret named *{secret_name}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Add Following Tags to Secret:* ```{self.__get_tags(tags)}```"""
        return self.__get_formatted_json(message)

    def backup_plan_creation_without_tags_message(self, severity, iam_user, backup_plan_name, backup_plan_arn, tags, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Backup Plan Created Without Proper Tags!`*
User {slack_user_id} created a Backup Plan named *{backup_plan_name}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Backup Plan ARN: {backup_plan_arn}
{pagerduty_block if pagerduty_block else ''}

*Add Following Tags to Backup Plan:* ```{self.__get_tags(tags)}```"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_without_tags_message(self, severity, iam_user, loadbalancer_name, loadbalancer_arn, lb_type, tags, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`LoadBalancer Created Without Proper Tags!`*
User {slack_user_id} created a LoadBalancer named *{loadbalancer_name}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}
LoadBalancer ARN: {loadbalancer_arn}
{pagerduty_block if pagerduty_block else ''}

*Add Following Tags to LoadBalancer:* ```{self.__get_tags(tags)}```"""
        return self.__get_formatted_json(message)

    def unencrypted_rds_creation_bypass_tag_message(self, severity, iam_user, db_identifier, resource_type, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = f"""
*Please add encryption to this {resource_type} by creating a snapshot of it, and then creating an encrypted copy of that snapshot and then restore an {resource_type} from the encrypted snapshot.*"""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{resource_type} Created Without Encryption Enabled{bypass_msg_header}!`*
User {slack_user_id} created an {resource_type} with ID *{db_identifier}* without encryption enabled {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def ebs_vol_rds_creation_without_encryption_missing_tags_scp_block_error_message(self, severity, iam_user, resource_type, is_unencrypted, bypass_tag_key, is_missing_tags, scp_tags, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        scp_message = ''
        remediated_message = ''
        bypass_message = f"""If you have a specific use case that requires creating an {resource_type} without encryption, you can bypass this SCP policy by tagging your {resource_type} with the following key and value:
*{bypass_tag_key}: enabled*"""
        if is_unencrypted and is_missing_tags:
            scp_message = 'without encryption enabled and certain tags'
            remediated_message = f"""with encryption enabled and following tags:

            {', '.join(scp_tags)}"""
        elif is_unencrypted or is_missing_tags:
            scp_message = 'without encryption enabled' if is_unencrypted else 'without certain tags'
            remediated_message = "with encryption enabled" if is_unencrypted else f"""with following tags:

            {', '.join(scp_tags)}"""
            bypass_message = '' if is_missing_tags else bypass_message
        message = f"""*[{severity}] :heavy_exclamation_mark:`{resource_type} Creation Blocked!`*
User {slack_user_id} tried to create an {resource_type} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

The launch failed due to an SCP policy restricting the creation of {resource_type}s {scp_message}. Please ensure that the {resource_type} is created {remediated_message}

{bypass_message}
"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_scp_block_error_message(self, severity, iam_user, lb_type, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :heavy_exclamation_mark:`LoadBalancer Creation Blocked!`*
User {slack_user_id} tried to create a LoadBalancer in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}

This creation was blocked because it was an unauthorized action with an *explicit deny in a service control policy*.
Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance.
"""
        return self.__get_formatted_json(message)

    def root_user_password_change(self, severity, ip_address, user_agent, is_completed, matched_ip_users, deploy_ip_tracker_project, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be *{','.join(matched_ip_users)}*, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Root User Password { 'Changed' if is_completed else 'Change Request Made'}!`*
Someone { 'changed password' if is_completed else 'requested for password change'} for *ROOT* user in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Source IP Address: {ip_address}
User Agent: {user_agent}
{pagerduty_block if pagerduty_block else ''}

:rotating_light:*Action Required*:rotating_light:
{ 'Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation.' if not deploy_ip_tracker_project else matched_ip_data if matched_ip_data else '`This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!`' }"""
        return self.__get_formatted_json(message)

    def root_user_login_message(self, severity, ip_address, user_agent, matched_ip_users, deploy_ip_tracker_project, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be *{','.join(matched_ip_users)}*, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        message = f"""*[{severity}] :heavy_exclamation_mark:`Root User Login!`*
A login to the AWS Management Console by the root user has been detected with the following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Source IP Address: {ip_address}
User Agent: {user_agent}
{pagerduty_block if pagerduty_block else ''}

{ '' if not deploy_ip_tracker_project else matched_ip_data if matched_ip_data else '`This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!</font>`' }

*Please review this activity and ensure that it was authorized.*
Logging in as the root user is not recommended due to the high level of access and privileges associated with this account. We recommend logging in using AWS IAM Identity Center to manage access to AWS resources instead of logging in as the root user.
"""
        return self.__get_formatted_json(message)

    def signin_brute_force_attack_message(self, severity, ip_address, user, matched_ip_users, deploy_ip_tracker_project, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be {','.join(matched_ip_users)}, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        else:
            if user != 'root':
                matched_ip_data = None
        message = f"""*[{severity}] :heavy_exclamation_mark:`Brute force attack detected!`*
A brute force attack has been detected on the account with the following details:

User Compromised: {user}
AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Source IP Address: {ip_address}
{pagerduty_block if pagerduty_block else ''}

{ '' if not deploy_ip_tracker_project else '' if matched_ip_data is None else matched_ip_data if matched_ip_data else '`This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!</font>`' }

*We recommend taking immediate action to secure the account and prevent further attempts. Some steps you could take include:*
*• Changing the password for the targeted account*
*• Enabling two-factor authentication (2FA) for the targeted account*
*• Limiting the number of failed login attempts allowed before the account is locked or disabled*"""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all_attachment_cron_message(self, severity, port, security_group_id, is_attached, attached_instances, attached_lb, pagerduty_incidents, slack_token=None):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        remediation_message = ''
        if is_attached and attached_instances:
            remediation_message = """*Remediation Recommendation:*
Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."""
        elif not is_attached:
            remediation_message = """*Remediation Recommendation:*
Either Attach Security Group to a Resource or Delete it."""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Security Group Ingress Open to Everyone!`*
Some ports are open to *0.0.0.0/0* in Security Group Ingress in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Here are the Ingress Details:*
Security Group ID: {security_group_id}
Ports: {', '.join(port).replace("-1", "All Traffic")}

{attachment_details}

{remediation_message}"""
        return self.__get_formatted_json(message)

    def secret_access_key_exist_message(self, severity, iam_user, access_key_ids, pagerduty_incidents, slack_token=None):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Active Secret-Access KeyPair Found!`*
We have found active Secret-Access KeyPair(s) for IAM User *{iam_user}* in the following location with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Access Key ID(s): {', '.join(access_key_ids)}
{pagerduty_block if pagerduty_block else ''}

*Remediation Recommendation:*
Please DELETE the active Secret-Access KeyPair(s) and utilize IAM Roles or AWS IAM Identity Center instead.
"""
        return self.__get_formatted_json(message)

    def console_access_enabled_message(self, severity, iam_user, pagerduty_incidents, slack_token=None):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""*[{severity}] :heavy_exclamation_mark:`Console Access Enabled!`*
AWS Console Access is enabled for IAM User *{iam_user}* in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

*Remediation Recommendation:*
Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User and utilize AWS IAM Identity Center for access instead.
"""
        return self.__get_formatted_json(message)

    def iam_user_exist_message(self, severity, iam_user, pagerduty_incidents, slack_token=None):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""*[{severity}] :heavy_exclamation_mark:`IAM User Exists!`*
An IAM User exists in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
IAM User: {iam_user}
{pagerduty_block if pagerduty_block else ''}

*Remediation Recommendation:*
Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS.
"""
        return self.__get_formatted_json(message)

    def iam_user_password_change_message(self, severity, iam_user, affected_user, is_failed, user_agent, source_ip_address, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`IAM User Password {'Change Attempt Failed' if is_failed else 'Changed'}!`*
User {slack_user_id} {'tried to change' if is_failed else 'changed'} console password for IAM User *{affected_user}* in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

User Agent: {user_agent}
Source IP Address: {source_ip_address}

:rotating_light:*Action Required*:rotating_light:
Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation. Disable compromised accounts if necessary. Communicate with affected users and consider implementing Multi-Factor Authentication (MFA). Enhance monitoring, update IAM policies, and document the incident for future reference, ensuring preventive measures are in place to mitigate recurrence."""
        return self.__get_formatted_json(message)

    def s3_public_bucket_object_remediation_message(self, severity, s3_bucket_name, slack_token=None):
        message = f"""*[{severity}] :white_check_mark: Public S3 Bucket Remediated!*
S3 Bucket *{s3_bucket_name}* does not have Public Access anymore at Bucket/Object level in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
"""
        return self.__get_formatted_json(message)

    def s3_public_bucket_object_message(self, severity, s3_bucket_name, is_encryption_enabled, pagerduty_incidents, slack_token=None):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        message = f"""*[{severity}] :heavy_exclamation_mark:`Public S3 Bucket!`*
Public Access for an S3 Bucket is enabled using BucketPolicy or ACLs at Object and/or Bucket-level in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*S3 Bucket Details:*
Bucket Name: {s3_bucket_name}
Encryption: {encryption_status}

*Remediation Recommendation:*
Please check the bucket and/or object permissions and ensure this S3 bucket is private and encrypted at REST.
"""
        return self.__get_formatted_json(message)

    def overpermissive_role_policy_attached_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`Over Permissive IAM Role Policy Found`*
User {slack_user_id} created/attached an over-permissive policy named {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

{resources}

{pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def overpermissive_role_policy_deleted_message(self, severity, iam_user, role_name, resources, policy_name, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`Over Permissive IAM Role Policy [DELETED]`*
This is to inform you that the over permissive policy named {policy_name} has been detached/deleted from IAM Role.
User {slack_user_id} created/attached an over-permissive policy to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

{resources}
"""
        return self.__get_formatted_json(message)

    def overpermissive_role_policies_deleted_message(self, severity, role_name, resources, detached_policies, deleted_policies, slack_token=None):
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`Over Permissive IAM Role Policies [DELETED]`*
This is to inform you that we ran a scan on IAM Role {role_name} attached to EC2 Instance(s) after the bypass tag was removed in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

{resources}

*Following policies were deleted/detached:*
Detached Policies: {', '.join(detached_policies)}
Deleted Inline Policies: {', '.join(deleted_policies)}
"""
        return self.__get_formatted_json(message)

    def launch_wizard_security_group_replaced(self, is_create_event, severity, iam_user, group_name, resource_type, attachments: list, is_replaced_by_blackhole_sg, is_deleted, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        remediated_header = []
        remediated_messages = []
        if is_replaced_by_blackhole_sg:
            remediated_header.append('Replaced')
            remediated_messages.append('has been replaced by a *blackhole* security group')
        if is_deleted:
            remediated_header.append('Deleted')
            remediated_messages.append('has been deleted')
        else:
            remediated_messages.append("hasn't been deleted because its also attached to some other resource")
        message = f"""*[{severity}] :heavy_exclamation_mark:`Launch Wizard Security Group {' and '.join(remediated_header)}!`*
User {slack_user_id} {f'created *{group_name}* security group and attached it' if is_create_event else f'attached *{group_name}* security group'} to {resource_type} {', '.join(attachments)} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

This Security Group {' and '.join(remediated_messages)}"""
        return self.__get_formatted_json(message)

    def overpermissive_role_policy_bypass_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`Over Permissive IAM Role Policy Bypassed!`*
User {slack_user_id} created/attached an over-permissive policy {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

{resources}

This policy was not deleted/detached because Admin has used *bypass tag* on IAM Role."""
        return self.__get_formatted_json(message)

    def captured_new_iam_user_event(self, severity, iam_user, access_key_id, action, source_ip_address, user_agent, slack_token=None):
        message = f"""*[{severity}] :heavy_exclamation_mark:`Unknown Activity using Secret-Access KeyPair detected!`*
An unauthorized activity has been detected in your AWS environment. The activity was initiated using a Secret-Access KeyPair with the ID *{access_key_id}*, associated with IAM User *{iam_user}* in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

These are the activity details for AWS API call which do not match any known User's IP address and appears abnormal:
Action Performed: {action}
Source IP Address: {source_ip_address}
User Agent: {user_agent}

*Please promptly review this activity to determine whether it was authorized. If this action was initiated by you, no further action is necessary. However, if this access is not authorized, we recommend taking the following steps:*
*• Deactivate the Secret-Access KeyPair with ID {access_key_id}.*
*• Delete the unauthorized Secret-Access KeyPair to prevent further unauthorized access.*

*Your AWS security is of utmost importance. If you have any concerns or need assistance, please contact our security team immediately.*
"""
        return self.__get_formatted_json(message)

    def secret_access_key_deactivated_remediation_message(self, severity, iam_user, access_key_id, slack_token=None):
        message = f"""*[{severity}] :white_check_mark:Secret-Access KeyPair Auto-Remediated!*
An unused Secret-Access KeyPair with the ID *{access_key_id}*, associated with IAM User *{iam_user}* has been deactivated in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

*This action was taken because we have identified that this Secret-Access KeyPair had been inactive for an extended period.*

*• If you believe this deactivation was in error or you still require the use of this KeyPair, please contact our support team immediately.*
*• If you no longer need this KeyPair, we recommend deleting it to further enhance the security of your AWS account.*

*Your AWS security is of utmost importance. If you have any concerns or need assistance, please contact our security team immediately.*
"""
        return self.__get_formatted_json(message)

    def guardduty_finding_message(self, severity, severity_number, guardduty_admin_account: dict, account_name, account_id, region, finding_id, finding_type, finding_description, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`GuardDuty Finding Detected!`*
We have detected a GuardDuty Finding of type *{finding_type}* with severity {severity_number} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {account_name}
AWS Account ID: {account_id}
AWS Region: {region}

*Finding Description:*
{finding_description}
{pagerduty_block if pagerduty_block else ''}

For more details open the <https://console.aws.amazon.com/guardduty/home?region={self.region}#/findings?search=id%3D{finding_id}|GuardDuty console> in {guardduty_admin_account['AccountName']} ({guardduty_admin_account['AccountId']}) AWS account.
"""
        return self.__get_formatted_json(message)

    def ssm_document_association_failure_message(self, severity, account_name, account_id, region, instance_id, association_id, document_name, incident_number, incident_url, slack_token=None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`SSM Document Association Failure Detected!`*
We have detected an SSM Document Association Failure of document *{document_name}* in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {account_name}
AWS Account ID: {account_id}
AWS Region: {region}

*Association Details:*
State Manager Association ID: {association_id}
Instance ID: {instance_id}
{pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def ssm_document_association_failure_cron_message(self, severity, account_name, account_id, region, instances: list, association_id, document_name, slack_token=None):
        message = f"""*[{severity}] :heavy_exclamation_mark:`SSM Document Association Failure Still Unresolved!`*
SSM Document Association Failure for document *{document_name}* in the following location is still unresolved:

AWS Organization: {self.org_name}
AWS Account Name: {account_name}
AWS Account ID: {account_id}
AWS Region: {region}

*Association Details:*
State Manager Association ID: {association_id}
Instance(s): [{', '.join(instances)}]

Please address this issue as soon as possible."""
        return self.__get_formatted_json(message)

    def ssm_associated_ec2_instance_update_message(self, severity, account_name, account_id, region, instance_id, association_id, document_name, is_terminated, slack_token=None):
        update_message = "Terminated" if is_terminated else "Association Succeeded"
        message = f"""*[{severity}] :heavy_exclamation_mark:`SSM Document Association Update: EC2 Instance {update_message}!`*
EC2 Instance *{instance_id}* which was previously in a failed state in the SSM Document Association for document *{document_name}* has {'been terminated' if is_terminated else 'now successfully associated'} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {account_name}
AWS Account ID: {account_id}
AWS Region: {region}

*Association Details:*
State Manager Association ID: {association_id}"""
        return self.__get_formatted_json(message)

    def resource_creation_wo_required_tags_scp_block_error_message(self, severity: str, resource_type: str, iam_user: str, tags: list, slack_token=None):
        slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        message = f"""*[{severity}] :heavy_exclamation_mark:`{resource_type} Creation Failed Due to Missing Tags`*
{slack_user_id} tried to create {resource_type} with missing tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*Please add the following missing tags to {resource_type} to have it successfully create:*
```{self.__get_tags(tags)}```"""
        return self.__get_formatted_json(message)
