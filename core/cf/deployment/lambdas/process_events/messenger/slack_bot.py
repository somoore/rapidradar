import re
import json
from typing import Optional
from os import getenv
import requests
from utils.sso_helper import SSOHelper

AWS_ORG_NAME = getenv('AWS_ORG_NAME')

class SlackBot:
    def __init__(self, slack_token, iam_user, account_id, account_name, region):
        self.slack_token = slack_token
        self.slack_user_id = self.__get_user_member_id(slack_token, iam_user)
        self.message_headers = { 'Content-Type': 'application/json; charset=UTF-8', "Authorization": f"Bearer {self.slack_token}"}
        self.account_id = account_id
        self.account_name = account_name
        self.org_name = AWS_ORG_NAME
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

    def __get_user_member_id(self, token, email):
        headers = { 'Content-Type': 'application/x-www-form-urlencoded', "Authorization": f"Bearer {token}" }
        if not self.__is_user_email(email):
            sso_helper = SSOHelper()
            email = sso_helper.get_sso_user_email(iam_user=email)
        params = { 'email': email }
        try:
            response = requests.get("https://slack.com/api/users.lookupByEmail", headers=headers, params=params, timeout=30)
            if response.status_code // 100 == 2:
                response_json = response.json()
                if response_json['ok']:
                    return f"{response_json['user']['id']}"
        except Exception as error:
            print(f"[ERROR] Failed to get Slack member ID against email {email}: {error}")
        return None

    @staticmethod
    def __is_user_email(iam_user):
        match = re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', iam_user)
        if match:
            return True
        return False

    @staticmethod
    def __get_tags_actions(missing_tags, alert_title, metadata):
        missing_tags_str = json.dumps(missing_tags)
        metadata_str = json.dumps(metadata)
        return [{
            "type": "button",
            "text": { "type": "plain_text", "text": "Acknowledge" },
            "value": json.dumps({"action": "acknowledge", "alert_title": alert_title, "missing_tags": missing_tags_str, "metadata": metadata_str}),
            "action_id": "action_acknowledge"
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": f"Tag {metadata['resource_type']}" },
            "value": json.dumps({"action": "tag_resource", "alert_title": alert_title, "missing_tags": missing_tags_str, "metadata": metadata_str}),
            "action_id": "action_tag_resource"
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": "Not Me, Report to Security!" },
            "style": "primary",
            "value": json.dumps({"action": "report_security", "alert_title": alert_title, "missing_tags": missing_tags_str, "metadata": metadata_str}),
            "action_id": "action_report_security"
        }]

    @staticmethod
    def __get_acknowledge_action(alert_title, metadata):
        metadata_str = json.dumps(metadata)
        return [{
            "type": "button",
            "text": { "type": "plain_text", "text": "Acknowledge" },
            "value": json.dumps({"action": "acknowledge", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_acknowledge"
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": "Not Me, Report to Security!" },
            "style": "primary",
            "value": json.dumps({"action": "report_security", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_report_security"
        }]

    @staticmethod
    def __get_delete_actions(alert_title, metadata):
        metadata_str = json.dumps(metadata)
        return [{
            "type": "button",
            "text": { "type": "plain_text", "text": "Acknowledge" },
            "value": json.dumps({"action": "acknowledge", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_acknowledge"
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": f"Delete {metadata['resource_type']}" },
            "style": "danger",
            "value": json.dumps({"action": "delete_resource", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_delete_resource",
            "confirm": {
                "title": {
                    "type": "plain_text",
                    "text": "Are you sure?"
                },
                "text": {
                    "type": "mrkdwn",
                    "text": f"This action will delete {metadata['resource_type']} {metadata['resource_id']}. Are you sure you want to proceed?"
                },
                "confirm": {
                    "type": "plain_text",
                    "text": "Yes"
                },
                "deny": {
                    "type": "plain_text",
                    "text": "No"
                }
            }
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": "Not Me, Report to Security!" },
            "style": "primary",
            "value": json.dumps({"action": "report_security", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_report_security"
        }]

    @staticmethod
    def __get_remediate_actions(alert_title, metadata, delete_text):
        metadata_str = json.dumps(metadata)
        return [{
            "type": "button",
            "text": { "type": "plain_text", "text": "Acknowledge" },
            "value": json.dumps({"action": "acknowledge", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_acknowledge"
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": delete_text },
            "value": json.dumps({"action": "remediate_resource", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_remediate_resource",
        },
        {
            "type": "button",
            "text": { "type": "plain_text", "text": "Not Me, Report to Security!" },
            "style": "primary",
            "value": json.dumps({"action": "report_security", "alert_title": alert_title, "metadata": metadata_str}),
            "action_id": "action_report_security"
        }]

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

    def __open_dm(self):
        payload = { "users": f"{self.slack_user_id}" }
        response = requests.post("https://slack.com/api/conversations.open", headers=self.message_headers, json=payload, timeout=30)
        response_json = response.json()
        if not response_json.get("ok"):
            print("Failed to open conversation:", response_json.get("error"))
            return None
        return response_json['channel']['id']

    def send_dm_alert(self, text, actions):
        user_dm_id = self.__open_dm()
        message = {
            "channel": user_dm_id,
            "blocks": [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{text}"
                }
            },
            {
                "type": "actions",
                "elements": actions
            }]
        }
        response = requests.post("https://slack.com/api/chat.postMessage", headers=self.message_headers, json=message, timeout=30)
        response_json = response.json()
        if not response_json.get("ok"):
            return False, f"Failed to send block message: {response_json.get('error')}"
        return True, response_json

    def resource_creation_without_tags_message(self, severity, iam_user, resource_type, resource_id, tags, incident_number, incident_url):
        alert_title = f"{resource_type} Created Without Proper Tags"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": resource_id}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created {resource_type} *{resource_id}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Missing Tags:* ```{self.__get_tags(tags)}```"""
        return self.send_dm_alert(message, self.__get_tags_actions(tags, alert_title, metadata))

    def backup_plan_creation_without_tags_message(self, severity, iam_user, backup_plan_name, backup_plan_arn, tags, incident_number, incident_url):
        alert_title = "Backup Plan Created Without Proper Tags"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Backup Plan", "resource_id": backup_plan_arn}
        pagerduty_block = {}
        if incident_number and incident_number:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created a Backup Plan named *{backup_plan_name}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Backup Plan ARN: {backup_plan_arn}
{pagerduty_block if  pagerduty_block else ''}

*Missing Tags:* ```{self.__get_tags(tags)}```"""
        return self.send_dm_alert(message, self.__get_tags_actions(tags, alert_title, metadata))

    def iam_user_creation_scp_block_error_message(self, severity, iam_user, is_creation_blocked, is_creation_blocked_wo_tags, iam_user_creation_scp_tag_keys):
        alert_title = "IAM User Creation Failed"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM User", "resource_id": ""}
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
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You tried to create an IAM User in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

The creation failed due to an SCP policy restricting the creation of IAM Users{block_message}
{remediation_message}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def iam_user_creation_bypass_tag_message(self, severity, iam_user, new_iam_user, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        alert_title = f"New IAM User Created{bypass_msg_header}"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM User", "resource_id": new_iam_user}
        remediation_block = """
*Remediation Recommendation:*
Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created an IAM User {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
IAM User: {new_iam_user}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.send_dm_alert(message, self.__get_delete_actions(alert_title, metadata))

    def secret_access_key_creation_message(self, severity, is_new, iam_user, secret_access_key_user, access_key_id, created_by, created_at, deploy_iam_keypair_access_tracker_project, incident_number, incident_url):
        alert_title = "New Secret-Access KeyPair Generated"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM Access Key", "resource_id": f"{secret_access_key_user}:{access_key_id}"}
        creation_message = "You created a new Secret-Access KeyPair"
        pagerduty_block = {}
        remediation_block = """
*Remediation Recommendation:*
Please DELETE this newly generated Secret-Access KeyPair and utilize IAM Roles or AWS IAM Identity Center instead."""
        if deploy_iam_keypair_access_tracker_project:
            remediation_block = """
This Secret-Access KeyPair has been successfully registered in our tracking system for security and compliance purposes. If you did not create this key pair or have any concerns, please contact your administrator."""
            if is_new:
                alert_title += " and Registered"
                creation_message = "A new Secret-Access KeyPair has been created by you"
            else:
                alert_title = "Secret-Access KeyPair Registered"
                creation_message = "A Secret-Access KeyPair owned by you has been detected"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
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
        return self.send_dm_alert(message, self.__get_delete_actions(alert_title, metadata))

    def eip_allocation_bypass_tag_message(self, severity, iam_user, allocation_id, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        alert_title= "Elastic IP allocated Bypassing SCP"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Elastic IP", "resource_id": allocation_id}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You allocated an Elastic IP with ID *{allocation_id}* against SCP applied on your Organization using bypass tag in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}"""
        return self.send_dm_alert(message, self.__get_delete_actions(alert_title, metadata))

    def eip_allocation_scp_block_error_message(self, severity, iam_user):
        alert_title = "Elastic IP Allocation Blocked"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Elastic IP", "resource_id": ""}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You tried to allocate an Elastic IP in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

This allocation was blocked because it was an unauthorized action with an *explicit deny in a service control policy*.
Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance."""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def eip_association_without_override_tag_message(self, severity, iam_user, eip_allocation_id, resource_id, resource_type, override_tag_key, found_override_tag, is_value_base64_encoded, incident_number, incident_url):
        message_title = "Without Proper Tags"
        issue_message = "missing proper tags"
        remediation_message = f"""*Missing Tags for {resource_type}:*
```{override_tag_key}: Base64EncodedSecretKey```"""
        if found_override_tag and not is_value_base64_encoded:
            message_title = "With Invalid Tag Value"
            issue_message = f"having invalid value for Tag {override_tag_key}"
            remediation_message = f"Please add valid base64 encoded value for Tag *{override_tag_key}* to {resource_type}."
        alert_title = f"Elastic IP Association {message_title}"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Elastic IP Association", "resource_id": eip_allocation_id}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You associated Elastic IP with ID *{eip_allocation_id}* to {resource_type} with ID {resource_id} {issue_message} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

{remediation_message}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def security_group_ingress_open_to_all(self, severity, iam_user, ip_protocol, port, security_group_id, security_group_rule_id, is_attached, attached_instances, attached_lb, is_critical, incident_number, incident_url):
        alert_title = "Security Group Ingress Open to Everyone"
        alert_emoji = ":heavy_exclamation_mark:" if is_critical else ":bell:"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Security Group Ingress", "resource_id": f"{security_group_id}:{security_group_rule_id}"}
        remediation_message = 'Please Close Access to 0.0.0.0/0'
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
        message = f"""*[{severity}] {alert_emoji} `{alert_title}!`*
You opened a {ip_protocol} port to *0.0.0.0/0* in Security Group Ingress in the following location:

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
        return self.send_dm_alert(message, self.__get_delete_actions(alert_title, metadata))

    def launch_wizard_security_group_replaced(self, is_create_event, severity, iam_user, group_name, resource_type, attachments: list, is_replaced_by_blackhole_sg, is_deleted, incident_number, incident_url):
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
        alert_title = f"Launch Wizard Security Group {' and '.join(remediated_header)}"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Launch Wizard Security Group", "resource_id": group_name}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You {f'created *{group_name}* security group and attached it' if is_create_event else f'attached *{group_name}* security group'} to {resource_type} {', '.join(attachments)} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

This Security Group {' and '.join(remediated_messages)}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def notifications_suppression_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        alert_title = "Suppressed Notification Confirmation"
        silence_message = "Security Group with some ports open to everyone" if resource_type == 'Security Group' else resource_type
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": silence_message, "resource_id": resource_id}
        message = f"""*[{severity}] :white_check_mark: {alert_title}!*
You have tagged {resource_type} {resource_id} with *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*This will silence the notifications for this {silence_message}*
To enable notifications, remove the *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag from the resource in order to continue receiving notifications."""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def notifications_suppression_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        alert_title = "Notification Suppression Failure"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": resource_id}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You added *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag to {resource_type} {resource_id}  in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag was added to the resource, you do not have permission to enable or disable notifications and you will continue to receive alerts for this resource.
*Please contact Security to for further help.*"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def ebs_vol_rds_creation_without_encryption_missing_tags_scp_block_error_message(self, severity, iam_user, resource_type, is_unencrypted, bypass_tag_key, is_missing_tags, scp_tags):
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
        alert_title = f"{resource_type} Creation Blocked"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": ""}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You tried to create an {resource_type} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

The launch failed due to an SCP policy restricting the creation of {resource_type}s {scp_message}. Please ensure that the {resource_type} is created {remediated_message}

{bypass_message}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def unencrypted_volume_creation_bypass_tag_message(self, severity, iam_user, volume_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        alert_title = "Unencrypted EBS Volume Created Bypassing SCP!" if found_bypass_tag else "EBS Volume Created Without Encryption Enabled!"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Unencrypted EBS Volume", "resource_id": volume_id}
        remediation_block = """
*Remediation Recommendation:*
Encrypt the volume using AWS Key Management Service (KMS) to safeguard sensitive data and update associated configurations, such as EC2 instance attachments, to use the newly encrypted volume."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}`*
You created an EBS Volume with ID *{volume_id}* without encryption enabled {'using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def notifications_suppression_removal_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        alert_message = ""
        if resource_type == 'Security Group':
            alert_message = "Security Group with some ports open to everyone"
        elif resource_type == 'IAM User':
            alert_message = 'IAM User'
        elif resource_type == 'S3 Bucket':
            alert_message = 'S3 Bucket'
        alert_title = "Notification Continuation Confirmation"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": resource_id}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You have removed *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag from {resource_type} {resource_id} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*Notifications for this specific {alert_message} will now continue until remediated or silenced once again*

To disable notifications once again, add the *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag to the resource"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def notifications_suppression_removal_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        alert_title = "Notification Suppression Disable Failure"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": resource_id}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You removed *{alert_suppression_tag_key}={alert_suppression_tag_value}* tag from {resource_type} {resource_id} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag has been removed from the resource, User {iam_user} does not have permission to enable or disable notifications and alerts for this resource will remain disabled.
*Please contact Security to for further help.*"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def public_resource_message(self, severity, iam_user, resource_type, resource_id, auto_remediate, incident_number, incident_url):
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": f"Public {resource_type}", "resource_id": resource_id}
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
            alert_title = f"Public {resource_type} Remediated"
            alert_emoji = ":white_check_mark:"
            remediation_message = f"Since, you have turned auto-remediation on for public {resource_type}, we have automatically made this {resource_type} PRIVATE."
        message = f"""*[{severity}] {alert_emoji} {alert_title}!*
You made {resource_type} with ID *{resource_id}* PUBLIC in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*{remediation_message}*"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata) if auto_remediate else self.__get_remediate_actions(alert_title, metadata, f"Make {resource_type} Private"))

    def security_group_ingress_open_to_all_attached_to_public_resource(self, severity, iam_user, security_group_id, resource_type, ports, is_attached, attached_instances, attached_lb, incident_number, incident_url):
        alert_title = f"Security Group Attached to {resource_type} with ports Open to 0.0.0.0/0"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Open Security Group", "resource_id": security_group_id}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You attached a Security Group with ports open to 0.0.0.0/0 to {resource_type} in the following location:

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
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def public_ebs_snapshot_scp_block_error_message(self, severity, iam_user, snapshot_id):
        alert_title = "EBS Snapshot Permission Modification Blocked"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Public EBS Snapshot", "resource_id": ""}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You tried to modify permissions for EBS Snapshot {snapshot_id} to make it public in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*This modification was blocked due to an SCP policy that restricts making an EBS Snapshot public. Please ensure that you only share it with those AWS accounts you need to share it with.*"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def ec2_launch_scp_block_error_message(self, severity, iam_user, is_imdsv2_failure=False, is_unencrypted_ebs_failure=False, is_publicip_failure=False, bypass_tag_key=None):
        alert_title = "EC2 Deployment Failed"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "EC2 Instance", "resource_id": ""}
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
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You tried to launch EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

{failure_reason}
{remediation_message}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def ec2_launch_scp_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, is_imdsv2=False, is_publicip=False, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        instance_status = ""
        remediation_block = ""
        pagerduty_block = {}
        alert_title = "EC2 Instance Launched "
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "EC2 Instance", "resource_id": ""}
        if is_imdsv2:
            instance_status = "without enabling IMDSv2"
            if found_bypass_tag:
                alert_title += "Bypassing IMDSV2 SCP!"
                instance_status += " against SCP applied on your Organization using bypass tag"
            else:
                alert_title += "Without IMDSv2 enabled!"
                remediation_block = """
*Remediation Recommendation:*
Ensure that the EC2 instance metadata service (IMDSv2) is enabled by updating the instance's configuration. This can be done by modifying the instance metadata options to require IMDSv2."""
        if is_publicip:
            if found_bypass_tag:
                alert_title += "Bypassing Public IP!"
                instance_status = "bypassing Public IP SCP using bypass tag"
            else:
                alert_title += "With Public IP!"
                instance_status = "with Public IP"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}`*

You launched EC2 Instance {instance_status} in the following location and with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Instance ID: {instance_id}
{pagerduty_block if pagerduty_block else ''}
{remediation_block}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def root_volume_unencrypted_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        remediation_block = """
*Remediation Recommendation:*
Encrypt the root volume using AWS Key Management Service (KMS) to safeguard sensitive data and update EC2 instance attachments to use the newly encrypted volume."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        alert_title = f"EC2 Instance launched with unencrypted Root EBS Volume{ ' Bypassing SCP' if found_bypass_tag else ''}"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "EC2 Instance", "resource_id": ""}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You launched EC2 Instance *{instance_id}* with unencrypted Root EBS Volume {'using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def loadbalancer_creation_bypass_tag_message(self, severity, iam_user, loadbalancer_name, lb_type, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        alert_title = "LoadBalancer Created Bypassing SCP"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": f"{lb_type} LoadBalancer", "resource_id": loadbalancer_name}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created LoadBalancer named *{loadbalancer_name}* against SCP applied on your Organization using bypass tag in the following location and with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}
{pagerduty_block if pagerduty_block else ''}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def loadbalancer_creation_without_tags_message(self, severity, iam_user, loadbalancer_name, loadbalancer_arn, lb_type, tags, incident_number, incident_url):
        alert_title = "LoadBalancer Created Without Proper Tags"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": f"{lb_type} LoadBalancer", "resource_id": loadbalancer_arn}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created a LoadBalancer named *{loadbalancer_name}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}
LoadBalancer ARN: {loadbalancer_arn}
{pagerduty_block if pagerduty_block else ''}

*Missing Tags:* ```{self.__get_tags(tags)}```"""
        return self.send_dm_alert(message, self.__get_tags_actions(tags, alert_title, metadata))

    def loadbalancer_creation_scp_block_error_message(self, severity, iam_user, lb_type):
        alert_title = "LoadBalancer Creation Blocked"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": f"{lb_type} LoadBalancer", "resource_id": ""}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You tried to create a LoadBalancer in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}

This creation was blocked because it was an unauthorized action with an *explicit deny in a service control policy*.
Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance."""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def overpermissive_role_policy_deleted_message(self, severity, iam_user, role_name, resources, policy_name):
        alert_title = "Over Permissive IAM Role Policy [DELETED]"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM Role Policy", "resource_id": ""}
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}`*
This is to inform you that the over permissive policy named {policy_name} has been detached/deleted from IAM Role.
You created/attached an over-permissive policy to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

{resources}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def overpermissive_role_policy_attached_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url):
        alert_title = "Over Permissive IAM Role Policy Found"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM Role Policy", "resource_id": f"{role_name}:{policy_name}"}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}`*
You created/attached an over-permissive policy named {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

{resources}

{pagerduty_block if pagerduty_block else ''}"""
        return self.send_dm_alert(message, self.__get_delete_actions(alert_title, metadata))

    def overpermissive_role_policy_bypass_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url):
        alert_title = "Over Permissive IAM Role Policy Bypassed"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM Role Policy", "resource_id": f"{role_name}:{policy_name}"}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        resources = "\n".join([str(elem) for elem in resources])
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created/attached an over-permissive policy {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

{resources}

This policy was not deleted/detached because Admin has used *bypass tag* on IAM Role."""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def login_profile_creation_message(self, severity, iam_user, login_profile_user, created_at, incident_number, incident_url):
        alert_title = "AWS Console Access Enabled"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM User Login Profile", "resource_id": f"{login_profile_user}"}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You enabled AWS Console Access in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

*Console Access Details:*
IAM User: {login_profile_user}
Enabled At: {created_at}

*Remediation Recommendation:*
Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User. Please utilize AWS IAM Identity Center for access instead."""
        return self.send_dm_alert(message, self.__get_delete_actions(alert_title, metadata))

    def iam_user_password_change_message(self, severity, iam_user, affected_user, is_failed, user_agent, source_ip_address, incident_number, incident_url):
        alert_title = f"IAM User Password {'Change Attempt Failed' if is_failed else 'Changed'}"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "IAM User Password", "resource_id": f"{affected_user}"}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You {'tried to change' if is_failed else 'changed'} console password for IAM User *{affected_user}* in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
{pagerduty_block if pagerduty_block else ''}

User Agent: {user_agent}
Source IP Address: {source_ip_address}

:rotating_light:*Action Required*:rotating_light:
Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation. Disable compromised accounts if necessary. Communicate with affected users and consider implementing Multi-Factor Authentication (MFA). Enhance monitoring, update IAM policies, and document the incident for future reference, ensuring preventive measures are in place to mitigate recurrence."""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def unencrypted_rds_creation_bypass_tag_message(self, severity, iam_user, db_identifier, resource_type, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = f"""
*Please add encryption to this {resource_type} by creating a snapshot of it, and then creating an encrypted copy of that snapshot and then restore an {resource_type} from the encrypted snapshot.*"""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        alert_title = f"{resource_type} Created Without Encryption Enabled{bypass_msg_header}"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": f"{db_identifier}"}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created an {resource_type} with ID *{db_identifier}* without encryption enabled {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}
{remediation_block if not found_bypass_tag else ''}"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def s3_account_public_access_auto_remediation_message(self, severity, iam_user):
        alert_title = "S3 Account Block Public Access Auto Remediated"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "S3 Account Public Access Block", "resource_id": ""}
        message = f"""*[{severity}] :white_check_mark: {alert_title}!*
We have detected that you modified the S3 account block public access setting and disabled it for the following account:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

In order to ensure the security and compliance of our AWS account, we have automatically reverted your change and enabled the setting.
Please be aware that this setting is critical to preventing public access to your S3 buckets, and disabling it may result in data exposure and security risks.

*If you have any questions or concerns, please contact our support team for assistance.*"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def s3_account_public_access_config_modification_message(self, severity, iam_user, restrict_public_buckets, block_public_policy, block_public_acls, ignore_public_acls, incident_number, incident_url):
        alert_title = "S3 Account Block Public Access Settings Modified"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "S3 Account Public Access Block", "resource_id": ""}
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
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You modified S3 Block Public Access Settings for the following account:

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
        return self.send_dm_alert(message, self.__get_remediate_actions(alert_title, metadata, "Enable S3 Account Public Access Block"))

    def s3_public_bucket_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url):
        alert_title = "Public S3 Bucket"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Public S3 Bucket", "resource_id": s3_bucket_name}
        encryption_enabled_message = ' and encrypted at REST' if not is_encryption_enabled else ''
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You enabled Public Access for an S3 Bucket in the following location:

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
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def s3_public_object_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url):
        alert_title = "Objects Public in S3 Bucket"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "Public S3 Object", "resource_id": s3_bucket_name}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You enabled Public Access for some Objects in S3 Bucket in the following location and can potentially be downloaded externally:

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
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))

    def secret_creation_without_tags_message(self, severity, iam_user, secret_name, secret_arn, tags, incident_number, incident_url):
        alert_title = "Secret Created Without Proper Tags"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": "SecretManager Secret", "resource_id": f"{secret_arn}"}
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
*PagerDuty Incident:*
Incident Number: {incident_number}
Details: <{incident_url}|Incident Details>"""
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}!`*
You created a SecretsManager Secret named *{secret_name}* without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{pagerduty_block if pagerduty_block else ''}

*Missing Tags:* ```{self.__get_tags(tags)}```"""
        return self.send_dm_alert(message, self.__get_tags_actions(tags, alert_title, metadata))

    def resource_creation_wo_required_tags_scp_block_error_message(self, severity: str, resource_type: str, iam_user, tags: list):
        alert_title = f"{resource_type} Creation Failed Due to Missing Tags"
        metadata = {"account_name": f"{self.account_name}", "account_id": f"{self.account_id}", "region": self.region, "resource_type": resource_type, "resource_id": ""}
        message = f"""*[{severity}] :heavy_exclamation_mark:`{alert_title}`*
You tried to create {resource_type} with missing tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

*Missing tags:*
```{self.__get_tags(tags)}```"""
        return self.send_dm_alert(message, self.__get_acknowledge_action(alert_title, metadata))
