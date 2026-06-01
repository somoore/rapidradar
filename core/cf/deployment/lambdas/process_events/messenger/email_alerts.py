from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from os import getenv
import re
import datetime
from typing import Optional
import boto3
from utils.secretsmanager import GetConfig

AWS_ORG_NAME = getenv('AWS_ORG_NAME')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
DEPLOYMENT_TARGET_ACCOUNTS_SECRET = getenv('DEPLOYMENT_TARGET_ACCOUNTS')
DEPLOYMENT_TARGET_ACCOUNTS = GetConfig(DEPLOYMENT_TARGET_ACCOUNTS_SECRET).values

class CustomException(Exception):
    """ Custom Exception class inherited from Exception class """

class EmailAlert:
    """
    Class for Alerts
    """
    def __init__(self, sender_email, account_id=None, region=None):
        self.sender_email = sender_email
        self.account_id = account_id
        self.region = region
        self.account_name = None
        if account_id:
            self.account_name = self.__get_account_name(self.account_id)
        self.org_name = AWS_ORG_NAME

    @staticmethod
    def __is_user_email(iam_user):
        match = re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', iam_user)
        if match is not None:
            return True
        return False

    @staticmethod
    def __get_sg_attachment_details(is_attached, attached_instances, attached_lb):
        attachment_details = []
        if attached_instances or attached_lb:
            attachment_details = []
            attachment_details.append("<b>Attachment Details:</b>")
            attachment_details.append('<div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">')
            if len(attached_instances) > 0:
                instances_details = ''
                for instance in attached_instances:
                    instances_details += f"• {instance['ResourceId']} ({instance['Context']})<br>"
                attachment_details.append(f"<b>EC2 Instance(s):</b><br>{instances_details}")
            if len(attached_lb) > 0:
                lb_details = ''
                for lb in attached_lb:
                    lb_details += f"• {lb['ResourceId']} ({lb['Context']})<br>"
                attachment_details.append(f"<b>LoadBalancers(s):</b><br>{lb_details}")
            attachment_details.append('</div><br>')
        attachment_details = '<br>'.join(attachment_details) if attachment_details else '<b>Attachment:</b> Currently Not Attached to Any Resource' if not is_attached else ''
        return attachment_details

    def send_email(self, email_subject, body_html, receiver_email):
        try:
            msg = MIMEMultipart('mixed')
            msg['From'] = self.sender_email
            msg_body = MIMEMultipart('alternative')
            ses = boto3.client('ses')
            msg['To'] = receiver_email
            msg['Subject'] = email_subject
            htmlpart = MIMEText(body_html.encode("utf-8"), 'html', "utf-8")
            msg_body.attach(htmlpart)
            msg.attach(msg_body)

            if self.__is_user_email(receiver_email):
                ses.send_raw_email(
                    Source=self.sender_email,
                    Destinations=[receiver_email],
                    RawMessage={'Data':msg.as_string()}
                )
                return True, "Email message sent successfully"
            return True, f"Cannot send email to user {receiver_email} as it is not a valid email address"
        except Exception as error:
            return False, f"Could not send email to {receiver_email}: {str(error)}"

    def resource_creation_without_tags_message(self, severity, iam_user, resource_type, resource_id, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] {resource_type} Created Without Proper Tags!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created {resource_type} <b>{resource_id}</b> without proper tags in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Add Following Tags to {resource_type}:</b><br>
            {self.__get_tags(tags)}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def security_group_ingress_open_to_all(self, severity, iam_user, ip_protocol, port, security_group_id, security_group_rule_id, is_attached, attached_instances, attached_lb, is_critical, incident_number, incident_url):
        remediation_message = 'Please Close Access to 0.0.0.0/0'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        if is_attached and attached_instances:
            remediation_message = "Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."
        elif not is_attached:
            remediation_message = "Either Attach Security Group to a Resource or Delete it."

        email_subject = f"[{severity}] Security Group Ingress Open to Everyone!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You have opened a {ip_protocol} port to <b>0.0.0.0/0</b> in Security Group Ingress in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Ingress Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Security Group ID:</b> {security_group_id}<br>
                <b>Security Group Rule ID:</b> {security_group_rule_id}<br>
                <b>IP Protocol:</b> {ip_protocol}<br>
                <b>Port:</b> {port}
            </div><br>
            {attachment_details}
            {f"<b>Remediation Recommendation:</b><br>{remediation_message}<br><br>" if is_critical else ''}
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def security_group_ingress_open_to_all_attached_to_public_resource(self, severity, iam_user, security_group_id, resource_type, ports, is_attached, attached_instances, attached_lb, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        email_subject = f"[{severity}] Security Group Attached to {resource_type} with ports Open to 0.0.0.0/0!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You attached a Security Group with ports open to 0.0.0.0/0 to {resource_type} in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Ingress Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Security Group ID:</b> {security_group_id}<br>
                <b>Ports:</b> {', '.join(ports).replace("-1", "All Traffic")}
            </div><br>
            {attachment_details}
            <b>Remediation Recommendation:</b><br>
            Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def unencrypted_rds_creation_bypass_tag_message(self, severity, iam_user, db_identifier, resource_type, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        bypass_email_subject = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = f"Please add encryption to this {resource_type} by creating a snapshot of it, and then creating an encrypted copy of that snapshot and then restore a DB instance from the encrypted snapshot.<br>"
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] {resource_type} Created Without Encryption Enabled{bypass_email_subject}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created an {resource_type} with ID <b>{db_identifier}</b> without encryption enabled {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_block if not found_bypass_tag else ''}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def ebs_vol_rds_creation_without_encryption_missing_tags_scp_block_error_message(self, severity, iam_user, resource_type, is_unencrypted, bypass_tag_key, is_missing_tags, scp_tags):
        scp_message = ''
        remediated_message = ''
        bypass_message = f"""<br><br>If you have a specific use case that requires creating an {resource_type} without encryption, you can bypass this SCP policy by tagging your {resource_type} with the following key and value:
<b>{bypass_tag_key}: enabled</b>"""
        if is_unencrypted and is_missing_tags:
            scp_message = 'without encryption enabled and certain tags'
            remediated_message = f"""with encryption enabled and following tags:<br><br>

            {', '.join(scp_tags)}"""
        elif is_unencrypted or is_missing_tags:
            scp_message = 'without encryption enabled' if is_unencrypted else 'without certain tags'
            remediated_message = "with encryption enabled" if is_unencrypted else f"""with following tags:<br><br>

            {', '.join(scp_tags)}"""
            bypass_message = '' if is_missing_tags else bypass_message
        email_subject = f"[{severity}] {resource_type} Creation Blocked!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to create an {resource_type} in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
            </div><br>
            The launch failed due to an SCP policy restricting the creation of {resource_type} {scp_message}. Please ensure that the {resource_type} is launched {remediated_message}.<br><br>
            {bypass_message}<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def iam_user_creation_scp_block_error_message(self, severity, iam_user, is_creation_blocked, is_creation_blocked_wo_tags, iam_user_creation_scp_tag_keys):
        block_message = "."
        remediation_message = "If you have a specific use case that requires creating an IAM User, please contact your administrator."
        if is_creation_blocked and is_creation_blocked_wo_tags:
            block_message = " either fully or due to missing specific tags."
            remediation_message = f"If you believe this is a general restriction, please contact your administrator otherwise ensure the following tags are present when creating the IAM User: [{', '.join(iam_user_creation_scp_tag_keys)}]"
        elif is_creation_blocked_wo_tags:
            block_message = f""" without specific tags.<br>
            Please ensure the following tags are present when creating the IAM User: [{', '.join(iam_user_creation_scp_tag_keys)}]"""
        email_subject = f"[{severity}] IAM User Creation Failed!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to create an IAM User in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
            </div><br>
            The creation failed due to an SCP policy restricting the creation of IAM Users{block_message}<br><br>
            {remediation_message}<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def ec2_launch_scp_block_error_message(self, severity, iam_user, is_imdsv2_failure=False, is_unencrypted_ebs_failure=False, is_publicip_failure=False, bypass_tag_key=None):
        remediation_message = ""
        failure_reason = "The launch failed due to an SCP policy restricting the deployment of instances "
        if is_imdsv2_failure:
            failure_reason += "without IMDSv2 enabled. Please ensure that the EC2 instance is launched with IMDSv2 enabled.<br><br>"
            remediation_message = f"""
        If you have a specific use case that requires launching an instance without IMDSv2 enabled, you can bypass this SCP policy by tagging your instance with the following key and value:<br>
        <b>{bypass_tag_key}: enabled</b>"""
        if is_unencrypted_ebs_failure:
            failure_reason += "with unencrypted Root EBS Volume. Please ensure that the EC2 instance is launched with encrypted Root EBS Volume.<br><br>"
            remediation_message = f"""
        If you have a specific use case that requires launching an instance without encrypted Root EBS Volume, you can bypass this SCP policy by tagging your instance with the following key and value:<br>
        <b>{bypass_tag_key}: enabled</b>"""
        if is_publicip_failure:
            failure_reason += "with Public IP. Please ensure that the EC2 instance is launched without Public IPs."
        email_subject = f"[{severity}] EC2 Deployment Failed!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to launch EC2 Instance in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
            </div><br>
            {failure_reason}
            {remediation_message}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def ec2_launch_scp_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, is_imdsv2=False, is_publicip=False, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
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
        <b>Remediation Recommendation:</b>
        Ensure that the EC2 instance metadata service (IMDSv2) is enabled by updating the instance's configuration. This can be done by modifying the instance metadata options to require IMDSv2."""
        if is_publicip:
            if found_bypass_tag:
                msg_header += "Bypassing Public IP!"
                instance_status = "bypassing Public IP SCP using bypass tag"
            else:
                msg_header += "With Public IP!"
                instance_status = "with Public IP"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] {msg_header}"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You launched EC2 Instance {instance_status} in the following location and with following details:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
                <b>Instance ID:</b> {instance_id}
            </div><br><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_block}
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def iam_user_password_change_message(self, severity, iam_user, affected_user, is_failed, user_agent, source_ip_address, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] IAM User Password {'Change Attempt Failed' if is_failed else 'Changed'}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You {'tried to change' if is_failed else 'changed'} console password for IAM User <b>{affected_user}</b> in the following location:<br><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>User Agent:</b> {user_agent}<br>
                <b>Source IP Address:</b> {source_ip_address}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Action Required:</b><br>
            Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation. Disable compromised accounts if necessary. Communicate with affected users and consider implementing Multi-Factor Authentication (MFA). Enhance monitoring, update IAM policies, and document the incident for future reference, ensuring preventive measures are in place to mitigate recurrence.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def iam_user_creation_bypass_tag_message(self, severity, iam_user, new_iam_user, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        bypass_email_subject = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = """<b>Remediation Recommendation:</b><br>
        Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS.<br><br>"""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] New IAM User Created{bypass_email_subject}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created an IAM User {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>IAM User:</b> {new_iam_user}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_block if not found_bypass_tag else ''}
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def secret_access_key_creation_message(self, severity, is_new, iam_user, secret_access_key_user, access_key_id, created_by, created_at, deploy_iam_keypair_access_tracker_project, incident_number, incident_url):
        receiver_email = iam_user
        message_header = "New Secret-Access KeyPair Generated"
        creation_message = "You created a new Secret-Access KeyPair"
        pagerduty_block = {}
        remediation_block = """<b>Remediation Recommendation:</b><br>
        Please DELETE this newly generated Secret-Access KeyPair and utilize IAM Roles or AWS IAM Identity Center instead.<br>"""
        if deploy_iam_keypair_access_tracker_project:
            if self.__is_user_email(created_by):
                receiver_email = created_by
                remediation_block = "This Secret-Access KeyPair has been successfully registered in our tracking system for security and compliance purposes. If you did not create this key pair or have any concerns, please contact your administrator."
                if is_new:
                    message_header += " and Registered"
                    creation_message = "A new Secret-Access KeyPair has been created and is owned by you"
                else:
                    message_header = "Secret-Access KeyPair Registered"
                    creation_message = "A Secret-Access KeyPair owned by you has been detected"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] {message_header}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            {creation_message} in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Secret-Access KeyPair Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Access Key ID:</b> {access_key_id}<br>
                <b>Associated with IAM User:</b> {secret_access_key_user}<br>
                <b>Created At:</b> {created_at}
            </div><br>
            {remediation_block}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, receiver_email)

    def secret_access_key_expiry_reminder_message(self, severity, iam_user, access_key_id, created_by, creation_date, expiry_date, days_remaining):
        email_subject = f"[{severity}] Secret-Access Key Expiration Reminder!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {created_by},</p>
            A Secret-Access Key Pair you own is approaching its expiry date in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}
            </div><br>
            <b>Secret-Access KeyPair Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Access Key ID:</b> {access_key_id}<br>
                <b>Associated with IAM User:</b> {iam_user}<br>
                <b>Creation Date:</b> {creation_date}<br>
                <b>Expiry Date:</b> {expiry_date}<br>
                <b>Days Remaining:</b> {days_remaining} days
            </div><br>
            Please take the necessary action to rotate this key pair before it expires. If you have any concerns or need assistance, please contact your administrator.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, created_by)

    def login_profile_creation_message(self, severity, iam_user, login_profile_user, created_at, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] AWS Console Access Enabled!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You enabled AWS Console Access in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Console Access Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>IAM User:</b> {login_profile_user}<br>
                <b>Enabled At:</b> {created_at}
            </div><br>
            <b>Remediation Recommendation:</b><br>
            Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User. Please utilize AWS IAM Identity Center for access instead.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def s3_account_public_access_config_modification_message(self, severity, iam_user, restrict_public_buckets, block_public_policy, block_public_acls, ignore_public_acls, incident_number, incident_url):
        restrict_public_buckets = 'Enabled' if restrict_public_buckets else 'Disabled'
        block_public_policy = 'Enabled' if block_public_policy else 'Disabled'
        block_public_acls = 'Enabled' if block_public_acls else 'Disabled'
        ignore_public_acls = 'Enabled' if ignore_public_acls else 'Disabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""

        email_subject = f"[{severity}] S3 Account Block Public Access Settings Modified!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            We have detected that you modified the S3 account block public access setting and disabled it for the following account:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Block Public Access settings for account:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Restrict Public Buckets:</b> {restrict_public_buckets}<br>
                <b>Block Public Policy:</b> {block_public_policy}<br>
                <b>Block Public ACLs:</b> {block_public_acls}<br>
                <b>Ignore Public ACLs:</b> {ignore_public_acls}
            </div><br>
            <b>Remediation Recommendation:</b><br>
            Please enable all of the above settings for S3 Account Block Public Access and block all Public Access.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def s3_account_public_access_auto_remediation_message(self, severity, iam_user):
        email_subject = f"[{severity}] S3 Account Block Public Access Auto Remediated!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            We have detected that you modified the S3 account block public access setting and disabled it for the following account:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}
            </div><br>
            In order to ensure the security and compliance of our AWS account, we have automatically reverted your change and enabled the setting.<br>
            Please be aware that this setting is critical to preventing public access to your S3 buckets, and disabling it may result in data exposure and security risks.<br><br>
            <b>If you have any questions or concerns, please contact our support team for assistance.</b><br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def notifications_suppression_removal_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        alert_message = ""
        if resource_type == 'Security Group':
            alert_message = "Security Group with some ports open to everyone"
        elif resource_type == 'IAM User':
            alert_message = 'IAM User'
        elif resource_type == 'S3 Bucket':
            alert_message = 'S3 Bucket'

        email_subject = f"[{severity}] Notification Continuation Confirmation!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You have removed <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag from {resource_type} {resource_id} in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            <b>Notifications for this specific {alert_message} will now continue until remediated or silenced once again</b><br>
            To disable notifications once again, add the <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag to the resource<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def notifications_suppression_removal_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        email_subject = f"[{severity}] Notification Suppression Disable Failure!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You removed <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag from {resource_type} {resource_id} in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag has been removed from the resource, you DO NOT have permission to enable or disable notifications and alerts for this resource will remain disabled.<br><br>
            <b>Please contact Security to for further help.</b><br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def notifications_suppression_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        silence_message = ""
        if resource_type == 'Security Group':
            silence_message = "Security Group with some ports open to everyone"
        elif resource_type == 'IAM User':
            silence_message = 'IAM User'
        elif resource_type == 'S3 Bucket':
            silence_message = 'S3 Bucket'

        email_subject = f"[{severity}] Suppressed Notification Confirmation!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You have tagged {resource_type} {resource_id} with <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            <b>This will silence the notifications for this {silence_message}</b><br><br>
            To enable notifications, remove the <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag from the resource in order to continue receiving notifications.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def notifications_suppression_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        email_subject = f"[{severity}] Notification Suppression Failure!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You added <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag to {resource_type} {resource_id}  in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag was added to the resource, you DO NOT have permission to enable or disable notifications and you will continue to receive alerts for this resource.<br><br>
            <b>Please contact Security to for further help.</b><br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def s3_public_bucket_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url):
        encryption_enabled_message = ''
        encryption_status = 'Enabled'
        if not is_encryption_enabled:
            encryption_enabled_message = ' and encrypted at REST'
            encryption_status = 'Disabled'

        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Public S3 Bucket!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You enabled Public Access for an S3 Bucket in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>S3 Bucket Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Bucket Name:</b> {s3_bucket_name}<br>
                <b>Encryption:</b> {encryption_status}
            </div><br>
            <b>Remediation Recommendation:</b><br>
            Please check the bucket permissions and ensure this S3 bucket is private{encryption_enabled_message}<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def s3_public_object_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url):
        encryption_status = 'Enabled'
        if not is_encryption_enabled:
            encryption_status = 'Disabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Objects Public in S3 Bucket!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You enabled Public Access for some Objects in S3 Bucket in the following location and can potentially be downloaded externally:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>S3 Bucket Details:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Bucket Name:</b> {s3_bucket_name}<br>
                <b>Encryption:</b> {encryption_status}
            </div><br>
            <b>Remediation Recommendation:</b><br>
            Please check the bucket and/or object permissions and ensure this S3 bucket is private and encrypted at REST.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def unencrypted_volume_creation_bypass_tag_message(self, severity, iam_user, volume_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        remediation_block = """<b>Remediation Recommendation:</b><br>
        Encrypt the volume using AWS Key Management Service (KMS) to safeguard sensitive data and update associated configurations, such as EC2 instance attachments, to use the newly encrypted volume.<br>"""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] { 'Unencrypted EBS Volume Created Bypassing SCP!' if found_bypass_tag else 'EBS Volume Created Without Encryption Enabled!'}"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created an EBS Volume with ID <b>{volume_id}</b> without encryption enabled {'using bypass tag ' if found_bypass_tag else ''}in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_block if not found_bypass_tag else ''}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def root_volume_unencrypted_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        remediation_block = """<b>Remediation Recommendation:</b><br>
        Encrypt the root volume using AWS Key Management Service (KMS) to safeguard sensitive data and update EC2 instance attachments to use the newly encrypted volume.<br>"""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] EC2 Instance launched with unencrypted Root EBS Volume{ ' Bypassing SCP' if found_bypass_tag else ''}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You launched EC2 Instance <b>{instance_id}</b> with unencrypted Root EBS Volume {'using bypass tag ' if found_bypass_tag else ''}in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_block if not found_bypass_tag else ''}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def eip_allocation_scp_block_error_message(self, severity, iam_user):
        email_subject = f"[{severity}] Elastic IP Allocation Blocked!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to allocate an Elastic IP in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            This allocation was blocked because it was an unauthorized action with an <b>explicit deny in a service control policy</b>.<br>
            Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def eip_allocation_bypass_tag_message(self, severity, iam_user, allocation_id, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Elastic IP allocated Bypassing SCP!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You allocated an Elastic IP with ID <b>{allocation_id}</b> against SCP applied on your Organization using bypass tag in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def eip_association_without_override_tag_message(self, severity, iam_user, eip_allocation_id, resource_id, resource_type, override_tag_key, found_override_tag, is_value_base64_encoded, incident_number, incident_url):
        message_title = "Without Proper Tags"
        issue_message = "missing proper tags"
        remediation_message = f"""<b>Add Following Tags to {resource_type}:</b><br>
        <b>{override_tag_key}:</b> <font color=#808080>Base64EncodedSecretKey</font>"""
        if found_override_tag and not is_value_base64_encoded:
            message_title = "With Invalid Tag Value"
            issue_message = f"having invalid value for Tag {override_tag_key}"
            remediation_message = f"Please add valid base64 encoded value for Tag <b>{override_tag_key}</b> to {resource_type}."
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Elastic IP Association {message_title}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You associated Elastic IP with ID <b>{eip_allocation_id}</b> to {resource_type} with ID {resource_id} {issue_message} in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_message}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def public_resource_message(self, severity, iam_user, resource_type, resource_id, auto_remediate, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        remediation_message = f"Since, you have turned auto-remediation on for public {resource_type}, we have automatically made this {resource_type} PRIVATE." if auto_remediate else f"Please make this {resource_type} private and share it with only those AWS accounts you need to share it with."
        email_subject = f"[{severity}] Public {resource_type} Remediated!" if auto_remediate else f"[{severity}] Public {resource_type}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You made {resource_type} with ID <b>{resource_id}</b> PUBLIC in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_message}<br><br>
            Thank you!
        </body>"""
        return self.send_email(email_subject, body_html, iam_user)

    def public_ebs_snapshot_scp_block_error_message(self, severity, iam_user, snapshot_id):
        email_subject = f"[{severity}] EBS Snapshot Permission Modification Blocked!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to modify permissions for EBS Snapshot {snapshot_id} to make it public in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            This modification was blocked due to an SCP policy that restricts making an EBS Snapshot public. Please ensure that you only share it with those AWS accounts you need to share it with.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def public_ebs_snapshot_message(self, severity, iam_user, snapshot_id, auto_remediate, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        remediation_message = "Since, you have turned auto-remediation on for public EBS Snapshots, we have automatically made this snapshot PRIVATE." if auto_remediate else "Please make this EBS Snapshot private and share it with only those AWS accounts you need to share it with."
        email_subject = f"[{severity}] Public EBS Snapshot Remediated!" if auto_remediate else f"[{severity}] Public EBS Snapshot!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You made EBS Snapshot with ID <b>{snapshot_id}</b> PUBLIC in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            {remediation_message}<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def secret_creation_without_tags_message(self, severity, iam_user, secret_name, secret_arn, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Secret Created Without Proper Tags!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created a SecretsManager Secret named <b>{secret_name}</b> without proper tags in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Add Following Tags to Secret:</b><br>
            {self.__get_tags(tags)}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def backup_plan_creation_without_tags_message(self, severity, iam_user, backup_plan_name, backup_plan_arn, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Backup Plan Created Without Proper Tags!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created a Backup Plan named <b>{backup_plan_name}</b> without proper tags in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
                <b>Backup Plan:</b> {backup_plan_arn}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Add Following Tags to Backup Plan:</b><br>
            {self.__get_tags(tags)}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def loadbalancer_creation_bypass_tag_message(self, severity, iam_user, loadbalancer_name, lb_type, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] LoadBalancer Created Bypassing SCP!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created a LoadBalancer named <b>{loadbalancer_name}</b> against SCP applied on your Organization using bypass tag in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br><br>
                <b>LoadBalancer Type:</b> {lb_type}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def loadbalancer_creation_without_tags_message(self, severity, iam_user, loadbalancer_name, loadbalancer_arn, lb_type, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] LoadBalancer Created Without Proper Tags!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created a LoadBalancer named <b>{loadbalancer_name}</b> without proper tags in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br><br>
                <b>LoadBalancer Type:</b> {lb_type}<br>
                <b>LoadBalancer ARN:</b> {loadbalancer_arn}
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <b>Add Following Tags to LoadBalancer:</b><br>
            {self.__get_tags(tags)}<br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def loadbalancer_creation_scp_block_error_message(self, severity, iam_user, lb_type):
        email_subject = f"[{severity}] LoadBalancer Creation Blocked!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to create a LoadBalancer in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br><br>
                <b>LoadBalancer Type:</b> {lb_type}
            </div><br>
            This creation was blocked because it was an unauthorized action with an <b>explicit deny in a service control policy</b>.<br>
            Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def overpermissive_role_policy_deleted_message(self, severity, iam_user, role_name, resources, policy_name):
        email_subject = f"[{severity}] Over Permissive IAM Role Policy [DELETED]"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            This is to inform you that the over permissive policy named {policy_name} has been detached/deleted from IAM Role.<br>
            You created/attached an over-permissive policy to IAM Role {role_name} which is attached to EC2 Instance in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
            </div><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                {"<br>".join([str(elem) for elem in resources])}
            </div><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def overpermissive_role_policy_attached_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Over Permissive IAM Role Policy Found"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created/attached an over-permissive policy named {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                {"<br>".join([str(elem) for elem in resources])}
            </div><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def overpermissive_role_policy_bypass_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        email_subject = f"[{severity}] Over Permissive IAM Role Policy [BYPASSED]"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You created/attached an over-permissive policy {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
            </div><br>
            {pagerduty_block if pagerduty_block else ''}
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                {"<br>".join([str(elem) for elem in resources])}
            </div><br>
            This policy was not deleted/detached because Admin has used <b>bypass tag</b> on IAM Role.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def launch_wizard_security_group_replaced(self, is_create_event, severity, iam_user, group_name, resource_type, attachments: list, is_replaced_by_blackhole_sg, is_deleted, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""<b>PagerDuty Incident:</b><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>Incident Number:</b> {incident_number}<br>
                <b>Details:</b> <a href="{incident_url}">Incident Details</a><br>
            </div><br>"""
        deleted_header = ""
        deleted_message = " but hasn't been deleted because its also attached to some other resource"
        if is_deleted:
            deleted_header = " and Deleted"
            deleted_message = " and has been deleted"

        email_subject = f"[{severity}] Launch Wizard Security Group Replaced{deleted_header}!"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You {f'created <b>{group_name}</b> security group and attached it' if is_create_event else f'attached <b>{group_name}</b> security group'} to {resource_type} {', '.join(attachments)} in the following location:<br><br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
            </div><br><br>
            {pagerduty_block if pagerduty_block else ''}
            This Security Group has been replaced by a <b>blackhole</b> security group{deleted_message}.<br><br>
            Thank you!
        </body>
        """
        return self.send_email(email_subject, body_html, iam_user)

    def resource_creation_wo_required_tags_scp_block_error_message(self, severity: str, resource_type: str, iam_user: str, tags: list):
        email_subject = f"[{severity}] {resource_type} Creation Failed Due to Missing Tags"
        body_html = f"""<body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <p>Hello {iam_user},</p>
            You tried to create {resource_type} with missing tags in the following location:<br>
            <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                <b>AWS Organization:</b> {self.org_name}<br>
                <b>AWS Account Name:</b> {self.account_name}<br>
                <b>AWS Account ID:</b> {self.account_id}<br>
                <b>AWS Region:</b> {self.region}<br>
            </div><br>
            Please add the following missing tags to {resource_type} to have it successfully create:<br><br>
            {self.__get_tags(tags)}<br>
            Thank you!
        </body>"""
        return self.send_email(email_subject, body_html, iam_user)

    def send_daily_cost_report(self, user: str, current_date: str, hr24_resources_table, hr24_old_resources_table, stopped_resources_table) -> bool:
        email_subject = f"Daily AWS Cost Report Summary - {current_date}"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            Hello {user},<br><br>
            Here is today's Cost Summary for your AWS Resources:<br><br>
            {hr24_resources_table if hr24_resources_table else ''}
            {hr24_old_resources_table if hr24_old_resources_table else ''}
            {stopped_resources_table if stopped_resources_table else ''}

            As part of our ongoing commitment to efficient resource allocation, it is crucial for everyone to play their part in optimizing costs. AWS provides a vast array of powerful services and resources, enabling us to build and scale our applications effectively. However, it's equally
            essential to ensure that we are utilizing these resources optimally and not incurring unnecessary expenses. By actively monitoring and managing our AWS infrastructure, we can significantly reduce costs without compromising performance or functionality.<br><br>
            We kindly request your cooperation in reviewing your current resource usage and identifying any areas where adjustments can be made. If you no longer require certain resources or if they can be right-sized to better match your needs, we encourage you to take action and make the necessary changes. Doing so will not only help us optimize costs but also contribute to a more sustainable and responsible use of AWS services.
            <br><br>
            Thank you!
        </body>"""
        return self.send_email(email_subject, body_html, user)

    def send_weekly_cost_report(self, user: str, one_day_prior_date: str, last_week_start_date: str, user_resources_table, percentage_status) -> bool:
        email_subject = f"Weekly AWS Cost Report Summary - {last_week_start_date} to {one_day_prior_date}"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            Hello {user},<br><br>
            Here is your Cost Summary for this week for your AWS Resources:<br><br>
            {user_resources_table if user_resources_table else ''}

            We would like to inform you that your cost for AWS resources this week is <b>{percentage_status}</b> compared to last week. Please review your usage and budget accordingly. By actively monitoring and managing our AWS infrastructure, we can significantly reduce costs without compromising performance or functionality.<br><br>
            We kindly request your cooperation in reviewing your current resource usage and identifying any areas where adjustments can be made. If you no longer require certain resources or if they can be right-sized to better match your needs, we encourage you to take action and make the necessary changes. Doing so will not only help us optimize costs but also contribute to a more sustainable and responsible use of AWS services.
            <br><br>
            Thank you!
        </body>"""
        return self.send_email(email_subject, body_html, user)

    def send_monthly_cost_report(self, user: str, one_day_prior_date: datetime.date, last_month_start_date: datetime.date, user_resources_table, percentage_status) -> bool:
        email_subject = f"Monthly AWS Cost Report Summary - {last_month_start_date.strftime('%b %d, %Y')} to {one_day_prior_date.strftime('%b %d, %Y')}"
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            Hello {user},<br><br>
            Here is your Cost Summary for month {one_day_prior_date.strftime("%B")} for your AWS Resources:<br><br>
            {user_resources_table if user_resources_table else ''}

            We would like to inform you that your cost for AWS resources for month {one_day_prior_date.strftime("%B")} is <b>{percentage_status}</b> compared to last month. Please review your usage and budget accordingly. By actively monitoring and managing our AWS infrastructure, we can significantly reduce costs without compromising performance or functionality.<br><br>
            We kindly request your cooperation in reviewing your current resource usage and identifying any areas where adjustments can be made. If you no longer require certain resources or if they can be right-sized to better match your needs, we encourage you to take action and make the necessary changes. Doing so will not only help us optimize costs but also contribute to a more sustainable and responsible use of AWS services.
            <br><br>
            Thank you!
        </body>"""
        return self.send_email(email_subject, body_html, user)

    @staticmethod
    def __get_account_name(account_id):
        """
        Get the name of the AWS account associated with the given account ID.
        Args:
            account_id (str): The ID of the AWS account to look up.
        Returns:
            str: The name of the AWS account associated with the given account ID.
        Raises:
            botocore.exceptions.ClientError: If there is an error making the API call to describe the account.
        """
        return DEPLOYMENT_TARGET_ACCOUNTS[account_id]

    def __get_tags(self, tags):
        tags_msg = ''
        for tag in tags:
            if '=' in tag:
                key_value = tag.split('=')
                tags_msg += f'{key_value[0]}: <font color=#808080>{key_value[1]}</font><br>'
            else:
                tags_msg += f'• {tag}<br>'
        return tags_msg
