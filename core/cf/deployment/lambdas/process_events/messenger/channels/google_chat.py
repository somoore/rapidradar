from typing import Optional
import re
class GoogleChatMessenger():
    def __init__(self, account_id, account_name, org_name, region):
        self.account_id = account_id
        self.account_name = account_name
        self.org_name = org_name
        self.region = region

    def get_message(self, alert_id, message_params: dict):
        method = getattr(Messages(self.account_id, self.account_name, self.org_name, self.region), alert_id)
        return method(**message_params)

class Messages():
    def __init__(self, account_id, account_name, org_name, region):
        self.account_id = account_id
        self.account_name = account_name
        self.org_name = org_name
        self.region = region

    @staticmethod
    def __get_tags(tags):
        tags_msg = ''
        for tag in tags:
            if '=' in tag:
                key_value = tag.split('=')
                tags_msg += f'{key_value[0]}: <font color=\"#808080\">{key_value[1]}</font><br>'
            else:
                tags_msg += f'• {tag}<br>'
        return tags_msg

    @staticmethod
    def __is_user_email(iam_user):
        match = re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', iam_user)
        if match is not None:
            return True
        return False

    @staticmethod
    def __get_formatted_json(text_json):
        return {
            "cards": [{
                "sections": [{
                    "widgets": [{
                        "textParagraph": {
                            "text": f"{text_json}"
                        }
                    }]
                }]
            }]
        }

    @staticmethod
    def __get_sg_attachment_details(is_attached, attached_instances, attached_lb):
        attachment_details = []
        if attached_instances or attached_lb:
            attachment_details = []
            attachment_details.append("<b>Attachment Details:</b>")
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
        attachment_details = '<br>'.join(attachment_details) if attachment_details else '<b>Attachment:</b> Currently Not Attached to Any Resource' if not is_attached else ''
        return attachment_details

    @staticmethod
    def __get_pagerduty_incidents_details(incidents: list):
        pagerduty_incidents_details = {}
        if len(incidents) > 0:
            pagerduty_incidents = []
            for incident in incidents:
                pagerduty_incidents.append(f"<a href='{incident['IncidentUrl']}'>{incident['IncidentNumber']}</a>")
            pagerduty_incidents_details = f"""
            <b>PagerDuty Incidents:</b>
            {', '.join(pagerduty_incidents)}"""
        return pagerduty_incidents_details

    def resource_creation_without_tags_message(self, severity, iam_user, resource_type, resource_id, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{resource_type} Created Without Proper Tags!</font></b>

        User {iam_user} created {resource_type} <b>{resource_id}</b> without proper tags in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>Add Following Tags to {resource_type}:</b>
        {self.__get_tags(tags)}"""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all(self, severity, iam_user, ip_protocol, port, security_group_id, security_group_rule_id, is_attached, attached_instances, attached_lb, is_critical, incident_number, incident_url):
        remediation_message = 'Please Close Access to 0.0.0.0/0'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        if is_attached and attached_instances:
            remediation_message = """Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."""
        elif not is_attached:
            remediation_message = """Either Attach Security Group to a Resource or Delete it."""
        message = f"""<b>[{severity}] <font color=\"#{'FF0000' if is_critical else 'E1AD01'}\">Security Group Ingress Open to Everyone!</font></b>

        User {iam_user} opened a {ip_protocol} port to <b>0.0.0.0/0</b> in Security Group Ingress in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>Ingress Details:</b>
        Security Group ID: {security_group_id}
        Security Group Rule ID: {security_group_rule_id}
        IP Protocol: {ip_protocol}
        Port: {port}

        {attachment_details}

        {f"<b>Remediation Recommendation:</b><br>{remediation_message}" if is_critical else ''}"""
        return self.__get_formatted_json(message)

    def critical_port_closed_message(self, severity, security_group_id, ip_protocol, port):
        message = f"""<b>[{severity}] Security Group Ingress Port Closed!</b>

        {ip_protocol} port{'' if port == '-1' else f' {port}'} was open to the 0.0.0.0/0 IP range, which is against our company's security policy. Therefore, we have taken the necessary steps to {'delete' if port == '-1' else 'close'} this port to prevent unauthorized access to your resources with following details:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        Security Group ID: {security_group_id}

        <b>Please note that in future, {'' if port == '-1' else f'to access resources over port {port}, '}you should either use SSM Session Manager or an ACL Inbound rule with your IP address/32. These are both secure methods for accessing resources over the internet and will help to ensure the safety and integrity of your AWS resources.</b>
        """
        return self.__get_formatted_json(message)

    def ec2_launch_scp_block_error_message(self, severity, iam_user, is_imdsv2_failure=False, is_unencrypted_ebs_failure=False, is_publicip_failure=False, bypass_tag_key=None):
        remediation_message = ""
        failure_reason = "The launch failed due to an SCP policy restricting the deployment of instances "
        if is_imdsv2_failure:
            failure_reason += "without IMDSv2 enabled. Please ensure that the EC2 instance is launched with IMDSv2 enabled."
            remediation_message = f"""
        If you have a specific use case that requires launching an instance without IMDSv2 enabled, you can bypass this SCP policy by tagging your instance with the following key and value:
        <b>{bypass_tag_key}: enabled</b>"""
        if is_unencrypted_ebs_failure:
            failure_reason += "with unencrypted Root EBS Volume. Please ensure that the EC2 instance is launched with encrypted Root EBS Volume."
            remediation_message = f"""
        If you have a specific use case that requires launching an instance without encrypted Root EBS Volume, you can bypass this SCP policy by tagging your instance with the following key and value:
        <b>{bypass_tag_key}: enabled</b>"""
        if is_publicip_failure:
            failure_reason += "with Public IP. Please ensure that the EC2 instance is launched without Public IPs."
        message = f"""<b>[{severity}] <font color=\"#FF0000\">EC2 Deployment Failed!</font></b>

        User {iam_user} tried to launch EC2 Instance in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        {failure_reason}
        {remediation_message}"""
        return self.__get_formatted_json(message)

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
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{msg_header}</font></b>

        User {iam_user} launched EC2 Instance {instance_status} in the following location and with following details:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        Instance ID: {instance_id}
        {pagerduty_block if pagerduty_block else ''}
        {remediation_block}"""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all_attached_to_public_resource(self, severity, iam_user, security_group_id, resource_type, ports, is_attached, attached_instances, attached_lb, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Security Group Attached to {resource_type} with ports Open to 0.0.0.0/0!</font></b>

        User {iam_user} attached a Security Group with ports open to 0.0.0.0/0 to {resource_type} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>Ingress Details:</b>
        Security Group ID: {security_group_id}
        Ports: {', '.join(ports).replace("-1", "All Traffic")}

        {attachment_details}

        <b>Remediation Recommendation:</b>
        Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all_attachment_remediation_message(self, severity, port, security_group_id, is_attached, attached_instances, attached_lb, is_deleted):
        conditional_message = ""
        ingress_details = ""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        if is_deleted:
            conditional_message = f"Security group with ID <b>{security_group_id}</b> got remediated and does not exist anymore"
        elif not is_deleted:
            conditional_message = "Security Group with ports open to everyone got remediated"
            ingress_details = f"""
            <b>Here are the Ingress Details:</b>
            Security Group ID: {security_group_id}
            Ports: {', '.join(port).replace("-1", "All Traffic")}

            {attachment_details}"""
        message = f"""<b>[{severity}] Security Group Remediated!</b>

        {conditional_message} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {ingress_details}
        """
        return self.__get_formatted_json(message)

    def iam_user_password_change_message(self, severity, iam_user, affected_user, is_failed, user_agent, source_ip_address, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">IAM User Password {'Change Attempt Failed' if is_failed else 'Changed'}!</font></b>

        User {iam_user} {'tried to change' if is_failed else 'changed'} console password for IAM User {affected_user} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        User Agent: {user_agent}
        Source IP Address: {source_ip_address}

        <b><font color=\"#FF0000\">Action Required:</font></b>
        Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation. Disable compromised accounts if necessary. Communicate with affected users and consider implementing Multi-Factor Authentication (MFA). Enhance monitoring, update IAM policies, and document the incident for future reference, ensuring preventive measures are in place to mitigate recurrence."""
        return self.__get_formatted_json(message)

    def iam_user_creation_scp_block_error_message(self, severity, iam_user, is_creation_blocked, is_creation_blocked_wo_tags, iam_user_creation_scp_tag_keys):
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
        message = f"""<b>[{severity}] <font color=\"#FF0000\">IAM User Creation Failed!</font></b>
        User {iam_user} tried to create an IAM User in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        The creation failed due to an SCP policy restricting the creation of IAM Users{block_message}

        {remediation_message}"""
        return self.__get_formatted_json(message)

    def iam_user_creation_bypass_tag_message(self, severity, iam_user, new_iam_user, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = """
        <b>Remediation Recommendation:</b>
        Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">New IAM User Created{bypass_msg_header}!</font></b>

        User {iam_user} created an IAM User {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        IAM User: {new_iam_user}
        {pagerduty_block if pagerduty_block else ''}
        {remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def iam_user_remediation_message(self, severity, iam_user):
        message = f"""<b>[{severity}] IAM User Remediated!</b>

        IAM User <b>{iam_user}</b> does not exist anymore in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        """
        return self.__get_formatted_json(message)

    def secret_access_key_creation_message(self, severity, is_new, iam_user, secret_access_key_user, access_key_id, created_by, created_at, deploy_iam_keypair_access_tracker_project, incident_number, incident_url):
        message_header = "New Secret-Access KeyPair Generated"
        creation_message = f"User {iam_user} created a new Secret-Access KeyPair"
        pagerduty_block = {}
        remediation_block = """
        <b>Remediation Recommendation:</b>
        Please DELETE this newly generated Secret-Access KeyPair and utilize IAM Roles or AWS IAM Identity Center instead."""
        if deploy_iam_keypair_access_tracker_project:
            remediation_block = """
            This Secret-Access KeyPair has been successfully registered in our tracking system for security and compliance purposes. If you did not create this key pair or have any concerns, please contact your administrator."""
            if is_new:
                message_header += " and Registered"
                owner_message = f"is owned by {created_by}" if self.__is_user_email(created_by) else "its owner is unknown"
                creation_message = f"A new Secret-Access KeyPair has been created and {owner_message}"
            else:
                message_header = "Secret-Access KeyPair Registered"
                owner_message = f"{created_by}" if self.__is_user_email(created_by) else "unknown owner"
                creation_message = f"A Secret-Access KeyPair owned by {owner_message} has been detected"
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{message_header}!</font></b>

        {creation_message} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        <b>Secret-Access KeyPair Details:</b>
        Access Key ID: {access_key_id}
        Associated with IAM User: {secret_access_key_user}
        Created At: {created_at}
        {remediation_block}"""
        return self.__get_formatted_json(message)

    def secret_access_key_expiry_reminder_message(self, severity, iam_user, access_key_id, created_by, creation_date, expiry_date, days_remaining):
        owner_message = f"{created_by}" if self.__is_user_email(created_by) else "unknown owner"
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Secret-Access Key Expiration Reminder!</font></b>

        A Secret-Access Key Pair owned by {owner_message} is approaching its expiry date in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        <b>Secret-Access KeyPair Details:</b>
        Access Key ID: {access_key_id}
        Associated with IAM User: {iam_user}
        Creation Date: {creation_date}
        Expiry Date: {expiry_date}
        Days Remaining: {days_remaining} days

        Please take the necessary action to rotate this key pair before it expires. If you have any concerns or need assistance, please contact your administrator.
        """
        return self.__get_formatted_json(message)

    def login_profile_creation_message(self, severity, iam_user, login_profile_user, created_at, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">AWS Console Access Enabled!</font></b>

        User {iam_user} enabled AWS Console Access in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        <b>Console Access Details:</b>
        IAM User: {login_profile_user}
        Enabled At: {created_at}

        <b>Remediation Recommendation:</b>
        Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User. Please utilize AWS IAM Identity Center for access instead."""
        return self.__get_formatted_json(message)

    def s3_account_public_access_auto_remediation_message(self, severity, iam_user):
        message = f"""<b>[{severity}] S3 Account Block Public Access Auto Remediated!</b>

        We have detected that user {iam_user} modified the S3 account block public access setting and disabled it for the following account:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        In order to ensure the security and compliance of our AWS account, we have automatically reverted your change and enabled the setting.
        Please be aware that this setting is critical to preventing public access to your S3 buckets, and disabling it may result in data exposure and security risks.

        <b>If you have any questions or concerns, please contact our support team for assistance.</b>
        """
        return self.__get_formatted_json(message)

    def s3_account_public_access_config_modification_message(self, severity, iam_user, restrict_public_buckets, block_public_policy, block_public_acls, ignore_public_acls, incident_number, incident_url):
        restrict_public_buckets = 'Enabled' if restrict_public_buckets else 'Disabled'
        block_public_policy = 'Enabled' if block_public_policy else 'Disabled'
        block_public_acls = 'Enabled' if block_public_acls else 'Disabled'
        ignore_public_acls = 'Enabled' if ignore_public_acls else 'Disabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">S3 Account Block Public Access Settings Modified!</font></b>

        User {iam_user} modified S3 Block Public Access Settings for the following account:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        <b>Block Public Access settings for account</b>
        Restrict Public Buckets: {restrict_public_buckets}
        Block Public Policy: {block_public_policy}
        Block Public ACLs: {block_public_acls}
        Ignore Public ACLs: {ignore_public_acls}

        <b>Remediation Recommendation:</b>
        Please enable all of the above settings for S3 Account Block Public Access and block all Public Access."""
        return self.__get_formatted_json(message)

    def notifications_suppression_removal_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        alert_message = ""
        if resource_type == 'Security Group':
            alert_message = "Security Group with some ports open to everyone"
        elif resource_type == 'IAM User':
            alert_message = 'IAM User'
        elif resource_type == 'S3 Bucket':
            alert_message = 'S3 Bucket'
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Notification Continuation Confirmation!</font></b>

        User {iam_user} has removed <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag from {resource_type} {resource_id} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        <b>Notifications for this specific {alert_message} will now continue until remediated or silenced once again</b>

        To disable notifications once again, add the <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag to the resource
        """
        return self.__get_formatted_json(message)

    def notifications_suppression_removal_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Notification Suppression Disable Failure!</font></b>

        User {iam_user} removed <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag from {resource_type} {resource_id} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag has been removed from the resource, User {iam_user} does not have permission to enable or disable notifications and alerts for this resource will remain disabled.
        <b>Please contact Security to for further help.</b>
        """
        return self.__get_formatted_json(message)

    def notifications_suppression_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        silence_message = "Security Group with some ports open to everyone" if resource_type == 'Security Group' else resource_type
        message = f"""<b>[{severity}] Suppressed Notification Confirmation!</b>

        User {iam_user} has tagged {resource_type} {resource_id} with <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        <b>This will silence the notifications for this {silence_message}</b>

        To enable notifications, remove the <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag from the resource in order to continue receiving notifications.
        """
        return self.__get_formatted_json(message)

    def notifications_suppression_failure_message(self, severity, iam_user, resource_type, resource_id, alert_suppression_tag_key, alert_suppression_tag_value):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Notification Suppression Failure!</font></b>

        User {iam_user} added <b>{alert_suppression_tag_key}={alert_suppression_tag_value}</b> tag to {resource_type} {resource_id} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        Even though {alert_suppression_tag_key}={alert_suppression_tag_value} tag was added to the resource, User {iam_user} does not have permission to enable or disable notifications and you will continue to receive alerts for this resource.
        <b>Please contact Security to for further help.</b>
        """
        return self.__get_formatted_json(message)

    def s3_public_bucket_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url):
        encryption_enabled_message = ' and encrypted at REST' if not is_encryption_enabled else ''
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Public S3 Bucket!</font></b>

        User {iam_user} enabled Public Access for an S3 Bucket in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>S3 Bucket Details:</b>
        Bucket Name: {s3_bucket_name}
        Encryption: {encryption_status}

        <b>Remediation Recommendation:</b>
        Please check the bucket permissions and ensure this S3 bucket is private{encryption_enabled_message}."""
        return self.__get_formatted_json(message)

    def s3_public_object_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled, incident_number, incident_url):
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Objects Public in S3 Bucket!</font></b>

        User {iam_user} enabled Public Access for some Objects in S3 Bucket in the following location and can potentially be downloaded externally:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>S3 Bucket Details:</b>
        Bucket Name: {s3_bucket_name}
        Encryption: {encryption_status}

        <b>Remediation Recommendation:</b>
        Please check the bucket and/or object permissions and ensure this S3 bucket is private and encrypted at REST."""
        return self.__get_formatted_json(message)

    def s3_public_bucket_deletion_remediation_message(self, severity, bucket_name):
        message = f"""<b>[{severity}] Public S3 Bucket Remediated!</b>

        S3 Bucket <b>{bucket_name}</b> has been deleted and does not exist anymore in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        """
        return self.__get_formatted_json(message)

    def ec2_instance_profile_auto_remediated(self, severity, role_name, ec2_instances):
        message = f"""<b>[{severity}] EC2 Instance Profile Auto-Remediated!</b>
        IAM role was disassociated from EC2 instance [{', '.join(ec2_instances)}] in the following location:"

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        As part of our security measures, IAM Role named {role_name} with required policies has been associated to this EC2 instance to ensure proper access and security controls are maintained."""
        return self.__get_formatted_json(message)

    def iam_role_auto_remediation(self, severity, role_name, policy, ec2_instances):
        message = f"""<b>[{severity}] IAM Role Auto-Remediated!</b>

        The IAM role named {role_name} associated with EC2 instance(s) [{', '.join(ec2_instances)}] had certain policies detached in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        Detached Policies: {policy}

        As part of our security measures, the policies have been re-attached to ensure proper access and security controls are maintained."""
        return self.__get_formatted_json(message)

    def ec2_creation_invoked_by_aws_service_action_message(self, severity, instances, service, action, to_do_list, incident_number, incident_url):
        to_do_list = "<br>".join(to_do_list) if to_do_list else ''
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        action_message = f"""<b>deleted in 10 minutes</b> if the following actions are not taken:
        { to_do_list }

        <b>Or you can also tag your resource(s) with keep-alive=true tag to bypass deletion</b>""" if action == 'Delete' else 'ignored'
        message = f"""<b>[{severity}] <font color=\"#FF0000\">EC2 Instance(s) launched by AWS Service bypassing SCPs</font></b>
        EC2 Instance(s) were launched by <b>{service}</b> against SCPs applied on your Organization in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        Instance IDs: {', '.join(instances)}
        {pagerduty_block if pagerduty_block else ''}

        <b>While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.</b>
        So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def unencrypted_ebs_vol_creation_invoked_by_aws_service_action_message(self, severity, volume, service, action, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        action_message = """deleted in 10 minutes if the following actions are not taken:

        Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        message = f"""<b>[{severity}] <font color=\"#FF0000\">EBS Volume created by AWS Service bypassing SCPs</font></b>
        EBS Volume was created by <b>{service}</b> against SCPs applied on your Organization in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        EBS Volume: {volume}
        {pagerduty_block if pagerduty_block else ''}

        <b>While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.</b>
        So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_invoked_by_aws_service_action_message(self, severity, loadbalancer, service, action, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        action_message = """deleted in 10 minutes if the following actions are not taken:

        Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        message = f"""<b>[{severity}] <font color=\"#FF0000\">LoadBalancer created by AWS Service bypassing SCPs</font></b>
        LoadBalancer was created by <b>{service}</b> against SCPs applied on your Organization in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        LoadBalancer Name: {loadbalancer}
        {pagerduty_block if pagerduty_block else ''}

        <b>While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.</b>
        So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_bypass_tag_message(self, severity, iam_user, loadbalancer_name, lb_type, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">LoadBalancer Created Bypassing SCP!</font></b>
        User {iam_user} created a LoadBalancer named <b>{loadbalancer_name}</b> against SCP applied on your Organization using bypass tag in the following location and with following details:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        LoadBalancer Type: {lb_type}
        {pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def eip_allocation_invoked_by_aws_service_action_message(self, severity, allocation_id, service, action, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        action_message = """deleted in 10 minutes if the following actions are not taken:

        Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Elastic IP allocated by AWS Service bypassing SCPs</font></b>
        Elastic IP was allocated by <b>{service}</b> against SCPs applied on your Organization in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        EIP Allocation ID: {allocation_id}
        {pagerduty_block if pagerduty_block else ''}

        <b>While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.</b>
        So, these resources will be {action_message}"""
        return self.__get_formatted_json(message)

    def eip_allocation_bypass_tag_message(self, severity, iam_user, allocation_id, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Elastic IP allocated Bypassing SCP!</font></b>
        User {iam_user} allocated an Elastic IP with ID <b>{allocation_id}</b> against SCP applied on your Organization using bypass tag in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def unencrypted_volume_creation_bypass_tag_message(self, severity, iam_user, volume_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        msg_header = "Unencrypted EBS Volume Created Bypassing SCP!" if found_bypass_tag else "EBS Volume Created Without Encryption Enabled!"
        remediation_block = """
        <b>Remediation Recommendation:</b>
        Encrypt the volume using AWS Key Management Service (KMS) to safeguard sensitive data and update associated configurations, such as EC2 instance attachments, to use the newly encrypted volume."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{msg_header}</font></b>

        User {iam_user} created an EBS Volume with ID <b>{volume_id}</b> without encryption enabled {'using bypass tag ' if found_bypass_tag else ''}in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}
        {remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def root_volume_unencrypted_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        remediation_block = """
        <b>Remediation Recommendation:</b>
        Encrypt the root volume using AWS Key Management Service (KMS) to safeguard sensitive data and update EC2 instance attachments to use the newly encrypted volume."""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">EC2 Instance launched with unencrypted Root EBS Volume{ ' Bypassing SCP' if found_bypass_tag else ''}!</font></b>

        User {iam_user} launched EC2 Instance <b>{instance_id}</b> with unencrypted Root EBS Volume {'using bypass tag ' if found_bypass_tag else ''}in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}
        {remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def eip_allocation_scp_block_error_message(self, severity, iam_user):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Elastic IP Allocation Blocked!</font></b>

        User {iam_user} tried to allocate an Elastic IP in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        This allocation was blocked because it was an unauthorized action with an <b>explicit deny in a service control policy</b>.
        Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance.
        """
        return self.__get_formatted_json(message)

    def eip_association_without_override_tag_message(self, severity, iam_user, eip_allocation_id, resource_id, resource_type, override_tag_key, found_override_tag, is_value_base64_encoded, incident_number, incident_url):
        message_title = "Without Proper Tags"
        issue_message = "missing proper tags"
        remediation_message = f"""<b>Add Following Tags to {resource_type}:</b>
        {override_tag_key}: <font color=\"#808080\">Base64EncodedSecretKey</font>"""
        if found_override_tag and not is_value_base64_encoded:
            message_title = "With Invalid Tag Value"
            issue_message = f"having invalid value for Tag {override_tag_key}"
            remediation_message = f"Please add valid base64 encoded value for Tag <b>{override_tag_key}</b> to {resource_type}"
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Elastic IP Association {message_title}!</font></b>

        User {iam_user} associated Elastic IP with ID <b>{eip_allocation_id}</b> to {resource_type} with ID {resource_id} {issue_message} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        {remediation_message}"""
        return self.__get_formatted_json(message)

    def public_resource_message(self, severity, iam_user, resource_type, resource_id, auto_remediate, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        remediation_message = f"Please make this {resource_type} private and share it with only those AWS accounts you need to share it with."
        alert_title = f"<font color=\"#FF0000\">Public {resource_type}!</font>"
        if auto_remediate:
            remediation_message = f"Since, you have turned auto-remediation on for public {resource_type}, we have automatically made this {resource_type} PRIVATE."
            alert_title = f"Public {resource_type} Remediated!"
        message = f"""<b>[{severity}] {alert_title}</b>

        User {iam_user} made an {resource_type} with ID <b>{resource_id}</b> PUBLIC in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>{remediation_message}</b>"""
        return self.__get_formatted_json(message)

    def public_ebs_snapshot_scp_block_error_message(self, severity, iam_user, snapshot_id):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">EBS Snapshot Permission Modification Blocked!</font></b>

        User {iam_user} tried to modify permissions for EBS Snapshot {snapshot_id} to make it public in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        <b>This modification was blocked due to an SCP policy that restricts making an EBS Snapshot public. Please ensure that you only share it with those AWS accounts you need to share it with.</b>"""
        return self.__get_formatted_json(message)

    def public_ebs_snapshot_message(self, severity, iam_user, snapshot_id, auto_remediate, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        remediation_message = "Since, you have turned auto-remediation on for public EBS Snapshots, we have automatically made this snapshot PRIVATE." if auto_remediate else "Please make this EBS Snapshot private and share it with only those AWS accounts you need to share it with."
        title = f"[{severity}] Public EBS Snapshot Remediated!" if auto_remediate else f"[{severity}] <font color=\"#FF0000\">Public EBS Snapshot!</font>"
        message = f"""<b>{title}</b>

        User {iam_user} made EBS Snapshot with ID <b>{snapshot_id}</b> PUBLIC in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>{remediation_message}</b>"""
        return self.__get_formatted_json(message)

    def secret_creation_without_tags_message(self, severity, iam_user, secret_name, secret_arn, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Secret Created Without Proper Tags!</font></b>

        User {iam_user} created a SecretsManager Secret named <b>{secret_name}</b> without proper tags in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>Add Following Tags to Secret:</b>
        {self.__get_tags(tags)}"""
        return self.__get_formatted_json(message)

    def backup_plan_creation_without_tags_message(self, severity, iam_user, backup_plan_name, backup_plan_arn, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}]<font color=\"#FF0000\">Backup Plan Created Without Proper Tags!</font></b>

        User {iam_user} created a Backup Plan named <b>{backup_plan_name}</b> without proper tags in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        Backup Plan ARN: {backup_plan_arn}
        {pagerduty_block if pagerduty_block else ''}

        <b>Add Following Tags to Backup Plan:</b>
        {self.__get_tags(tags)}"""
        return self.__get_formatted_json(message)

    def loadbalancer_creation_without_tags_message(self, severity, iam_user, loadbalancer_name, loadbalancer_arn, lb_type, tags, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}]<font color=\"#FF0000\">LoadBalancer Created Without Proper Tags!</font></b>

        User {iam_user} created a LoadBalancer named <b>{loadbalancer_name}</b> without proper tags in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        LoadBalancer Type: {lb_type}
        LoadBalancer ARN: {loadbalancer_arn}
        {pagerduty_block if pagerduty_block else ''}

        <b>Add Following Tags to LoadBalancer:</b>
        {self.__get_tags(tags)}"""
        return self.__get_formatted_json(message)

    def unencrypted_rds_creation_bypass_tag_message(self, severity, iam_user, db_identifier, resource_type, found_bypass_tag, incident_number: Optional[str] = None, incident_url: Optional[str] = None):
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = f"""
        <b>Please add encryption to this {resource_type} by creating a snapshot of it, and then creating an encrypted copy of that snapshot and then restore an {resource_type} from the encrypted snapshot</b>"""
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{resource_type} Created Without Encryption Enabled{bypass_msg_header}!</font></b>

        User {iam_user} created an {resource_type} with ID <b>{db_identifier}</b> without encryption enabled {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}
        {remediation_block if not found_bypass_tag else ''}"""
        return self.__get_formatted_json(message)

    def ebs_vol_rds_creation_without_encryption_missing_tags_scp_block_error_message(self, severity, iam_user, resource_type, is_unencrypted, bypass_tag_key, is_missing_tags, scp_tags):
        scp_message = ''
        remediated_message = ''
        bypass_message = f"""If you have a specific use case that requires creating an {resource_type} without encryption, you can bypass this SCP policy by tagging your {resource_type} with the following key and value:
<b>{bypass_tag_key}: enabled</b>"""
        if is_unencrypted and is_missing_tags:
            scp_message = 'without encryption enabled and certain tags'
            remediated_message = f"""with encryption enabled and following tags:

            {', '.join(scp_tags)}"""
        elif is_unencrypted or is_missing_tags:
            scp_message = 'without encryption enabled' if is_unencrypted else 'without certain tags'
            remediated_message = "with encryption enabled" if is_unencrypted else f"""with following tags:

            {', '.join(scp_tags)}"""
            bypass_message = '' if is_missing_tags else bypass_message
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{resource_type} Creation Blocked!</font></b>

        User {iam_user} tried to create an {resource_type} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        The launch failed due to an SCP policy restricting the creation of {resource_type}s {scp_message}. Please ensure that the {resource_type} is created {remediated_message}

        {bypass_message}
        """
        return self.__get_formatted_json(message)

    def loadbalancer_creation_scp_block_error_message(self, severity, iam_user, lb_type):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">LoadBalancer Creation Blocked!</font></b>

        User {iam_user} tried to create a LoadBalancer in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        LoadBalancer Type: {lb_type}

        This creation was blocked because it was an unauthorized action with an <b>explicit deny in a service control policy</b>.
        Please check your organization's policies and procedures for load balancer creation, or contact your administrator or support team for assistance.
        """
        return self.__get_formatted_json(message)

    def root_user_password_change(self, severity, ip_address, user_agent, is_completed, matched_ip_users, deploy_ip_tracker_project, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be {','.join(matched_ip_users)}, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Root User Password { 'Changed' if is_completed else 'Change Request Made' }!</font></b>

        Someone { 'changed password' if is_completed else 'requested for password change'} for <b>ROOT</b> user in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        Source IP Address: {ip_address}
        User Agent: {user_agent}
        {pagerduty_block if pagerduty_block else ''}

        <font color=\"#FF0000\">Action Required</font>
        { '<font color="#FF0000">Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation.</font>' if not deploy_ip_tracker_project else matched_ip_data if matched_ip_data else '<font color="#FF0000">This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!</font>' }"""
        return self.__get_formatted_json(message)

    def root_user_login_message(self, severity, ip_address, user_agent, matched_ip_users, deploy_ip_tracker_project, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be {','.join(matched_ip_users)}, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Root User Login!</font></b>

        A login to the AWS Management Console by the root user has been detected with the following details:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        Source IP Address: {ip_address}
        User Agent: {user_agent}
        {pagerduty_block if pagerduty_block else ''}

        { '' if not deploy_ip_tracker_project else matched_ip_data if matched_ip_data else '<font color="#FF0000">This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!</font>' }

        <b>Please review this activity and ensure that it was authorized.</b>
        <b><font color=\"#868686\">Logging in as the root user is not recommended due to the high level of access and privileges associated with this account. We recommend logging in using AWS IAM Identity Center to manage access to AWS resources instead of logging in as the root user.</font></b>
        """
        return self.__get_formatted_json(message)

    def signin_brute_force_attack_message(self, severity, ip_address, user, matched_ip_users, deploy_ip_tracker_project, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
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
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Brute force attack detected!</font></b>

        A brute force attack has been detected on the account with the following details:

        User Compromised: {user}
        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        Source IP Address: {ip_address}
        {pagerduty_block if pagerduty_block else ''}

        { '' if not deploy_ip_tracker_project else '' if matched_ip_data is None else matched_ip_data if matched_ip_data else '<font color="#FF0000">This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!</font>' }

        <b><font color=\"#868686\">We recommend taking immediate action to secure the account and prevent further attempts. Some steps you could take include:
        • Changing the password for the targeted account
        • Enabling two-factor authentication (2FA) for the targeted account
        • Limiting the number of failed login attempts allowed before the account is locked or disabled</font></b>"""
        return self.__get_formatted_json(message)

    def security_group_ingress_open_to_all_attachment_cron_message(self, severity, port, security_group_id, is_attached, attached_instances, attached_lb, pagerduty_incidents):
        remediation_message = ''
        if is_attached and attached_instances:
            remediation_message = """<b>Remediation Recommendation:</b>
            Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."""
        elif not is_attached:
            remediation_message = """<b>Remediation Recommendation:</b>
            Either Attach Security Group to a Resource or Delete it."""
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Security Group Ingress Open to Everyone!</font></b>

        Some ports are open to <b>0.0.0.0/0</b> in Security Group Ingress in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>Ingress Details:</b>
        Security Group ID: {security_group_id}
        Ports: {', '.join(port).replace("-1", "All Traffic")}

        {attachment_details}

        {remediation_message}"""
        return self.__get_formatted_json(message)

    def secret_access_key_exist_message(self, severity, iam_user, access_key_ids, pagerduty_incidents):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Active Secret-Access KeyPair Found!</font></b>

        We have found active Secret-Access KeyPair(s) for IAM User <b>{iam_user}</b> in the following location with following details:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        Access Key ID(s): {', '.join(access_key_ids)}
        {pagerduty_block if pagerduty_block else ''}

        <b>Remediation Recommendation:</b>
        Please DELETE the active Secret-Access KeyPair(s) and utilize IAM Roles or AWS IAM Identity Center instead.
        """
        return self.__get_formatted_json(message)

    def console_access_enabled_message(self, severity, iam_user, pagerduty_incidents):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Console Access Enabled!</font></b>

        AWS Console Access is enabled for IAM User <b>{iam_user}</b> in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        <b>Remediation Recommendation:</b>
        Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User and utilize AWS IAM Identity Center for access instead.
        """
        return self.__get_formatted_json(message)

    def iam_user_exist_message(self, severity, iam_user, pagerduty_incidents):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        message = f"""<b>[{severity}] <font color=\"#FF0000\">IAM User Exists!</font></b>

        An IAM User exists in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        IAM User: {iam_user}
        {pagerduty_block if pagerduty_block else ''}

        <b>Remediation Recommendation:</b>
        Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS.
        """
        return self.__get_formatted_json(message)

    def s3_public_bucket_object_remediation_message(self, severity, s3_bucket_name):
        message = f"""<b>[{severity}] Public S3 Bucket Remediated!</b>

        S3 Bucket <b>{s3_bucket_name}</b> does not have Public Access anymore at Bucket/Object level in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        """
        return self.__get_formatted_json(message)

    def s3_public_bucket_object_message(self, severity, s3_bucket_name, is_encryption_enabled, pagerduty_incidents):
        pagerduty_block = self.__get_pagerduty_incidents_details(pagerduty_incidents)
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Public S3 Bucket!</font></b>

        Public Access for an S3 Bucket is enabled using BucketPolicy or ACLs at Object and/or Bucket-level in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}
        {pagerduty_block if pagerduty_block else ''}

        <b>S3 Bucket Details:</b>
        Bucket Name: {s3_bucket_name}
        Encryption: {encryption_status}

        <b>Remediation Recommendation:</b>
        Please check the bucket and/or object permissions and ensure this S3 bucket is private and encrypted at REST.
        """
        return self.__get_formatted_json(message)

    def overpermissive_role_policy_attached_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        resources = "<br>".join([str(elem) for elem in resources])
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Over Permissive IAM Role Policy Found</font></b>

        User {iam_user} created/attached an over-permissive policy named {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        {resources}"""
        return self.__get_formatted_json(message)

    def overpermissive_role_policy_deleted_message(self, severity, iam_user, role_name, resources, policy_name):
        resources = "<br>".join([str(elem) for elem in resources])
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Over Permissive IAM Role Policy [DELETED]</font></b>

        This is to inform you that the over permissive policy named {policy_name} has been detached/deleted from IAM Role.
        User {iam_user} created/attached an over-permissive policy to IAM Role {role_name} which is attached to EC2 Instance in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        {resources}
        """
        return self.__get_formatted_json(message)

    def overpermissive_role_policies_deleted_message(self, severity, role_name, resources, detached_policies, deleted_policies):
        resources = "<br>".join([str(elem) for elem in resources])
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Over Permissive IAM Role Policies [DELETED]</font></b>

        This is to inform you that we ran a scan on IAM Role {role_name} attached to EC2 Instance(s) after the bypass tag was removed in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        {resources}

        <b>Following policies were deleted/detached:</b>
        Detached Policies: {', '.join(detached_policies)}
        Deleted Inline Policies: {', '.join(deleted_policies)}
        """
        return self.__get_formatted_json(message)

    def launch_wizard_security_group_replaced(self, is_create_event, severity, iam_user, group_name, resource_type, attachments: list, is_replaced_by_blackhole_sg, is_deleted, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        remediated_header = []
        remediated_messages = []
        if is_replaced_by_blackhole_sg:
            remediated_header.append('Replaced')
            remediated_messages.append('has been replaced by a <b>blackhole</b> security group')
        if is_deleted:
            remediated_header.append('Deleted')
            remediated_messages.append('has been deleted')
        else:
            remediated_messages.append("hasn't been deleted because its also attached to some other resource")
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Launch Wizard Security Group {' and '.join(remediated_header)}!</font></b>

        User {iam_user} {f'created <b>{group_name}</b> security group and attached it' if is_create_event else f'attached <b>{group_name}</b> security group'} to {resource_type} {', '.join(attachments)} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        This Security Group {' and '.join(remediated_messages)}"""
        return self.__get_formatted_json(message)

    def overpermissive_role_policy_bypass_message(self, severity, iam_user, role_name, resources, policy_name, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        resources = "<br>".join([str(elem) for elem in resources])
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Over Permissive IAM Role Policy Bypassed!</font></b>

        User {iam_user} created/attached an over-permissive policy {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        {pagerduty_block if pagerduty_block else ''}

        {resources}

        This policy was not deleted/detached because Admin has used <b>bypass tag</b> on IAM Role."""
        return self.__get_formatted_json(message)

    def captured_new_iam_user_event(self, severity, iam_user, access_key_id, action, source_ip_address, user_agent):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">Unknown Activity using Secret-Access KeyPair detected!</font></b>

        An unauthorized activity has been detected in your AWS environment. The activity was initiated using a Secret-Access KeyPair with the ID <b>{access_key_id}</b>, associated with IAM User <b>{iam_user}</b> in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        These are the activity details for AWS API call which do not match any known User's IP address and appears abnormal:
        Action Performed: {action}
        Source IP Address: {source_ip_address}
        User Agent: {user_agent}

        <b>Please promptly review this activity to determine whether it was authorized. If this action was initiated by you, no further action is necessary. However, if this access is not authorized, we recommend taking the following steps:</b>
        <b>• Deactivate the Secret-Access KeyPair with ID {access_key_id}.</b>
        <b>• Delete the unauthorized Secret-Access KeyPair to prevent further unauthorized access.</b>

        <b>Your AWS security is of utmost importance. If you have any concerns or need assistance, please contact our security team immediately.</b>
        """
        return self.__get_formatted_json(message)

    def secret_access_key_deactivated_remediation_message(self, severity, iam_user, access_key_id):
        message = f"""<b>[{severity}] Secret-Access KeyPair Auto-Remediated!</b>

        An unused Secret-Access KeyPair with the ID <b>{access_key_id}</b>, associated with IAM User <b>{iam_user}</b> has been deactivated in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        <b>This action was taken because we have identified that this Secret-Access KeyPair had been inactive for an extended period.</b>

        <b>• If you believe this deactivation was in error or you still require the use of this KeyPair, please contact our support team immediately.</b>
        <b>• If you no longer need this KeyPair, we recommend deleting it to further enhance the security of your AWS account.</b>

        <b>Your AWS security is of utmost importance. If you have any concerns or need assistance, please contact our security team immediately.</b>
        """
        return self.__get_formatted_json(message)

    def guardduty_finding_message(self, severity, severity_number, guardduty_admin_account: dict, account_name, account_id, region, finding_id, finding_type, finding_description, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">GuardDuty Finding Detected!<font color=\"#FF0000\"></b>

        We have detected a GuardDuty Finding of type <b>{finding_type}</b> with severity {severity_number} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {account_name}
        AWS Account ID: {account_id}
        AWS Region: {region}

        <b>Finding Description:</b>
        {finding_description}
        {pagerduty_block if pagerduty_block else ''}

        For more details open the <a href="https://console.aws.amazon.com/guardduty/home?region={self.region}#/findings?search=id%3D{finding_id}">GuardDuty console</a> in {guardduty_admin_account['AccountName']} ({guardduty_admin_account['AccountId']}) AWS account.
        """
        return self.__get_formatted_json(message)

    def ssm_document_association_failure_message(self, severity, account_name, account_id, region, instance_id, association_id, document_name, incident_number, incident_url):
        pagerduty_block = {}
        if incident_number and incident_number is not None:
            pagerduty_block = f"""
            <b>PagerDuty Incident:</b>
            Incident Number: {incident_number}
            Details: <a href="{incident_url}">Incident Details</a>"""
        message = f"""<b>[{severity}] <font color=\"#FF0000\">SSM Document Association Failure Detected!<font color=\"#FF0000\"></b>

        We have detected an SSM Document Association Failure of document <b>{document_name}</b> in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {account_name}
        AWS Account ID: {account_id}
        AWS Region: {region}

        <b>Association Details:</b>
        State Manager Association ID: {association_id}
        Instance ID: {instance_id}
        {pagerduty_block if pagerduty_block else ''}"""
        return self.__get_formatted_json(message)

    def ssm_document_association_failure_cron_message(self, severity, account_name, account_id, region, instances: list, association_id, document_name):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">SSM Document Association Failure Still Unresolved!<font color=\"#FF0000\"></b>

        SSM Document Association Failure for document <b>{document_name}</b> in the following location is still unresolved:

        AWS Organization: {self.org_name}
        AWS Account Name: {account_name}
        AWS Account ID: {account_id}
        AWS Region: {region}

        <b>Association Details:</b>
        State Manager Association ID: {association_id}
        Instance(s): [{', '.join(instances)}]

        Please address this issue as soon as possible."""
        return self.__get_formatted_json(message)

    def ssm_associated_ec2_instance_update_message(self, severity, account_name, account_id, region, instance_id, association_id, document_name, is_terminated):
        update_message = "Terminated" if is_terminated else "Association Succeeded"
        message = f"""<b>[{severity}] <font color=\"#FF0000\">SSM Document Association Update: EC2 Instance {update_message}!<font color=\"#FF0000\"></b>

        EC2 Instance <b>{instance_id}</b> which was previously in a failed state in the SSM Document Association for document <b>{document_name}</b> has {'been terminated' if is_terminated else 'now successfully associated'} in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {account_name}
        AWS Account ID: {account_id}
        AWS Region: {region}

        <b>Association Details:</b>
        State Manager Association ID: {association_id}"""
        return self.__get_formatted_json(message)

    def resource_creation_wo_required_tags_scp_block_error_message(self, severity: str, resource_type: str, iam_user: str, tags: list):
        message = f"""<b>[{severity}] <font color=\"#FF0000\">{resource_type} Creation Failed Due to Missing Tags</font></b>

        <b>{iam_user}</b> tried to create {resource_type} with missing tags in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}
        AWS Region: {self.region}

        Please add the following missing tags to {resource_type} to have it successfully create:
        {self.__get_tags(tags)}"""
        return self.__get_formatted_json(message)
