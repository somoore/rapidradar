class PagerDutyIncidents():
    def __init__(self, org_name, account_id, account_name, region):
        self.org_name = org_name
        self.account_id = account_id
        self.account_name = account_name
        self.region = region

    def get_details(self, alert_id, message_params):
        method = getattr(Details(self.org_name, self.account_id, self.account_name, self.region), alert_id)
        return method(**message_params)

class Details:
    def __init__(self, org_name, account_name, account_id, region):
        self.org_name = org_name
        self.account_name = account_name
        self.account_id = account_id
        self.region = region

    @staticmethod
    def __get_tags(tags):
        tags_msg = ''
        for tag in tags:
            if '=' in tag:
                key_value = tag.split('=')
                tags_msg += f'{key_value[0]}: {key_value[1]}\n'
            else:
                tags_msg += f'• {tag}\n'
        return tags_msg

    @staticmethod
    def __get_sg_attachment_details(is_attached, attached_instances, attached_lb):
        attachment_details = []
        if attached_instances or attached_lb:
            attachment_details = []
            attachment_details.append("Attachment Details:")
            if len(attached_instances) > 0:
                instances_details = []
                for instance in attached_instances:
                    instances_details.append(f"{instance['ResourceId']} ({instance['Context']})\n")
                attachment_details.append(f"EC2 Instance(s):\n{''.join(instances_details)}")
            if len(attached_lb) > 0:
                lb_details = []
                for lb in attached_lb:
                    lb_details.append(f"{lb['ResourceId']} ({lb['Context']})\n")
                attachment_details.append(f"LoadBalancers(s):\n{''.join(lb_details)}")
        attachment_details = '\n'.join(attachment_details) if attachment_details else 'Attachment: Currently Not Attached to Any Resource' if not is_attached else ''
        return attachment_details

    def resource_creation_without_tags_message(self, severity, iam_user, resource_type, resource_id, tags):
        title = f"[{severity}] {resource_type} Created Without Proper Tags!"
        incident_details = f"""User {iam_user} created {resource_type} {resource_id} without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Add Following Tags to {resource_type}:
{self.__get_tags(tags)}"""
        return title, incident_details

    def security_group_ingress_open_to_all(self, severity, iam_user, ip_protocol, port, security_group_id, security_group_rule_id, is_attached, attached_instances, attached_lb, is_critical):
        remediation_message = 'Please Close Access to 0.0.0.0/0'
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        if is_attached and attached_instances:
            remediation_message = "Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."
        elif not is_attached:
            remediation_message = "Either Attach Security Group to a Resource or Delete it."

        remediation_block = f"Remediation Recommendation: {remediation_message}" if is_critical else ''
        title = f"[{severity}] Security Group Ingress Port {port} Open to Everyone!"
        incident_details = f"""User {iam_user} opened a {ip_protocol} port to 0.0.0.0/0 in Security Group Ingress in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Ingress Details:
Security Group ID: {security_group_id}
Security Group Rule ID: {security_group_rule_id}
IP Protocol: {ip_protocol}
Port: {port}

{attachment_details}

{remediation_block}"""
        return title, incident_details

    def ec2_launch_scp_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag, is_imdsv2=False, is_publicip=False):
        instance_status = ""
        remediation_block = ""
        msg_header = "EC2 Instance Launched "
        if is_imdsv2:
            instance_status = "without enabling IMDSv2"
            if found_bypass_tag:
                msg_header += "Bypassing IMDSV2 SCP!"
                instance_status += " against SCP applied on your Organization using bypass tag"
            else:
                msg_header += "Without IMDSv2 enabled!"
                remediation_block = """
Remediation Recommendation:
Ensure that the EC2 instance metadata service (IMDSv2) is enabled by updating the instance's configuration. This can be done by modifying the instance metadata options to require IMDSv2."""
        if is_publicip:
            if found_bypass_tag:
                msg_header += "Bypassing Public IP!"
                instance_status = "bypassing Public IP SCP using bypass tag"
            else:
                msg_header += "With Public IP!"
                instance_status = "with Public IP"
        title = f"[{severity}] {msg_header}"
        incident_details = f"""User {iam_user} launched EC2 Instance {instance_status} in the following location and with following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Instance ID: {instance_id}
{remediation_block}"""
        return title, incident_details

    def launch_wizard_security_group_replaced(self, is_create_event, severity, iam_user, group_name, resource_type, attachments: list, is_replaced_by_blackhole_sg, is_deleted):
        remediated_header = []
        remediated_messages = []
        if is_replaced_by_blackhole_sg:
            remediated_header.append('Replaced')
            remediated_messages.append('has been replaced by a blackhole security group')
        if is_deleted:
            remediated_header.append('Deleted')
            remediated_messages.append('has been deleted')
        else:
            remediated_messages.append("hasn't been deleted because its also attached to some other resource")

        title = f"[{severity}] Launch Wizard Security Group {' and '.join(remediated_header)}!"
        incident_details = f"""User {iam_user} {f'created {group_name} security group and attached it' if is_create_event else f'attached {group_name} security group'} to {resource_type} {', '.join(attachments)} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

This Security Group {' and '.join(remediated_messages)}."""
        return title, incident_details

    def s3_public_bucket_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled):
        encryption_enabled_message = ' and encrypted at REST' if not is_encryption_enabled else ''
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        title = f"[{severity}] Public S3 Bucket!"
        incident_details = f"""User {iam_user} enabled Public Access for an S3 Bucket in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

S3 Bucket Details:
Bucket Name: {s3_bucket_name}
Encryption: {encryption_status}

Remediation Recommendation:
Please check the bucket permissions and ensure this S3 bucket is private{encryption_enabled_message}."""
        return title, incident_details

    def s3_public_object_message(self, severity, iam_user, s3_bucket_name, is_encryption_enabled):
        title = f"[{severity}] Objects Public in S3 Bucket!"
        encryption_status = 'Disabled' if not is_encryption_enabled else 'Enabled'
        incident_details = f"""User {iam_user} enabled Public Access for some Objects in S3 Bucket in the following location and can potentially be downloaded externally:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

S3 Bucket Details:
Bucket Name: {s3_bucket_name}
Encryption: {encryption_status}

Remediation Recommendation:
Please check the bucket and/or object permissions and ensure this S3 bucket is private and encrypted at REST."""
        return title, incident_details

    def security_group_ingress_open_to_all_attached_to_public_resource(self, severity, iam_user, security_group_id, resource_type, ports, is_attached, attached_instances, attached_lb):
        attachment_details = self.__get_sg_attachment_details(is_attached, attached_instances, attached_lb)
        title = f"[{severity}] Security Group Attached to {resource_type} with ports Open to 0.0.0.0/0!"
        incident_details = f"""User {iam_user} attached a Security Group with ports open to 0.0.0.0/0 to {resource_type} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Ingress Details:
Security Group ID: {security_group_id}
Ports: {', '.join(ports).replace("-1", "All Traffic")}

{attachment_details}

Remediation Recommendation:
Close Access to 0.0.0.0/0. Please utilize AWS Client VPN or AWS Systems Manager Session Manager instead."""
        return title, incident_details

    def iam_user_creation_bypass_tag_message(self, severity, iam_user, new_iam_user, found_bypass_tag):
        bypass_title = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = """
Remediation Recommendation:
Please delete IAM User and utilize AWS IAM Identity Center or an IAM Role to provide least-privilege access to AWS."""
        title = f'[{severity}] New IAM User Created{bypass_title}!'
        incident_details = f"""User {iam_user} created an IAM User {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
IAM User: {new_iam_user}
{remediation_block if not found_bypass_tag else ''}"""
        return title, incident_details

    def secret_access_key_creation_message(self, severity, is_new, iam_user, secret_access_key_user, access_key_id, created_by, created_at, deploy_iam_keypair_access_tracker_project):
        title = f'[{severity}] New Secret-Access KeyPair Generated!'
        incident_details = f"""User {iam_user} created a new Secret-Access KeyPair in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

Secret-Access KeyPair Details:
Access Key ID: {access_key_id}
Associated with IAM User: {secret_access_key_user}
Created At: {created_at}

Remediation Recommendation:
Please DELETE this newly generated Secret-Access KeyPair and utilize IAM Roles or AWS IAM Identity Center instead."""
        return title, incident_details

    def login_profile_creation_message(self, severity, iam_user, login_profile_user, created_at):
        title = f"[{severity}] AWS Console Access Enabled!"
        incident_details = f"""User {iam_user} enabled AWS Console Access in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

Console Access Details:
IAM User: {login_profile_user}
Enabled At: {created_at}

Remediation Recommendation:
Please DISABLE AWS Console access for this IAM User. If possible, please also DELETE IAM User. Please utilize AWS IAM Identity Center for access instead."""
        return title, incident_details

    def s3_account_public_access_config_modification_message(self, severity, iam_user, restrict_public_buckets, block_public_policy, block_public_acls, ignore_public_acls):
        restrict_public_buckets = 'Enabled' if restrict_public_buckets else 'Disabled'
        block_public_policy = 'Enabled' if block_public_policy else 'Disabled'
        block_public_acls = 'Enabled' if block_public_acls else 'Disabled'
        ignore_public_acls = 'Enabled' if ignore_public_acls else 'Disabled'
        title = f'[{severity}] S3 Account Block Public Access Settings Modified!'
        incident_details = f"""User {iam_user} modified S3 Block Public Access Settings for the following account:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

Block Public Access settings for account:
Restrict Public Buckets: {restrict_public_buckets}
Block Public Policy: {block_public_policy}
Block Public ACLs: {block_public_acls}
Ignore Public ACLs: {ignore_public_acls}

Remediation Recommendation:
Please enable all of the above settings for S3 Account Block Public Access and block all Public Access."""
        return title, incident_details

    def unencrypted_volume_creation_bypass_tag_message(self, severity, iam_user, volume_id, found_bypass_tag):
        bypass_title = 'Unencrypted EBS Volume Created Bypassing SCP!' if found_bypass_tag else 'EBS Volume Created Without Encryption Enabled!'
        remediation_block = """Remediation Recommendation:
Encrypt the volume using AWS Key Management Service (KMS) to safeguard sensitive data and update associated configurations, such as EC2 instance attachments, to use the newly encrypted volume."""
        title = f"[{severity}] {bypass_title}"
        incident_details = f"""User {iam_user} created an EBS Volume with ID {volume_id} without encryption enabled {'using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

{remediation_block if not found_bypass_tag else ''}"""
        return title, incident_details

    def root_volume_unencrypted_bypass_tag_message(self, severity, iam_user, instance_id, found_bypass_tag):
        bypass_title = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = """Remediation Recommendation:
Encrypt the root volume using AWS Key Management Service (KMS) to safeguard sensitive data and update EC2 instance attachments to use the newly encrypted volume."""
        title = f"[{severity}] EC2 Instance launched with unencrypted Root EBS Volume{bypass_title}!"
        incident_details = f"""User {iam_user} launched EC2 Instance {instance_id} with unencrypted Root EBS Volume {'using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

{remediation_block if not found_bypass_tag else ''}"""
        return title, incident_details

    def public_resource_message(self, severity, iam_user, resource_type, resource_id, auto_remediate):
        remediation_message = f"Please make this {resource_type} private and share it with only those AWS accounts you need to share it with."
        title = f"[{severity}] Public {resource_type}"
        incident_details = f"""User {iam_user} made an {resource_type} with ID {resource_id} PUBLIC in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Remediation Recommendation:
{remediation_message}"""
        return title, incident_details

    def unencrypted_rds_creation_bypass_tag_message(self, severity, iam_user, db_identifier, resource_type, found_bypass_tag):
        bypass_msg_header = ' Bypassing SCP' if found_bypass_tag else ''
        remediation_block = f"""
Remediation Recommendation:
Please enable encryption for this {resource_type} by creating a snapshot of it, and then creating an encrypted copy of that snapshot and then restore an {resource_type} from the encrypted snapshot."""
        title = f'[{severity}] {resource_type} Created Without Encryption Enabled{bypass_msg_header}!'
        incident_details = f"""User {iam_user} created an {resource_type} with ID {db_identifier} without encryption enabled {'against SCP applied on your Organization using bypass tag ' if found_bypass_tag else ''}in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
{remediation_block if not found_bypass_tag else ''}"""
        return title, incident_details

    def root_user_password_change(self, severity, ip_address, user_agent, is_completed, matched_ip_users, deploy_ip_tracker_project):
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be {','.join(matched_ip_users)}, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        title = f"[{severity}] Root User Password { 'Changed' if is_completed else 'Change Request Made' }!"
        incident_details = f"""Someone { 'changed password' if is_completed else 'requested for password change'} for ROOT user in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Source IP Address: {ip_address}
User Agent: {user_agent}

Action Required:
{'Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation.' if not deploy_ip_tracker_project else matched_ip_data if matched_ip_data else 'This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!'}"""
        return title, incident_details

    def root_user_login_message(self, severity, ip_address, user_agent, matched_ip_users, deploy_ip_tracker_project):
        matched_ip_data = ''
        if matched_ip_users:
            if len(matched_ip_users) == 1:
                matched_ip_data = f"Based on our data, this could potentially be {','.join(matched_ip_users)}, however we should check with this user to be certain and verify legitimate access"
            else:
                matched_ip_data = f"""Based on our data, this could be one of these users:
{', '.join(matched_ip_users)}

Since there are multiple matches, actor is potentially coming from a physical office/shared Internet connection where multiple employees with AWS access have authenticated recently. Please contact the individuals listed to verify legitimate access."""
        title = f"[{severity}] Root User Login!"
        incident_details = f"""A login to the AWS Management Console by the root user has been detected with the following details:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Source IP Address: {ip_address}
User Agent: {user_agent}

{ '' if not deploy_ip_tracker_project else matched_ip_data if matched_ip_data else 'This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!' }

Please review this activity and ensure that it was authorized.
Logging in as the root user is not recommended due to the high level of access and privileges associated with this account. We recommend logging in using AWS IAM Identity Center to manage access to AWS resources instead of logging in as the root user."""
        return title, incident_details

    def iam_user_password_change_message(self, severity, iam_user, affected_user, is_failed, user_agent, source_ip_address):
        title = f"[{severity}] IAM User Password {'Change Attempt Failed' if is_failed else 'Changed'}!"
        incident_details = f"""User {iam_user} {'tried to change' if is_failed else 'changed'} console password for IAM User {affected_user} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

User Agent: {user_agent}
Source IP Address: {source_ip_address}

Action Required:
Please verify the legitimacy of the password change event, and if unauthorized access is suspected, initiate an immediate security investigation. Disable compromised accounts if necessary. Communicate with affected users and consider implementing Multi-Factor Authentication (MFA). Enhance monitoring, update IAM policies, and document the incident for future reference, ensuring preventive measures are in place to mitigate recurrence."""
        return title, incident_details

    def signin_brute_force_attack_message(self, severity, ip_address, user, matched_ip_users, deploy_ip_tracker_project):
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
        title = f"[{severity}] Brute force attack detected!"
        incident_details = f"""A brute force attack has been detected on the account with the following details:

User Compromised: {user}
AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
Source IP Address: {ip_address}

{ '' if not deploy_ip_tracker_project else '' if matched_ip_data is None else matched_ip_data if matched_ip_data else 'This IP address does not match any known User who has federated with AWS IAM Identity Center now or in the past and appears abnormal. Please treat this notification with the utmost urgency, follow immediate IR procedures and check for any IoCs!' }

We recommend taking immediate action to secure the account and prevent further attempts. Some steps you could take include:
• Changing the password for the targeted account
• Enabling two-factor authentication (2FA) for the targeted account
• Limiting the number of failed login attempts allowed before the account is locked or disabled"""
        return title, incident_details

    def ec2_creation_invoked_by_aws_service_action_message(self, severity, instances, service, action, to_do_list):
        to_do_list = "\n".join(to_do_list) if to_do_list else ''
        action_message = f"""deleted in 10 minutes if the following actions are not taken:
        { to_do_list }

        Or you can also tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        title = f'[{severity}] EC2 Instance(s) launched by AWS Service bypassing SCPs'
        incident_details = f"""EC2 Instance(s) were launched by {service} against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Instance IDs: {', '.join(instances)}

While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.
So, these resources will be {action_message}"""
        return title, incident_details

    def unencrypted_ebs_vol_creation_invoked_by_aws_service_action_message(self, severity, volume, service, action):
        action_message = """deleted in 10 minutes if the following actions are not taken:

        Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        title = f"[{severity}] EBS Volume created by AWS Service bypassing SCPs"
        incident_details = f"""EBS Volume was created by {service} against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
EBS Volume: {volume}

While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.
So, these resources will be {action_message}"""
        return title, incident_details

    def loadbalancer_creation_invoked_by_aws_service_action_message(self, severity, loadbalancer, service, action):
        action_message = """deleted in 10 minutes if the following actions are not taken:

        Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        title = f"[{severity}] LoadBalancer created by AWS Service bypassing SCPs"
        incident_details = f"""LoadBalancer was created by {service} against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
LoadBalancer Name: {loadbalancer}

While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.
So, these resources will be {action_message}"""
        return title, incident_details

    def loadbalancer_creation_bypass_tag_message(self, severity, iam_user, loadbalancer_name, lb_type):
        title = f"[{severity}] LoadBalancer Created Bypassing SCP!"
        incident_details = f"""User {iam_user} created LoadBalancer named {loadbalancer_name} against SCP applied on your Organization using bypass tag in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}"""
        return title, incident_details

    def eip_allocation_invoked_by_aws_service_action_message(self, severity, allocation_id, service, action):
        action_message = """deleted in 10 minutes if the following actions are not taken:

        Tag your resource(s) with keep-alive=true tag to bypass deletion""" if action == 'Delete' else 'ignored'
        title = f"[{severity}] Elastic IP allocated by AWS Service bypassing SCPs"
        incident_details = f"""Elastic IP was allocated by {service} against SCPs applied on your Organization in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
EIP Allocation ID: {allocation_id}

While deploying RapidRadar, you chose to {action.lower()} the resources if AWS Service deploys on your behalf.
So, these resources will be {action_message}"""
        return title, incident_details

    def eip_association_without_override_tag_message(self, severity, iam_user, eip_allocation_id, resource_id, resource_type, override_tag_key, found_override_tag, is_value_base64_encoded):
        message_title = "Without Proper Tags"
        issue_message = "missing proper tags"
        remediation_message = f"""Add Following Tags to {resource_type}:
{override_tag_key}: <Base64EncodedSecretKey>"""
        if found_override_tag and not is_value_base64_encoded:
            message_title = "With Invalid Tag Value"
            issue_message = f"having invalid value for Tag {override_tag_key}"
            remediation_message = f"Please add valid base64 encoded value for Tag {override_tag_key} to {resource_type}."
        title = f"[{severity}] Elastic IP Association {message_title}"
        incident_details = f"""User {iam_user} associated Elastic IP with ID {eip_allocation_id} to {resource_type} with ID {resource_id} {issue_message} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

{remediation_message}"""
        return title, incident_details

    def overpermissive_role_policy_attached_message(self, severity, iam_user, role_name, resources, policy_name):
        resources = "\n".join([str(elem) for elem in resources])
        title = f"[{severity}] Over Permissive IAM Role Policy Found"
        incident_details = f"""User {iam_user} created/attached an over-permissive policy named {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

        AWS Organization: {self.org_name}
        AWS Account Name: {self.account_name}
        AWS Account ID: {self.account_id}

        {resources}"""
        return title, incident_details

    def overpermissive_role_policy_bypass_message(self, severity, iam_user, role_name, resources, policy_name):
        resources = "\n".join([str(elem) for elem in resources])
        title = f"[{severity}] Over Permissive IAM Role Policy Bypassed!"
        incident_details = f"""User {iam_user} created/attached an over-permissive policy {policy_name} to IAM Role {role_name} which is attached to EC2 Instance in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}

{resources}

This policy was not deleted/detached because Admin has used bypass tag on IAM Role."""
        return title, incident_details

    def secret_creation_without_tags_message(self, severity, iam_user, secret_name, secret_arn, tags):
        title = f"[{severity}] Secret Created Without Proper Tags!"
        incident_details = f"""User {iam_user} created a SecretsManager Secret named {secret_name} without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

Add Following Tags to Secret:
{self.__get_tags(tags)}"""
        return title, incident_details

    def backup_plan_creation_without_tags_message(self, severity, iam_user, backup_plan_name, backup_plan_arn, tags):
        title = f"[{severity}] Backup Plan Created Without Proper Tags!"
        incident_details = f"""User {iam_user} created a Backup Plan named {backup_plan_name} without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}
Backup Plan ARN: {backup_plan_arn}

Add Following Tags to Backup Plan:
{self.__get_tags(tags)}"""
        return title, incident_details

    def loadbalancer_creation_without_tags_message(self, severity, iam_user, loadbalancer_name, loadbalancer_arn, lb_type, tags):
        title = f"[{severity}] LoadBalancer Created Without Proper Tags!"
        incident_details = f"""User {iam_user} created a LoadBalancer named {loadbalancer_name} without proper tags in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {self.account_name}
AWS Account ID: {self.account_id}
AWS Region: {self.region}

LoadBalancer Type: {lb_type}
LoadBalancer ARN: {loadbalancer_arn}

Add Following Tags to LoadBalancer:
{self.__get_tags(tags)}"""
        return title, incident_details

    def guardduty_finding_message(self, severity, severity_number, guardduty_admin_account: dict, account_name, account_id, region, finding_id, finding_type, finding_description):
        title = f"[{severity}] GuardDuty Finding Detected!"
        incident_details = f"""We have detected a GuardDuty Finding of type {finding_type} with severity {severity_number} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {account_name}
AWS Account ID: {account_id}
AWS Region: {region}

Finding Description:
{finding_description}

For more details open https://console.aws.amazon.com/guardduty/home?region={self.region}#/findings?search=id%3D{finding_id} in {guardduty_admin_account['AccountName']} ({guardduty_admin_account['AccountId']}) AWS account."""
        return title, incident_details

    def ssm_document_association_failure_message(self, severity, account_name, account_id, region, instance_id, association_id, document_name):
        title = f"[{severity}] SSM Document Association Failure Detected!"
        incident_details = f"""We have detected an SSM Document Association Failure of document {document_name} in the following location:

AWS Organization: {self.org_name}
AWS Account Name: {account_name}
AWS Account ID: {account_id}
AWS Region: {region}

Association Details:
State Manager Association ID: {association_id}
Instance ID: {instance_id}"""
        return title, incident_details
