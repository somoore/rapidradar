import logging
from os import getenv
from time import sleep
import json
from parliament import analyze_policy_string
from utils.utility import Helper

CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class IAM:
    def __init__(self, active_session):
        self.client = active_session.client(service_name='iam', region_name='us-east-1')

    def check_iam_user_exists(self, iam_user):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.get_user(UserName=iam_user)
                return True
            except self.client.exceptions.NoSuchEntityException:
                return False
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                raise error

    def found_user_access_keys(self, iam_user):
        found_active_access_key = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.list_access_keys(
                    UserName=iam_user
                )['AccessKeyMetadata']
                if len(response) > 0:
                    for key in response:
                        if key['Status'] == 'Active':
                            found_active_access_key = True
                            break
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'NoSuchEntity':
                    LOGGER.info("IAM User %s cannot be found", iam_user)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Unexpected error: %s", str(error))
                return False
        return found_active_access_key

    def get_active_iam_user_access_key_ids(self, iam_user):
        access_key_ids = []
        try:
            response = self.client.list_access_keys(
                UserName=iam_user
            )['AccessKeyMetadata']
            if len(response) > 0:
                for key in response:
                    if key['Status'] == 'Active':
                        access_key_ids.append(key['AccessKeyId'])
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchEntity':
                LOGGER.info("IAM User %s cannot be found", iam_user)
            else:
                LOGGER.error("Unexpected error: %s", str(error))
        return access_key_ids

    def found_iam_user_login_profile(self, user):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.get_login_profile(UserName=user)
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'NoSuchEntity':
                    LOGGER.info("Login Profile for IAM User %s cannot be found", user)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Unexpected error: %s", str(error))
                break
        return False

    def get_iam_user_tags_created_by(self, user):
        try:
            response = self.client.get_user(UserName=user)
            if 'User' in response and 'Tags' in response['User']:
                user_tags = []
                created_by = ''
                for tag in response['User']['Tags']:
                    user_tags.append(f"{tag['Key']}: {tag['Value']}")
                    if tag['Key'] in ['CreatedBy', 'Createdby', 'createdBy', 'createdby', 'GeneratedBy', 'Generatedby', 'generatedBy', 'generatedby']:
                        if Helper().is_user_email(tag['Value']):
                            created_by = tag['Value']
                return user_tags, created_by
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchEntity':
                LOGGER.info("Login Profile for IAM User %s cannot be found", user)
            else:
                LOGGER.error("Unexpected error: %s", str(error))
        return [], ''

    def get_instance_profiles(self, role_name):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.list_instance_profiles_for_role(
                    RoleName=role_name
                )['InstanceProfiles']
                instance_profiles = [profile['Arn'] for profile in response]
                return instance_profiles
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return []

    def found_iam_role_bypass_tag(self, role_name, bypass_tag_key):
        found_bypass_tag = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.list_role_tags(RoleName=role_name)['Tags']
                for tag in response:
                    if tag['Key'] == bypass_tag_key:
                        found_bypass_tag = True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return found_bypass_tag

    def detach_role_policy(self, role_name, policy_arn):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] in ['NoSuchEntityException', 'InvalidInputException']:
                    LOGGER.info("IAM Role %s not Found", role_name)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def delete_role_policy(self, role_name, policy_name):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] in ['NoSuchEntityException', 'InvalidInputException']:
                    LOGGER.info("IAM Role %s not Found", role_name)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def overly_permissive_attached_role_policies(self, role_name):
        policies = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                for policy in response:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        policies.append(policy['PolicyArn'])
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] in ['NoSuchEntityException']:
                    LOGGER.info("IAM Role %s not Found", role_name)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return policies

    def overly_permissive_inline_role_policies(self, role_name):
        policies = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                role_policies = self.client.list_role_policies(RoleName=role_name)['PolicyNames']
                for policy in role_policies:
                    policy_document = self.client.get_role_policy(RoleName=role_name,PolicyName=policy)['PolicyDocument']
                    analysis = analyze_policy_string(json.dumps(policy_document))
                    for result in analysis.findings:
                        if result.issue == 'RESOURCE_STAR':
                            policies.append(policy)
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] in ['NoSuchEntityException']:
                    LOGGER.info("IAM Role %s not Found", role_name)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return list(set(policies))

    def found_suppression_tag(self, iam_user, alert_suppression_tag_key, alert_suppression_tag_value):
        found_suppression_tag = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.list_user_tags(UserName=iam_user)['Tags']
                for tag in response:
                    if tag['Key'] == alert_suppression_tag_key and tag['Value'] == alert_suppression_tag_value:
                        found_suppression_tag = True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False
        return found_suppression_tag

    def get_access_key_last_used(self, access_key_id):
        last_used = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_access_key_last_used(AccessKeyId=access_key_id)
                if 'LastUsedDate' in response['AccessKeyLastUsed']:
                    last_used = response['AccessKeyLastUsed']['LastUsedDate'].strftime("%Y-%m-%dT%H:%M:%S")
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return last_used

    def get_access_key_status(self, iam_user, access_key_id):
        status = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                access_keys_metadata = self.client.list_access_keys(UserName=iam_user)['AccessKeyMetadata']
                for access_key in access_keys_metadata:
                    if access_key['AccessKeyId'] == access_key_id:
                        status = access_key['Status']
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return status

    def make_access_key_inactive(self, iam_user, access_key_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.update_access_key(
                    UserName=iam_user,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def __get_instance_profile_roles(self, profile_name: str):
        roles = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                instance_profile = self.client.get_instance_profile(InstanceProfileName=profile_name)
                roles = [ role['RoleName'] for role in instance_profile['InstanceProfile']['Roles'] ]
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Could not get roles for IAM Instance Profile %s", profile_name)
                raise error
        return roles

    def __get_attached_role_policies(self, role_name: str):
        policy_names = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                role_policies = self.client.list_attached_role_policies(RoleName=role_name)
                policy_names = [ policy['PolicyName'] for policy in role_policies['AttachedPolicies'] ]
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Could not get attached Role Policies for IAM Role %s", role_name)
                raise error
        return policy_names

    def __get_all_managed_policies(self):
        base_kwargs = {'Scope': 'All', 'MaxItems': 1000}
        try:
            kwargs = base_kwargs.copy()
            response = self.client.list_policies(**kwargs)
            policies = response['Policies']
            while response.get('IsTruncated'):
                kwargs.update({'Marker': response['Marker']})
                response = self.client.list_policies(**kwargs)
                policies.extend(response['Policies'])
            return policies
        except Exception as error:
            print(f"[ERROR] Could not list IAM policies due to unexpected error: {str(error)}")
            raise error

    def get_policy_arns(self, policy_names: list):
        policy_arns = []
        all_managed_policies = self.__get_all_managed_policies()
        for policy in all_managed_policies:
            if policy['PolicyName'] in policy_names:
                policy_arns.append(policy['Arn'])
        return policy_arns

    def attach_policies(self, role_name, additional_policies_arns, custom_managed_policy_arn):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                attached_role_policies = self.__get_attached_role_policies(role_name)
                if 'AmazonSSMManagedInstanceCore' not in attached_role_policies:
                    LOGGER.info("...Attaching Missing AWS Managed Policy [AmazonSSMManagedInstanceCore]")
                    self.client.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
                    )
                if 'AmazonSSMManagedEC2InstanceDefaultPolicy' not in attached_role_policies:
                    LOGGER.info("...Attaching Missing AWS Managed Policy [AmazonSSMManagedEC2InstanceDefaultPolicy]")
                    self.client.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy'
                    )
                if custom_managed_policy_arn:
                    access_policy_name = custom_managed_policy_arn.split('/')[-1]
                    if access_policy_name not in attached_role_policies:
                        LOGGER.info("...Attaching Missing Policy [%s]", access_policy_name)
                        self.client.attach_role_policy(
                            RoleName=role_name,
                            PolicyArn=custom_managed_policy_arn
                        )
                for policy_arn in additional_policies_arns:
                    if policy_arn != "":
                        additional_policy_name = policy_arn.split('/')[-1]
                        if additional_policy_name not in attached_role_policies:
                            LOGGER.info("...Attaching Missing Policy [%s]", additional_policy_name)
                            self.client.attach_role_policy(
                                RoleName=role_name,
                                PolicyArn=policy_arn
                            )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error

    def attach_missing_role_policies(self, profile_name: str, additional_policies_arns, custom_managed_policy_arn):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                roles = self.__get_instance_profile_roles(profile_name)
                for role in roles:
                    self.attach_policies(role, additional_policies_arns, custom_managed_policy_arn)
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Could not attach missing policies to already attach IAM Role %s", profile_name)
                raise error

    def __get_managed_role_name(self, role_name: str, additional_policies_arns, custom_managed_policy_arn):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_role(RoleName=role_name)
                LOGGER.info("Role %s already exists", role_name)
                return response['Role']['RoleName']
            except self.client.exceptions.NoSuchEntityException:
                LOGGER.info("Role %s does not exist. Creating...", role_name)
                response = self.client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    })
                )
                self.attach_policies(response['Role']['RoleName'], additional_policies_arns, custom_managed_policy_arn)
                return response['Role']['RoleName']
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error

    def __get_managed_instance_profile_arn(self, profile_name: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_instance_profile(InstanceProfileName=profile_name)
                LOGGER.info("The instance profile %s already exists.", profile_name)
                return response['InstanceProfile']['Arn']
            except self.client.exceptions.NoSuchEntityException:
                LOGGER.info("The instance profile %s does not exist, creating...", profile_name)
                response = self.client.create_instance_profile(InstanceProfileName=profile_name)
                self.client.add_role_to_instance_profile(
                    InstanceProfileName=profile_name,
                    RoleName=profile_name
                )
                return response['InstanceProfile']['Arn']
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error

    def __get_existing_role_instance_profile_arn(self, role_name: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_instance_profile(InstanceProfileName=role_name)
                return response['InstanceProfile']['Arn']
            except self.client.exceptions.NoSuchEntityException as error:
                LOGGER.info("The instance profile %s does not exist. Automation could not create a new one because Auto-Creation of IAM Roles is disabled.", role_name)
                raise error
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error

    def get_custom_policy_arn(self, account_id, policy_name: str):
        try:
            get_policy_response = self.client.get_policy(PolicyArn=f"arn:aws:iam::{account_id}:policy/{policy_name}")
            return get_policy_response['Policy']['Arn']
        except self.client.exceptions.NoSuchEntityException:
            print(f"The policy {policy_name} does not exist")
        except Exception as error:
            print(f"[ERROR] {str(error)}")
        return ''

    def check_role(self, custom_managed_policy_arn, auto_manage_role, managed_role_name, existing_role_name, additional_policies_arns):
        instance_profile_arn = ''
        if auto_manage_role:
            LOGGER.info("...Checking if IAM Role %s exists.", managed_role_name)
            managed_role = self.__get_managed_role_name(managed_role_name, additional_policies_arns, custom_managed_policy_arn)
            instance_profile_arn = self.__get_managed_instance_profile_arn(managed_role)
            profile_name = instance_profile_arn.split('/')[1]
            self.attach_missing_role_policies(profile_name, additional_policies_arns, custom_managed_policy_arn)
        else:
            LOGGER.info("Auto-creation of IAM Roles is disabled. Attaching Existing Role %s...", existing_role_name)
            managed_role = existing_role_name
            instance_profile_arn = self.__get_existing_role_instance_profile_arn(existing_role_name)
            profile_name = instance_profile_arn.split('/')[1]
            self.attach_missing_role_policies(profile_name, additional_policies_arns, custom_managed_policy_arn)
        return instance_profile_arn

    def get_role_instance_profiles_arns(self, role_name: str):
        next_token = ''
        base_kwargs = {
            'RoleName': role_name
        }
        instance_profiles = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                while next_token is not None:
                    kwargs = base_kwargs.copy()
                    if next_token != '':
                        kwargs.update({'Marker': next_token})
                    response = self.client.list_instance_profiles_for_role(**kwargs)
                    for profile in response['InstanceProfiles']:
                        instance_profiles.append(profile['Arn'])
                    next_token = response['Marker'] if response['IsTruncated'] else None
                return instance_profiles
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'NoSuchEntity':
                    LOGGER.info("IAM Role %s cannot be found", role_name)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Unexpected error: %s", str(error))
                raise error
        return instance_profiles
